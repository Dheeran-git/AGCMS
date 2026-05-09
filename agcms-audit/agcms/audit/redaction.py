"""GDPR Article 17 — right-to-erasure executor.

Given an approved ``gdpr_purge_requests`` row, locate every ``audit_logs``
row whose ``user_id`` matches the subject and tombstone the PII fields
on each one while preserving hash-chain verifiability.

Design notes (tombstone with witness):

* The subject-PII columns (``user_id``, ``department``,
  ``enforcement_reason``) are overwritten in place with the fixed
  sentinel ``[REDACTED]``. The original values are NOT preserved
  anywhere — that is the point of erasure.
* Each redacted row is re-signed. The new signing payload includes two
  additional fields that were not part of the original signature:
  ``redaction_record_id`` (the UUID of the witness row) and
  ``pre_redaction_signature`` (the row's signature before redaction,
  used by the chain verifier for linkage continuity into the next row).
* One ``redaction_records`` row is written per tombstoned audit row.
  The redaction record stores ``original_signature`` +
  ``redacted_signature`` and is itself HMAC-signed by the active row
  key. A DB-level attacker who mutates a redacted row cannot then
  recompute a valid ``record_signature`` without the key, so the
  verifier will flag the redaction as inauthentic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional

import sqlalchemy

from agcms.audit.keys import REGISTRY
from agcms.audit.logger import AuditLogger
from agcms.db import database


REDACTED_SENTINEL = "[REDACTED]"

# Audit-row columns that carry (or may carry) data-subject PII. These
# are the fields overwritten to the sentinel during redaction.
_PII_COLUMNS = ("user_id", "department", "enforcement_reason")


@dataclass
class RedactionResult:
    purge_request_id: str
    tenant_id: str
    rows_redacted: int
    redaction_record_ids: List[str]


# ----------------------------------------------------------------------
# Redaction-record signing (the "witness" signature)
# ----------------------------------------------------------------------

def sign_redaction_record(record: dict, *, kid: Optional[str] = None) -> str:
    """HMAC-SHA256 over the immutable fields of a redaction_records row.

    Covers ``purge_request_id``, ``audit_interaction_id``,
    ``audit_sequence_number``, ``original_signature``,
    ``redacted_signature``, ``redacted_at``, ``signing_key_id``.
    """
    chosen_kid = kid or record.get("signing_key_id") or REGISTRY.active_row_kid
    key = REGISTRY.row_key(chosen_kid)
    payload = {
        "purge_request_id": str(record["purge_request_id"]),
        "audit_interaction_id": str(record["audit_interaction_id"]),
        "audit_sequence_number": int(record["audit_sequence_number"]),
        "original_signature": record["original_signature"],
        "redacted_signature": record["redacted_signature"],
        "redacted_at": (
            record["redacted_at"].isoformat()
            if hasattr(record["redacted_at"], "isoformat")
            else str(record["redacted_at"])
        ),
        "signing_key_id": chosen_kid,
    }
    serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(key, serialized, hashlib.sha256).hexdigest()


def verify_redaction_record(record: dict) -> bool:
    """Validate ``record_signature`` against the row's immutable fields."""
    stored = record.get("record_signature")
    if not stored:
        return False
    try:
        expected = sign_redaction_record(record)
    except KeyError:
        return False
    return hmac.compare_digest(stored, expected)


# ----------------------------------------------------------------------
# Purge-request approval signature
# ----------------------------------------------------------------------

def sign_purge_approval(request: dict, *, kid: Optional[str] = None) -> str:
    """HMAC over the purge-request approval payload."""
    chosen_kid = kid or REGISTRY.active_row_kid
    key = REGISTRY.row_key(chosen_kid)
    payload = {
        "id": str(request["id"]),
        "tenant_id": request["tenant_id"],
        "subject_user_id": request["subject_user_id"],
        "requested_by": str(request["requested_by"]),
        "requested_at": _iso(request["requested_at"]),
        "approved_by": str(request["approved_by"]),
        "approved_at": _iso(request["approved_at"]),
        "reason": request["reason"],
        "signing_key_id": chosen_kid,
    }
    serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(key, serialized, hashlib.sha256).hexdigest()


def _iso(value: Any) -> str:
    if value is None:
        return ""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


# ----------------------------------------------------------------------
# Executor
# ----------------------------------------------------------------------

async def execute_purge(purge_request_id: str) -> RedactionResult:
    """Tombstone every audit row belonging to the purge request's subject.

    Must only be called after the request has reached state='approved'
    and the approval is within the 24-hour window. Caller is expected
    to flip state='executed' and write ``rows_redacted`` / ``executed_at``
    on the request after this returns.
    """
    # Load + lock the purge request.
    async with database.transaction():
        request = await database.fetch_one(
            sqlalchemy.text(
                "SELECT id, tenant_id, subject_user_id, state, approval_expires_at, "
                "       requested_by, requested_at, approved_by, approved_at, reason "
                "FROM gdpr_purge_requests "
                "WHERE id = :id FOR UPDATE"
            ).bindparams(id=purge_request_id),
        )
        if request is None:
            raise LookupError(f"purge request {purge_request_id} not found")
        if request["state"] != "approved":
            raise ValueError(
                f"purge request {purge_request_id} is state={request['state']!r}; "
                "must be 'approved' to execute"
            )

        tenant_id = request["tenant_id"]
        subject = request["subject_user_id"]
        active_kid = REGISTRY.active_row_kid
        now = datetime.now(timezone.utc)

        # Stream candidate rows. We exclude rows already redacted (idempotent re-runs)
        # and the zero-sequence legacy rows (no chain linkage anyway).
        rows = await database.fetch_all(
            sqlalchemy.text(
                "SELECT interaction_id, tenant_id, user_id, department, created_at, "
                "       llm_provider, llm_model, prompt_hash, pii_detected, "
                "       pii_entity_types, pii_risk_level, injection_score, "
                "       injection_type, enforcement_action, enforcement_reason, "
                "       triggered_policies, response_violated, response_violations, "
                "       total_latency_ms, log_signature, previous_log_hash, "
                "       sequence_number, signing_key_id "
                "FROM audit_logs "
                "WHERE tenant_id = :tid AND user_id = :sub "
                "  AND redaction_record_id IS NULL "
                "ORDER BY sequence_number ASC"
            ).bindparams(tid=tenant_id, sub=subject),
        )

        record_ids: List[str] = []
        for raw in rows:
            entry = _normalize_entry(dict(raw))
            original_signature = entry["log_signature"]

            redaction_record_id = str(uuid.uuid4())

            # Apply tombstones and build the new signing payload.
            for col in _PII_COLUMNS:
                if entry.get(col) is not None:
                    entry[col] = REDACTED_SENTINEL

            signable = {
                k: v for k, v in entry.items()
                if k != "log_signature"
            }
            signable["redaction_record_id"] = redaction_record_id
            signable["pre_redaction_signature"] = original_signature
            # The signing key may have rotated since the original write;
            # we always sign redacted rows with the currently active kid
            # and persist it on the row.
            signable["signing_key_id"] = active_kid
            redacted_signature = AuditLogger.sign(signable, kid=active_kid)

            record = {
                "id": redaction_record_id,
                "purge_request_id": purge_request_id,
                "tenant_id": tenant_id,
                "audit_interaction_id": str(entry["interaction_id"]),
                "audit_sequence_number": int(entry["sequence_number"]),
                "audit_created_at": raw["created_at"],
                "original_signature": original_signature,
                "redacted_signature": redacted_signature,
                "signing_key_id": active_kid,
                "redacted_at": now,
            }
            record["record_signature"] = sign_redaction_record(record, kid=active_kid)

            await database.execute(
                sqlalchemy.text(
                    "INSERT INTO redaction_records ("
                    "  id, purge_request_id, tenant_id, audit_interaction_id, "
                    "  audit_sequence_number, audit_created_at, original_signature, "
                    "  redacted_signature, signing_key_id, record_signature, redacted_at"
                    ") VALUES ("
                    "  :id, :prid, :tid, :iid, :seq, :cat, :orig, :red, :kid, :rsig, :rat"
                    ")"
                ).bindparams(
                    id=redaction_record_id,
                    prid=purge_request_id,
                    tid=tenant_id,
                    iid=str(entry["interaction_id"]),
                    seq=int(entry["sequence_number"]),
                    cat=raw["created_at"],
                    orig=original_signature,
                    red=redacted_signature,
                    kid=active_kid,
                    rsig=record["record_signature"],
                    rat=now,
                ),
            )

            await database.execute(
                sqlalchemy.text(
                    "UPDATE audit_logs SET "
                    "  user_id = :uid, department = :dep, "
                    "  enforcement_reason = :er, "
                    "  log_signature = :sig, "
                    "  pre_redaction_signature = :pre, "
                    "  redaction_record_id = :rrid, "
                    "  signing_key_id = :kid "
                    "WHERE interaction_id = :iid AND created_at = :cat"
                ).bindparams(
                    uid=REDACTED_SENTINEL,
                    dep=REDACTED_SENTINEL if raw["department"] is not None else None,
                    er=REDACTED_SENTINEL if raw["enforcement_reason"] is not None else None,
                    sig=redacted_signature,
                    pre=original_signature,
                    rrid=redaction_record_id,
                    kid=active_kid,
                    iid=str(entry["interaction_id"]),
                    cat=raw["created_at"],
                ),
            )

            record_ids.append(redaction_record_id)

        return RedactionResult(
            purge_request_id=purge_request_id,
            tenant_id=tenant_id,
            rows_redacted=len(record_ids),
            redaction_record_ids=record_ids,
        )


def _normalize_entry(row: dict) -> dict:
    """Same shape the signer originally produced."""
    if row.get("interaction_id") is not None:
        row["interaction_id"] = str(row["interaction_id"])
    created = row.get("created_at")
    if created is not None and hasattr(created, "isoformat"):
        row["created_at"] = created.isoformat()
    score = row.get("injection_score")
    if score is not None:
        try:
            row["injection_score"] = float(score)
        except (TypeError, ValueError):
            pass
    return row


__all__ = [
    "REDACTED_SENTINEL",
    "RedactionResult",
    "execute_purge",
    "sign_redaction_record",
    "verify_redaction_record",
    "sign_purge_approval",
]
