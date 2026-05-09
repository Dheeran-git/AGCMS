"""Hash-chain verifier.

Given an ordered sequence of audit-log rows for one tenant, rebuild the
chain and report any discrepancy. Standalone from the writer so it can
run inside the audit service, the CLI bundle verifier, or a read replica.

The verifier is deterministic and side-effect-free — it does not write
to the database — which makes it safe to run under load.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

from agcms.audit.logger import AuditLogger


# The set of fields that go into an audit row's signature, excluding
# ``log_signature`` itself. Any mismatch between a row's stored hash
# and the recomputation over these fields is a tamper signal.
_CHAIN_ROW_FIELDS: frozenset[str] = frozenset(
    {
        "interaction_id",
        "tenant_id",
        "user_id",
        "department",
        "created_at",
        "llm_provider",
        "llm_model",
        "prompt_hash",
        "pii_detected",
        "pii_entity_types",
        "pii_risk_level",
        "injection_score",
        "injection_type",
        "enforcement_action",
        "enforcement_reason",
        "triggered_policies",
        "response_violated",
        "response_violations",
        "total_latency_ms",
        "previous_log_hash",
        "sequence_number",
        "signing_key_id",
    }
)


@dataclass
class ChainIssue:
    """One discrepancy found while replaying the chain."""

    kind: str            # 'gap' | 'reorder' | 'signature' | 'link' | 'unknown_kid' | 'missing_field' | 'legacy' | 'redaction'
    sequence_number: Optional[int]
    interaction_id: Optional[str]
    detail: str


@dataclass
class ChainReport:
    tenant_id: str
    rows_examined: int = 0
    chain_rows_examined: int = 0
    legacy_rows_skipped: int = 0
    first_sequence_number: Optional[int] = None
    last_sequence_number: Optional[int] = None
    last_log_signature: Optional[str] = None
    issues: List[ChainIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "ok": self.ok,
            "rows_examined": self.rows_examined,
            "chain_rows_examined": self.chain_rows_examined,
            "legacy_rows_skipped": self.legacy_rows_skipped,
            "first_sequence_number": self.first_sequence_number,
            "last_sequence_number": self.last_sequence_number,
            "last_log_signature": self.last_log_signature,
            "issues": [
                {
                    "kind": i.kind,
                    "sequence_number": i.sequence_number,
                    "interaction_id": i.interaction_id,
                    "detail": i.detail,
                }
                for i in self.issues
            ],
        }


def verify_chain(
    tenant_id: str,
    rows: Sequence[dict],
    *,
    expected_start_sequence: Optional[int] = None,
    expected_previous_hash: Optional[str] = None,
) -> ChainReport:
    """Replay ``rows`` as a chain for ``tenant_id``.

    ``rows`` must be ordered ascending by ``sequence_number``. Rows with
    ``sequence_number == 0`` are treated as legacy pre-chain entries and
    are not linked — they are counted but not inspected further.

    If ``expected_start_sequence`` / ``expected_previous_hash`` are
    supplied (e.g. verifying a slice mid-chain), the first chain row in
    the slice must match them.
    """
    report = ChainReport(tenant_id=tenant_id)
    previous_log_hash = expected_previous_hash or AuditLogger.ZERO_HASH
    previous_seq: Optional[int] = (
        expected_start_sequence - 1 if expected_start_sequence is not None else None
    )

    for row in rows:
        report.rows_examined += 1
        row_tenant = row.get("tenant_id")
        if row_tenant != tenant_id:
            report.issues.append(
                ChainIssue(
                    kind="tenant_mismatch",
                    sequence_number=row.get("sequence_number"),
                    interaction_id=_iid(row),
                    detail=f"row has tenant_id={row_tenant!r}, verifier expected {tenant_id!r}",
                )
            )
            continue

        seq = row.get("sequence_number")
        iid = _iid(row)

        if seq is None:
            report.issues.append(
                ChainIssue(
                    kind="missing_field",
                    sequence_number=None,
                    interaction_id=iid,
                    detail="row is missing sequence_number",
                )
            )
            continue

        if seq == 0:
            report.legacy_rows_skipped += 1
            continue

        # Gap / reorder detection
        if previous_seq is None:
            # First chain row in this slice
            if expected_start_sequence is not None and seq != expected_start_sequence:
                report.issues.append(
                    ChainIssue(
                        kind="reorder",
                        sequence_number=seq,
                        interaction_id=iid,
                        detail=(
                            f"first row sequence_number={seq} does not match "
                            f"expected_start_sequence={expected_start_sequence}"
                        ),
                    )
                )
            report.first_sequence_number = seq
        else:
            if seq < previous_seq + 1:
                report.issues.append(
                    ChainIssue(
                        kind="reorder",
                        sequence_number=seq,
                        interaction_id=iid,
                        detail=(
                            f"sequence_number {seq} is not greater than previous {previous_seq}"
                        ),
                    )
                )
                continue
            if seq > previous_seq + 1:
                report.issues.append(
                    ChainIssue(
                        kind="gap",
                        sequence_number=seq,
                        interaction_id=iid,
                        detail=(
                            f"gap between sequence_number {previous_seq} and {seq} "
                            f"(expected {previous_seq + 1})"
                        ),
                    )
                )

        # Previous-hash link check
        row_prev = row.get("previous_log_hash")
        if row_prev != previous_log_hash:
            report.issues.append(
                ChainIssue(
                    kind="link",
                    sequence_number=seq,
                    interaction_id=iid,
                    detail=(
                        f"previous_log_hash on row does not match previous row's signature "
                        f"(expected {previous_log_hash}, got {row_prev})"
                    ),
                )
            )

        # Signature check (constant-time compare inside AuditLogger.verify)
        missing = _CHAIN_ROW_FIELDS - row.keys()
        if missing:
            report.issues.append(
                ChainIssue(
                    kind="missing_field",
                    sequence_number=seq,
                    interaction_id=iid,
                    detail=f"row is missing required signing fields: {sorted(missing)}",
                )
            )
            # Cannot verify without the fields — advance pointers on what we have.
            previous_seq = seq
            previous_log_hash = row.get("log_signature") or previous_log_hash
            report.chain_rows_examined += 1
            report.last_sequence_number = seq
            report.last_log_signature = row.get("log_signature")
            continue

        verified = AuditLogger.verify(row)
        if not verified:
            # Distinguish unknown kid from bad signature so auditors get
            # actionable output.
            from agcms.audit.keys import REGISTRY

            kid = row.get("signing_key_id")
            if kid is None:
                report.issues.append(
                    ChainIssue(
                        kind="missing_field",
                        sequence_number=seq,
                        interaction_id=iid,
                        detail="row is missing signing_key_id",
                    )
                )
            elif not REGISTRY.has_row_kid(kid):
                report.issues.append(
                    ChainIssue(
                        kind="unknown_kid",
                        sequence_number=seq,
                        interaction_id=iid,
                        detail=(
                            f"no key material registered for kid {kid!r}; "
                            "row cannot be verified without it"
                        ),
                    )
                )
            else:
                report.issues.append(
                    ChainIssue(
                        kind="signature",
                        sequence_number=seq,
                        interaction_id=iid,
                        detail="recomputed HMAC does not match stored log_signature",
                    )
                )

        previous_seq = seq
        # A row's "outgoing hash" for chain linkage is normally its
        # log_signature. When the row has been tombstoned by a GDPR
        # Art. 17 purge, pre_redaction_signature holds the ORIGINAL
        # signature (captured before redaction) — that is what the
        # next row's previous_log_hash was set to at the time the
        # next row was written, so we use it for linkage continuity.
        outgoing = row.get("pre_redaction_signature") or row.get("log_signature")
        previous_log_hash = outgoing or previous_log_hash
        report.chain_rows_examined += 1
        report.last_sequence_number = seq
        report.last_log_signature = row.get("log_signature")

    return report


def _iid(row: dict) -> Optional[str]:
    v = row.get("interaction_id")
    return str(v) if v is not None else None


# ----------------------------------------------------------------------
# Database-backed entry point (used by API + CLI)
# ----------------------------------------------------------------------

async def verify_tenant_chain(
    tenant_id: str,
    *,
    start: Optional[str] = None,
    end: Optional[str] = None,
) -> ChainReport:
    """Stream every chain row for ``tenant_id`` in order and verify.

    ``start`` / ``end`` are ISO timestamps on ``created_at`` (inclusive).
    """
    import sqlalchemy
    from agcms.db import database

    where = ["tenant_id = :tid", "sequence_number > 0"]
    params: dict = {"tid": tenant_id}
    if start is not None:
        where.append("created_at >= :start")
        params["start"] = start
    if end is not None:
        where.append("created_at <= :end")
        params["end"] = end

    query = sqlalchemy.text(
        "SELECT interaction_id, tenant_id, user_id, department, created_at, "
        "llm_provider, llm_model, prompt_hash, pii_detected, pii_entity_types, "
        "pii_risk_level, injection_score, injection_type, enforcement_action, "
        "enforcement_reason, triggered_policies, response_violated, "
        "response_violations, total_latency_ms, log_signature, "
        "previous_log_hash, sequence_number, signing_key_id, "
        "redaction_record_id, pre_redaction_signature "
        f"FROM audit_logs WHERE {' AND '.join(where)} "
        "ORDER BY sequence_number ASC"
    ).bindparams(**params)

    raw_rows = await database.fetch_all(query)
    rows = [_normalize_row(dict(r)) for r in raw_rows]
    return verify_chain(tenant_id, rows)


def _normalize_row(row: dict) -> dict:
    """Coerce DB-native types to the JSON-native shapes the signer uses."""
    import json

    if row.get("interaction_id") is not None:
        row["interaction_id"] = str(row["interaction_id"])
    created = row.get("created_at")
    if created is not None and hasattr(created, "isoformat"):
        row["created_at"] = created.isoformat()
    score = row.get("injection_score")
    if score is not None:
        # Numeric -> float to match writer rounding.
        try:
            row["injection_score"] = float(score)
        except (TypeError, ValueError):
            pass
    # JSONB columns may come back as JSON-encoded strings from asyncpg.
    # The signer always works with Python-native values, so decode here.
    rv = row.get("response_violations")
    if isinstance(rv, str):
        try:
            row["response_violations"] = json.loads(rv)
        except Exception:
            pass
    # Signature compatibility: the signer only includes redaction_record_id
    # / pre_redaction_signature in the payload when they are set. So when
    # a non-redacted row is read from DB, those keys come back as None and
    # must be removed from the dict before verification — otherwise they
    # would be serialized as `null` and break the HMAC recomputation.
    if row.get("redaction_record_id") is None:
        row.pop("redaction_record_id", None)
    else:
        row["redaction_record_id"] = str(row["redaction_record_id"])
    if row.get("pre_redaction_signature") is None:
        row.pop("pre_redaction_signature", None)
    return row


__all__ = [
    "ChainIssue",
    "ChainReport",
    "verify_chain",
    "verify_tenant_chain",
]
