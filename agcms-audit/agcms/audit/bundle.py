"""Audit-bundle builder.

Packages a tenant's chain rows + Merkle-root anchors + portable verifier
script into a single ZIP an external auditor can verify offline. The
wedge claim — "legally defensible, third-party-verifiable audit trail"
— becomes concretely demonstrable through this artifact.

Bundle contents:
    metadata.json   Bundle descriptor (tenant, period, chain start hints).
    logs.jsonl      One audit row per line, full signing payload + signature.
    roots.json      Merkle roots for every (tenant, period) overlap.
    README.md       Auditor-facing instructions.
    verify.py       Portable stdlib-only verifier (copied from tools/).

The verifier script validates:
    (a) per-tenant hash-chain continuity (no key needed), and
    (b) Merkle root recomputation against each ``audit_roots`` entry
        (no key needed).
If ``AGCMS_ANCHOR_KEY`` is supplied in the environment at verify time,
the verifier additionally HMAC-checks each ``signed_root``.
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Optional

import sqlalchemy

from agcms.audit.logger import AuditLogger
from agcms.db import database

_VERIFIER_PATH = (
    Path(__file__).resolve().parents[3] / "tools" / "verify.py"
)

_README = """# AGCMS Audit Bundle

This bundle is a self-contained, offline-verifiable record of one
tenant's AI-governance audit log over a fixed time window.

## What's inside

| File             | Purpose |
|------------------|---------|
| metadata.json    | Bundle descriptor (tenant, period, chain start hints). |
| logs.jsonl       | One audit row per line, with all fields covered by the HMAC signature. |
| roots.json       | Merkle-root anchors (one per day) for the period, signed with the anchor key. |
| verify.py        | Portable verifier — requires Python 3 only, no dependencies. |

## How to verify

    python3 verify.py .

Exit code 0 = bundle is intact. Exit code 1 = one or more checks failed
(the script prints a precise, line-by-line error report).

## What the verifier proves

1. **Chain continuity** — every row's `previous_log_hash` matches the
   preceding row's `log_signature`, sequence numbers are contiguous, and
   no rows were reordered. This is checked WITHOUT needing the signing
   key — tampering breaks either the sequence or the hash link.

2. **Merkle root match** — for every entry in `roots.json`, the
   verifier recomputes the Merkle tree over the in-period rows and
   confirms `merkle_root` matches. This is checked WITHOUT needing the
   key either.

The stored `merkle_root` values in our `audit_roots` table correspond
one-to-one with signed manifests we publish to an S3 bucket under Object
Lock (Compliance mode). An auditor can cross-reference any root against
those immutable S3 objects to rule out retroactive edits to our database.

If an auditor is given the anchor key out-of-band, they can run

    AGCMS_ANCHOR_KEY=<hex> python3 verify.py .

to also HMAC-verify each `signed_root`.

## Scheme reference

* Row signature: HMAC-SHA256 over `json.dumps(entry, sort_keys=True)`
  where `entry` excludes `log_signature` itself.
* Merkle tree: tagged-leaf/tagged-node, duplicate-odd.
  `leaf(s) = SHA256(0x00 || bytes.fromhex(s))`,
  `node(l, r) = SHA256(0x01 || l || r)`.
* Anchor signature: HMAC-SHA256 over the 32-byte Merkle root.

## Contact

For questions about this bundle, contact the issuing tenant's
compliance administrator or AGCMS support.
"""


async def build_bundle(
    tenant_id: str,
    *,
    period_start: datetime,
    period_end: datetime,
) -> bytes:
    """Return the bytes of a ZIP containing the bundle for the given slice."""
    rows = await _fetch_rows(tenant_id, period_start, period_end)
    roots = await _fetch_roots(tenant_id, period_start, period_end)

    first_seq, prev_hash = await _chain_start_hints(tenant_id, period_start)

    metadata = {
        "tenant_id": tenant_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "row_count": len(rows),
        "chain_starts": {
            tenant_id: {
                "expected_start_sequence": first_seq,
                "expected_previous_hash": prev_hash,
            }
        },
        "bundle_schema": "agcms.bundle/1",
        "hash_algorithm": "sha256",
        "tree_scheme": "tagged-leaf-tagged-node-duplicate-odd",
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("metadata.json", json.dumps(metadata, indent=2, sort_keys=True))

        logs_buf = io.StringIO()
        for row in rows:
            logs_buf.write(json.dumps(row, sort_keys=True, default=_json_default))
            logs_buf.write("\n")
        zf.writestr("logs.jsonl", logs_buf.getvalue())

        zf.writestr("roots.json", json.dumps(roots, indent=2, sort_keys=True, default=_json_default))
        zf.writestr("README.md", _README)

        if _VERIFIER_PATH.exists():
            zf.writestr("verify.py", _VERIFIER_PATH.read_text(encoding="utf-8"))
        else:
            # Still ship a stub so the bundle structure is honest.
            zf.writestr(
                "verify.py",
                "# verify.py was not available at bundle generation time. "
                "Contact the AGCMS team for the portable verifier.\n",
            )

    return buf.getvalue()


async def _fetch_rows(tenant_id: str, start: datetime, end: datetime) -> list[dict]:
    rows = await database.fetch_all(
        sqlalchemy.text(
            "SELECT interaction_id, tenant_id, user_id, department, created_at, "
            "llm_provider, llm_model, prompt_hash, pii_detected, pii_entity_types, "
            "pii_risk_level, injection_score, injection_type, enforcement_action, "
            "enforcement_reason, triggered_policies, response_violated, "
            "response_violations, total_latency_ms, log_signature, "
            "previous_log_hash, sequence_number, signing_key_id "
            "FROM audit_logs WHERE tenant_id = :tid "
            "AND sequence_number > 0 "
            "AND created_at >= :start AND created_at < :end "
            "ORDER BY sequence_number ASC"
        ).bindparams(tid=tenant_id, start=start, end=end),
    )
    return [_normalize_row(dict(r)) for r in rows]


async def _fetch_roots(tenant_id: str, start: datetime, end: datetime) -> list[dict]:
    rows = await database.fetch_all(
        sqlalchemy.text(
            "SELECT tenant_id, period_start, period_end, row_count, "
            "first_sequence_number, last_sequence_number, merkle_root, "
            "signed_root, anchor_key_id, s3_url, s3_object_version, retention_until "
            "FROM audit_roots WHERE tenant_id = :tid "
            "AND period_end > :start AND period_start < :end "
            "ORDER BY period_start ASC"
        ).bindparams(tid=tenant_id, start=start, end=end),
    )
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        for k in ("period_start", "period_end", "retention_until"):
            if d.get(k) is not None and hasattr(d[k], "isoformat"):
                d[k] = d[k].isoformat()
        out.append(d)
    return out


async def _chain_start_hints(tenant_id: str, period_start: datetime) -> tuple[int, str]:
    """Return the sequence_number and log_signature the bundle's first row must link to.

    If there is no prior chain row, the first row must link to ZERO_HASH at sequence 1.
    """
    row = await database.fetch_one(
        sqlalchemy.text(
            "SELECT sequence_number, log_signature FROM audit_logs "
            "WHERE tenant_id = :tid AND sequence_number > 0 AND created_at < :start "
            "ORDER BY sequence_number DESC LIMIT 1"
        ).bindparams(tid=tenant_id, start=period_start),
    )
    if row is None:
        return 1, AuditLogger.ZERO_HASH
    return int(row["sequence_number"]) + 1, row["log_signature"]


def _normalize_row(row: dict) -> dict:
    """Shape the DB row to match the exact signing payload."""
    if row.get("interaction_id") is not None:
        row["interaction_id"] = str(row["interaction_id"])
    created = row.get("created_at")
    if created is not None and hasattr(created, "isoformat"):
        row["created_at"] = created.isoformat()
    score = row.get("injection_score")
    if isinstance(score, Decimal):
        row["injection_score"] = float(score)
    rv = row.get("response_violations")
    if isinstance(rv, str):
        try:
            row["response_violations"] = json.loads(rv)
        except json.JSONDecodeError:
            pass
    if row.get("pii_entity_types") is None:
        row["pii_entity_types"] = []
    if row.get("triggered_policies") is None:
        row["triggered_policies"] = []
    return row


def _json_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


__all__ = ["build_bundle"]
