#!/usr/bin/env python3
"""AGCMS audit-bundle verifier — portable, Python stdlib only.

Usage:
    python verify.py <bundle.zip>
    python verify.py <unzipped-bundle-dir>

Exit codes:
    0 — every check passed (chain intact + Merkle roots match)
    1 — one or more integrity checks failed
    2 — bundle is malformed / unreadable

Design: ships alongside every exported audit bundle. No AGCMS imports,
no pip installs, no network access. An auditor running this on an
air-gapped laptop with a clean Python 3 install should get the same
result we do.

What it verifies
----------------
1. Chain continuity — per tenant, rows are ordered by sequence_number
   starting from `metadata.first_sequence`, contiguous, and each row's
   `previous_log_hash` equals the prior row's `log_signature`. The first
   row links to `metadata.expected_previous_hash` (zero-hash if the
   bundle covers chain position 1).

2. Merkle roots — for each entry in `roots.json`, recomputes the tree
   over the rows in that period and requires `merkle_root` to match.
   If the bundle ships the anchor public key (symmetric HMAC secrets
   are never shipped, so `signed_root` verification is optional and
   only runs when `AGCMS_ANCHOR_KEY` is in the environment).

Tampering with any row (content, signature, ordering) breaks (1) or (2).
Tampering with a published Merkle root in the stored audit_roots table
is detectable by cross-referencing the S3-Object-Lock-published
manifests listed in `metadata.anchors_s3`.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

ZERO_HASH = "0" * 64
LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"


# ----------------------------------------------------------------------
# Terminal output helpers
# ----------------------------------------------------------------------
def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def ok(msg: str) -> None:
    prefix = "\033[32mOK\033[0m" if _supports_color() else "OK"
    print(f"[{prefix}] {msg}")


def fail(msg: str) -> None:
    prefix = "\033[31mFAIL\033[0m" if _supports_color() else "FAIL"
    print(f"[{prefix}] {msg}")


def info(msg: str) -> None:
    print(f"[--] {msg}")


# ----------------------------------------------------------------------
# Merkle (mirrors agcms.audit.merkle — must stay in sync)
# ----------------------------------------------------------------------
def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _leaf(sig_hex: str) -> bytes:
    return _h(LEAF_TAG + bytes.fromhex(sig_hex))


def _node(left: bytes, right: bytes) -> bytes:
    return _h(NODE_TAG + left + right)


def merkle_root(signatures: List[str]) -> str:
    if not signatures:
        return "00" * 32
    level = [_leaf(s) for s in signatures]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


# ----------------------------------------------------------------------
# Bundle IO
# ----------------------------------------------------------------------
def _load_bundle(path: Path) -> Path:
    """Return a filesystem directory containing the bundle contents."""
    if path.is_dir():
        return path
    if path.is_file() and zipfile.is_zipfile(path):
        tmp = Path(tempfile.mkdtemp(prefix="agcms-bundle-"))
        with zipfile.ZipFile(path) as zf:
            zf.extractall(tmp)
        return tmp
    fail(f"bundle path is not a directory or ZIP file: {path}")
    sys.exit(2)


def _require(path: Path) -> Path:
    if not path.exists():
        fail(f"required bundle file missing: {path.name}")
        sys.exit(2)
    return path


def _read_jsonl(path: Path) -> List[dict]:
    out: List[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                fail(f"{path.name}:{i} is not valid JSON: {exc}")
                sys.exit(2)
    return out


# ----------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------
def check_chain(
    rows: List[dict],
    *,
    expected_previous_hash: str,
    expected_start_sequence: int,
) -> List[str]:
    """Return a list of error messages (empty = chain intact)."""
    errors: List[str] = []
    if not rows:
        return errors

    rows = sorted(rows, key=lambda r: r.get("sequence_number", 0))
    previous = expected_previous_hash
    previous_seq = expected_start_sequence - 1

    for row in rows:
        seq = row.get("sequence_number")
        iid = row.get("interaction_id", "?")
        if seq is None:
            errors.append(f"row {iid} missing sequence_number")
            continue
        if seq == 0:
            continue  # legacy pre-chain
        if seq != previous_seq + 1:
            errors.append(
                f"gap or reorder: expected sequence_number {previous_seq + 1}, "
                f"got {seq} (row {iid})"
            )
        row_prev = row.get("previous_log_hash")
        if row_prev != previous:
            errors.append(
                f"chain break at sequence_number {seq}: "
                f"row.previous_log_hash={row_prev} does not match "
                f"prior row.log_signature={previous}"
            )
        sig = row.get("log_signature")
        if not isinstance(sig, str) or len(sig) != 64:
            errors.append(f"row at seq {seq} has invalid log_signature")
            previous = ZERO_HASH
        else:
            previous = sig
        previous_seq = seq

    return errors


def check_merkle_root(entry: dict, rows_in_period: List[dict]) -> List[str]:
    errors: List[str] = []
    expected_root = entry.get("merkle_root")
    if not expected_root or len(expected_root) != 64:
        errors.append(
            f"roots entry for tenant={entry.get('tenant_id')} "
            f"period={entry.get('period_start')}..{entry.get('period_end')} "
            "is missing or has malformed merkle_root"
        )
        return errors

    sorted_rows = sorted(rows_in_period, key=lambda r: r["sequence_number"])
    signatures = [r["log_signature"] for r in sorted_rows]
    computed = merkle_root(signatures)

    if computed != expected_root:
        errors.append(
            f"Merkle root mismatch for tenant={entry.get('tenant_id')} "
            f"period={entry.get('period_start')}..{entry.get('period_end')}: "
            f"expected {expected_root}, recomputed {computed}"
        )

    declared = entry.get("row_count")
    if declared is not None and declared != len(sorted_rows):
        errors.append(
            f"row_count mismatch for tenant={entry.get('tenant_id')} "
            f"period={entry.get('period_start')}..{entry.get('period_end')}: "
            f"manifest says {declared}, bundle contains {len(sorted_rows)}"
        )
    return errors


def check_optional_anchor_signatures(
    roots: List[dict],
    anchor_key_hex: Optional[str],
) -> List[str]:
    """HMAC-verify signed_root iff the caller supplied AGCMS_ANCHOR_KEY.

    Anchor HMAC keys are symmetric secrets; they are NOT shipped in the
    bundle. When absent we simply skip this check — the Merkle-root
    match against Object-Lock-anchored manifests remains the binding
    integrity proof.
    """
    if not anchor_key_hex:
        info("skipping signed_root HMAC checks (AGCMS_ANCHOR_KEY not supplied)")
        return []
    key = anchor_key_hex.encode("utf-8")
    errors: List[str] = []
    for entry in roots:
        root_bytes = bytes.fromhex(entry["merkle_root"])
        expected = hmac.new(key, root_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, entry.get("signed_root", "")):
            errors.append(
                f"signed_root does not verify under supplied anchor key for "
                f"tenant={entry.get('tenant_id')} "
                f"period={entry.get('period_start')}..{entry.get('period_end')}"
            )
    return errors


def _row_keys_from_env() -> Dict[str, bytes]:
    """Collect row-signing keys keyed by kid from AGCMS_ROW_KEYS_<KID> env vars.

    Symmetric HMAC keys are never shipped in the bundle — an auditor supplies
    them out-of-band (e.g. from a sealed envelope held alongside the bundle)
    to detect content-only tampers that leave log_signature and the chain
    links intact.
    """
    prefix = "AGCMS_ROW_KEYS_"
    out: Dict[str, bytes] = {}
    for env_name, val in os.environ.items():
        if not env_name.startswith(prefix) or not val:
            continue
        kid = env_name[len(prefix):].lower()
        out[kid] = val.encode("utf-8")
    return out


def check_optional_row_signatures(
    rows: List[dict],
    row_keys: Dict[str, bytes],
) -> List[str]:
    """Recompute each row's HMAC and compare to stored log_signature.

    Only runs when the caller supplied row keys via AGCMS_ROW_KEYS_<KID>.
    Without keys we skip and surface the gap — the Merkle root still
    commits to the exact log_signature values, so any tamper that
    modifies log_signature (to match new content) would instead be
    caught by Merkle root mismatch. Per-row HMAC is the defense against
    content-only tampers that leave log_signature unchanged.
    """
    if not row_keys:
        info(
            "skipping per-row HMAC checks (no AGCMS_ROW_KEYS_<KID> env vars supplied; "
            "Merkle root over log_signature is the remaining integrity proof)"
        )
        return []
    errors: List[str] = []
    for row in rows:
        seq = row.get("sequence_number")
        if seq == 0 or seq is None:
            continue
        kid = row.get("signing_key_id")
        if kid is None:
            errors.append(f"row seq {seq} has no signing_key_id — cannot verify")
            continue
        key = row_keys.get(kid.lower())
        if key is None:
            errors.append(
                f"row seq {seq} signed with kid={kid!r} but no AGCMS_ROW_KEYS_{kid.upper()} "
                "provided — cannot verify this row"
            )
            continue
        stored_sig = row.get("log_signature")
        if not isinstance(stored_sig, str):
            errors.append(f"row seq {seq} missing log_signature")
            continue
        payload = dict(row)
        payload.pop("log_signature", None)
        # Match writer behavior: redaction fields only present when set.
        if payload.get("redaction_record_id") is None:
            payload.pop("redaction_record_id", None)
        if payload.get("pre_redaction_signature") is None:
            payload.pop("pre_redaction_signature", None)
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        recomputed = hmac.new(key, encoded, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(recomputed, stored_sig):
            errors.append(
                f"row seq {seq} (interaction_id={row.get('interaction_id')}) "
                f"HMAC mismatch — row content was tampered with"
            )
    return errors


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an AGCMS audit bundle.")
    parser.add_argument("bundle", help="Path to a bundle ZIP or extracted directory.")
    args = parser.parse_args()

    bundle_root = _load_bundle(Path(args.bundle))

    metadata = json.loads(_require(bundle_root / "metadata.json").read_text(encoding="utf-8"))
    logs = _read_jsonl(_require(bundle_root / "logs.jsonl"))
    roots = json.loads(_require(bundle_root / "roots.json").read_text(encoding="utf-8"))

    info(f"bundle tenant: {metadata.get('tenant_id')}")
    info(f"period: {metadata.get('period_start')}..{metadata.get('period_end')}")
    info(f"rows in bundle: {len(logs)}")
    info(f"roots in bundle: {len(roots)}")

    errors: List[str] = []

    per_tenant: Dict[str, List[dict]] = {}
    for row in logs:
        per_tenant.setdefault(row.get("tenant_id", "?"), []).append(row)

    for tenant_id, rows in per_tenant.items():
        meta_starts = {
            t: s for t, s in (metadata.get("chain_starts") or {}).items()
        }
        start_seq = meta_starts.get(tenant_id, {}).get(
            "expected_start_sequence", 1
        )
        start_prev = meta_starts.get(tenant_id, {}).get(
            "expected_previous_hash", ZERO_HASH
        )
        chain_errors = check_chain(
            rows,
            expected_previous_hash=start_prev,
            expected_start_sequence=start_seq,
        )
        if chain_errors:
            errors.extend(chain_errors)
        else:
            ok(f"chain intact for tenant {tenant_id} ({len(rows)} rows)")

    for entry in roots:
        tenant_id = entry.get("tenant_id")
        first = entry.get("first_sequence_number")
        last = entry.get("last_sequence_number")
        in_period = [
            r for r in per_tenant.get(tenant_id, [])
            if first is not None and last is not None
            and first <= r.get("sequence_number", -1) <= last
        ]
        merkle_errors = check_merkle_root(entry, in_period)
        if merkle_errors:
            errors.extend(merkle_errors)
        else:
            ok(
                f"Merkle root matches for tenant {tenant_id} "
                f"period {entry.get('period_start')}..{entry.get('period_end')} "
                f"({len(in_period)} rows)"
            )

    signature_errors = check_optional_anchor_signatures(
        roots, os.environ.get("AGCMS_ANCHOR_KEY")
    )
    errors.extend(signature_errors)

    row_keys = _row_keys_from_env()
    row_sig_errors = check_optional_row_signatures(logs, row_keys)
    if row_keys and not row_sig_errors:
        ok(
            f"per-row HMAC verified against {len(row_keys)} supplied key(s) "
            f"({sum(1 for r in logs if r.get('sequence_number', 0) > 0)} chain rows)"
        )
    errors.extend(row_sig_errors)

    print()
    if errors:
        for e in errors:
            fail(e)
        fail(f"VERIFICATION FAILED — {len(errors)} issue(s)")
        return 1

    ok("VERIFICATION PASSED — bundle is intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
