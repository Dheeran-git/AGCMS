"""End-to-end test for the audit bundle + portable verifier.

Builds a chain of rows in memory, generates a bundle, and runs
``tools/verify.py`` as a subprocess (with zero AGCMS imports) to confirm
it reports the bundle as intact. Then tampers a row and confirms the
verifier fails with exit code 1.
"""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Tuple

import pytest

from agcms.audit.logger import AuditLogger
from agcms.audit.merkle import compute_root


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFY_SCRIPT = REPO_ROOT / "tools" / "verify.py"


def _mk_signed_row(seq: int, prev_hash: str, *, tenant: str = "default") -> dict:
    row = {
        "interaction_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "user_id": "u1",
        "department": "Eng",
        "created_at": f"2026-04-01T12:00:{seq:02d}+00:00",
        "llm_provider": "groq",
        "llm_model": "llama-3.3-70b-versatile",
        "prompt_hash": hashlib.sha256(f"p-{seq}".encode()).hexdigest(),
        "pii_detected": False,
        "pii_entity_types": [],
        "pii_risk_level": "NONE",
        "injection_score": None,
        "injection_type": None,
        "enforcement_action": "ALLOW",
        "enforcement_reason": None,
        "triggered_policies": [],
        "response_violated": False,
        "response_violations": None,
        "total_latency_ms": 10,
        "previous_log_hash": prev_hash,
        "sequence_number": seq,
        "signing_key_id": "v1",
    }
    row["log_signature"] = AuditLogger.sign(row, kid="v1")
    return row


def _build_chain(n: int) -> List[dict]:
    rows: List[dict] = []
    prev = AuditLogger.ZERO_HASH
    for seq in range(1, n + 1):
        row = _mk_signed_row(seq, prev)
        rows.append(row)
        prev = row["log_signature"]
    return rows


def _build_bundle_zip(rows: List[dict]) -> bytes:
    """Assemble a bundle ZIP directly (no DB) so the subprocess verifier can run."""
    signatures = [r["log_signature"] for r in rows]
    root_hex = compute_root(signatures).hex()
    period_start = "2026-04-01T00:00:00+00:00"
    period_end = "2026-04-02T00:00:00+00:00"

    metadata = {
        "tenant_id": "default",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_start": period_start,
        "period_end": period_end,
        "row_count": len(rows),
        "chain_starts": {
            "default": {
                "expected_start_sequence": 1,
                "expected_previous_hash": AuditLogger.ZERO_HASH,
            }
        },
        "bundle_schema": "agcms.bundle/1",
        "hash_algorithm": "sha256",
        "tree_scheme": "tagged-leaf-tagged-node-duplicate-odd",
    }
    roots = [
        {
            "tenant_id": "default",
            "period_start": period_start,
            "period_end": period_end,
            "row_count": len(rows),
            "first_sequence_number": rows[0]["sequence_number"],
            "last_sequence_number": rows[-1]["sequence_number"],
            "merkle_root": root_hex,
            "signed_root": "00" * 32,  # not checked unless AGCMS_ANCHOR_KEY is set
            "anchor_key_id": "a1",
            "s3_url": None,
            "s3_object_version": None,
            "retention_until": "2033-04-02T00:00:00+00:00",
        }
    ]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("metadata.json", json.dumps(metadata))
        logs_body = "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n"
        zf.writestr("logs.jsonl", logs_body)
        zf.writestr("roots.json", json.dumps(roots))
        zf.writestr("README.md", "test bundle\n")
        zf.writestr("verify.py", VERIFY_SCRIPT.read_text(encoding="utf-8"))
    return buf.getvalue()


def _run_verifier(bundle_zip: bytes, tmp_path: Path) -> subprocess.CompletedProcess:
    bundle_path = tmp_path / "bundle.zip"
    bundle_path.write_bytes(bundle_zip)
    return subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), str(bundle_path)],
        capture_output=True,
        text=True,
        env={"PATH": "", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")},
    )


@pytest.mark.skipif(not VERIFY_SCRIPT.exists(), reason="tools/verify.py not present")
class TestPortableVerifier:
    def test_intact_bundle_passes(self, tmp_path):
        rows = _build_chain(5)
        result = _run_verifier(_build_bundle_zip(rows), tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "VERIFICATION PASSED" in result.stdout

    def test_tampered_signature_fails(self, tmp_path):
        rows = _build_chain(5)
        # The portable verifier has NO signing key — it detects tampering
        # via (a) chain linkage and (b) Merkle root over signatures. So
        # simulate an attacker who tried to substitute a row: the only
        # way that surfaces without the key is that log_signature changes,
        # which breaks BOTH the next row's previous_log_hash link AND the
        # Merkle root (which is computed over signatures). A content-only
        # tamper with the signature left intact is only detectable with
        # the key (that's the /verify/{interaction_id} path, not this one).
        rows[2]["log_signature"] = "ff" * 32
        result = _run_verifier(_build_bundle_zip(rows), tmp_path)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "FAILED" in result.stdout

    def test_dropped_row_fails(self, tmp_path):
        rows = _build_chain(5)
        rows.pop(2)  # drop seq=3 → gap between 2 and 4
        result = _run_verifier(_build_bundle_zip(rows), tmp_path)
        assert result.returncode == 1, result.stdout + result.stderr

    def test_reordered_rows_fail(self, tmp_path):
        rows = _build_chain(5)
        rows[1], rows[2] = rows[2], rows[1]
        # Recompute roots for the reordered list to isolate the chain check
        result = _run_verifier(_build_bundle_zip(rows), tmp_path)
        assert result.returncode == 1, result.stdout + result.stderr

    def test_wrong_merkle_root_fails(self, tmp_path):
        rows = _build_chain(5)
        zip_bytes = _build_bundle_zip(rows)
        # Post-process the bundle to corrupt the published merkle_root
        buf = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buf, "r") as zin:
            parts = {n: zin.read(n) for n in zin.namelist()}
        roots = json.loads(parts["roots.json"])
        roots[0]["merkle_root"] = "ff" * 32
        parts["roots.json"] = json.dumps(roots).encode()
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
            for n, b in parts.items():
                zout.writestr(n, b)
        result = _run_verifier(out.getvalue(), tmp_path)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Merkle root mismatch" in result.stdout
