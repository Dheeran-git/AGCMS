"""Unit tests for the hash-chain verifier.

Builds synthetic chains in-memory (no DB), applies various tamper
patterns, and asserts the verifier flags them with the expected
``ChainIssue.kind``.
"""
from __future__ import annotations

import hashlib
import uuid
from copy import deepcopy
from typing import List

import pytest

from agcms.audit.chain_verifier import ChainIssue, verify_chain
from agcms.audit.logger import AuditLogger


TENANT = "default"


def _mk_row(
    seq: int,
    previous_log_hash: str,
    *,
    action: str = "ALLOW",
    interaction_id: str | None = None,
    signing_key_id: str = "v1",
) -> dict:
    """Build a fully-populated, correctly-signed row at sequence ``seq``."""
    row = {
        "interaction_id": interaction_id or str(uuid.uuid4()),
        "tenant_id": TENANT,
        "user_id": "test-user",
        "department": "Engineering",
        "created_at": f"2026-04-01T12:00:{seq:02d}+00:00",
        "llm_provider": "groq",
        "llm_model": "llama-3.3-70b-versatile",
        "prompt_hash": hashlib.sha256(f"prompt-{seq}".encode()).hexdigest(),
        "pii_detected": False,
        "pii_entity_types": [],
        "pii_risk_level": "NONE",
        "injection_score": None,
        "injection_type": None,
        "enforcement_action": action,
        "enforcement_reason": None,
        "triggered_policies": [],
        "response_violated": False,
        "response_violations": None,
        "total_latency_ms": 10 + seq,
        "previous_log_hash": previous_log_hash,
        "sequence_number": seq,
        "signing_key_id": signing_key_id,
    }
    row["log_signature"] = AuditLogger.sign(row, kid=signing_key_id)
    return row


def _build_chain(length: int) -> List[dict]:
    rows: List[dict] = []
    previous = AuditLogger.ZERO_HASH
    for seq in range(1, length + 1):
        row = _mk_row(seq, previous)
        rows.append(row)
        previous = row["log_signature"]
    return rows


class TestCleanChain:
    def test_10_row_chain_verifies(self):
        rows = _build_chain(10)
        report = verify_chain(TENANT, rows)
        assert report.ok, report.issues
        assert report.chain_rows_examined == 10
        assert report.first_sequence_number == 1
        assert report.last_sequence_number == 10
        assert report.last_log_signature == rows[-1]["log_signature"]

    def test_empty_chain_is_ok(self):
        report = verify_chain(TENANT, [])
        assert report.ok
        assert report.rows_examined == 0

    def test_legacy_rows_are_skipped_not_flagged(self):
        # Legacy rows have sequence_number=0 and signing_key_id='v0'; the
        # verifier must skip them without trying to recompute the HMAC
        # (since 'v0' has no key material in the runtime registry).
        legacy = {
            "interaction_id": str(uuid.uuid4()),
            "tenant_id": TENANT,
            "sequence_number": 0,
            "signing_key_id": "v0",
            "log_signature": "deadbeef" * 8,
        }
        rows = [legacy] + _build_chain(3)
        report = verify_chain(TENANT, rows)
        assert report.ok, report.issues
        assert report.legacy_rows_skipped == 1
        assert report.chain_rows_examined == 3


class TestTamperDetection:
    def test_truncation_detected_as_gap_when_slice_start_is_known(self):
        """Dropping row 5 from a 10-row chain → gap between 4 and 6."""
        rows = _build_chain(10)
        rows.pop(4)  # remove seq=5
        report = verify_chain(TENANT, rows)
        assert not report.ok
        gaps = [i for i in report.issues if i.kind == "gap"]
        assert any(i.sequence_number == 6 for i in gaps)

    def test_row_substitution_detected(self):
        """Replace row 5's enforcement_action but keep its signature → sig mismatch."""
        rows = _build_chain(10)
        rows[4]["enforcement_action"] = "BLOCK"
        # signature is now stale
        report = verify_chain(TENANT, rows)
        sig_issues = [i for i in report.issues if i.kind == "signature"]
        assert any(i.sequence_number == 5 for i in sig_issues), report.issues

    def test_previous_hash_break_detected(self):
        """Tampering previous_log_hash on row 5 → link break AND sig mismatch."""
        rows = _build_chain(10)
        rows[4]["previous_log_hash"] = "a" * 64
        report = verify_chain(TENANT, rows)
        kinds = {i.kind for i in report.issues if i.sequence_number == 5}
        assert "link" in kinds

    def test_reorder_detected(self):
        """Swap two rows → reorder flag on the later-seq one that appears first."""
        rows = _build_chain(5)
        rows[2], rows[3] = rows[3], rows[2]  # now order is 1, 2, 4, 3, 5
        report = verify_chain(TENANT, rows)
        reorders = [i for i in report.issues if i.kind == "reorder"]
        assert any(i.sequence_number == 3 for i in reorders)

    def test_unknown_kid_is_called_out_distinctly(self):
        """A row signed by an unregistered kid should report unknown_kid, not signature."""
        rows = _build_chain(3)
        rows[1]["signing_key_id"] = "ghost-kid-not-in-env"
        report = verify_chain(TENANT, rows)
        kinds = [i.kind for i in report.issues if i.sequence_number == 2]
        assert "unknown_kid" in kinds

    def test_tenant_mismatch_on_row(self):
        rows = _build_chain(3)
        rows[1]["tenant_id"] = "evil-tenant"
        report = verify_chain(TENANT, rows)
        assert any(i.kind == "tenant_mismatch" for i in report.issues)

    def test_backfill_detected_via_signature(self):
        """Inserting a valid-looking row between 3 and 4 → link break at 4."""
        rows = _build_chain(5)
        # Craft a backfilled row that claims seq=4 but won't match the real chain.
        fake = _mk_row(4, rows[2]["log_signature"], action="BLOCK")
        rows[3] = fake
        # Row 5 was signed over the OLD row 4 signature, so its
        # previous_log_hash no longer matches → link break.
        report = verify_chain(TENANT, rows)
        assert not report.ok
        assert any(i.kind == "link" and i.sequence_number == 5 for i in report.issues)


class TestMissingFields:
    def test_missing_sequence_number(self):
        rows = _build_chain(3)
        del rows[1]["sequence_number"]
        report = verify_chain(TENANT, rows)
        assert any(i.kind == "missing_field" for i in report.issues)

    def test_missing_signing_key_id_causes_signature_or_missing(self):
        rows = _build_chain(3)
        del rows[1]["signing_key_id"]
        report = verify_chain(TENANT, rows)
        # Either way, something is flagged — the row is not verifiable.
        assert not report.ok


class TestSliceVerification:
    def test_slice_with_expected_start_hash_verifies(self):
        rows = _build_chain(10)
        slice_rows = rows[4:8]  # seq 5..8
        report = verify_chain(
            TENANT,
            slice_rows,
            expected_start_sequence=5,
            expected_previous_hash=rows[3]["log_signature"],
        )
        assert report.ok, report.issues

    def test_slice_with_wrong_start_hash_flagged(self):
        rows = _build_chain(10)
        slice_rows = rows[4:8]
        report = verify_chain(
            TENANT,
            slice_rows,
            expected_start_sequence=5,
            expected_previous_hash="0" * 64,  # wrong
        )
        assert not report.ok
        assert any(i.kind == "link" for i in report.issues)
