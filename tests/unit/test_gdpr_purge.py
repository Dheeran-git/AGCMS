"""Phase 6.6 — GDPR Article 17 purge unit tests.

Covers:
  * Redaction record signing + verification (cryptographic primitives)
  * Purge-approval signing
  * Chain verifier correctness after redaction (linkage preserved via
    ``pre_redaction_signature``)
  * Gateway endpoints — two-admin rule, 24h approval window, state
    transitions, RBAC gating.

The executor (``agcms.audit.redaction.execute_purge``) is exercised by
simulating its end-state manually (redacting rows + writing
``redaction_records`` rows), then handing the mutated chain to the
verifier. This avoids needing a real DB in unit tests.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")
os.environ.setdefault("AGCMS_SIGNING_KEY", "test-row-signing-key-phase-5-fixture")
os.environ.setdefault("AGCMS_ANCHOR_KEY", "test-anchor-key-phase-5-fixture")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agcms.audit.chain_verifier import verify_chain  # noqa: E402
from agcms.audit.logger import AuditLogger  # noqa: E402
from agcms.audit.redaction import (  # noqa: E402
    REDACTED_SENTINEL,
    sign_purge_approval,
    sign_redaction_record,
    verify_redaction_record,
)
from agcms.gateway.auth import AuthContext  # noqa: E402
from agcms.gateway.gdpr import router as gdpr_router  # noqa: E402
from agcms.gateway.rbac import get_current_auth  # noqa: E402


TENANT = "t1"


# ======================================================================
# Helpers
# ======================================================================


def _mk_row(
    seq: int,
    previous: str,
    *,
    user_id: str = "alice",
    department: str = "Engineering",
    interaction_id: str | None = None,
) -> dict:
    row = {
        "interaction_id": interaction_id or str(uuid.uuid4()),
        "tenant_id": TENANT,
        "user_id": user_id,
        "department": department,
        "created_at": f"2026-04-01T12:00:{seq:02d}+00:00",
        "llm_provider": "groq",
        "llm_model": "llama-3.3-70b-versatile",
        "prompt_hash": hashlib.sha256(f"prompt-{seq}".encode()).hexdigest(),
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
        "total_latency_ms": 10 + seq,
        "previous_log_hash": previous,
        "sequence_number": seq,
        "signing_key_id": "v1",
    }
    row["log_signature"] = AuditLogger.sign(row, kid="v1")
    return row


def _build_chain(length: int, *, user_id: str = "alice") -> list[dict]:
    rows: list[dict] = []
    prev = AuditLogger.ZERO_HASH
    for seq in range(1, length + 1):
        row = _mk_row(seq, prev, user_id=user_id)
        rows.append(row)
        prev = row["log_signature"]
    return rows


def _simulate_redaction(row: dict, purge_request_id: str) -> dict:
    """Produce the post-redaction shape for a single audit row.

    Mirrors what ``agcms.audit.redaction.execute_purge`` does in-DB:
      1. Overwrite PII fields with the sentinel.
      2. Add ``redaction_record_id`` + ``pre_redaction_signature`` to the
         signing payload.
      3. Recompute ``log_signature``.
    """
    original_signature = row["log_signature"]
    redaction_record_id = str(uuid.uuid4())
    redacted = dict(row)
    for col in ("user_id", "department", "enforcement_reason"):
        if redacted.get(col) is not None:
            redacted[col] = REDACTED_SENTINEL
    redacted["redaction_record_id"] = redaction_record_id
    redacted["pre_redaction_signature"] = original_signature
    redacted.pop("log_signature", None)
    redacted["log_signature"] = AuditLogger.sign(redacted, kid="v1")
    redacted["_redaction_record"] = {
        "id": redaction_record_id,
        "purge_request_id": purge_request_id,
        "audit_interaction_id": row["interaction_id"],
        "audit_sequence_number": row["sequence_number"],
        "original_signature": original_signature,
        "redacted_signature": redacted["log_signature"],
        "redacted_at": datetime.now(timezone.utc),
        "signing_key_id": "v1",
    }
    redacted["_redaction_record"]["record_signature"] = sign_redaction_record(
        redacted["_redaction_record"], kid="v1"
    )
    return redacted


# ======================================================================
# 1. Cryptographic primitives
# ======================================================================


class TestRedactionRecordSignature:
    def _record(self) -> dict:
        return {
            "purge_request_id": str(uuid.uuid4()),
            "audit_interaction_id": str(uuid.uuid4()),
            "audit_sequence_number": 42,
            "original_signature": "a" * 64,
            "redacted_signature": "b" * 64,
            "redacted_at": datetime(2026, 4, 21, 12, 0, tzinfo=timezone.utc),
            "signing_key_id": "v1",
        }

    def test_sign_is_deterministic(self):
        r = self._record()
        s1 = sign_redaction_record(r, kid="v1")
        s2 = sign_redaction_record(r, kid="v1")
        assert s1 == s2

    def test_verify_accepts_correctly_signed_record(self):
        r = self._record()
        r["record_signature"] = sign_redaction_record(r, kid="v1")
        assert verify_redaction_record(r) is True

    def test_verify_rejects_tampered_original_signature(self):
        r = self._record()
        r["record_signature"] = sign_redaction_record(r, kid="v1")
        r["original_signature"] = "c" * 64
        assert verify_redaction_record(r) is False

    def test_verify_rejects_missing_signature(self):
        r = self._record()
        assert verify_redaction_record(r) is False

    def test_verify_rejects_swapped_fields(self):
        r = self._record()
        r["record_signature"] = sign_redaction_record(r, kid="v1")
        # Attacker swaps the original + redacted — MAC no longer matches.
        r["original_signature"], r["redacted_signature"] = (
            r["redacted_signature"], r["original_signature"],
        )
        assert verify_redaction_record(r) is False


class TestPurgeApprovalSignature:
    def _req(self) -> dict:
        now = datetime(2026, 4, 21, 12, 0, tzinfo=timezone.utc)
        return {
            "id": uuid.uuid4(),
            "tenant_id": TENANT,
            "subject_user_id": "alice@example.com",
            "requested_by": uuid.uuid4(),
            "requested_at": now,
            "approved_by": uuid.uuid4(),
            "approved_at": now + timedelta(hours=2),
            "reason": "Data subject request #DSR-42",
        }

    def test_approval_is_deterministic(self):
        r = self._req()
        s1 = sign_purge_approval(r, kid="v1")
        s2 = sign_purge_approval(r, kid="v1")
        assert s1 == s2

    def test_approval_changes_if_approver_changes(self):
        r = self._req()
        s1 = sign_purge_approval(r, kid="v1")
        r["approved_by"] = uuid.uuid4()
        s2 = sign_purge_approval(r, kid="v1")
        assert s1 != s2

    def test_approval_changes_if_reason_changes(self):
        r = self._req()
        s1 = sign_purge_approval(r, kid="v1")
        r["reason"] = "Different pretext"
        s2 = sign_purge_approval(r, kid="v1")
        assert s1 != s2


# ======================================================================
# 2. Chain verifier after redaction
# ======================================================================


class TestChainVerifierAfterRedaction:
    def test_chain_still_verifies_when_middle_row_redacted(self):
        """Redact row 3 of a 5-row chain — chain must still verify intact."""
        rows = _build_chain(5)
        purge_id = str(uuid.uuid4())
        redacted_row = _simulate_redaction(rows[2], purge_id)
        # Strip the test-only _redaction_record helper before verifying
        clean = {k: v for k, v in redacted_row.items() if not k.startswith("_")}
        rows[2] = clean

        report = verify_chain(TENANT, rows)
        assert report.ok, report.issues
        assert report.chain_rows_examined == 5

    def test_chain_still_verifies_when_multiple_rows_redacted(self):
        rows = _build_chain(8)
        purge_id = str(uuid.uuid4())
        for idx in (1, 3, 4, 6):
            red = _simulate_redaction(rows[idx], purge_id)
            rows[idx] = {k: v for k, v in red.items() if not k.startswith("_")}

        report = verify_chain(TENANT, rows)
        assert report.ok, report.issues

    def test_chain_verify_fails_if_redacted_row_retroactively_tampered(self):
        """After redaction, an attacker editing redacted row's PII field
        without re-signing must still be caught (signature mismatch)."""
        rows = _build_chain(5)
        purge_id = str(uuid.uuid4())
        red = _simulate_redaction(rows[2], purge_id)
        red = {k: v for k, v in red.items() if not k.startswith("_")}
        # Attacker overwrites the sentinel with reconstructed PII.
        red["user_id"] = "alice"
        rows[2] = red

        report = verify_chain(TENANT, rows)
        sig_issues = [i for i in report.issues if i.kind == "signature"]
        assert sig_issues, report.issues

    def test_redacted_row_without_pre_sig_breaks_linkage(self):
        """If pre_redaction_signature is dropped, chain linkage must break."""
        rows = _build_chain(5)
        purge_id = str(uuid.uuid4())
        red = _simulate_redaction(rows[2], purge_id)
        red = {k: v for k, v in red.items() if not k.startswith("_")}
        red.pop("pre_redaction_signature", None)
        # Row must be re-signed to remain self-consistent, otherwise the
        # sig check will flag it before we get to the linkage test.
        red["log_signature"] = AuditLogger.sign(
            {k: v for k, v in red.items() if k != "log_signature"}, kid="v1"
        )
        rows[2] = red

        report = verify_chain(TENANT, rows)
        link_issues = [i for i in report.issues if i.kind == "link"]
        assert link_issues, report.issues

    def test_post_redaction_row_has_sentinel_values(self):
        rows = _build_chain(3)
        purge_id = str(uuid.uuid4())
        red = _simulate_redaction(rows[1], purge_id)
        assert red["user_id"] == REDACTED_SENTINEL
        assert red["department"] == REDACTED_SENTINEL
        # Non-PII fields untouched
        assert red["prompt_hash"] == rows[1]["prompt_hash"]
        assert red["sequence_number"] == 2


# ======================================================================
# 3. Gateway endpoints (TestClient + fake DB)
# ======================================================================


class FakeTxn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeConn:
    def __init__(self):
        self.fetch = AsyncMock(return_value=[])
        self.fetchrow = AsyncMock(return_value=None)
        self.execute = AsyncMock(return_value="OK")
        self.close = AsyncMock(return_value=None)

    def transaction(self):
        return FakeTxn()


def _patch_gateway_asyncpg(conn: FakeConn):
    return patch(
        "agcms.gateway.gdpr.asyncpg.connect",
        new_callable=AsyncMock,
        return_value=conn,
    )


_ADMIN_A = AuthContext(tenant_id=TENANT, user_id="admin-a", role="admin", auth_method="jwt")
_ADMIN_B = AuthContext(tenant_id=TENANT, user_id="admin-b", role="admin", auth_method="jwt")
_NORMAL = AuthContext(tenant_id=TENANT, user_id="alice", role="user", auth_method="jwt")


def _app(ctx: AuthContext) -> FastAPI:
    app = FastAPI()
    app.include_router(gdpr_router)
    app.dependency_overrides[get_current_auth] = lambda: ctx
    return app


class TestPurgeRequestCreation:
    def test_admin_can_file_purge_request(self):
        conn = FakeConn()
        admin_uuid = uuid.uuid4()
        subject_uuid = uuid.uuid4()
        request_uuid = uuid.uuid4()
        now = datetime.now(timezone.utc)

        async def fetchrow(query, *args):
            if "FROM tenant_users" in query and "external_id = $2" in query:
                if args[1] == "admin-a":
                    return {"id": admin_uuid}
                if args[1] == "alice@example.com":
                    return {"id": subject_uuid}
                return None
            if "INSERT INTO gdpr_purge_requests" in query:
                return {
                    "id": request_uuid,
                    "tenant_id": TENANT,
                    "subject_user_id": "alice@example.com",
                    "subject_tenant_user_id": subject_uuid,
                    "requested_by": admin_uuid,
                    "requested_at": now,
                    "approval_expires_at": now + timedelta(hours=24),
                    "approved_by": None,
                    "approved_at": None,
                    "rejected_by": None,
                    "rejected_at": None,
                    "executed_at": None,
                    "rows_redacted": None,
                    "state": "pending",
                    "reason": "DSR-42: subject requested erasure",
                }
            return None

        conn.fetchrow.side_effect = fetchrow

        with _patch_gateway_asyncpg(conn):
            resp = TestClient(_app(_ADMIN_A)).post(
                "/api/v1/gdpr/purge-requests",
                json={
                    "subject_user_id": "alice@example.com",
                    "reason": "DSR-42: subject requested erasure",
                },
            )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["state"] == "pending"
        assert body["subject_user_id"] == "alice@example.com"
        assert body["requested_by"] == str(admin_uuid)

    def test_non_admin_user_gets_403(self):
        conn = FakeConn()
        with _patch_gateway_asyncpg(conn):
            resp = TestClient(_app(_NORMAL)).post(
                "/api/v1/gdpr/purge-requests",
                json={
                    "subject_user_id": "alice@example.com",
                    "reason": "DSR-42: subject requested erasure",
                },
            )
        assert resp.status_code == 403

    def test_reason_must_be_at_least_10_chars(self):
        conn = FakeConn()
        with _patch_gateway_asyncpg(conn):
            resp = TestClient(_app(_ADMIN_A)).post(
                "/api/v1/gdpr/purge-requests",
                json={"subject_user_id": "alice@example.com", "reason": "too short"},
            )
        assert resp.status_code == 422


class TestPurgeApprovalRules:
    def _row(self, requested_by, *, state="pending", expires_delta=timedelta(hours=12)):
        now = datetime.now(timezone.utc)
        return {
            "id": uuid.uuid4(),
            "tenant_id": TENANT,
            "subject_user_id": "alice@example.com",
            "subject_tenant_user_id": None,
            "requested_by": requested_by,
            "requested_at": now,
            "approval_expires_at": now + expires_delta,
            "approved_by": None,
            "approved_at": None,
            "rejected_by": None,
            "rejected_at": None,
            "executed_at": None,
            "rows_redacted": None,
            "state": state,
            "reason": "DSR-42: subject requested erasure",
        }

    def test_same_admin_cannot_approve_own_request(self):
        """Two-admin rule: requester may not be the approver."""
        admin_a_uuid = uuid.uuid4()
        conn = FakeConn()
        purge_row = self._row(requested_by=admin_a_uuid)

        async def fetchrow(query, *args):
            if "FROM tenant_users" in query:
                return {"id": admin_a_uuid}
            if "FROM gdpr_purge_requests" in query and "FOR UPDATE" in query:
                return purge_row
            return None

        conn.fetchrow.side_effect = fetchrow

        with _patch_gateway_asyncpg(conn):
            resp = TestClient(_app(_ADMIN_A)).post(
                f"/api/v1/gdpr/purge-requests/{purge_row['id']}/approve",
            )
        assert resp.status_code == 403
        assert "two-admin" in resp.json()["detail"].lower()

    def test_different_admin_can_approve(self):
        admin_a_uuid = uuid.uuid4()
        admin_b_uuid = uuid.uuid4()
        purge_row = self._row(requested_by=admin_a_uuid)
        approved_row = dict(purge_row)
        approved_row["state"] = "approved"
        approved_row["approved_by"] = admin_b_uuid
        approved_row["approved_at"] = datetime.now(timezone.utc)

        conn = FakeConn()
        state = {"row": purge_row}

        async def fetchrow(query, *args):
            if "FROM tenant_users" in query:
                return {"id": admin_b_uuid}
            if "FROM gdpr_purge_requests" in query and "FOR UPDATE" in query:
                return state["row"]
            if "FROM gdpr_purge_requests WHERE id" in query:
                return state["row"]
            if query.strip().startswith("UPDATE gdpr_purge_requests"):
                state["row"] = approved_row
                return approved_row
            return None

        conn.fetchrow.side_effect = fetchrow

        with _patch_gateway_asyncpg(conn):
            resp = TestClient(_app(_ADMIN_B)).post(
                f"/api/v1/gdpr/purge-requests/{purge_row['id']}/approve",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["state"] == "approved"
        assert body["approved_by"] == str(admin_b_uuid)

    def test_approval_past_24h_window_rejected(self):
        admin_a_uuid = uuid.uuid4()
        admin_b_uuid = uuid.uuid4()
        purge_row = self._row(
            requested_by=admin_a_uuid,
            expires_delta=timedelta(hours=-1),  # expired an hour ago
        )
        conn = FakeConn()

        async def fetchrow(query, *args):
            if "FROM tenant_users" in query:
                return {"id": admin_b_uuid}
            if "FOR UPDATE" in query:
                return purge_row
            return None

        conn.fetchrow.side_effect = fetchrow

        with _patch_gateway_asyncpg(conn):
            resp = TestClient(_app(_ADMIN_B)).post(
                f"/api/v1/gdpr/purge-requests/{purge_row['id']}/approve",
            )
        assert resp.status_code == 409
        assert "expired" in resp.json()["detail"].lower()

    def test_cannot_approve_already_approved_request(self):
        admin_a_uuid = uuid.uuid4()
        admin_b_uuid = uuid.uuid4()
        purge_row = self._row(requested_by=admin_a_uuid, state="approved")
        conn = FakeConn()

        async def fetchrow(query, *args):
            if "FROM tenant_users" in query:
                return {"id": admin_b_uuid}
            if "FOR UPDATE" in query:
                return purge_row
            return None

        conn.fetchrow.side_effect = fetchrow

        with _patch_gateway_asyncpg(conn):
            resp = TestClient(_app(_ADMIN_B)).post(
                f"/api/v1/gdpr/purge-requests/{purge_row['id']}/approve",
            )
        assert resp.status_code == 409


class TestPurgeExecution:
    def test_cannot_execute_pending_request(self):
        conn = FakeConn()
        rid = uuid.uuid4()

        async def fetchrow(query, *args):
            if "FROM gdpr_purge_requests" in query:
                return {"state": "pending"}
            return None

        conn.fetchrow.side_effect = fetchrow

        with _patch_gateway_asyncpg(conn):
            resp = TestClient(_app(_ADMIN_B)).post(
                f"/api/v1/gdpr/purge-requests/{rid}/execute",
            )
        assert resp.status_code == 409
        assert "approved" in resp.json()["detail"].lower()

    def test_execute_calls_redaction_executor_on_approved_request(self):
        from agcms.audit.redaction import RedactionResult

        conn = FakeConn()
        rid = uuid.uuid4()
        exec_now = datetime.now(timezone.utc)

        state = {"fetched_once": False}

        async def fetchrow(query, *args):
            if "FROM gdpr_purge_requests" in query and "WHERE id = $1 AND tenant_id" in query:
                return {"state": "approved"}
            if query.strip().startswith("UPDATE gdpr_purge_requests"):
                return {
                    "id": rid,
                    "tenant_id": TENANT,
                    "subject_user_id": "alice@example.com",
                    "subject_tenant_user_id": None,
                    "requested_by": uuid.uuid4(),
                    "requested_at": exec_now,
                    "approval_expires_at": exec_now + timedelta(hours=24),
                    "approved_by": uuid.uuid4(),
                    "approved_at": exec_now,
                    "rejected_by": None, "rejected_at": None,
                    "executed_at": exec_now,
                    "rows_redacted": 7,
                    "state": "executed",
                    "reason": "DSR-42: subject requested erasure",
                }
            return None

        conn.fetchrow.side_effect = fetchrow

        async def fake_execute_purge(request_id):
            return RedactionResult(
                purge_request_id=request_id,
                tenant_id=TENANT,
                rows_redacted=7,
                redaction_record_ids=[str(uuid.uuid4()) for _ in range(7)],
            )

        with _patch_gateway_asyncpg(conn), \
             patch("agcms.audit.redaction.execute_purge", side_effect=fake_execute_purge):
            resp = TestClient(_app(_ADMIN_B)).post(
                f"/api/v1/gdpr/purge-requests/{rid}/execute",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["state"] == "executed"
        assert body["rows_redacted"] == 7
        assert len(body["redaction_record_ids"]) == 7
