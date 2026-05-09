import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Tuple

import sqlalchemy

from agcms.audit.keys import REGISTRY
from agcms.common.observability import metrics as _obs_metrics
from agcms.db import audit_logs, database

# Backward-compat export: existing tests and callers import SIGNING_KEY
# as the raw bytes of the active row-signing key.
SIGNING_KEY: bytes = REGISTRY.row_key(REGISTRY.active_row_kid)


class AuditLogger:
    """Tamper-evident audit logger with per-tenant hash chaining.

    Every row's signing payload includes the previous row's signature
    (``previous_log_hash``), its position in the chain (``sequence_number``),
    and the id of the key that signed it (``signing_key_id``). Chain
    extension is serialized per-tenant via ``SELECT ... FOR UPDATE`` on
    ``chain_heads``; concurrent writers for the same tenant queue behind
    that row lock.
    """

    ZERO_HASH = "0" * 64

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def log(
        self,
        interaction_id: str,
        tenant_id: str,
        user_id: str,
        department: Optional[str],
        raw_body: dict,
        pii_result: Any,
        injection_result: Any,
        decision: Any,
        compliance_result: Any,
        start_time: float,
        llm_provider: str = "groq",
        llm_model: Optional[str] = None,
    ) -> dict:
        """Build, chain-extend, sign, and persist an audit log entry.

        Returns the full entry dict (including chain columns + signature).
        """
        now = time.time()
        prompt_text = self._extract_prompt(raw_body)
        active_kid = REGISTRY.active_row_kid

        # Pre-populate entry with placeholder chain fields so the object
        # shape is complete for callers that patch `_write` in tests.
        # `_write` will overwrite the chain fields and re-sign under the
        # chain_heads row lock before persisting.
        entry = {
            "interaction_id": str(interaction_id),
            "tenant_id": tenant_id,
            "user_id": user_id,
            "department": department,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "llm_provider": llm_provider,
            "llm_model": llm_model,
            "prompt_hash": hashlib.sha256(prompt_text.encode()).hexdigest(),
            "pii_detected": self._get_pii_detected(pii_result),
            "pii_entity_types": self._get_pii_entity_types(pii_result),
            "pii_risk_level": self._get_pii_risk_level(pii_result),
            "injection_score": self._get_injection_score(injection_result),
            "injection_type": self._get_injection_type(injection_result),
            "enforcement_action": self._get_action(decision),
            "enforcement_reason": self._get_reason(decision),
            "triggered_policies": self._get_triggered_policies(decision),
            "response_violated": self._get_response_violated(compliance_result),
            "response_violations": self._get_response_violations(compliance_result),
            "total_latency_ms": int((now - start_time) * 1000),
            "previous_log_hash": self.ZERO_HASH,
            "sequence_number": 0,
            "signing_key_id": active_kid,
        }

        entry["log_signature"] = self.sign(entry, kid=active_kid)

        _write_start = time.perf_counter()
        try:
            await self._write(entry)
        finally:
            _obs_metrics.audit_chain_write.labels(tenant=tenant_id).observe(
                time.perf_counter() - _write_start,
            )
        return entry

    @staticmethod
    def sign(entry: dict, *, kid: Optional[str] = None) -> str:
        """Compute HMAC-SHA256 over the deterministic JSON of ``entry``.

        If ``kid`` is None, uses ``entry['signing_key_id']`` (if present)
        or the active row kid. The signature covers every field of the
        entry — including the chain columns — so any tampering with
        ``previous_log_hash`` or ``sequence_number`` invalidates the row.
        """
        chosen_kid = kid or entry.get("signing_key_id") or REGISTRY.active_row_kid
        key = REGISTRY.row_key(chosen_kid)
        payload = json.dumps(entry, sort_keys=True, default=str).encode("utf-8")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def verify(entry: dict) -> bool:
        """Verify a row's signature using the kid recorded on the row.

        Returns False on any of: missing signature, unknown kid, mismatch.
        """
        entry_copy = dict(entry)
        stored_sig = entry_copy.pop("log_signature", None)
        if stored_sig is None or stored_sig == "":
            return False
        try:
            expected_sig = AuditLogger.sign(entry_copy)
        except KeyError:
            return False
        return hmac.compare_digest(stored_sig, expected_sig)

    @staticmethod
    def hash_prompt(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Database write with chain extension
    # ------------------------------------------------------------------

    async def _write(self, entry: dict) -> None:
        """Persist `entry` after extending the tenant's chain.

        Transaction scope:
          1. UPSERT chain_heads row (idempotent).
          2. SELECT ... FOR UPDATE on that row.
          3. Mutate `entry` with real chain fields; re-sign.
          4. INSERT audit_logs row.
          5. UPDATE chain_heads with new tip.

        Tests that don't need a real database patch this method with an
        AsyncMock; those callers will see the placeholder chain fields
        set in ``log()``.
        """
        tenant_id = entry["tenant_id"]

        async with database.transaction():
            await database.execute(
                sqlalchemy.text(
                    "INSERT INTO chain_heads (tenant_id) VALUES (:tid) "
                    "ON CONFLICT DO NOTHING"
                ).bindparams(tid=tenant_id),
            )

            head = await database.fetch_one(
                sqlalchemy.text(
                    "SELECT last_sequence_number, last_log_signature "
                    "FROM chain_heads WHERE tenant_id = :tid FOR UPDATE"
                ).bindparams(tid=tenant_id),
            )

            previous_log_hash = (
                head["last_log_signature"] or self.ZERO_HASH
            ) if head is not None else self.ZERO_HASH
            sequence_number = (
                (head["last_sequence_number"] if head is not None else 0) + 1
            )
            active_kid = REGISTRY.active_row_kid

            entry["previous_log_hash"] = previous_log_hash
            entry["sequence_number"] = sequence_number
            entry["signing_key_id"] = active_kid
            # Strip the placeholder signature from log() before re-signing —
            # otherwise it would be included in the payload and the stored
            # hash would diverge from what any verifier (which strips
            # log_signature before recomputing) produces.
            entry.pop("log_signature", None)
            entry["log_signature"] = self.sign(entry, kid=active_kid)

            await database.execute(
                audit_logs.insert().values(**self._row_values(entry))
            )

            await database.execute(
                sqlalchemy.text(
                    "UPDATE chain_heads SET "
                    "last_sequence_number = :seq, "
                    "last_log_signature = :sig, "
                    "last_row_created_at = :ts, "
                    "updated_at = NOW() "
                    "WHERE tenant_id = :tid"
                ).bindparams(
                    seq=sequence_number,
                    sig=entry["log_signature"],
                    ts=datetime.fromisoformat(entry["created_at"]),
                    tid=tenant_id,
                ),
            )

    @staticmethod
    def _row_values(entry: dict) -> dict:
        values = {
            "interaction_id": uuid.UUID(entry["interaction_id"]),
            "tenant_id": entry["tenant_id"],
            "user_id": entry["user_id"],
            "department": entry["department"],
            "created_at": datetime.fromisoformat(entry["created_at"]),
            "llm_provider": entry["llm_provider"],
            "llm_model": entry["llm_model"],
            "prompt_hash": entry["prompt_hash"],
            "pii_detected": entry["pii_detected"],
            "pii_entity_types": entry["pii_entity_types"],
            "pii_risk_level": entry["pii_risk_level"],
            "injection_score": entry["injection_score"],
            "injection_type": entry["injection_type"],
            "enforcement_action": entry["enforcement_action"],
            "enforcement_reason": entry["enforcement_reason"],
            "triggered_policies": entry["triggered_policies"],
            "response_violated": entry["response_violated"],
            "response_violations": entry["response_violations"],
            "total_latency_ms": entry["total_latency_ms"],
            "log_signature": entry["log_signature"],
            "previous_log_hash": entry["previous_log_hash"],
            "sequence_number": entry["sequence_number"],
            "signing_key_id": entry["signing_key_id"],
        }
        # Redaction columns are only populated for rows that have been
        # tombstoned under a GDPR Art. 17 purge. At insert time they are
        # always NULL; the redaction writer patches them later.
        if entry.get("redaction_record_id") is not None:
            values["redaction_record_id"] = entry["redaction_record_id"]
        if entry.get("pre_redaction_signature") is not None:
            values["pre_redaction_signature"] = entry["pre_redaction_signature"]
        return values

    # ------------------------------------------------------------------
    # Field extractors (duck-typed for flexibility)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_prompt(body: dict) -> str:
        messages = body.get("messages", [])
        return " ".join(
            m.get("content", "")
            for m in messages
            if isinstance(m.get("content"), str)
        )

    @staticmethod
    def _get_pii_detected(pii_result: Any) -> bool:
        if pii_result is None:
            return False
        if isinstance(pii_result, dict):
            return pii_result.get("has_pii", False)
        if hasattr(pii_result, "has_pii"):
            return pii_result.has_pii
        return bool(pii_result)

    @staticmethod
    def _get_pii_entity_types(pii_result: Any) -> list:
        if pii_result is None:
            return []
        if isinstance(pii_result, dict):
            return pii_result.get("entity_types", [])
        if hasattr(pii_result, "entities"):
            return [e.entity_type for e in pii_result.entities]
        return []

    @staticmethod
    def _get_pii_risk_level(pii_result: Any) -> str:
        if pii_result is None:
            return "NONE"
        if isinstance(pii_result, dict):
            return pii_result.get("risk_level", "NONE")
        if hasattr(pii_result, "risk_level"):
            return pii_result.risk_level
        return "NONE"

    @staticmethod
    def _get_injection_score(injection_result: Any) -> Optional[float]:
        if injection_result is None:
            return None
        if isinstance(injection_result, dict):
            score = injection_result.get("risk_score")
            return round(score, 3) if score is not None else None
        if hasattr(injection_result, "risk_score"):
            return round(injection_result.risk_score, 3)
        return None

    @staticmethod
    def _get_injection_type(injection_result: Any) -> Optional[str]:
        if injection_result is None:
            return None
        if isinstance(injection_result, dict):
            return injection_result.get("attack_type")
        if hasattr(injection_result, "attack_type"):
            return injection_result.attack_type
        return None

    @staticmethod
    def _get_action(decision: Any) -> str:
        if decision is None:
            return "ALLOW"
        if isinstance(decision, dict):
            return decision.get("action", "ALLOW")
        if hasattr(decision, "action"):
            return decision.action
        return "ALLOW"

    @staticmethod
    def _get_reason(decision: Any) -> Optional[str]:
        if decision is None:
            return None
        if isinstance(decision, dict):
            return decision.get("reason")
        if hasattr(decision, "reason"):
            return decision.reason
        return None

    @staticmethod
    def _get_triggered_policies(decision: Any) -> list:
        if decision is None:
            return []
        if isinstance(decision, dict):
            return decision.get("triggered_policies", [])
        if hasattr(decision, "triggered_policies"):
            return decision.triggered_policies
        return []

    @staticmethod
    def _get_response_violated(compliance_result: Any) -> bool:
        if compliance_result is None:
            return False
        if isinstance(compliance_result, dict):
            return compliance_result.get("violated", False)
        if hasattr(compliance_result, "violated"):
            return compliance_result.violated
        return False

    @staticmethod
    def _get_response_violations(compliance_result: Any) -> Optional[list]:
        if compliance_result is None:
            return None
        if isinstance(compliance_result, dict):
            return compliance_result.get("violations")
        if hasattr(compliance_result, "violations"):
            return compliance_result.violations
        return None
