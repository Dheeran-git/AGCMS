import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from agcms.db import audit_logs, database

# RULE 4: Fail fast if signing key is missing
_raw_key = os.environ.get("AGCMS_SIGNING_KEY")
if _raw_key is None:
    raise RuntimeError(
        "AGCMS_SIGNING_KEY environment variable is not set. "
        "The audit logger cannot start without a signing key."
    )
if not _raw_key:
    raise RuntimeError(
        "AGCMS_SIGNING_KEY environment variable is empty. "
        "Provide a non-empty signing key."
    )

SIGNING_KEY: bytes = _raw_key.encode("utf-8")


class AuditLogger:
    """Tamper-evident audit logger with HMAC-SHA256 signing.

    Every audit log entry is cryptographically signed before being written
    to PostgreSQL.  The signature covers a deterministic JSON serialization
    of the entry (sort_keys=True) and is appended as the last field.
    """

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
        """Build, sign, and persist an audit log entry.

        Returns the full entry dict (including log_signature).
        """
        now = time.time()
        prompt_text = self._extract_prompt(raw_body)

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
        }

        # Signature is ALWAYS the last field written (never included in
        # the payload that generates it).
        entry["log_signature"] = self.sign(entry)

        await self._write(entry)
        return entry

    @staticmethod
    def sign(entry: dict) -> str:
        """Compute HMAC-SHA256 signature over a deterministic JSON payload."""
        payload = json.dumps(entry, sort_keys=True, default=str).encode("utf-8")
        return hmac.new(SIGNING_KEY, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def verify(entry: dict) -> bool:
        """Verify the integrity of an audit log entry.

        Removes the stored signature, recomputes it, and compares using
        constant-time comparison to prevent timing attacks.
        """
        entry_copy = dict(entry)
        stored_sig = entry_copy.pop("log_signature", None)
        if stored_sig is None:
            return False
        expected_sig = AuditLogger.sign(entry_copy)
        return hmac.compare_digest(stored_sig, expected_sig)

    @staticmethod
    def hash_prompt(text: str) -> str:
        """SHA-256 hash of prompt text (raw prompts never stored)."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Database write
    # ------------------------------------------------------------------

    async def _write(self, entry: dict) -> None:
        """Persist entry to PostgreSQL via the ``databases`` async driver.

        Explicitly passes ``created_at`` parsed from the signed entry so that
        the stored timestamp matches the one covered by the HMAC signature.
        Relying on the column's ``DEFAULT NOW()`` would produce a different
        instant and break signature verification.
        """
        row = {
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
        }
        await database.execute(audit_logs.insert().values(**row))

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
