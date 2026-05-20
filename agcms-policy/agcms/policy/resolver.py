"""Policy Resolution Engine — evaluates scan results against tenant policy."""

import os
from typing import Optional

import yaml

from agcms.policy.models import EnforcementDecision

# Risk level ordering for threshold comparison
_RISK_LEVELS = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Default policy path
_DEFAULT_POLICY_PATH = os.environ.get(
    "AGCMS_DEFAULT_POLICY", "/app/policies/default.yaml"
)


class PolicyResolver:
    """Resolves enforcement decisions by evaluating scan results against policy.

    Priority order (highest wins):
      1. Injection detection → BLOCK (if enabled and above threshold)
      2. Injection repeated attempts → ESCALATE (if escalate_on_repeat enabled)
      3. PII critical risk → BLOCK or ESCALATE (based on critical_action)
      4. PII detected → REDACT / ALLOW (based on action_on_detection)
      5. No issues → ALLOW
    """

    def __init__(self):
        self._default_policy = self._load_default_policy()

    def _load_default_policy(self) -> dict:
        """Load the default YAML policy from disk."""
        if os.path.exists(_DEFAULT_POLICY_PATH):
            with open(_DEFAULT_POLICY_PATH) as f:
                return yaml.safe_load(f) or {}
        return {}

    def resolve(
        self,
        pii_result: Optional[dict],
        injection_result: Optional[dict],
        policy: Optional[dict] = None,
    ) -> EnforcementDecision:
        """Evaluate scan results against policy and return enforcement decision.

        Args:
            pii_result: Dict with keys: has_pii, risk_level, entity_types, entities.
            injection_result: Dict with keys: risk_score, attack_type, is_injection.
            policy: Tenant policy dict (or None to use default).
        """
        p = policy or self._default_policy
        triggered = []

        # --- Injection check (highest priority) ---
        # Real prompt injections light up heuristic rules AND score very high.
        # Pure-ML scores (no triggered rules) have been observed to false-positive
        # on benign markdown, non-English text, and imperative phrasing
        # ("...please remember it"), so a single tunable score threshold is
        # not enough. We require EITHER rule corroboration above
        # block_threshold OR a near-certain ML-only score above
        # ml_only_block_threshold (default 0.95) before blocking.
        inj_policy = p.get("injection", {})
        if inj_policy.get("enabled", True) and injection_result:
            threshold = inj_policy.get("block_threshold", 0.65)
            ml_only_threshold = inj_policy.get("ml_only_block_threshold", 0.95)
            score = injection_result.get("risk_score", 0.0)
            has_rules = bool(injection_result.get("triggered_rules") or [])
            should_block = (has_rules and score >= threshold) or (
                score >= ml_only_threshold
            )
            if should_block:
                attack = injection_result.get("attack_type", "UNKNOWN")
                triggered.append("injection")
                # Escalate on repeated injection if configured
                escalate_threshold = inj_policy.get("escalate_threshold")
                if escalate_threshold is not None and score >= escalate_threshold:
                    return EnforcementDecision(
                        action="ESCALATE",
                        reason=f"Repeated/high-severity injection detected: {attack} (score={score:.2f})",
                        triggered_policies=triggered,
                    )
                return EnforcementDecision(
                    action="BLOCK",
                    reason=f"Prompt injection detected: {attack} (score={score:.2f})",
                    triggered_policies=triggered,
                )

        # --- PII check ---
        pii_policy = p.get("pii", {})
        if pii_policy.get("enabled", True) and pii_result:
            risk_level = pii_result.get("risk_level", "NONE")
            has_pii = pii_result.get("has_pii", False)

            # Critical PII → action based on critical_action (BLOCK or ESCALATE)
            critical_action = pii_policy.get("critical_action", "BLOCK")
            if risk_level == "CRITICAL" and critical_action in ("BLOCK", "ESCALATE"):
                triggered.append("pii_critical")
                return EnforcementDecision(
                    action=critical_action,
                    reason=f"Critical PII detected (risk_level={risk_level})",
                    triggered_policies=triggered,
                )

            # PII above threshold → action_on_detection (REDACT / BLOCK / ESCALATE / ALLOW)
            if has_pii:
                risk_threshold = pii_policy.get("risk_threshold", "MEDIUM")
                if _RISK_LEVELS.get(risk_level, 0) >= _RISK_LEVELS.get(risk_threshold, 2):
                    action = pii_policy.get("action_on_detection", "REDACT")
                    triggered.append("pii_detected")
                    return EnforcementDecision(
                        action=action,
                        reason=f"PII detected (risk_level={risk_level})",
                        triggered_policies=triggered,
                    )

        return EnforcementDecision(action="ALLOW")
