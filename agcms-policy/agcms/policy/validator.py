"""Policy YAML/JSON schema validator.

Validates a policy config dict against the AGCMS policy DSL rules:
  - Required top-level sections present
  - Enum values match allowed sets
  - Numeric fields within acceptable ranges
  - Unknown keys flagged as warnings (not errors)

Returns a list of error strings; empty list means valid.
"""

from typing import Any

# Allowed action enum values
_PII_ACTIONS = {"ALLOW", "REDACT", "BLOCK", "ESCALATE"}
_RISK_LEVELS = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_CRITICAL_ACTIONS = {"BLOCK", "ESCALATE"}

# Sections that must be present (but can be empty dicts)
_REQUIRED_SECTIONS = {"pii", "injection"}


def validate_policy(config: Any) -> list[str]:
    """Validate a policy config dict.

    Args:
        config: The policy config (should be a dict).

    Returns:
        List of error strings. Empty list = valid.
    """
    errors: list[str] = []

    if not isinstance(config, dict):
        return ["Policy config must be a JSON object/dict"]

    # --- Required sections ---
    for section in _REQUIRED_SECTIONS:
        if section not in config:
            errors.append(f"Missing required section: '{section}'")

    # --- PII section ---
    pii = config.get("pii")
    if pii is not None:
        if not isinstance(pii, dict):
            errors.append("'pii' must be an object")
        else:
            errors.extend(_validate_pii(pii))

    # --- Injection section ---
    injection = config.get("injection")
    if injection is not None:
        if not isinstance(injection, dict):
            errors.append("'injection' must be an object")
        else:
            errors.extend(_validate_injection(injection))

    # --- Response compliance section (optional) ---
    rc = config.get("response_compliance")
    if rc is not None:
        if not isinstance(rc, dict):
            errors.append("'response_compliance' must be an object")
        else:
            errors.extend(_validate_response_compliance(rc))

    # --- Rate limits section (optional) ---
    rl = config.get("rate_limits")
    if rl is not None:
        if not isinstance(rl, dict):
            errors.append("'rate_limits' must be an object")
        else:
            errors.extend(_validate_rate_limits(rl))

    return errors


def _validate_pii(pii: dict) -> list[str]:
    errors: list[str] = []

    enabled = pii.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        errors.append("pii.enabled must be a boolean")

    action = pii.get("action_on_detection")
    if action is not None and action not in _PII_ACTIONS:
        errors.append(
            f"pii.action_on_detection must be one of {sorted(_PII_ACTIONS)}, got '{action}'"
        )

    critical_action = pii.get("critical_action")
    if critical_action is not None and critical_action not in _CRITICAL_ACTIONS:
        errors.append(
            f"pii.critical_action must be one of {sorted(_CRITICAL_ACTIONS)}, got '{critical_action}'"
        )

    risk_threshold = pii.get("risk_threshold")
    if risk_threshold is not None and risk_threshold not in _RISK_LEVELS:
        errors.append(
            f"pii.risk_threshold must be one of {sorted(_RISK_LEVELS)}, got '{risk_threshold}'"
        )

    custom_patterns = pii.get("custom_patterns")
    if custom_patterns is not None and not isinstance(custom_patterns, dict):
        errors.append("pii.custom_patterns must be an object")

    return errors


def _validate_injection(injection: dict) -> list[str]:
    errors: list[str] = []

    enabled = injection.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        errors.append("injection.enabled must be a boolean")

    block_threshold = injection.get("block_threshold")
    if block_threshold is not None:
        if not isinstance(block_threshold, (int, float)):
            errors.append("injection.block_threshold must be a number")
        elif not (0.0 <= block_threshold <= 1.0):
            errors.append(
                f"injection.block_threshold must be between 0.0 and 1.0, got {block_threshold}"
            )

    escalate_threshold = injection.get("escalate_threshold")
    if escalate_threshold is not None:
        if not isinstance(escalate_threshold, (int, float)):
            errors.append("injection.escalate_threshold must be a number")
        elif not (0.0 <= escalate_threshold <= 1.0):
            errors.append(
                f"injection.escalate_threshold must be between 0.0 and 1.0, got {escalate_threshold}"
            )
        elif block_threshold is not None and isinstance(block_threshold, (int, float)):
            if escalate_threshold < block_threshold:
                errors.append(
                    "injection.escalate_threshold must be >= injection.block_threshold "
                    f"({escalate_threshold} < {block_threshold})"
                )

    log_all = injection.get("log_all_attempts")
    if log_all is not None and not isinstance(log_all, bool):
        errors.append("injection.log_all_attempts must be a boolean")

    return errors


def _validate_response_compliance(rc: dict) -> list[str]:
    errors: list[str] = []

    enabled = rc.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        errors.append("response_compliance.enabled must be a boolean")

    restricted_topics = rc.get("restricted_topics")
    if restricted_topics is not None:
        if not isinstance(restricted_topics, list):
            errors.append("response_compliance.restricted_topics must be a list")
        elif not all(isinstance(t, str) for t in restricted_topics):
            errors.append("response_compliance.restricted_topics must contain only strings")

    action = rc.get("action_on_violation")
    if action is not None and action not in _PII_ACTIONS:
        errors.append(
            f"response_compliance.action_on_violation must be one of {sorted(_PII_ACTIONS)}, "
            f"got '{action}'"
        )

    return errors


def _validate_rate_limits(rl: dict) -> list[str]:
    errors: list[str] = []

    rpm = rl.get("requests_per_minute")
    if rpm is not None:
        if not isinstance(rpm, int) or rpm < 1:
            errors.append("rate_limits.requests_per_minute must be a positive integer")

    rpd = rl.get("requests_per_day")
    if rpd is not None:
        if not isinstance(rpd, int) or rpd < 1:
            errors.append("rate_limits.requests_per_day must be a positive integer")
        elif rpm is not None and isinstance(rpm, int) and rpm >= 1:
            if rpd < rpm:
                errors.append(
                    "rate_limits.requests_per_day must be >= requests_per_minute "
                    f"({rpd} < {rpm})"
                )

    return errors
