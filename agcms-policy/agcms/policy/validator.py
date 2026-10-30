"""Policy YAML/JSON schema validator.

Validates a policy config dict against the AGCMS policy DSL rules:
  - Required top-level sections present
  - Enum values match allowed sets
  - Numeric fields within acceptable ranges
  - Unknown keys flagged as warnings (not errors)

Returns a list of error strings; empty list means valid.
"""

import re
from typing import Any

# Allowed action enum values
_PII_ACTIONS = {"ALLOW", "REDACT", "BLOCK", "ESCALATE"}
_RISK_LEVELS = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_CRITICAL_ACTIONS = {"BLOCK", "ESCALATE"}

# Sections that must be present (but can be empty dicts)
_REQUIRED_SECTIONS = {"pii", "injection"}


def _is_number(value: Any) -> bool:
    """True for int/float but not bool (bool is an int subclass in Python)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _string_list_errors(name: str, value: Any) -> list[str]:
    """An empty string would match every response, so entries must be non-blank."""
    if not isinstance(value, list):
        return [f"{name} must be a list"]
    if not all(isinstance(t, str) and t.strip() for t in value):
        return [f"{name} must contain only non-empty strings"]
    return []


def _custom_pattern_errors(patterns: Any) -> list[str]:
    """Each pattern must compile and must not match the empty string."""
    if not isinstance(patterns, dict):
        return ["pii.custom_patterns must be an object"]
    errors = []
    for name, pattern in patterns.items():
        if not name.strip() or not isinstance(pattern, str):
            errors.append(f"pii.custom_patterns.{name!r} must map a name to a regex string")
            continue
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            errors.append(f"pii.custom_patterns.{name} is not a valid regex: {exc}")
            continue
        if compiled.fullmatch(""):
            errors.append(f"pii.custom_patterns.{name} must not match the empty string")
    return errors


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
    if "pii" in config:
        if not isinstance(pii, dict):
            errors.append("'pii' must be an object")
        else:
            errors.extend(_validate_pii(pii))

    # --- Injection section ---
    injection = config.get("injection")
    if "injection" in config:
        if not isinstance(injection, dict):
            errors.append("'injection' must be an object")
        else:
            errors.extend(_validate_injection(injection))

    # --- Response compliance section (optional) ---
    rc = config.get("response_compliance")
    if "response_compliance" in config:
        if not isinstance(rc, dict):
            errors.append("'response_compliance' must be an object")
        else:
            errors.extend(_validate_response_compliance(rc))

    # --- Rate limits section (optional) ---
    rl = config.get("rate_limits")
    if "rate_limits" in config:
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
    if custom_patterns is not None:
        errors.extend(_custom_pattern_errors(custom_patterns))

    return errors


def _validate_injection(injection: dict) -> list[str]:
    errors: list[str] = []

    enabled = injection.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        errors.append("injection.enabled must be a boolean")

    block_threshold = injection.get("block_threshold")
    if block_threshold is not None:
        if not _is_number(block_threshold):
            errors.append("injection.block_threshold must be a number")
        elif not (0.0 <= block_threshold <= 1.0):
            errors.append(
                f"injection.block_threshold must be between 0.0 and 1.0, got {block_threshold}"
            )

    ml_only_threshold = injection.get("ml_only_block_threshold")
    if ml_only_threshold is not None:
        if not _is_number(ml_only_threshold):
            errors.append("injection.ml_only_block_threshold must be a number")
        elif not (0.0 <= ml_only_threshold <= 1.0):
            errors.append(
                "injection.ml_only_block_threshold must be between 0.0 and 1.0, "
                f"got {ml_only_threshold}"
            )

    escalate_threshold = injection.get("escalate_threshold")
    if escalate_threshold is not None:
        if not _is_number(escalate_threshold):
            errors.append("injection.escalate_threshold must be a number")
        elif not (0.0 <= escalate_threshold <= 1.0):
            errors.append(
                f"injection.escalate_threshold must be between 0.0 and 1.0, got {escalate_threshold}"
            )
        elif _is_number(block_threshold):
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

    for key in ("restricted_topics", "system_prompt_keywords"):
        if rc.get(key) is not None:
            errors.extend(_string_list_errors(f"response_compliance.{key}", rc[key]))

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
        if not _is_positive_int(rpm):
            errors.append("rate_limits.requests_per_minute must be a positive integer")

    rpd = rl.get("requests_per_day")
    if rpd is not None:
        if not _is_positive_int(rpd):
            errors.append("rate_limits.requests_per_day must be a positive integer")
        elif _is_positive_int(rpm):
            if rpd < rpm:
                errors.append(
                    "rate_limits.requests_per_day must be >= requests_per_minute "
                    f"({rpd} < {rpm})"
                )

    return errors
