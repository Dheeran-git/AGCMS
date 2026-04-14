"""Response Compliance Agent — checks LLM responses for policy violations.

Checks:
  1. PII echo — did the LLM repeat PII from the original prompt?
  2. System prompt leak — did the LLM reveal system instructions?
  3. Restricted topics — did the response contain forbidden content?
"""

import re
from typing import List, Optional

from agcms.response.models import ComplianceResult, ComplianceViolation

# System prompt leak indicators
_SYSTEM_LEAK_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"my\s+(system\s+)?instructions?\s+(are|say|tell\s+me\s+to)",
        r"(I\s+was|I\s+am)\s+(instructed|told|programmed)\s+to",
        r"my\s+(initial|original)\s+prompt\s+(is|was|says)",
        r"(here\s+(are|is)|these\s+are)\s+my\s+(system\s+)?(instructions|rules|guidelines)",
        r"as\s+per\s+my\s+(system\s+)?prompt",
    ]
]

# PII patterns to check for echo (subset of the full PII patterns)
_PII_ECHO_PATTERNS = {
    "SSN": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ \-]?){13,16}\b"),
    "PHONE_US": re.compile(r"\b(\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"),
}


class ResponseComplianceAgent:
    """Checks LLM responses for compliance violations."""

    def check(
        self,
        response_text: str,
        original_prompt: Optional[str] = None,
        policy: Optional[dict] = None,
    ) -> ComplianceResult:
        """Run all compliance checks on a response.

        Args:
            response_text: The LLM's response text.
            original_prompt: The original user prompt (for PII echo check).
            policy: Response compliance policy config.
        """
        if not response_text:
            return ComplianceResult()

        p = (policy or {}).get("response_compliance", {})
        violations: List[ComplianceViolation] = []

        # Check 1: System prompt leak
        violations.extend(self._check_system_prompt_leak(response_text, p))

        # Check 2: PII echo
        if original_prompt:
            violations.extend(self._check_pii_echo(response_text, original_prompt))

        # Check 3: Restricted topics
        violations.extend(self._check_restricted_topics(response_text, p))

        return ComplianceResult(
            violated=len(violations) > 0,
            violations=violations,
        )

    def _check_system_prompt_leak(
        self, response_text: str, policy: dict
    ) -> List[ComplianceViolation]:
        """Detect if the LLM leaked system prompt information."""
        violations = []

        # Check built-in patterns
        for pattern in _SYSTEM_LEAK_PATTERNS:
            if pattern.search(response_text):
                violations.append(ComplianceViolation(
                    rule="SYSTEM_PROMPT_LEAK",
                    description="Response may contain system prompt information",
                    severity="HIGH",
                ))
                break

        # Check tenant-configured keywords
        keywords = policy.get("system_prompt_keywords", [])
        for kw in keywords:
            if kw.lower() in response_text.lower():
                violations.append(ComplianceViolation(
                    rule="SYSTEM_PROMPT_KEYWORD",
                    description=f"Response contains restricted keyword: {kw}",
                    severity="HIGH",
                ))
                break

        return violations

    def _check_pii_echo(
        self, response_text: str, original_prompt: str
    ) -> List[ComplianceViolation]:
        """Check if PII from the original prompt was echoed in the response."""
        violations = []

        for pii_type, pattern in _PII_ECHO_PATTERNS.items():
            prompt_matches = set(m.group() for m in pattern.finditer(original_prompt))
            if not prompt_matches:
                continue
            for m in pattern.finditer(response_text):
                if m.group() in prompt_matches:
                    violations.append(ComplianceViolation(
                        rule="PII_ECHO",
                        description=f"LLM echoed {pii_type} from the original prompt",
                        severity="CRITICAL",
                    ))
                    break

        return violations

    def _check_restricted_topics(
        self, response_text: str, policy: dict
    ) -> List[ComplianceViolation]:
        """Check for restricted topics defined in tenant policy."""
        violations = []
        topics = policy.get("restricted_topics", [])
        lower_text = response_text.lower()

        for topic in topics:
            if topic.lower() in lower_text:
                violations.append(ComplianceViolation(
                    rule="RESTRICTED_TOPIC",
                    description=f"Response contains restricted topic: {topic}",
                    severity="MEDIUM",
                ))

        return violations
