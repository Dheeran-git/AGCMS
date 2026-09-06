"""PII regex patterns for deterministic detection.

Each pattern maps an entity type name to a compiled-ready regex string.
All patterns are designed to minimize false positives in enterprise text.
"""

import re

# ------------------------------------------------------------------
# Core PII Patterns (20+)
# ------------------------------------------------------------------

PATTERNS: dict[str, str] = {
    # Contact information
    "EMAIL": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "PHONE_US": r"\b(\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b",
    "PHONE_INTL": r"(?<!\w)\+(?:[0-9][\s\-]?){6,14}[0-9]\b",
    "PHONE_UK": r"\b(?:\+44[\s\-]?|0)(?:\d[\s\-]?){9,10}\b",

    # Government IDs
    "SSN": r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
    "AADHAAR": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
    "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "PASSPORT": r"\b[A-Z][0-9]{7,8}\b",
    "DRIVER_LICENSE": r"\b[A-Z]{1,2}\d{6,8}\b",

    # Financial
    "CREDIT_CARD": r"\b(?:\d[ \-]?){13,16}\b",
    "IBAN": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    "BANK_ROUTING": r"\b[0-9]{9}\b",

    # Healthcare
    "MRN": r"\bMRN[-\s]?\d{4,10}\b",

    # Network / Technical
    "IP_ADDRESS": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "MAC_ADDRESS": r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
    "IPV6_ADDRESS": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",

    # Secrets / Credentials
    "AWS_ACCESS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
    "GENERIC_API_KEY": r"\b(?:api[_\-]?key|apikey|token)[\s:=\"']+[A-Za-z0-9\-_.]{20,}\b",

    # Dates (potential DOB)
    "DATE_OF_BIRTH": r"\b(?:0?[1-9]|[12]\d|3[01])[-/\.](0?[1-9]|1[0-2])[-/\.](19|20)\d{2}\b",

    # URLs with embedded credentials
    "URL_WITH_CREDENTIALS": r"\bhttps?://[^:]+:[^@]+@[^\s]+\b",
}

# Patterns that need extra validation beyond regex
PATTERNS_WITH_VALIDATORS: set[str] = {"CREDIT_CARD", "BANK_ROUTING"}


def luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm.

    Used to reduce false positives for credit card detection.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def validate_ip_address(ip: str) -> bool:
    """Validate that an IP address has valid octets (not e.g. version numbers)."""
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts) and not all(int(p) == 0 for p in parts)


def get_all_patterns(custom_patterns: dict[str, str] | None = None) -> dict[str, re.Pattern]:
    """Compile all patterns including optional tenant custom patterns."""
    combined = dict(PATTERNS)
    if custom_patterns:
        combined.update(custom_patterns)
    return {name: re.compile(pattern) for name, pattern in combined.items()}
