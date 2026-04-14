"""PII Detection Agent — regex + spaCy NER with deduplication and risk scoring."""

import os
import re
from typing import List, Optional

import spacy

from agcms.pii.models import PIIEntity, PIIScanResult
from agcms.pii.patterns import (
    PATTERNS,
    PATTERNS_WITH_VALIDATORS,
    get_all_patterns,
    luhn_check,
    validate_ip_address,
)

# spaCy model toggled by env var (RULE 5 / Q2 decision)
_SPACY_MODEL = os.environ.get("AGCMS_SPACY_MODEL", "en_core_web_sm")

# NER entity types from spaCy that map to PII
_SPACY_PII_MAP = {
    "PERSON": "PERSON_NAME",
    "ORG": "ORGANIZATION",
}

# High-risk entity types that trigger CRITICAL risk level
_HIGH_RISK_TYPES = frozenset({
    "SSN", "CREDIT_CARD", "AADHAAR", "PAN", "IBAN", "MRN",
})


class PIIAgent:
    """Detects and masks PII using deterministic regex patterns + spaCy NER.

    Detection pipeline:
      1. Regex scan — deterministic, high confidence (1.0)
      2. spaCy NER scan — probabilistic, confidence from model scores
      3. Deduplication — overlapping entities resolved by confidence
      4. Risk scoring — based on entity types and count
    """

    def __init__(self, spacy_model: Optional[str] = None):
        model_name = spacy_model or _SPACY_MODEL
        self.nlp = spacy.load(model_name)

    async def scan(self, text: str, policy: dict) -> PIIScanResult:
        """Run full PII detection pipeline on text.

        Args:
            text: The input text to scan.
            policy: Tenant policy dict (may contain custom_patterns).

        Returns:
            PIIScanResult with detected entities and risk level.
        """
        entities: List[PIIEntity] = []
        entities.extend(self._regex_scan(text, policy))
        entities.extend(self._ner_scan(text))
        entities = self._deduplicate(entities)

        result = PIIScanResult(entities=entities)
        result.risk_level = self._compute_risk(entities)
        return result

    def _regex_scan(self, text: str, policy: dict) -> List[PIIEntity]:
        """Scan text using compiled regex patterns."""
        found: List[PIIEntity] = []
        custom = policy.get("custom_patterns") if isinstance(policy, dict) else None
        compiled_patterns = get_all_patterns(custom)

        for entity_type, pattern in compiled_patterns.items():
            for match in pattern.finditer(text):
                matched_text = match.group()

                # Extra validation for patterns prone to false positives
                if entity_type == "CREDIT_CARD":
                    digits_only = re.sub(r"[\s\-]", "", matched_text)
                    if not luhn_check(digits_only):
                        continue
                elif entity_type == "IP_ADDRESS":
                    if not validate_ip_address(matched_text):
                        continue
                elif entity_type == "BANK_ROUTING":
                    # Only flag 9-digit numbers that look like routing numbers
                    # (avoid matching arbitrary 9-digit sequences)
                    if match.start() > 0 and text[match.start() - 1].isdigit():
                        continue
                    if match.end() < len(text) and text[match.end()].isdigit():
                        continue

                found.append(PIIEntity(
                    text=matched_text,
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=1.0,
                ))
        return found

    def _ner_scan(self, text: str) -> List[PIIEntity]:
        """Scan text using spaCy NER model."""
        doc = self.nlp(text)
        found: List[PIIEntity] = []

        for ent in doc.ents:
            pii_type = _SPACY_PII_MAP.get(ent.label_)
            if pii_type is None:
                continue

            # Skip very short entities (likely noise)
            if len(ent.text.strip()) < 2:
                continue

            found.append(PIIEntity(
                text=ent.text,
                entity_type=pii_type,
                start=ent.start_char,
                end=ent.end_char,
                confidence=0.85,  # spaCy sm model default confidence
            ))
        return found

    @staticmethod
    def _deduplicate(entities: List[PIIEntity]) -> List[PIIEntity]:
        """Remove overlapping detections, keeping higher-confidence ones.

        When two entities overlap in position, the one with higher confidence
        wins.  If confidence is equal, the one that starts first wins.
        """
        entities.sort(key=lambda e: (e.start, -e.confidence, -(e.end - e.start)))
        deduped: List[PIIEntity] = []
        last_end = -1
        for entity in entities:
            if entity.start >= last_end:
                deduped.append(entity)
                last_end = entity.end
        return deduped

    @staticmethod
    def _compute_risk(entities: List[PIIEntity]) -> str:
        """Compute risk level based on entity types and count."""
        if not entities:
            return "NONE"
        if any(e.entity_type in _HIGH_RISK_TYPES for e in entities):
            return "CRITICAL"
        if len(entities) >= 3:
            return "HIGH"
        if len(entities) >= 1:
            return "MEDIUM"
        return "NONE"
