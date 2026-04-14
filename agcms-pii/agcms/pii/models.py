from dataclasses import dataclass, field
from typing import List


@dataclass
class PIIEntity:
    """A single detected PII entity with position and confidence."""

    text: str
    entity_type: str
    start: int
    end: int
    confidence: float


@dataclass
class PIIScanResult:
    """Result of a PII scan containing all detected entities."""

    entities: List[PIIEntity] = field(default_factory=list)
    risk_level: str = "NONE"  # NONE / LOW / MEDIUM / HIGH / CRITICAL

    def mask(self, text: str) -> str:
        """Replace detected PII entities with [ENTITY_TYPE] tokens.

        Entities are processed in reverse order of position so that
        replacements do not shift the offsets of earlier entities.
        """
        result = text
        for entity in sorted(self.entities, key=lambda e: e.start, reverse=True):
            replacement = f"[{entity.entity_type}]"
            result = result[:entity.start] + replacement + result[entity.end:]
        return result

    @property
    def has_pii(self) -> bool:
        return len(self.entities) > 0

    @property
    def entity_types(self) -> List[str]:
        return list({e.entity_type for e in self.entities})
