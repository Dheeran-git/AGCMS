from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class InjectionRule:
    """A single triggered injection heuristic rule."""

    name: str
    pattern: str
    weight: float


@dataclass
class InjectionScanResult:
    """Result of an injection scan with risk scoring."""

    risk_score: float = 0.0
    attack_type: Optional[str] = None
    triggered_rules: List[InjectionRule] = field(default_factory=list)

    @property
    def is_injection(self) -> bool:
        return self.risk_score >= 0.5

    def to_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score, 3),
            "attack_type": self.attack_type,
            "is_injection": self.is_injection,
            "triggered_rules": [
                {"name": r.name, "pattern": r.pattern, "weight": r.weight}
                for r in self.triggered_rules
            ],
        }
