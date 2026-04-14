from dataclasses import dataclass, field
from typing import List


@dataclass
class ComplianceViolation:
    """A single compliance violation found in an LLM response."""

    rule: str
    description: str
    severity: str = "MEDIUM"  # LOW / MEDIUM / HIGH / CRITICAL


@dataclass
class ComplianceResult:
    """Result of response compliance checking."""

    violated: bool = False
    violations: List[ComplianceViolation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "violated": self.violated,
            "violations": [
                {"rule": v.rule, "description": v.description, "severity": v.severity}
                for v in self.violations
            ],
        }
