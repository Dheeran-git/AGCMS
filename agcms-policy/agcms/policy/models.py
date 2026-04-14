from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EnforcementDecision:
    """The outcome of policy evaluation against scan results."""

    action: str = "ALLOW"  # ALLOW / BLOCK / REDACT / ESCALATE
    reason: Optional[str] = None
    triggered_policies: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reason": self.reason,
            "triggered_policies": self.triggered_policies,
        }
