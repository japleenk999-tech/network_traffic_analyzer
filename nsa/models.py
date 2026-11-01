from dataclasses import dataclass, asdict
from typing import List


@dataclass
class Finding:
    severity: str  # info | low | medium | high
    category: str
    target: str
    message: str
    recommendation: str = ""

    def to_dict(self):
        return asdict(self)


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
