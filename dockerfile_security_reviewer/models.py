from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["low", "medium", "high"]

SEVERITY_ORDER: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


@dataclass(frozen=True)
class Instruction:
    keyword: str
    value: str
    start_line: int
    raw: str


@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    severity: Severity
    line: int
    message: str
    recommendation: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ReviewSummary:
    total: int
    low: int
    medium: int
    high: int

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class ReviewResult:
    path: str
    findings: list[Finding]
    summary: ReviewSummary

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "summary": self.summary.as_dict(),
            "findings": [finding.as_dict() for finding in self.findings],
        }

