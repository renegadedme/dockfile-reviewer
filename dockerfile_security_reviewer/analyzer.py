from __future__ import annotations

from pathlib import Path

from .models import ReviewResult, ReviewSummary
from .parser import parse_dockerfile
from .rules import run_rules


class DockerfileReviewer:
    def review_text(self, text: str, path: str = "<memory>") -> ReviewResult:
        instructions = parse_dockerfile(text)
        findings = run_rules(instructions)
        summary = ReviewSummary(
            total=len(findings),
            low=sum(1 for finding in findings if finding.severity == "low"),
            medium=sum(1 for finding in findings if finding.severity == "medium"),
            high=sum(1 for finding in findings if finding.severity == "high"),
        )
        return ReviewResult(path=path, findings=findings, summary=summary)

    def review_file(self, path: str | Path) -> ReviewResult:
        dockerfile_path = Path(path)
        return self.review_text(dockerfile_path.read_text(encoding="utf-8"), path=str(dockerfile_path))

