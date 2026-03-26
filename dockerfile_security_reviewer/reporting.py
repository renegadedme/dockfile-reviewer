from __future__ import annotations

import json

from .models import ReviewResult, SEVERITY_ORDER, Severity


def format_text_report(result: ReviewResult) -> str:
    lines = [
        f"Dockerfile review for {result.path}",
        (
            f"Found {result.summary.total} issue{'s' if result.summary.total != 1 else ''}: "
            f"{result.summary.high} high, {result.summary.medium} medium, {result.summary.low} low"
        ),
    ]

    if not result.findings:
        lines.append("")
        lines.append("No findings. The Dockerfile passed the current rule set.")
        return "\n".join(lines)

    for finding in result.findings:
        lines.append("")
        lines.append(f"[{finding.severity.upper()}] {finding.code} line {finding.line}: {finding.title}")
        lines.append(f"  {finding.message}")
        lines.append(f"  Fix: {finding.recommendation}")

    return "\n".join(lines)


def format_json_report(result: ReviewResult, explanation: str | None = None) -> str:
    payload = result.as_dict()
    if explanation:
        payload["explanation"] = explanation
    return json.dumps(payload, indent=2)


def meets_threshold(result: ReviewResult, minimum: Severity) -> bool:
    required_score = SEVERITY_ORDER[minimum]
    return any(SEVERITY_ORDER[finding.severity] >= required_score for finding in result.findings)

