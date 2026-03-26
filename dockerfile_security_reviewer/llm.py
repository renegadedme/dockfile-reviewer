from __future__ import annotations

from .models import ReviewResult


class OpenAIExplanationError(RuntimeError):
    """Raised when the optional OpenAI explanation cannot be generated."""


def explain_with_openai(result: ReviewResult, dockerfile_text: str, model: str) -> str:
    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise OpenAIExplanationError(
            "The optional OpenAI dependency is not installed. Run `python3 -m pip install -e .[openai]` first."
        ) from exc

    client = OpenAI()
    findings_block = "\n".join(
        f"- {finding.code} ({finding.severity}) on line {finding.line}: {finding.title}. {finding.message}"
        for finding in result.findings
    ) or "- No findings."

    response = client.responses.create(
        model=model,
        input=[
            {
                "role": "system",
                "content": (
                    "You explain Dockerfile security findings. Be concise, practical, and prioritize the highest-risk issues first. "
                    "Always include a short remediation strategy and a full revised Dockerfile."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Review this Dockerfile and explain the findings in plain language.\n\n"
                    f"Dockerfile:\n{dockerfile_text}\n\n"
                    f"Findings:\n{findings_block}\n\n"
                    "Respond in two sections named `Summary` and `Suggested Dockerfile`."
                ),
            },
        ],
    )
    return response.output_text.strip()
