from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import DockerfileReviewer
from .llm import OpenAIExplanationError, explain_with_openai
from .models import Severity
from .reporting import format_json_report, format_text_report, meets_threshold


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dockerfile-reviewer",
        description="Review Dockerfiles for common security and maintainability mistakes.",
    )
    parser.add_argument("path", help="Path to the Dockerfile to review.")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format.")
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high"),
        default="high",
        help="Exit with status 1 when findings meet or exceed this severity.",
    )
    parser.add_argument(
        "--explain-with-openai",
        action="store_true",
        help="Use the optional OpenAI integration to summarize findings.",
    )
    parser.add_argument(
        "--openai-model",
        default="gpt-4.1-mini",
        help="Model name used when --explain-with-openai is enabled.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    reviewer = DockerfileReviewer()
    dockerfile_path = Path(args.path)
    dockerfile_text = dockerfile_path.read_text(encoding="utf-8")
    result = reviewer.review_text(dockerfile_text, path=str(dockerfile_path))

    explanation: str | None = None
    if args.explain_with_openai:
        try:
            explanation = explain_with_openai(result, dockerfile_text, model=args.openai_model)
        except OpenAIExplanationError as exc:
            parser.exit(status=2, message=f"{exc}\n")

    if args.format == "json":
        print(format_json_report(result, explanation=explanation))
    else:
        print(format_text_report(result))
        if explanation:
            print("\nOpenAI summary\n")
            print(explanation)

    return 1 if meets_threshold(result, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())

