from __future__ import annotations

import unittest
from pathlib import Path

from dockerfile_security_reviewer.analyzer import DockerfileReviewer
from dockerfile_security_reviewer.parser import parse_dockerfile


ROOT = Path(__file__).resolve().parents[1]


class ParserTests(unittest.TestCase):
    def test_multiline_instructions_are_collapsed(self) -> None:
        dockerfile = """
        FROM python:3.12-slim
        RUN apt-get update && apt-get install -y --no-install-recommends curl \\
            git
        USER appuser
        """
        instructions = parse_dockerfile(dockerfile)

        self.assertEqual([instruction.keyword for instruction in instructions], ["FROM", "RUN", "USER"])
        self.assertEqual(instructions[1].start_line, 3)


class AnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reviewer = DockerfileReviewer()

    def test_insecure_sample_has_expected_findings(self) -> None:
        sample = (ROOT / "samples" / "insecure.Dockerfile").read_text(encoding="utf-8")
        result = self.reviewer.review_text(sample, path="samples/insecure.Dockerfile")
        codes = {finding.code for finding in result.findings}

        self.assertTrue({"DSR001", "DSR002", "DSR003", "DSR005", "DSR007", "DSR008", "DSR011"}.issubset(codes))
        self.assertEqual(result.summary.high, 3)

    def test_secure_sample_has_no_findings(self) -> None:
        sample = (ROOT / "samples" / "secure.Dockerfile").read_text(encoding="utf-8")
        result = self.reviewer.review_text(sample, path="samples/secure.Dockerfile")

        self.assertEqual(result.summary.total, 0)

    def test_explicit_root_user_is_flagged(self) -> None:
        dockerfile = """
        FROM python:3.12-slim
        USER root
        """
        result = self.reviewer.review_text(dockerfile)
        codes = [finding.code for finding in result.findings]
        self.assertIn("DSR004", codes)


if __name__ == "__main__":
    unittest.main()

