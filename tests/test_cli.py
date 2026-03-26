from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_json_output_is_machine_readable(self) -> None:
        command = [
            sys.executable,
            "-m",
            "dockerfile_security_reviewer",
            str(ROOT / "samples" / "insecure.Dockerfile"),
            "--format",
            "json",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)

        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["summary"]["total"], 7)

    def test_fail_on_high_passes_for_clean_file(self) -> None:
        command = [
            sys.executable,
            "-m",
            "dockerfile_security_reviewer",
            str(ROOT / "samples" / "secure.Dockerfile"),
            "--fail-on",
            "high",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)

        self.assertEqual(completed.returncode, 0)
        self.assertIn("No findings", completed.stdout)


if __name__ == "__main__":
    unittest.main()
