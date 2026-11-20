"""Replay the committed ``cases.json`` and check that it is reproducible."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from solution import runner

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_PATH = os.path.join(ROOT, "cases.json")


class ReplayCasesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = runner.load_cases(CASES_PATH)
        cls.report = runner.run_cases(cls.document)

    def test_every_case_passes(self):
        failed = [case["name"] for case in self.report["cases"] if not case["passed"]]
        self.assertEqual(failed, [], f"failing cases: {failed}")
        self.assertEqual(self.report["summary"]["cases_failed"], 0)
        self.assertEqual(self.report["summary"]["steps_failed"], 0)

    def test_case_count_and_step_count(self):
        summary = self.report["summary"]
        self.assertEqual(summary["cases"], 20)
        self.assertGreaterEqual(summary["steps"], 160)
        self.assertEqual(summary["cases_passed"], summary["cases"])
        self.assertEqual(summary["steps_passed"], summary["steps"])

    def test_expected_codes_are_all_documented(self):
        from solution.errors import ERROR_CODES
        codes = set()
        for case in self.document["cases"]:
            for step in case["steps"]:
                if "code" in step["expect"] and step["expect"]["code"]:
                    codes.add(step["expect"]["code"])
        self.assertTrue(codes <= set(ERROR_CODES), sorted(codes - set(ERROR_CODES)))
        # The replay file must actually exercise a broad slice of the rule set.
        self.assertGreaterEqual(len(codes), 20, sorted(codes))

    def test_cases_file_is_reproducible(self):
        """Regenerating the file must reproduce it byte for byte (deterministic)."""
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            script = (
                "import json,sys,os\n"
                f"sys.path.insert(0, {ROOT!r})\n"
                "sys.path.insert(0, os.path.join(%r, 'tools'))\n"
                "import build_cases\n"
                "print(json.dumps(build_cases.build(), sort_keys=False))\n" % ROOT
            )
            output = subprocess.run([sys.executable, "-c", script], capture_output=True,
                                    text=True, check=True).stdout
        regenerated = json.loads(output)
        with open(CASES_PATH, "r", encoding="utf-8") as handle:
            committed = json.load(handle)
        self.assertEqual(regenerated, committed,
                         "cases.json is stale: run python tools/build_cases.py")


if __name__ == "__main__":
    unittest.main()
