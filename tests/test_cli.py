"""End-to-end command-line checks (run the real module as a subprocess)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES = os.path.join(ROOT, "cases.json")


def run_cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([sys.executable, "-m", "solution", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=300)


class CliTests(unittest.TestCase):
    def test_replay_produces_report_with_exit_code_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "result.json")
            completed = run_cli("--input", CASES, "--output", output, "--quiet")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            with open(output, "r", encoding="utf-8") as handle:
                report = json.load(handle)
        self.assertEqual(report["summary"]["cases_failed"], 0)
        self.assertEqual(report["summary"]["steps_failed"], 0)
        self.assertEqual(report["summary"]["cases"], 20)
        for case in report["cases"]:
            self.assertTrue(case["passed"], case["name"])
            for step in case["steps"]:
                self.assertTrue(step["passed"], (case["name"], step["index"]))

    def test_failing_expectation_yields_exit_code_one_and_details(self):
        document = {
            "schema_version": 1,
            "title": "negative control",
            "cases": [{
                "name": "deliberately-wrong",
                "description": "expects an impossible code; the runner must report the mismatch",
                "steps": [{
                    "request": {"op": "get_device", "request_id": "x", "device_id": "nobody"},
                    "expect": {"status": "denied", "code": "BASELINE_REVOKED"},
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            case_path = os.path.join(tmp, "bad.json")
            out_path = os.path.join(tmp, "out.json")
            with open(case_path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            completed = run_cli("--input", case_path, "--output", out_path, "--quiet")
            self.assertEqual(completed.returncode, 1)
            with open(out_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)
        step = report["cases"][0]["steps"][0]
        self.assertFalse(step["passed"])
        self.assertEqual(step["actual"]["code"], "UNKNOWN_DEVICE")
        self.assertTrue(any("expected 'BASELINE_REVOKED'" in failure for failure in step["failures"]))

    def test_isolated_mode_replays_the_same_report(self):
        """Every phase-A check in its own spawned process must agree exactly."""
        with tempfile.TemporaryDirectory() as tmp:
            in_process = os.path.join(tmp, "in-process.json")
            isolated = os.path.join(tmp, "isolated.json")
            first = run_cli("--input", CASES, "--output", in_process, "--quiet")
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            second = run_cli("--input", CASES, "--output", isolated, "--isolated", "--quiet")
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            with open(in_process, "r", encoding="utf-8") as handle:
                a = json.load(handle)
            with open(isolated, "r", encoding="utf-8") as handle:
                b = json.load(handle)
        self.assertEqual(a["summary"], b["summary"])
        self.assertEqual(b["summary"]["cases_failed"], 0)
        self.assertEqual(b["summary"]["steps_failed"], 0)
        def strip(report):
            return [(step["actual"]["status"], step["actual"]["code"],
                     step["actual"]["replayed"])
                    for case in report["cases"] for step in case["steps"]]
        self.assertEqual(strip(a), strip(b))

    def test_single_request_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "audit.db")
            setup = {
                "op": "create_group", "request_id": "r1", "group_id": "tenant-a:grp-1",
                "at": 0, "full_min_version": 1, "recovery_min_version": 1,
            }
            request_path = os.path.join(tmp, "request.json")
            with open(request_path, "w", encoding="utf-8") as handle:
                json.dump(setup, handle)
            completed = run_cli("--db", db_path, "--request", request_path)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            response = json.loads(completed.stdout)
            self.assertEqual(response["status"], "accepted")
            self.assertEqual(response["result"]["group"]["full_min_version"], 1)


if __name__ == "__main__":
    unittest.main()
