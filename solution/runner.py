"""Case-file runner: replay ``cases.json`` and compare against expectations.

The case file is a list of named cases; each case owns a fresh SQLite database
and is a list of steps.  A step is ``{"request": {...}, "expect": {...}}`` where
``expect`` may contain:

``status``  ``"accepted"`` or ``"denied"``
``code``    the exact error code (``null`` for accepted steps)
``result``  a nested object that must be a *subset* of the response ``result``

Subset matching keeps the expected data readable while still asserting concrete
values (credential scope, counter watermark, baseline state ...).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Any

from . import service, store


def _subset(expected: Any, actual: Any, path: str = "") -> list[str]:
    """Return a list of human-readable mismatches."""
    failures: list[str] = []
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path or '.'}: expected object, got {type(actual).__name__}"]
        for key, value in expected.items():
            child = f"{path}.{key}" if path else key
            if key not in actual:
                failures.append(f"{child}: missing from response")
            else:
                failures.extend(_subset(value, actual[key], child))
        return failures
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(expected) != len(actual):
            return [f"{path or '.'}: expected list of {len(expected)}, got {actual!r}"]
        for index, (want, got) in enumerate(zip(expected, actual)):
            failures.extend(_subset(want, got, f"{path}[{index}]"))
        return failures
    if expected != actual:
        failures.append(f"{path or '.'}: expected {expected!r}, got {actual!r}")
    return failures


def check_expectation(expect: dict, response: dict) -> list[str]:
    failures: list[str] = []
    if "status" in expect and response.get("status") != expect["status"]:
        failures.append(f"status: expected {expect['status']!r}, got {response.get('status')!r}")
    if "code" in expect and response.get("code") != expect["code"]:
        failures.append(f"code: expected {expect['code']!r}, got {response.get('code')!r}")
    if "result" in expect:
        failures.extend(_subset(expect["result"], response.get("result"), "result"))
    return failures


def run_case(db_path: str, case: dict, control=None) -> dict:
    steps_out = []
    for index, step in enumerate(case.get("steps", [])):
        request = step["request"]
        expect = step.get("expect", {})
        try:
            response = service.execute_operation(db_path, request, control)
        except Exception as exc:  # pragma: no cover - runner-level safety net
            response = {"status": "error", "code": "INTERNAL", "message": repr(exc),
                        "result": None, "replayed": False}
        failures = check_expectation(expect, response)
        steps_out.append({
            "index": index,
            "op": request.get("op"),
            "request_id": request.get("request_id"),
            "expected": expect,
            "actual": {
                "status": response.get("status"),
                "code": response.get("code"),
                "message": response.get("message"),
                "stage": response.get("stage"),
                "replayed": response.get("replayed"),
                "result": response.get("result"),
            },
            "passed": not failures,
            "failures": failures,
        })
    return {
        "name": case.get("name"),
        "description": case.get("description"),
        "passed": all(step["passed"] for step in steps_out),
        "steps": steps_out,
    }


def run_cases(document: dict, workdir: str | None = None, keep: bool = False) -> dict:
    """Replay every case against a fresh database; return a report.

    ``workdir`` is where the disposable per-case databases are created (the
    caller's ``--workdir``); ``keep`` leaves them in place for inspection and
    reports the directory in the summary.
    """
    cases = document.get("cases", [])
    if workdir:
        os.makedirs(workdir, exist_ok=True)
    root = tempfile.mkdtemp(prefix="boot-attest-cases-", dir=workdir)
    results = []
    try:
        for case in cases:
            safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(case.get("name")))[:64]
            case_dir = os.path.join(root, safe or "case")
            os.makedirs(case_dir, exist_ok=True)
            results.append(run_case(os.path.join(case_dir, "audit.db"), case))
    finally:
        store.close_thread_connections()
        if not keep:
            shutil.rmtree(root, ignore_errors=True)
    summary = {
        "cases": len(results),
        "cases_passed": sum(1 for case in results if case["passed"]),
        "steps": sum(len(case["steps"]) for case in results),
        "steps_passed": sum(1 for case in results for step in case["steps"] if step["passed"]),
    }
    summary["cases_failed"] = summary["cases"] - summary["cases_passed"]
    summary["steps_failed"] = summary["steps"] - summary["steps_passed"]
    if keep:
        summary["databases"] = root
    return {
        "schema_version": document.get("schema_version", 1),
        "title": document.get("title"),
        "summary": summary,
        "cases": results,
    }


def load_cases(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
        raise SystemExit(f"{path}: expected an object with a 'cases' list")
    return document
