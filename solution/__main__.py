"""Command-line entry point.

    python -m solution --input cases.json --output result.json

Also supports a one-shot request mode:

    python -m solution --db audit.db --request request.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import runner, service, store


def _write_json(path: str, payload: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, indent=2)
        handle.write("\n")
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Offline synthetic boot-attestation audit service.")
    parser.add_argument("--input", help="case file to replay (JSON)")
    parser.add_argument("--output", help="where to write the result report (JSON)")
    parser.add_argument("--db", help="single-request mode: SQLite database path")
    parser.add_argument("--request", help="single-request mode: request JSON file")
    parser.add_argument("--workdir", help="directory for per-case databases")
    parser.add_argument("--keep-databases", action="store_true",
                        help="do not delete the per-case databases")
    parser.add_argument("--quiet", action="store_true", help="only print the summary line")
    parser.add_argument("--isolated", action="store_true",
                        help="verify each proof's phase A in a separate spawned process")
    args = parser.parse_args(argv)

    if args.isolated:
        from .isolate import SubprocessVerifier

        service.set_verifier(SubprocessVerifier())

    if args.db and args.request:
        with open(args.request, "r", encoding="utf-8") as handle:
            request = json.load(handle)
        response = service.execute_operation(args.db, request)
        store.close_thread_connections()
        print(json.dumps(response, sort_keys=True, indent=2))
        return 0 if response.get("status") == "accepted" else 1

    if not args.input:
        parser.error("either --input or (--db and --request) is required")

    document = runner.load_cases(args.input)
    report = runner.run_cases(document, workdir=args.workdir, keep=args.keep_databases)
    summary = report["summary"]
    if args.output:
        _write_json(args.output, report)
    if args.keep_databases and "databases" in summary:
        print(f"databases kept in {summary['databases']}")
    if not args.quiet:
        for case in report["cases"]:
            marker = "PASS" if case["passed"] else "FAIL"
            print(f"[{marker}] {case['name']}")
            for step in case["steps"]:
                if not step["passed"]:
                    print(f"        step {step['index']} ({step['op']}):")
                    for failure in step["failures"]:
                        print(f"          - {failure}")
    print(f"cases {summary['cases_passed']}/{summary['cases']} passed, "
          f"steps {summary['steps_passed']}/{summary['steps']} passed")
    return 0 if summary["cases_failed"] == 0 and summary["steps_failed"] == 0 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
