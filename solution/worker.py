"""Worker entry point used by the crash / concurrency tests.

``worker_main`` is a module-level function so it can be the target of a
``multiprocessing.Process`` started with the Windows ``spawn`` start method.
The optional ``Control`` object is pickled across the process boundary; its
events are process-shared, which is how a test driver can arm a kill point and
then terminate the worker exactly inside (or immediately after) the write
transaction.
"""

from __future__ import annotations

import sys


def worker_main(db_path: str, request: dict, control, out=None) -> dict | None:
    from .service import execute_operation

    try:
        result = execute_operation(db_path, request, control)
    except BaseException as exc:  # pragma: no cover - only on hard failure
        result = {"status": "error", "code": "WORKER_FAILED", "message": repr(exc)}
    if out is not None:
        out.put(result)
    return result


def main(argv: list[str] | None = None) -> int:
    """``python -m solution.worker --db PATH --request FILE`` for manual poking."""
    import argparse
    import json

    from .service import execute_operation

    parser = argparse.ArgumentParser(description="run one protocol operation in its own process")
    parser.add_argument("--db", required=True)
    parser.add_argument("--request", required=True, help="path to a JSON request file")
    args = parser.parse_args(argv)
    with open(args.request, "r", encoding="utf-8") as handle:
        request = json.load(handle)
    json.dump(execute_operation(args.db, request), sys.stdout, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
