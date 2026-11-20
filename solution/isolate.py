"""Run phase-A attestation verification in a genuinely separate OS process.

The service never requires this -- an in-process verification is functionally
identical -- but the task calls for *independent processes* to verify proofs and
issue credentials, so the split is available as a first-class option:

    execute_operation(db, request, verifier=SubprocessVerifier())

Phase A (document load, signature checks, SHA-256 chain audit) then happens in a
short-lived child process that holds no transaction and no write lock.  Phase B
(state re-checks, watermark advance, credential issuance) still happens in the
calling process inside ``BEGIN IMMEDIATE``.  If the child dies, the caller gets
``WORKER_FAILED`` and nothing is committed.
"""

from __future__ import annotations

import multiprocessing
import os
from typing import Any

from .errors import Denial


def _child(db_path: str, attestation: dict, conn) -> None:
    """Child process body: verify and send the outcome over the pipe."""
    from . import service, store

    try:
        summary = service._precheck(db_path, attestation)
        summary["verified_by_pid"] = os.getpid()
        payload: dict[str, Any] = {"ok": summary}
    except Denial as denial:
        payload = {"denial": {"code": denial.code, "message": denial.message,
                              "stage": denial.stage, "detail": denial.detail}}
    except BaseException as exc:  # pragma: no cover - defensive
        payload = {"denial": {"code": "WORKER_FAILED", "message": repr(exc),
                              "stage": "precheck", "detail": None}}
    try:
        conn.send(payload)
    finally:
        store.close_thread_connections()
        conn.close()


class SubprocessVerifier:
    """Callable verifier that executes :func:`solution.service._precheck` in a child."""

    def __init__(self, timeout: float = 60.0) -> None:
        self.timeout = timeout
        self.last_worker_pid: int | None = None
        self.calls = 0

    def __call__(self, db_path: str, attestation: dict) -> dict:
        ctx = multiprocessing.get_context("spawn")
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        process = ctx.Process(target=_child, args=(db_path, attestation, child_conn),
                              name="attest-precheck")
        process.start()
        child_conn.close()
        try:
            if not parent_conn.poll(self.timeout):
                raise Denial("TIMEOUT", "verification worker did not answer in time",
                             stage="precheck")
            payload = parent_conn.recv()
        except EOFError:
            raise Denial("WORKER_FAILED", "verification worker died before answering",
                         stage="precheck")
        finally:
            parent_conn.close()
            process.join(5)
            if process.is_alive():  # pragma: no cover - defensive
                process.terminate()
                process.join(5)
        if "denial" in payload:
            denial = payload["denial"]
            raise Denial(denial["code"], denial["message"], stage=denial["stage"],
                         detail=denial["detail"])
        if process.exitcode not in (0, None):
            raise Denial("WORKER_FAILED",
                         f"verification worker exited with {process.exitcode}", stage="precheck")
        self.calls += 1
        self.last_worker_pid = payload["ok"].get("verified_by_pid")
        return payload["ok"]
