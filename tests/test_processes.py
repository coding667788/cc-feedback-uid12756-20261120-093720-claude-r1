"""Real multi-process behaviour: concurrent contention, generation races,
separate-process verification, and termination inside the two commit windows.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import unittest

from solution import service, store, worker
from solution.isolate import SubprocessVerifier
from tests.support import DEV_A, WINDOW_END, WINDOW_START, DatabaseCase

CTX = multiprocessing.get_context("spawn")
KILL_TIMEOUT = 60.0


def _run_worker(db_path: str, request: dict, out, control=None) -> None:
    """Top-level so the spawn start method can pickle it.

    Delegates to the shipped worker entry point (``solution.worker``) so the
    tests exercise the same code path a real out-of-process verifier uses.
    """
    worker.worker_main(db_path, request, control, out)


def _spawn(db_path: str, request: dict, control=None):
    out = CTX.Queue()
    process = CTX.Process(target=_run_worker, args=(db_path, request, out, control))
    process.start()
    return process, out


class ProcessCase(DatabaseCase):
    def collect(self, process, out: "queue.Queue", timeout: float = 120.0) -> dict:
        process.join(timeout)
        self.assertFalse(process.is_alive(), "worker did not finish")
        try:
            return out.get(timeout=5)
        finally:
            out.close()
            out.join_thread()

    def audit_connection(self) -> sqlite3.Connection:
        """A fresh connection used by the *test* process to inspect the database."""
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn


class ConcurrentContentionTests(ProcessCase):
    def test_two_qualifying_proofs_race_for_one_challenge(self):
        self.create_world()
        self.issue("ch-a")

        requests = [self.attest("race-a", 9), self.attest("race-b", 10)]
        workers = [_spawn(self.db_path, request) for request in requests]
        responses = [self.collect(*worker) for worker in workers]

        statuses = sorted((response["status"], response["code"]) for response in responses)
        self.assertEqual(statuses,
                         [("accepted", None), ("denied", "CHALLENGE_CONSUMED")],
                         f"unexpected outcomes: {statuses}")

        accepted = next(response for response in responses if response["status"] == "accepted")
        self.assertEqual(accepted["result"]["credential"]["boot_counter"],
                         accepted["result"]["device"]["counter_watermark"])
        self.assertEqual(self.watermark(), accepted["result"]["credential"]["boot_counter"])

        state = self.ok({"op": "get_challenge", "request_id": "q-after", "challenge_id": "ch-a"})
        self.assertIn(state["challenge"]["consumed_by"], ("race-a", "race-b"))

    def test_two_proofs_for_different_challenges_cannot_reuse_a_counter(self):
        self.create_world()
        self.issue("ch-a")
        self.issue("ch-b")
        workers = [_spawn(self.db_path, self.attest("duel-a", 5)),
                   _spawn(self.db_path, self.attest("duel-b", 5, challenge_id="ch-b"))]
        responses = [self.collect(*worker) for worker in workers]
        codes = sorted(str(response["code"]) for response in responses)
        self.assertEqual(codes, ["COUNTER_ROLLBACK", "None"], codes)
        self.assertEqual(self.watermark(), 5)
        rows = self.ok({"op": "list_credentials", "request_id": "q", "device_id": DEV_A})
        self.assertEqual(len(rows["credentials"]), 1)

    def test_verification_runs_in_a_separately_spawned_process(self):
        self.create_world()
        self.issue("ch-a")

        verifier = SubprocessVerifier()
        previous = service.VERIFIER
        service.set_verifier(verifier)
        try:
            result = self.ok(self.attest("iso-a", 4))
            self.assertEqual(result["credential"]["scope"], "full-access")
            self.assertEqual(verifier.calls, 1)
            self.assertIsNotNone(verifier.last_worker_pid)
            self.assertNotEqual(verifier.last_worker_pid, os.getpid(),
                                "phase-A verification must run in its own OS process")

            self.issue("ch-b")
            bad = self.attest("iso-bad", 5, challenge_id="ch-b", tamper=1)
            self.denied(bad, "DIGEST_MISMATCH")
            self.assertEqual(self.watermark(), 4)
        finally:
            service.set_verifier(previous)


    def test_identical_request_ids_in_two_processes_commit_once(self):
        self.create_world()
        self.issue("ch-a")
        request = self.attest("same-id", 8)
        workers = [_spawn(self.db_path, dict(request)) for _ in range(2)]
        responses = [self.collect(*worker) for worker in workers]
        self.assertEqual(sorted(response["status"] for response in responses),
                         ["accepted", "accepted"])
        self.assertEqual(sorted(bool(response.get("replayed")) for response in responses),
                         [False, True])
        first, second = responses
        self.assertEqual(first["result"]["credential"], second["result"]["credential"])
        credentials = self.ok({"op": "list_credentials", "request_id": "q",
                               "device_id": DEV_A})["credentials"]
        self.assertEqual(len(credentials), 1)
        self.assertEqual(self.watermark(), 8)

    def test_conflicting_content_under_one_request_id_in_two_processes(self):
        self.create_world()
        self.issue("ch-a")
        self.issue("ch-b")
        workers = [_spawn(self.db_path, self.attest("shared", 8)),
                   _spawn(self.db_path, self.attest("shared", 8, challenge_id="ch-b"))]
        responses = [self.collect(*worker) for worker in workers]
        codes = sorted(str(response["code"]) for response in responses)
        self.assertEqual(codes, ["None", "REQUEST_ID_CONFLICT"], codes)
        self.assertEqual(len(self.ok({"op": "list_credentials", "request_id": "q",
                                      "device_id": DEV_A})["credentials"]), 1)


class GenerationRaceTests(ProcessCase):
    def test_rotation_during_verification_is_caught_at_commit(self):
        self.create_world()
        self.issue("ch-a", issued=WINDOW_START, expires=10_000)

        original = service._precheck
        state = {"rotated": False}

        def racing_precheck(db_path, attestation):
            summary = original(db_path, attestation)
            if not state["rotated"]:
                state["rotated"] = True
                rotation = service.execute_operation(db_path, {
                    "op": "rotate_generation", "request_id": "rot-mid", "device_id": DEV_A,
                    "new_generation": 2, "at": 5000})
                assert rotation["status"] == "accepted", rotation
            return summary

        service._precheck = racing_precheck
        try:
            response = self.op(self.attest("a-stale", 6))
        finally:
            service._precheck = original

        self.assertEqual(response["status"], "denied", response)
        self.assertEqual(response["code"], "GENERATION_MISMATCH")
        self.assertEqual(response["stage"], "commit")
        device = self.ok({"op": "get_device", "request_id": "q", "device_id": DEV_A})["device"]
        self.assertEqual(device["generation"], 2)
        self.assertEqual(device["counter_watermark"], -1)

    def test_generation_bump_from_another_process_invalidates_challenge(self):
        self.create_world()
        self.issue("ch-a")
        rotation = {"op": "rotate_generation", "request_id": "rot-proc", "device_id": DEV_A,
                    "new_generation": 3, "at": 5000}
        process, out = _spawn(self.db_path, rotation)
        self.assertEqual(self.collect(process, out)["status"], "accepted")

        stale = self.op(self.attest("a-stale", 6, at=1050))
        self.assertEqual(stale["code"], "GENERATION_MISMATCH")


class CrashWindowTests(ProcessCase):
    """Terminate a worker in each of the two documented windows, then replay."""

    def _race_setup(self):
        self.create_world()
        self.issue("ch-a", issued=WINDOW_START, expires=WINDOW_END)
        return self.attest("crash-a", 21)

    def _kill_inside(self, request: dict, tag: str) -> None:
        control = store.Control()
        control.arm(tag)
        process, out = _spawn(self.db_path, request, control)
        try:
            self.assertTrue(control.entered.wait(KILL_TIMEOUT),
                            f"worker never reached kill point {tag!r}")
        finally:
            process.terminate()
            process.join(30)
            out.close()
            out.join_thread()
        self.assertIsNotNone(process.exitcode)

    def test_kill_before_commit_leaves_no_trace(self):
        request = self._race_setup()
        self._kill_inside(dict(request), "before_commit")

        device = self.ok({"op": "get_device", "request_id": "q1", "device_id": DEV_A})["device"]
        self.assertEqual(device["counter_watermark"], -1,
                         "the watermark write must have been rolled back")
        challenge = self.ok({"op": "get_challenge", "request_id": "q2",
                             "challenge_id": "ch-a"})["challenge"]
        self.assertIsNone(challenge["consumed_by"])
        credentials = self.ok({"op": "list_credentials", "request_id": "q3",
                               "device_id": DEV_A})["credentials"]
        self.assertEqual(credentials, [])
        self.assert_no_receipt("crash-a")

        # Replay of the exact same request id succeeds and lands exactly once.
        replay = self.ok(self.attest("crash-a", 21))
        self.assertEqual(replay["credential"]["boot_counter"], 21)
        self.assertEqual(self.watermark(), 21)
        self.assertEqual(len(self.ok({"op": "list_credentials", "request_id": "q4",
                                      "device_id": DEV_A})["credentials"]), 1)

    def test_kill_after_commit_then_replay_returns_the_same_receipt(self):
        request = self._race_setup()
        self._kill_inside(dict(request), "after_commit")

        # The transaction is durable even though the caller never answered.
        device = self.ok({"op": "get_device", "request_id": "q1", "device_id": DEV_A})["device"]
        self.assertEqual(device["counter_watermark"], 21)
        challenge = self.ok({"op": "get_challenge", "request_id": "q2",
                             "challenge_id": "ch-a"})["challenge"]
        self.assertEqual(challenge["consumed_by"], "crash-a")
        first = self.ok({"op": "list_credentials", "request_id": "q3", "device_id": DEV_A})
        self.assertEqual(len(first["credentials"]), 1)
        token = self.ok(self.present(_token_from_receipt(self.db_path, "crash-a")))
        self.assertEqual(token["scope"], "full-access")

        # Replaying the identical request id returns the stored receipt and
        # issues nothing new: same credential id, same token.
        replay_response = self.op(dict(request))
        self.assertEqual(replay_response["status"], "accepted")
        self.assertTrue(replay_response["replayed"])
        stored = self.receipt("crash-a")
        self.assertEqual(replay_response["result"]["credential"],
                         stored["result"]["credential"])
        self.assertEqual(self.watermark(), 21)
        after = self.ok({"op": "list_credentials", "request_id": "q4", "device_id": DEV_A})
        self.assertEqual(len(after["credentials"]), 1)

    def test_replay_after_crash_in_a_fresh_process_is_idempotent(self):
        request = self._race_setup()
        self._kill_inside(dict(request), "after_commit")

        process, out = _spawn(self.db_path, dict(request))
        response = self.collect(process, out)
        self.assertEqual(response["status"], "accepted")
        self.assertTrue(response["replayed"])
        self.assertEqual(self.watermark(), 21)

    # -- helpers ---------------------------------------------------------
    def assert_no_receipt(self, request_id: str) -> None:
        with self.audit_connection() as conn:
            row = conn.execute("SELECT 1 FROM receipts WHERE request_id = ?",
                               (request_id,)).fetchone()
        self.assertIsNone(row)

    def receipt(self, request_id: str) -> dict:
        with self.audit_connection() as conn:
            row = conn.execute("SELECT response_json FROM receipts WHERE request_id = ?",
                               (request_id,)).fetchone()
        self.assertIsNotNone(row)
        return json.loads(row["response_json"])


def _token_from_receipt(db_path: str, request_id: str) -> str:
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        row = conn.execute("SELECT response_json FROM receipts WHERE request_id = ?",
                           (request_id,)).fetchone()
    finally:
        conn.close()
    payload = json.loads(row[0])
    return payload["result"]["credential"]["token"]


if __name__ == "__main__":
    unittest.main()
