"""Atomicity: one commit or nothing, for every shared-state rule.

Each test injects a change *after* phase A (the precheck) and *before* the
commit transaction, which is precisely the window in which a stale verdict
would otherwise be committed.  The same hook also proves that the expensive
verification really does happen outside the transaction: the injected change
runs while no write lock is held.
"""

from __future__ import annotations

import json
import sqlite3
import unittest

from solution import service, store
from tests.support import DEV_A, FULL_V1, FULL_V2, GROUP_A, RECOVERY_V1, DatabaseCase


class PhaseBoundary:
    """Patch ``service._precheck`` to run an action between phase A and phase B."""

    def __init__(self, case: DatabaseCase, action):
        self.case = case
        self.action = action
        self.original = None
        self.calls = 0

    def __enter__(self):
        self.original = service._precheck
        self.active = True

        def wrapped(db_path, attestation):
            summary = self.original(db_path, attestation)
            # The injected action may itself submit a proof; that inner proof
            # must not re-trigger the injection.
            if self.active:
                self.active = False
                try:
                    self.action(self.case, attestation)
                finally:
                    self.active = True
            self.calls += 1
            return summary

        service._precheck = wrapped
        return self

    def __exit__(self, *exc_info):
        service._precheck = self.original
        return False


class CommitRevalidationTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()
        self.issue("ch-a", issued=1000, expires=5000)

    def _attest(self, request_id="a-1", counter=5, **kwargs):
        return self.attest(request_id, counter, at=2000, **kwargs)

    def test_precheck_holds_no_write_lock(self):
        """Another connection may write while phase A is running."""
        observed = {}

        def action(case, attestation):
            conn = sqlite3.connect(case.db_path, timeout=0.1)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE groups SET recovery_min_version = recovery_min_version "
                             "WHERE group_id = ?", (GROUP_A,))
                conn.execute("COMMIT")
                observed["lock"] = "free"
            except sqlite3.OperationalError as exc:
                observed["lock"] = f"held: {exc}"
                conn.execute("ROLLBACK")
            finally:
                conn.close()

        with PhaseBoundary(self, action):
            self.ok(self._attest())
        self.assertEqual(observed["lock"], "free")

    def test_baseline_revoked_during_verification(self):
        def action(case, attestation):
            case.ok({"op": "revoke_baseline", "request_id": "rev-mid", "at": 1900,
                     "baseline_id": FULL_V1["baseline_id"]})

        with PhaseBoundary(self, action) as boundary:
            response = self.op(self._attest())
        self.assertEqual(boundary.calls, 1)
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["code"], "BASELINE_REVOKED")
        self.assertEqual(self.watermark(), -1)
        challenge = self.ok({"op": "get_challenge", "request_id": "q",
                             "challenge_id": "ch-a"})["challenge"]
        self.assertIsNone(challenge["consumed_by"])

    def test_newer_baseline_activated_during_verification(self):
        def action(case, attestation):
            case.ok({"op": "publish_baseline", "request_id": "pub-mid", "at": 1900,
                     "baseline": FULL_V2})

        with PhaseBoundary(self, action):
            response = self.op(self._attest())
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["code"], "BASELINE_SUPERSEDED")

    def test_challenge_expires_during_verification(self):
        def action(case, attestation):
            case.ok({"op": "issue_challenge", "request_id": "noop", "challenge_id": "ch-z",
                     "nonce": "nonce-z", "device_id": DEV_A, "issued_at": 1000,
                     "expires_at": 2100})
            conn = store.connection_for(case.db_path)
            conn.execute("UPDATE challenges SET expires_at = 1999 WHERE challenge_id = 'ch-a'")

        with PhaseBoundary(self, action):
            response = self.op(self._attest())
        self.assertEqual(response["code"], "CHALLENGE_EXPIRED")

    def test_floor_raised_during_verification(self):
        def action(case, attestation):
            case.ok({"op": "set_floors", "request_id": "floors-mid", "group_id": GROUP_A,
                     "at": 1900, "full_min_version": 2})

        with PhaseBoundary(self, action):
            response = self.op(self._attest())
        self.assertEqual(response["code"], "FULL_FLOOR_NOT_MET")

    def test_challenge_reissued_in_newer_generation_during_verification(self):
        def action(case, attestation):
            case.ok({"op": "rotate_generation", "request_id": "rot-mid", "device_id": DEV_A,
                     "new_generation": 2, "at": 1900})

        with PhaseBoundary(self, action):
            response = self.op(self._attest())
        self.assertEqual(response["code"], "GENERATION_MISMATCH")

    def test_counter_advanced_by_another_proof_during_verification(self):
        self.issue("ch-b", issued=1000, expires=5000)

        def action(case, attestation):
            case.ok(case.attest("a-other", 9, challenge_id="ch-b", at=2000))

        with PhaseBoundary(self, action):
            response = self.op(self._attest(counter=5))
        self.assertEqual(response["code"], "COUNTER_ROLLBACK")
        self.assertEqual(self.watermark(), 9)


class AtomicWriteTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()
        self.issue("ch-a")

    def test_receipt_challenge_watermark_and_credential_share_one_commit(self):
        self.ok(self.attest("a-1", 4))
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            receipt = conn.execute("SELECT * FROM receipts WHERE request_id = 'a-1'").fetchone()
            challenge = conn.execute(
                "SELECT * FROM challenges WHERE challenge_id = 'ch-a'").fetchone()
            device = conn.execute("SELECT * FROM devices WHERE device_id = ?",
                                  (DEV_A,)).fetchone()
            credential = conn.execute(
                "SELECT * FROM credentials WHERE issued_at = 1050").fetchone()
        self.assertEqual(receipt["created_at"], 1050)
        self.assertEqual(challenge["consumed_by"], "a-1")
        self.assertEqual(challenge["consumed_at"], 1050)
        self.assertEqual(device["counter_watermark"], 4)
        self.assertEqual(credential["boot_counter"], 4)
        stored = json.loads(receipt["response_json"])
        self.assertEqual(stored["result"]["credential"]["credential_id"],
                         credential["credential_id"])

    def test_denial_is_recorded_and_replayed_identically(self):
        self.issue("ch-b")
        first = self.op(self.attest("deny-1", 4, challenge_id="ch-b", tamper=0))
        self.assertEqual(first["code"], "DIGEST_MISMATCH")
        replay = self.op(self.attest("deny-1", 4, challenge_id="ch-b", tamper=0))
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["code"], "DIGEST_MISMATCH")
        self.assertEqual(self.watermark(), -1)

    def test_reused_request_id_with_new_content_is_refused(self):
        self.ok(self.attest("a-1", 4))
        self.issue("ch-b")
        response = self.op(self.attest("a-1", 5, challenge_id="ch-b"))
        self.assertEqual(response["code"], "REQUEST_ID_CONFLICT")
        self.assertEqual(self.watermark(), 4)

    def test_invalid_request_id(self):
        bad = self.attest("bad id with spaces", 4)
        response = self.op(bad)
        self.assertEqual(response["code"], "REQUEST_ID_INVALID")
        self.assertEqual(self.watermark(), -1)

    def test_unknown_op_and_malformed_request(self):
        self.assertEqual(self.op({"op": "nope", "request_id": "x"})["code"], "BAD_REQUEST")
        self.assertEqual(self.op({"op": "attest", "request_id": "x"})["code"], "BAD_REQUEST")

    def test_recovery_proof_advances_counter_atomically(self):
        self.issue("ch-r")
        self.ok(self.attest("a-r", 6, baseline=RECOVERY_V1, challenge_id="ch-r"))
        self.issue("ch-b")
        self.assertEqual(self.op(self.attest("a-full", 6, challenge_id="ch-b"))["code"],
                         "COUNTER_ROLLBACK")
        self.assertEqual(self.watermark(), 6)


if __name__ == "__main__":
    unittest.main()
