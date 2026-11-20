"""Edge conditions and the codes that the happy/sad paths of the main suite
do not reach: unknown references, stale credentials, limits, lock timeouts.
"""

from __future__ import annotations

import sqlite3
import unittest

from solution import crypto, service, store, synthetic
from tests.support import (DEV_A, FULL_V1, GROUP_A, RECOVERY_V1, TENANT_A, DatabaseCase)


class ReferenceTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()
        self.issue("ch-a")

    def test_unknown_challenge(self):
        self.denied(self.attest("a-unknown", 3, challenge_id="ch-nope"), "CHALLENGE_UNKNOWN")

    def test_challenge_issued_for_another_device(self):
        self.ok({"op": "register_device", "request_id": "reg-b", "at": 0, "device_id": DEV_B_LOCAL,
                 "tenant_id": TENANT_A, "group_id": GROUP_A})
        self.issue("ch-b", device=DEV_B_LOCAL)
        self.denied(self.attest("a-other", 3, challenge_id="ch-b"), "CHALLENGE_DEVICE_MISMATCH")

    def test_tenant_mismatch_against_registration(self):
        # Signed by the device itself, but claims the wrong tenant.
        request = self.attest("a-tenant", 3, tenant="tenant-z")
        self.denied(request, "TENANT_MISMATCH")

    def test_baseline_not_yet_published(self):
        future = synthetic.baseline_doc("bl-future", GROUP_A, "full", 2, 0, label="bl-future")
        self.ok({"op": "publish_baseline", "request_id": "p-future", "at": 3000,
                 "baseline": future})
        # The baseline can be selected, but at t=1050 it did not exist yet:
        # this is the historical check, and it fires before the current-state
        # supersession check for the same reason.
        self.issue("ch-wide", issued=2900, expires=3100)
        response = self.op({"op": "attest", "request_id": "a-future", "at": 2999,
                            "attestation": synthetic.attestation(
                                TENANT_A, DEV_A, GROUP_A, 1, "ch-wide", "bl-future", 3, 2999,
                                synthetic.chain_entries(future))})
        self.assertEqual(response["code"], "BASELINE_NOT_PUBLISHED")
        self.assertEqual(response["stage"], "commit")

    def test_recovery_below_its_own_floor(self):
        self.ok({"op": "set_floors", "request_id": "floors", "group_id": GROUP_A,
                 "at": 0, "recovery_min_version": 2})
        self.issue("ch-r")
        self.denied(self.attest("a-rec", 3, baseline=RECOVERY_V1, challenge_id="ch-r"),
                    "RECOVERY_FLOOR_NOT_MET")

    def test_chain_too_long(self):
        request = self.attest("a-long", 3)
        chain = request["attestation"]["chain"]
        filler = dict(chain[-1])
        while len(chain) <= crypto.MAX_CHAIN:
            filler = dict(filler, seq=len(chain))
            chain.append(dict(filler))
        request["attestation"]["chain_root"] = crypto.recompute_chain(
            TENANT_A, "ch-a", chain)[-1]
        self.denied(self.resign(request), "CHAIN_TOO_LONG")

    def test_baseline_with_too_many_modules(self):
        doc = synthetic.baseline_doc("bl-huge", GROUP_A, "full", 4, 0)
        doc["modules"] = [
            synthetic.module(index, f"m{index}", synthetic.digest_of(f"bl-huge/m{index}"))
            for index in range(crypto.MAX_CHAIN + 1)
        ]
        response = self.op({"op": "publish_baseline", "request_id": "p-huge", "at": 0,
                            "baseline": doc})
        self.assertEqual(response["code"], "CHAIN_TOO_LONG")

    def test_credential_from_previous_generation(self):
        self.ok(self.attest("a-1", 4))
        token = self.ok({"op": "list_credentials", "request_id": "q",
                         "device_id": DEV_A})["credentials"]
        self.assertEqual(len(token), 1)
        # Revoke only via generation change, then present with a "revocation
        # happened after this moment" timestamp trick: the generation check
        # still catches it.
        self.rotate(2, at=5000)
        self.denied(self.present(_token_of(self.db_path, "a-1"), at=4000),
                    "CREDENTIAL_GENERATION_STALE")

    def test_credential_without_device(self):
        self.ok(self.attest("a-1", 4))
        token = _token_of(self.db_path, "a-1")
        store.close_thread_connections()
        raw = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        try:
            raw.execute("PRAGMA foreign_keys = OFF")
            raw.execute("DELETE FROM credentials WHERE device_id = ?", (DEV_A,))
            raw.execute("DELETE FROM challenges WHERE device_id = ?", (DEV_A,))
            raw.execute("DELETE FROM devices WHERE device_id = ?", (DEV_A,))
            self.denied(self.present(token), "CREDENTIAL_UNKNOWN")
            # Recreate the credential row directly to exercise the "known
            # credential, unknown device" branch (possible only after manual
            # data loss: the service itself never leaves an orphan behind).
            raw.execute(
                "INSERT INTO credentials(credential_id, token, device_id, tenant_id, scope, "
                "generation, baseline_id, boot_counter, issued_at, revoked_at, revoke_reason) "
                "VALUES ('cred-orphan', ?, ?, ?, 'full-access', 1, ?, 4, 1050, NULL, NULL)",
                (token, DEV_A, TENANT_A, FULL_V1["baseline_id"]))
        finally:
            raw.close()
        self.denied(self.present(token), "CREDENTIAL_DEVICE_UNKNOWN")


DEV_B_LOCAL = "syn-dev-0002"


class LockContentionTests(DatabaseCase):
    def test_writer_times_out_with_a_stable_code(self):
        self.create_world()
        self.issue("ch-a")
        previous = service.TXN_DEADLINE_SECONDS
        service.TXN_DEADLINE_SECONDS = 0.2
        blocker = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            response = self.op(self.attest("a-blocked", 3))
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()
            service.TXN_DEADLINE_SECONDS = previous
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["code"], "TIMEOUT")
        self.assertEqual(self.watermark(), -1)


def _token_of(db_path: str, request_id: str) -> str:
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        row = conn.execute("SELECT response_json FROM receipts WHERE request_id = ?",
                           (request_id,)).fetchone()
    finally:
        conn.close()
    import json
    return json.loads(row[0])["result"]["credential"]["token"]


if __name__ == "__main__":
    unittest.main()
