"""Shared test helpers: a throw-away database plus synthetic fixtures."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from solution import service, store, synthetic

GROUP_A = "tenant-a:grp-1"
GROUP_B = "tenant-b:grp-1"
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
DEV_A = "syn-dev-0001"
DEV_B = "syn-dev-0002"

WINDOW_START = 1000
WINDOW_END = 1100

FULL_V1 = synthetic.baseline_doc("bl-full-v1", GROUP_A, "full", 1, 0)
FULL_V2 = synthetic.baseline_doc("bl-full-v2", GROUP_A, "full", 2, 2000, label="bl-full-v2")
RECOVERY_V1 = synthetic.baseline_doc("bl-rec-v1", GROUP_A, "recovery", 1, 0, label="bl-rec-v1")
FULL_B_V1 = synthetic.baseline_doc("bl-b-full-v1", GROUP_B, "full", 1, 0, label="bl-b-full-v1")


class DatabaseCase(unittest.TestCase):
    """A test case with its own temporary directory and SQLite database."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="boot-attest-test-")
        self.db_path = os.path.join(self.tmpdir, "audit.db")

    def tearDown(self) -> None:
        store.close_thread_connections()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- request helpers ---------------------------------------------------
    def op(self, request: dict) -> dict:
        return service.execute_operation(self.db_path, request)

    def ok(self, request: dict) -> dict:
        response = self.op(request)
        self.assertEqual(response["status"], "accepted",
                         f"{request.get('op')} failed: {response.get('code')} {response.get('message')}")
        return response["result"]

    def denied(self, request: dict, code: str) -> dict:
        response = self.op(request)
        self.assertEqual(response["status"], "denied",
                         f"{request.get('op')} unexpectedly accepted")
        self.assertEqual(response["code"], code)
        return response

    # -- world building ----------------------------------------------------
    def create_world(self, *, full: int = 1, recovery: int = 1, device: str = DEV_A,
                     tenant: str = TENANT_A) -> dict:
        self.ok({"op": "create_group", "request_id": "w-group", "group_id": GROUP_A,
                 "at": 0, "full_min_version": full, "recovery_min_version": recovery})
        self.ok({"op": "publish_baseline", "request_id": "w-full", "at": 0, "baseline": FULL_V1})
        self.ok({"op": "publish_baseline", "request_id": "w-rec", "at": 0,
                 "baseline": RECOVERY_V1})
        if device is not None:
            self.ok({"op": "register_device", "request_id": "w-dev", "at": 0,
                     "device_id": device, "tenant_id": tenant, "group_id": GROUP_A})
        return {"full": FULL_V1, "recovery": RECOVERY_V1, "device": device, "tenant": tenant}

    def issue(self, challenge_id: str, *, device: str = DEV_A, nonce: str | None = None,
              issued: int = WINDOW_START, expires: int = WINDOW_END) -> str:
        self.ok({"op": "issue_challenge", "request_id": f"issue-{challenge_id}",
                 "challenge_id": challenge_id, "nonce": nonce or f"nonce-{challenge_id}",
                 "device_id": device, "issued_at": issued, "expires_at": expires})
        return challenge_id

    def rotate(self, generation: int, at: int, device: str = DEV_A) -> dict:
        return self.ok({"op": "rotate_generation", "request_id": f"rot-{generation}-{at}",
                        "device_id": device, "new_generation": generation, "at": at})

    def watermark(self, device: str = DEV_A) -> int:
        result = self.ok({"op": "get_device", "request_id": f"get-{device}-{self._seq()}",
                          "device_id": device})
        return result["device"]["counter_watermark"]

    _counter = 0

    def _seq(self) -> int:
        DatabaseCase._counter += 1
        return DatabaseCase._counter

    def attest(self, request_id: str, counter: int, *, baseline: dict | None = None,
               challenge_id: str = "ch-a", at: int = 1050, observed: int | None = None,
               device: str = DEV_A, tenant: str = TENANT_A, generation: int = 1,
               group: str | None = None, requested_scope: str | None = None,
               **chain_kwargs) -> dict:
        doc = baseline or FULL_V1
        entries = synthetic.chain_entries(doc, **chain_kwargs)
        payload = synthetic.attestation(tenant, device, group or doc["group_id"], generation,
                                        challenge_id, doc["baseline_id"], counter,
                                        at if observed is None else observed, entries)
        return synthetic.attest_request(request_id, at, payload, requested_scope)

    def resign(self, request: dict, *, device: str = DEV_A) -> dict:
        """Re-sign an attestation after a deliberate mutation.

        Chain defects are simulated at the *witness* side (a buggy or
        compromised measurement agent), so the witness signature must be
        recomputed; otherwise every mutation test would stop at the signature
        rule and never reach the chain rule under test.
        """
        payload = request["attestation"]
        payload.pop("witness_signature", None)
        payload["witness_signature"] = synthetic.crypto.sign_attestation(device, payload)
        return request

    def present(self, token: str, *, at: int = 1050) -> dict:
        return {"op": "present_credential", "request_id": f"present-{self._seq()}",
                "token": token, "at": at}
