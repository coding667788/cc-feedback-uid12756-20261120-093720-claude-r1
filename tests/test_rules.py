"""Verification rules and baseline lifecycle."""

from __future__ import annotations

import unittest

from solution import baselines, crypto, synthetic
from tests.support import (DEV_A, DEV_B, FULL_B_V1, FULL_V1, FULL_V2, GROUP_A, GROUP_B,
                           RECOVERY_V1, TENANT_B, DatabaseCase)

module_names = ["firmware", "bootloader", "kernel", "initramfs", "userspace"]


class HappyPathTests(DatabaseCase):
    def test_full_proof_issues_full_access_and_advances_counter(self):
        self.create_world()
        self.issue("ch-a")
        result = self.ok(self.attest("a-1", 7))
        cred = result["credential"]
        self.assertEqual(cred["scope"], "full-access")
        self.assertEqual(cred["baseline_kind"], "full")
        self.assertEqual(cred["boot_counter"], 7)
        self.assertEqual(result["previous_counter"], -1)
        self.assertEqual(result["device"]["counter_watermark"], 7)
        self.assertEqual(result["chain_length"], 5)
        self.assertEqual(result["critical_modules"], ["firmware", "bootloader", "kernel"])
        self.assertEqual(result["chain_root"], crypto.recompute_chain(
            "tenant-a", "ch-a", synthetic.chain_entries(FULL_V1))[-1])
        self.assertEqual(self.watermark(), 7)
        token_ok = self.ok(self.present(cred["token"]))
        self.assertEqual(token_ok["scope"], "full-access")

    def test_credential_token_is_deterministic_and_checked_against_db(self):
        self.create_world()
        self.issue("ch-a")
        token = self.ok(self.attest("a-1", 7))["credential"]["token"]
        credential_id = "cred-" + crypto.sha256_hex(b"a-1")[:24]
        self.assertEqual(token, crypto.credential_token(credential_id, "full-access", 1, DEV_A))
        forged = token[:-1] + ("0" if token[-1] != "0" else "1")
        self.denied(self.present(forged), "CREDENTIAL_UNKNOWN")


class ChainAuditTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()
        self.issue("ch-a")

    def test_missing_module(self):
        self.denied(self.attest("a-missing", 3, drop=2), "MISSING_MODULE")
        self.assertEqual(self.watermark(), -1)

    def test_truncated_chain(self):
        self.denied(self.attest("a-short", 3, truncated_to=3), "MISSING_MODULE")

    def test_wrong_order(self):
        self.denied(self.attest("a-order", 3, reorder=(1, 2)), "MODULE_POSITION_MISMATCH")

    def test_shuffled_sequence_numbers(self):
        self.denied(self.attest("a-seq", 3, reorder=(1, 2), keep_seq=True), "CHAIN_SEQ_ORDER")

    def test_sequence_gap(self):
        request = self.attest("a-gap", 3)
        # All five modules are present and in the right positions, but the
        # numbering skips 4 and ends at 5.
        request["attestation"]["chain"][4]["seq"] = 5
        self.denied(self.resign(request), "CHAIN_SEQ_GAP")

    def test_duplicate_sequence_number(self):
        request = self.attest("a-dup", 3)
        request["attestation"]["chain"][2]["seq"] = 1
        self.denied(self.resign(request), "CHAIN_SEQ_DUPLICATE")

    def test_tampered_digest(self):
        self.denied(self.attest("a-digest", 3, tamper=2), "DIGEST_MISMATCH")

    def test_extra_module(self):
        self.denied(self.attest("a-extra", 3, extra_module="telemetry-agent"), "EXTRA_MODULE")

    def test_empty_chain(self):
        request = self.attest("a-empty", 3)
        request["attestation"]["chain"] = []
        request["attestation"]["chain_root"] = "00" * 32
        self.denied(self.resign(request), "CHAIN_EMPTY")

    def test_tampered_link_digest(self):
        request = self.attest("a-link", 3)
        request["attestation"]["chain"][2]["link_digest"] = "cd" * 32
        self.denied(self.resign(request), "CHAIN_LINK_MISMATCH")

    def test_tampered_root(self):
        request = self.attest("a-root", 3)
        request["attestation"]["chain_root"] = "ef" * 32
        self.denied(self.resign(request), "CHAIN_ROOT_MISMATCH")

    def test_witness_signature_invalid(self):
        request = self.attest("a-sig", 3)
        request["attestation"]["witness_signature"] = "ab" * 32
        self.denied(request, "WITNESS_SIGNATURE_INVALID")

    def test_critical_flag_must_match_baseline(self):
        request = self.attest("a-crit", 3)
        request["attestation"]["chain"][3]["critical"] = True
        # The witness signed the pre-mutation payload, so re-sign to isolate
        # the criticality rule from the signature rule.
        payload = request["attestation"]
        payload["witness_signature"] = crypto.sign_attestation(DEV_A, payload)
        self.denied(request, "CRITICAL_MODULE_UNKNOWN")

    def test_baseline_module_positions_are_contiguous(self):
        bad = synthetic.baseline_doc("bl-x", GROUP_A, "full", 3, 0)
        bad["modules"][2]["position"] = 4
        response = self.op({"op": "publish_baseline", "request_id": "p-bad", "at": 0,
                            "baseline": bad})
        self.assertEqual(response["code"], "BAD_REQUEST")

    def test_baseline_signature_must_verify(self):
        bad = dict(FULL_V1, note="edited after signing", signature="11" * 32)
        response = self.op({"op": "publish_baseline", "request_id": "p-sig", "at": 0,
                            "baseline": bad})
        self.assertEqual(response["code"], "BASELINE_SIGNATURE_INVALID")
        signed = baselines.attach_signature(
            synthetic.baseline_doc("bl-full-signed", GROUP_A, "full", 2, 0, label="signed"))
        self.ok({"op": "publish_baseline", "request_id": "p-sig-ok", "at": 0, "baseline": signed})

    def test_baseline_digest_mismatch_is_detected_at_read_time(self):
        from solution import store
        conn = store.connection_for(self.db_path)
        conn.execute("UPDATE baselines SET doc_json = replace(doc_json, 'userspace', 'userspac3') "
                     "WHERE baseline_id = ?", (FULL_V1["baseline_id"],))
        self.denied(self.attest("a-doc", 3), "BASELINE_DOC_MISMATCH")
        conn.execute("UPDATE baselines SET doc_json = replace(doc_json, 'userspac3', 'userspace') "
                     "WHERE baseline_id = ?", (FULL_V1["baseline_id"],))


class TenantAndGroupTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()
        self.ok({"op": "create_group", "request_id": "b-group", "group_id": GROUP_B, "at": 0})
        self.ok({"op": "publish_baseline", "request_id": "b-full", "at": 0, "baseline": FULL_B_V1})
        self.ok({"op": "register_device", "request_id": "b-dev", "at": 0, "device_id": DEV_B,
                 "tenant_id": TENANT_B, "group_id": GROUP_B})
        self.issue("ch-a")
        self.issue("ch-b", device=DEV_B)

    def test_same_module_names_in_other_tenant_cannot_be_reused(self):
        # Identical module names and digests are not enough: the baseline is
        # bound to its group, and the device to its tenant.
        # Claiming group B while registered to group A: rejected at commit.
        response = self.denied(
            self.attest("a-cross", 3, baseline=FULL_B_V1, challenge_id="ch-b"),
            "GROUP_MISMATCH")
        self.assertEqual(response["stage"], "commit")
        # Claiming group A but naming a group-B baseline: rejected before commit.
        response = self.denied(
            self.attest("a-cross-2", 3, baseline=FULL_B_V1, challenge_id="ch-b",
                        group=GROUP_A),
            "BASELINE_GROUP_MISMATCH")
        self.assertEqual(response["stage"], "precheck")

    def test_challenge_from_other_tenant(self):
        self.denied(self.attest("b-cross", 3, challenge_id="ch-a", device=DEV_B,
                                tenant=TENANT_B, baseline=FULL_B_V1),
                    "CHALLENGE_TENANT_MISMATCH")

    def test_device_using_other_tenant_challenge_for_its_own_baseline(self):
        self.denied(self.attest("b-cross-2", 3, challenge_id="ch-a", device=DEV_B,
                                tenant=TENANT_B, baseline=FULL_B_V1),
                    "CHALLENGE_TENANT_MISMATCH")

    def test_group_claim_contradicting_registration(self):
        self.ok({"op": "register_device", "request_id": "c-dev", "at": 0,
                 "device_id": "syn-dev-0003", "tenant_id": TENANT_B, "group_id": GROUP_A})
        self.issue("ch-c", device="syn-dev-0003")
        self.denied(self.attest("c-claim", 3, challenge_id="ch-c", device="syn-dev-0003",
                                tenant=TENANT_B, baseline=FULL_B_V1),
                    "GROUP_MISMATCH")

    def test_unknown_device_and_unknown_baseline(self):
        self.denied(self.attest("d-unknown", 3, device="syn-dev-9999",
                                challenge_id="ch-a"), "UNKNOWN_DEVICE")
        ghost = synthetic.baseline_doc("bl-ghost", GROUP_A, "full", 9, 0)
        self.denied(self.attest("d-ghost", 3, baseline=ghost), "BASELINE_UNKNOWN")


class ChallengeWindowTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()

    def test_half_open_window_boundaries(self):
        self.issue("ch-a")
        self.ok(self.attest("a-first", 1, at=1000))
        self.issue("ch-b")
        self.ok(self.attest("a-last", 2, challenge_id="ch-b", at=1099))
        self.issue("ch-c")
        self.denied(self.attest("a-edge", 3, challenge_id="ch-c", at=1100), "CHALLENGE_EXPIRED")
        self.issue("ch-d")
        self.denied(self.attest("a-late", 4, challenge_id="ch-d", at=1300), "CHALLENGE_EXPIRED")

    def test_before_issue_time(self):
        self.issue("ch-a")
        self.denied(self.attest("a-early", 1, at=999), "CHALLENGE_NOT_YET_VALID")

    def test_device_observation_window_is_checked_too(self):
        self.issue("ch-a")
        self.denied(self.attest("a-obs", 1, at=1050, observed=1100), "CHALLENGE_EXPIRED")

    def test_challenge_single_use(self):
        self.issue("ch-a")
        self.ok(self.attest("a-1", 5))
        self.denied(self.attest("a-2", 6), "CHALLENGE_CONSUMED")
        self.denied(self.attest("a-3", 6), "CHALLENGE_CONSUMED")
        self.assertEqual(self.watermark(), 5)

    def test_duplicate_challenge_id_and_nonce(self):
        self.issue("ch-a")
        duplicate_id = {"op": "issue_challenge", "request_id": "dup-id", "challenge_id": "ch-a",
                        "nonce": "another", "device_id": DEV_A, "issued_at": 1000,
                        "expires_at": 1100}
        self.assertEqual(self.op(duplicate_id)["code"], "CHALLENGE_CONFLICT")
        duplicate_nonce = {"op": "issue_challenge", "request_id": "dup-nonce",
                           "challenge_id": "ch-b", "nonce": "nonce-ch-a", "device_id": DEV_A,
                           "issued_at": 1000, "expires_at": 1100}
        self.assertEqual(self.op(duplicate_nonce)["code"], "CHALLENGE_CONFLICT")
        inverted = {"op": "issue_challenge", "request_id": "inv", "challenge_id": "ch-c",
                    "nonce": "n-c", "device_id": DEV_A, "issued_at": 1100, "expires_at": 1100}
        self.assertEqual(self.op(inverted)["code"], "BAD_REQUEST")


class CounterTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()

    def test_monotonic_watermark(self):
        self.issue("ch-1")
        self.ok(self.attest("a-1", 5, challenge_id="ch-1"))
        self.issue("ch-2")
        self.denied(self.attest("a-2", 5, challenge_id="ch-2"), "COUNTER_ROLLBACK")
        self.issue("ch-3")
        self.denied(self.attest("a-3", 4, challenge_id="ch-3"), "COUNTER_ROLLBACK")
        self.issue("ch-4")
        self.ok(self.attest("a-4", 6, challenge_id="ch-4"))

    def test_recovery_advances_the_watermark(self):
        self.issue("ch-r")
        self.ok(self.attest("a-r", 9, baseline=RECOVERY_V1, challenge_id="ch-r"))
        self.assertEqual(self.watermark(), 9)
        self.issue("ch-2")
        self.denied(self.attest("a-2", 9, challenge_id="ch-2"), "COUNTER_ROLLBACK")
        self.issue("ch-3")
        self.denied(self.attest("a-3", 8, challenge_id="ch-3", baseline=RECOVERY_V1),
                    "COUNTER_ROLLBACK")

    def test_negative_and_missing_counter(self):
        self.issue("ch-a")
        request = self.attest("a-neg", -1)
        self.denied(request, "COUNTER_INVALID")
        request = self.attest("a-missing", 0)
        del request["attestation"]["boot_counter"]
        self.assertEqual(self.op(request)["code"], "BAD_REQUEST")

    def test_recovery_cannot_lower_the_counter_or_the_floor(self):
        # The group requires full >= 2; a recovery proof may not present v1 full.
        self.ok({"op": "set_floors", "request_id": "floors", "group_id": GROUP_A,
                 "at": 0, "full_min_version": 2})
        self.issue("ch-a")
        self.denied(self.attest("a-old-full", 3), "FULL_FLOOR_NOT_MET")
        self.issue("ch-r")
        self.ok(self.attest("a-rec", 3, baseline=RECOVERY_V1, challenge_id="ch-r",
                            requested_scope="diagnostic-readonly"))


class RecoveryTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()

    def test_recovery_only_issues_diagnostic_readonly(self):
        self.issue("ch-r")
        result = self.ok(self.attest("a-r", 2, baseline=RECOVERY_V1, challenge_id="ch-r"))
        self.assertEqual(result["credential"]["scope"], "diagnostic-readonly")
        self.assertEqual(result["credential"]["baseline_kind"], "recovery")

    def test_recovery_cannot_be_upgraded(self):
        self.issue("ch-r")
        self.denied(self.attest("a-r", 2, baseline=RECOVERY_V1, challenge_id="ch-r",
                                requested_scope="full-access"),
                    "RECOVERY_SCOPE_DENIED")
        # Denial is atomic: the challenge survives and the watermark is untouched.
        self.assertEqual(self.watermark(), -1)
        self.ok(self.attest("a-r-ok", 2, baseline=RECOVERY_V1, challenge_id="ch-r"))

    def test_recovery_baseline_cannot_declare_lower_full_floor(self):
        self.ok({"op": "set_floors", "request_id": "floors", "group_id": GROUP_A,
                 "at": 0, "full_min_version": 3})
        lowering = synthetic.baseline_doc("bl-rec-bad", GROUP_A, "recovery", 2, 0,
                                          min_full_version=2, label="bl-rec-bad")
        self.denied({"op": "publish_baseline", "request_id": "p-rec-bad", "at": 0,
                     "baseline": lowering},
                    "RECOVERY_LOWERS_FULL_FLOOR")
        raising = synthetic.baseline_doc("bl-rec-ok", GROUP_A, "recovery", 3, 0,
                                         min_full_version=3, label="bl-rec-ok")
        self.ok({"op": "publish_baseline", "request_id": "p-rec-ok", "at": 0,
                 "baseline": raising})

    def test_generation_change_marks_old_challenges_and_keeps_the_watermark(self):
        self.issue("ch-a")
        self.ok(self.attest("a-1", 4))
        self.issue("ch-b")
        before = self.ok({"op": "get_device", "request_id": "q-dev", "device_id": DEV_A})["device"]
        self.assertEqual(before["counter_watermark"], 4)
        self.rotate(2, at=5000)
        after = self.ok({"op": "get_device", "request_id": "q-dev-2", "device_id": DEV_A})["device"]
        self.assertEqual(after["generation"], 2)
        self.assertEqual(after["counter_watermark"], 4, "rotation must preserve the watermark")
        statuses = {
            row["challenge_id"]: row
            for row in self.ok({"op": "snapshot", "request_id": "q-snap",
                                "device_id": DEV_A})["challenges"]
        }
        self.assertEqual(statuses["ch-a"]["consumed_by"], "a-1")
        self.assertEqual(statuses["ch-b"]["invalidated"], 1)
        # Challenges issued after the change belong to the new generation.
        self.issue("ch-c")
        self.assertEqual(self.ok({"op": "get_challenge", "request_id": "q-ch",
                                  "challenge_id": "ch-c"})["challenge"]["generation"], 2)

    def test_recovery_line_is_independent_of_full_revocation(self):
        self.ok({"op": "revoke_baseline", "request_id": "rev", "at": 500,
                 "baseline_id": "bl-full-v1"})
        self.issue("ch-r")
        self.ok(self.attest("a-r", 2, baseline=RECOVERY_V1, challenge_id="ch-r"))
        self.issue("ch-a")
        self.denied(self.attest("a-full", 3), "BASELINE_REVOKED")


class BaselineLifecycleTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.create_world()

    def test_new_publication_supersedes_old_proof(self):
        self.issue("ch-a", issued=1000, expires=2100)
        self.ok({"op": "publish_baseline", "request_id": "pub-v2", "at": 2000,
                 "baseline": FULL_V2})
        state = self.ok({"op": "get_baseline", "request_id": "q-v1",
                         "baseline_id": "bl-full-v1"})["baseline"]
        self.assertEqual(state["state"], "superseded")
        self.assertEqual(state["superseded_at"], 2000)
        self.assertEqual(state["superseded_by"], "bl-full-v2")
        self.denied(self.attest("a-old", 3), "BASELINE_SUPERSEDED")
        self.denied(self.attest("a-old-dated", 3, at=1050), "BASELINE_SUPERSEDED")
        self.ok(self.attest("a-new", 3, baseline=FULL_V2, at=2050))

    def test_revocation(self):
        self.issue("ch-a", issued=1000, expires=2200)
        result = self.ok({"op": "revoke_baseline", "request_id": "rev", "at": 2000,
                          "baseline_id": "bl-full-v1"})
        self.assertEqual(result["baseline"]["state"], "revoked")
        self.assertFalse(result["already_revoked"])
        again = self.ok({"op": "revoke_baseline", "request_id": "rev-2", "at": 2100,
                         "baseline_id": "bl-full-v1"})
        self.assertTrue(again["already_revoked"])
        self.assertEqual(again["baseline"]["revoked_at"], 2000)
        self.denied(self.attest("a-rev", 3, at=2050), "BASELINE_REVOKED")
        # Even a proof dated *before* the revocation fails: the current state
        # governs whether a credential may still be issued.
        self.denied(self.attest("a-rev-old-date", 3, at=1050), "BASELINE_REVOKED")

    def test_revoked_older_version_is_not_resurrected_by_a_newer_publication(self):
        self.ok({"op": "revoke_baseline", "request_id": "rev", "at": 100,
                 "baseline_id": "bl-full-v1"})
        self.ok({"op": "publish_baseline", "request_id": "pub-v2", "at": 200,
                 "baseline": FULL_V2})
        state = self.ok({"op": "get_baseline", "request_id": "q", "baseline_id": "bl-full-v1"})
        self.assertEqual(state["baseline"]["state"], "revoked")
        self.assertIsNone(state["baseline"]["superseded_at"])

    def test_older_version_cannot_be_published_after_a_newer_one(self):
        self.ok({"op": "publish_baseline", "request_id": "pub-v2", "at": 100,
                 "baseline": FULL_V2})
        stale = synthetic.baseline_doc("bl-full-v1-retry", GROUP_A, "full", 1, 0,
                                       label="bl-full-v1-retry")
        self.denied({"op": "publish_baseline", "request_id": "pub-stale", "at": 200,
                     "baseline": stale}, "BASELINE_CONFLICT")
        # The current baseline is still the only one that can issue.
        self.issue("ch-a", issued=1000, expires=2100)
        self.ok(self.attest("a-v2", 3, baseline=FULL_V2, at=2050))

    def test_floors_are_monotonic(self):
        self.denied({"op": "set_floors", "request_id": "down", "group_id": GROUP_A,
                     "at": 0, "full_min_version": 0}, "POLICY_NOT_MONOTONIC")
        self.ok({"op": "set_floors", "request_id": "up", "group_id": GROUP_A,
                 "at": 0, "full_min_version": 4})
        self.denied({"op": "publish_baseline", "request_id": "old-full", "at": 0,
                     "baseline": synthetic.baseline_doc("bl-full-v3", GROUP_A, "full", 3, 0)},
                    "FULL_FLOOR_NOT_MET")

    def test_baseline_version_conflict_and_duplicate(self):
        conflict = synthetic.baseline_doc("bl-other-id", GROUP_A, "full", 1, 0, note="other")
        self.denied({"op": "publish_baseline", "request_id": "conflict", "at": 0,
                     "baseline": conflict}, "BASELINE_CONFLICT")
        duplicate = self.ok({"op": "publish_baseline", "request_id": "dup", "at": 0,
                             "baseline": FULL_V1})
        self.assertTrue(duplicate["duplicate"])

    def test_unknown_group(self):
        orphan = synthetic.baseline_doc("bl-orphan", "tenant-z:grp-9", "full", 1, 0)
        self.denied({"op": "publish_baseline", "request_id": "orphan", "at": 0,
                     "baseline": orphan}, "DEVICE_GROUP_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
