"""Regenerate ``cases.json`` (deterministic; run from the project root).

    python tools/build_cases.py

Every expected value in the produced file is written by hand.  The file is a
*replayable specification*: ``python -m solution --input cases.json --output
result.json`` asserts each expectation, and ``tests/test_cases.py`` re-runs it.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from solution import synthetic  # noqa: E402

GROUP_A = "tenant-a:grp-1"
GROUP_B = "tenant-b:grp-1"
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
DEV_A = "syn-dev-0001"
DEV_B = "syn-dev-0002"


def step(request: dict, **expect) -> dict:
    return {"request": request, "expect": expect}


def case(name: str, description: str, *steps) -> dict:
    return {"name": name, "description": description, "steps": list(steps)}


def create_group(rid: str, group: str, at: int, full: int = 1, recovery: int = 1) -> dict:
    return {"op": "create_group", "request_id": rid, "group_id": group, "at": at,
            "full_min_version": full, "recovery_min_version": recovery}


def publish(rid: str, at: int, doc: dict) -> dict:
    return {"op": "publish_baseline", "request_id": rid, "at": at, "baseline": doc}


def register(rid: str, at: int, device: str, tenant: str, group: str, generation: int = 1) -> dict:
    return {"op": "register_device", "request_id": rid, "at": at, "device_id": device,
            "tenant_id": tenant, "group_id": group, "generation": generation}


def challenge(rid: str, cid: str, nonce: str, device: str, issued: int, expires: int) -> dict:
    return {"op": "issue_challenge", "request_id": rid, "challenge_id": cid, "nonce": nonce,
            "device_id": device, "issued_at": issued, "expires_at": expires}


FULL_V1 = synthetic.baseline_doc("bl-full-v1", GROUP_A, "full", 1, 0)
FULL_V2 = synthetic.baseline_doc("bl-full-v2", GROUP_A, "full", 2, 2000, label="bl-full-v2")
RECOVERY_V1 = synthetic.baseline_doc("bl-rec-v1", GROUP_A, "recovery", 1, 0, label="bl-rec-v1")
FULL_B_V1 = synthetic.baseline_doc("bl-b-full-v1", GROUP_B, "full", 1, 0, label="bl-b-full-v1")

WINDOW = (1000, 1100)


def full_setup() -> list[dict]:
    """Common prologue: one group, full v1, recovery v1, one device."""
    return [
        create_group("setup-group", GROUP_A, 0),
        publish("setup-full", 0, FULL_V1),
        publish("setup-recovery", 0, RECOVERY_V1),
        register("setup-device", 0, DEV_A, TENANT_A, GROUP_A),
    ]


def valid_attest(rid: str, at: int, counter: int, *, baseline: dict = FULL_V1,
                 challenge_id: str = "ch-a", device: str = DEV_A, tenant: str = TENANT_A,
                 generation: int = 1, observed: int | None = None,
                 group: str | None = None, chain_from: dict | None = None,
                 **chain_kwargs) -> dict:
    entries = synthetic.chain_entries(chain_from or baseline, **chain_kwargs)
    payload = synthetic.attestation(tenant, device, group or baseline["group_id"], generation,
                                    challenge_id, baseline["baseline_id"], counter,
                                    at if observed is None else observed, entries)
    return synthetic.attest_request(rid, at, payload)


def build() -> dict:
    cases = []

    # ---------------------------------------------------------------- happy path
    cases.append(case(
        "happy-path-full",
        "A valid full-baseline proof issues a full-access credential and advances the counter.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW),
             status="accepted", result={"challenge": {"generation": 1}}),
        step(valid_attest("a-1", 1050, 7),
             status="accepted",
             result={"credential": {"scope": "full-access", "baseline_kind": "full",
                                    "device_id": DEV_A, "generation": 1, "boot_counter": 7},
                     "previous_counter": -1,
                     "device": {"counter_watermark": 7},
                     "chain_length": 5,
                     "critical_modules": ["firmware", "bootloader", "kernel"]}),
        # The challenge is consumed and the receipt is stored in the same commit.
        step({"op": "get_challenge", "request_id": "q1", "challenge_id": "ch-a"},
             status="accepted",
             result={"challenge": {"consumed_by": "a-1", "consumed_at": 1050, "invalidated": 0}}),
        step({"op": "list_credentials", "request_id": "q2", "device_id": DEV_A},
             status="accepted",
             result={"credentials": [{"scope": "full-access", "generation": 1,
                                      "boot_counter": 7, "revoked_at": None}]}),
    ))

    # ------------------------------------------------------- measurement chains
    cases.append(case(
        "chain-missing-module",
        "Dropping a baseline-required module is MISSING_MODULE (chain covers the whole boot).",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-missing", 1050, 3, drop=2), status="denied", code="MISSING_MODULE"),
        step({"op": "get_device", "request_id": "q1", "device_id": DEV_A},
             status="accepted", result={"device": {"counter_watermark": -1}}),
    ))

    cases.append(case(
        "chain-wrong-order",
        "Two modules at each other's positions are MODULE_POSITION_MISMATCH.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-order", 1050, 3, reorder=(1, 2)),
             status="denied", code="MODULE_POSITION_MISMATCH"),
    ))

    cases.append(case(
        "chain-sequence-order",
        "Renumbered-but-shuffled sequence numbers are CHAIN_SEQ_ORDER.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-seqorder", 1050, 3, reorder=(1, 2), keep_seq=True),
             status="denied", code="CHAIN_SEQ_ORDER"),
    ))

    cases.append(case(
        "chain-digest-tampered",
        "A recomputed chain whose kernel digest differs from the baseline is DIGEST_MISMATCH.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-digest", 1050, 3, tamper=2),
             status="denied", code="DIGEST_MISMATCH"),
    ))

    cases.append(case(
        "chain-extra-and-misplaced-critical",
        "An undefined module is EXTRA_MODULE; a false critical claim is CRITICAL_MODULE_UNKNOWN.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-extra", 1050, 3, extra_module="telemetry-agent"),
             status="denied", code="EXTRA_MODULE"),
    ))

    # ------------------------------------------------------------ cross tenant
    cases.append(case(
        "cross-tenant-same-modules",
        "Tenant B publishes a baseline with identical module names; tenant A's device may not use it.",
        create_group("b-group", GROUP_B, 0),
        publish("b-full", 0, FULL_B_V1),
        *full_setup(),
        register("b-device", 0, DEV_B, TENANT_B, GROUP_B),
        step(challenge("c-issue-b", "ch-b", "nonce-b", DEV_B, *WINDOW), status="accepted"),
        # Tenant A's device presents its own group, but tenant B's baseline id.
        # The baseline's modules have the same *names* as tenant A's, so only
        # the group binding can tell them apart.
        step(valid_attest("a-cross", 1050, 3, baseline=FULL_B_V1, challenge_id="ch-b",
                          group=GROUP_A),
             status="denied", code="BASELINE_GROUP_MISMATCH"),
        # Tenant A's challenge, tenant B's device.
        step(challenge("c-issue-a", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("b-cross", 1050, 3, challenge_id="ch-a", device=DEV_B, tenant=TENANT_B,
                          baseline=FULL_B_V1),
             status="denied", code="CHALLENGE_TENANT_MISMATCH"),
        # A device registered to group A sends a group-B baseline and claims
        # group B.  The baseline is internally consistent, so only the device's
        # real registration exposes the claim.
        register("reg-c", 0, "syn-dev-0003", TENANT_B, GROUP_A),
        step(challenge("c-issue-c", "ch-c", "nonce-c", "syn-dev-0003", *WINDOW), status="accepted"),
        step(valid_attest("c-group-claim", 1050, 3, challenge_id="ch-c",
                          device="syn-dev-0003", tenant=TENANT_B, baseline=FULL_B_V1),
             status="denied", code="GROUP_MISMATCH"),
    ))

    # --------------------------------------------------------------- signatures
    cases.append(case(
        "tampered-signature",
        "A mutated witness signature is WITNESS_SIGNATURE_INVALID; a re-linked chain is CHAIN_LINK_MISMATCH.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        "SIG_TAMPER",
        "LINK_TAMPER",
    ))

    # --------------------------------------------------------------- expiry
    cases.append(case(
        "challenge-exactly-expired",
        "The window is half-open: at expires_at-1 accepted, at expires_at CHALLENGE_EXPIRED, later too.",
        *full_setup(),
        step(challenge("c-1", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-edge-in", 1099, 4), status="accepted",
             result={"credential": {"boot_counter": 4}}),
        step(challenge("c-2", "ch-b", "nonce-b", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-edge-out", 1100, 5, challenge_id="ch-b"),
             status="denied", code="CHALLENGE_EXPIRED"),
        step(challenge("c-3", "ch-c", "nonce-c", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-late", 1201, 5, challenge_id="ch-c"),
             status="denied", code="CHALLENGE_EXPIRED"),
    ))

    # ---------------------------------------------------------------- recovery
    cases.append(case(
        "recovery-low-privilege",
        "A valid recovery proof only ever yields diagnostic-readonly, and still advances the counter.",
        *full_setup(),
        step(challenge("c-issue", "ch-r", "nonce-r", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-r1", 1050, 9, baseline=RECOVERY_V1, challenge_id="ch-r"),
             status="accepted",
             result={"credential": {"scope": "diagnostic-readonly", "baseline_kind": "recovery",
                                    "boot_counter": 9},
                     "previous_counter": -1,
                     "device": {"counter_watermark": 9}}),
    ))

    cases.append(case(
        "recovery-cannot-get-general-access",
        "Asking for full-access on a recovery baseline is denied and the counter is not consumed.",
        *full_setup(),
        step(challenge("c-issue", "ch-r", "nonce-r", DEV_A, *WINDOW), status="accepted"),
        step(dict(valid_attest("a-r-deny", 1050, 9, baseline=RECOVERY_V1, challenge_id="ch-r"),
                  requested_scope="full-access"),
             status="denied", code="RECOVERY_SCOPE_DENIED"),
        step({"op": "get_device", "request_id": "q1", "device_id": DEV_A},
             status="accepted", result={"device": {"counter_watermark": -1}}),
        # The same challenge is still unconsumed, so the legal request succeeds.
        step(valid_attest("a-r-ok", 1050, 9, baseline=RECOVERY_V1, challenge_id="ch-r"),
             status="accepted", result={"credential": {"scope": "diagnostic-readonly"}}),
    ))

    cases.append(case(
        "recovery-cannot-lower-full-floor",
        "A recovery baseline may not declare a full-privilege floor below the group minimum.",
        create_group("g", GROUP_A, 0, full=2, recovery=1),
        publish("full2", 0, FULL_V2),
        step(publish("rec-bad", 0, synthetic.baseline_doc(
            "bl-rec-bad", GROUP_A, "recovery", 1, 0, min_full_version=1)),
            status="denied", code="RECOVERY_LOWERS_FULL_FLOOR"),
        step(publish("rec-ok", 0, synthetic.baseline_doc(
            "bl-rec-ok", GROUP_A, "recovery", 1, 0, min_full_version=2)),
            status="accepted", result={"baseline": {"kind": "recovery", "state": "published"}}),
    ))

    # -------------------------------------------------------------- counters
    cases.append(case(
        "counter-rollback",
        "A counter at or below the watermark is COUNTER_ROLLBACK; recovery advances the same watermark.",
        *full_setup(),
        step(challenge("c-1", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-1", 1050, 5), status="accepted"),
        step(challenge("c-2", "ch-b", "nonce-b", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-2", 1050, 5, challenge_id="ch-b"),
             status="denied", code="COUNTER_ROLLBACK"),
        step(challenge("c-3", "ch-c", "nonce-c", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-3", 1050, 4, challenge_id="ch-c"),
             status="denied", code="COUNTER_ROLLBACK"),
        step(challenge("c-4", "ch-r", "nonce-r", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-4", 1050, 6, baseline=RECOVERY_V1, challenge_id="ch-r"),
             status="accepted", result={"device": {"counter_watermark": 6}}),
        step(challenge("c-5", "ch-d", "nonce-d", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-5", 1050, 6, challenge_id="ch-d"),
             status="denied", code="COUNTER_ROLLBACK"),
    ))

    # ------------------------------------------------------ baseline lifecycle
    cases.append(case(
        "new-baseline-supersedes-old-proof",
        "Publishing v2 supersedes v1; a proof already measured against v1 then fails closed.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, 1000, 2100), status="accepted"),
        publish("pub-v2", 2000, FULL_V2),
        step(valid_attest("a-old", 1050, 3),
             status="denied", code="BASELINE_SUPERSEDED"),
        step({"op": "get_baseline", "request_id": "q1", "baseline_id": "bl-full-v1"},
             status="accepted",
             result={"baseline": {"state": "superseded", "superseded_by": "bl-full-v2"}}),
        # v2 has a different layout label, so v1's chain cannot be replayed at v2.
        step(valid_attest("a-v2-bad", 2050, 3, baseline=FULL_V2, chain_from=FULL_V1),
             status="denied", code="DIGEST_MISMATCH"),
        # v2's own chain is fine and supersedes the old one's credential line.
        step(valid_attest("a-v2-ok", 2050, 3, baseline=FULL_V2),
             status="accepted", result={"credential": {"baseline_id": "bl-full-v2"},
                                        "baseline": {"version": 2, "state": "published"}}),
    ))

    cases.append(case(
        "revoked-baseline",
        "A revoked baseline denies with BASELINE_REVOKED even to a fresh, well-formed proof.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step({"op": "revoke_baseline", "request_id": "rev", "at": 500, "baseline_id": "bl-full-v1"},
             status="accepted", result={"baseline": {"state": "revoked", "revoked_at": 500}}),
        step(valid_attest("a-rev", 1050, 3), status="denied", code="BASELINE_REVOKED"),
        # Recovery is an independent line: revoking the full baseline leaves it usable.
        step(challenge("c-r", "ch-r", "nonce-r", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-rec", 1050, 3, baseline=RECOVERY_V1, challenge_id="ch-r"),
             status="accepted", result={"credential": {"scope": "diagnostic-readonly"}}),
    ))

    cases.append(case(
        "baseline-publication-rules",
        "Bad signature, version conflict and floors below the group minimum are refused.",
        create_group("g", GROUP_A, 0, full=1, recovery=1),
        step(publish("bad-sig", 0, dict(FULL_V1, signature="11" * 32)),
             status="denied", code="BASELINE_SIGNATURE_INVALID"),
        publish("ok", 0, FULL_V1),
        step(publish("conflict", 0, synthetic.baseline_doc("bl-full-v1b", GROUP_A, "full", 1, 0,
                                                          note="different content")),
             status="denied", code="BASELINE_CONFLICT"),
        step(publish("dup", 0, FULL_V1), status="accepted", result={"duplicate": True}),
        step({"op": "set_floors", "request_id": "floors-down", "group_id": GROUP_A,
              "at": 0, "full_min_version": 0},
             status="denied", code="POLICY_NOT_MONOTONIC"),
        step({"op": "set_floors", "request_id": "floors-up", "group_id": GROUP_A,
              "at": 0, "full_min_version": 3},
             status="accepted", result={"group": {"full_min_version": 3}}),
        step(publish("below-floor", 0, synthetic.baseline_doc("bl-full-v2x", GROUP_A, "full", 2, 0)),
             status="denied", code="FULL_FLOOR_NOT_MET"),
    ))

    # ---------------------------------------------------------------- rotation
    cases.append(case(
        "generation-rotation",
        "Rotation revokes credentials, invalidates challenges and preserves the counter watermark.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-1", 1050, 8), status="accepted"),
        step({"op": "rotate_generation", "request_id": "rot", "device_id": DEV_A,
              "new_generation": 2, "at": 1500},
             status="accepted", result={"device": {"generation": 2, "counter_watermark": 8}}),
        # The old credential is revoked by the rotation.
        step({"op": "present_credential", "request_id": "p1", "at": 1600,
              "token": synthetic_token("a-1")},
             status="denied", code="CREDENTIAL_REVOKED"),
        # The old challenge was invalidated, and its generation is stale anyway.
        step(valid_attest("a-2", 1050, 9, challenge_id="ch-a", generation=1),
             status="denied", code="GENERATION_MISMATCH"),
        step(challenge("c-2", "ch-b", "nonce-b", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-3", 1050, 9, challenge_id="ch-b", generation=2),
             status="accepted",
             result={"credential": {"generation": 2, "boot_counter": 9},
                     "device": {"counter_watermark": 9}}),
        # Rotation alone must not reset the watermark.
        step(challenge("c-3", "ch-c", "nonce-c", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-4", 1050, 9, challenge_id="ch-c", generation=2),
             status="denied", code="COUNTER_ROLLBACK"),
    ))

    cases.append(case(
        "reregistration-keeps-watermark",
        "Re-registering never resets the anti-rollback watermark.",
        *full_setup(),
        step(challenge("c-1", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-1", 1050, 11), status="accepted"),
        step(register("re-reg", 1200, DEV_A, TENANT_A, GROUP_A),
             status="accepted",
             result={"device": {"counter_watermark": 11, "generation": 1},
                     "created": False, "rotated": False}),
        step(challenge("c-2", "ch-b", "nonce-b", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-2", 1050, 11, challenge_id="ch-b"),
             status="denied", code="COUNTER_ROLLBACK"),
        create_group("b-group", GROUP_B, 0),
        step(register("conflict", 1200, DEV_A, TENANT_B, GROUP_B),
             status="denied", code="DEVICE_ID_CONFLICT"),
    ))

    # -------------------------------------------------------------- idempotency
    cases.append(case(
        "request-id-idempotency",
        "The same request id replays the stored receipt; different content conflicts.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-1", 1050, 12),
             status="accepted", result={"credential": {"boot_counter": 12}}),
        step(valid_attest("a-1", 1050, 12),
             status="accepted", result={"credential": {"boot_counter": 12}}, replayed=True),
        step(valid_attest("a-1", 1050, 13),
             status="denied", code="REQUEST_ID_CONFLICT"),
    ))

    cases.append(case(
        "challenge-single-use",
        "A second, independently valid proof for the same challenge is CHALLENGE_CONSUMED.",
        *full_setup(),
        step(challenge("c-issue", "ch-a", "nonce-a", DEV_A, *WINDOW), status="accepted"),
        step(valid_attest("a-1", 1050, 13), status="accepted"),
        step(valid_attest("a-2", 1050, 14),
             status="denied", code="CHALLENGE_CONSUMED"),
        step({"op": "get_device", "request_id": "q1", "device_id": DEV_A},
             status="accepted", result={"device": {"counter_watermark": 13}}),
    ))

    return {
        "schema_version": 1,
        "title": "Offline synthetic boot-attestation audit service - replayable conformance cases",
        "generated_by": "tools/build_cases.py",
        "window": {"issued_at": WINDOW[0], "expires_at": WINDOW[1],
                   "rule": "half-open [issued_at, expires_at)"},
        "cases": [_materialise(item) for item in cases],
    }


def _materialise(item: dict) -> dict:
    """Fill in generated attestations and special tampering steps.

    A bare request dict is shorthand for "this setup step must be accepted".
    """
    steps = []
    for entry in item["steps"]:
        if isinstance(entry, dict) and "request" not in entry:
            entry = step(entry, status="accepted")
        if entry == "SIG_TAMPER":
            steps.append(step(_tampered_attest("a-sig", signature_bad=True),
                              status="denied", code="WITNESS_SIGNATURE_INVALID"))
            continue
        if entry == "LINK_TAMPER":
            steps.append(step(_tampered_attest("a-link", link_bad=True),
                              status="denied", code="CHAIN_LINK_MISMATCH"))
            continue
        steps.append(entry)
    item["steps"] = steps
    return item


def _tampered_attest(rid: str, *, signature_bad: bool = False, link_bad: bool = False) -> dict:
    entries = synthetic.chain_entries(FULL_V1)
    payload = synthetic.attestation(TENANT_A, DEV_A, GROUP_A, 1, "ch-a", FULL_V1["baseline_id"],
                                    3, 1050, entries)
    if signature_bad:
        payload["witness_signature"] = "ab" * 32
    if link_bad:
        payload["chain"][2]["link_digest"] = "cd" * 32
        payload.pop("witness_signature")
        payload["witness_signature"] = synthetic.crypto.sign_attestation(DEV_A, payload)
    return synthetic.attest_request(rid, 1050, payload)


def synthetic_token(request_id: str) -> str:
    """Token that a successful attest with ``request_id`` would have produced."""
    credential_id = "cred-" + synthetic.crypto.sha256_hex(request_id.encode("utf-8"))[:24]
    return synthetic.crypto.credential_token(credential_id, "full-access", 1, DEV_A)


def main() -> int:
    document = build()
    out = os.path.join(ROOT, "cases.json")
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")
    total = sum(len(case_["steps"]) for case_ in document["cases"])
    print(f"wrote {out}: {len(document['cases'])} cases, {total} steps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
