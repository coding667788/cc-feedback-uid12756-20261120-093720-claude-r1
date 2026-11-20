"""Phase A: stateless verification of a boot attestation.

Nothing here touches the database.  Every check depends only on the request,
the baseline document and the derived witness key, which is exactly what makes
it safe to run in a separate, disposable worker process outside any SQLite
transaction.  The expensive measurement-chain audit is repeated after the
transaction begins (see :mod:`solution.service`) so a stale baseline snapshot
can never be used to authorise a commit.
"""

from __future__ import annotations

from typing import Any

from . import crypto
from .baselines import is_hex64, is_int, module_layout
from .errors import Denial

STAGE = "precheck"

REQUIRED_ATTESTATION_KEYS = {
    "tenant_id",
    "device_id",
    "group_id",
    "generation",
    "challenge_id",
    "baseline_id",
    "boot_counter",
    "observed_at",
    "chain",
    "chain_root",
    "witness_signature",
}
OPTIONAL_ATTESTATION_KEYS = {"nonce"}


def validate_attestation_shape(attestation: Any) -> None:
    if not isinstance(attestation, dict):
        raise Denial("BAD_REQUEST", "attestation must be an object", stage=STAGE)
    unknown = set(attestation) - (REQUIRED_ATTESTATION_KEYS | OPTIONAL_ATTESTATION_KEYS)
    if unknown:
        raise Denial("BAD_REQUEST", f"unknown attestation fields: {sorted(unknown)}", stage=STAGE)
    missing = REQUIRED_ATTESTATION_KEYS - set(attestation)
    if missing:
        raise Denial("BAD_REQUEST", f"missing attestation fields: {sorted(missing)}", stage=STAGE)
    for key in ("tenant_id", "device_id", "group_id", "challenge_id", "baseline_id"):
        if not isinstance(attestation[key], str) or not attestation[key]:
            raise Denial("BAD_REQUEST", f"{key} must be a non-empty string", stage=STAGE)
    for key in ("generation", "boot_counter", "observed_at"):
        if not is_int(attestation[key]):
            raise Denial("BAD_REQUEST", f"{key} must be an integer", stage=STAGE)
    if not isinstance(attestation["chain"], list):
        raise Denial("BAD_REQUEST", "chain must be a list", stage=STAGE)
    if not isinstance(attestation["chain_root"], str):
        raise Denial("BAD_REQUEST", "chain_root must be a string", stage=STAGE)
    if not isinstance(attestation["witness_signature"], str):
        raise Denial("BAD_REQUEST", "witness_signature must be a string", stage=STAGE)


def _entry_error(seq: int, message: str) -> Denial:
    return Denial("BAD_REQUEST", f"chain[{seq}]: {message}", stage="chain", detail={"seq": seq})


def validate_chain_shape(chain: list) -> None:
    if not chain:
        raise Denial("CHAIN_EMPTY", "measurement chain is empty", stage="chain")
    if len(chain) > crypto.MAX_CHAIN:
        raise Denial("CHAIN_TOO_LONG", "measurement chain exceeds the implementation limit", stage="chain")
    for index, entry in enumerate(chain):
        if not isinstance(entry, dict):
            raise _entry_error(index, "entry must be an object")
        allowed = {"seq", "module", "payload_digest", "link_digest", "critical"}
        if not {"seq", "module", "payload_digest"} <= set(entry) or set(entry) - allowed:
            raise _entry_error(index, "entry must contain seq/module/payload_digest "
                                      "and optionally link_digest/critical")
        if "critical" in entry and not isinstance(entry["critical"], bool):
            raise _entry_error(index, "critical must be a boolean when present")
        if not is_int(entry["seq"]):
            raise _entry_error(index, "seq must be an integer")
        if not isinstance(entry["module"], str) or not entry["module"]:
            raise _entry_error(index, "module must be a non-empty string")
        if not is_hex64(entry["payload_digest"]):
            raise _entry_error(index, "payload_digest must be 64 hex characters")


def audit_chain(attestation: dict, baseline_doc: dict) -> dict:
    """Full measurement audit: ordering, links, baseline layout and digests."""
    chain = attestation["chain"]
    validate_chain_shape(chain)

    layout = module_layout(baseline_doc)
    expected_len = len(layout)
    if len(chain) > expected_len:
        raise Denial("EXTRA_MODULE",
                     f"chain has {len(chain)} entries but baseline pins {expected_len} modules",
                     stage="chain", detail={"seq": expected_len})

    # Coverage first: every baseline module must appear exactly once somewhere,
    # so "the chain skipped the kernel" is reported as missing rather than as a
    # positional mismatch of everything after it.
    present = [entry["module"] for entry in chain]
    for pinned in layout:
        if pinned["module"] not in present:
            raise Denial("MISSING_MODULE",
                         f"required module {pinned['module']!r} is missing from the chain",
                         stage="chain", detail={"seq": min(pinned["position"], len(chain) - 1),
                                                "module": pinned["module"]})

    seqs = [entry["seq"] for entry in chain]
    duplicates = sorted({seq for seq in seqs if seqs.count(seq) > 1})
    if duplicates:
        raise Denial("CHAIN_SEQ_DUPLICATE",
                     f"sequence number(s) {duplicates} appear more than once",
                     stage="chain", detail={"seq": seqs.index(duplicates[0])})
    if sorted(seqs) == list(range(len(seqs))) and seqs != list(range(len(seqs))):
        first_bad = next(index for index, seq in enumerate(seqs) if seq != index)
        raise Denial("CHAIN_SEQ_ORDER",
                     f"chain entries are not ordered by sequence number (position {first_bad} holds seq {seqs[first_bad]})",
                     stage="chain", detail={"seq": first_bad})
    for index, seq in enumerate(seqs):
        if seq != index:
            raise Denial("CHAIN_SEQ_GAP",
                         f"expected sequence number {index}, found {seq}",
                         stage="chain", detail={"seq": index})

    # Recompute links before looking at layout so tampering is reported as such.
    links = crypto.recompute_chain(attestation["tenant_id"], attestation["challenge_id"], chain)
    declared_links = [entry.get("link_digest") for entry in chain]
    for index, (declared, actual) in enumerate(zip(declared_links, links)):
        if declared is not None and declared != actual:
            raise Denial("CHAIN_LINK_MISMATCH", f"chain[{index}] link digest does not match SHA-256",
                         stage="chain", detail={"seq": index})
    if attestation["chain_root"] != links[-1]:
        raise Denial("CHAIN_ROOT_MISMATCH", "declared chain_root is not the recomputed final link",
                     stage="chain")

    for index in range(min(len(chain), expected_len)):
        entry = chain[index]
        pinned = layout[index]
        if entry["module"] != pinned["module"]:
            if entry["module"] in {m["module"] for m in layout}:
                raise Denial("MODULE_POSITION_MISMATCH",
                             f"module {entry['module']!r} appears at position {index}, "
                             f"baseline defines it at {next(m['position'] for m in layout if m['module'] == entry['module'])}",
                             stage="chain", detail={"seq": index})
            raise Denial("EXTRA_MODULE", f"module {entry['module']!r} is not part of the baseline",
                         stage="chain", detail={"seq": index})
        if entry["payload_digest"] != pinned["payload_digest"]:
            raise Denial("DIGEST_MISMATCH", f"module {entry['module']!r} digest differs from baseline",
                         stage="chain", detail={"seq": index})
        if "critical" in entry and entry["critical"] != pinned["critical"]:
            # A module may only claim criticality where the selected baseline
            # defines a critical module.
            raise Denial("CRITICAL_MODULE_UNKNOWN",
                         f"module {entry['module']!r} claims critical={entry['critical']} "
                         f"but the baseline defines critical={pinned['critical']}",
                         stage="chain", detail={"seq": index})

    if len(chain) < expected_len:
        missing = layout[len(chain)]["module"]
        raise Denial("MISSING_MODULE", f"required module {missing!r} is missing from the chain",
                     stage="chain", detail={"seq": len(chain), "module": missing})

    return {
        "chain_length": len(chain),
        "chain_root": links[-1],
        "modules": [entry["module"] for entry in chain],
        "critical_modules": [pinned["module"] for pinned in layout if pinned["critical"]],
    }


def verify_attestation(attestation: Any, baseline_doc: dict) -> dict:
    """Run every stateless check; return the derived measurement summary."""
    validate_attestation_shape(attestation)
    if attestation["group_id"] != baseline_doc["group_id"]:
        raise Denial("BASELINE_GROUP_MISMATCH", "baseline belongs to a different device group", stage=STAGE)
    if attestation["baseline_id"] != baseline_doc["baseline_id"]:
        raise Denial("BASELINE_UNKNOWN", "baseline document does not match requested baseline", stage=STAGE)
    if not crypto.verify_attestation_signature(attestation["device_id"], attestation):
        raise Denial("WITNESS_SIGNATURE_INVALID", "witness signature does not verify", stage=STAGE)
    return audit_chain(attestation, baseline_doc)
