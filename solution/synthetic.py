"""Synthetic fixture builders (all inputs are self-generated, offline).

These helpers are used by ``tools/build_cases.py`` to regenerate
``cases.json`` and by the test-suite to build attestations step by step.  They
encode the *format* of the protocol, not any hidden rule: every rule lives in
:mod:`solution.verify`, :mod:`solution.baselines` and :mod:`solution.service`.
"""

from __future__ import annotations

from typing import Iterable

from . import crypto


def digest_of(label: str) -> str:
    """A deterministic 64-hex payload digest for a synthetic module."""
    return crypto.sha256_hex(f"payload:{label}".encode("utf-8"))


def module(position: int, name: str, digest: str, critical: bool = False) -> dict:
    return {"position": position, "module": name, "payload_digest": digest, "critical": critical}


DEFAULT_MODULES = [
    ("firmware", True),
    ("bootloader", True),
    ("kernel", True),
    ("initramfs", False),
    ("userspace", False),
]


def baseline_doc(baseline_id: str, group_id: str, kind: str, version: int, released_at: int,
                 modules: Iterable[tuple[str, bool]] | None = None,
                 min_full_version: int | None = None, note: str | None = None,
                 label: str | None = None) -> dict:
    """Build an unsigned baseline document (deterministic digests)."""
    spec = list(modules if modules is not None else DEFAULT_MODULES)
    tag = label if label is not None else baseline_id
    doc = {
        "baseline_id": baseline_id,
        "group_id": group_id,
        "kind": kind,
        "version": version,
        "released_at": released_at,
        "modules": [
            module(position, name, digest_of(f"{tag}/{name}"), critical)
            for position, (name, critical) in enumerate(spec)
        ],
    }
    if min_full_version is not None:
        doc["min_full_version"] = min_full_version
    if note is not None:
        doc["note"] = note
    return doc


def chain_entries(doc: dict, *, drop: int | None = None, tamper: int | None = None,
                  reorder: tuple[int, int] | None = None, truncated_to: int | None = None,
                  extra_module: str | None = None, label: str | None = None,
                  keep_seq: bool = False) -> list[dict]:
    """Build measurement entries for a baseline layout, with optional defects.

    ``drop``          omit the module at that position (missing module)
    ``tamper``        replace that position's payload digest (digest mismatch)
    ``reorder``       swap the two listed positions (wrong order); with
                      ``keep_seq`` the original sequence numbers travel with the
                      modules, producing an out-of-order chain
    ``truncated_to``  keep only the first N modules (short chain)
    ``extra_module``  append a module the baseline does not define
    """
    tag = label if label is not None else doc["baseline_id"]
    modules = [dict(m) for m in doc["modules"]]
    if drop is not None:
        modules = [m for m in modules if m["position"] != drop]
    if truncated_to is not None:
        modules = modules[:truncated_to]
    if reorder is not None:
        a, b = reorder
        modules[a], modules[b] = modules[b], modules[a]
    entries = []
    for position, pinned in enumerate(modules):
        payload = pinned["payload_digest"]
        if tamper is not None and position == tamper:
            payload = digest_of(f"{tag}/{pinned['module']}/tampered")
        seq = pinned["position"] if keep_seq else position
        entries.append({"seq": seq, "module": pinned["module"], "payload_digest": payload})
    if extra_module is not None:
        entries.append({"seq": len(entries), "module": extra_module,
                        "payload_digest": digest_of(f"{tag}/{extra_module}")})
    return entries


def with_links(entries: list[dict], tenant_id: str, challenge_id: str) -> tuple[list[dict], str]:
    """Attach each recomputed link digest and return (entries, root)."""
    links = crypto.recompute_chain(tenant_id, challenge_id, entries)
    linked = []
    for entry, link in zip(entries, links):
        item = dict(entry)
        item["link_digest"] = link
        linked.append(item)
    return linked, links[-1]


def attestation(tenant_id: str, device_id: str, group_id: str, generation: int,
                challenge_id: str, baseline_id: str, boot_counter: int, observed_at: int,
                entries: list[dict], *, sign: bool = True, root: str | None = None) -> dict:
    linked, computed_root = with_links(entries, tenant_id, challenge_id)
    payload = {
        "tenant_id": tenant_id,
        "device_id": device_id,
        "group_id": group_id,
        "generation": generation,
        "challenge_id": challenge_id,
        "baseline_id": baseline_id,
        "boot_counter": boot_counter,
        "observed_at": observed_at,
        "chain": linked,
        "chain_root": computed_root if root is None else root,
    }
    if sign:
        payload["witness_signature"] = crypto.sign_attestation(device_id, payload)
    else:
        payload["witness_signature"] = "00" * 32
    return payload


def attest_request(request_id: str, at: int, attestation_payload: dict,
                   requested_scope: str | None = None) -> dict:
    request = {"op": "attest", "request_id": request_id, "at": at,
               "attestation": attestation_payload}
    if requested_scope is not None:
        request["requested_scope"] = requested_scope
    return request
