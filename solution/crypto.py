"""Deterministic offline cryptography for the simulated boot-attestation service.

Only the Python standard library is used.

Threat model (repeated in README.md): this is an *offline synthetic
simulation*.  There is no key management, no network, no wall clock.  Signing
keys are deterministically derived from synthetic identifiers (the device-group
id for baseline publishers, the device id for device witnesses) so that a
replayable ``cases.json`` can carry real, checkable signatures without carrying
secrets.  The tags are HMAC-SHA256 and are compared in constant time; changing
any signed field invalidates them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

CHAIN_DOMAIN = "BOOT-CHAIN/v1"
MAX_CHAIN = 64
MASTER_LABEL = b"OFFLINE-BOOT-ATTEST-SIM/v1"


def canonical_bytes(value: Any) -> bytes:
    """Canonical JSON: sorted keys, no insignificant whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def derive_key(*parts: str) -> str:
    """Deterministic synthetic key material (documented, not secret)."""
    digest = hashlib.sha256()
    digest.update(MASTER_LABEL)
    for part in parts:
        digest.update(b"|")
        digest.update(part.encode("utf-8"))
    return digest.hexdigest()


def publisher_key(group_id: str) -> str:
    return derive_key("publisher", group_id)


def witness_key(device_id: str) -> str:
    return derive_key("witness", device_id)


TOKEN_KEY = derive_key("token")


def _tag(key_hex: str, purpose: str, payload: Any) -> str:
    message = purpose.encode("utf-8") + b"|" + hashlib.sha256(canonical_bytes(payload)).digest()
    return hmac.new(bytes.fromhex(key_hex), message, hashlib.sha256).hexdigest()


def _check_tag(key_hex: str, purpose: str, payload: Any, tag_hex: Any) -> bool:
    if not isinstance(tag_hex, str):
        return False
    try:
        expected = _tag(key_hex, purpose, payload)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, tag_hex.lower())


# --------------------------------------------------------------------------
# Baseline publisher signatures
# --------------------------------------------------------------------------

def baseline_signing_payload(doc: dict) -> dict:
    """Everything in the document except its own signature."""
    return {key: value for key, value in doc.items() if key != "signature"}


def sign_baseline(group_id: str, doc: dict) -> str:
    return _tag(publisher_key(group_id), "BASELINE/v1", baseline_signing_payload(doc))


def verify_baseline_signature(group_id: str, doc: dict, signature_hex: Any) -> bool:
    return _check_tag(publisher_key(group_id), "BASELINE/v1", baseline_signing_payload(doc), signature_hex)


def baseline_digest(doc: dict) -> str:
    return sha256_hex(canonical_bytes(baseline_signing_payload(doc)))


# --------------------------------------------------------------------------
# Simulated device witness signatures
# --------------------------------------------------------------------------

def attestation_signing_payload(attestation: dict) -> dict:
    return {key: value for key, value in attestation.items() if key != "witness_signature"}


def sign_attestation(device_id: str, attestation: dict) -> str:
    return _tag(witness_key(device_id), "ATTEST/v1", attestation_signing_payload(attestation))


def verify_attestation_signature(device_id: str, attestation: dict) -> bool:
    return _check_tag(witness_key(device_id), "ATTEST/v1", attestation_signing_payload(attestation),
                      attestation.get("witness_signature"))


# --------------------------------------------------------------------------
# Measurement hash chain
# --------------------------------------------------------------------------

def chain_link(domain: str, seed: str, previous: str | None, seq: int, module: str,
               payload_digest: str) -> str:
    """One SHA-256 link.

    Link 0 commits to (domain, seed, seq, module, payload_digest); each later
    link commits to the previous *recomputed* link plus its own tuple.  The
    anchor of link 0 is ``domain + seed``, where seed is the tenant id and the
    challenge id, so a chain is bound to both tenant and challenge.
    """
    anchor = seed if previous is None else previous
    material = "|".join([CHAIN_DOMAIN, domain, anchor, str(seq), module, payload_digest])
    return sha256_hex(material.encode("utf-8"))


def recompute_chain(domain: str, seed: str, entries: list[dict]) -> list[str]:
    links: list[str] = []
    previous: str | None = None
    for entry in entries:
        previous = chain_link(domain, seed, previous, int(entry["seq"]), str(entry["module"]),
                              str(entry["payload_digest"]))
        links.append(previous)
    return links


def credential_token(credential_id: str, scope: str, generation: int, device_id: str) -> str:
    message = "|".join(["TOKEN/v1", credential_id, scope, str(generation), device_id]).encode("utf-8")
    digest = hmac.new(bytes.fromhex(TOKEN_KEY), message, hashlib.sha256).hexdigest()
    return "syn-" + digest[:32]
