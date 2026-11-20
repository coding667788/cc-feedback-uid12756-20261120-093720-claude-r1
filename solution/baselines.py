"""Baseline document validation, publication helpers and eligibility rules.

A baseline document describes one boot-chain layout for one device group: an
ordered list of modules, the SHA-256 digest each module payload must hash to,
and whether the module is critical.  Documents are immutable once stored; only
their revocation state may change.
"""

from __future__ import annotations

from typing import Any

from . import crypto
from .errors import Denial

KINDS = ("full", "recovery")

DOC_KEYS = {"baseline_id", "group_id", "kind", "version", "released_at", "modules"}
OPTIONAL_DOC_KEYS = {"min_full_version", "note"}
MODULE_KEYS = {"position", "module", "payload_digest", "critical"}


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _bad(message: str) -> Denial:
    return Denial("BAD_REQUEST", message, stage="baseline")


def validate_doc(doc: Any) -> dict:
    """Structural validation of a (possibly unsigned) baseline document."""
    if not isinstance(doc, dict):
        raise _bad("baseline document must be an object")
    unknown = set(doc) - (DOC_KEYS | OPTIONAL_DOC_KEYS | {"signature"})
    if unknown:
        raise _bad(f"unknown baseline fields: {sorted(unknown)}")
    missing = DOC_KEYS - set(doc)
    if missing:
        raise _bad(f"missing baseline fields: {sorted(missing)}")

    if not isinstance(doc["baseline_id"], str) or not doc["baseline_id"]:
        raise _bad("baseline_id must be a non-empty string")
    if not isinstance(doc["group_id"], str) or not doc["group_id"]:
        raise _bad("group_id must be a non-empty string")
    if doc["kind"] not in KINDS:
        raise _bad("kind must be 'full' or 'recovery'")
    if not is_int(doc["version"]) or doc["version"] < 1:
        raise _bad("version must be an integer >= 1")
    if not is_int(doc["released_at"]) or doc["released_at"] < 0:
        raise _bad("released_at must be an integer >= 0")
    if "min_full_version" in doc and (not is_int(doc["min_full_version"]) or doc["min_full_version"] < 0):
        raise _bad("min_full_version must be an integer >= 0")
    if "note" in doc and not isinstance(doc["note"], str):
        raise _bad("note must be a string")
    if "signature" in doc and not isinstance(doc["signature"], str):
        raise _bad("signature must be a string")

    modules = doc["modules"]
    if not isinstance(modules, list) or not modules:
        raise _bad("modules must be a non-empty list")
    if len(modules) > crypto.MAX_CHAIN:
        raise Denial("CHAIN_TOO_LONG", "baseline defines too many modules", stage="baseline")
    names: set[str] = set()
    for index, module in enumerate(modules):
        if not isinstance(module, dict) or set(module) != MODULE_KEYS:
            raise _bad("each module entry must contain exactly position/module/payload_digest/critical")
        if not is_int(module["position"]) or module["position"] != index:
            raise _bad("module positions must be contiguous, ascending and start at zero")
        if not isinstance(module["module"], str) or not module["module"]:
            raise _bad("module name must be a non-empty string")
        if module["module"] in names:
            raise _bad(f"duplicate module name {module['module']!r}")
        if not is_hex64(module["payload_digest"]):
            raise _bad("payload_digest must be 64 hex characters")
        if not isinstance(module["critical"], bool):
            raise _bad("critical must be a boolean")
        names.add(module["module"])
    return doc


def attach_signature(doc: dict, group_id: str | None = None) -> dict:
    """Return a copy of ``doc`` with a publisher signature over its content."""
    signed = {key: value for key, value in doc.items() if key != "signature"}
    signed["signature"] = crypto.sign_baseline(group_id or doc["group_id"], signed)
    return signed


def verify_signature(doc: dict) -> bool:
    signature = doc.get("signature")
    if not isinstance(signature, str):
        return False
    return crypto.verify_baseline_signature(doc["group_id"], doc, signature)


def module_layout(doc: dict) -> list[dict]:
    return [dict(module) for module in doc["modules"]]


def historical_denial(row: dict, at: int) -> str | None:
    """State checks that depend on the *declared* verification instant ``at``."""
    if row["published_at"] > at:
        return "BASELINE_NOT_PUBLISHED"
    if row["revoked_at"] is not None and row["revoked_at"] <= at:
        return "BASELINE_REVOKED"
    return None


def current_denial(row: dict) -> str | None:
    """State checks against the baseline's *current* status, at commit time.

    Attestation commits are gated on the current state rather than solely on
    the client-declared ``at``: a superseded or revoked baseline may never
    issue a credential again, no matter how the attestation is dated.  This is
    what makes "an old proof arrives after a new baseline was activated" fail
    closed.
    """
    if row["revoked_at"] is not None or row["state"] == "revoked":
        return "BASELINE_REVOKED"
    if row["superseded_at"] is not None or row["state"] == "superseded":
        return "BASELINE_SUPERSEDED"
    if row["state"] != "published":
        return "BASELINE_NOT_PUBLISHED"
    return None


def effective_floor(group: dict, row: dict) -> int:
    return group["full_min_version"] if row["kind"] == "full" else group["recovery_min_version"]


def floor_code(row: dict) -> str:
    return "FULL_FLOOR_NOT_MET" if row["kind"] == "full" else "RECOVERY_FLOOR_NOT_MET"
