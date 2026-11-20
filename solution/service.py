"""Attestation audit core and SQLite-backed service.

Public entry point
------------------
``execute_operation(db_path, request, control=None) -> dict``
    Runs exactly one protocol operation.  Used in-process (``cases.json``
    replay) and from worker processes (concurrency and crash tests).

Request envelope: every request is a JSON object with ``op`` and
``request_id`` plus operation-specific fields.  The response envelope is
``{request_id, op, status, code, message, stage, replayed, result}`` where
``status`` is ``accepted`` or ``denied`` and ``code`` is one of
:data:`solution.errors.ERROR_CODES`.

Two-phase attestation
---------------------
``_precheck`` runs outside any transaction (in whatever process is handling the
request): it loads the baseline, verifies its signature and digest, verifies
the simulated witness signature, and audits the measurement chain.  Then
``_attest_body`` runs inside ``BEGIN IMMEDIATE`` and re-checks *everything that
depends on shared mutable state*: device generation, challenge tenant / device /
generation / window / consumption, baseline publication, revocation and
supersession at the declared instant, the group's privilege floors, and the
device's previous boot counter.  The chain is re-audited against the baseline
document re-read under the lock, so a revocation or replacement that raced
with the precheck cannot authorise a commit.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from . import baselines, crypto, store, verify
from .errors import Denial

REQUEST_ID_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
MAX_REQUEST_ID = 128

SCOPES = ("full-access", "diagnostic-readonly")
NATURAL_SCOPE = {"full": "full-access", "recovery": "diagnostic-readonly"}

TRANSIENT_CODES = {"INTERNAL", "WORKER_FAILED", "TIMEOUT"}

# How long a writer waits for the write lock before reporting TIMEOUT.
TXN_DEADLINE_SECONDS = 30.0


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def request_digest(request: dict) -> str:
    return crypto.sha256_hex(crypto.canonical_bytes(request))


def _require_int(value: Any, name: str, minimum: int | None = None) -> int:
    if not baselines.is_int(value):
        raise Denial("BAD_REQUEST", f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise Denial("BAD_REQUEST", f"{name} must be >= {minimum}")
    return value


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise Denial("BAD_REQUEST", f"{name} must be a non-empty string")
    return value


def validate_request_id(request: dict) -> str:
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REQUEST_ID:
        raise Denial("REQUEST_ID_INVALID", "request_id must be a 1..128 character string")
    if set(request_id) - REQUEST_ID_ALLOWED:
        raise Denial("REQUEST_ID_INVALID", "request_id contains unsupported characters")
    return request_id


def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return None if row is None else {key: row[key] for key in row.keys()}


def _decode_doc(row: dict) -> dict:
    """Load a stored baseline document and re-verify its digest and signature."""
    try:
        doc = json.loads(row["doc_json"])
    except (TypeError, ValueError):
        raise Denial("BASELINE_DOC_MISMATCH", "stored baseline document is unreadable")
    if not isinstance(doc, dict):
        raise Denial("BASELINE_DOC_MISMATCH", "stored baseline document is not an object")
    if crypto.baseline_digest(doc) != row["doc_digest"]:
        raise Denial("BASELINE_DOC_MISMATCH", "stored baseline digest does not match its content")
    if not crypto.verify_baseline_signature(row["group_id"], doc, row["signature"]):
        raise Denial("BASELINE_SIGNATURE_INVALID", "stored baseline signature does not verify")
    return doc


def _load_group(conn: sqlite3.Connection, group_id: str) -> dict:
    row = conn.execute("SELECT * FROM groups WHERE group_id = ?", (group_id,)).fetchone()
    if row is None:
        raise Denial("DEVICE_GROUP_UNKNOWN", f"group {group_id!r} has no policy record")
    return _row_to_dict(row)


def _load_baseline(conn: sqlite3.Connection, baseline_id: str) -> dict:
    row = conn.execute("SELECT * FROM baselines WHERE baseline_id = ?", (baseline_id,)).fetchone()
    if row is None:
        raise Denial("BASELINE_UNKNOWN", f"baseline {baseline_id!r} does not exist")
    return _row_to_dict(row)


def _load_challenge(conn: sqlite3.Connection, challenge_id: str) -> dict:
    row = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
    if row is None:
        raise Denial("CHALLENGE_UNKNOWN", f"challenge {challenge_id!r} does not exist")
    return _row_to_dict(row)


def _load_device(conn: sqlite3.Connection, device_id: str) -> dict:
    row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if row is None:
        raise Denial("UNKNOWN_DEVICE", f"device {device_id!r} is not registered")
    return _row_to_dict(row)


def _baseline_state(row: dict) -> dict:
    return {
        "baseline_id": row["baseline_id"],
        "group_id": row["group_id"],
        "kind": row["kind"],
        "version": row["version"],
        "state": row["state"],
        "published_at": row["published_at"],
        "revoked_at": row["revoked_at"],
        "superseded_at": row["superseded_at"],
        "superseded_by": row["superseded_by"],
    }


def _device_state(device: dict) -> dict:
    return {
        "device_id": device["device_id"],
        "tenant_id": device["tenant_id"],
        "group_id": device["group_id"],
        "generation": device["generation"],
        "counter_watermark": device["counter_watermark"],
    }


def _group_state(group: dict) -> dict:
    return {
        "group_id": group["group_id"],
        "full_min_version": group["full_min_version"],
        "recovery_min_version": group["recovery_min_version"],
    }


# --------------------------------------------------------------------------
# Transactions, kill points and receipts
# --------------------------------------------------------------------------

def _stored_receipt(conn: sqlite3.Connection, request: dict) -> dict | None:
    """The receipt for ``request`` if this id has already been committed.

    Called *inside* the write transaction as well as before it, so two
    processes submitting the same request id concurrently converge on one commit
    and one identical answer instead of racing into different outcomes.
    """
    request_id = request.get("request_id")
    digest = request.get("_digest")
    if not isinstance(request_id, str) or not request_id or digest is None:
        return None
    row = conn.execute("SELECT request_digest, response_json FROM receipts WHERE request_id = ?",
                       (request_id,)).fetchone()
    if row is None:
        return None
    if row["request_digest"] != digest:
        raise Denial("REQUEST_ID_CONFLICT",
                     "request id was already used with different request content")
    response = json.loads(row["response_json"])
    response["replayed"] = True
    return response


def _write_txn(db_path: str, control, body, request: dict | None = None):
    """``BEGIN IMMEDIATE`` ... ``COMMIT`` with the two documented kill points.

    When ``request`` is supplied, the receipt table is consulted *after* the
    write lock is held; a concurrent duplicate of the same request id therefore
    returns the winner's receipt instead of re-executing against state that the
    winner already changed.
    """
    conn = store.connection_for(db_path)
    deadline = time.monotonic() + TXN_DEADLINE_SECONDS
    # Bound SQLite's own busy wait by the remaining budget so a wedged writer
    # surfaces as a TIMEOUT denial instead of hanging for the driver's timeout.
    remaining_ms = max(1, int(TXN_DEADLINE_SECONDS * 1000))
    conn.execute(f"PRAGMA busy_timeout = {remaining_ms}")
    while True:
        try:
            conn.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc) and "busy" not in str(exc):
                raise
            if time.monotonic() > deadline:
                raise Denial("TIMEOUT", "could not acquire the write lock")
            time.sleep(0.005)
    try:
        if request is not None:
            stored = _stored_receipt(conn, request)
            if stored is not None:
                conn.execute("COMMIT")
                return stored
        result = body(conn, control)
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    else:
        conn.execute("COMMIT")
        # Kill window B: the transaction is durable but the caller has not been
        # answered.  A crash here must be indistinguishable from a retry of the
        # same request id -- the stored receipt makes the replay identical.
        if control is not None:
            control.checkpoint("after_commit")
        return result


def _store_receipt(conn: sqlite3.Connection, request_id: str, digest: str, response: dict, at: int) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO receipts(request_id, request_digest, response_json, created_at) "
        "VALUES (?,?,?,?)",
        (request_id, digest, json.dumps(response, sort_keys=True), at),
    )


def _finish(conn: sqlite3.Connection, request: dict, op: str, result: dict, at: int) -> dict:
    response = _accepted(request.get("request_id"), op, result)
    _store_receipt(conn, request["request_id"], request["_digest"], response, at)
    return response


# --------------------------------------------------------------------------
# Registry and policy operations
# --------------------------------------------------------------------------

def op_create_group(db_path: str, request: dict, control) -> dict:
    group_id = _require_str(request.get("group_id"), "group_id")
    full_min = _require_int(request.get("full_min_version", 0), "full_min_version", 0)
    recovery_min = _require_int(request.get("recovery_min_version", 0), "recovery_min_version", 0)
    at = _require_int(request.get("at"), "at", 0)

    def body(conn, ctl):
        existing = _row_to_dict(conn.execute(
            "SELECT * FROM groups WHERE group_id = ?", (group_id,)).fetchone())
        if existing is not None:
            if existing["full_min_version"] > full_min or existing["recovery_min_version"] > recovery_min:
                raise Denial("POLICY_NOT_MONOTONIC",
                             "full_min_version and recovery_min_version may never decrease")
            conn.execute("UPDATE groups SET full_min_version = ?, recovery_min_version = ? "
                         "WHERE group_id = ?", (full_min, recovery_min, group_id))
        else:
            conn.execute("INSERT INTO groups(group_id, full_min_version, recovery_min_version) "
                         "VALUES (?,?,?)", (group_id, full_min, recovery_min))
        return _finish(conn, request, "create_group",
                       {"group": _group_state(_load_group(conn, group_id))}, at)

    return _write_txn(db_path, control, body, request)


def op_set_floors(db_path: str, request: dict, control) -> dict:
    group_id = _require_str(request.get("group_id"), "group_id")
    at = _require_int(request.get("at"), "at", 0)

    def body(conn, ctl):
        group = _load_group(conn, group_id)
        full_min = group["full_min_version"]
        recovery_min = group["recovery_min_version"]
        if "full_min_version" in request:
            full_min = _require_int(request["full_min_version"], "full_min_version", 0)
        if "recovery_min_version" in request:
            recovery_min = _require_int(request["recovery_min_version"], "recovery_min_version", 0)
        if full_min < group["full_min_version"]:
            raise Denial("POLICY_NOT_MONOTONIC",
                         f"full_min_version may not decrease "
                         f"({group['full_min_version']} -> {full_min})")
        if recovery_min < group["recovery_min_version"]:
            raise Denial("POLICY_NOT_MONOTONIC",
                         f"recovery_min_version may not decrease "
                         f"({group['recovery_min_version']} -> {recovery_min})")
        conn.execute("UPDATE groups SET full_min_version = ?, recovery_min_version = ? "
                     "WHERE group_id = ?", (full_min, recovery_min, group_id))
        return _finish(conn, request, "set_floors",
                       {"group": _group_state(_load_group(conn, group_id))}, at)

    return _write_txn(db_path, control, body, request)


def op_publish_baseline(db_path: str, request: dict, control) -> dict:
    raw = request.get("baseline")
    at = _require_int(request.get("at"), "at", 0)
    baselines.validate_doc(raw)
    # The publisher signature is a pure function of the document, so it can be
    # (and is) checked before the transaction: a forged document never even
    # reaches the conflict / floor logic, and cannot be "accepted as a duplicate".
    if "signature" in raw and not baselines.verify_signature(dict(raw)):
        raise Denial("BASELINE_SIGNATURE_INVALID",
                     "baseline publisher signature does not verify", stage="baseline")

    def body(conn, ctl):
        group = _load_group(conn, raw["group_id"])
        clash = conn.execute("SELECT group_id, kind, version FROM baselines WHERE baseline_id = ?",
                             (raw["baseline_id"],)).fetchone()
        if clash is not None and (clash["group_id"], clash["kind"], clash["version"]) != (
                raw["group_id"], raw["kind"], raw["version"]):
            raise Denial("BASELINE_CONFLICT",
                         f"baseline id {raw['baseline_id']!r} is already used for another "
                         f"group/kind/version")
        if "signature" in raw:
            doc = dict(raw)
        else:
            doc = baselines.attach_signature(dict(raw))
        signature = doc["signature"]
        doc_digest = crypto.baseline_digest(doc)
        stored_doc = {key: value for key, value in doc.items() if key != "signature"}

        existing = _row_to_dict(conn.execute(
            "SELECT * FROM baselines WHERE group_id = ? AND kind = ? AND version = ?",
            (doc["group_id"], doc["kind"], doc["version"])).fetchone())
        if existing is not None:
            if existing["doc_digest"] == doc_digest and existing["signature"] == signature:
                return _finish(conn, request, "publish_baseline",
                               {"baseline": _baseline_state(existing), "duplicate": True}, at)
            raise Denial("BASELINE_CONFLICT",
                         "a different baseline already occupies this group/kind/version")

        declared = doc.get("min_full_version")
        if doc["kind"] == "recovery":
            # A recovery baseline may never lower the full-privilege floor.
            if declared is not None and declared < group["full_min_version"]:
                raise Denial("RECOVERY_LOWERS_FULL_FLOOR",
                             "a recovery baseline may not lower the full-privilege minimum version")
            if doc["version"] < group["recovery_min_version"]:
                raise Denial("RECOVERY_FLOOR_NOT_MET",
                             "recovery baseline version is below the group recovery minimum")
        else:
            if declared is not None and declared < group["full_min_version"]:
                raise Denial("FULL_FLOOR_NOT_MET",
                             "a full baseline may not lower the full-privilege minimum version")
            if doc["version"] < group["full_min_version"]:
                raise Denial("FULL_FLOOR_NOT_MET",
                             "full baseline version is below the group minimum")
            if declared is not None and declared > group["full_min_version"]:
                conn.execute("UPDATE groups SET full_min_version = ? WHERE group_id = ?",
                             (declared, doc["group_id"]))

        # Versions move forward: after a newer version exists, an older one may
        # not be (re)published as fresh.  Otherwise a retired layout could come
        # back to life next to the current baseline.
        newer = conn.execute(
            "SELECT baseline_id, version FROM baselines WHERE group_id = ? AND kind = ? "
            "AND version > ? LIMIT 1", (doc["group_id"], doc["kind"], doc["version"])).fetchone()
        if newer is not None:
            raise Denial("BASELINE_CONFLICT",
                         f"version {doc['version']} is older than the already known version "
                         f"{newer['version']} ({newer['baseline_id']})")

        # A newly published version supersedes every older *published*
        # baseline of the same group and kind.  Revoked and already-superseded
        # rows keep their timestamps: a later publication never resurrects an
        # older version.
        conn.execute(
            "UPDATE baselines SET state = 'superseded', superseded_at = ?, superseded_by = ? "
            "WHERE group_id = ? AND kind = ? AND version < ? AND state = 'published'",
            (at, doc["baseline_id"], doc["group_id"], doc["kind"], doc["version"]),
        )
        conn.execute(
            "INSERT INTO baselines(baseline_id, group_id, kind, version, doc_json, doc_digest, "
            "signature, state, published_at, revoked_at, superseded_at, superseded_by) "
            "VALUES (?,?,?,?,?,?,?,'published',?,NULL,NULL,NULL)",
            (doc["baseline_id"], doc["group_id"], doc["kind"], doc["version"],
             json.dumps(stored_doc, sort_keys=True), doc_digest, signature, at),
        )
        row = _load_baseline(conn, doc["baseline_id"])
        return _finish(conn, request, "publish_baseline",
                       {"baseline": _baseline_state(row), "duplicate": False}, at)

    return _write_txn(db_path, control, body, request)


def op_revoke_baseline(db_path: str, request: dict, control) -> dict:
    baseline_id = _require_str(request.get("baseline_id"), "baseline_id")
    at = _require_int(request.get("at"), "at", 0)
    reason = request.get("reason", "revoked")
    if not isinstance(reason, str):
        raise Denial("BAD_REQUEST", "reason must be a string")

    def body(conn, ctl):
        row = _load_baseline(conn, baseline_id)
        _decode_doc(row)  # never mutate a document whose integrity is broken
        if row["revoked_at"] is not None:
            return _finish(conn, request, "revoke_baseline",
                           {"baseline": _baseline_state(row), "already_revoked": True}, at)
        conn.execute("UPDATE baselines SET state = 'revoked', revoked_at = ? WHERE baseline_id = ?",
                     (at, baseline_id))
        row = _load_baseline(conn, baseline_id)
        return _finish(conn, request, "revoke_baseline",
                       {"baseline": _baseline_state(row), "already_revoked": False, "reason": reason}, at)

    return _write_txn(db_path, control, body, request)


def _apply_generation(conn: sqlite3.Connection, device: dict, new_generation: int, at: int) -> None:
    """Bump the generation: cancel old credentials and challenges, keep the watermark."""
    conn.execute("UPDATE devices SET generation = ? WHERE device_id = ?",
                 (new_generation, device["device_id"]))
    conn.execute(
        "UPDATE credentials SET revoked_at = ?, revoke_reason = 'generation-change' "
        "WHERE device_id = ? AND revoked_at IS NULL",
        (at, device["device_id"]),
    )
    conn.execute(
        "UPDATE challenges SET invalidated = 1 WHERE device_id = ? AND generation < ?",
        (device["device_id"], new_generation),
    )


def op_register_device(db_path: str, request: dict, control) -> dict:
    device_id = _require_str(request.get("device_id"), "device_id")
    tenant_id = _require_str(request.get("tenant_id"), "device tenant_id")
    group_id = _require_str(request.get("group_id"), "device group_id")
    generation = _require_int(request.get("generation", 1), "generation", 1)
    at = _require_int(request.get("at"), "at", 0)

    def body(conn, ctl):
        _load_group(conn, group_id)
        row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO devices(device_id, tenant_id, group_id, generation, "
                "counter_watermark, registered_at) VALUES (?,?,?,?,-1,?)",
                (device_id, tenant_id, group_id, generation, at),
            )
            device = _load_device(conn, device_id)
            return _finish(conn, request, "register_device",
                           {"device": _device_state(device), "created": True, "rotated": False}, at)
        existing = _row_to_dict(row)
        if existing["tenant_id"] != tenant_id or existing["group_id"] != group_id:
            raise Denial("DEVICE_ID_CONFLICT",
                         "device id already exists with a different tenant or group")
        if generation < existing["generation"]:
            raise Denial("GENERATION_MISMATCH",
                         "re-registration may not move a device to an older generation")
        rotated = False
        if generation > existing["generation"]:
            _apply_generation(conn, existing, generation, at)
            rotated = True
        # Re-registration never touches counter_watermark: the anti-rollback
        # watermark survives re-registration and generation changes alike.
        device = _load_device(conn, device_id)
        return _finish(conn, request, "register_device",
                       {"device": _device_state(device), "created": False, "rotated": rotated}, at)

    return _write_txn(db_path, control, body, request)


def op_rotate_generation(db_path: str, request: dict, control) -> dict:
    device_id = _require_str(request.get("device_id"), "device_id")
    new_generation = _require_int(request.get("new_generation"), "new_generation", 1)
    at = _require_int(request.get("at"), "at", 0)

    def body(conn, ctl):
        device = _load_device(conn, device_id)
        if new_generation == device["generation"]:
            return _finish(conn, request, "rotate_generation",
                           {"device": _device_state(device), "rotated": False}, at)
        if new_generation < device["generation"]:
            raise Denial("GENERATION_MISMATCH", "generations only move forward")
        _apply_generation(conn, device, new_generation, at)
        device = _load_device(conn, device_id)
        return _finish(conn, request, "rotate_generation",
                       {"device": _device_state(device), "rotated": True}, at)

    return _write_txn(db_path, control, body, request)


def op_issue_challenge(db_path: str, request: dict, control) -> dict:
    challenge_id = _require_str(request.get("challenge_id"), "challenge_id")
    nonce = _require_str(request.get("nonce"), "nonce")
    device_id = _require_str(request.get("device_id"), "device_id")
    issued_at = _require_int(request.get("issued_at"), "issued_at", 0)
    expires_at = _require_int(request.get("expires_at"), "expires_at", 0)
    tenant_id = request.get("tenant_id")

    def body(conn, ctl):
        device = _load_device(conn, device_id)
        if tenant_id is not None:
            _require_str(tenant_id, "tenant_id")
            if tenant_id != device["tenant_id"]:
                raise Denial("TENANT_MISMATCH",
                             "challenge tenant does not match the device tenant")
        if expires_at <= issued_at:
            raise Denial("BAD_REQUEST", "expires_at must be after issued_at")
        if conn.execute("SELECT 1 FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone():
            raise Denial("CHALLENGE_CONFLICT", "challenge id already exists")
        if conn.execute("SELECT 1 FROM challenges WHERE tenant_id = ? AND nonce = ?",
                        (device["tenant_id"], nonce)).fetchone():
            raise Denial("CHALLENGE_CONFLICT", "nonce already used for this tenant")
        conn.execute(
            "INSERT INTO challenges(challenge_id, nonce, tenant_id, device_id, generation, "
            "issued_at, expires_at, consumed_by, consumed_at, invalidated) "
            "VALUES (?,?,?,?,?,?,?,NULL,NULL,0)",
            (challenge_id, nonce, device["tenant_id"], device_id, device["generation"],
             issued_at, expires_at),
        )
        return _finish(conn, request, "issue_challenge", {
            "challenge": {
                "challenge_id": challenge_id,
                "nonce": nonce,
                "tenant_id": device["tenant_id"],
                "device_id": device_id,
                "generation": device["generation"],
                "issued_at": issued_at,
                "expires_at": expires_at,
                "window": "half-open [issued_at, expires_at)",
            }
        }, issued_at)

    return _write_txn(db_path, control, body, request)


# --------------------------------------------------------------------------
# Attestation
# --------------------------------------------------------------------------

def _precheck(db_path: str, attestation: dict) -> dict:
    """Stateless verification, deliberately outside any transaction."""
    baseline_id = attestation.get("baseline_id")
    if not isinstance(baseline_id, str) or not baseline_id:
        raise Denial("BAD_REQUEST", "baseline_id must be a non-empty string")
    conn = store.connection_for(db_path)
    row = conn.execute("SELECT * FROM baselines WHERE baseline_id = ?", (baseline_id,)).fetchone()
    if row is None:
        raise Denial("BASELINE_UNKNOWN", f"baseline {baseline_id!r} does not exist")
    row = _row_to_dict(row)
    doc = _decode_doc(row)
    summary = verify.verify_attestation(attestation, doc)
    summary["baseline_kind"] = row["kind"]
    summary["baseline_version"] = row["version"]
    return summary


def _check_state(conn: sqlite3.Connection, attestation: dict, at: int) -> dict:
    """Every check that depends on shared mutable state, under the write lock."""
    device = _load_device(conn, attestation["device_id"])
    if device["tenant_id"] != attestation["tenant_id"]:
        raise Denial("TENANT_MISMATCH", "device is registered to a different tenant", stage="commit")
    if device["group_id"] != attestation["group_id"]:
        raise Denial("GROUP_MISMATCH",
                     "attestation claims a group the device is not registered to", stage="commit")
    if attestation["generation"] != device["generation"]:
        raise Denial("GENERATION_MISMATCH",
                     "attestation generation is not the current device generation", stage="commit")

    challenge = _load_challenge(conn, attestation["challenge_id"])
    if challenge["tenant_id"] != attestation["tenant_id"]:
        raise Denial("CHALLENGE_TENANT_MISMATCH", "challenge belongs to a different tenant",
                     stage="commit")
    if challenge["device_id"] != attestation["device_id"]:
        raise Denial("CHALLENGE_DEVICE_MISMATCH", "challenge was issued for a different device",
                     stage="commit")
    # A generation change both bumps the counter and marks the old challenges;
    # the generation comparison is the authoritative check (it also covers a
    # dataset where only one of the two markers was written).
    if challenge["generation"] != device["generation"]:
        raise Denial("CHALLENGE_GENERATION_MISMATCH",
                     "challenge was issued in a previous device generation", stage="commit")
    if challenge["consumed_by"] is not None:
        raise Denial("CHALLENGE_CONSUMED", "challenge was already consumed", stage="commit")
    # Half-open challenge window [issued_at, expires_at): "exactly at expiry"
    # is expired, not valid.
    if at < challenge["issued_at"]:
        raise Denial("CHALLENGE_NOT_YET_VALID", "verification time precedes the challenge issue",
                     stage="commit")
    if at >= challenge["expires_at"]:
        raise Denial("CHALLENGE_EXPIRED",
                     "verification time reached or passed the challenge expiry", stage="commit")
    if attestation["observed_at"] < challenge["issued_at"]:
        raise Denial("CHALLENGE_NOT_YET_VALID", "device observation precedes the challenge issue",
                     stage="commit")
    if attestation["observed_at"] >= challenge["expires_at"]:
        raise Denial("CHALLENGE_EXPIRED",
                     "device observation reached or passed the challenge expiry", stage="commit")

    baseline = _load_baseline(conn, attestation["baseline_id"])
    if baseline["group_id"] != device["group_id"]:
        raise Denial("BASELINE_GROUP_MISMATCH", "baseline belongs to a different device group",
                     stage="commit")
    # Two different questions are asked, and both must pass:
    #   * historical -- was the baseline legitimately published at the
    #     declared verification instant?  (catches "not published yet" and
    #     "already revoked when the device measured")
    #   * current    -- may it still issue at commit time?  (catches a
    #     revocation or a newer activation that raced with this request,
    #     whatever the client claims ``at`` to be)
    denial = baselines.historical_denial(baseline, at) or baselines.current_denial(baseline)
    if denial is not None:
        raise Denial(denial, f"baseline {baseline['baseline_id']!r} may not issue at t={at}",
                     stage="commit")
    group = _load_group(conn, device["group_id"])
    floor = baselines.effective_floor(group, baseline)
    if baseline["version"] < floor:
        raise Denial(baselines.floor_code(baseline),
                     f"baseline version {baseline['version']} is below the group floor {floor}",
                     stage="commit")

    if not baselines.is_int(attestation["boot_counter"]) or attestation["boot_counter"] < 0:
        raise Denial("COUNTER_INVALID", "boot_counter must be an integer >= 0", stage="commit")
    if device["counter_watermark"] >= 0 and attestation["boot_counter"] <= device["counter_watermark"]:
        raise Denial("COUNTER_ROLLBACK",
                     f"boot_counter {attestation['boot_counter']} is not above the observed "
                     f"watermark {device['counter_watermark']}", stage="commit")

    return {"device": device, "challenge": challenge, "baseline": baseline, "group": group}


def _attest_body(conn, request: dict, control) -> dict:
    attestation = request["attestation"]
    at = request["at"]
    state = _check_state(conn, attestation, at)
    baseline = state["baseline"]
    device = state["device"]

    # Re-read and re-verify the baseline under the lock and re-audit the chain:
    # a revocation or supersession that raced with the precheck must not be
    # able to authorise this commit.
    doc = _decode_doc(baseline)
    if doc["baseline_id"] != attestation["baseline_id"]:
        raise Denial("BASELINE_DOC_MISMATCH", "stored baseline id mismatch", stage="commit")
    summary = verify.audit_chain(attestation, doc)

    requested_scope = request.get("requested_scope")
    if requested_scope is not None and requested_scope not in SCOPES:
        raise Denial("BAD_REQUEST", f"requested_scope must be one of {list(SCOPES)}")
    if baseline["kind"] == "recovery" and requested_scope == "full-access":
        raise Denial("RECOVERY_SCOPE_DENIED",
                     "a recovery baseline may only issue diagnostic-readonly credentials",
                     stage="commit")
    scope = requested_scope or NATURAL_SCOPE[baseline["kind"]]

    previous = device["counter_watermark"]
    # Kill window A: the watermark write is in the open transaction but nothing
    # is committed yet.  A crash here must leave the database untouched.
    conn.execute("UPDATE devices SET counter_watermark = ? WHERE device_id = ?",
                 (attestation["boot_counter"], device["device_id"]))
    if control is not None:
        control.checkpoint("before_commit")

    credential_id = "cred-" + crypto.sha256_hex(str(request["request_id"]).encode("utf-8"))[:24]
    token = crypto.credential_token(credential_id, scope, device["generation"],
                                    device["device_id"])
    conn.execute(
        "INSERT INTO credentials(credential_id, token, device_id, tenant_id, scope, generation, "
        "baseline_id, boot_counter, issued_at, revoked_at, revoke_reason) "
        "VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL)",
        (credential_id, token, device["device_id"], device["tenant_id"], scope,
         device["generation"], baseline["baseline_id"], attestation["boot_counter"], at),
    )
    conn.execute("UPDATE challenges SET consumed_by = ?, consumed_at = ? WHERE challenge_id = ?",
                 (request["request_id"], at, state["challenge"]["challenge_id"]))

    result = {
        "credential": {
            "credential_id": credential_id,
            "token": token,
            "scope": scope,
            "tenant_id": device["tenant_id"],
            "device_id": device["device_id"],
            "generation": device["generation"],
            "baseline_id": baseline["baseline_id"],
            "baseline_kind": baseline["kind"],
            "boot_counter": attestation["boot_counter"],
            "issued_at": at,
        },
        "baseline": _baseline_state(baseline),
        "device": _device_state(_load_device(conn, device["device_id"])),
        "previous_counter": previous,
        "chain_root": summary["chain_root"],
        "chain_length": summary["chain_length"],
        "critical_modules": summary["critical_modules"],
    }
    return _finish(conn, request, "attest", result, at)


VERIFIER = None  # optional callable(db_path, attestation) -> summary


def op_attest(db_path: str, request: dict, control) -> dict:
    attestation = request.get("attestation")
    if not isinstance(attestation, dict):
        raise Denial("BAD_REQUEST", "attestation must be an object")
    at = request.get("at")
    if not baselines.is_int(at) or at < 0:
        raise Denial("BAD_REQUEST", "at must be an integer >= 0")
    if VERIFIER is None:
        _precheck(db_path, attestation)      # phase A, outside any transaction
    else:
        VERIFIER(db_path, attestation)       # phase A, in a separate process
    return _write_txn(db_path, control,
                      lambda conn, ctl: _attest_body(conn, request, ctl), request)


def op_present_credential(db_path: str, request: dict, control) -> dict:
    token = _require_str(request.get("token"), "token")
    at = _require_int(request.get("at"), "at", 0)
    conn = store.connection_for(db_path)
    row = conn.execute("SELECT * FROM credentials WHERE token = ?", (token,)).fetchone()
    if row is None:
        raise Denial("CREDENTIAL_UNKNOWN", "credential token is unknown")
    cred = _row_to_dict(row)
    device_row = conn.execute("SELECT * FROM devices WHERE device_id = ?",
                              (cred["device_id"],)).fetchone()
    if device_row is None:
        raise Denial("CREDENTIAL_DEVICE_UNKNOWN", "credential refers to an unknown device")
    device = _row_to_dict(device_row)
    if cred["revoked_at"] is not None and cred["revoked_at"] <= at:
        raise Denial("CREDENTIAL_REVOKED", f"credential was revoked ({cred['revoke_reason']})")
    if cred["generation"] != device["generation"]:
        raise Denial("CREDENTIAL_GENERATION_STALE",
                     "credential belongs to a previous device generation")
    return _accepted(request.get("request_id"), "present_credential", {
        "credential_id": cred["credential_id"],
        "scope": cred["scope"],
        "tenant_id": cred["tenant_id"],
        "device_id": cred["device_id"],
        "generation": cred["generation"],
        "baseline_id": cred["baseline_id"],
        "boot_counter": cred["boot_counter"],
        "valid_at": at,
    })


# --------------------------------------------------------------------------
# Read-only inspection operations
# --------------------------------------------------------------------------

def op_get_device(db_path: str, request: dict, control) -> dict:
    device_id = _require_str(request.get("device_id"), "device_id")
    device = _load_device(store.connection_for(db_path), device_id)
    return _accepted(request.get("request_id"), "get_device", {"device": _device_state(device)})


def op_get_baseline(db_path: str, request: dict, control) -> dict:
    baseline_id = _require_str(request.get("baseline_id"), "baseline_id")
    conn = store.connection_for(db_path)
    row = _load_baseline(conn, baseline_id)
    doc = _decode_doc(row)
    return _accepted(request.get("request_id"), "get_baseline", {
        "baseline": _baseline_state(row),
        "modules": doc["modules"],
        "min_full_version": doc.get("min_full_version"),
    })


def op_get_challenge(db_path: str, request: dict, control) -> dict:
    challenge_id = _require_str(request.get("challenge_id"), "challenge_id")
    row = _load_challenge(store.connection_for(db_path), challenge_id)
    return _accepted(request.get("request_id"), "get_challenge", {"challenge": row})


def op_list_credentials(db_path: str, request: dict, control) -> dict:
    device_id = _require_str(request.get("device_id"), "device_id")
    rows = store.connection_for(db_path).execute(
        "SELECT credential_id, scope, generation, boot_counter, issued_at, revoked_at, "
        "revoke_reason FROM credentials WHERE device_id = ? ORDER BY issued_at, credential_id",
        (device_id,),
    ).fetchall()
    return _accepted(request.get("request_id"), "list_credentials",
                     {"credentials": [_row_to_dict(row) for row in rows]})


def op_snapshot(db_path: str, request: dict, control) -> dict:
    conn = store.connection_for(db_path)
    payload: dict[str, Any] = {}
    device_id = request.get("device_id")
    if device_id is not None:
        payload["device"] = _device_state(_load_device(conn, _require_str(device_id, "device_id")))
        payload["credentials"] = [_row_to_dict(row) for row in conn.execute(
            "SELECT credential_id, scope, generation, boot_counter, revoked_at, revoke_reason "
            "FROM credentials WHERE device_id = ? ORDER BY issued_at, credential_id",
            (device_id,)).fetchall()]
        payload["challenges"] = [_row_to_dict(row) for row in conn.execute(
            "SELECT challenge_id, generation, consumed_by, invalidated FROM challenges "
            "WHERE device_id = ? ORDER BY issued_at, challenge_id", (device_id,)).fetchall()]
    payload["receipt_count"] = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    return _accepted(request.get("request_id"), "snapshot", payload)


def op_get_receipt(db_path: str, request: dict, control) -> dict:
    target = _require_str(request.get("target_request_id"), "target_request_id")
    row = store.connection_for(db_path).execute(
        "SELECT request_id, request_digest, response_json FROM receipts WHERE request_id = ?",
        (target,)).fetchone()
    if row is None:
        raise Denial("BAD_REQUEST", "no receipt for that request id")
    return _accepted(request.get("request_id"), "get_receipt", {
        "request_id": row["request_id"],
        "request_digest": row["request_digest"],
        "response": json.loads(row["response_json"]),
    })


OPS = {
    "create_group": op_create_group,
    "set_floors": op_set_floors,
    "publish_baseline": op_publish_baseline,
    "revoke_baseline": op_revoke_baseline,
    "register_device": op_register_device,
    "rotate_generation": op_rotate_generation,
    "issue_challenge": op_issue_challenge,
    "attest": op_attest,
    "present_credential": op_present_credential,
    "get_device": op_get_device,
    "get_baseline": op_get_baseline,
    "get_challenge": op_get_challenge,
    "list_credentials": op_list_credentials,
    "snapshot": op_snapshot,
    "get_receipt": op_get_receipt,
}

READ_ONLY_OPS = {"get_device", "get_baseline", "get_challenge", "list_credentials",
                 "snapshot", "get_receipt"}

SEQUENCED_OPS = {op for op in OPS if op not in READ_ONLY_OPS}


# --------------------------------------------------------------------------
# Response envelopes
# --------------------------------------------------------------------------

def _accepted(request_id, op: str, result: dict, replayed: bool = False) -> dict:
    return {
        "request_id": request_id,
        "op": op,
        "status": "accepted",
        "code": None,
        "message": None,
        "stage": None,
        "replayed": replayed,
        "result": result,
    }


def _denied(request_id, op: str, denial: Denial, replayed: bool = False) -> dict:
    return {
        "request_id": request_id,
        "op": op,
        "status": "denied",
        "code": denial.code,
        "message": denial.message,
        "stage": denial.stage,
        "replayed": replayed,
        "result": None,
        "detail": denial.detail,
    }


# --------------------------------------------------------------------------
# Top level
# --------------------------------------------------------------------------

def set_verifier(verifier) -> None:
    """Install a phase-A verifier (``None`` = in-process, the default)."""
    global VERIFIER
    VERIFIER = verifier


def execute_operation(db_path: str, request: dict, control=None) -> dict:
    """Run one request, honouring the same-request-id receipt contract."""
    if not isinstance(request, dict):
        return _denied(None, "?", Denial("BAD_REQUEST", "request must be an object"))
    op = request.get("op")
    request_id = request.get("request_id")
    if not isinstance(op, str) or op not in OPS:
        return _denied(request_id if isinstance(request_id, str) else None, str(op),
                       Denial("BAD_REQUEST",
                              f"unknown op {op!r}; expected one of {sorted(OPS)}"))

    try:
        digest = request_digest(request)
    except (TypeError, ValueError):
        return _denied(request_id if isinstance(request_id, str) else None, op,
                       Denial("BAD_REQUEST", "request is not JSON-serialisable"))

    if op in SEQUENCED_OPS:
        try:
            validate_request_id(request)
        except Denial as denial:
            return _denied(request_id if isinstance(request_id, str) else None, op, denial)

        row = store.connection_for(db_path).execute(
            "SELECT request_digest, response_json FROM receipts WHERE request_id = ?",
            (request_id,)).fetchone()
        if row is not None:
            if row["request_digest"] != digest:
                return _denied(request_id, op, Denial(
                    "REQUEST_ID_CONFLICT",
                    "request id was already used with different request content"))
            response = json.loads(row["response_json"])
            response["replayed"] = True
            return response

    enriched = dict(request)
    enriched["_digest"] = digest
    try:
        return OPS[op](db_path, enriched, control)
    except Denial as denial:
        response = _denied(request_id, op, denial)
        if denial.code not in TRANSIENT_CODES and op in SEQUENCED_OPS:
            _persist_denial(db_path, request_id, digest, response, request.get("at"))
        return response
    except sqlite3.IntegrityError as exc:
        # A race lost at the storage layer (for example two processes inserting
        # the same natural key).  Reported with a stable code, never persisted:
        # the caller may retry with a fresh request id.
        return _denied(request_id, op, Denial("INTERNAL", f"storage constraint: {exc}"))
    except (sqlite3.Error, OSError) as exc:  # pragma: no cover - defensive
        return _denied(request_id, op, Denial("INTERNAL", f"storage failure: {exc}"))


def _persist_denial(db_path: str, request_id, digest: str, response: dict, at) -> None:
    """Record a denial receipt in its own transaction (never in the failed one)."""
    if not isinstance(request_id, str) or not request_id:
        return
    if not baselines.is_int(at):
        at = 0

    def body(conn, ctl):
        _store_receipt(conn, request_id, digest, response, at)
        return None

    try:
        _write_txn(db_path, None, body)
    except (sqlite3.Error, Denial):
        pass
