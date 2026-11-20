"""SQLite schema, connection handling and units of work.

Design notes
------------
* ``BEGIN IMMEDIATE`` is used for every mutating unit of work, so writers
  serialize in SQLite instead of relying on in-process locks.  That is what
  makes the concurrency test meaningful across real subprocesses.
* Attestation *verification* (crypto + measurement-chain audit) runs outside
  any transaction, in a separate process.  Every check that depends on shared
  state (device generation, challenge window, baseline publication/revocation,
  previous counter) is repeated inside the write transaction.
* ``journal_mode=WAL`` + ``synchronous=FULL`` give the two crash windows of the
  task their meaning: an uncommitted watermark write leaves no trace, while a
  committed-but-unacknowledged transaction is fully durable and is found by a
  replay of the same request id.
"""

from __future__ import annotations

import os
import sqlite3
import threading

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS groups (
    group_id              TEXT PRIMARY KEY,
    full_min_version      INTEGER NOT NULL DEFAULT 0,
    recovery_min_version  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS baselines (
    baseline_id     TEXT PRIMARY KEY,
    group_id        TEXT NOT NULL REFERENCES groups(group_id),
    kind            TEXT NOT NULL CHECK (kind IN ('full', 'recovery')),
    version         INTEGER NOT NULL CHECK (version >= 1),
    doc_json        TEXT NOT NULL,
    doc_digest      TEXT NOT NULL,
    signature       TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('published', 'revoked', 'superseded')),
    published_at    INTEGER NOT NULL,
    revoked_at      INTEGER,
    superseded_at   INTEGER,
    superseded_by   TEXT,
    UNIQUE (group_id, kind, version)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id          TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    group_id           TEXT NOT NULL REFERENCES groups(group_id),
    generation         INTEGER NOT NULL CHECK (generation >= 1),
    counter_watermark  INTEGER NOT NULL DEFAULT -1,
    registered_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id  TEXT PRIMARY KEY,
    nonce         TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    device_id     TEXT NOT NULL REFERENCES devices(device_id),
    generation    INTEGER NOT NULL,
    issued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    consumed_by   TEXT,
    consumed_at   INTEGER,
    invalidated   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, nonce)
);

CREATE TABLE IF NOT EXISTS receipts (
    request_id     TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    response_json  TEXT NOT NULL,
    created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id  TEXT PRIMARY KEY,
    token          TEXT NOT NULL UNIQUE,
    device_id      TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    scope          TEXT NOT NULL CHECK (scope IN ('full-access', 'diagnostic-readonly')),
    generation     INTEGER NOT NULL,
    baseline_id    TEXT NOT NULL,
    boot_counter   INTEGER NOT NULL,
    issued_at      INTEGER NOT NULL,
    revoked_at     INTEGER,
    revoke_reason  TEXT
);

CREATE INDEX IF NOT EXISTS idx_baselines_group ON baselines(group_id, kind, state);
CREATE INDEX IF NOT EXISTS idx_challenges_device ON challenges(device_id, generation);
CREATE INDEX IF NOT EXISTS idx_credentials_device ON credentials(device_id, generation);
CREATE INDEX IF NOT EXISTS idx_credentials_token ON credentials(token);
"""

META_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('epoch', '1');
"""


def connect(path: str) -> sqlite3.Connection:
    """Open a connection configured for durability and cross-process use."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


KILL_POINTS = {"before_commit": 1, "after_commit": 2}


class Control:
    """Kill-point control shared between a test driver and a worker process.

    Allocated by the driving test and passed to a worker process as a *Process
    argument*, so multiprocessing pickles the underlying ``Event`` and
    ``Value`` and both sides observe the same objects.  When armed for a named
    kill point, the worker signals ``entered`` immediately before that block and
    then spins until the driver terminates it.  No test-only branch is needed in
    the protocol logic: the checkpoints sit at the two boundaries the crash
    tests care about and are inert unless armed.
    """

    def __init__(self) -> None:
        import multiprocessing

        self.entered = multiprocessing.Event()
        self.target = multiprocessing.Value("i", 0)

    def arm(self, tag: str) -> None:
        self.target.value = KILL_POINTS[tag]

    def disarm(self) -> None:
        self.target.value = 0

    def checkpoint(self, tag: str) -> None:
        if self.target.value == KILL_POINTS[tag]:
            self.entered.set()
            import time

            while True:
                time.sleep(0.005)


_local = threading.local()


def _init_connection(path: str) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(META_SQL)
    conn.executescript(SCHEMA_SQL)
    return conn


def connection_for(path: str) -> sqlite3.Connection:
    """Thread-local connection cache; schema creation is idempotent."""
    key = os.path.abspath(path)
    cache = getattr(_local, "conns", None)
    if cache is None:
        cache = _local.conns = {}
    conn = cache.get(key)
    if conn is None:
        conn = _init_connection(key)
        cache[key] = conn
    return conn


def close_thread_connections() -> None:
    cache = getattr(_local, "conns", None)
    if not cache:
        return
    for conn in cache.values():
        try:
            conn.close()
        except sqlite3.Error:
            pass
    _local.conns = {}
