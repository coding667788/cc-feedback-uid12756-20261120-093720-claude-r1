# Offline Boot-Attestation Audit Service (synthetic, single host)

A self-contained, offline **simulated** attestation-audit service: devices
prove what they booted, the service verifies the proof and issues a local
synthetic access credential, and every commit is atomic in SQLite.  All input is
synthesised; there is no network, no real key material, no wall clock.

* Python **3.12**, **standard library only**, CPU only, Windows-native.
* No third-party packages, no downloads, no network access at any point.

```
python -m solution --input cases.json --output result.json
python -m unittest discover -s tests -v
```

Optional: `--isolated` verifies each proof's stateless phase in its own OS
process; `--db audit.db --request request.json` runs one request directly.

---

## 1. Model

| Concept | Representation |
|---|---|
| Device | synthetic id (e.g. `syn-dev-0001`), tenant, device group, **generation** (int ≥ 1), independent **boot counter** |
| Challenge | tenant-bound unique `challenge_id` + `nonce`, issued for one device and one generation, with a half-open validity window |
| Baseline | versioned per **(group, kind)**; `kind` is `full` or `recovery`; pins an ordered module layout with a SHA-256 payload digest per module plus a `critical` flag |
| Measurement chain | ordered entries `{seq, module, payload_digest, link_digest}` plus a `chain_root` |
| Credential | local synthetic token, scope `full-access` or `diagnostic-readonly` |

Two independent baseline lines per group:

* **full** — may issue `full-access`;
* **recovery** — a read-only recovery line that may *only* issue
  `diagnostic-readonly` credentials and may never lower the full-privilege
  floor or the device's observed boot counter.

## 2. Rules

### 2.1 Measurement chain (verified per proof)

The chain is a SHA-256 hash chain bound to the tenant and the challenge:

```
link[0] = SHA256("BOOT-CHAIN/v1|tenant_id|challenge_id|0|module|payload_digest")
link[i] = SHA256("BOOT-CHAIN/v1|tenant_id|link[i-1]|i|module|payload_digest")
chain_root must equal link[last]
```

Checks, in order:

1. chain non-empty and ≤ 64 entries (`CHAIN_EMPTY`, `CHAIN_TOO_LONG`);
2. sequence numbers unique, contiguous from 0 **and in ascending order**
   (`CHAIN_SEQ_DUPLICATE`, `CHAIN_SEQ_GAP`, `CHAIN_SEQ_ORDER`);
3. every declared `link_digest` equals the recomputed link, and `chain_root`
   equals the final link (`CHAIN_LINK_MISMATCH`, `CHAIN_ROOT_MISMATCH`);
4. **coverage**: every module the selected baseline pins appears in the chain
   (`MISSING_MODULE`) and nothing else does (`EXTRA_MODULE`);
5. **position**: each module sits at exactly the index the baseline defines
   for it — a critical module cannot be moved (`MODULE_POSITION_MISMATCH`);
6. **digest**: each measured payload digest equals the baseline pin
   (`DIGEST_MISMATCH`);
7. **criticality**: an entry may only claim `critical` where the baseline
   defines a critical module (`CRITICAL_MODULE_UNKNOWN`).

### 2.2 Simulated signatures

Both signatures are HMAC-SHA256 tags over canonical JSON (sorted keys, no
whitespace), compared in constant time:

* **baseline publisher signature** — key derived from the group id; stored with
  the document, re-verified on every read, so a mutated stored document is
  detected (`BASELINE_SIGNATURE_INVALID`, `BASELINE_DOC_MISMATCH`);
* **device witness signature** — key derived from the device id; covers the
  whole attestation except the tag itself (`WITNESS_SIGNATURE_INVALID`).

> The keys are deterministic functions of synthetic identifiers.  This is
> deliberate (so `cases.json` is replayable without secrets) and is a
> simulation property, **not** a production key-management design.

### 2.3 Challenge

* unique `challenge_id` and unique `(tenant, nonce)` (`CHALLENGE_CONFLICT`);
* bound to tenant, device and the device generation current at issue time;
* **half-open window** `[issued_at, expires_at)`: `t == expires_at` is
  **expired**, `t == expires_at - 1` is valid;
* both the verification instant (`at`) and the device observation instant
  (`observed_at`) must lie inside the window;
* single use — the first accepted proof consumes it; all later proofs get
  `CHALLENGE_CONSUMED`.

### 2.4 Baseline lifecycle

* publishing a **higher version** of the same (group, kind) marks every older
  *published* baseline `superseded` with `superseded_at` / `superseded_by`;
* revoking marks `revoked` and stamps `revoked_at`; revoking twice is
  idempotent (`already_revoked: true`) and keeps the first timestamp;
* a revoked or superseded baseline is **never resurrected** by a later
  publication or by back-dating a proof;
* documents are immutable: re-publishing identical content is a no-op
  (`duplicate: true`), different content at the same (group, kind, version) is
  `BASELINE_CONFLICT`;
* versions only move forward: once a newer version exists for a (group, kind),
  an older version can never be published (or re-published) again, so a
  retired layout cannot be brought back to life (`BASELINE_CONFLICT`);
* group floors (`full_min_version`, `recovery_min_version`) are
  **monotonic** — they may rise, never fall (`POLICY_NOT_MONOTONIC`);
* a recovery baseline may not declare `min_full_version` below the group's
  current `full_min_version` (`RECOVERY_LOWERS_FULL_FLOOR`).

### 2.5 Commit re-validation

Verification is split in two phases:

* **Phase A — precheck, outside any transaction.** Loads the baseline,
  verifies its digest and signature, verifies the witness signature, audits the
  chain.  This is the expensive part and it holds no write lock (asserted by a
  test that writes from another connection during phase A).  It can run in a
  separate OS process (`solution.isolate.SubprocessVerifier`).
* **Phase B — commit, inside `BEGIN IMMEDIATE`.** Re-reads and re-verifies
  everything that depends on shared mutable state, then re-audits the chain
  against the baseline document it re-read under the lock:
  device tenant, device group, **current generation**, challenge tenant /
  device / generation / consumption / window, baseline group, **historical and
  current** publication+revocation+supersession state, the group floor, and
  the **previous counter watermark**.

### 2.6 Counter watermark

* strictly increasing per device; `boot_counter` must be `> watermark`
  (`COUNTER_ROLLBACK`); a device's first proof accepts any counter ≥ 0
  (watermark starts at `-1`);
* **a valid low-privilege recovery proof advances the watermark too**;
* **generation change** (re-registration to a higher generation, or an explicit
  rotation) revokes all of the device's credentials, invalidates its older
  challenges, and **preserves the watermark**;
* re-registration at the same generation changes nothing at all — in
  particular it never resets the watermark.

### 2.7 Atomic commit and idempotency

One transaction writes, together or not at all: the challenge consumption, the
counter watermark, the credential, and the **receipt** keyed by `request_id`.
A denial is persisted in its own transaction (the failed one is rolled back
first), so a replay reproduces the same denial.

Replaying a `request_id` with **identical** content returns the stored receipt
with `"replayed": true`; replaying it with **different** content is
`REQUEST_ID_CONFLICT`.  Read-only ops bypass the receipt mechanism.

## 3. Input / output

### 3.1 Requests (`cases.json` steps, or `--request` file)

Every mutating request needs `op`, `request_id` (1–128 chars from
`A-Za-z0-9._:-`) and `at` (integer verification instant).

| `op` | fields |
|---|---|
| `create_group` | `group_id`, `full_min_version?`, `recovery_min_version?` |
| `set_floors` | `group_id`, `full_min_version?`, `recovery_min_version?` |
| `publish_baseline` | `baseline` (document); `signature` optional (computed if absent) |
| `revoke_baseline` | `baseline_id`, `reason?` |
| `register_device` | `device_id`, `tenant_id`, `group_id`, `generation?` |
| `rotate_generation` | `device_id`, `new_generation` |
| `issue_challenge` | `challenge_id`, `nonce`, `device_id`, `issued_at`, `expires_at` |
| `attest` | `attestation`, `requested_scope?` (`full-access` / `diagnostic-readonly`) |
| `present_credential` | `token` |
| `get_device` / `get_baseline` / `get_challenge` | `device_id` / `baseline_id` / `challenge_id` |
| `list_credentials` | `device_id` |
| `snapshot` | `device_id?` |
| `get_receipt` | `target_request_id` |

Baseline document:

```json
{
  "baseline_id": "bl-full-v1", "group_id": "tenant-a:grp-1",
  "kind": "full", "version": 1, "released_at": 0,
  "min_full_version": 1,
  "modules": [{"position": 0, "module": "firmware",
               "payload_digest": "<64 hex>", "critical": true}, ...],
  "signature": "<64 hex, optional on input>"
}
```

Attestation:

```json
{
  "tenant_id": "...", "device_id": "...", "group_id": "...",
  "generation": 1, "challenge_id": "...", "baseline_id": "...",
  "boot_counter": 7, "observed_at": 1050,
  "chain": [{"seq": 0, "module": "firmware",
             "payload_digest": "<64 hex>", "link_digest": "<64 hex, optional>"}],
  "chain_root": "<64 hex>",
  "witness_signature": "<64 hex>"
}
```

### 3.2 Response envelope

```json
{"request_id": "...", "op": "attest", "status": "accepted" | "denied",
 "code": null | "CHALLENGE_CONSUMED", "message": null | "...",
 "stage": null | "precheck" | "chain" | "commit" | "baseline",
 "replayed": true | false,
 "result": { ... } | null,
 "detail": { ... } | null}
```

`result` on an accepted `attest`:
`credential{credential_id, token, scope, tenant_id, device_id, generation,
baseline_id, baseline_kind, boot_counter, issued_at}`, `baseline{...}`,
`device{...}`, `previous_counter`, `chain_root`, `chain_length`,
`critical_modules`.

### 3.3 Case file

```json
{"schema_version": 1, "cases": [{"name": "...", "description": "...",
  "steps": [{"request": {...}, "expect": {"status": "...", "code": "...",
                                          "result": {<subset>}}}]}]}
```

`expect.result` is a **subset** match (concrete values, readable expectations).
Each case gets a fresh database.  The CLI exits `0` only if every case and step
passes, and writes a report with per-step `actual` values and failure lists.

CLI options:

| option | meaning |
|---|---|
| `--input FILE --output FILE` | replay a case file; write the report (`exit 0` all passed, `1` otherwise) |
| `--isolated` | run phase A of each proof in a spawned OS process (same results) |
| `--workdir DIR` | where the disposable per-case databases are created |
| `--keep-databases` | keep them and print the directory |
| `--quiet` | only print the summary lines |
| `--db PATH --request FILE` | one-shot mode: run a single request, print its response (`exit 0` accepted, `1` denied) |

## 4. Error codes

52 stable codes.  The canonical table is `ERROR_CODES` in
`solution/errors.py`; this is the same table:

| Group | Codes |
|---|---|
| Request / service | `BAD_REQUEST`, `REQUEST_ID_INVALID`, `REQUEST_ID_CONFLICT`, `INTERNAL`, `TIMEOUT`, `WORKER_FAILED` |
| Device, group and policy | `UNKNOWN_DEVICE`, `TENANT_MISMATCH`, `GROUP_MISMATCH`, `GENERATION_MISMATCH`, `DEVICE_GROUP_UNKNOWN`, `DEVICE_ID_CONFLICT`, `POLICY_NOT_MONOTONIC` |
| Challenge | `CHALLENGE_UNKNOWN`, `CHALLENGE_CONFLICT`, `CHALLENGE_TENANT_MISMATCH`, `CHALLENGE_DEVICE_MISMATCH`, `CHALLENGE_GENERATION_MISMATCH`, `CHALLENGE_NOT_YET_VALID`, `CHALLENGE_EXPIRED`, `CHALLENGE_CONSUMED` |
| Baseline | `BASELINE_UNKNOWN`, `BASELINE_GROUP_MISMATCH`, `BASELINE_SIGNATURE_INVALID`, `BASELINE_DOC_MISMATCH`, `BASELINE_NOT_PUBLISHED`, `BASELINE_REVOKED`, `BASELINE_SUPERSEDED`, `BASELINE_CONFLICT`, `FULL_FLOOR_NOT_MET`, `RECOVERY_FLOOR_NOT_MET`, `RECOVERY_LOWERS_FULL_FLOOR`, `RECOVERY_SCOPE_DENIED` |
| Measurement chain and witness | `WITNESS_SIGNATURE_INVALID`, `CHAIN_EMPTY`, `CHAIN_TOO_LONG`, `CHAIN_SEQ_GAP`, `CHAIN_SEQ_DUPLICATE`, `CHAIN_SEQ_ORDER`, `CHAIN_LINK_MISMATCH`, `CHAIN_ROOT_MISMATCH`, `MISSING_MODULE`, `EXTRA_MODULE`, `MODULE_POSITION_MISMATCH`, `CRITICAL_MODULE_UNKNOWN`, `DIGEST_MISMATCH` |
| Counter and credential | `COUNTER_ROLLBACK`, `COUNTER_INVALID`, `CREDENTIAL_UNKNOWN`, `CREDENTIAL_REVOKED`, `CREDENTIAL_GENERATION_STALE`, `CREDENTIAL_DEVICE_UNKNOWN` |

Every code is one `status: "denied"` response with a `stage` (`precheck`, `chain`, `commit`, `baseline`) saying where the rule fired.

## 5. Persistence

SQLite (`WAL`, `synchronous=FULL`, `foreign_keys=ON`).  Tables:
`groups`, `baselines`, `devices`, `challenges`, `credentials`, `receipts`.
Every mutation is `BEGIN IMMEDIATE`; state-dependent checks are repeated under
the write lock.  `solution/store.py::Control` exposes the two kill points used
by the crash tests:

| kill point | position | required recovery behaviour |
|---|---|---|
| `before_commit` | watermark `UPDATE` executed, transaction **not** committed | nothing survives; replay of the same request id succeeds once |
| `after_commit` | `COMMIT` returned, response **not** delivered | the transaction is durable; replay returns the identical stored receipt |

## 6. Layout

```
solution/__main__.py   CLI (--input/--output, --db/--request)
solution/crypto.py     canonical JSON, HMAC tags, SHA-256 chain, tokens
solution/baselines.py  document validation, supersession/revocation rules
solution/verify.py     stateless chain + signature audit (phase A)
solution/store.py      schema, connections, Control kill points
solution/service.py    operations, transactional commit, receipts
solution/isolate.py    phase A in a spawned child process
solution/synthetic.py  deterministic fixture builders
solution/runner.py     cases.json replay engine
solution/worker.py     worker entry point used by the crash tests
tools/build_cases.py   regenerates cases.json deterministically
tests/                 85 unittest tests (see below)
cases.json             replayable conformance file (20 cases, 169 steps)
result.json            report produced by the replay command above
```

## 7. Tests

`python -m unittest discover -s tests -v` — **85 tests, all passing**
(Python 3.12.8, SQLite 3.45.3, Windows 11 10.0.26200, CPU only).

| file | what it proves |
|---|---|
| `tests/test_rules.py` (44) | happy path; every chain defect (missing / truncated / reordered / shuffled seq / gap / duplicate seq / tampered digest / extra module / empty / bad link / bad root / bad witness); baseline signature & digest tampering; cross-tenant same-module-name isolation; half-open window edges; recovery scope and floors; counter rollback; supersession & revocation; forward-only versions; floor monotonicity |
| `tests/test_processes.py` (10) | two qualifying proofs in **two real processes** racing one challenge → exactly one `accepted`, one `CHALLENGE_CONSUMED`; two challenges, same counter → one `COUNTER_ROLLBACK`; rotation from another process invalidates an in-flight proof; phase A verified in a **separate OS process** (worker pid ≠ caller pid); kill inside `before_commit` → no watermark, no consumption, no credential, no receipt, replay succeeds once; kill inside `after_commit` → durable, replay returns the identical receipt; the **same request id from two processes** commits once and answers both callers identically, while the same id with different content yields one acceptance and one `REQUEST_ID_CONFLICT` |
| `tests/test_atomicity.py` (13) | phase A holds no write lock; revocation / new publication / expiry / floor raise / generation change / counter advance injected **between** phase A and phase B are all caught at commit; receipt+challenge+watermark+credential share one commit; denial replay |
| `tests/test_edges.py` (10) | unknown challenge; challenge for another device; tenant mismatch; not-yet-published baseline; recovery below its floor; over-long chain and over-long baseline; stale-generation credential; orphan credential; writer lock timeout → `TIMEOUT` |
| `tests/test_cases.py` (4) | the committed `cases.json` replays clean, is byte-reproducible from `tools/build_cases.py`, and every expected code is documented |
| `tests/test_cli.py` (4) | `python -m solution --input … --output …` exits 0 and writes the full report; a deliberately failing expectation exits 1 with details; `--db/--request` one-shot mode |

Measured on this machine (Python 3.12.8, SQLite 3.45.3, Windows 11
10.0.26200), consecutive full runs of this build:

```
Ran 85 tests in 14.643s   OK
Ran 85 tests in 14.323s   OK
Ran 85 tests in 14.316s   OK
```

`cases.json` replay — `python -m solution --input cases.json --output result.json`:

```
cases 20/20 passed, steps 169/169 passed        (exit code 0, ~1.1 s)
```

The same replay with `--isolated` (phase-A verification in a spawned process
per proof) gives an identical step-by-step report, `cases 20/20 passed,
steps 169/169 passed`.

## 8. Known scope limits

* Two *different* qualifying proofs (different request ids, different
  challenges) are serialised by the write lock; the second one fails on the
  counter watermark (or the challenge), which is the required behaviour.
  There is no fairness guarantee about *which* contender wins.  Two copies of
  the *same* request id are not a race at all: they converge on one commit and
  one identical answer.
* `at` / `observed_at` are supplied by the caller (there is no clock); they are
  constrained by the challenge window, and the baseline's *current* state is
  always authoritative at commit.
* Keys are synthetic and derivable; do not reuse any of this for real
  attestation.
