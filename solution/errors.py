"""Stable error codes for the offline boot-attestation audit service.

Every denial carries one of these codes.  The codes are part of the public
contract documented in README.md and asserted by the test-suite and by
``cases.json``.
"""

from __future__ import annotations

# code -> (human readable meaning, verification stage where it is normally raised)
ERROR_CODES: dict[str, str] = {
    "BAD_REQUEST": "Malformed or incomplete request / baseline document.",
    "UNKNOWN_DEVICE": "Device id is not registered.",
    "TENANT_MISMATCH": "Device is registered to a different tenant.",
    "GROUP_MISMATCH": "Attestation claims a device group the device is not registered to.",
    "GENERATION_MISMATCH": "Claimed device generation is not the current generation.",
    "DEVICE_GROUP_UNKNOWN": "Device group has no policy record.",
    "DEVICE_ID_CONFLICT": "Device id already exists with a different tenant/group.",
    "CHALLENGE_UNKNOWN": "Challenge id does not exist.",
    "CHALLENGE_CONFLICT": "Challenge id or (tenant, nonce) pair already exists.",
    "CHALLENGE_TENANT_MISMATCH": "Challenge belongs to a different tenant.",
    "CHALLENGE_DEVICE_MISMATCH": "Challenge was issued for a different device.",
    "CHALLENGE_GENERATION_MISMATCH": "Challenge was issued in a previous device generation.",
    "CHALLENGE_NOT_YET_VALID": "Verification time is before the challenge issue time.",
    "CHALLENGE_EXPIRED": "Verification time reached or passed the challenge expiry (half-open window).",
    "CHALLENGE_CONSUMED": "Challenge was already consumed by another request.",
    "BASELINE_UNKNOWN": "Baseline id does not exist.",
    "BASELINE_GROUP_MISMATCH": "Baseline belongs to a different device group.",
    "BASELINE_SIGNATURE_INVALID": "Baseline publisher signature does not verify.",
    "BASELINE_DOC_MISMATCH": "Stored baseline document digest does not match its content.",
    "BASELINE_NOT_PUBLISHED": "Baseline is not in the published state.",
    "BASELINE_REVOKED": "Baseline has been revoked.",
    "BASELINE_SUPERSEDED": "A newer published baseline exists for this group and kind.",
    "BASELINE_CONFLICT": "Baseline id/version conflict, or an attempt to publish an older version.",
    "RECOVERY_FLOOR_NOT_MET": "Recovery baseline version is below the group recovery minimum.",
    "TIMEOUT": "The request did not complete within the configured timeout.",
    "FULL_FLOOR_NOT_MET": "Full-privilege baseline version is below the group minimum.",
    "RECOVERY_SCOPE_DENIED": "A recovery baseline may only issue diagnostic-readonly credentials.",
    "RECOVERY_LOWERS_FULL_FLOOR": "Recovery baseline would lower the full-privilege minimum version.",
    "POLICY_NOT_MONOTONIC": "Group full-privilege minimum version may never decrease.",
    "WITNESS_SIGNATURE_INVALID": "Simulated device witness signature does not verify.",
    "CHAIN_EMPTY": "Measurement chain is empty.",
    "CHAIN_TOO_LONG": "Measurement chain exceeds the implementation limit.",
    "CHAIN_SEQ_GAP": "Measurement sequence numbers are not contiguous from zero.",
    "CHAIN_SEQ_DUPLICATE": "Measurement sequence number is duplicated.",
    "CHAIN_SEQ_ORDER": "Measurement entries are not ordered by sequence number.",
    "CHAIN_LINK_MISMATCH": "A measurement link digest does not equal SHA-256 over its inputs.",
    "CHAIN_ROOT_MISMATCH": "Declared chain root is not the final recomputed link digest.",
    "MISSING_MODULE": "A baseline-required module is not present in the chain.",
    "EXTRA_MODULE": "The chain contains a module outside the selected baseline.",
    "MODULE_POSITION_MISMATCH": "A module appears at a position not defined by the baseline.",
    "CRITICAL_MODULE_UNKNOWN": "A chain entry claims criticality the baseline does not define.",
    "DIGEST_MISMATCH": "A measured payload digest differs from the baseline-pinned digest.",
    "COUNTER_ROLLBACK": "Boot counter is not above the device's observed counter watermark.",
    "COUNTER_INVALID": "Boot counter is missing, negative, or not an integer.",
    "REQUEST_ID_CONFLICT": "Request id was already used with different request content.",
    "REQUEST_ID_INVALID": "Request id is empty or contains unsupported characters.",
    "CREDENTIAL_UNKNOWN": "Credential token is unknown.",
    "CREDENTIAL_REVOKED": "Credential was revoked (for example by a generation change).",
    "CREDENTIAL_GENERATION_STALE": "Credential belongs to a previous device generation.",
    "CREDENTIAL_DEVICE_UNKNOWN": "Credential refers to a device that no longer exists.",
    "INTERNAL": "Unexpected internal error.",
    "WORKER_FAILED": "Verification worker process failed or was killed.",
}


class Denial(Exception):
    """A rule-based refusal.  Carries a stable code and the checking stage."""

    def __init__(self, code: str, message: str | None = None, stage: str = "precheck", detail=None):
        if code not in ERROR_CODES:
            code = "INTERNAL"
        self.code = code
        self.message = message or ERROR_CODES[code]
        self.stage = stage
        self.detail = detail
        super().__init__(f"{code}: {self.message}")
