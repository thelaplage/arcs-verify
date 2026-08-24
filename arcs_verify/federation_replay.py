"""
arcs_verify/federation_replay.py — FEDERATION-REPLAY0 (COUNTERPEDIA-FEDERATION-WAVE2,
Lane L02): independent offline replay verifier for a federation run's artifact set.

GOAL
  Independently replay/verify a complete federation run offline.
  replayable != valid != authorized != true != admitted.

INDEPENDENCE CONTRACT
  This module imports NOTHING from counterpedia-agent, counterpedia-registry,
  harness-prototypes, dagr-mcp, dagr-ingest, or any other producer repository.
  It recomputes digest bindings from the byte-level contract only, over bytes
  the caller supplies out-of-band.

SCHEMA AUTHORITY NOTE
  This module does not define or own the FederationRunEnvelope wire schema.
  That authority belongs to FEDERATION-RUN-ENVELOPE0 (counterpedia-agent,
  Lane L01 of COUNTERPEDIA-FEDERATION-WAVE2), which has not landed as of this
  lane (AUTHORITY_MOVEMENT=0, DRAFT). Pending that authority, this verifier
  operates against the minimal transport-neutral structural contract already
  implied by that lane's own goal ("indexing native refs/digests only"): an
  envelope carrying a run_id and a list of {kind, ref, digest} artifact rows.
  SCHEMA below is an internal identifier for this module's own report shape,
  not a cross-repo pin. When FEDERATION-RUN-ENVELOPE0 lands, this verifier
  should be re-pinned against its authoritative envelope bytes, and this note
  removed.

WHAT THIS VERIFIER CHECKS (digest-binding replay only)
  For every artifact row the envelope declares, and for which the caller
  supplied literal bytes: the recomputed sha256 of those bytes against the
  row's declared digest. Nothing more.

WHAT THIS VERIFIER DOES NOT CHECK (non-goals)
  - Whether the artifact bytes are authentic, admitted, or were actually
    produced by the node the envelope claims produced them.
  - Whether the federation run itself was authorized, trusted, or occurred.
  - Cross-node identity crosswalks (SAM peer / Counterpedia node /
    organization / SRS issuer identity) — that is FEDERATION-IDENTITY0's
    concern, not this verifier's.
  - SRS envelope signature/issuer verification of individual artifacts — use
    the SRS-specific verifiers (arcs_verify.verifier, arcs_verify.universal)
    for that; this module only replays federation-run-level digest bindings.
  - Any semantic claim carried inside a replayed artifact.

VERIFICATION VOCABULARY (permanent non-equivalences)
  replayable != valid
  replayable != authorized
  replayable != true
  replayable != admitted
  digest match != authenticity
  a run with zero replayed artifact rows is NOT_EVALUATED, never PASS
  authority_effect is always "none" — this verifier confers no authority
  truth_verified is always "not_evaluated" — a digest match does not
    establish that the underlying federation exchange occurred

REQUIRED INVARIANT — replay verification never silently applies
  Every artifact row resolves to exactly one of:
    PASS           bytes were supplied and the recomputed digest matches
    FAIL           bytes were supplied and the digest does not match, or the
                   row itself is structurally malformed (missing ref,
                   malformed digest, non-bytes payload)
    NOT_EVALUATED  bytes were not supplied for that ref
  NOT_EVALUATED never collapses into PASS, at the row level or the run
  level: the run-level status is NOT_EVALUATED whenever at least one row is
  NOT_EVALUATED and none is FAIL, and it is NOT_EVALUATED — never PASS —
  when there are no rows to replay at all (a vacuous run is not a verified
  run).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

SCHEMA = "arcs_verify.federation_replay_report.v0_1"

PASS = "PASS"
FAIL = "FAIL"
NOT_EVALUATED = "NOT_EVALUATED"

_SHA256_PREFIX = "sha256:"
_SHA256_TOTAL_LEN = 71  # len("sha256:") + 64

# Always present, regardless of replay outcome. These are the epistemic
# guards this verifier's goal statement names; they are not conditional on
# any finding.
_PERMANENT_NON_EQUIVALENCES: tuple[str, ...] = (
    "replayable != valid",
    "replayable != authorized",
    "replayable != true",
    "replayable != admitted",
    "digest match != authenticity",
    "authority_effect:none is a hard constant, not a posture",
)


def sha256_bytes(data: bytes) -> str:
    """sha256 digest of ``data``, formatted as ``sha256:<64 lowercase hex>``."""
    return _SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != _SHA256_TOTAL_LEN:
        return False
    if not value.startswith(_SHA256_PREFIX):
        return False
    body = value[len(_SHA256_PREFIX):]
    if body != body.lower():
        return False
    try:
        int(body, 16)
    except ValueError:
        return False
    return True


# ── result dataclasses ──────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class ArtifactReplayCheck:
    """One artifact row's independent replay outcome."""

    ref: str
    kind: str
    status: str  # PASS | FAIL | NOT_EVALUATED
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "kind": self.kind,
            "status": self.status,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class FederationReplayReport:
    """Independent offline-replay findings for one federation run envelope.

    authority_effect is always "none" on every code path: a successful
    replay never confers authority, admission, or trust. truth_verified is
    always "not_evaluated": a digest match does not establish that the
    underlying federation exchange occurred or that its content is true.
    """

    run_id: str
    checks: tuple[ArtifactReplayCheck, ...]
    overall_status: str  # PASS | FAIL | NOT_EVALUATED
    artifacts_total: int
    artifacts_passed: int
    artifacts_failed: int
    artifacts_not_evaluated: int
    authority_effect: str = "none"
    truth_verified: str = "not_evaluated"
    non_equivalences: tuple[str, ...] = _PERMANENT_NON_EQUIVALENCES
    failure_code: str | None = None
    failure_detail: str | None = None
    schema_version: str = SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "checks": [c.to_dict() for c in self.checks],
            "overall_status": self.overall_status,
            "artifacts_total": self.artifacts_total,
            "artifacts_passed": self.artifacts_passed,
            "artifacts_failed": self.artifacts_failed,
            "artifacts_not_evaluated": self.artifacts_not_evaluated,
            "authority_effect": self.authority_effect,
            "truth_verified": self.truth_verified,
            "non_equivalences": list(self.non_equivalences),
            "failure_code": self.failure_code,
            "failure_detail": self.failure_detail,
            "schema_version": self.schema_version,
        }


def _fail(run_id: str, code: str, detail: str) -> FederationReplayReport:
    """Return a structurally-failed report. No rows were replayed."""
    return FederationReplayReport(
        run_id=run_id,
        checks=(),
        overall_status=FAIL,
        artifacts_total=0,
        artifacts_passed=0,
        artifacts_failed=0,
        artifacts_not_evaluated=0,
        failure_code=code,
        failure_detail=detail,
    )


# ── public entry point ───────────────────────────────────────────────────────

def replay_federation_run(
    envelope: Mapping[str, Any],
    artifact_bytes: Mapping[str, bytes],
) -> FederationReplayReport:
    """Independently replay a federation run's artifact digest bindings offline.

    Args:
        envelope: a mapping with ``run_id`` (non-empty str) and ``artifacts``
            (a list of ``{"kind": str, "ref": str, "digest": "sha256:<hex>"}``
            rows). Any other fields on the envelope, including a schema/
            version discriminator, are ignored — this verifier does not
            interpret or own that authority (see module docstring "SCHEMA
            AUTHORITY NOTE").
        artifact_bytes: a mapping from artifact ``ref`` to the literal
            producer bytes for that artifact, supplied by the caller
            out-of-band (e.g. read from local disk after an offline
            transport, never fetched by this verifier). A ref absent from
            this mapping is NOT_EVALUATED, never FAIL — an unavailable input
            is not a validation failure.

    Returns:
        A FederationReplayReport. ``authority_effect`` is always "none" and
        ``truth_verified`` is always "not_evaluated", on every code path,
        including structural failure.
    """
    if not isinstance(envelope, Mapping):
        return _fail("", "invalid_envelope", "envelope must be a mapping")

    run_id = envelope.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        return _fail(
            "", "missing_run_id", 'envelope["run_id"] is absent, empty, or not a string'
        )

    if not isinstance(artifact_bytes, Mapping):
        return _fail(
            run_id, "invalid_artifact_bytes", "artifact_bytes must be a mapping"
        )

    rows = envelope.get("artifacts")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        return _fail(
            run_id,
            "invalid_artifacts_field",
            'envelope["artifacts"] is absent or not a list',
        )

    checks: list[ArtifactReplayCheck] = []
    for row in rows:
        if not isinstance(row, Mapping):
            checks.append(
                ArtifactReplayCheck("", "unknown", FAIL, "artifact row is not a mapping")
            )
            continue

        kind = str(row.get("kind", ""))
        ref = row.get("ref")

        if not isinstance(ref, str) or not ref:
            checks.append(
                ArtifactReplayCheck("", kind, FAIL, "artifact row is missing a usable ref")
            )
            continue

        declared_digest = row.get("digest")
        if not _is_sha256(declared_digest):
            checks.append(
                ArtifactReplayCheck(
                    ref, kind, FAIL, "declared digest is absent or malformed"
                )
            )
            continue

        if ref not in artifact_bytes:
            checks.append(
                ArtifactReplayCheck(ref, kind, NOT_EVALUATED, "artifact bytes unavailable")
            )
            continue

        raw = artifact_bytes[ref]
        if not isinstance(raw, (bytes, bytearray)):
            checks.append(
                ArtifactReplayCheck(
                    ref, kind, FAIL, "supplied artifact bytes are not raw bytes"
                )
            )
            continue

        actual_digest = sha256_bytes(bytes(raw))
        if actual_digest == declared_digest:
            checks.append(ArtifactReplayCheck(ref, kind, PASS, ""))
        else:
            checks.append(ArtifactReplayCheck(ref, kind, FAIL, "digest mismatch"))

    total = len(checks)
    passed = sum(1 for c in checks if c.status == PASS)
    failed = sum(1 for c in checks if c.status == FAIL)
    not_evaluated = sum(1 for c in checks if c.status == NOT_EVALUATED)

    if total == 0:
        # A run that names zero artifacts replays nothing. That is not the
        # same as a run that replayed cleanly — never claim PASS for a
        # vacuous run.
        overall = NOT_EVALUATED
    elif failed > 0:
        overall = FAIL
    elif not_evaluated > 0:
        overall = NOT_EVALUATED
    else:
        overall = PASS

    return FederationReplayReport(
        run_id=run_id,
        checks=tuple(checks),
        overall_status=overall,
        artifacts_total=total,
        artifacts_passed=passed,
        artifacts_failed=failed,
        artifacts_not_evaluated=not_evaluated,
    )
