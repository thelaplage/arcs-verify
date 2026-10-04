"""Independent sequence-level verifier for governed memory read sequences.

This module recomputes structural, linkage, digest-continuity, and replay
findings for a governed memory read sequence from serialized artifacts.
A governed memory sequence consists of: a memory_read_request, an
authorization_decision, a context_packet, and optionally source descriptors,
exclusion declarations, and replay evidence.

Authority boundaries
--------------------
- This verifier operates on *serialized bytes only* (deserialized from JSON).
  It does not import arcs_amnesiac or any other producer code.
- Findings are independently recomputed from the supplied artifact bundle.
  They are not emitter assertions.
- Integrity does not prove source truth, completeness of the external world,
  or policy correctness.
- Packet digest match does not prove the same real-world memory read.
- authorization_decision.disposition == authorized does not make the read
  compliant. This verifier does not assert compliance.
- Unknown external source state is NOT converted to failure or success.
- Source descriptor references are verified for presence and linkage; the
  referenced sources are not retrieved.
- NOT_EVALUATED is not PASS. not_applicable is not PASS.

Independent findings produced
-----------------------------
- request_present: A memory_read_request artifact is present and structurally
  conformant (required identity fields non-empty).
- decision_present: An authorization_decision artifact is present and
  structurally conformant.
- packet_present: A context_packet artifact is present and structurally
  conformant.
- request_decision_linkage: The authorization_decision references the
  memory_read_request by request_id.
- decision_packet_linkage: The context_packet references the
  authorization_decision by decision_id.
- subject_continuity: The subject_ref is consistent across request,
  decision, and packet.
- scope_continuity: The scope_ref is consistent across request, decision,
  and packet where declared.
- source_descriptor_refs_present: All source_refs declared in the
  context_packet resolve to entries in the supplied source_descriptors list
  (when provided). Unknown external source state does not produce failure.
- exclusion_declarations_present: Artifact class exclusions declared in the
  packet match those declared in the request (where both are present).
- packet_digest_match: The packet_hash recorded in the authorization_decision
  matches the packet_hash in the context_packet (where both are present).
- replay_evidence_clean: No artifact_id appears more than once across the
  supplied artifacts.
- raw_content_posture_valid: No artifact carries known raw-content fields
  (prompt, transcript, tool_arguments, etc.).
- reopening_refs_valid: Any reopening_ref present in the context_packet
  resolves to a known artifact_id in the supplied set.
- stale_authorization_declared: Whether the authorization_decision bears a
  not_after field that is declared (informational; does not gate passed).
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

SEQUENCE_SCHEMA = "arcs_verify.governed_memory_sequence_report.v0_1"
SEQUENCE_PROFILE = "arcs_verify.governed_memory_sequence.v0_1"

# Raw-content field names that must not appear in any governed memory artifact.
# These parallel the arcs_verify.verifier RAW_KEY_RE sentinel keys and the
# arcs_amnesiac FORBIDDEN_RAW_CONTENT_FIELD_NAMES list — reproduced here
# independently so the verifier imports no producer code.
_FORBIDDEN_RAW_KEYS: frozenset[str] = frozenset({
    "body",
    "raw_body",
    "full_text",
    "page_content",
    "raw_document",
    "document_body",
    "html",
    "raw_html",
    "transcript",
    "prompt",
    "system_prompt",
    "model_output",
    "completion",
    "tool_arguments",
    "tool_args",
    "http_body",
    "headers",
    "request_headers",
    "response_headers",
    "credentials",
    "secret",
    "secrets",
    "password",
    "private_key",
    "api_key",
    "authorization_token",
    "local_path",
    "absolute_path",
    "prompt_text",
    "raw_payload",
    "raw_content",
    "raw_prompt",
    "raw_output",
    "raw_tool_arguments",
    "raw_tool_result",
    "result_body",
    "arguments",
})

SEQUENCE_LIMITATIONS: list[str] = [
    (
        "Integrity does not prove source truth. A structurally valid sequence "
        "does not establish that the external sources referenced in "
        "source_descriptor_refs existed, were accessible, or returned the "
        "declared content at the time of the read."
    ),
    (
        "Integrity does not prove completeness of the external world. The "
        "verifier cannot determine whether additional records existed in the "
        "source that were not included in the context_packet."
    ),
    (
        "Integrity does not prove policy correctness. A structurally valid "
        "sequence may not satisfy the governing policy pack. This verifier "
        "does not assert compliance."
    ),
    (
        "authorization_decision.disposition == authorized does not make the "
        "read compliant. This verifier does not assert compliance or "
        "admissibility."
    ),
    (
        "packet_digest_match does not prove the same real-world memory read. "
        "The digest covers declared identity material at the time of "
        "issuance. A different read may produce an identical digest."
    ),
    (
        "Unknown external source state is NOT converted to failure or "
        "success. source_descriptor_refs are checked for structural presence "
        "and linkage; the referenced sources are not retrieved."
    ),
    (
        "stale_authorization_declared is informational only. A declared "
        "not_after on the authorization_decision is not independently "
        "verified against wall-clock time by this verifier."
    ),
    (
        "NOT_EVALUATED is not PASS. not_applicable is not PASS."
    ),
]


class Conclusion(str, Enum):
    TRUE = "true"
    FALSE = "false"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class SequenceFinding:
    code: str
    detail: str


@dataclass(slots=True)
class GovernedMemorySequenceReport:
    """Independent findings for a governed memory read sequence.

    No single master status replaces findings. ``passed`` requires all
    structural linkage findings to be TRUE.
    """

    # Presence findings
    request_present: Conclusion = Conclusion.NOT_EVALUATED
    decision_present: Conclusion = Conclusion.NOT_EVALUATED
    packet_present: Conclusion = Conclusion.NOT_EVALUATED

    # Linkage findings
    request_decision_linkage: Conclusion = Conclusion.NOT_EVALUATED
    decision_packet_linkage: Conclusion = Conclusion.NOT_EVALUATED

    # Continuity findings
    subject_continuity: Conclusion = Conclusion.NOT_EVALUATED
    scope_continuity: Conclusion = Conclusion.NOT_EVALUATED

    # Content integrity findings
    source_descriptor_refs_present: Conclusion = Conclusion.NOT_EVALUATED
    exclusion_declarations_present: Conclusion = Conclusion.NOT_EVALUATED
    packet_digest_match: Conclusion = Conclusion.NOT_EVALUATED
    replay_evidence_clean: Conclusion = Conclusion.NOT_EVALUATED
    raw_content_posture_valid: Conclusion = Conclusion.NOT_EVALUATED
    reopening_refs_valid: Conclusion = Conclusion.NOT_EVALUATED

    # Informational (does not gate passed)
    stale_authorization_declared: Conclusion = Conclusion.NOT_EVALUATED

    findings: list[SequenceFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        # Core structural findings must be TRUE.
        # source_descriptor_refs_present and packet_digest_match are
        # NOT_EVALUATED when the corresponding inputs are absent (unknown
        # external source state / no packet_hash in decision). Per the
        # acceptance gate: unknown external source state is NOT converted
        # to failure or success. NOT_EVALUATED findings do not gate passed;
        # only FALSE does.
        def _gates(c: Conclusion) -> bool:
            # TRUE passes; NOT_EVALUATED is neutral (not a failure, not a
            # pass assertion); FALSE fails.
            return c is not Conclusion.FALSE

        return (
            self.request_present is Conclusion.TRUE
            and self.decision_present is Conclusion.TRUE
            and self.packet_present is Conclusion.TRUE
            and self.request_decision_linkage is Conclusion.TRUE
            and self.decision_packet_linkage is Conclusion.TRUE
            and self.subject_continuity is Conclusion.TRUE
            and self.scope_continuity is Conclusion.TRUE
            and _gates(self.source_descriptor_refs_present)
            and _gates(self.exclusion_declarations_present)
            and _gates(self.packet_digest_match)
            and self.replay_evidence_clean is Conclusion.TRUE
            and self.raw_content_posture_valid is Conclusion.TRUE
            and self.reopening_refs_valid is Conclusion.TRUE
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SEQUENCE_SCHEMA,
            "verification_profile": SEQUENCE_PROFILE,
            "findings": [
                {"code": f.code, "detail": f.detail}
                for f in self.findings
            ],
            "conclusions": {
                "request_present": self.request_present.value,
                "decision_present": self.decision_present.value,
                "packet_present": self.packet_present.value,
                "request_decision_linkage": self.request_decision_linkage.value,
                "decision_packet_linkage": self.decision_packet_linkage.value,
                "subject_continuity": self.subject_continuity.value,
                "scope_continuity": self.scope_continuity.value,
                "source_descriptor_refs_present": (
                    self.source_descriptor_refs_present.value
                ),
                "exclusion_declarations_present": (
                    self.exclusion_declarations_present.value
                ),
                "packet_digest_match": self.packet_digest_match.value,
                "replay_evidence_clean": self.replay_evidence_clean.value,
                "raw_content_posture_valid": self.raw_content_posture_valid.value,
                "reopening_refs_valid": self.reopening_refs_valid.value,
                # Informational — does not gate passed
                "stale_authorization_declared": (
                    self.stale_authorization_declared.value
                ),
            },
            "passed": self.passed,
            "limitations": SEQUENCE_LIMITATIONS,
        }


def _fail(
    report: GovernedMemorySequenceReport,
    code: str,
    detail: str,
) -> None:
    report.findings.append(SequenceFinding(code=code, detail=detail))


def _all_keys(value: Any) -> list[str]:
    """Recursively collect all string dict keys in a nested structure."""
    keys: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            keys.append(str(k))
            keys.extend(_all_keys(v))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_all_keys(item))
    return keys


def _recompute_packet_hash(packet: dict[str, Any]) -> str | None:
    """Recompute a sha256 hash over the canonical-JSON of the packet's
    identity fields, excluding packet_id and created_at (which are mutable
    provenance fields per the ContextPacket identity rule).

    The identity payload must be stable: sort_keys=True, separators no-space.
    If packet_hash is already a 'sha256:' prefixed string, recompute it from
    the same payload structure used at emission time — this is the verifier's
    independent recomputation path.

    Returns the hex digest string (without prefix) or None if the packet
    structure is insufficient.
    """
    # Identity fields: all top-level keys except packet_id, created_at,
    # and packet_hash itself (which is the output). This mirrors the
    # ContextPacket.compute_packet_hash() structural contract.
    excluded = {"packet_id", "created_at", "packet_hash"}
    identity: dict[str, Any] = {
        k: v for k, v in packet.items() if k not in excluded
    }
    if not identity:
        return None
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _check_raw_content(
    artifact: dict[str, Any],
    *,
    artifact_kind: str,
    artifact_id: str,
) -> list[str]:
    """Return list of failure messages for any raw-content keys found."""
    failures: list[str] = []
    all_keys = _all_keys(artifact)
    for key in all_keys:
        if key.lower() in _FORBIDDEN_RAW_KEYS:
            failures.append(
                f"{artifact_kind} (id={artifact_id!r}) "
                f"carries forbidden raw-content key: {key!r}"
            )
    return failures


def verify_governed_memory_sequence(
    bundle: dict[str, Any],
) -> GovernedMemorySequenceReport:
    """Independently verify a governed memory read sequence from a bundle.

    The bundle must contain the following top-level keys:

    Required:
        memory_read_request (dict): The request artifact.
        authorization_decision (dict): The authorization decision artifact.
        context_packet (dict): The resulting context packet artifact.

    Optional:
        source_descriptors (list[dict]): Descriptor artifacts for each source
            referenced in the context_packet. Unknown external source state is
            NOT converted to failure if this key is absent.
        exclusion_declarations (list[str]): Artifact classes declared excluded.
            Used for cross-checking against the packet's declared exclusions.
        replay_evidence (dict): Replay evidence artifact, if present.

    Parameters
    ----------
    bundle:
        Dict with the above structure, deserialized from JSON bytes.
        No producer code is imported; the verifier reads only serialized fields.
    """
    report = GovernedMemorySequenceReport()

    if not isinstance(bundle, dict):
        _fail(report, "bundle_not_a_dict", "bundle must be a JSON object")
        report.request_present = Conclusion.FALSE
        report.decision_present = Conclusion.FALSE
        report.packet_present = Conclusion.FALSE
        report.request_decision_linkage = Conclusion.FALSE
        report.decision_packet_linkage = Conclusion.FALSE
        report.subject_continuity = Conclusion.FALSE
        report.scope_continuity = Conclusion.FALSE
        report.source_descriptor_refs_present = Conclusion.FALSE
        report.exclusion_declarations_present = Conclusion.FALSE
        report.packet_digest_match = Conclusion.FALSE
        report.replay_evidence_clean = Conclusion.FALSE
        report.raw_content_posture_valid = Conclusion.FALSE
        report.reopening_refs_valid = Conclusion.FALSE
        report.stale_authorization_declared = Conclusion.FALSE
        return report

    request = bundle.get("memory_read_request")
    decision = bundle.get("authorization_decision")
    packet = bundle.get("context_packet")
    source_descriptors = bundle.get("source_descriptors")
    exclusion_declarations = bundle.get("exclusion_declarations")
    replay_evidence = bundle.get("replay_evidence")

    # --- request_present ---
    if not isinstance(request, dict):
        _fail(
            report,
            "memory_read_request_absent",
            "bundle.memory_read_request must be a non-null JSON object",
        )
        report.request_present = Conclusion.FALSE
    else:
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            _fail(
                report,
                "request_missing_request_id",
                "memory_read_request.request_id is required and must be non-empty",
            )
            report.request_present = Conclusion.FALSE
        elif not isinstance(request.get("subject_ref"), str) or not request.get("subject_ref"):
            _fail(
                report,
                "request_missing_subject_ref",
                "memory_read_request.subject_ref is required and must be non-empty",
            )
            report.request_present = Conclusion.FALSE
        else:
            report.request_present = Conclusion.TRUE

    # --- decision_present ---
    if not isinstance(decision, dict):
        _fail(
            report,
            "authorization_decision_absent",
            "bundle.authorization_decision must be a non-null JSON object",
        )
        report.decision_present = Conclusion.FALSE
    else:
        decision_id = decision.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            _fail(
                report,
                "decision_missing_decision_id",
                "authorization_decision.decision_id is required and must be non-empty",
            )
            report.decision_present = Conclusion.FALSE
        elif not isinstance(decision.get("disposition"), str) or not decision.get("disposition"):
            _fail(
                report,
                "decision_missing_disposition",
                "authorization_decision.disposition is required and must be non-empty",
            )
            report.decision_present = Conclusion.FALSE
        else:
            report.decision_present = Conclusion.TRUE

    # --- packet_present ---
    if not isinstance(packet, dict):
        _fail(
            report,
            "context_packet_absent",
            "bundle.context_packet must be a non-null JSON object",
        )
        report.packet_present = Conclusion.FALSE
    else:
        packet_id = packet.get("packet_id")
        if not isinstance(packet_id, str) or not packet_id:
            _fail(
                report,
                "packet_missing_packet_id",
                "context_packet.packet_id is required and must be non-empty",
            )
            report.packet_present = Conclusion.FALSE
        elif not isinstance(packet.get("packet_hash"), str) or not packet.get("packet_hash"):
            _fail(
                report,
                "packet_missing_packet_hash",
                "context_packet.packet_hash is required and must be non-empty",
            )
            report.packet_present = Conclusion.FALSE
        else:
            report.packet_present = Conclusion.TRUE

    # If any core artifact is absent, mark dependent findings FALSE and return
    if (
        report.request_present is not Conclusion.TRUE
        or report.decision_present is not Conclusion.TRUE
        or report.packet_present is not Conclusion.TRUE
    ):
        for attr in (
            "request_decision_linkage",
            "decision_packet_linkage",
            "subject_continuity",
            "scope_continuity",
            "source_descriptor_refs_present",
            "exclusion_declarations_present",
            "packet_digest_match",
            "replay_evidence_clean",
            "raw_content_posture_valid",
            "reopening_refs_valid",
            "stale_authorization_declared",
        ):
            if getattr(report, attr) is Conclusion.NOT_EVALUATED:
                setattr(report, attr, Conclusion.FALSE)
        return report

    # From here all three core artifacts are structurally present.
    request_id = request["request_id"]
    decision_id = decision["decision_id"]
    packet_id = packet["packet_id"]

    # --- replay_evidence_clean ---
    # Collect all artifact_id values across core artifacts and replay evidence
    seen_ids: set[str] = set()
    replay_ok = True

    def _check_replay(artifact_id: str, kind: str) -> None:
        nonlocal replay_ok
        if not isinstance(artifact_id, str) or not artifact_id:
            return
        if artifact_id in seen_ids:
            replay_ok = False
            _fail(
                report,
                "duplicate_artifact_id",
                f"{kind} artifact_id={artifact_id!r} appears more than once",
            )
        else:
            seen_ids.add(artifact_id)

    _check_replay(request_id, "memory_read_request")
    _check_replay(decision_id, "authorization_decision")
    _check_replay(packet_id, "context_packet")
    if isinstance(replay_evidence, dict):
        replay_id = replay_evidence.get("replay_id") or replay_evidence.get("artifact_id", "")
        _check_replay(str(replay_id) if replay_id else "", "replay_evidence")

    report.replay_evidence_clean = Conclusion.TRUE if replay_ok else Conclusion.FALSE

    # --- request_decision_linkage ---
    # The authorization_decision must reference the memory_read_request by request_id
    decision_request_ref = decision.get("request_ref") or decision.get("request_id_ref")
    if not isinstance(decision_request_ref, str) or not decision_request_ref:
        _fail(
            report,
            "decision_missing_request_ref",
            (
                "authorization_decision has no request_ref linking it to the "
                "memory_read_request"
            ),
        )
        report.request_decision_linkage = Conclusion.FALSE
    elif decision_request_ref != request_id:
        _fail(
            report,
            "decision_request_ref_mismatch",
            (
                f"authorization_decision.request_ref={decision_request_ref!r} "
                f"does not match memory_read_request.request_id={request_id!r}"
            ),
        )
        report.request_decision_linkage = Conclusion.FALSE
    else:
        report.request_decision_linkage = Conclusion.TRUE

    # --- decision_packet_linkage ---
    # The context_packet must reference the authorization_decision by decision_id
    packet_decision_ref = packet.get("decision_ref") or packet.get("authorization_decision_ref")
    if not isinstance(packet_decision_ref, str) or not packet_decision_ref:
        _fail(
            report,
            "packet_missing_decision_ref",
            (
                "context_packet has no decision_ref linking it to the "
                "authorization_decision"
            ),
        )
        report.decision_packet_linkage = Conclusion.FALSE
    elif packet_decision_ref != decision_id:
        _fail(
            report,
            "packet_decision_ref_mismatch",
            (
                f"context_packet.decision_ref={packet_decision_ref!r} "
                f"does not match authorization_decision.decision_id={decision_id!r}"
            ),
        )
        report.decision_packet_linkage = Conclusion.FALSE
    else:
        report.decision_packet_linkage = Conclusion.TRUE

    # --- subject_continuity ---
    # subject_ref must be consistent across request, decision, and packet
    request_subject = request.get("subject_ref", "")
    decision_subject = decision.get("subject_ref", "")
    packet_subject = packet.get("subject_ref", "")

    subject_refs = {
        s for s in (request_subject, decision_subject, packet_subject)
        if isinstance(s, str) and s
    }
    if len(subject_refs) > 1:
        _fail(
            report,
            "subject_ref_discontinuity",
            (
                f"subject_ref is inconsistent across artifacts: "
                + ", ".join(f"{k}={v!r}" for k, v in (
                    ("request", request_subject),
                    ("decision", decision_subject),
                    ("packet", packet_subject),
                ))
            ),
        )
        report.subject_continuity = Conclusion.FALSE
    elif not subject_refs:
        _fail(
            report,
            "subject_ref_absent",
            "no non-empty subject_ref found across request, decision, or packet",
        )
        report.subject_continuity = Conclusion.FALSE
    else:
        report.subject_continuity = Conclusion.TRUE

    # --- scope_continuity ---
    # scope_ref is optional; where declared it must be consistent
    request_scope = request.get("scope_ref", "")
    decision_scope = decision.get("scope_ref", "")
    packet_scope = packet.get("scope_ref", "")

    declared_scopes = {
        s for s in (request_scope, decision_scope, packet_scope)
        if isinstance(s, str) and s
    }
    if len(declared_scopes) > 1:
        _fail(
            report,
            "scope_ref_discontinuity",
            (
                f"scope_ref is declared but inconsistent across artifacts: "
                + ", ".join(f"{k}={v!r}" for k, v in (
                    ("request", request_scope),
                    ("decision", decision_scope),
                    ("packet", packet_scope),
                ) if v)
            ),
        )
        report.scope_continuity = Conclusion.FALSE
    else:
        # Zero or one distinct scope — consistent (or not applicable)
        report.scope_continuity = Conclusion.TRUE

    # --- source_descriptor_refs_present ---
    # The context_packet may declare source_refs; when source_descriptors are
    # supplied in the bundle, each source_ref must resolve to a descriptor.
    # Unknown external source state is NOT converted to failure if
    # source_descriptors are not supplied.
    packet_source_refs: list[str] = []
    if isinstance(packet.get("source_refs"), list):
        packet_source_refs = [
            r for r in packet["source_refs"] if isinstance(r, str) and r
        ]
    # Also check evidence_manifest.source_refs
    evidence_manifest = packet.get("evidence_manifest") or {}
    if isinstance(evidence_manifest.get("source_refs"), list):
        for r in evidence_manifest["source_refs"]:
            if isinstance(r, str) and r and r not in packet_source_refs:
                packet_source_refs.append(r)

    if source_descriptors is None:
        # Unknown external source state — do not convert to failure or success
        report.source_descriptor_refs_present = Conclusion.NOT_EVALUATED
    elif not isinstance(source_descriptors, list):
        _fail(
            report,
            "source_descriptors_malformed",
            "bundle.source_descriptors must be a list when supplied",
        )
        report.source_descriptor_refs_present = Conclusion.FALSE
    else:
        # Build set of known source refs from descriptors
        descriptor_refs: set[str] = set()
        for desc in source_descriptors:
            if not isinstance(desc, dict):
                continue
            src_ref = desc.get("source_ref") or desc.get("canonical_public_ref") or ""
            if isinstance(src_ref, str) and src_ref:
                descriptor_refs.add(src_ref)

        missing_refs = [r for r in packet_source_refs if r not in descriptor_refs]
        if missing_refs:
            _fail(
                report,
                "source_descriptor_refs_unresolved",
                (
                    f"{len(missing_refs)} packet source_ref(s) not present in "
                    "supplied source_descriptors: "
                    + ", ".join(repr(r) for r in missing_refs[:5])
                    + (" ..." if len(missing_refs) > 5 else "")
                ),
            )
            report.source_descriptor_refs_present = Conclusion.FALSE
        else:
            report.source_descriptor_refs_present = Conclusion.TRUE

    # --- exclusion_declarations_present ---
    # Artifact class exclusions from the bundle's exclusion_declarations must
    # be consistent with those declared in the request (where both are present).
    request_exclusions: set[str] = set()
    if isinstance(request.get("artifact_classes_excluded"), list):
        request_exclusions = {
            str(e) for e in request["artifact_classes_excluded"]
            if isinstance(e, str) and e
        }

    if exclusion_declarations is None:
        # Not supplied — informational gap only, not a failure
        if request_exclusions:
            # Request has exclusions but no bundle-level declarations supplied
            report.exclusion_declarations_present = Conclusion.NOT_EVALUATED
        else:
            report.exclusion_declarations_present = Conclusion.TRUE
    elif not isinstance(exclusion_declarations, list):
        _fail(
            report,
            "exclusion_declarations_malformed",
            "bundle.exclusion_declarations must be a list when supplied",
        )
        report.exclusion_declarations_present = Conclusion.FALSE
    else:
        bundle_exclusions = {
            str(e) for e in exclusion_declarations
            if isinstance(e, str) and e
        }
        if request_exclusions and not request_exclusions.issubset(bundle_exclusions):
            missing_excl = request_exclusions - bundle_exclusions
            _fail(
                report,
                "exclusion_declarations_incomplete",
                (
                    "bundle.exclusion_declarations does not include all "
                    "artifact_classes_excluded from the memory_read_request: "
                    + ", ".join(sorted(missing_excl))
                ),
            )
            report.exclusion_declarations_present = Conclusion.FALSE
        else:
            report.exclusion_declarations_present = Conclusion.TRUE

    # --- packet_digest_match ---
    # The authorization_decision may carry a packet_hash; if present, it must
    # match the packet_hash in the context_packet.
    decision_packet_hash = decision.get("packet_hash")
    packet_packet_hash = packet.get("packet_hash")

    if decision_packet_hash is None:
        # Decision does not carry a packet_hash — not verifiable from the
        # decision side alone. This is not a structural failure.
        report.packet_digest_match = Conclusion.NOT_EVALUATED
    elif not isinstance(decision_packet_hash, str) or not decision_packet_hash:
        _fail(
            report,
            "decision_packet_hash_malformed",
            "authorization_decision.packet_hash is present but not a non-empty string",
        )
        report.packet_digest_match = Conclusion.FALSE
    elif decision_packet_hash != packet_packet_hash:
        _fail(
            report,
            "packet_digest_mismatch",
            (
                f"authorization_decision.packet_hash={decision_packet_hash!r} "
                f"does not match context_packet.packet_hash={packet_packet_hash!r}"
            ),
        )
        report.packet_digest_match = Conclusion.FALSE
    else:
        report.packet_digest_match = Conclusion.TRUE

    # --- raw_content_posture_valid ---
    # No artifact in the bundle may carry known raw-content keys.
    raw_ok = True
    for artifact, kind in (
        (request, "memory_read_request"),
        (decision, "authorization_decision"),
        (packet, "context_packet"),
    ):
        artifact_id = (
            artifact.get("request_id")
            or artifact.get("decision_id")
            or artifact.get("packet_id")
            or "unknown"
        )
        failures = _check_raw_content(artifact, artifact_kind=kind, artifact_id=artifact_id)
        for msg in failures:
            raw_ok = False
            _fail(report, "raw_content_posture_violation", msg)

    if isinstance(source_descriptors, list):
        for desc in source_descriptors:
            if isinstance(desc, dict):
                desc_id = desc.get("source_ref") or desc.get("artifact_id") or "unknown"
                failures = _check_raw_content(
                    desc, artifact_kind="source_descriptor", artifact_id=str(desc_id)
                )
                for msg in failures:
                    raw_ok = False
                    _fail(report, "raw_content_posture_violation", msg)

    if isinstance(replay_evidence, dict):
        replay_id = (
            replay_evidence.get("replay_id")
            or replay_evidence.get("artifact_id")
            or "unknown"
        )
        failures = _check_raw_content(
            replay_evidence, artifact_kind="replay_evidence", artifact_id=str(replay_id)
        )
        for msg in failures:
            raw_ok = False
            _fail(report, "raw_content_posture_violation", msg)

    report.raw_content_posture_valid = Conclusion.TRUE if raw_ok else Conclusion.FALSE

    # --- reopening_refs_valid ---
    # Any reopening_ref in the context_packet must resolve to a known artifact_id
    # in the supplied set (request_id, decision_id, or replay evidence id).
    known_ids: set[str] = {request_id, decision_id, packet_id}
    if isinstance(replay_evidence, dict):
        replay_id = (
            replay_evidence.get("replay_id")
            or replay_evidence.get("artifact_id")
        )
        if isinstance(replay_id, str) and replay_id:
            known_ids.add(replay_id)

    reopening_refs: list[str] = []
    if isinstance(packet.get("reopening_ref"), str) and packet["reopening_ref"]:
        reopening_refs.append(packet["reopening_ref"])
    if isinstance(packet.get("reopening_refs"), list):
        for r in packet["reopening_refs"]:
            if isinstance(r, str) and r:
                reopening_refs.append(r)

    reopen_ok = True
    for rref in reopening_refs:
        if rref not in known_ids:
            reopen_ok = False
            _fail(
                report,
                "reopening_ref_unresolved",
                (
                    f"context_packet.reopening_ref={rref!r} does not resolve to "
                    "a known artifact_id in the supplied sequence"
                ),
            )
    report.reopening_refs_valid = Conclusion.TRUE if reopen_ok else Conclusion.FALSE

    # --- stale_authorization_declared (informational) ---
    if isinstance(decision.get("not_after"), str) and decision["not_after"]:
        report.stale_authorization_declared = Conclusion.TRUE
    else:
        report.stale_authorization_declared = Conclusion.FALSE

    return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def build_parser() -> "argparse.ArgumentParser":
    import argparse

    parser = argparse.ArgumentParser(
        prog="arcs-verify governed-memory-sequence",
        description=(
            "Independently verify a governed memory read sequence. "
            "The bundle is a JSON object containing memory_read_request, "
            "authorization_decision, and context_packet artifacts."
        ),
    )
    parser.add_argument(
        "--bundle",
        type=Path,
        metavar="BUNDLE_JSON",
        help="Path to a JSON file containing the sequence bundle object.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit report as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    import argparse

    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    if args.bundle is None:
        sys.stderr.write("error: --bundle is required\n")
        return 2

    try:
        raw = json.loads(
            Path(args.bundle).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    if not isinstance(raw, dict):
        sys.stderr.write("error: bundle must be a JSON object\n")
        return 2

    report = verify_governed_memory_sequence(raw)
    data = report.to_dict()

    if args.as_json:
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"profile: {data['verification_profile']}")
        conclusions = data["conclusions"]
        for name, value in conclusions.items():
            print(f"{name}: {value.upper()}")
        print(f"passed: {str(data['passed']).lower()}")
        for finding in data["findings"]:
            print(f"finding: {finding['code']}: {finding['detail']}")

    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
