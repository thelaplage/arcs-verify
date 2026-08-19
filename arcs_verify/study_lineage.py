"""Independent integrity verifier for provider-neutral study/memory lineage.

This verifier reads serialized artifacts only.  It imports neither
``counterpedia-agent`` (the STUDY-CONTRACTS0 producer) nor ``countergraph``
(the MEMORY-IMPACT0 producer).

It verifies structural shape, producer pins, canonical manifest digest,
artifact->manifest linkage, and optional Countergraph impact->manifest/artifact
linkage.  It does not verify source truth, study completeness, model contents,
forgetting, causal reliance, authorization, or correctness of an impact state.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

REPORT_SCHEMA = "arcs_verify.study_lineage_report.v0_1"
REPORT_PROFILE = "arcs_verify.study_lineage.v0_1"
STUDY_MANIFEST_SCHEMA = "counterpedia.study_manifest/v0.1"
STUDY_ARTIFACT_SCHEMA = "counterpedia.study_artifact/v0.1"
MEMORY_IMPACT_SCHEMA = "countergraph.study-memory-impact/v0.1"

# Draft pins. These must be replaced with merged producer commits before merge.
STUDY_PRODUCER_REPO = "thelaplage/counterpedia-agent"
STUDY_PRODUCER_COMMIT = "04a9828475763ea88d159eb232e16ed350db991a"
IMPACT_PRODUCER_REPO = "thelaplage/countergraph"
IMPACT_PRODUCER_COMMIT = "a1ced197a533fb012c5d4d225c4e02f539b7318d"

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

LIMITATIONS = [
    "Manifest integrity does not prove source truth or claim standing.",
    "Artifact linkage does not prove that a provider actually learned or retained the declared inputs.",
    "Provider deletion or artifact replacement does not prove parametric forgetting.",
    "Impact linkage does not verify that an impact state is semantically correct.",
    "Recall observation is outside this profile and causal reliance is not inferred.",
    "Authorization and effective invocation authority are outside this profile.",
    "NOT_EVALUATED is not PASS.",
]


class Conclusion(str, Enum):
    TRUE = "true"
    FALSE = "false"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    detail: str


@dataclass(slots=True)
class StudyLineageReport:
    manifest_present: Conclusion = Conclusion.NOT_EVALUATED
    study_producer_pin_match: Conclusion = Conclusion.NOT_EVALUATED
    manifest_digest_match: Conclusion = Conclusion.NOT_EVALUATED
    artifact_present: Conclusion = Conclusion.NOT_EVALUATED
    artifact_manifest_linkage: Conclusion = Conclusion.NOT_EVALUATED
    artifact_addressability_valid: Conclusion = Conclusion.NOT_EVALUATED
    impact_present: Conclusion = Conclusion.NOT_EVALUATED
    impact_producer_pin_match: Conclusion = Conclusion.NOT_EVALUATED
    impact_manifest_linkage: Conclusion = Conclusion.NOT_EVALUATED
    impact_artifact_linkage: Conclusion = Conclusion.NOT_EVALUATED
    impact_digest_present: Conclusion = Conclusion.NOT_EVALUATED
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        required = (
            self.manifest_present,
            self.study_producer_pin_match,
            self.manifest_digest_match,
        )
        if any(value is Conclusion.FALSE for value in required):
            return False
        if not all(value is Conclusion.TRUE for value in required):
            return False
        optional = (
            self.artifact_present,
            self.artifact_manifest_linkage,
            self.artifact_addressability_valid,
            self.impact_present,
            self.impact_producer_pin_match,
            self.impact_manifest_linkage,
            self.impact_artifact_linkage,
            self.impact_digest_present,
        )
        return not any(value is Conclusion.FALSE for value in optional)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA,
            "verification_profile": REPORT_PROFILE,
            "conclusions": {
                "manifest_present": self.manifest_present.value,
                "study_producer_pin_match": self.study_producer_pin_match.value,
                "manifest_digest_match": self.manifest_digest_match.value,
                "artifact_present": self.artifact_present.value,
                "artifact_manifest_linkage": self.artifact_manifest_linkage.value,
                "artifact_addressability_valid": self.artifact_addressability_valid.value,
                "impact_present": self.impact_present.value,
                "impact_producer_pin_match": self.impact_producer_pin_match.value,
                "impact_manifest_linkage": self.impact_manifest_linkage.value,
                "impact_artifact_linkage": self.impact_artifact_linkage.value,
                "impact_digest_present": self.impact_digest_present.value,
            },
            "findings": [
                {"code": finding.code, "detail": finding.detail}
                for finding in self.findings
            ],
            "passed": self.passed,
            "limitations": LIMITATIONS,
        }


def _fail(report: StudyLineageReport, code: str, detail: str) -> None:
    report.findings.append(Finding(code=code, detail=detail))


def _sha(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def _manifest_digest(manifest: Mapping[str, Any]) -> str:
    body = dict(manifest)
    body.pop("manifest_digest", None)
    encoded = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _manifest_shape_valid(manifest: Mapping[str, Any]) -> tuple[bool, str]:
    expected = {
        "schema_version",
        "study_ref",
        "method_ref",
        "configuration_ref",
        "studied_at",
        "inputs",
        "scope_refs",
        "authority_movement",
        "manifest_digest",
    }
    if set(manifest) != expected:
        return False, "manifest field set mismatch"
    if manifest.get("schema_version") != STUDY_MANIFEST_SCHEMA:
        return False, "manifest schema mismatch"
    if manifest.get("authority_movement") != 0:
        return False, "manifest authority_movement must be 0"
    for key in ("study_ref", "method_ref", "configuration_ref", "studied_at"):
        if not isinstance(manifest.get(key), str) or not manifest.get(key):
            return False, f"manifest {key} must be non-empty string"
    inputs = manifest.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        return False, "manifest inputs must be non-empty array"
    seen: set[tuple[Any, ...]] = set()
    for raw in inputs:
        if not isinstance(raw, Mapping) or set(raw) != {"kind", "ref", "digest"}:
            return False, "manifest input field set mismatch"
        if not isinstance(raw.get("kind"), str) or not raw.get("kind"):
            return False, "manifest input kind missing"
        if not isinstance(raw.get("ref"), str) or not raw.get("ref"):
            return False, "manifest input ref missing"
        digest = raw.get("digest")
        if digest is not None and not _sha(digest):
            return False, "manifest input digest malformed"
        item = (raw.get("kind"), raw.get("ref"), digest)
        if item in seen:
            return False, "manifest duplicate input"
        seen.add(item)
    scopes = manifest.get("scope_refs")
    if not isinstance(scopes, list) or not all(isinstance(x, str) and x for x in scopes):
        return False, "manifest scope_refs malformed"
    if len(scopes) != len(set(scopes)):
        return False, "manifest duplicate scope_ref"
    if not _sha(manifest.get("manifest_digest")):
        return False, "manifest digest malformed"
    return True, "ok"


def verify_study_lineage(bundle: Mapping[str, Any]) -> StudyLineageReport:
    report = StudyLineageReport()
    if not isinstance(bundle, Mapping):
        _fail(report, "bundle_not_object", "bundle must be a JSON object")
        report.manifest_present = Conclusion.FALSE
        report.study_producer_pin_match = Conclusion.FALSE
        report.manifest_digest_match = Conclusion.FALSE
        return report

    manifest = bundle.get("study_manifest")
    artifact = bundle.get("study_artifact")
    impact = bundle.get("memory_impact")
    study_pin = bundle.get("study_producer")
    impact_pin = bundle.get("impact_producer")

    if not isinstance(manifest, Mapping):
        _fail(report, "manifest_absent", "study_manifest must be a JSON object")
        report.manifest_present = Conclusion.FALSE
        report.manifest_digest_match = Conclusion.FALSE
    else:
        valid, detail = _manifest_shape_valid(manifest)
        if not valid:
            _fail(report, "manifest_invalid", detail)
            report.manifest_present = Conclusion.FALSE
            report.manifest_digest_match = Conclusion.FALSE
        else:
            report.manifest_present = Conclusion.TRUE
            expected = _manifest_digest(manifest)
            if manifest.get("manifest_digest") == expected:
                report.manifest_digest_match = Conclusion.TRUE
            else:
                _fail(report, "manifest_digest_mismatch", "manifest digest does not recompute")
                report.manifest_digest_match = Conclusion.FALSE

    if not isinstance(study_pin, Mapping):
        _fail(report, "study_producer_pin_absent", "study_producer pin is required")
        report.study_producer_pin_match = Conclusion.FALSE
    elif (
        study_pin.get("repository") == STUDY_PRODUCER_REPO
        and study_pin.get("commit") == STUDY_PRODUCER_COMMIT
    ):
        report.study_producer_pin_match = Conclusion.TRUE
    else:
        _fail(report, "study_producer_pin_mismatch", "study producer repo/commit mismatch")
        report.study_producer_pin_match = Conclusion.FALSE

    if artifact is None:
        report.artifact_present = Conclusion.NOT_EVALUATED
        report.artifact_manifest_linkage = Conclusion.NOT_EVALUATED
        report.artifact_addressability_valid = Conclusion.NOT_EVALUATED
    elif not isinstance(artifact, Mapping):
        _fail(report, "artifact_invalid", "study_artifact must be a JSON object")
        report.artifact_present = Conclusion.FALSE
        report.artifact_manifest_linkage = Conclusion.FALSE
        report.artifact_addressability_valid = Conclusion.FALSE
    else:
        report.artifact_present = Conclusion.TRUE
        if artifact.get("schema_version") != STUDY_ARTIFACT_SCHEMA:
            _fail(report, "artifact_schema_mismatch", "study artifact schema mismatch")
            report.artifact_manifest_linkage = Conclusion.FALSE
        elif isinstance(manifest, Mapping) and artifact.get("manifest_digest") == manifest.get("manifest_digest"):
            report.artifact_manifest_linkage = Conclusion.TRUE
        elif isinstance(manifest, Mapping):
            _fail(report, "artifact_manifest_mismatch", "artifact manifest_digest does not bind to study_manifest")
            report.artifact_manifest_linkage = Conclusion.FALSE
        else:
            report.artifact_manifest_linkage = Conclusion.NOT_EVALUATED

        addressability = artifact.get("addressability")
        artifact_digest = artifact.get("artifact_digest")
        if addressability == "content_addressed" and _sha(artifact_digest):
            report.artifact_addressability_valid = Conclusion.TRUE
        elif addressability == "provider_addressed" and artifact_digest is None:
            report.artifact_addressability_valid = Conclusion.TRUE
        else:
            _fail(report, "artifact_addressability_invalid", "artifact addressability/digest posture is inconsistent")
            report.artifact_addressability_valid = Conclusion.FALSE

    if impact is None:
        report.impact_present = Conclusion.NOT_EVALUATED
        report.impact_producer_pin_match = Conclusion.NOT_EVALUATED
        report.impact_manifest_linkage = Conclusion.NOT_EVALUATED
        report.impact_artifact_linkage = Conclusion.NOT_EVALUATED
        report.impact_digest_present = Conclusion.NOT_EVALUATED
    elif not isinstance(impact, Mapping):
        _fail(report, "impact_invalid", "memory_impact must be a JSON object")
        report.impact_present = Conclusion.FALSE
        report.impact_producer_pin_match = Conclusion.FALSE
        report.impact_manifest_linkage = Conclusion.FALSE
        report.impact_artifact_linkage = Conclusion.FALSE
        report.impact_digest_present = Conclusion.FALSE
    else:
        report.impact_present = Conclusion.TRUE
        if impact.get("schema") != MEMORY_IMPACT_SCHEMA or impact.get("authority_effect") != "none":
            _fail(report, "impact_schema_or_authority_invalid", "memory impact schema/authority posture mismatch")
            report.impact_manifest_linkage = Conclusion.FALSE
        elif isinstance(manifest, Mapping) and impact.get("study_manifest_digest") == manifest.get("manifest_digest"):
            report.impact_manifest_linkage = Conclusion.TRUE
        elif isinstance(manifest, Mapping):
            _fail(report, "impact_manifest_mismatch", "impact does not bind to study manifest digest")
            report.impact_manifest_linkage = Conclusion.FALSE
        else:
            report.impact_manifest_linkage = Conclusion.NOT_EVALUATED

        if artifact is None:
            report.impact_artifact_linkage = Conclusion.NOT_EVALUATED
        elif isinstance(artifact, Mapping) and impact.get("study_artifact_ref") == artifact.get("artifact_ref"):
            report.impact_artifact_linkage = Conclusion.TRUE
        elif isinstance(artifact, Mapping):
            _fail(report, "impact_artifact_mismatch", "impact study_artifact_ref does not bind to artifact")
            report.impact_artifact_linkage = Conclusion.FALSE
        else:
            report.impact_artifact_linkage = Conclusion.NOT_EVALUATED

        if _sha(impact.get("impact_digest")):
            # Presence/shape only in v0.1: Countergraph uses its own canonical
            # serializer. Independent recomputation is a follow-up once that
            # exact wire canonicalization is frozen as a cross-repo contract.
            report.impact_digest_present = Conclusion.TRUE
        else:
            _fail(report, "impact_digest_missing", "impact_digest must be canonical sha256")
            report.impact_digest_present = Conclusion.FALSE

        if not isinstance(impact_pin, Mapping):
            _fail(report, "impact_producer_pin_absent", "impact_producer pin is required when impact is supplied")
            report.impact_producer_pin_match = Conclusion.FALSE
        elif (
            impact_pin.get("repository") == IMPACT_PRODUCER_REPO
            and impact_pin.get("commit") == IMPACT_PRODUCER_COMMIT
        ):
            report.impact_producer_pin_match = Conclusion.TRUE
        else:
            _fail(report, "impact_producer_pin_mismatch", "impact producer repo/commit mismatch")
            report.impact_producer_pin_match = Conclusion.FALSE

    return report


__all__ = [
    "Conclusion",
    "Finding",
    "IMPACT_PRODUCER_COMMIT",
    "IMPACT_PRODUCER_REPO",
    "LIMITATIONS",
    "REPORT_PROFILE",
    "REPORT_SCHEMA",
    "STUDY_PRODUCER_COMMIT",
    "STUDY_PRODUCER_REPO",
    "StudyLineageReport",
    "verify_study_lineage",
]
