"""Independent verifier for Counterplayer's landed persistent-study artifacts.

Reads serialized artifacts only.  Does not import Counterplayer.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

REPORT_SCHEMA = "arcs_verify.counterplayer_study_report.v0_1"
REPORT_PROFILE = "arcs_verify.counterplayer_study.v0_1"
COUNTERPLAYER_REPO = "thelaplage/counterplayer"
COUNTERPLAYER_PIN = "13bfb93da886c209799da1610a4905729453888a"
STUDY_ARTIFACT_SCHEMA = "counterplayer.study-artifact-manifest/v0.1"
STUDY_IMPACT_SCHEMA = "counterplayer.study-impact/v0.1"
RESEARCH_EVENTS_SCHEMA = "research-events0.v0.1"
IMPACT_CLASSIFICATIONS = {
    "UNAFFECTED",
    "DIRECTLY_AFFECTED",
    "TRANSITIVELY_AFFECTED",
    "UNKNOWN",
}
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_STUDY_REF = re.compile(r"^study:sha256:[0-9a-f]{64}$")

LIMITATIONS = [
    "Integrity does not prove source truth, currentness, admission, or standing.",
    "A valid StudyArtifactManifest does not prove a provider actually learned or retained its declared dependencies.",
    "StudyImpact integrity does not prove the semantic correctness of its impact classification.",
    "RecallEvent integrity does not make recalled material evidence and does not establish causal reliance.",
    "Artifact replacement or provider deletion does not prove parametric forgetting.",
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
class CounterplayerStudyReport:
    producer_pin_match: Conclusion = Conclusion.NOT_EVALUATED
    manifest_present: Conclusion = Conclusion.NOT_EVALUATED
    manifest_digest_match: Conclusion = Conclusion.NOT_EVALUATED
    manifest_identity_match: Conclusion = Conclusion.NOT_EVALUATED
    impact_present: Conclusion = Conclusion.NOT_EVALUATED
    impact_digest_match: Conclusion = Conclusion.NOT_EVALUATED
    impact_manifest_linkage: Conclusion = Conclusion.NOT_EVALUATED
    recall_present: Conclusion = Conclusion.NOT_EVALUATED
    recall_digest_match: Conclusion = Conclusion.NOT_EVALUATED
    recall_artifact_linkage: Conclusion = Conclusion.NOT_EVALUATED
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        mandatory = (
            self.producer_pin_match,
            self.manifest_present,
            self.manifest_digest_match,
            self.manifest_identity_match,
        )
        if not all(item is Conclusion.TRUE for item in mandatory):
            return False
        optional = (
            self.impact_present,
            self.impact_digest_match,
            self.impact_manifest_linkage,
            self.recall_present,
            self.recall_digest_match,
            self.recall_artifact_linkage,
        )
        return not any(item is Conclusion.FALSE for item in optional)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA,
            "verification_profile": REPORT_PROFILE,
            "producer": {"repository": COUNTERPLAYER_REPO, "commit": COUNTERPLAYER_PIN},
            "conclusions": {
                name: getattr(self, name).value
                for name in (
                    "producer_pin_match",
                    "manifest_present",
                    "manifest_digest_match",
                    "manifest_identity_match",
                    "impact_present",
                    "impact_digest_match",
                    "impact_manifest_linkage",
                    "recall_present",
                    "recall_digest_match",
                    "recall_artifact_linkage",
                )
            },
            "findings": [{"code": item.code, "detail": item.detail} for item in self.findings],
            "passed": self.passed,
            "limitations": LIMITATIONS,
        }


def _fail(report: CounterplayerStudyReport, code: str, detail: str) -> None:
    report.findings.append(Finding(code=code, detail=detail))


def _nfc(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {key: _nfc(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_nfc(child) for child in value]
    if isinstance(value, float):
        raise ValueError("Counterplayer canonical subset does not support floats")
    return value


def _jcs(value: Any) -> bytes:
    return json.dumps(
        _nfc(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_jcs(value)).hexdigest()


def _manifest_payload(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": document["schema"],
        "study_artifact_ref": document["study_artifact_ref"],
        "artifact_kind": document["artifact_kind"],
        "artifact_digest": document["artifact_digest"],
        "producer": document["producer"],
        "base_model": document["base_model"],
        "study_recipe_ref": document["study_recipe_ref"],
        "study_recipe_digest": document["study_recipe_digest"],
        "created_at": document["created_at"],
        "limitations": document["limitations"],
        "dependency_coverage": document["dependency_coverage"],
        "input_object_refs": document["input_object_refs"],
        "selection_scope_bindings": document["selection_scope_bindings"],
    }


def _impact_payload(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": document["schema"],
        "study_artifact_ref": document["study_artifact_ref"],
        "historical_binding_digest": document["historical_binding_digest"],
        "current_binding_digest": document["current_binding_digest"],
        "classification": document["classification"],
        "reasons": document["reasons"],
        "changed_dependency_refs": document["changed_dependency_refs"],
        "producer_diff_digests": document["producer_diff_digests"],
        "producer_attribution_digests": document["producer_attribution_digests"],
        "non_claims": document["non_claims"],
    }


def _recall_payload(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "basis_kind": document["basis_kind"],
        "proposition": document["proposition"],
        "study_artifact_refs": document["study_artifact_refs"],
        "candidate_refs": document["candidate_refs"],
        "candidate_locators": document["candidate_locators"],
        "limitations": document["limitations"],
    }


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA.fullmatch(value))


def verify_counterplayer_study(bundle: Mapping[str, Any]) -> CounterplayerStudyReport:
    report = CounterplayerStudyReport()
    if not isinstance(bundle, Mapping):
        _fail(report, "bundle_invalid", "bundle must be an object")
        return report

    producer = bundle.get("producer")
    if isinstance(producer, Mapping) and producer.get("repository") == COUNTERPLAYER_REPO and producer.get("commit") == COUNTERPLAYER_PIN:
        report.producer_pin_match = Conclusion.TRUE
    else:
        report.producer_pin_match = Conclusion.FALSE
        _fail(report, "producer_pin_mismatch", "Counterplayer repository/commit pin mismatch")

    manifest = bundle.get("study_artifact_manifest")
    expected_manifest = {
        "schema", "study_artifact_ref", "artifact_kind", "artifact_digest",
        "producer", "base_model", "study_recipe_ref", "study_recipe_digest",
        "created_at", "limitations", "dependency_coverage", "input_object_refs",
        "selection_scope_bindings", "manifest_digest",
    }
    if not isinstance(manifest, Mapping) or set(manifest) != expected_manifest:
        report.manifest_present = Conclusion.FALSE
        report.manifest_digest_match = Conclusion.FALSE
        report.manifest_identity_match = Conclusion.FALSE
        _fail(report, "manifest_invalid", "StudyArtifactManifest missing or field set mismatch")
        return report
    report.manifest_present = Conclusion.TRUE
    if manifest.get("schema") != STUDY_ARTIFACT_SCHEMA or not _valid_sha(manifest.get("artifact_digest")) or not _valid_sha(manifest.get("manifest_digest")):
        report.manifest_digest_match = Conclusion.FALSE
        report.manifest_identity_match = Conclusion.FALSE
        _fail(report, "manifest_shape_invalid", "StudyArtifactManifest schema/digest shape invalid")
    else:
        expected_ref = f"study:{manifest['artifact_digest']}"
        report.manifest_identity_match = Conclusion.TRUE if manifest.get("study_artifact_ref") == expected_ref else Conclusion.FALSE
        if report.manifest_identity_match is Conclusion.FALSE:
            _fail(report, "manifest_identity_mismatch", "study_artifact_ref does not derive from artifact_digest")
        try:
            expected_digest = _digest(_manifest_payload(manifest))
        except Exception as exc:
            report.manifest_digest_match = Conclusion.FALSE
            _fail(report, "manifest_canonicalization_failed", str(exc))
        else:
            report.manifest_digest_match = Conclusion.TRUE if manifest.get("manifest_digest") == expected_digest else Conclusion.FALSE
            if report.manifest_digest_match is Conclusion.FALSE:
                _fail(report, "manifest_digest_mismatch", "manifest_digest does not recompute")

    impact = bundle.get("study_impact")
    if impact is None:
        report.impact_present = Conclusion.NOT_EVALUATED
        report.impact_digest_match = Conclusion.NOT_EVALUATED
        report.impact_manifest_linkage = Conclusion.NOT_EVALUATED
    else:
        expected_impact = {
            "schema", "study_artifact_ref", "historical_binding_digest",
            "current_binding_digest", "classification", "reasons",
            "changed_dependency_refs", "producer_diff_digests",
            "producer_attribution_digests", "non_claims", "impact_digest",
        }
        if not isinstance(impact, Mapping) or set(impact) != expected_impact or impact.get("schema") != STUDY_IMPACT_SCHEMA or impact.get("classification") not in IMPACT_CLASSIFICATIONS:
            report.impact_present = Conclusion.FALSE
            report.impact_digest_match = Conclusion.FALSE
            report.impact_manifest_linkage = Conclusion.FALSE
            _fail(report, "impact_invalid", "StudyImpact missing, field set mismatch, or unsupported classification")
        else:
            report.impact_present = Conclusion.TRUE
            report.impact_manifest_linkage = Conclusion.TRUE if impact.get("study_artifact_ref") == manifest.get("study_artifact_ref") else Conclusion.FALSE
            if report.impact_manifest_linkage is Conclusion.FALSE:
                _fail(report, "impact_artifact_mismatch", "StudyImpact does not bind StudyArtifactManifest")
            try:
                expected_digest = _digest(_impact_payload(impact))
            except Exception as exc:
                report.impact_digest_match = Conclusion.FALSE
                _fail(report, "impact_canonicalization_failed", str(exc))
            else:
                report.impact_digest_match = Conclusion.TRUE if impact.get("impact_digest") == expected_digest else Conclusion.FALSE
                if report.impact_digest_match is Conclusion.FALSE:
                    _fail(report, "impact_digest_mismatch", "impact_digest does not recompute")

    recall = bundle.get("recall_event")
    if recall is None:
        report.recall_present = Conclusion.NOT_EVALUATED
        report.recall_digest_match = Conclusion.NOT_EVALUATED
        report.recall_artifact_linkage = Conclusion.NOT_EVALUATED
    else:
        expected_recall = {
            "schema_version", "kind", "recall_digest", "basis_kind",
            "study_artifact_refs", "proposition", "candidate_refs",
            "candidate_locators", "limitations",
        }
        if not isinstance(recall, Mapping) or set(recall) != expected_recall or recall.get("schema_version") != RESEARCH_EVENTS_SCHEMA or recall.get("kind") != "recall":
            report.recall_present = Conclusion.FALSE
            report.recall_digest_match = Conclusion.FALSE
            report.recall_artifact_linkage = Conclusion.FALSE
            _fail(report, "recall_invalid", "RecallEvent missing or field set mismatch")
        else:
            report.recall_present = Conclusion.TRUE
            refs = recall.get("study_artifact_refs")
            if not isinstance(refs, list) or not all(isinstance(ref, str) and _STUDY_REF.fullmatch(ref) for ref in refs):
                report.recall_artifact_linkage = Conclusion.FALSE
                _fail(report, "recall_refs_invalid", "RecallEvent study_artifact_refs malformed")
            else:
                report.recall_artifact_linkage = Conclusion.TRUE if manifest.get("study_artifact_ref") in refs else Conclusion.FALSE
                if report.recall_artifact_linkage is Conclusion.FALSE:
                    _fail(report, "recall_artifact_mismatch", "RecallEvent does not name supplied StudyArtifactManifest")
            try:
                expected_digest = _digest(_recall_payload(recall))
            except Exception as exc:
                report.recall_digest_match = Conclusion.FALSE
                _fail(report, "recall_canonicalization_failed", str(exc))
            else:
                report.recall_digest_match = Conclusion.TRUE if recall.get("recall_digest") == expected_digest else Conclusion.FALSE
                if report.recall_digest_match is Conclusion.FALSE:
                    _fail(report, "recall_digest_mismatch", "recall_digest does not recompute")

    return report


__all__ = [
    "COUNTERPLAYER_PIN",
    "COUNTERPLAYER_REPO",
    "CounterplayerStudyReport",
    "Conclusion",
    "LIMITATIONS",
    "REPORT_PROFILE",
    "REPORT_SCHEMA",
    "verify_counterplayer_study",
]
