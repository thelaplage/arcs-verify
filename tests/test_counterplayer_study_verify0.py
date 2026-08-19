from __future__ import annotations

import hashlib
import json
import unicodedata
from copy import deepcopy

from arcs_verify.counterplayer_study import (
    COUNTERPLAYER_PIN,
    COUNTERPLAYER_REPO,
    Conclusion,
    verify_counterplayer_study,
)


def nfc(value):
    if isinstance(value, str): return unicodedata.normalize("NFC", value)
    if isinstance(value, dict): return {k: nfc(v) for k, v in value.items()}
    if isinstance(value, list): return [nfc(v) for v in value]
    return value


def digest(value):
    encoded = json.dumps(nfc(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def manifest():
    artifact_digest = "sha256:" + "a" * 64
    payload = {
        "schema": "counterplayer.study-artifact-manifest/v0.1",
        "study_artifact_ref": f"study:{artifact_digest}",
        "artifact_kind": "structured_notes",
        "artifact_digest": artifact_digest,
        "producer": {"system": "fixture", "version": "v1"},
        "base_model": None,
        "study_recipe_ref": "recipe:fixture",
        "study_recipe_digest": "sha256:" + "b" * 64,
        "created_at": "2026-08-18T20:00:00Z",
        "limitations": ["derived memory only"],
        "dependency_coverage": "complete",
        "input_object_refs": ["claim:C1"],
        "selection_scope_bindings": [],
    }
    return {**payload, "manifest_digest": digest(payload)}


def impact(m):
    payload = {
        "schema": "counterplayer.study-impact/v0.1",
        "study_artifact_ref": m["study_artifact_ref"],
        "historical_binding_digest": "sha256:" + "c" * 64,
        "current_binding_digest": "sha256:" + "d" * 64,
        "classification": "DIRECTLY_AFFECTED",
        "reasons": ["declared_dependency_changed"],
        "changed_dependency_refs": ["claim:C1"],
        "producer_diff_digests": ["sha256:" + "e" * 64],
        "producer_attribution_digests": ["sha256:" + "f" * 64],
        "non_claims": [
            "affected != false",
            "unaffected != true",
            "structural_change != factual_change",
            "memory != evidence",
            "impact != admission",
            "impact != automatic_restudy",
        ],
    }
    return {**payload, "impact_digest": digest(payload)}


def recall(m):
    payload = {
        "basis_kind": "structured_notes",
        "proposition": "C1 may be relevant",
        "study_artifact_refs": [m["study_artifact_ref"]],
        "candidate_refs": [],
        "candidate_locators": ["https://example.test/source"],
        "limitations": ["requires source traversal"],
    }
    return {
        "schema_version": "research-events0.v0.1",
        "kind": "recall",
        "recall_digest": digest(payload),
        **payload,
    }


def bundle():
    m = manifest()
    return {
        "producer": {"repository": COUNTERPLAYER_REPO, "commit": COUNTERPLAYER_PIN},
        "study_artifact_manifest": m,
        "study_impact": impact(m),
        "recall_event": recall(m),
    }


def test_full_landed_study_sequence_integrity_passes():
    report = verify_counterplayer_study(bundle())
    assert report.producer_pin_match is Conclusion.TRUE
    assert report.manifest_digest_match is Conclusion.TRUE
    assert report.manifest_identity_match is Conclusion.TRUE
    assert report.impact_digest_match is Conclusion.TRUE
    assert report.impact_manifest_linkage is Conclusion.TRUE
    assert report.recall_digest_match is Conclusion.TRUE
    assert report.recall_artifact_linkage is Conclusion.TRUE
    assert report.passed is True
    assert any("does not prove source truth" in line for line in report.to_dict()["limitations"])


def test_manifest_tamper_and_identity_tamper_fail():
    value = bundle()
    value["study_artifact_manifest"]["input_object_refs"] = ["claim:C2"]
    report = verify_counterplayer_study(value)
    assert report.manifest_digest_match is Conclusion.FALSE
    assert report.passed is False

    value = bundle()
    value["study_artifact_manifest"]["study_artifact_ref"] = "study:sha256:" + "0" * 64
    report = verify_counterplayer_study(value)
    assert report.manifest_identity_match is Conclusion.FALSE


def test_impact_tamper_and_wrong_artifact_link_fail():
    value = bundle()
    value["study_impact"]["classification"] = "UNKNOWN"
    report = verify_counterplayer_study(value)
    assert report.impact_digest_match is Conclusion.FALSE

    value = bundle()
    value["study_impact"]["study_artifact_ref"] = "study:sha256:" + "1" * 64
    report = verify_counterplayer_study(value)
    assert report.impact_manifest_linkage is Conclusion.FALSE


def test_recall_tamper_and_wrong_artifact_link_fail():
    value = bundle()
    value["recall_event"]["proposition"] = "changed"
    report = verify_counterplayer_study(value)
    assert report.recall_digest_match is Conclusion.FALSE

    value = bundle()
    value["recall_event"]["study_artifact_refs"] = ["study:sha256:" + "2" * 64]
    value["recall_event"]["recall_digest"] = digest({
        "basis_kind": value["recall_event"]["basis_kind"],
        "proposition": value["recall_event"]["proposition"],
        "study_artifact_refs": value["recall_event"]["study_artifact_refs"],
        "candidate_refs": value["recall_event"]["candidate_refs"],
        "candidate_locators": value["recall_event"]["candidate_locators"],
        "limitations": value["recall_event"]["limitations"],
    })
    report = verify_counterplayer_study(value)
    assert report.recall_digest_match is Conclusion.TRUE
    assert report.recall_artifact_linkage is Conclusion.FALSE


def test_producer_pin_drift_fails_closed():
    value = bundle()
    value["producer"]["commit"] = "0" * 40
    report = verify_counterplayer_study(value)
    assert report.producer_pin_match is Conclusion.FALSE
    assert report.passed is False


def test_optional_impact_and_recall_are_not_evaluated_not_fabricated():
    value = bundle()
    value.pop("study_impact")
    value.pop("recall_event")
    report = verify_counterplayer_study(value)
    assert report.impact_present is Conclusion.NOT_EVALUATED
    assert report.recall_present is Conclusion.NOT_EVALUATED
    assert report.passed is True
    assert "NOT_EVALUATED is not PASS." in report.to_dict()["limitations"]


def test_float_canonicalization_is_refused():
    value = bundle()
    value["study_artifact_manifest"]["limitations"] = [1.2]
    report = verify_counterplayer_study(value)
    assert report.manifest_digest_match is Conclusion.FALSE
