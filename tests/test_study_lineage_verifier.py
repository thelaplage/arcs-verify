from __future__ import annotations

import hashlib
import json
from copy import deepcopy

from arcs_verify.study_impact_integrity import (
    DIGEST_SENTINEL,
    canonical_serialize,
    recompute_memory_impact_digest,
    verify_memory_impact_digest,
)
from arcs_verify.study_lineage import (
    IMPACT_PRODUCER_COMMIT,
    IMPACT_PRODUCER_REPO,
    STUDY_PRODUCER_COMMIT,
    STUDY_PRODUCER_REPO,
    Conclusion,
    verify_study_lineage,
)


def manifest():
    value = {
        "schema_version": "counterpedia.study_manifest/v0.1",
        "study_ref": "study:firm-v1",
        "method_ref": "method:fixture",
        "configuration_ref": "config:fixture",
        "studied_at": "2026-08-18T20:00:00Z",
        "inputs": [
            {
                "kind": "source_version",
                "ref": "source:S1@v1",
                "digest": "sha256:" + "a" * 64,
            }
        ],
        "scope_refs": ["tenant:firm", "matter:A"],
        "authority_movement": 0,
    }
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    value["manifest_digest"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    return value


def artifact(m):
    return {
        "schema_version": "counterpedia.study_artifact/v0.1",
        "artifact_ref": "memory:M1",
        "provider_id": "provider:fixture",
        "provider_kind": "structured_notes",
        "provider_version": "v1",
        "manifest_digest": m["manifest_digest"],
        "produced_at": "2026-08-18T20:01:00Z",
        "scope_refs": ["tenant:firm", "matter:A"],
        "addressability": "content_addressed",
        "artifact_digest": "sha256:" + "b" * 64,
        "authority_movement": 0,
    }


def impact(m):
    value = {
        "schema": "countergraph.study-memory-impact/v0.1",
        "authority_effect": "none",
        "study_artifact_ref": "memory:M1",
        "study_ref": m["study_ref"],
        "study_manifest_digest": m["manifest_digest"],
        "study_contract_producer": {
            "repository": STUDY_PRODUCER_REPO,
            "commit": STUDY_PRODUCER_COMMIT,
        },
        "changed_refs": ["source:S1@v1"],
        "unresolved_refs": [],
        "direct_input_refs": ["source:S1@v1"],
        "transitive_input_refs": [],
        "dependency_paths": [],
        "coverage": {"complete": False, "basis_refs": []},
        "impact_state": "DIRECTLY_AFFECTED",
        "impact_digest": DIGEST_SENTINEL,
        "non_claims": [
            "study_artifact != governed_corpus_record",
            "affected != incorrect",
            "unaffected != globally_current",
            "unknown != unaffected",
            "explicit_path != causal_model_influence",
            "study_scope != effective_authorization",
            "impact_projection != retraining_instruction",
        ],
    }
    value["impact_digest"] = recompute_memory_impact_digest(value)
    return value


def bundle():
    m = manifest()
    return {
        "study_manifest": m,
        "study_artifact": artifact(m),
        "memory_impact": impact(m),
        "study_producer": {
            "repository": STUDY_PRODUCER_REPO,
            "commit": STUDY_PRODUCER_COMMIT,
        },
        "impact_producer": {
            "repository": IMPACT_PRODUCER_REPO,
            "commit": IMPACT_PRODUCER_COMMIT,
        },
    }


def test_full_linkage_is_structurally_valid_without_semantic_overclaim():
    report = verify_study_lineage(bundle())
    assert report.manifest_present is Conclusion.TRUE
    assert report.study_producer_pin_match is Conclusion.TRUE
    assert report.manifest_digest_match is Conclusion.TRUE
    assert report.artifact_manifest_linkage is Conclusion.TRUE
    assert report.artifact_addressability_valid is Conclusion.TRUE
    assert report.impact_manifest_linkage is Conclusion.TRUE
    assert report.impact_artifact_linkage is Conclusion.TRUE
    assert report.impact_producer_pin_match is Conclusion.TRUE
    assert report.passed is True
    assert any("does not prove source truth" in text for text in report.to_dict()["limitations"])


def test_manifest_tamper_fails_independent_digest_recomputation():
    value = bundle()
    value["study_manifest"]["inputs"][0]["ref"] = "source:S2@v1"
    report = verify_study_lineage(value)
    assert report.manifest_digest_match is Conclusion.FALSE
    assert report.passed is False


def test_study_producer_pin_drift_fails_closed():
    value = bundle()
    value["study_producer"]["commit"] = "0" * 40
    report = verify_study_lineage(value)
    assert report.study_producer_pin_match is Conclusion.FALSE
    assert report.passed is False


def test_artifact_manifest_mismatch_fails():
    value = bundle()
    value["study_artifact"]["manifest_digest"] = "sha256:" + "f" * 64
    report = verify_study_lineage(value)
    assert report.artifact_manifest_linkage is Conclusion.FALSE
    assert report.passed is False


def test_provider_addressed_artifact_cannot_claim_unavailable_content_digest():
    value = bundle()
    value["study_artifact"]["addressability"] = "provider_addressed"
    report = verify_study_lineage(value)
    assert report.artifact_addressability_valid is Conclusion.FALSE

    value["study_artifact"]["artifact_digest"] = None
    report = verify_study_lineage(value)
    assert report.artifact_addressability_valid is Conclusion.TRUE


def test_impact_manifest_and_artifact_mismatch_fail_independently():
    value = bundle()
    value["memory_impact"]["study_manifest_digest"] = "sha256:" + "e" * 64
    report = verify_study_lineage(value)
    assert report.impact_manifest_linkage is Conclusion.FALSE

    value = bundle()
    value["memory_impact"]["study_artifact_ref"] = "memory:other"
    report = verify_study_lineage(value)
    assert report.impact_artifact_linkage is Conclusion.FALSE


def test_impact_producer_pin_drift_fails_closed():
    value = bundle()
    value["impact_producer"]["commit"] = "f" * 40
    report = verify_study_lineage(value)
    assert report.impact_producer_pin_match is Conclusion.FALSE
    assert report.passed is False


def test_countergraph_canonical_profile_is_recomputed_not_trusted():
    value = impact(manifest())
    assert verify_memory_impact_digest(value) is True

    tampered = deepcopy(value)
    tampered["impact_state"] = "UNKNOWN"
    assert verify_memory_impact_digest(tampered) is False

    body = deepcopy(tampered)
    body["impact_digest"] = DIGEST_SENTINEL
    expected = "sha256:" + hashlib.sha256(canonical_serialize(body)).hexdigest()
    assert recompute_memory_impact_digest(tampered) == expected


def test_optional_artifact_and_impact_are_not_evaluated_not_pass_assertions():
    m = manifest()
    report = verify_study_lineage(
        {
            "study_manifest": m,
            "study_producer": {
                "repository": STUDY_PRODUCER_REPO,
                "commit": STUDY_PRODUCER_COMMIT,
            },
        }
    )
    assert report.artifact_present is Conclusion.NOT_EVALUATED
    assert report.impact_present is Conclusion.NOT_EVALUATED
    assert report.passed is True
    assert "NOT_EVALUATED is not PASS." in report.to_dict()["limitations"]
