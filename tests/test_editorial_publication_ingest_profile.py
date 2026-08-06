"""Tests for the srs.editorial.publication_ingest.v0.1 profile verifier.

Verifies that the editorial publication ingest profile checker correctly
identifies conformant receipts and fires precise error codes on mutations.
No private keys, no bootstrap code imports — serialized receipt dicts only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from arcs_verify.verifier import (
    EDITORIAL_PUBLICATION_INGEST_PROFILE,
    _editorial_publication_ingest_profile_errors,
)

_SHA = "sha256:" + "a" * 64
_SHA2 = "sha256:" + "b" * 64

_BASE_LIMIT = (
    "The receipt declares that an editorial publication artifact was ingested "
    "and parsed by the stated parser. It does not establish article truth, "
    "evidence completeness, or source verification. Declared references are "
    "not independently captured."
)
_INGEST_LIMIT = (
    "The receipt does not establish that any declared source was captured, "
    "verified, or independently confirmed."
)


def _valid_receipt(**overrides) -> dict[str, Any]:
    base = {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.editorial.publication_ingest",
        "profile_version": "v0.1",
        "receipt_id": "test-receipt-001",
        "receipt_type": "provenance",
        "receipt_kind": "ingest",
        "boundary_type": "editorial_corpus_boundary",
        "protocol_binding": "editorial-corpus-parser/0.2.0",
        "subject_ref": _SHA,
        "issued_at": "2026-08-06T00:00:00Z",
        "publication_artifact_id": _SHA,
        "declared_record_id": "PUB-1",
        "corpus_scope": {
            "scope_id": "test.corpus.v0",
            "repository_ref": {"repository": "example/corpus", "commit": "abc123"},
            "roots": [{"root_id": "root1", "relative_path": "corpus", "tree_digest": _SHA2}],
            "file_occurrence_count": 10,
            "unique_artifact_count": 10,
        },
        "root_id": "root1",
        "relative_path": "PUB_1.md",
        "occurrence_posture": "unique_artifact",
        "corpus_manifest_ref": _SHA2,
        "parser_identity": "editorial-corpus-parser/0.2.0",
        "declaration_manifest_ref": _SHA2,
        "artifact_classes_covered": [
            "publication_artifact_digest",
            "declared_reference_manifest_digest",
        ],
        "artifact_classes_excluded": [
            "raw_publication_bytes",
            "raw_frontmatter_yaml",
            "raw_body_text",
        ],
        "attestation_limits": [_BASE_LIMIT, _INGEST_LIMIT],
        "machine_limitations": [
            {"code": "ARTICLE_TRUTH_NOT_EVALUATED"},
            {"code": "EVIDENCE_COMPLETENESS_NOT_EVALUATED"},
        ],
        "extensions": {},
    }
    base.update(overrides)
    return base


def _errors(receipt: dict) -> list[str]:
    return _editorial_publication_ingest_profile_errors(receipt)


class TestValidReceipt:
    def test_valid_receipt_no_errors(self):
        assert _errors(_valid_receipt()) == []

    def test_duplicate_location_posture_valid(self):
        assert _errors(_valid_receipt(occurrence_posture="duplicate_location")) == []

    def test_none_declared_record_id_valid(self):
        r = _valid_receipt()
        r["declared_record_id"] = None
        assert _errors(r) == []


class TestProfileIdChecks:
    def test_wrong_profile_id(self):
        errors = _errors(_valid_receipt(profile_id="srs.mcp.sdk_enforcement"))
        assert "editorial_ingest.invalid_profile_id" in errors

    def test_wrong_profile_version(self):
        errors = _errors(_valid_receipt(profile_version="v0.2"))
        assert "editorial_ingest.invalid_profile_version" in errors

    def test_wrong_receipt_type(self):
        errors = _errors(_valid_receipt(receipt_type="sdk_enforcement"))
        assert "editorial_ingest.invalid_receipt_type" in errors

    def test_wrong_boundary_type(self):
        errors = _errors(_valid_receipt(boundary_type="mcp_tool_call"))
        assert "editorial_ingest.invalid_boundary_type" in errors

    def test_wrong_receipt_kind(self):
        errors = _errors(_valid_receipt(receipt_kind="capture_attempt"))
        assert "editorial_ingest.invalid_receipt_kind" in errors


class TestSubjectBinding:
    def test_subject_ref_matches_pub_artifact_id_no_error(self):
        assert _errors(_valid_receipt()) == []

    def test_subject_ref_mismatch_fires_error(self):
        r = _valid_receipt()
        r["subject_ref"] = "sha256:" + "c" * 64
        errors = _errors(r)
        assert "editorial_ingest.subject_binding_mismatch" in errors

    def test_both_absent_no_mismatch_error(self):
        r = _valid_receipt()
        del r["subject_ref"]
        del r["publication_artifact_id"]
        errors = _errors(r)
        assert "editorial_ingest.subject_binding_mismatch" not in errors


class TestRequiredFields:
    @pytest.mark.parametrize("field", [
        "publication_artifact_id",
        "corpus_scope",
        "root_id",
        "relative_path",
        "occurrence_posture",
        "corpus_manifest_ref",
        "parser_identity",
        "declaration_manifest_ref",
    ])
    def test_missing_required_field(self, field):
        r = _valid_receipt()
        del r[field]
        errors = _errors(r)
        assert f"editorial_ingest.missing_required:{field}" in errors


class TestOccurrencePosture:
    def test_invalid_posture(self):
        errors = _errors(_valid_receipt(occurrence_posture="unverified"))
        assert "editorial_ingest.invalid_occurrence_posture" in errors

    def test_none_posture_no_invalid_error(self):
        r = _valid_receipt()
        del r["occurrence_posture"]
        errors = _errors(r)
        assert "editorial_ingest.invalid_occurrence_posture" not in errors


class TestArtifactClasses:
    def test_missing_covered_classes(self):
        r = _valid_receipt(artifact_classes_covered=[])
        errors = _errors(r)
        assert "editorial_ingest.missing_required_covered_classes" in errors

    def test_missing_excluded_classes(self):
        r = _valid_receipt(artifact_classes_excluded=[])
        errors = _errors(r)
        assert "editorial_ingest.missing_required_excluded_classes" in errors

    def test_additional_covered_classes_allowed(self):
        r = _valid_receipt(artifact_classes_covered=[
            "publication_artifact_digest",
            "declared_reference_manifest_digest",
            "some_additional_class",
        ])
        assert _errors(r) == []


class TestMachineLimitationCodes:
    def test_missing_article_truth_code(self):
        r = _valid_receipt(machine_limitations=[
            {"code": "EVIDENCE_COMPLETENESS_NOT_EVALUATED"}
        ])
        errors = _errors(r)
        assert "editorial_ingest.missing_required_limitation_code:ARTICLE_TRUTH_NOT_EVALUATED" in errors

    def test_missing_evidence_completeness_code(self):
        r = _valid_receipt(machine_limitations=[
            {"code": "ARTICLE_TRUTH_NOT_EVALUATED"}
        ])
        errors = _errors(r)
        assert "editorial_ingest.missing_required_limitation_code:EVIDENCE_COMPLETENESS_NOT_EVALUATED" in errors

    def test_empty_machine_limitations(self):
        r = _valid_receipt(machine_limitations=[])
        errors = _errors(r)
        assert "editorial_ingest.missing_required_limitation_code:ARTICLE_TRUTH_NOT_EVALUATED" in errors
        assert "editorial_ingest.missing_required_limitation_code:EVIDENCE_COMPLETENESS_NOT_EVALUATED" in errors

    def test_none_machine_limitations(self):
        r = _valid_receipt()
        del r["machine_limitations"]
        errors = _errors(r)
        assert "editorial_ingest.missing_required_limitation_code:ARTICLE_TRUTH_NOT_EVALUATED" in errors

    def test_additional_codes_allowed(self):
        r = _valid_receipt(machine_limitations=[
            {"code": "ARTICLE_TRUTH_NOT_EVALUATED"},
            {"code": "EVIDENCE_COMPLETENESS_NOT_EVALUATED"},
            {"code": "SOURCE_NOT_CAPTURED"},
        ])
        assert _errors(r) == []


class TestAttestationLimits:
    def test_missing_base_limit(self):
        r = _valid_receipt(attestation_limits=[_INGEST_LIMIT])
        errors = _errors(r)
        assert "editorial_ingest.missing_base_attestation_limit" in errors

    def test_missing_ingest_limit(self):
        r = _valid_receipt(attestation_limits=[_BASE_LIMIT])
        errors = _errors(r)
        assert "editorial_ingest.missing_ingest_attestation_limit" in errors

    def test_both_limits_present_no_error(self):
        assert _errors(_valid_receipt()) == []


class TestProfileConstant:
    def test_profile_constant_value(self):
        assert EDITORIAL_PUBLICATION_INGEST_PROFILE == "srs.editorial.publication_ingest.v0.1"
