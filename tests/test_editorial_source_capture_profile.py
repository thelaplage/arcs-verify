"""Tests for the srs.editorial.source_capture.v0.1 profile verifier.

Verifies that the editorial source-capture profile checker correctly identifies
conformant capture receipts and fires precise error codes on mutations. A
capture receipt attests to the digest of the bytes a referenced EXTERNAL URL
returned at a network capture; it never asserts article truth, claim support,
or source identity. The profile is external-only: an internal governed-record
reference is a distinct class and must be rejected, not admitted.

No private keys, no bootstrap code imports — serialized receipt dicts only.
"""

from __future__ import annotations

from typing import Any

from arcs_verify.verifier import _editorial_source_capture_profile_errors

_SHA = "sha256:" + "a" * 64


def _valid_receipt(**overrides) -> dict[str, Any]:
    base = {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.editorial.source_capture",
        "profile_version": "v0.1",
        "receipt_id": "urn:example:source_capture:001",
        "receipt_type": "provenance",
        "receipt_kind": "source_capture",
        "boundary_type": "editorial_source_capture_boundary",
        "protocol_binding": "editorial-source-capture/0.1.0",
        "subject_ref": "PUB-1::ref::0",
        "issued_at": "2026-08-07T00:00:00Z",
        "reference": {
            "ref_id": "PUB-1::ref::0",
            "pub_id": "PUB-1",
            "source_label": "Example Source",
            "source_type": "news_article",
            "declared_url": "https://example.com/article",
            "source_identity_posture": "not_evaluated",
        },
        "capture": {
            "requested_url": "https://example.com/article",
            "final_url": "https://example.com/article",
            "http_status": 200,
            "content_type": "text/html; charset=utf-8",
            "captured_bytes": 1234,
            "captured_body_sha256": _SHA,
            "captured_at": "2026-08-07T00:00:00Z",
        },
        "artifact_classes_covered": [
            "captured_response_digest",
            "capture_transaction_metadata",
        ],
        "artifact_classes_excluded": [
            "raw_network_response_body",
            "raw_source_bytes",
            "article_truth",
            "claim_support_assessment",
            "source_identity_assertion",
        ],
        "attestation_limits": ["capture attests to returned bytes only"],
        "machine_limitations": [
            {"code": "ARTICLE_TRUTH_NOT_EVALUATED"},
            {"code": "CLAIM_SUPPORT_NOT_EVALUATED"},
            {"code": "SOURCE_IDENTITY_NOT_EVALUATED"},
        ],
        "retention_class_applied": "hash_only",
        "extensions": {},
    }
    base.update(overrides)
    return base


def test_conformant_capture_receipt_has_no_profile_errors() -> None:
    assert _editorial_source_capture_profile_errors(_valid_receipt()) == []


def test_wrong_receipt_kind_fires() -> None:
    errors = _editorial_source_capture_profile_errors(_valid_receipt(receipt_kind="ingest"))
    assert "source_capture.invalid_receipt_kind" in errors


def test_wrong_boundary_type_fires() -> None:
    errors = _editorial_source_capture_profile_errors(
        _valid_receipt(boundary_type="editorial_corpus_boundary")
    )
    assert "source_capture.invalid_boundary_type" in errors


def test_missing_capture_block_fires() -> None:
    r = _valid_receipt()
    del r["capture"]
    errors = _editorial_source_capture_profile_errors(r)
    assert "source_capture.missing_capture_block" in errors


def test_invalid_captured_body_digest_fires() -> None:
    r = _valid_receipt()
    r["capture"] = {**r["capture"], "captured_body_sha256": "not-a-digest"}
    errors = _editorial_source_capture_profile_errors(r)
    assert "source_capture.invalid_captured_body_digest" in errors


def test_subject_binding_mismatch_fires() -> None:
    errors = _editorial_source_capture_profile_errors(_valid_receipt(subject_ref="urn:wrong"))
    assert "source_capture.subject_binding_mismatch" in errors


def test_missing_required_limitation_code_fires() -> None:
    r = _valid_receipt()
    r["machine_limitations"] = [
        item for item in r["machine_limitations"]
        if item["code"] != "SOURCE_IDENTITY_NOT_EVALUATED"
    ]
    errors = _editorial_source_capture_profile_errors(r)
    assert "source_capture.missing_required_limitation_code:SOURCE_IDENTITY_NOT_EVALUATED" in errors


def test_internal_reference_shaped_receipt_is_rejected() -> None:
    """A receipt whose captured URL is an internal governed-record reference
    (not an external http(s) URL) must be rejected: source_capture is external
    capture only and must not become the route for internal reference
    resolution (the internal_source_capture_masquerade defect)."""
    r = _valid_receipt()
    r["capture"] = {
        **r["capture"],
        "requested_url": "counterpedia://record/CP-SIG-24",
        "final_url": "counterpedia://record/CP-SIG-24",
    }
    r["reference"] = {**r["reference"], "source_type": "governed_record_cross_reference"}
    errors = _editorial_source_capture_profile_errors(r)
    assert "source_capture.capture_url_not_external" in errors


def test_missing_requested_url_fires() -> None:
    r = _valid_receipt()
    r["capture"] = {k: v for k, v in r["capture"].items() if k != "requested_url"}
    errors = _editorial_source_capture_profile_errors(r)
    assert "source_capture.capture_url_not_external" in errors


def test_non_hash_only_retention_fires() -> None:
    errors = _editorial_source_capture_profile_errors(
        _valid_receipt(retention_class_applied="full")
    )
    assert "source_capture.invalid_retention_class" in errors


def test_missing_required_excluded_classes_fires() -> None:
    errors = _editorial_source_capture_profile_errors(
        _valid_receipt(artifact_classes_excluded=["raw_source_bytes"])
    )
    assert "source_capture.missing_required_excluded_classes" in errors
