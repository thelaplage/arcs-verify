"""Tests for the provisional srs.editorial.citation_pack.v0.1 profile verifier.

A citation pack is a single ``pack_assembly`` provenance receipt for one
editorial publication artifact. This verifier is single-receipt and structural:
it validates fixed identity, the FORM of the digest references, subject binding,
required covered/excluded classes, required machine-limitation codes, and the
base attestation limit. It never recomputes referenced artifact bytes or sizes
(the receipt is metadata-only and supplies none), and it never treats a
Counterpedia demo-pack ZIP archive as a citation_pack — that is a different
artifact family and is excluded from positive vectors.

Positive authority vectors are the vendored arcs-srs conformance fixtures
(vendor/arcs-srs/vectors/editorial-citation-pack-v0.1/, arcs-srs 4d90b9c,
PROVISIONAL).

No private keys, no bootstrap code imports — serialized receipt dicts only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from arcs_verify.verifier import (
    CITATION_PACK_BASE_ATTESTATION_LIMIT,
    EDITORIAL_CITATION_PACK_PROFILE,
    PROVISIONAL_PROFILE_DETAILS,
    _editorial_citation_pack_profile_errors,
    _profile_errors,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vendor" / "arcs-srs" / "vectors" / "editorial-citation-pack-v0.1"
VALID_DIR = VECTORS / "fixtures" / "valid"
INVALID_DIR = VECTORS / "fixtures" / "invalid"
ENVELOPE_SCHEMA = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.1.schema.json"
# Citation-pack v0.1 receipts are unsigned structural fixtures (requires_signing
# is false). An empty keyring exercises the envelope + profile findings without
# asserting a signature chain.
EMPTY_KEYRING: dict[str, Any] = {"issuers": []}

_PUB = "sha256:" + "a" * 64


def _valid_receipt(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.editorial.citation_pack",
        "profile_version": "v0.1",
        "receipt_id": "editorial-pack-test-0001",
        "receipt_type": "provenance",
        "receipt_kind": "pack_assembly",
        "boundary_type": "editorial_corpus_boundary",
        "protocol_binding": "editorial-corpus-bootstrap",
        "subject_ref": _PUB,
        "issuer_id": "issuer.test/editorial-corpus/2026-01",
        "runtime_instance_id": "runtime-editorial-test-0001",
        "boundary_id": "boundary-editorial-corpus-0001",
        "issued_at": "2026-08-06T00:05:00Z",
        "publication_artifact_id": _PUB,
        "pack_integrity_ref": "sha256:" + "b" * 64,
        "declaration_manifest_ref": "sha256:" + "c" * 64,
        "capture_manifest_ref": "sha256:" + "d" * 64,
        "artifact_classes_covered": [
            "publication_artifact_identity",
            "declaration_manifest_digest",
            "pack_integrity_digest",
        ],
        "artifact_classes_excluded": [
            "raw_publication_bytes",
            "raw_captured_bytes",
        ],
        "attestation_limits": [CITATION_PACK_BASE_ATTESTATION_LIMIT],
        "machine_limitations": [
            {"code": "ARTICLE_TRUTH_NOT_EVALUATED"},
            {"code": "EVIDENCE_COMPLETENESS_NOT_EVALUATED"},
            {"code": "CITATION_MAPPING_MACHINE_PROPOSED"},
        ],
        "extensions": {},
    }
    base.update(overrides)
    return base


def test_conformant_citation_pack_has_no_profile_errors() -> None:
    assert _editorial_citation_pack_profile_errors(_valid_receipt()) == []


def test_dispatch_routes_to_citation_pack_checker() -> None:
    assert _profile_errors(_valid_receipt(), EDITORIAL_CITATION_PACK_PROFILE) == []


def test_provisional_status_is_surfaced_in_report_details() -> None:
    detail = PROVISIONAL_PROFILE_DETAILS.get(EDITORIAL_CITATION_PACK_PROFILE)
    assert detail is not None
    assert detail.startswith("provisional_profile:")
    assert "PROVISIONAL" in detail
    # never phrase a PASS as ratified/stable conformance
    assert "not ratified" in detail


# --- vendored arcs-srs conformance fixtures = the positive/negative authority ---

def test_vendored_valid_fixtures_pass() -> None:
    files = sorted(VALID_DIR.glob("*.json"))
    assert len(files) == 2  # citation-pack-with-captures, citation-pack-declared-only
    for path in files:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        assert _editorial_citation_pack_profile_errors(receipt) == [], path.name


def test_vendored_invalid_fixture_fires_missing_limitation_code() -> None:
    receipt = json.loads(
        (INVALID_DIR / "citation-pack-missing-limitation-code.json").read_text(
            encoding="utf-8"
        )
    )
    errors = _editorial_citation_pack_profile_errors(receipt)
    assert (
        "citation_pack.missing_required_limitation_code:CITATION_MAPPING_MACHINE_PROPOSED"
        in errors
    )


# --- exhaustive per-mutation negatives (inline) ---

@pytest.mark.parametrize(
    "overrides, expected_code",
    [
        ({"profile_id": "srs.editorial.wrong"}, "citation_pack.invalid_profile_id"),
        ({"profile_version": "v9"}, "citation_pack.invalid_profile_version"),
        ({"receipt_type": "outcome"}, "citation_pack.invalid_receipt_type"),
        ({"receipt_kind": "source_capture"}, "citation_pack.invalid_receipt_kind"),
        ({"boundary_type": "editorial_source_capture_boundary"}, "citation_pack.invalid_boundary_type"),
        ({"protocol_binding": ""}, "citation_pack.invalid_protocol_binding"),
        ({"protocol_binding": "   "}, "citation_pack.invalid_protocol_binding"),
        ({"protocol_binding": 123}, "citation_pack.invalid_protocol_binding"),
        ({"publication_artifact_id": "not-a-digest"}, "citation_pack.invalid_publication_artifact_id_digest"),
        ({"pack_integrity_ref": "sha256:zz"}, "citation_pack.invalid_pack_integrity_digest"),
        ({"declaration_manifest_ref": "abc"}, "citation_pack.invalid_declaration_manifest_digest"),
        ({"capture_manifest_ref": "not-a-digest"}, "citation_pack.invalid_capture_manifest_digest"),
        ({"subject_ref": "sha256:" + "9" * 64}, "citation_pack.subject_binding_mismatch"),
        (
            {"artifact_classes_covered": ["publication_artifact_identity"]},
            "citation_pack.missing_required_covered_classes",
        ),
        (
            {"artifact_classes_excluded": ["raw_publication_bytes"]},
            "citation_pack.missing_required_excluded_classes",
        ),
        (
            {
                "machine_limitations": [
                    {"code": "ARTICLE_TRUTH_NOT_EVALUATED"},
                    {"code": "EVIDENCE_COMPLETENESS_NOT_EVALUATED"},
                ]
            },
            "citation_pack.missing_required_limitation_code:CITATION_MAPPING_MACHINE_PROPOSED",
        ),
        ({"attestation_limits": ["some other note"]}, "citation_pack.missing_base_attestation_limit"),
    ],
)
def test_mutation_fires_expected_code(overrides: dict[str, Any], expected_code: str) -> None:
    errors = _editorial_citation_pack_profile_errors(_valid_receipt(**overrides))
    assert expected_code in errors


def test_capture_manifest_ref_is_optional_when_absent_or_null() -> None:
    absent = _valid_receipt()
    absent.pop("capture_manifest_ref")
    assert _editorial_citation_pack_profile_errors(absent) == []
    assert _editorial_citation_pack_profile_errors(_valid_receipt(capture_manifest_ref=None)) == []


def test_counterpedia_demo_pack_zip_shape_is_not_a_citation_pack() -> None:
    """A Counterpedia demo-pack registry row is a different artifact family and
    must never be treated as a citation_pack positive vector."""
    demo_pack_row = {
        "pack_id": "quiet-utility",
        "title": "Quiet Utility Complete Pack",
        "filename": "COUNTERPEDIA_QUIET_UTILITY_COMPLETE_PACK_AUG09_2026.zip",
        "bytes": 75607,
        "sha256": "99a4dffb2112d69ff59c4100b9d54e3c66e38d419a7d07b7a27dc3c1bf280d67",
        "serving_binding": "BOUND",
    }
    errors = _editorial_citation_pack_profile_errors(demo_pack_row)
    assert errors  # decisively not a citation_pack
    assert "citation_pack.invalid_profile_id" in errors


# --- fail-closed: malformed container/member types must not raise ---

@pytest.mark.parametrize(
    "overrides",
    [
        {"artifact_classes_covered": [{}]},
        {"artifact_classes_excluded": [{}]},
        {"attestation_limits": [{}]},
        {"machine_limitations": [{}]},
        {"artifact_classes_covered": "publication_artifact_identity"},
        {"artifact_classes_excluded": 7},
        {"attestation_limits": {"base": "x"}},
        {"machine_limitations": "none"},
        {"publication_artifact_id": {"sha256": "x"}},
        {"subject_ref": ["a"]},
    ],
)
def test_malformed_member_types_fail_closed_without_raising(overrides: dict[str, Any]) -> None:
    # The checker must return a deterministic list of codes, never raise.
    errors = _editorial_citation_pack_profile_errors(_valid_receipt(**overrides))
    assert isinstance(errors, list)
    assert errors  # malformed input is a profile failure, not a pass


def test_verify_receipt_malformed_fails_closed_with_report() -> None:
    # verify_receipt runs profile checks even after envelope validation fails;
    # a malformed member must produce a VerificationReport, not a TypeError.
    receipt = _valid_receipt(artifact_classes_covered=[{}], attestation_limits=[{}])
    report = verify_receipt(
        receipt,
        EMPTY_KEYRING,
        schema_path=ENVELOPE_SCHEMA,
        selected_profile=EDITORIAL_CITATION_PACK_PROFILE,
    )
    assert report.to_dict()["passed"] is False
    assert report.profile is False


# --- end-to-end integration: real verify_receipt over vendored positives ---

def test_verify_receipt_vendored_valid_passes_profile_and_surfaces_provisional() -> None:
    for path in sorted(VALID_DIR.glob("*.json")):
        receipt = json.loads(path.read_text(encoding="utf-8"))
        report = verify_receipt(
            receipt,
            EMPTY_KEYRING,
            schema_path=ENVELOPE_SCHEMA,
            selected_profile=EDITORIAL_CITATION_PACK_PROFILE,
        )
        assert report.profile is True, (path.name, report.failure_codes)
        assert report.envelope is True, (path.name, report.details)
        # PROVISIONAL advisory is actually placed in report.details end-to-end.
        assert any(
            d.startswith("provisional_profile:") for d in report.details
        ), (path.name, report.details)
