"""Tests for the srs.editorial.source_capture.v0.1.1 profile verifier.

v0.1.1 is a PROVISIONAL successor with a distinct receipt model from v0.1:
the capture disposition is a top-level ``outcome`` enum, and ``declared_url``
/ ``captured_bytes_ref`` are top-level fields bound to that outcome by two
structurally enforced cross-field rules:

  - ``captured_bytes_ref`` is a sha256:<hex> digest exactly when ``outcome``
    is ``success`` and JSON null for every other outcome;
  - ``declared_url`` is JSON null exactly when ``outcome`` is
    ``no_url_declared`` and a non-empty string otherwise.

The receipt vectors below are byte-identical to the seven conformance
fixtures shipped with the v0.1.1 profile (3 valid, 4 invalid). The frozen
v0.1 ``capture``-block verifier is exercised here only to confirm it is
untouched.

No private keys, no bootstrap code imports — serialized receipt dicts only.
"""

from __future__ import annotations

from typing import Any

from arcs_verify.verifier import (
    EDITORIAL_SOURCE_CAPTURE_PROFILE_V011,
    PROFILE_IDENTITIES,
    _editorial_source_capture_profile_errors,
    _editorial_source_capture_v011_profile_errors,
    _profile_errors,
)

_REF = (
    "urn:editorial.bootstrap:declared-reference:sha256:"
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
)
_DIGEST = "sha256:e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
_ATTESTATION = (
    "The receipt declares a source capture attempt for an editorial corpus "
    "declared reference. It does not establish that the captured bytes are "
    "authentic, that the source is the one the author intended, or that the "
    "content supports the publication's claims."
)


def _valid(**overrides: Any) -> dict[str, Any]:
    """A conformant v0.1.1 success receipt; mirrors the success fixture."""
    base: dict[str, Any] = {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.editorial.source_capture",
        "profile_version": "v0.1.1",
        "receipt_id": "editorial-capture-v011-valid-success-0001",
        "receipt_type": "provenance",
        "receipt_kind": "capture_attempt",
        "boundary_type": "editorial_corpus_boundary",
        "protocol_binding": "editorial-corpus-bootstrap",
        "subject_ref": _REF,
        "issuer_id": "issuer.test/editorial-corpus/2026-01",
        "runtime_instance_id": "runtime-editorial-test-0001",
        "boundary_id": "boundary-editorial-corpus-0001",
        "issued_at": "2026-08-06T00:02:00Z",
        "reference_artifact_id": _REF,
        "declared_url": "https://example.org/article/2024-01-15/editorial-source",
        "outcome": "success",
        "captured_bytes_ref": _DIGEST,
        "artifact_classes_covered": [
            "declared_reference_identity",
            "capture_attempt_record",
        ],
        "artifact_classes_excluded": ["raw_captured_bytes"],
        "attestation_limits": [_ATTESTATION],
        "machine_limitations": [{"code": "CONTENT_NOT_VERIFIED"}],
        "extensions": {},
    }
    base.update(overrides)
    return base


# --- the three valid fixtures produce zero profile errors -----------------


def test_valid_success() -> None:
    assert _editorial_source_capture_v011_profile_errors(_valid()) == []


def test_valid_blocked() -> None:
    receipt = _valid(
        outcome="blocked",
        declared_url="https://paywalled-journal.example.com/article/2023-09",
        captured_bytes_ref=None,
    )
    assert _editorial_source_capture_v011_profile_errors(receipt) == []


def test_valid_no_url_declared() -> None:
    receipt = _valid(
        outcome="no_url_declared",
        declared_url=None,
        captured_bytes_ref=None,
    )
    assert _editorial_source_capture_v011_profile_errors(receipt) == []


# --- the four invalid fixtures fire exactly their intended code -----------


def test_invalid_outcome() -> None:
    receipt = _valid(outcome="fetch_ok")
    assert _editorial_source_capture_v011_profile_errors(receipt) == [
        "source_capture.invalid_outcome",
    ]


def test_invalid_nonnull_bytes_on_blocked() -> None:
    receipt = _valid(
        outcome="blocked",
        declared_url="https://paywalled-journal.example.com/article/2023-09",
        captured_bytes_ref="sha256:" + "ab" * 32,
    )
    assert _editorial_source_capture_v011_profile_errors(receipt) == [
        "source_capture.captured_bytes_on_nonsuccess",
    ]


def test_invalid_null_bytes_on_success() -> None:
    receipt = _valid(captured_bytes_ref=None)
    assert _editorial_source_capture_v011_profile_errors(receipt) == [
        "source_capture.missing_captured_bytes_on_success",
    ]


def test_invalid_url_present_on_no_url_declared() -> None:
    receipt = _valid(
        outcome="no_url_declared",
        declared_url="https://example.com/should-not-be-here",
        captured_bytes_ref=None,
    )
    assert _editorial_source_capture_v011_profile_errors(receipt) == [
        "source_capture.declared_url_on_no_url_declared",
    ]


# --- dispatch, identity registration, and v0.1 isolation ------------------


def test_dispatch_routes_v011_by_profile_string() -> None:
    receipt = _valid()
    assert _profile_errors(receipt, EDITORIAL_SOURCE_CAPTURE_PROFILE_V011) == []


def test_v011_identity_registered() -> None:
    assert PROFILE_IDENTITIES[EDITORIAL_SOURCE_CAPTURE_PROFILE_V011] == (
        "srs.editorial.source_capture",
        "v0.1.1",
    )


def test_v011_verifier_rejects_a_v01_version_string() -> None:
    receipt = _valid(profile_version="v0.1")
    assert "source_capture.invalid_profile_version" in (
        _editorial_source_capture_v011_profile_errors(receipt)
    )


def test_frozen_v01_verifier_rejects_a_v011_receipt() -> None:
    # A v0.1.1 receipt has none of the v0.1 capture-block shape, so the frozen
    # v0.1 verifier must reject it — the two models do not silently overlap.
    errors = _editorial_source_capture_profile_errors(_valid())
    assert "source_capture.invalid_profile_version" in errors
    assert "source_capture.missing_capture_block" in errors
