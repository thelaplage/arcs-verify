"""Tests for the universal verification entry points and schema freeze module.

These cover:
- verify_action_receipt: routes MCP/action profiles correctly
- verify_claim_receipt: routes editorial/claim profiles correctly
- verify_memory_receipt: stub returns the expected not-ratified response
- Wrong-domain routing: each entry point rejects receipts from other domains
- arcs_verify.schema: stable import-path exports are consistent with verifier
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import arcs_verify
from arcs_verify import (
    VerificationReport,
    verify_action_receipt,
    verify_claim_receipt,
    verify_memory_receipt,
)
from arcs_verify import schema as schema_module
from arcs_verify.verifier import (
    ACCEPTED_SCHEMA_SHA256 as _VERIFIER_ACCEPTED,
    ENVELOPE_SCHEMA_PINS as _VERIFIER_PINS,
    FROZEN_SCHEMA_SHA256 as _VERIFIER_FROZEN,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vendor/arcs-srs/vectors/signed-receipt-v0.1"


def _load_vector(name: str) -> bytes:
    return (VECTORS / "valid" / name).read_bytes()


# ---------------------------------------------------------------------------
# Schema freeze: arcs_verify.schema exports are consistent with verifier.py
# ---------------------------------------------------------------------------

class TestSchemaFreeze:
    def test_schema_pin_v0_2_0_matches_verifier_frozen(self):
        assert schema_module.SCHEMA_PIN_V0_2_0 == _VERIFIER_FROZEN

    def test_envelope_schema_pins_match_verifier(self):
        assert schema_module.ENVELOPE_SCHEMA_PINS == _VERIFIER_PINS

    def test_accepted_sha256_frozenset_matches_verifier(self):
        assert schema_module.ACCEPTED_SCHEMA_SHA256 == _VERIFIER_ACCEPTED

    def test_current_schema_version_is_accepted(self):
        assert (
            schema_module.ENVELOPE_SCHEMA_PINS.get(schema_module.CURRENT_SCHEMA_VERSION)
            in schema_module.ACCEPTED_SCHEMA_SHA256
        )

    def test_receipt_version_constant(self):
        assert schema_module.RECEIPT_VERSION == "srs.core.v5.1"

    def test_schema_exports_are_top_level_in_package(self):
        # Downstream consumers can import directly from arcs_verify.
        assert arcs_verify.ENVELOPE_SCHEMA_PINS == schema_module.ENVELOPE_SCHEMA_PINS
        assert arcs_verify.CURRENT_SCHEMA_VERSION == schema_module.CURRENT_SCHEMA_VERSION
        assert arcs_verify.ACCEPTED_SCHEMA_SHA256 == schema_module.ACCEPTED_SCHEMA_SHA256


# ---------------------------------------------------------------------------
# verify_action_receipt
# ---------------------------------------------------------------------------

class TestVerifyActionReceipt:
    def test_valid_mcp_admission_routes_through(self):
        raw = _load_vector("admission-admitted.json")
        report = verify_action_receipt(raw)
        assert isinstance(report, VerificationReport)
        # Schema, envelope, profile, raw_content, attestation_limits must be True
        # for a well-formed vector (key resolution fails without a keyring but
        # that is expected for the stub keyring path).
        assert report.schema_digest
        assert report.envelope
        assert report.profile
        assert report.raw_content_exclusion
        assert report.attestation_limits_present

    def test_invalid_bytes_returns_failure(self):
        report = verify_action_receipt(b"not json")
        assert not report.schema_digest
        assert any("receipt_decode_failed" in c for c in report.failure_codes)

    def test_wrong_domain_editorial_rejected(self):
        # Construct a minimal receipt with an editorial profile_id.
        fake = {
            "profile_id": "srs.editorial.source_capture",
            "profile_version": "v0.1",
        }
        report = verify_action_receipt(json.dumps(fake).encode())
        assert "profile.wrong_domain" in report.failure_codes

    def test_wrong_domain_memory_rejected(self):
        fake = {
            "profile_id": "srs.memory.sovereignty",
            "profile_version": "v0.1",
        }
        report = verify_action_receipt(json.dumps(fake).encode())
        assert "profile.wrong_domain" in report.failure_codes

    def test_missing_profile_id_returns_failure(self):
        report = verify_action_receipt(json.dumps({}).encode())
        assert "profile.missing_or_non_string" in report.failure_codes


# ---------------------------------------------------------------------------
# verify_claim_receipt
# ---------------------------------------------------------------------------

class TestVerifyClaimReceipt:
    def test_editorial_source_capture_profile_routes(self):
        # Construct a minimal v0.1 source-capture receipt and confirm routing
        # (the envelope check will fail because required fields are absent, but
        # the profile must be selected and not rejected as wrong-domain).
        fake = {
            "profile_id": "srs.editorial.source_capture",
            "profile_version": "v0.1",
            "receipt_version": "srs.core.v5.1",
        }
        report = verify_claim_receipt(json.dumps(fake).encode())
        assert "profile.wrong_domain" not in report.failure_codes

    def test_wrong_domain_action_rejected(self):
        fake = {
            "profile_id": "srs.mcp.sdk_enforcement",
            "profile_version": "v0.1",
        }
        report = verify_claim_receipt(json.dumps(fake).encode())
        assert "profile.wrong_domain" in report.failure_codes

    def test_wrong_domain_memory_rejected(self):
        fake = {
            "profile_id": "srs.memory.sovereignty",
            "profile_version": "v0.1",
        }
        report = verify_claim_receipt(json.dumps(fake).encode())
        assert "profile.wrong_domain" in report.failure_codes

    def test_invalid_bytes_returns_failure(self):
        report = verify_claim_receipt(b"\xff\xfe")
        assert any("receipt_decode_failed" in c for c in report.failure_codes)


# ---------------------------------------------------------------------------
# verify_memory_receipt (stub)
# ---------------------------------------------------------------------------

class TestVerifyMemoryReceipt:
    def test_memory_profile_returns_stub_code(self):
        fake = {
            "profile_id": "srs.memory.sovereignty",
            "profile_version": "v0.1",
        }
        report = verify_memory_receipt(json.dumps(fake).encode())
        assert "profile.memory_not_yet_ratified" in report.failure_codes
        assert not report.profile

    def test_stub_does_not_assert_authenticity(self):
        # The not_evaluated discipline must be preserved for authenticity fields.
        # Those fields default to False (not True) in VerificationReport.
        fake = {
            "profile_id": "srs.memory.anything",
            "profile_version": "v0.1",
        }
        report = verify_memory_receipt(json.dumps(fake).encode())
        # signature_valid and issuer_key_trusted must remain False (not promoted
        # to True by the stub).
        assert not report.signature_valid
        assert not report.issuer_key_trusted

    def test_wrong_domain_editorial_rejected(self):
        fake = {
            "profile_id": "srs.editorial.source_capture",
            "profile_version": "v0.1",
        }
        report = verify_memory_receipt(json.dumps(fake).encode())
        assert "profile.wrong_domain" in report.failure_codes

    def test_wrong_domain_action_rejected(self):
        fake = {
            "profile_id": "srs.mcp.sdk_enforcement",
            "profile_version": "v0.1",
        }
        report = verify_memory_receipt(json.dumps(fake).encode())
        assert "profile.wrong_domain" in report.failure_codes

    def test_invalid_bytes_returns_failure(self):
        report = verify_memory_receipt(b"not-json!!!")
        assert any("receipt_decode_failed" in c for c in report.failure_codes)


# ---------------------------------------------------------------------------
# Report shape invariant: all three functions return VerificationReport
# ---------------------------------------------------------------------------

class TestReportShape:
    """The 8-Boolean + chain_status shape is preserved for all entry points."""

    BOOLEANS = (
        "schema_digest",
        "envelope",
        "profile",
        "raw_content_exclusion",
        "signature_valid",
        "issuer_key_resolved",
        "issuer_key_trusted",
        "attestation_limits_present",
    )

    def _check_shape(self, report: VerificationReport) -> None:
        for attr in self.BOOLEANS:
            val = getattr(report, attr)
            assert isinstance(val, bool), f"{attr} is not bool: {val!r}"
        assert isinstance(report.chain_status, str)

    def test_action_report_shape(self):
        raw = _load_vector("admission-admitted.json")
        self._check_shape(verify_action_receipt(raw))

    def test_claim_report_shape(self):
        fake = {
            "profile_id": "srs.editorial.source_capture",
            "profile_version": "v0.1",
        }
        self._check_shape(verify_claim_receipt(json.dumps(fake).encode()))

    def test_memory_report_shape(self):
        fake = {"profile_id": "srs.memory.x", "profile_version": "v0.1"}
        self._check_shape(verify_memory_receipt(json.dumps(fake).encode()))
