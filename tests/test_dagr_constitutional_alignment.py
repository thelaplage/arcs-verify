"""L11: DAGR constitutional alignment tests for arcs-verify.

Verifies that arcs-verify correctly declares its independent-verifier role
under the DAGR Constitutional Contract v0.1, and that verify_dagr_receipt
propagates dagr_constitution_id in its output.
"""
from __future__ import annotations

import pytest

from arcs_verify.dagr_constitutional_consumer import (
    DAGR_CONSTITUTIONAL_CONTRACT_ID,
    DAGR_CONSTITUTIONAL_CONTRACT_STATUS,
    VERIFIER_ROLE,
    VERIFIER_DOMAIN,
    DOMAIN_NEQ_ASSERTIONS,
)
from arcs_verify.dagr_v02 import verify_dagr_receipt


# ---------------------------------------------------------------------------
# Constitutional constants
# ---------------------------------------------------------------------------

class TestConstitutionalConstants:
    def test_contract_id_exact_value(self):
        assert DAGR_CONSTITUTIONAL_CONTRACT_ID == "dagr.constitutional-contract.v0.1"

    def test_verifier_role(self):
        assert VERIFIER_ROLE == "independent_verifier"

    def test_verifier_domain(self):
        assert VERIFIER_DOMAIN == "arcs_verify"

    def test_contract_status_mentions_wave0(self):
        assert "DAGR-MIGRATION-WAVE-0" in DAGR_CONSTITUTIONAL_CONTRACT_STATUS


# ---------------------------------------------------------------------------
# DOMAIN_NEQ_ASSERTIONS
# ---------------------------------------------------------------------------

class TestDomainNeqAssertions:
    def test_is_non_empty_tuple(self):
        assert isinstance(DOMAIN_NEQ_ASSERTIONS, tuple)
        assert len(DOMAIN_NEQ_ASSERTIONS) > 0

    def test_all_entries_contain_neq_operator(self):
        for entry in DOMAIN_NEQ_ASSERTIONS:
            assert "!=" in entry, f"Entry missing !=: {entry!r}"

    def test_all_entries_use_arcs_verify_prefix(self):
        for entry in DOMAIN_NEQ_ASSERTIONS:
            assert entry.startswith("arcs_verify:"), (
                f"All L11 NEQ assertions must start with 'arcs_verify:': {entry!r}"
            )

    def test_contains_verification_neq_truth(self):
        assert any(
            "verification" in e and "truth" in e for e in DOMAIN_NEQ_ASSERTIONS
        )

    def test_contains_valid_signature_neq_trusted_issuer(self):
        assert any(
            "valid_signature" in e and "trusted_issuer" in e for e in DOMAIN_NEQ_ASSERTIONS
        )

    def test_contains_not_evaluated_neq_pass(self):
        assert any(
            "not_evaluated" in e and "pass" in e for e in DOMAIN_NEQ_ASSERTIONS
        )

    def test_contains_emitter_assertion_neq_recomputed_finding(self):
        assert any(
            "emitter_assertion" in e and "independently_recomputed_finding" in e
            for e in DOMAIN_NEQ_ASSERTIONS
        )

    def test_contains_independent_verifier_neq_emitter(self):
        assert any(
            "independent_verifier" in e and "dagr:emitter" in e
            for e in DOMAIN_NEQ_ASSERTIONS
        )


# ---------------------------------------------------------------------------
# verify_dagr_receipt carries dagr_constitution_id
# ---------------------------------------------------------------------------

def _minimal_receipt():
    """Minimal valid-looking receipt for verify_dagr_receipt input."""
    return {
        "schema": "dagr.receipt/v0.1",
        "decision": {
            "domain": "evidence",
            "state": "SUPPORTED",
            "decision_digest": "sha256:" + "a" * 64,
        },
        "receipt_digest": "sha256:" + "b" * 64,
    }


class TestVerifyDagrReceiptCarriesConstitutionId:
    def test_result_has_dagr_constitution_id_key(self):
        result = verify_dagr_receipt(_minimal_receipt())
        assert "dagr_constitution_id" in result

    def test_result_value_matches_constant(self):
        result = verify_dagr_receipt(_minimal_receipt())
        assert result["dagr_constitution_id"] == DAGR_CONSTITUTIONAL_CONTRACT_ID

    def test_result_value_is_canonical_string(self):
        result = verify_dagr_receipt(_minimal_receipt())
        assert result["dagr_constitution_id"] == "dagr.constitutional-contract.v0.1"

    def test_existing_five_findings_still_present(self):
        result = verify_dagr_receipt(_minimal_receipt())
        for key in ("schema_matches", "domain_qualified", "decision_domain_matches",
                    "digest_algorithm_valid", "receipt_digest_match"):
            assert key in result, f"Pre-existing key {key!r} missing from result"

    def test_constitution_id_is_not_a_finding_value(self):
        result = verify_dagr_receipt(_minimal_receipt())
        assert result["dagr_constitution_id"] not in (True, False, "not_evaluated", "not_applicable")

    def test_constitution_id_consistent_across_calls(self):
        r1 = verify_dagr_receipt(_minimal_receipt())
        r2 = verify_dagr_receipt({})
        assert r1["dagr_constitution_id"] == r2["dagr_constitution_id"]
