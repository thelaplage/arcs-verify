"""Conformance tests for the provisional EBC conformance harness.

NON-NORMATIVE / PROVISIONAL, same as the harness itself
(``arcs_verify.ebc_conformance``). These tests exercise
``verify_ebc_vector`` against fixture vectors under
``tests/fixtures/ebc-conformance/`` and assert PASS/FAIL/NOT_EVALUATED
conclusions -- never truth, admission, or standing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arcs_verify.ebc_conformance import EBCConclusion, verify_ebc_vector

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ebc-conformance"


def load(name: str) -> dict:
    return json.loads((FIXTURES_DIR / f"{name}.json").read_text())


def test_positive_vector_is_fully_reproducible() -> None:
    report = verify_ebc_vector(load("ebc-pos-001-valid"))
    assert report.reproducible is True
    assert report.findings == []
    assert report.horizon_digest_reproducible is EBCConclusion.TRUE
    assert report.context_digest_reproducible is EBCConclusion.TRUE
    assert report.omission_digest_reproducible is EBCConclusion.TRUE
    assert report.doctrine_manifest_digest_reproducible is EBCConclusion.TRUE
    assert report.boundary_digest_reproducible is EBCConclusion.TRUE
    assert report.boundary_references_consistent is EBCConclusion.TRUE
    assert report.commitment_digest_reproducible is EBCConclusion.TRUE
    assert report.commitment_has_precommit_reference is EBCConclusion.TRUE
    assert report.omission_binds_declared_horizon is EBCConclusion.TRUE
    assert report.horizon_no_out_of_scope_fields is EBCConclusion.TRUE
    assert report.all_digests_well_formed is EBCConclusion.TRUE
    assert report.witness_status == "present"


def test_reordered_fields_still_reproduce() -> None:
    """Canonicalization sorts keys; reordering top-level fields must not break it."""
    report = verify_ebc_vector(load("ebc-pos-002-reordered-fields"))
    assert report.reproducible is True
    assert report.findings == []


def test_mutated_context_digest_fails() -> None:
    report = verify_ebc_vector(load("ebc-neg-001-mutated-context-digest"))
    assert report.context_digest_reproducible is EBCConclusion.FALSE
    assert report.reproducible is False


def test_mutated_omission_reason_fails_omission_root() -> None:
    report = verify_ebc_vector(load("ebc-neg-002-mutated-omission-reason"))
    assert report.omission_digest_reproducible is EBCConclusion.FALSE
    assert report.reproducible is False


def test_mutated_horizon_fails() -> None:
    report = verify_ebc_vector(load("ebc-neg-003-mutated-horizon"))
    assert report.horizon_digest_reproducible is EBCConclusion.FALSE
    assert report.reproducible is False


def test_mutated_doctrine_manifest_digest_fails() -> None:
    report = verify_ebc_vector(load("ebc-neg-004-mutated-doctrine-manifest-digest"))
    assert report.doctrine_manifest_digest_reproducible is EBCConclusion.FALSE
    assert report.reproducible is False


def test_wrong_domain_prefix_fails_boundary_reproduction() -> None:
    report = verify_ebc_vector(load("ebc-neg-005-wrong-domain-prefix"))
    assert report.boundary_digest_reproducible is EBCConclusion.FALSE
    assert report.reproducible is False


def test_malformed_digest_format_fails() -> None:
    report = verify_ebc_vector(load("ebc-neg-006-malformed-digest-format"))
    assert report.all_digests_well_formed is EBCConclusion.FALSE
    assert report.reproducible is False


def test_standing_field_injected_into_horizon_is_flagged() -> None:
    report = verify_ebc_vector(load("ebc-neg-007-standing-field-injected"))
    assert report.horizon_no_out_of_scope_fields is EBCConclusion.FALSE
    codes = {f.code for f in report.findings}
    assert "horizon_out_of_scope_field" in codes
    assert report.reproducible is False


def test_incomplete_horizon_fails_completeness_check() -> None:
    report = verify_ebc_vector(load("ebc-neg-008-incomplete-horizon"))
    assert report.horizon_required_fields_present is EBCConclusion.FALSE
    assert report.reproducible is False


def test_commitment_without_precommit_reference_fails() -> None:
    report = verify_ebc_vector(load("ebc-neg-009-missing-precommit-reference"))
    assert report.commitment_has_precommit_reference is EBCConclusion.FALSE
    assert report.reproducible is False


def test_missing_sections_are_not_evaluated_not_coerced() -> None:
    """An absent section must never read as a silent PASS."""
    report = verify_ebc_vector({})
    assert report.horizon_digest_reproducible is EBCConclusion.NOT_EVALUATED
    assert report.context_digest_reproducible is EBCConclusion.NOT_EVALUATED
    assert report.omission_digest_reproducible is EBCConclusion.NOT_EVALUATED
    assert report.doctrine_manifest_digest_reproducible is EBCConclusion.NOT_EVALUATED
    assert report.boundary_digest_reproducible is EBCConclusion.NOT_EVALUATED
    assert report.commitment_digest_reproducible is EBCConclusion.NOT_EVALUATED
    assert report.all_digests_well_formed is EBCConclusion.NOT_EVALUATED
    assert report.witness_status == "absent"
    assert report.reproducible is False


@pytest.mark.parametrize(
    "name",
    [p.stem for p in sorted(FIXTURES_DIR.glob("*.json"))],
)
def test_every_fixture_matches_its_declared_expectation(name: str) -> None:
    vector = load(name)
    expected = vector["expected"]
    report = verify_ebc_vector(vector)
    if expected == "PASS":
        assert report.reproducible is True, f"{name}: expected PASS, findings={report.findings}"
    else:
        assert expected.startswith("FAIL:")
        check_name = expected.split(":", 1)[1]
        conclusion = getattr(report, check_name)
        assert conclusion is EBCConclusion.FALSE, f"{name}: expected {check_name} FALSE, got {conclusion}"
        assert report.reproducible is False


def test_report_to_dict_is_distinct_from_srs_verification_report() -> None:
    """Sanity guard: this report never claims the SRS VerificationReport schema/shape."""
    from arcs_verify.verifier import VerificationReport

    report = verify_ebc_vector(load("ebc-pos-001-valid"))
    payload = report.to_dict()
    assert payload["schema"] == "arcs.verify.ebc_conformance_report.v0.1.provisional"
    assert "passed" not in payload
    assert not isinstance(report, VerificationReport)
