"""Independent-verifier tests for the EXIT-O origin-authentication proof.

Fixtures under tests/fixtures/exit_o/ are literal producer bytes from
arcs-srs@11db54bb (see PROVENANCE.md); hostile variants are derived in-test.
The verifier imports no producer code.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from arcs_verify.exit_o_origin_authentication import (
    PROFILE_DOCUMENT_SHA256,
    PROFILE_SCHEMA_BLOB_SHA1,
    VERDICT_FAIL,
    VERDICT_NOT_EVALUATED,
    VERDICT_PASS,
    VERDICT_UNAVAILABLE,
    ExitOOriginAuthenticationVerificationReport,
    verify_exit_o_origin_authentication_receipt,
)

_FX = Path(__file__).resolve().parent / "fixtures" / "exit_o"


def _load(name: str) -> dict:
    return json.loads((_FX / name).read_text(encoding="utf-8"))


def _partial() -> dict:
    return _load("origin-auth-partial-honest.json")


# --- pinned authority --------------------------------------------------------

def test_vendored_schema_matches_pin():
    schema = (
        Path(__file__).resolve().parent.parent
        / "arcs_verify"
        / "data"
        / "srs.activity.semantic_issuer_origin_authentication.v0.1.schema.json"
    ).read_bytes()
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(schema))
    h.update(schema)
    assert h.hexdigest() == PROFILE_SCHEMA_BLOB_SHA1


def test_report_pins_are_stable():
    assert PROFILE_DOCUMENT_SHA256.startswith("85dd6a9b")


# --- structural findings the verifier recomputes -----------------------------

def test_literal_producer_receipt_conforms_and_binds():
    r = verify_exit_o_origin_authentication_receipt(_partial())
    assert r.profile_schema_pinned is True
    assert r.proof_receipt_conformance is True
    assert r.exact_semantic_disposition_binding is True
    assert r.temporal_consistency_finding == VERDICT_PASS


# --- the load-bearing rule: bytes/digest != semantic verification ------------

def test_partial_honest_proof_never_satisfies_chain():
    # A well-formed, correctly-bound proof still does NOT satisfy the chain,
    # because no governed verifier exists for the semantic layers.
    r = verify_exit_o_origin_authentication_receipt(_partial())
    assert r.exit_o_chain_satisfied is False
    for f in (
        "key_authentication_finding",
        "act_principal_finding",
        "semantic_authority_finding",
        "semantic_act_finding",
    ):
        assert getattr(r, f) in {VERDICT_UNAVAILABLE, VERDICT_NOT_EVALUATED}
        assert getattr(r, f) != VERDICT_PASS


def test_all_positive_producer_postures_never_become_passes():
    # Even the all-positive producer fixture (every layer posture "positive")
    # must not yield layer passes: postures are not verifier findings.
    r = verify_exit_o_origin_authentication_receipt(
        _load("origin-auth-all-positive-no-aggregate.json")
    )
    assert r.exit_o_chain_satisfied is False
    for f in (
        "key_authentication_finding",
        "act_principal_finding",
        "semantic_authority_finding",
        "semantic_act_finding",
    ):
        assert getattr(r, f) != VERDICT_PASS


def test_supplied_evidence_bytes_are_hashed_independently_not_trusted():
    r = _partial()
    evidence = b"literal key-authentication evidence bytes"
    r["key_authentication"]["binding_digest"] = (
        "sha256:" + hashlib.sha256(evidence).hexdigest()
    )
    report = verify_exit_o_origin_authentication_receipt(
        r, supplied_evidence_bytes={"key_authentication": evidence}
    )
    # independently recomputed digest matches -> integrity only; semantic
    # authentication still requires a governed upstream verifier.
    assert report.key_authentication_finding == VERDICT_NOT_EVALUATED
    assert report.key_authentication_finding != VERDICT_PASS


def test_caller_asserted_digest_string_is_not_accepted_as_evidence_bytes():
    r = _partial()
    report = verify_exit_o_origin_authentication_receipt(
        r,
        supplied_evidence_bytes={
            "key_authentication": r["key_authentication"]["binding_digest"]  # type: ignore[dict-item]
        },
    )
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "layer_evidence_bytes_invalid:key_authentication" in c
        for c in report.failure_codes
    )


def test_missing_evidence_becomes_unavailable_not_pass():
    r = verify_exit_o_origin_authentication_receipt(_partial())  # no evidence supplied
    assert r.act_principal_finding == VERDICT_UNAVAILABLE
    assert r.act_principal_finding != VERDICT_PASS


# --- enumerated failure modes ------------------------------------------------

def test_binding_byte_substitution_fails():
    r = _partial()
    expected = b"expected evidence bytes"
    supplied = b"substituted evidence bytes"
    r["key_authentication"]["binding_digest"] = (
        "sha256:" + hashlib.sha256(expected).hexdigest()
    )
    report = verify_exit_o_origin_authentication_receipt(
        r, supplied_evidence_bytes={"key_authentication": supplied}
    )
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "layer_evidence_digest_mismatch:key_authentication" in c
        for c in report.failure_codes
    )


def test_wrong_profile_or_version_refused():
    r = _partial()
    r["profile_version"] = "v9.9"
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.proof_receipt_conformance is False
    assert any("wrong_profile_or_version" in c for c in report.failure_codes)


def test_exact_act_substitution_fails():
    r = _partial()
    r["semantic_act"]["binding_digest"] = "sha256:" + "a" * 63 + "b"
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.exact_semantic_disposition_binding is False
    assert any("exact_act_binding_mismatch" in c for c in report.failure_codes)


def test_attestation_time_mismatch_fails():
    r = _partial()
    r["present_attestation_time"] = "2099-01-01T00:00:00Z"  # != issued_at
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.temporal_consistency_finding == VERDICT_FAIL
    assert any("attestation_time_mismatch" in c for c in report.failure_codes)


def test_historical_not_before_present_fails():
    r = _partial()
    # make historical == present == issued_at (collapse the temporal order)
    r["historical_act_time"] = r["present_attestation_time"]
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.temporal_consistency_finding == VERDICT_FAIL


def test_temporal_order_uses_instants_not_lexicographic_strings():
    r = _partial()
    # 01:00+01:00 == 00:00Z, which is before the 00:10Z attestation.
    # Lexicographic comparison would get this wrong.
    r["historical_act_time"] = "2026-09-22T01:00:00+01:00"
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.temporal_consistency_finding == VERDICT_PASS


def test_temporal_order_refuses_later_instant_hidden_by_offset():
    r = _partial()
    # 00:05-01:00 == 01:05Z, which is AFTER 00:10Z even though its
    # literal clock string sorts before "00:10".
    r["historical_act_time"] = "2026-09-22T00:05:00-01:00"
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.temporal_consistency_finding == VERDICT_FAIL
    assert any("historical_not_before_present" in c for c in report.failure_codes)


def test_historical_scope_interval_excluding_attestation_fails():
    r = _partial()
    hsa = r.get("historical_scope_authorization")
    assert isinstance(hsa, dict), "producer fixture must carry historical_scope_authorization"
    hsa["effective_interval"] = {
        "effective_not_before": "1999-01-01T00:00:00Z",
        "effective_not_after": "1999-12-31T00:00:00Z",
    }
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.historical_scope_authorization_finding == VERDICT_FAIL


def test_historical_scope_same_string_as_actor_fails():
    r = _partial()
    hsa = r["historical_scope_authorization"]
    hsa["binding_ref"] = r["historical_actor_ref"]  # same-string != continuity
    # keep the interval covering attestation so we isolate the same-string rule
    hsa["effective_interval"] = {
        "effective_not_before": "2000-01-01T00:00:00Z",
        "effective_not_after": "2100-01-01T00:00:00Z",
    }
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.historical_scope_authorization_finding == VERDICT_FAIL
    assert any("same_string_as_actor" in c for c in report.failure_codes)


def test_historical_scope_structural_ok_is_not_evaluated_not_pass():
    r = _partial()
    hsa = r["historical_scope_authorization"]
    hsa["binding_ref"] = "urn:governed:historical-scope-auth/independent-basis"
    hsa["effective_interval"] = {
        "effective_not_before": "2000-01-01T00:00:00Z",
        "effective_not_after": "2100-01-01T00:00:00Z",
    }
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.historical_scope_authorization_finding == VERDICT_NOT_EVALUATED
    assert report.historical_scope_authorization_finding != VERDICT_PASS


def test_historical_scope_open_ended_interval_is_valid_shape():
    r = _partial()
    hsa = r["historical_scope_authorization"]
    hsa["binding_ref"] = "urn:governed:historical-scope-auth/open-ended"
    hsa["effective_interval"] = {
        "effective_not_before": "2026-09-01T00:00:00Z"
    }
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.proof_receipt_conformance is True
    assert report.historical_scope_authorization_finding == VERDICT_NOT_EVALUATED


def test_historical_scope_copied_scope_mismatch_fails_independently():
    r = _partial()
    # Shape remains schema-valid; equality to top-level is a checker/verifier
    # invariant that JSON Schema cannot express.
    r["historical_scope_authorization"]["authority_domain"] = "different_domain"
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.proof_receipt_conformance is True
    assert report.historical_scope_authorization_finding == VERDICT_FAIL
    assert any("historical_scope_mismatch" in c for c in report.failure_codes)


def test_semantic_authority_scope_replay_fails_independently():
    r = _partial()
    r["semantic_authority"]["semantic_issuer_ref"] = "urn:actor:different-issuer"
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.proof_receipt_conformance is True
    assert report.semantic_authority_finding == VERDICT_FAIL
    assert any("semantic_authority_scope_mismatch" in c for c in report.failure_codes)


def test_signature_absent_fails_present_shape_is_not_evaluated():
    r = _partial()
    r.pop("receipt_signature", None)
    report = verify_exit_o_origin_authentication_receipt(r)
    assert report.proof_receipt_signature == VERDICT_FAIL
    r2 = _partial()
    report2 = verify_exit_o_origin_authentication_receipt(r2)  # no trust bundle
    assert report2.proof_receipt_signature == VERDICT_NOT_EVALUATED
    assert report2.proof_receipt_signature != VERDICT_PASS


def test_overall_requires_structural_and_substantive_gates():
    from arcs_verify import exit_o_origin_authentication as mod

    rep = ExitOOriginAuthenticationVerificationReport(
        profile_schema_pinned=True,
        proof_receipt_conformance=True,
        exact_semantic_disposition_binding=True,
    )
    for name in mod._REQUIRED_SUBSTANTIVE:
        setattr(rep, name, VERDICT_PASS)

    assert mod._compute_exit_o_chain_satisfied(rep) is True

    rep.key_authentication_finding = VERDICT_NOT_EVALUATED
    assert mod._compute_exit_o_chain_satisfied(rep) is False
    rep.key_authentication_finding = VERDICT_PASS

    rep.proof_receipt_conformance = False
    assert mod._compute_exit_o_chain_satisfied(rep) is False
    rep.proof_receipt_conformance = True

    rep.exact_semantic_disposition_binding = False
    assert mod._compute_exit_o_chain_satisfied(rep) is False
    rep.exact_semantic_disposition_binding = True

    rep.profile_schema_pinned = False
    assert mod._compute_exit_o_chain_satisfied(rep) is False


def test_no_producer_import():
    # Issuer/verifier separation: the verifier module must not import producer
    # packages.
    import arcs_verify.exit_o_origin_authentication as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in (
        "import arcs_srs",
        "from arcs_srs",
        "import arcs_amnesiac",
        "from arcs_amnesiac",
        "import counterpedia",
        "import dagr_runtime",
        "from dagr_runtime",
        "import garp_core",
    ):
        assert banned not in src, f"producer import leaked: {banned}"


def test_substantive_domain_values_only():
    r = verify_exit_o_origin_authentication_receipt(_partial())
    from arcs_verify.exit_o_origin_authentication import SUBSTANTIVE_DOMAIN

    for name in (
        "proof_receipt_signature",
        "key_authentication_finding",
        "act_principal_finding",
        "semantic_authority_finding",
        "semantic_act_finding",
        "historical_scope_authorization_finding",
        "temporal_consistency_finding",
    ):
        assert getattr(r, name) in SUBSTANTIVE_DOMAIN


def test_golden_report_is_reproduced():
    """The committed golden report must equal the verifier's actual output on the
    literal producer fixture — the report contract cannot drift from the code."""
    golden = json.loads(
        (
            Path(__file__).resolve().parent.parent
            / "arcs_verify"
            / "contracts"
            / "exit-o-origin-authentication-report-v0-1"
            / "golden"
            / "partial-honest-report.json"
        ).read_text(encoding="utf-8")
    )
    got = verify_exit_o_origin_authentication_receipt(_partial()).to_dict()
    assert got == golden
    assert "chain_status" not in got  # never reuse VerificationReport's field
