"""Independent-verifier tests for the EXIT-O origin-authentication proof.

Fixtures under tests/fixtures/exit_o/ are literal producer bytes from
arcs-srs@11db54bb (see PROVENANCE.md); hostile variants are derived in-test.
The verifier imports no producer code.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

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


def test_report_schema_is_closed_and_golden_conforms():
    import jsonschema

    contract_dir = (
        Path(__file__).resolve().parent.parent
        / "arcs_verify"
        / "contracts"
        / "exit-o-origin-authentication-report-v0-1"
    )
    schema = json.loads((contract_dir / "verification-report.schema.json").read_text())
    golden = json.loads(
        (contract_dir / "golden" / "partial-honest-report.json").read_text()
    )

    jsonschema.Draft202012Validator(schema).validate(golden)
    assert schema["additionalProperties"] is False
    assert "profile_schema_sha256" in schema["required"]
    assert "profile_document_sha256" in schema["required"]
    assert "chain_status" not in schema["properties"]

    hostile = copy.deepcopy(golden)
    hostile["chain_status"] = "not_applicable"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(hostile)


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


# --- EXIT-O SUBSTANTIVE ADAPTER (#94 step 10): trust-bundle signature +
# key-authentication recomputation. All keys here are ephemeral fixture
# Ed25519 keys generated in-test with `cryptography`; no dagr-runtime
# producer code is imported anywhere in this file.

_FIXTURE_KEY_ID = "issuer.test/semantic-issuer-origin-auth/2026-01"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _signed_receipt_and_pem():
    """A literal-shaped positive-fixture receipt, deep-copied and re-signed
    in-test with a freshly generated ephemeral Ed25519 key. Returns
    (receipt, public_key_pem_str, private_key)."""
    receipt = _load("origin-auth-all-positive-no-aggregate.json")
    # The upstream producer fixture predates the production relation scope.
    # Normalize only this in-test copy so a positive key binding must name
    # the exact attester/profile/domain the signed receipt names.
    receipt["authority_domain"] = "institutional_admission"
    receipt["semantic_authority"]["authority_domain"] = "institutional_admission"
    receipt["historical_scope_authorization"]["authority_domain"] = "institutional_admission"
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]
    canonical = rfc8785.dumps(preimage)
    signature = private_key.sign(canonical)
    receipt["receipt_signature"]["signature"] = _b64url_encode(signature)
    return receipt, pem, private_key


def _fixture_fingerprint(pem: str) -> str:
    """Independent in-test recomputation of the WIRE0 key fingerprint, built
    separately from (and not calling into) the verifier module's own
    recompute helper, so the test fixture and the code under test are not
    circularly defined."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(pem.encode("ascii"))
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    digest = hashlib.sha256(
        b"dagr.institutional_key_binding.fingerprint.v0.1:" + raw
    ).hexdigest()
    return f"keyfp:sha256:{digest}"


def _trust_bundle(
    pem: str,
    *,
    key_id: str = _FIXTURE_KEY_ID,
    allowed_profiles=None,
    not_before: str | None = "2026-01-01T00:00:00Z",
    not_after: str | None = "2027-01-01T00:00:00Z",
    revoked: bool = False,
    compromise: bool = False,
) -> dict:
    return {
        "bundle_version": "0.2",
        "bundle_id": "test-bundle-exit-o-0001",
        "bundle_digest": "sha256:" + "0" * 64,
        "issued_at": "2026-01-01T00:00:00Z",
        "keys": [
            {
                "key_id": key_id,
                "public_key_pem": pem,
                "purpose": ["signing"],
                "allowed_profiles": (
                    allowed_profiles
                    if allowed_profiles is not None
                    else [
                        "srs.activity.semantic_issuer_origin_authentication.v0.1"
                    ]
                ),
                "allowed_receipt_classes": ["provenance"],
                "not_before": not_before,
                "not_after": not_after,
                "institutional_authorization": {
                    "authorized_by": "test-owner",
                    "authorization_date": "2026-01-01T00:00:00Z",
                    "authorization_ref": None,
                },
                "revocation": {
                    "revoked": revoked,
                    "revoked_at": "2026-06-01T00:00:00Z" if revoked else None,
                    "revocation_reason": "test-revocation" if revoked else None,
                    "compromise": compromise,
                },
            }
        ],
    }


def _key_principal_binding(
    pem: str,
    *,
    key_id: str = _FIXTURE_KEY_ID,
    fingerprint: str | None = None,
    authority_domain: str = "institutional_admission",
    relation_purpose: str = "semantic-origin-authentication",
    actor_ref: str = "urn:participant:present/attester-1",
    semantic_authority_profile_ref: str = "urn:authority-profile:test/memory-admission/v0.1",
    genesis_ref: str = "urn:genesis:test/0001",
    genesis_digest: str = "sha256:" + "9" * 64,
) -> dict:
    return {
        "schema": "dagr.institutional_key_principal_binding.v0.1",
        "binding_id": "binding-test-0001",
        "key_fingerprint": (
            fingerprint if fingerprint is not None else _fixture_fingerprint(pem)
        ),
        "key_id": key_id,
        "actor_ref": actor_ref,
        "semantic_authority_profile_ref": semantic_authority_profile_ref,
        "authority_domain": authority_domain,
        "relation_purpose": relation_purpose,
        "genesis_ref": genesis_ref,
        "genesis_digest": genesis_digest,
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": None,
        "producer_ref": "test-producer",
        "binding_digest": "sha256:" + "8" * 64,
    }


def _genesis_evidence(
    *,
    actor_ref: str = "urn:participant:present/attester-1",
    semantic_authority_profile_ref: str = "urn:authority-profile:test/memory-admission/v0.1",
    genesis_ref: str = "urn:genesis:test/0001",
    genesis_digest: str = "sha256:" + "9" * 64,
) -> dict:
    return {
        "actor_ref": actor_ref,
        "semantic_authority_profile_ref": semantic_authority_profile_ref,
        "genesis_ref": genesis_ref,
        "genesis_digest": genesis_digest,
    }


def test_valid_trust_bundle_and_binding_yield_passes():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(pem)
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle, key_principal_binding=binding
    )
    assert report.proof_receipt_signature == VERDICT_PASS
    assert report.key_authentication_finding == VERDICT_PASS
    assert report.failure_codes == []


def test_valid_trust_bundle_binding_and_genesis_evidence_yield_passes():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(pem)
    genesis = _genesis_evidence()
    report = verify_exit_o_origin_authentication_receipt(
        receipt,
        trust_bundle=bundle,
        key_principal_binding=binding,
        genesis_evidence=genesis,
    )
    assert report.proof_receipt_signature == VERDICT_PASS
    assert report.key_authentication_finding == VERDICT_PASS


def test_genesis_evidence_mismatch_fails_key_authentication():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(pem)
    genesis = _genesis_evidence(actor_ref="urn:actor:different/actor")
    report = verify_exit_o_origin_authentication_receipt(
        receipt,
        trust_bundle=bundle,
        key_principal_binding=binding,
        genesis_evidence=genesis,
    )
    assert report.proof_receipt_signature == VERDICT_PASS
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "key_authentication_genesis_mismatch" in c for c in report.failure_codes
    )


def test_tampered_signature_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    # Flip one byte of the (decoded) signature.
    raw_sig = base64.urlsafe_b64decode(
        receipt["receipt_signature"]["signature"]
        + "=" * (-len(receipt["receipt_signature"]["signature"]) % 4)
    )
    tampered = bytes([raw_sig[0] ^ 0xFF]) + raw_sig[1:]
    receipt["receipt_signature"]["signature"] = _b64url_encode(tampered)
    bundle = _trust_bundle(pem)
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    assert report.proof_receipt_signature == VERDICT_FAIL
    assert any("signature_invalid" in c for c in report.failure_codes)
    assert report.key_authentication_finding == VERDICT_FAIL


def test_tampered_receipt_body_fails_signature():
    receipt, pem, _ = _signed_receipt_and_pem()
    receipt["subject_ref"] = "urn:amnesiac.disposition:reject/candidate-tampered-0099"
    bundle = _trust_bundle(pem)
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    assert report.proof_receipt_signature == VERDICT_FAIL
    assert any("signature_invalid" in c for c in report.failure_codes)


def test_fingerprint_mismatch_binding_fails_key_authentication():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    # Binding asserts a fingerprint belonging to a DIFFERENT key.
    other_pem = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    binding = _key_principal_binding(pem, fingerprint=_fixture_fingerprint(other_pem))
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle, key_principal_binding=binding
    )
    assert report.proof_receipt_signature == VERDICT_PASS
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "key_authentication_fingerprint_mismatch" in c for c in report.failure_codes
    )


def test_key_id_absent_from_bundle_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem, key_id="some-other-key-id")
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    assert report.proof_receipt_signature == VERDICT_FAIL
    assert any("signature_key_id_unresolved" in c for c in report.failure_codes)
    assert report.key_authentication_finding == VERDICT_FAIL


def test_revoked_entry_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem, revoked=True)
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    assert report.proof_receipt_signature == VERDICT_FAIL
    assert any("signature_key_revoked" in c for c in report.failure_codes)


def test_compromised_entry_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem, compromise=True)
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    assert report.proof_receipt_signature == VERDICT_FAIL
    assert any("signature_key_compromised" in c for c in report.failure_codes)


def test_issued_at_outside_validity_window_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    # The fixture's issued_at is 2026-09-22; shrink the window to exclude it.
    bundle = _trust_bundle(
        pem,
        not_before="2020-01-01T00:00:00Z",
        not_after="2021-01-01T00:00:00Z",
    )
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    assert report.proof_receipt_signature == VERDICT_FAIL
    assert any(
        "signature_key_outside_validity_window" in c for c in report.failure_codes
    )


def test_not_after_is_exclusive_boundary():
    receipt, pem, _ = _signed_receipt_and_pem()
    # not_after exactly equal to issued_at: the window is [not_before, not_after)
    # so issued_at == not_after must fail.
    bundle = _trust_bundle(pem, not_after=receipt["issued_at"])
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    assert report.proof_receipt_signature == VERDICT_FAIL
    assert any(
        "signature_key_outside_validity_window" in c for c in report.failure_codes
    )


def test_profile_not_in_allowed_profiles_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem, allowed_profiles=["some.other.profile.v9.9"])
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    assert report.proof_receipt_signature == VERDICT_FAIL
    assert any(
        "signature_key_profile_not_allowed" in c for c in report.failure_codes
    )


def test_no_trust_bundle_stays_not_evaluated():
    receipt, _pem, _ = _signed_receipt_and_pem()
    report = verify_exit_o_origin_authentication_receipt(receipt)
    assert report.proof_receipt_signature == VERDICT_NOT_EVALUATED
    # key_authentication is UNAVAILABLE here because no
    # supplied_evidence_bytes["key_authentication"] was given either -- this
    # is the pre-existing generic-layer baseline, unrelated to the new seam.
    assert report.key_authentication_finding == VERDICT_UNAVAILABLE
    assert report.key_authentication_finding != VERDICT_PASS


def test_binding_evidence_absent_key_authentication_never_upgraded_to_pass():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle
    )
    # signature genuinely passes, but with no binding evidence at all,
    # key_authentication must never be upgraded to pass -- it stays at
    # whatever the generic evidence-layer baseline already was (unavailable,
    # since no supplied_evidence_bytes["key_authentication"] was given).
    assert report.proof_receipt_signature == VERDICT_PASS
    assert report.key_authentication_finding == VERDICT_UNAVAILABLE
    assert report.key_authentication_finding != VERDICT_PASS


def test_binding_key_id_mismatch_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(pem, key_id="a-different-key-id")
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle, key_principal_binding=binding
    )
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "key_authentication_binding_key_id_mismatch" in c
        for c in report.failure_codes
    )


def test_binding_authority_domain_mismatch_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(pem, authority_domain="wrong_domain")
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle, key_principal_binding=binding
    )
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "key_authentication_binding_domain_mismatch" in c
        for c in report.failure_codes
    )


def test_binding_relation_purpose_mismatch_fails():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(pem, relation_purpose="wrong-purpose")
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle, key_principal_binding=binding
    )
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "key_authentication_binding_purpose_mismatch" in c
        for c in report.failure_codes
    )


def test_binding_actor_must_equal_receipt_present_attester():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(pem, actor_ref="urn:actor:someone-else")
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle, key_principal_binding=binding
    )
    assert report.proof_receipt_signature == VERDICT_PASS
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "key_authentication_binding_attester_mismatch" in c
        for c in report.failure_codes
    )


def test_binding_profile_must_equal_receipt_semantic_authority_profile():
    receipt, pem, _ = _signed_receipt_and_pem()
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(
        pem, semantic_authority_profile_ref="urn:authority-profile:wrong/v9"
    )
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle, key_principal_binding=binding
    )
    assert report.proof_receipt_signature == VERDICT_PASS
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "key_authentication_binding_profile_mismatch" in c
        for c in report.failure_codes
    )


def test_binding_domain_must_equal_receipt_authority_domain():
    receipt, pem, private_key = _signed_receipt_and_pem()
    # Keep the binding on the fixed production relation constant but change
    # only the signed receipt's scope. Re-sign so failure is the scope join,
    # not signature validity.
    receipt["authority_domain"] = "different_receipt_domain"
    receipt["semantic_authority"]["authority_domain"] = "different_receipt_domain"
    receipt["historical_scope_authorization"]["authority_domain"] = "different_receipt_domain"
    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]
    receipt["receipt_signature"]["signature"] = _b64url_encode(
        private_key.sign(rfc8785.dumps(preimage))
    )
    bundle = _trust_bundle(pem)
    binding = _key_principal_binding(pem)
    report = verify_exit_o_origin_authentication_receipt(
        receipt, trust_bundle=bundle, key_principal_binding=binding
    )
    assert report.proof_receipt_signature == VERDICT_PASS
    assert report.key_authentication_finding == VERDICT_FAIL
    assert any(
        "key_authentication_binding_receipt_domain_mismatch" in c
        for c in report.failure_codes
    )


def test_the_two_existing_exit_o_fixtures_are_unaffected_by_the_new_seam():
    """No trust_bundle/binding supplied -> byte-identical behavior to before
    the substantive adapter existed."""
    for name in (
        "origin-auth-all-positive-no-aggregate.json",
        "origin-auth-partial-honest.json",
    ):
        report = verify_exit_o_origin_authentication_receipt(_load(name))
        assert report.proof_receipt_signature == VERDICT_NOT_EVALUATED
        assert report.key_authentication_finding != VERDICT_PASS
        assert report.exit_o_chain_satisfied is False
