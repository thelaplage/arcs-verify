"""The lane's named negative cases, end to end through consume_observation.

SYNTHETIC observations, test-double validator. Each row states where the run must stop (or
that it must complete with a typed not-evaluated axis) and whether the native validator may
have been invoked at all."""
import pytest

from arcs_verify import c2pa_srs_observed as adapter

from . import material as m

GOOD_SIG = {"algorithm": "Ed25519", "canonicalization": "RFC8785-JCS", "key_id": "synthetic-key-id", "signature": "c2lnbmF0dXJl"}


def altered_asset_case():
    return m.synthetic_observation(), m.evidence_for(asset=m.SYNTHETIC_OTHER_ASSET)


def altered_report_case():
    return m.synthetic_observation(), m.evidence_for(m.REPORT_INVALID_CLAIM)


def swapped_report_other_asset_case():
    # The retained report belongs to a different asset's observation.
    other = m.synthetic_observation(m.REPORT_TRUSTED_ALLOWED, asset=m.SYNTHETIC_OTHER_ASSET)
    return other, m.evidence_for(m.REPORT_VALID_UNTRUSTED, asset=m.SYNTHETIC_OTHER_ASSET)


def profile_violation_case():
    return m.mutated(m.synthetic_observation(), "native_report.verdict_source", "process_exit_code"), m.evidence_for()


def unknown_field_case():
    return m.mutated(m.synthetic_observation(), "x_unmapped_extra", {"anything": 1}), m.evidence_for()


def producer_trust_without_basis_case():
    return m.mutated(m.synthetic_observation(), "signer_trust.trust_observation", "trusted"), m.evidence_for()


def unmapped_trust_basis_case():
    obs = m.synthetic_observation()
    obs["signer_trust"].update(trust_basis="official_trust_list", trust_observation="untrusted")
    obs["signer_trust"]["trust_material_refs"] = [
        {"role": "trust_anchors", "digest": m.ANCHORS_DIGEST, "source_identity": "SYNTHETIC", "source_pin": "pin-0001"}
    ]
    return obs, m.evidence_for()


ROWS = [
    ("asset digest mismatch", altered_asset_case, "input_correspondence", "CORR_ASSET_DIGEST_MISMATCH"),
    ("native report digest mismatch", altered_report_case, "input_correspondence", "CORR_NATIVE_REPORT_DIGEST_MISMATCH"),
    ("report swapped from another asset", swapped_report_other_asset_case, "input_correspondence", "CORR_NATIVE_REPORT_DIGEST_MISMATCH"),
    ("profile violation", profile_violation_case, "profile_conformance", "EXIT_CODE_AS_VERDICT"),
    ("unknown / extra field", unknown_field_case, "profile_conformance", "ADAPTER_UNKNOWN_FIELD"),
    ("producer-asserted trust with no trust basis", producer_trust_without_basis_case, "profile_conformance", "TRUST_OBSERVATION_WITHOUT_BASIS"),
]


@pytest.mark.parametrize("label,case,stopped_at,code", ROWS, ids=[r[0] for r in ROWS])
def test_refused_before_any_recomputation(tmp_path, label, case, stopped_at, code):
    obs, evidence = case()
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (m.REPORT_VALID_UNTRUSTED, 0), m.SYNTHETIC_OTHER_ASSET: (m.REPORT_VALID_UNTRUSTED, 0)})
    result = adapter.consume_observation(m.encode(obs), evidence, executable=fake.path)
    assert result.stopped_at == stopped_at
    assert code in {r.code for r in result.stages[stopped_at].refusals}
    assert fake.calls() == []  # the native validator was never invoked
    assert result.report["axes"]["independent_comparison"]["status"] == "not_run"
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []
    assert result.report["axes"]["srs_receipt_authentication"]["issuance_authentication"] == "not_evaluated"


def test_signature_field_present_but_unverifiable_completes_with_signature_axes_not_evaluated(tmp_path):
    obs = m.mutated(m.synthetic_observation(), "receipt_signature", GOOD_SIG)
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (m.REPORT_VALID_UNTRUSTED, 0)})
    result = adapter.consume_observation(m.encode(obs), m.evidence_for(), executable=fake.path)
    assert result.stopped_at is None
    auth = result.report["axes"]["srs_receipt_authentication"]
    assert auth["receipt_signature_present"] is True
    assert (auth["signature_valid"], auth["key_resolved"], auth["key_trusted"], auth["issuance_authentication"]) == ("not_evaluated",) * 4


def test_native_invalid_with_process_exit_zero_never_reads_as_satisfied(tmp_path):
    obs = m.synthetic_observation(m.REPORT_INVALID_CLAIM, exit_code=0)
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (m.REPORT_INVALID_CLAIM, 0)})
    result = adapter.consume_observation(m.encode(obs), m.evidence_for(m.REPORT_INVALID_CLAIM), executable=fake.path)
    claim = {a["axis"]: a for a in result.report["axes"]["independent_comparison"]["per_axis"]}["claim_signature"]
    assert (claim["observed_status"], claim["recomputed_status"]) == ("failed", "failed")


def test_missing_manifest_store_leaves_the_comparison_not_evaluated(tmp_path):
    fake = m.install_fake_validator(tmp_path, {})
    result = adapter.consume_observation(m.encode(m.synthetic_observation()), m.evidence_for(), executable=fake.path)
    assert result.stages["comparison"].status == "not_evaluated"
    assert result.report["axes"]["independent_comparison"]["status"] == "not_evaluated"


# -- a report that belongs to a different asset than the digests name --------------------------
#
# Report-to-asset binding is caller-composed on the producer side: a producer can pair an
# unrelated native report with an asset and name both digests correctly. Correspondence cannot
# see this (the digests do match the retained bytes). The verifier's own recomputation over the
# frozen asset is the control; the outcome must be a divergence or a non-evaluation, never a match.


def test_foreign_invalid_report_paired_with_the_named_asset_is_a_mismatch_never_a_match(tmp_path):
    obs = m.synthetic_observation(m.REPORT_INVALID_CLAIM, asset=m.SYNTHETIC_ASSET)  # names asset A, carries another asset's Invalid report
    evidence = m.evidence_for(m.REPORT_INVALID_CLAIM, asset=m.SYNTHETIC_ASSET)
    assert adapter._stage_correspondence(obs, evidence)[1].status == "completed"  # the gap correspondence cannot close
    fake = m.install_fake_validator(
        tmp_path,
        {m.SYNTHETIC_ASSET: (m.REPORT_VALID_UNTRUSTED, 0), m.SYNTHETIC_OTHER_ASSET: (m.REPORT_INVALID_CLAIM, 0)},
    )
    result = adapter.consume_observation(m.encode(obs), evidence, executable=fake.path)
    assert result.stopped_at is None  # the comparison ran, on the verifier's own recomputation
    axes = {a["axis"]: a for a in result.report["axes"]["independent_comparison"]["per_axis"]}
    claim = axes["claim_signature"]
    assert claim["state"] == "mismatch" and claim["integrity_posture"] == "possible_substantive_divergence"
    assert (claim["observed_status"], claim["recomputed_status"]) == ("failed", "satisfied")
    assert result.report["axes"]["native_failure_codes"]["only_in_observed"] == ["claimSignature.mismatch"]
    states = result.report["axes"]["native_validation_state"]
    assert (states["observed_verbatim"], states["recomputed_verbatim"]) == ("Invalid", "Valid")
    # the report the producer retained was never used as the independent result
    assert result.report["native_recomputation"]["recomputed"]["evidence_class"] == "live_native_invocation"


def test_foreign_valid_report_paired_with_an_asset_that_really_fails_is_a_mismatch_never_a_match(tmp_path):
    obs = m.synthetic_observation(m.REPORT_VALID_UNTRUSTED, asset=m.SYNTHETIC_ASSET)  # producer-side Valid report
    evidence = m.evidence_for(m.REPORT_VALID_UNTRUSTED, asset=m.SYNTHETIC_ASSET)
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (m.REPORT_INVALID_CLAIM, 0)})  # the asset really fails
    result = adapter.consume_observation(m.encode(obs), evidence, executable=fake.path)
    claim = {a["axis"]: a for a in result.report["axes"]["independent_comparison"]["per_axis"]}["claim_signature"]
    assert claim["state"] == "mismatch" and (claim["observed_status"], claim["recomputed_status"]) == ("satisfied", "failed")


def test_foreign_report_paired_with_an_asset_the_verifier_cannot_evaluate_is_not_evaluated_never_a_match(tmp_path):
    obs = m.synthetic_observation(m.REPORT_INVALID_CLAIM, asset=m.SYNTHETIC_ASSET)
    fake = m.install_fake_validator(tmp_path, {})  # the verifier's own run produces no report for the asset
    result = adapter.consume_observation(m.encode(obs), m.evidence_for(m.REPORT_INVALID_CLAIM), executable=fake.path)
    assert result.stages["comparison"].status == "not_evaluated"
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []
    assert result.report["native_comparison_report"] is None


def test_no_axis_whose_statuses_differ_is_ever_reported_as_a_match(tmp_path):
    obs = m.synthetic_observation(m.REPORT_INVALID_CLAIM, asset=m.SYNTHETIC_ASSET)
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (m.REPORT_TRUSTED_ALLOWED, 0)})
    result = adapter.consume_observation(m.encode(obs), m.evidence_for(m.REPORT_INVALID_CLAIM), executable=fake.path)
    entries = result.report["axes"]["independent_comparison"]["per_axis"]
    assert entries
    assert not [e for e in entries if e["state"] == "match" and e["observed_status"] != e["recomputed_status"]]
    assert [e["axis"] for e in entries if e["state"] == "mismatch"]  # and at least one real divergence is named


def test_unmappable_observed_side_still_gets_an_independent_recomputation(tmp_path):
    """A trust basis with no canonical mode refuses the OBSERVED side only. The verifier's own run
    over the frozen inputs does not depend on the producer's claims, so it still happens and is
    reported on its own; there is simply nothing canonical to compare it with."""
    obs, evidence = unmapped_trust_basis_case()
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (m.REPORT_VALID_UNTRUSTED, 0)})
    result = adapter.consume_observation(m.encode(obs), evidence, executable=fake.path)
    assert result.stages["observed_finding_construction"].status == "refused"
    assert "MAP_TRUST_BASIS_UNMAPPED" in {r.code for r in result.stages["observed_finding_construction"].refusals}
    assert result.stages["native_recomputation"].status == "completed"
    assert result.stages["comparison"].status == "not_evaluated"
    assert [r.code for r in result.stages["comparison"].refusals] == ["COMPARISON_OBSERVED_SIDE_NOT_CONSTRUCTED"]
    assert len(fake.calls()) == 1
    recomputation = result.report["axes"]["independent_recomputation"]
    assert recomputation["evaluation_status"] == "evaluated"
    assert {a["axis"]: a["recomputed_status"] for a in recomputation["per_axis"]}["claim_signature"] == "satisfied"
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []
