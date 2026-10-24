"""Adversarial tests for the stranger0 receiver process.

Every negative family is paired with a positive control. Expectations are
written out in this file rather than read from stranger0/cases/cases.json.
Each failing check is asserted to fail for the stated reason: the exact set of
failed verifier checks, the verifier failure code, and the receiver reason token.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from stranger0_support import (
    CR, DEFAULT, PM, PV, REPO, S0, TRUST, Run, run_receiver,
)

SIGNATURE_ONLY = ["signature_valid"]
KEY_NOT_HELD = ["issuer_key_resolved", "issuer_key_trusted", "signature_valid"]


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    """Run the receiver process once per distinct (receipts, trust input) pair."""
    cache: dict[tuple, Run] = {}

    def _run(receipts, trust=DEFAULT) -> Run:
        key = (tuple(str(r) for r in receipts), str(trust))
        if key not in cache:
            result = run_receiver(list(receipts), trust, tmp_path_factory.mktemp("s0run"))
            assert result.proc.returncode == 0, result.proc.stderr
            cache[key] = result
        return cache[key]

    return _run


def assert_relied(result: Run, index: int = 0, claim: str | None = None) -> None:
    d = result.decisions[index]
    assert d["decision"] == "rely", d["reasons"]
    assert d["reasons"] == []
    assert result.report(index)["passed"] is True
    assert result.failed_checks(index) == []
    assert result.report(index)["chain_status"] == "not_applicable"
    if claim:
        assert d["reliance_claim"] == claim
    # reliance is scoped: the record states what it does NOT rely on
    assert "occurrence_of_the_real_world_event" in d["not_relied_upon"]
    assert "receiver_admission_of_the_underlying_action" in d["not_relied_upon"]


# --------------------------------------------------------------------------- controls
@pytest.mark.parametrize(
    "receipt, claim",
    [
        (PV("admission-admitted"), "issuer_attests_admission_disposition_admitted"),
        (PV("admission-refused"), "issuer_attests_admission_disposition_refused"),
        (PV("admission-deferred"), "issuer_attests_admission_disposition_deferred_for_review"),
        (PM("whitespace-reserialization-pass"), "issuer_attests_admission_disposition_admitted"),
        (PM("reordered-keys-pass"), "issuer_attests_admission_disposition_admitted"),
        (CR("s0-admitted-issuer-a"), "issuer_attests_admission_disposition_admitted"),
    ],
)
def test_positive_controls_are_relied_upon_with_scoped_claims(run, receipt, claim):
    assert_relied(run([receipt]), claim=claim)


# --------------------------------------------------------------------------- body tamper after signing
@pytest.mark.parametrize(
    "tampered, control",
    [
        (CR("n-tamper-refused-to-admitted"), PV("admission-refused")),
        (PM("semantic-field-change-fail"), PV("admission-admitted")),
        (PM("signature-bytes-fail"), PV("admission-admitted")),
        (PM("unknown-extension-added-fail"), PV("admission-admitted")),
    ],
)
def test_body_tamper_after_signing_fails_on_signature_alone(run, tampered, control):
    assert_relied(run([control]))
    bad = run([tampered])
    assert bad.decisions[0]["decision"] == "do_not_rely"
    assert bad.failed_checks() == SIGNATURE_ONLY            # nothing else broke
    assert bad.report()["failure_codes"] == ["signature_invalid"]
    assert bad.tokens() == ["verifier.not_passed"]
    assert bad.report()["issuer_key_trusted"] is True       # the key was fine; the content was not


def test_forged_refusal_to_admission_is_rejected_and_the_real_refusal_is_not_an_admission(run):
    real = run([PV("admission-refused")])
    forged = run([CR("n-tamper-refused-to-admitted")])
    assert real.decisions[0]["reliance_claim"].endswith("refused")
    assert forged.decisions[0]["decision"] == "do_not_rely"
    assert "reliance_claim" not in forged.decisions[0]
    assert forged.decisions[0]["receipt_declared_disposition"] == "admitted"  # declared by the receipt, not established


# --------------------------------------------------------------------------- wrong key
def test_wrong_key_under_a_trusted_key_id_fails_on_signature_alone(run):
    assert_relied(run([CR("s0-admitted-issuer-a")]))
    bad = run([CR("s0-wrong-key-claims-issuer-a")])
    assert bad.decisions[0]["decision"] == "do_not_rely"
    assert bad.failed_checks() == SIGNATURE_ONLY
    assert bad.report()["issuer_key_resolved"] is True and bad.report()["issuer_key_trusted"] is True
    assert bad.report()["failure_codes"] == ["signature_invalid"]


def test_pinned_unknown_key_id_is_unresolved(run):
    bad = run([PM("key-id-fail")])
    assert bad.decisions[0]["decision"] == "do_not_rely"
    assert bad.failed_checks() == KEY_NOT_HELD
    assert bad.report()["failure_codes"] == ["key_id_unresolved"]


# --------------------------------------------------------------------------- self-trust
def test_receipt_cannot_vouch_for_its_own_key(run, tmp_path):
    receipt = json.loads(CR("s0-selfclaimed-key").read_text())
    claimed = receipt["extensions"]["stranger0_claimed_issuer_key"]
    assert claimed["key_id"] == receipt["receipt_signature"]["key_id"]   # the receipt does carry a key claim
    assert receipt["issuer_id"] == "issuer:stranger0:synthetic-a"          # and names an issuer the receiver accepts

    bad = run([CR("s0-selfclaimed-key")])
    assert bad.decisions[0]["decision"] == "do_not_rely"
    assert bad.failed_checks() == KEY_NOT_HELD
    assert bad.report()["failure_codes"] == ["key_id_unresolved"]
    assert bad.tokens() == ["verifier.not_passed"]                         # policy was not the barrier: key trust was

    # control 1: same claim shape, claimed key is the one the receiver already holds
    assert_relied(run([CR("s0-claimed-key-trusted-issuer")]))
    # control 2 (counterfactual): the receiver itself adds that key; the same bytes are then fine.
    # This proves the receipt is well formed and validly signed under its own claimed key,
    # so trust-input membership is the only thing that separated rely from do_not_rely.
    counterfactual = run([CR("s0-selfclaimed-key")], TRUST("receiver-counterfactual-selftrust"))
    assert_relied(counterfactual)
    assert counterfactual.report()["signature_valid"] is True

    # the three runs share the very same receipt bytes only in the counterfactual pair
    assert bad.decisions[0]["receipt_bytes_sha256"] == counterfactual.decisions[0]["receipt_bytes_sha256"]


# --------------------------------------------------------------------------- receiver-supplied trust
def test_no_trust_anchors_means_no_reliance_on_the_same_bytes(run):
    assert_relied(run([PV("admission-admitted")]))
    bare = run([PV("admission-admitted")], TRUST("receiver-no-anchors"))
    assert bare.decisions[0]["decision"] == "do_not_rely"
    assert bare.failed_checks() == KEY_NOT_HELD
    assert bare.report()["failure_codes"] == ["key_id_unresolved"]


def test_valid_signature_is_not_receiver_trust(run):
    result = run([PV("admission-admitted")], TRUST("receiver-key-revoked"))
    assert result.report()["signature_valid"] is True           # the signature verifies
    assert result.report()["issuer_key_resolved"] is True
    assert result.failed_checks() == ["issuer_key_trusted"]     # the receiver does not trust the key
    assert result.report()["failure_codes"] == ["key_untrusted"]
    assert result.decisions[0]["decision"] == "do_not_rely"


# --------------------------------------------------------------------------- unknown version / profile
def test_unknown_receipt_version(run):
    bad = run([CR("s0-unknown-receipt-version")])
    assert bad.decisions[0]["decision"] == "do_not_rely"
    assert bad.report()["failure_codes"] == ["profile.invalid_receipt_version", "version_binding_mismatch"]
    assert bad.tokens() == ["policy.receipt_version_not_accepted", "verifier.not_passed"]
    assert_relied(run([CR("s0-admitted-issuer-a")]))


def test_unknown_profile_is_never_silently_replaced_by_the_default(run):
    bad = run([CR("s0-unknown-profile")])
    assert bad.findings["receipts"][0]["selected_profile"] == "srs.example.unregistered.v0.1"
    assert bad.report()["failure_codes"] == ["profile.unsupported_selection", "version_binding_mismatch"]
    assert bad.tokens() == ["policy.profile_not_accepted", "verifier.not_passed"]
    assert bad.decisions[0]["decision"] == "do_not_rely"


def test_pinned_profile_version_binding_vector(run):
    bad = run([PM("version-binding-fail")])
    assert bad.decisions[0]["decision"] == "do_not_rely"
    assert "version_binding_mismatch" in bad.report()["failure_codes"]
    assert "policy.profile_not_accepted" in bad.tokens()


# --------------------------------------------------------------------------- chain
def test_chain_intact_is_relied_upon_for_both_receipts(run):
    for receipts in ([PV("admission-admitted"), PV("outcome-result-returned")],
                     [CR("s0-admitted-issuer-a"), CR("s0-outcome-issuer-a")]):
        result = run(receipts)
        assert_relied(result, 0)
        assert_relied(result, 1, claim="issuer_attests_outcome_result_returned")
        assert result.findings["chain_findings"]["receipt_linkage_valid"] is True


def test_outcome_without_its_admission_is_insufficient_evidence_even_though_it_verifies(run):
    result = run([PV("outcome-result-returned")])
    assert result.report()["passed"] is True                       # every single-receipt check passes
    assert result.report()["chain_status"] == "not_applicable"
    assert result.decisions[0]["decision"] == "insufficient_evidence"
    assert result.tokens() == ["chain.admission_receipt_unresolved"]
    assert result.findings["chain_findings"]["receipt_linkage_valid"] is False
    # control: a receiver whose own policy does not require the link relies on the same bytes
    assert_relied(run([PV("outcome-result-returned")], TRUST("receiver-no-link-requirement")))


def test_inconsistent_linkage_is_not_relied_upon(run):
    result = run([CR("s0-admitted-issuer-a"), CR("s0-outcome-linkage-mismatch")])
    assert_relied(result, 0)                                      # the admission alone is fine
    assert result.report(1)["passed"] is True                     # the outcome verifies on its own
    assert result.decisions[1]["decision"] == "do_not_rely"
    # the strict dependent-reliance requirement establishes this itself rather than relying on
    # the linker's finding, so both are reported; the decision is unchanged.
    assert result.tokens(1) == ["chain.admission_not_relied_upon", "chain.admission_outcome_linkage_mismatch"]


# --------------------------------------------------------------------------- duplicate / replay
def test_duplicate_in_one_submission_is_relied_upon_once(run):
    result = run([PV("admission-admitted"), PV("admission-admitted")])
    assert_relied(result, 0)
    assert result.decisions[1]["decision"] == "do_not_rely"
    assert result.tokens(1) == ["replay.duplicate_in_submission"]
    assert result.report(1)["passed"] is True                     # replay is not a verifier matter
    assert len(result.decision["ledger_additions"]) == 1
    assert result.findings["chain_findings"]["manifest_integrity"] is False   # existing verifier also saw the duplicate id
    two = run([PV("admission-admitted"), PV("admission-refused")])
    assert_relied(two, 0)
    assert_relied(two, 1)


def test_replay_of_a_receipt_already_in_the_receivers_ledger(run):
    replay = run([PV("admission-admitted")], TRUST("receiver-ledger-has-admitted"))
    assert replay.decisions[0]["decision"] == "do_not_rely"
    assert replay.tokens() == ["replay.already_relied_in_ledger"]
    assert replay.report()["passed"] is True
    assert_relied(run([PV("admission-admitted")], TRUST("receiver-ledger-other")))


def test_two_validly_signed_receipts_with_one_id_are_both_refused(run):
    result = run([CR("s0-admitted-issuer-a"), CR("s0-conflict-b")])
    for i in (0, 1):
        assert result.report(i)["passed"] is True
        assert result.decisions[i]["decision"] == "do_not_rely"
        assert result.tokens(i) == ["replay.receipt_id_conflict"]
    assert result.decision["ledger_additions"] == []


# --------------------------------------------------------------------------- refused / deferred honesty
def test_refused_and_deferred_are_represented_not_dropped_and_not_upgraded(run):
    result = run([PV("admission-admitted"), PV("admission-refused"), PV("admission-deferred")])
    summary = result.decision["summary"]
    assert summary["receipts_in"] == summary["decisions_out"] == 3
    assert summary["no_receipt_dropped"] is True
    assert summary["counts_by_receipt_declared_disposition"] == {"admitted": 1, "deferred_for_review": 1, "refused": 1}
    claims = [d["reliance_claim"] for d in result.decisions]
    assert claims == [
        "issuer_attests_admission_disposition_admitted",
        "issuer_attests_admission_disposition_refused",
        "issuer_attests_admission_disposition_deferred_for_review",
    ]
    assert "approval_of_the_deferred_call" in result.decisions[2]["not_relied_upon"]
    assert "absence_of_execution_outside_the_named_boundary" in result.decisions[1]["not_relied_upon"]


def test_a_failing_receipt_does_not_remove_its_neighbours(run):
    result = run([PV("admission-admitted"), CR("n-tamper-refused-to-admitted"), PV("admission-deferred")])
    assert [d["decision"] for d in result.decisions] == ["rely", "do_not_rely", "rely"]
    assert result.decision["summary"]["decisions_out"] == 3


# --------------------------------------------------------------------------- metadata-only violation
@pytest.mark.parametrize("name, key", [
    ("s0-raw-tool-arguments", "tool_arguments"),
    ("s0-raw-result-body", "result_body"),
    ("s0-raw-access-token", "access_token"),
])
def test_validly_signed_raw_content_fails_raw_content_exclusion_only(run, name, key):
    assert_relied(run([CR("s0-admitted-issuer-a")]))
    bad = run([CR(name)])
    assert bad.report()["signature_valid"] is True and bad.report()["issuer_key_trusted"] is True
    assert bad.failed_checks() == ["raw_content_exclusion"]
    assert bad.report()["failure_codes"] == [f"raw_content.forbidden_key:{key}"]
    assert bad.decisions[0]["decision"] == "do_not_rely"
    assert bad.tokens() == ["verifier.not_passed"]


# --------------------------------------------------------------------------- valid but declined
@pytest.mark.parametrize("trust, token", [
    ("receiver-strict-boundary", "policy.boundary_not_accepted"),
    ("receiver-strict-issuer", "policy.issuer_not_accepted"),
])
def test_every_verifier_check_passes_and_the_receiver_still_declines(run, trust, token):
    same_bytes_default = run([PV("admission-admitted")])
    declined = run([PV("admission-admitted")], TRUST(trust))
    assert declined.report()["passed"] is True
    assert declined.report() == same_bytes_default.report()       # verifier output identical under both receivers
    assert declined.failed_checks() == []
    assert declined.decisions[0]["decision"] == "do_not_rely"
    assert declined.tokens() == [token]
    assert same_bytes_default.decisions[0]["decision"] == "rely"  # different receiver authority, same bytes


# --------------------------------------------------------------------------- input integrity
def test_malformed_bytes_produce_no_verifier_findings_and_no_reliance(run):
    result = run([CR("n-malformed-json")])
    assert result.report() is None                                  # not a pass: there is no report
    assert result.decisions[0]["decision"] == "do_not_rely"
    assert result.tokens() == ["input.malformed_json"]
    assert result.decisions[0]["verifier_passed"] is None
    assert result.findings["chain_findings"] is None


# --------------------------------------------------------------------------- two distinct records
def test_findings_and_decision_are_distinct_records_and_findings_are_unaltered(run):
    import subprocess, sys
    result = run([PV("admission-refused"), PV("admission-admitted")])
    findings_text = (result.out_dir / "verifier-findings.json").read_text()
    decision_text = (result.out_dir / "reliance-decision.json").read_text()
    assert findings_text != decision_text
    assert result.findings["record_kind"] == "verifier_findings"
    assert result.decision["record_kind"] == "receiver_reliance_decision"
    # the findings record holds no receiver decision, the decision record holds no full verifier report
    assert '"decision"' not in findings_text and '"reliance_claim"' not in findings_text
    assert '"verifier_report"' not in decision_text
    # the decision cites the findings by digest
    import hashlib
    assert result.decision["findings_record_sha256"] == "sha256:" + hashlib.sha256(findings_text.encode()).hexdigest()
    # unaltered: equal to a direct call of the existing verifier and to the existing CLI
    sys.path.insert(0, str(REPO))
    try:
        from arcs_verify.verifier import verify_receipt
    finally:
        sys.path.remove(str(REPO))
    trust = json.loads(DEFAULT.read_text())
    schema = REPO / "arcs_verify" / "data" / "srs-envelope-v0.2.0.schema.json"
    for index, path in enumerate((PV("admission-refused"), PV("admission-admitted"))):
        direct = verify_receipt(json.loads(path.read_text()), trust["keyring"], schema_path=schema,
                                selected_profile="srs.mcp.sdk_enforcement.v0.1").to_dict()
        assert result.report(index) == direct
        keyring_file = result.out_dir / f"keyring{index}.json"
        keyring_file.write_text(json.dumps(trust["keyring"]))
        cli = subprocess.run([sys.executable, "-I", "-c",
                              "import sys; sys.path.insert(0, sys.argv[1]); from arcs_verify.cli import main; raise SystemExit(main(sys.argv[2:]))",
                              str(REPO), str(path), "--keyring", str(keyring_file), "--json"],
                             capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        assert json.loads(cli.stdout) == result.report(index)


# --------------------------------------------------------------------------- receiver input validation
@pytest.mark.parametrize("mutate", [
    lambda t: t.pop("policy"),
    lambda t: t.__setitem__("surprise", 1),
    lambda t: t["policy"].__setitem__("accepted_issuer_ids", "issuer:not-a-list"),
    lambda t: t.__setitem__("schema", "something.else"),
    lambda t: t["policy"].pop("require_admission_link_for_outcome"),
])
def test_malformed_trust_input_is_a_usage_error_with_no_records(tmp_path, mutate):
    trust = json.loads(DEFAULT.read_text())
    mutate(trust)
    bad = tmp_path / "trust.json"
    bad.write_text(json.dumps(trust))
    result = run_receiver([PV("admission-admitted")], bad, tmp_path / "out")
    assert result.proc.returncode == 2
    assert result.decision is None and result.findings is None


def test_missing_receipt_file_is_a_usage_error(tmp_path):
    result = run_receiver([tmp_path / "does-not-exist.json"], DEFAULT, tmp_path / "out")
    assert result.proc.returncode == 2 and result.decision is None


def test_stale_records_from_an_earlier_run_are_never_left_beside_a_usage_error(tmp_path):
    out = tmp_path / "out"
    first = run_receiver([PV("admission-admitted")], DEFAULT, out)
    assert first.decision is not None
    second = run_receiver([tmp_path / "does-not-exist.json"], DEFAULT, out)
    assert second.proc.returncode == 2
    assert second.decision is None and second.findings is None and second.facts is None


# ----------------------------------------------- E-A-LINK: reliance on the referenced admission
# The outcome's own verification is never in question in this family: in every case below its
# verifier report passes. What changes is whether this receiver relied on the admission it
# references, and whether its selected policy requires that.

STRICT_TOKEN = "chain.admission_not_relied_upon"
BROKEN_ADMISSION = CR("s0-admission-signature-broken")
LINKED_OUTCOME = CR("s0-outcome-issuer-a")
INTACT_ADMISSION = CR("s0-admitted-issuer-a")
ARRIVAL_ONLY = TRUST("receiver-arrival-only-linkage")


def assert_outcome_declined_for_its_admission(result: Run, index: int) -> None:
    """The outcome is refused for the dependency, and for nothing about itself."""
    d = result.decisions[index]
    assert d["decision"] == "do_not_rely", d["reasons"]
    assert result.tokens(index) == [STRICT_TOKEN]
    # the verifier's own finding on these bytes is untouched and still passing
    assert result.report(index)["passed"] is True
    assert result.failed_checks(index) == []
    assert "reliance_claim" not in d
    reason = next(r for r in d["reasons"] if r["token"] == STRICT_TOKEN)
    assert reason["source"] == "receiver_policy"
    assert reason["detail"]["admission_receipt_id"] == "urn:srs:receipt:stranger0:admission:0001"


def test_ealink_refused_admission_stops_reliance_on_its_linked_outcome(run):
    assert_relied(run([INTACT_ADMISSION, LINKED_OUTCOME], DEFAULT), index=1,
                  claim="issuer_attests_outcome_result_returned")  # positive control
    result = run([BROKEN_ADMISSION, LINKED_OUTCOME], DEFAULT)
    assert result.decisions[0]["decision"] == "do_not_rely"
    assert result.tokens(0) == ["verifier.not_passed"]
    assert result.failed_checks(0) == SIGNATURE_ONLY
    assert_outcome_declined_for_its_admission(result, 1)
    assert result.decisions[1]["reasons"][0]["detail"]["admission_state"] == "do_not_rely"


def test_ealink_decision_does_not_depend_on_submission_order(run):
    forward = run([BROKEN_ADMISSION, LINKED_OUTCOME], DEFAULT)
    reversed_ = run([LINKED_OUTCOME, BROKEN_ADMISSION], DEFAULT)
    assert [d["decision"] for d in forward.decisions] == ["do_not_rely", "do_not_rely"]
    assert [d["decision"] for d in reversed_.decisions] == ["do_not_rely", "do_not_rely"]
    assert_outcome_declined_for_its_admission(reversed_, 0)  # the outcome arrived first
    by_id = lambda r: {d["receipt_id"]: (d["decision"], sorted(x["token"] for x in d["reasons"])) for d in r.decisions}
    assert by_id(forward) == by_id(reversed_)


def test_ealink_arrival_only_policy_relies_on_the_outcome_it_separately_verified(run):
    """The narrower reading stays reachable, and the record says which one was applied."""
    result = run([BROKEN_ADMISSION, LINKED_OUTCOME], ARRIVAL_ONLY)
    assert result.decisions[0]["decision"] == "do_not_rely"       # the admission is still refused
    assert result.tokens(0) == ["verifier.not_passed"]
    assert_relied(result, index=1, claim="issuer_attests_outcome_result_returned")
    policy = result.decision["effective_linkage_policy"]
    assert policy["require_admission_link_for_outcome"] is True
    assert policy["require_relied_admission_for_outcome"] is False


def test_ealink_strict_policy_is_named_in_the_decision_record(run):
    policy = run([INTACT_ADMISSION, LINKED_OUTCOME], DEFAULT).decision["effective_linkage_policy"]
    assert policy["require_admission_link_for_outcome"] is True
    assert policy["require_relied_admission_for_outcome"] is True


def test_ealink_duplicate_admission_receipt_id_is_not_a_unique_relied_admission(run):
    """Two receipts carry the referenced id, so no single relied admission exists."""
    result = run([INTACT_ADMISSION, BROKEN_ADMISSION, LINKED_OUTCOME], DEFAULT)
    assert result.tokens(0) == ["replay.receipt_id_conflict"]
    assert result.tokens(1) == ["replay.receipt_id_conflict", "verifier.not_passed"]
    assert_outcome_declined_for_its_admission(result, 2)
    detail = result.decisions[2]["reasons"][0]["detail"]
    assert detail["admission_state"] == "duplicate_receipt_id_in_submission"
    assert detail["matching_receipts_in_submission"] == 2


def test_ealink_admission_declined_from_the_receivers_own_ledger_stops_the_outcome(run):
    """The requirement keys on the receiver's decision, not on the verifier's result:
    here every verifier check passes and the admission is declined from the ledger."""
    ledger = TRUST("receiver-ledger-has-admitted")
    assert_relied(run([PV("admission-admitted"), PV("outcome-result-returned")], DEFAULT), index=1)
    result = run([PV("admission-admitted"), PV("outcome-result-returned")], ledger)
    assert result.report(0)["passed"] is True and result.report(1)["passed"] is True
    assert result.tokens(0) == ["replay.already_relied_in_ledger"]
    assert result.decisions[1]["decision"] == "do_not_rely"
    assert result.tokens(1) == [STRICT_TOKEN]
    assert result.decisions[1]["reasons"][0]["detail"]["admission_state"] == "do_not_rely"


def test_ealink_unrelated_valid_admission_is_not_a_substitute(run):
    """A valid admission the receiver does rely on, but not the referenced one. The
    pre-existing unresolved-reference semantics own this, and still do."""
    result = run([PV("admission-admitted"), LINKED_OUTCOME], DEFAULT)
    assert_relied(result, index=0, claim="issuer_attests_admission_disposition_admitted")
    assert result.decisions[1]["decision"] == "insufficient_evidence"
    assert result.tokens(1) == ["chain.admission_receipt_unresolved"]


def test_ealink_missing_admission_still_reports_insufficient_evidence(run):
    """Preserved: an admission that never arrived is missing evidence, not a refusal."""
    result = run([PV("outcome-result-returned")], DEFAULT)
    assert result.decisions[0]["decision"] == "insufficient_evidence"
    assert result.tokens(0) == ["chain.admission_receipt_unresolved"]
    assert STRICT_TOKEN not in result.tokens(0)


def test_ealink_strict_reliance_without_the_arrival_requirement_is_refused(tmp_path):
    """The one combination with no reading is refused at load time, not guessed at."""
    body = json.loads(DEFAULT.read_text())
    body["policy"]["require_admission_link_for_outcome"] = False
    body["policy"]["require_relied_admission_for_outcome"] = True
    bad = tmp_path / "incoherent-trust.json"
    bad.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = run_receiver([PV("admission-admitted")], bad, tmp_path / "out")
    assert result.proc.returncode == 2
    assert result.decision is None
    assert "require_relied_admission_for_outcome requires" in result.proc.stderr


def test_ealink_trust_input_without_the_new_setting_is_refused(tmp_path):
    """The setting is required, so no trust input silently falls back to either reading."""
    body = json.loads(DEFAULT.read_text())
    del body["policy"]["require_relied_admission_for_outcome"]
    bad = tmp_path / "missing-setting-trust.json"
    bad.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = run_receiver([PV("admission-admitted")], bad, tmp_path / "out")
    assert result.proc.returncode == 2 and result.decision is None
    assert "policy keys must be exactly" in result.proc.stderr


def test_ealink_matching_receipt_id_with_a_different_call_id_is_not_the_linked_admission(run):
    """A receipt id match is not linkage. The strict requirement establishes this itself
    rather than waiting for the receipt-set linker's finding to appear."""
    assert_relied(run([INTACT_ADMISSION, LINKED_OUTCOME], DEFAULT), index=1)  # positive control
    result = run([INTACT_ADMISSION, CR("s0-outcome-linkage-mismatch")], DEFAULT)
    assert_relied(result, index=0, claim="issuer_attests_admission_disposition_admitted")
    assert result.decisions[1]["decision"] == "do_not_rely"
    assert result.tokens(1) == [STRICT_TOKEN, "chain.admission_outcome_linkage_mismatch"]
    strict = next(r for r in result.decisions[1]["reasons"] if r["token"] == STRICT_TOKEN)
    assert strict["detail"]["admission_state"] == "logical_call_id_differs"
