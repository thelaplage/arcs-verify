"""No fetch during replay, no aggregate verdict, and nothing presented as authenticated issuance.

SYNTHETIC observations only. The autouse network tripwire in conftest.py records any socket
use and fails the test at teardown even if the code under test swallowed the exception."""
import ast
import json
import socket
from pathlib import Path

import pytest

from arcs_verify import c2pa_native
from arcs_verify import c2pa_srs_observed as adapter

from . import material as m

MODULE_PATH = Path(adapter.__file__)
GOOD_SIGNATURE = {
    "algorithm": "Ed25519",
    "canonicalization": "RFC8785-JCS",
    "key_id": "synthetic-key-id-NOT-A-KEY",
    "signature": "c3ludGhldGljLXNpZ25hdHVyZS1ieXRlcw",
}


def consume(tmp_path, obs, evidence=None, report=m.REPORT_VALID_UNTRUSTED):
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (report, 0)})
    result = adapter.consume_observation(m.encode(obs), evidence or m.evidence_for(report), executable=fake.path)
    return result, fake


def walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_keys(item)


# -- offline ------------------------------------------------------------------------------


def test_the_network_tripwire_is_live(network_tripwire):
    """Positive control: if the fixture did not work, every offline claim below is vacuous."""
    with pytest.raises(AssertionError):
        socket.create_connection(("synthetic.invalid", 9))
    assert len(network_tripwire) == 1
    network_tripwire.clear()


def test_module_imports_no_network_or_producer_code():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"socket", "ssl", "urllib", "http", "requests", "httpx", "ftplib", "smtplib", "asyncio", "aiohttp", "subprocess"}
    assert not imported & forbidden, imported & forbidden
    producers = {"dagr", "bagr", "arcs_srs", "acquisition", "counterpedia", "countergraph"}
    assert not any(name == p or name.startswith(p + "_") for name in imported for p in producers), imported


def test_remote_uris_in_the_observation_are_recorded_never_dereferenced(tmp_path, network_tripwire):
    obs = m.synthetic_observation(mode="remote_reference")
    obs["signer_trust"]["trust_pointer_uri"] = "https://synthetic.invalid/trustlist.json"
    obs["manifest_acquisition"]["remote_resolution_performed"] = True
    obs["manifest_acquisition"]["remote_resolution_phase"] = "acquisition"
    ev = m.evidence_for(manifest_store=m.SYNTHETIC_MANIFEST_STORE)
    result, fake = consume(tmp_path, obs, ev)
    assert result.stopped_at is None
    assert network_tripwire == []
    (call,) = fake.calls()
    assert not any("://" in token for token in call["argv"])
    assert result.report["producer_asserted"]["signer_trust"]["trust_pointer_uri"] == "https://synthetic.invalid/trustlist.json"
    hermeticity = result.report["observed_finding"]["settings"]["hermeticity"]
    assert hermeticity["trust_list_uri_dereferenced"] is False and hermeticity["remote_resource_fetch_attempted"] is False


def test_a_fetch_attempt_during_replay_would_be_caught(tmp_path, network_tripwire, monkeypatch):
    """Negative control for the tripwire against the real code path: make the recompute stage
    reach for the network and confirm the attempt is recorded and surfaces as a failure."""
    real = adapter._stage_recompute

    def fetching(obs, evidence, executable, bundle):
        socket.create_connection(("synthetic.invalid", 443))
        return real(obs, evidence, executable, bundle)

    monkeypatch.setattr(adapter, "_stage_recompute", fetching)
    with pytest.raises(AssertionError, match="network use is forbidden"):
        consume(tmp_path, m.synthetic_observation())
    assert len(network_tripwire) == 1
    network_tripwire.clear()


# -- no aggregate verdict ------------------------------------------------------------------

FORBIDDEN_KEYS = (
    set(c2pa_native.FORBIDDEN_AGGREGATE_KEYS)
    | {"valid", "is_valid", "authentic", "authenticated", "trusted", "signer_trusted", "passed", "ok", "success", "match", "matches", "overall"}
    | {"c2pa_valid", "provenance_valid", "content_authentic", "content_verified", "admission_verified", "standing_score"}
)


@pytest.mark.parametrize(
    "variant",
    ["match", "mismatch", "unavailable", "refused_profile", "refused_correspondence"],
)
def test_no_aggregate_or_verdict_key_appears_anywhere_in_any_report(tmp_path, variant):
    obs = m.synthetic_observation()
    report, scenarios = m.REPORT_VALID_UNTRUSTED, None
    if variant == "mismatch":
        report = m.REPORT_INVALID_CLAIM
    if variant == "refused_profile":
        obs = m.mutated(obs, "profile_id", "srs.other")
    if variant == "refused_correspondence":
        obs = m.mutated(obs, "asset_digest", "sha256:" + "0" * 64)
    scenarios = {} if variant == "unavailable" else {m.SYNTHETIC_ASSET: (report, 0)}
    fake = m.install_fake_validator(tmp_path, scenarios)
    result = adapter.consume_observation(m.encode(obs), m.evidence_for(), executable=fake.path)
    keys = set(walk_keys(result.report))
    assert not keys & FORBIDDEN_KEYS, keys & FORBIDDEN_KEYS
    json.dumps(result.report)  # serializable


def test_report_carries_per_axis_findings_and_the_stage_results_separately(tmp_path):
    result, _ = consume(tmp_path, m.synthetic_observation())
    axes = set(result.report["axes"])
    assert {
        "observation_conformance",
        "asset_manifest_binding",
        "native_validation_state",
        "native_failure_codes",
        "signer_trust",
        "signer_validity",
        "timestamp",
        "revocation",
        "independent_comparison",
        "srs_receipt_authentication",
        "source_digest_pin",
    } <= axes
    assert result.report["status"] == "PROVISIONAL_EXPERIMENTAL_UNTRUSTED_ADAPTER"
    assert result.report["authority_movement"] == 0
    assert result.report["profile_pin"]["source_commit"] == adapter.SOURCE_COMMIT


# -- unsigned provenance is never authenticated issuance -----------------------------------

SIGNATURE_AXES = ("signature_shape", "signature_valid", "key_resolved", "key_trusted", "issuance_authentication")


def test_unsigned_observation_leaves_every_signature_and_key_axis_not_evaluated(tmp_path):
    result, _ = consume(tmp_path, m.synthetic_observation())
    auth = result.report["axes"]["srs_receipt_authentication"]
    assert auth["receipt_signature_present"] is False
    assert {auth[a] for a in SIGNATURE_AXES} == {"not_evaluated"}
    assert "unsigned" in auth["reason"] and "no receipt_signature is present" in auth["reason"]


def test_signature_field_present_but_unverifiable_is_reported_not_evaluated_and_not_authenticated(tmp_path):
    obs = m.synthetic_observation()
    obs["receipt_signature"] = GOOD_SIGNATURE
    result, _ = consume(tmp_path, obs)
    assert result.stopped_at is None  # presence of a signature neither gates nor authenticates
    auth = result.report["axes"]["srs_receipt_authentication"]
    assert auth["receipt_signature_present"] is True
    assert {auth[a] for a in SIGNATURE_AXES} == {"not_evaluated"}
    assert "was not verified" in auth["reason"]
    assert result.report["producer_asserted"]["provenance"] == "producer_asserted"


def test_malformed_signature_field_is_a_profile_refusal_not_a_silent_pass(tmp_path):
    obs = m.synthetic_observation()
    obs["receipt_signature"] = {"algorithm": "RSA", "key_id": "x"}
    result, fake = consume(tmp_path, obs)
    assert result.stopped_at == "profile_conformance"
    assert "ENVELOPE_SCHEMA" in {r.code for r in result.stages["profile_conformance"].refusals}
    assert result.report["axes"]["srs_receipt_authentication"]["issuance_authentication"] == "not_evaluated"
    assert fake.calls() == []


def test_a_refused_run_still_reports_the_signature_axes_as_not_evaluated(tmp_path):
    result, _ = consume(tmp_path, m.mutated(m.synthetic_observation(), "profile_id", "srs.other"))
    auth = result.report["axes"]["srs_receipt_authentication"]
    assert {auth[a] for a in SIGNATURE_AXES} == {"not_evaluated"}


def test_producer_asserted_signer_trust_is_labelled_and_not_an_independent_finding(tmp_path):
    obs = m.synthetic_observation(m.REPORT_TRUSTED_ALLOWED)
    obs["signer_trust"].update(
        trust_basis="custom_allowed_list",
        trust_observation="trusted",
        trust_material_refs=[{"role": "allowed_list", "digest": m.ALLOWED_LIST_DIGEST, "source_identity": "SYNTHETIC", "source_pin": "pin-0001"}],
    )
    result, _ = consume(tmp_path, obs, m.evidence_for(m.REPORT_TRUSTED_ALLOWED))
    asserted = result.report["producer_asserted"]
    assert asserted["provenance"] == "producer_asserted" and asserted["independent_finding"] == "not_evaluated"
    trust = result.report["axes"]["signer_trust"]
    assert trust["producer_asserted"]["trust_observation"] == "trusted"
    assert trust["independent_comparison"]["state"] != "match"


def test_issuer_identity_is_a_label_not_an_authority(tmp_path):
    result, _ = consume(tmp_path, m.synthetic_observation())
    assert result.report["producer_asserted"]["issuer_id"] == "issuer.synthetic-test/NON-OPERATIONAL"
    text = json.dumps(result.report["limitations"])
    assert "authenticated issuance" in text and "issuer standing" in text


# -- CLI -----------------------------------------------------------------------------------


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_cli_runs_the_pipeline_and_prints_a_json_report(tmp_path, capsys):
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (m.REPORT_VALID_UNTRUSTED, 0)})
    argv = [
        "--observation", write(tmp_path, "observation.json", m.encode(m.synthetic_observation())),
        "--asset", write(tmp_path, m.ASSET_NAME, m.SYNTHETIC_ASSET),
        "--native-report", write(tmp_path, "native-report.json", m.report_bytes(m.REPORT_VALID_UNTRUSTED)),
        "--c2patool", fake.path,
    ]
    assert adapter.main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["pipeline"]["stopped_at"] is None


def test_cli_exit_one_when_a_stage_refuses(tmp_path, capsys):
    argv = [
        "--observation", write(tmp_path, "observation.json", m.encode(m.mutated(m.synthetic_observation(), "profile_id", "srs.other"))),
        "--asset", write(tmp_path, m.ASSET_NAME, m.SYNTHETIC_ASSET),
        "--native-report", write(tmp_path, "native-report.json", m.report_bytes(m.REPORT_VALID_UNTRUSTED)),
    ]
    assert adapter.main(argv) == 1
    assert json.loads(capsys.readouterr().out)["pipeline"]["stopped_at"] == "profile_conformance"


def test_cli_exit_two_for_a_missing_input_file(tmp_path, capsys):
    assert adapter.main(["--observation", str(tmp_path / "absent.json"), "--asset", str(tmp_path / "absent.bin")]) == 2
    assert "source-integrity error" in capsys.readouterr().err


def test_cli_asset_name_override_supplies_the_validator_format_label(tmp_path, capsys):
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (m.REPORT_VALID_UNTRUSTED, 0)})
    argv = [
        "--observation", write(tmp_path, "observation.json", m.encode(m.synthetic_observation())),
        "--asset", write(tmp_path, "opaque name with spaces.bin", m.SYNTHETIC_ASSET),
        "--asset-name", "renamed.jpg",
        "--native-report", write(tmp_path, "native-report.json", m.report_bytes(m.REPORT_VALID_UNTRUSTED)),
        "--c2patool", fake.path,
    ]
    assert adapter.main(argv) == 0
    assert json.loads(capsys.readouterr().out)["native_recomputation"]["subject"]["asset_label"] == "renamed.jpg"
    (call,) = fake.calls()
    assert call["argv"][-1].endswith("renamed.jpg")
