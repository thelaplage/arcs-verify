"""Step 2 and the input-parse stage: one violation per case, each reaching its own rule.

SYNTHETIC observations only. Every case changes exactly one thing in an otherwise
conformant observation and asserts the specific code that rule owns."""
import json

import pytest

from arcs_verify import c2pa_srs_observed as adapter

from . import material as m

BASE = m.synthetic_observation()


def gate(obs):
    return adapter._stage_conformance(obs)[1]


def codes(obs):
    return {r.code for r in gate(obs).refusals}


def drop_limitation(obs, code):
    out = json.loads(json.dumps(obs))
    out["machine_limitations"] = [i for i in out["machine_limitations"] if i["code"] != code]
    return out


def with_refs(obs, basis, refs, **extra):
    out = m.mutated(obs, "signer_trust.trust_basis", basis)
    out["signer_trust"]["trust_material_refs"] = refs
    out["signer_trust"].update(extra)
    return out


GOOD_REF = {"role": "allowed_list", "digest": m.ALLOWED_LIST_DIGEST, "source_identity": "SYNTHETIC", "source_pin": "pin-0001"}

CASES = [
    ("PF-ENVELOPE-SCHEMA", m.mutated(BASE, "receipt_type", "not_a_receipt_type"), "ENVELOPE_SCHEMA"),
    ("PF-FIELD-SCHEMA", m.mutated(BASE, "manifest_store.state", "weird"), "FIELD_SCHEMA"),
    ("PF-UNKNOWN-FIELD", m.mutated(BASE, "x_unmapped_extra", 1), "ADAPTER_UNKNOWN_FIELD"),
    ("PF-EXTENSIONS", m.mutated(BASE, "extensions", {"a": 1}), "ADAPTER_EXTENSIONS_NOT_SUPPORTED"),
    ("PF-PROFILE-ID", m.mutated(BASE, "profile_id", "srs.other"), "PROFILE_ID_MISMATCH"),
    ("PF-PROFILE-VERSION", m.mutated(BASE, "profile_version", "v9"), "PROFILE_VERSION_MISMATCH"),
    ("PF-FIXED-VALUES", m.mutated(BASE, "external_binding_relation_mode", "native_emission"), "FIXED_VALUE_MISMATCH"),
    ("PF-REQUIRED-FIELDS", m.without(BASE, "signer_validity"), "MISSING_PROFILE_FIELD"),
    ("PF-CLASSES", m.mutated(BASE, "artifact_classes_covered", ["asset_digest"]), "MISSING_REQUIRED_COVERAGE"),
    ("PF-CLASSES", m.mutated(BASE, "artifact_classes_excluded", ["raw_asset_bytes"]), "MISSING_REQUIRED_EXCLUSION"),
    ("PF-RECEIPT-KIND", m.mutated(BASE, "receipt_kind", "other_kind"), "INVALID_RECEIPT_KIND"),
    ("PF-AGGREGATE-FIELDS", m.mutated(BASE, "c2pa_valid", True), "AGGREGATE_FIELD_PRESENT"),
    ("PF-ASSET-DIGEST-FORMAT", m.mutated(BASE, "asset_digest", "sha256:XYZ"), "INVALID_DIGEST_FORMAT"),
    ("PF-SUBJECT-BINDING", m.mutated(BASE, "subject_ref", "sha256:" + "1" * 64), "SUBJECT_BINDING_MISMATCH"),
    ("PF-STORE-STATE", m.mutated(BASE, "manifest_store.state", "weird"), "INVALID_MANIFEST_STORE_STATE"),
    ("PF-STORE-DIGEST-REQUIRED", m.without(BASE, "manifest_store.digest"), "MISSING_MANIFEST_DIGEST"),
    ("PF-STORE-DIGEST-FORBIDDEN", m.mutated(BASE, "manifest_store.state", "absent"), "MANIFEST_DIGEST_WITHOUT_BYTES"),
    ("PF-ACQUISITION-MODE", m.mutated(BASE, "manifest_acquisition.mode", "teleport"), "INVALID_ACQUISITION_MODE"),
    ("PF-REMOTE-URI", m.mutated(BASE, "manifest_acquisition.mode", "remote_reference"), "REMOTE_MANIFEST_URI_MISSING"),
    ("PF-HERMETIC", m.mutated(BASE, "hermetic_replay.remote_manifest_fetch_applied", True), "NON_HERMETIC_REPLAY"),
    ("PF-VALIDATOR-IDENTITY", m.mutated(BASE, "native_validator.version", ""), "MISSING_NATIVE_VALIDATOR_IDENTITY"),
    ("PF-CONFIG-DIGEST-REQUIRED", m.without(BASE, "native_validator.configuration_digest"), "MISSING_VALIDATOR_CONFIGURATION_DIGEST"),
    (
        "PF-CONFIG-DIGEST-FORBIDDEN",
        m.mutated(BASE, "native_validator.configuration_posture", "validator_defaults"),
        "VALIDATOR_CONFIGURATION_DIGEST_WITHOUT_CONFIGURATION",
    ),
    ("PF-SPEC-SOURCE", m.mutated(BASE, "native_validator.specification_version_applied_source", "manifest_claimed"), "SPEC_VERSION_CLAIM_WEAKENS_APPLIED"),
    ("PF-UNAVAILABLE-STATE", m.mutated(BASE, "evaluation_posture", "input_unavailable"), "INPUT_UNAVAILABLE_RENDERED_AS_VALIDATION_FAILURE"),
    (
        "PF-UNAVAILABLE-LIST",
        m.mutated(m.without(BASE, "native_report"), "evaluation_posture", "input_unavailable") | {"unavailable_inputs": []},
        "MISSING_UNAVAILABLE_INPUTS",
    ),
    ("PF-PERFORMED-REPORT", m.without(BASE, "native_report"), "MISSING_PROFILE_FIELD"),
    ("PF-VERDICT-SOURCE", m.mutated(BASE, "native_report.verdict_source", "process_exit_code"), "EXIT_CODE_AS_VERDICT"),
    ("PF-FINDINGS-REQUIRED", m.without(BASE, "native_findings"), "NATIVE_FINDINGS_MISSING"),
    ("PF-TRUST-BASIS", m.mutated(BASE, "signer_trust.trust_basis", "made_up"), "INVALID_TRUST_BASIS"),
    ("PF-TRUST-WITHOUT-BASIS", m.mutated(BASE, "signer_trust.trust_observation", "trusted"), "TRUST_OBSERVATION_WITHOUT_BASIS"),
    ("PF-TRUST-MATERIAL-REQUIRED", with_refs(BASE, "custom_allowed_list", []), "MISSING_TRUST_MATERIAL_DIGEST"),
    ("PF-TRUST-REF-KEYS", with_refs(BASE, "custom_allowed_list", [dict(GOOD_REF, source_pin="")]), "MISSING_TRUST_MATERIAL_DIGEST"),
    ("PF-OFFICIAL-MEMBERSHIP", m.mutated(BASE, "signer_trust.official_trust_list_membership", True), "TRUST_BASIS_MISREPRESENTED"),
    ("PF-TRUST-POINTER", m.mutated(BASE, "signer_trust.trust_pointer_dereferenced", True), "TRUST_POINTER_DEREFERENCED"),
    (
        "PF-SIGNER-ORDER",
        m.mutated(BASE, "signer_provenance", [{"order": 1, "subject": "a"}, {"order": 0, "subject": "b"}]),
        "SIGNER_PROVENANCE_NOT_ORDERED",
    ),
    (
        "PF-COMPARISON-POSTURE",
        m.mutated(m.mutated(BASE, "signer_trust.trust_basis", "unknown_not_captured"), "signer_trust.trust_observation", "not_evaluated"),
        "COMPARISON_POSTURE_OVERSTATED",
    ),
    ("PF-PRIOR-REPORT", m.mutated(BASE, "prior_producer_report.comparison_posture", "comparable"), "PRIOR_REPORT_COMPARISON_CONFLICT"),
    ("PF-ATTESTATION-LIMIT", m.mutated(BASE, "attestation_limits", ["something else"]), "MISSING_REQUIRED_ATTESTATION_LIMIT"),
    ("PF-LIMITATION-ITEM", m.mutated(BASE, "machine_limitations", BASE["machine_limitations"] + ["not an object"]), "INVALID_MACHINE_LIMITATION_ITEM"),
    ("PF-LIMITATION-REGISTERED", m.mutated(BASE, "machine_limitations", BASE["machine_limitations"] + [{"code": "MADE_UP_CODE"}]), "UNKNOWN_LIMITATION_CODE"),
    ("PF-LIMITATION-CONTRADICTION", m.mutated(BASE, "signer_trusted", True), "CONTRADICTION_DETECTED"),
    ("PF-LIMITATION-REQUIRED", drop_limitation(BASE, "CONTENT_TRUTH_NOT_EVALUATED"), "MISSING_REQUIRED_MACHINE_LIMITATION"),
    ("PF-LIMITATION-CONDITIONAL", drop_limitation(BASE, "C2PA_REVOCATION_NOT_EVALUATED"), "MISSING_CONDITIONAL_MACHINE_LIMITATION"),
    ("PF-LIMITATION-CONDITIONAL", drop_limitation(BASE, "C2PA_VALIDATION_TIME_NOT_CONTROLLED"), "MISSING_CONDITIONAL_MACHINE_LIMITATION"),
]


def test_the_baseline_synthetic_observation_passes_the_gate():
    outcome = gate(BASE)
    assert outcome.status == "completed" and not outcome.refusals
    assert outcome.detail["source_commit"] == adapter.SOURCE_COMMIT


@pytest.mark.parametrize("guard,obs,expected", CASES, ids=[f"{g}:{e}" for g, _, e in CASES])
def test_each_rule_refuses_its_own_violation(guard, obs, expected):
    outcome = gate(obs)
    assert outcome.status == "refused"
    assert expected in {r.code for r in outcome.refusals}


def test_trust_ref_key_violation_names_the_field():
    refusals = gate(with_refs(BASE, "custom_allowed_list", [dict(GOOD_REF, source_pin="")])).refusals
    assert any(r.field and r.field.endswith(".source_pin") for r in refusals)


def test_a_profile_gate_internal_error_is_a_refusal_never_a_pass(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("synthetic internal failure")

    monkeypatch.setattr(adapter, "_profile_findings", boom)
    outcome = gate(BASE)
    assert outcome.status == "refused"
    assert [r.code for r in outcome.refusals] == ["PROFILE_GATE_INTERNAL_ERROR"]


# -- input parse stage -------------------------------------------------------------------


def parse(data):
    return adapter._stage_parse(data)


def test_valid_observation_parses_and_records_its_digest():
    obs, outcome = parse(m.encode(BASE))
    assert outcome.status == "completed" and obs == BASE
    assert outcome.detail["observation_sha256"] == m.sha(m.encode(BASE))


@pytest.mark.parametrize(
    "data,code",
    [
        (b"\xff\xfe not utf-8", "OBS_NOT_UTF8"),
        (b"{not json", "OBS_NOT_JSON"),
        (b'{"a": 1, "a": 2}', "OBS_DUPLICATE_KEY"),
        (b'{"a": NaN}', "OBS_NOT_JSON"),
        (b'{"a": Infinity}', "OBS_NOT_JSON"),
        (b'{"a": 1e999}', "OBS_NOT_JSON"),
        (b"[1, 2]", "OBS_NOT_OBJECT"),
        (b'"text"', "OBS_NOT_OBJECT"),
        (b"", "OBS_NOT_JSON"),
    ],
)
def test_malformed_observation_is_refused_with_a_typed_code(data, code):
    obs, outcome = parse(data)
    assert obs is None and outcome.status == "refused"
    assert [r.code for r in outcome.refusals] == [code]


def test_oversized_observation_is_refused(monkeypatch):
    monkeypatch.setattr(adapter, "MAX_OBSERVATION_BYTES", 10)
    _, outcome = parse(b'{"a": "0123456789"}')
    assert [r.code for r in outcome.refusals] == ["OBS_TOO_LARGE"]


def test_deeply_nested_observation_is_refused():
    deep = b'{"a": ' + b"[" * 100 + b"]" * 100 + b"}"
    _, outcome = parse(deep)
    assert [r.code for r in outcome.refusals] == ["OBS_TOO_DEEP"]


def test_pathologically_nested_observation_does_not_crash_the_parser():
    bomb = b"[" * 100000 + b"]" * 100000
    _, outcome = parse(bomb)
    assert outcome.status == "refused"


def test_consume_stops_at_parse_without_touching_correspondence():
    result = adapter.consume_observation(b"[]", m.evidence_for())
    assert result.stopped_at == "input_parse"
    assert result.stages["input_correspondence"].status == "not_run"
