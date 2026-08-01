"""Direct contract gate for arcs_verify/contracts/dagr-srs-verification-report-v0-2/.

    python -m pytest tests/test_dagr_srs_report_contract_v0_2.py -q

Covers the eleven required proofs for the subject-reference origin lane:

 1. each declared value survives into the v0.2 report unchanged;
 2. genuine absence produces not_declared;
 3. malformed present values do not become not_declared;
 4. v0.1/v0.2 verdict parity for all existing pass and fail cases;
 5. the same eight Booleans remain unchanged;
 6. chain_status remains unchanged and is not counted as a Boolean verdict;
 7. v0.1 report and execution-record contract digests remain exact;
 8. v0.2 validates against its own frozen contract;
 9. no emitter package is imported;
10. the v0.2.1 SRS schema digest is checked against S1;
11. the retained v0.2.0 pin still verifies historical inputs.

Every report examined here is built in-process from the deterministic input
fixtures under ``input-fixtures/``, using an explicitly synthetic verifier
commit, so this module proves contract semantics without depending on the
authoritative goldens. Generator behavior is proven in
``tests/test_dagr_report_v0_2_generator.py``, and the committed authoritative
goldens under ``golden/`` are proven in
``tests/test_dagr_report_v0_2_golden_closure.py``.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from arcs_verify import dagr_report as dr
from arcs_verify import dagr_report_v0_2 as dr2
from arcs_verify import subject_ref_origin as sro
from arcs_verify.cli import main as cli_main
from arcs_verify.subject_ref_origin import (
    MalformedSubjectRefOrigin,
    read_subject_ref_origin,
)
from arcs_verify.verifier import (
    ACCEPTED_SCHEMA_SHA256,
    ENVELOPE_SCHEMA_PINS,
    FROZEN_SCHEMA_SHA256,
    MCP_PROFILE,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]

V0_1_ROOT = dr._CONTRACT_ROOT
V0_1_GOLDEN = V0_1_ROOT / "golden"
V0_2_ROOT = dr2._CONTRACT_ROOT

# Deterministic generator *inputs*, not goldens. The authoritative goldens live
# in golden/ and are gated separately; every report this module reasons about is
# built here, in-process, from these receipts.
V0_2_INPUTS = V0_2_ROOT / "input-fixtures"

SCHEMA_V0_2_0 = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.0.schema.json"
SCHEMA_V0_2_1 = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.1.schema.json"

VENDOR_SCHEMA_V0_2_1 = (
    ROOT
    / "vendor"
    / "arcs-srs"
    / "schemas"
    / "srs-envelope"
    / "v0.2.1"
    / "srs-envelope.schema.json"
)
VENDOR_VECTORS = ROOT / "vendor" / "arcs-srs" / "vectors" / "subject-ref-origin-v0.2.1"

# Pins supplied by S1 alongside arcs-srs merge ccc4e4bbcd195914be70be392c89094bf8e2781b.
S1_SCHEMA_SHA256 = "2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"
S1_VECTOR_PINS = {
    "valid/supplied-subject.json": (
        "08f3795780821e31b70fb6370e4701978f9cb8729aa170bafc35a7c1b7110097",
        "supplied_subject",
    ),
    "valid/derived-from-supplied-correlation.json": (
        "989cb13c203f7282f8c526427b75d6e10496c357ccec847a08e777e3852c2574",
        "derived_from_supplied_correlation",
    ),
    "valid/binding-minted.json": (
        "ee0506879037351389b19785b8029da564b08282331175488ff3af7645a97154",
        "binding_minted",
    ),
    "valid/v0-2-0-era-not-declared.json": (
        "98a9b481891ffcb85712c6c30f3625f6cd4f3a86319ac46dc875a05aa8b067b5",
        "not_declared",
    ),
}

# Byte digests of the frozen v0.1 predecessors, reasserted here so this lane
# cannot silently move one.
V0_1_FROZEN_DIGESTS = {
    "verification-report.schema.json": (
        "09ede151a735931cb749ede5c03729413ddbbbb4a974078c619a0bff73003969"
    ),
    "verification-execution-record.schema.json": (
        "a9f700ecda9807f086334fd06c7f042dbb0cf21b39bccb00835d35ebcde15871"
    ),
    "execution-contract.json": (
        "be84f93730a4fd042537e595ab6b09e9563fe433fbc66e053d06530e34c89754"
    ),
    "receipt-hash-contract.json": (
        "9d079fcda7418d3830a8bc466bba02150b65e107e6e188aa2be22ee0ea3e36df"
    ),
    "supported-receipt-contract.json": (
        "f22c6be5608e295756983c3bb2ad7e4271879233ddf1fd88033886d269bc7c3a"
    ),
    "README.md": (
        "ba744339c1f97be8e140fd37fa86009ac6ef9beadc3bbac59208351a8a7f0c7e"
    ),
    "golden/admission-receipt.json": (
        "3e635b7f03c10a0331984f8619b550b08a72e3802e4e6e8831f29ab7c47bb490"
    ),
    "golden/admission-report.json": (
        "a41cf21859f70cfc42e43188e9427a82aaf49c7fdf408f8955a4b47dc058fd37"
    ),
    "golden/admission-execution-record.json": (
        "f04885f323a6b99c1d818652fca118c848bd1a46c30f6be5ad73fdf86587c583"
    ),
    "golden/outcome-receipt.json": (
        "6eb1ad647a97d3fda6f1689b1887ae982edaeb0c8bf84abebc36205f2f2cbbd5"
    ),
    "golden/outcome-report.json": (
        "382c1c020dbeabc0cc0f58442843cd5b677dfcfd6990efd3659a99a2d173cf17"
    ),
    "golden/outcome-execution-record.json": (
        "a76db9db1b51826e4869fe57237d6e2102eda096e8d00fe1c44e9ed8d5bacbf9"
    ),
    "golden/trust-bundle.json": (
        "7499f7cbfeb94f6e3f3dba73c368bb4eb8f9f13b19c13eab7640b0071cab19f1"
    ),
    "golden/expectations.json": (
        "74d72e4f0758c38250b538ca7489b335126a28baecebffac5298959be05f427a"
    ),
}

# Synthetic, explicitly non-repository execution identity. Reports built in
# this module are test scratch and are never presented as authoritative output,
# so they must not carry any real commit of this repository.
VERIFIER_COMMIT = "0" * 40

DECLARED = sro.DECLARED_ORIGINS
SLUGS = {origin: origin.replace("_", "-") for origin in DECLARED}
SLUGS[sro.NOT_DECLARED] = sro.NOT_DECLARED.replace("_", "-")


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


V0_2_TRUST_BUNDLE = _load(V0_2_INPUTS / "trust-bundle.json")
V0_2_REPORT_SCHEMA = _load(V0_2_ROOT / "verification-report.schema.json")
ORIGIN_CONTRACT = _load(V0_2_ROOT / "origin-disclosure-contract.json")
PIN_CONTRACT = _load(V0_2_ROOT / "envelope-schema-pin-contract.json")

V0_1_ADMISSION_RECEIPT = _load(V0_1_GOLDEN / "admission-receipt.json")
V0_1_OUTCOME_RECEIPT = _load(V0_1_GOLDEN / "outcome-receipt.json")
V0_1_TRUST_BUNDLE = _load(V0_1_GOLDEN / "trust-bundle.json")
V0_1_ADMISSION_REPORT = _load(V0_1_GOLDEN / "admission-report.json")
V0_1_OUTCOME_REPORT = _load(V0_1_GOLDEN / "outcome-report.json")


def _input_receipt(state: str) -> dict:
    return _load(V0_2_INPUTS / f"origin-{SLUGS[state]}-receipt.json")


def _case(state: str) -> tuple[dict, dict]:
    """An input receipt and the report built from it, in-process.

    The report side of every pair is produced here by the real verification
    path rather than read from disk, so a contract failure is attributable to
    the builder rather than to a stale committed byte.
    """

    receipt = _input_receipt(state)
    _, report = _build_v0_2(receipt, V0_2_TRUST_BUNDLE, SCHEMA_V0_2_1)
    return receipt, report


def _build_v0_2(receipt, trust_bundle, schema_path, *, profile=MCP_PROFILE):
    verification = verify_receipt(
        receipt, trust_bundle, schema_path=schema_path, selected_profile=profile
    )
    report = dr2.build_verification_report(
        receipt,
        verification,
        selected_profile=profile,
        trust_bundle=trust_bundle,
        verifier_commit=VERIFIER_COMMIT,
        envelope_schema_sha256=_sha256(schema_path),
    )
    return verification, report


def _build_v0_1(receipt, trust_bundle, schema_path, *, profile=MCP_PROFILE):
    verification = verify_receipt(
        receipt, trust_bundle, schema_path=schema_path, selected_profile=profile
    )
    report = dr.build_verification_report(
        receipt,
        verification,
        selected_profile=profile,
        trust_bundle=trust_bundle,
        verifier_commit=VERIFIER_COMMIT,
        envelope_schema_sha256=_sha256(schema_path),
    )
    return verification, report


# ---------------------------------------------------------------------------
# Frozen predecessors (proof 7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relative", sorted(V0_1_FROZEN_DIGESTS))
def test_v0_1_predecessor_bytes_are_unchanged(relative: str) -> None:
    assert _sha256(V0_1_ROOT / relative) == V0_1_FROZEN_DIGESTS[relative], relative


def test_v0_1_report_and_execution_record_contracts_stay_closed() -> None:
    for name in (
        "verification-report.schema.json",
        "verification-execution-record.schema.json",
    ):
        schema = _load(V0_1_ROOT / name)
        assert schema["additionalProperties"] is False, name


def test_v0_1_report_schema_has_no_origin_field() -> None:
    schema = _load(V0_1_ROOT / "verification-report.schema.json")
    assert dr2.ORIGIN_DISCLOSURE_FIELD not in schema["properties"]
    assert "subject_ref_origin" not in schema["properties"]


# ---------------------------------------------------------------------------
# S1 schema pin (proof 10) and the retained v0.2.0 pin (proof 11)
# ---------------------------------------------------------------------------


def test_v0_2_1_schema_digest_matches_s1_pin() -> None:
    assert _sha256(VENDOR_SCHEMA_V0_2_1) == S1_SCHEMA_SHA256
    assert _sha256(SCHEMA_V0_2_1) == S1_SCHEMA_SHA256


def test_vendored_and_runtime_v0_2_1_schemas_are_byte_identical() -> None:
    assert VENDOR_SCHEMA_V0_2_1.read_bytes() == SCHEMA_V0_2_1.read_bytes()


def test_v0_2_0_pin_is_retained_verbatim() -> None:
    assert ENVELOPE_SCHEMA_PINS["v0.2.0"] == FROZEN_SCHEMA_SHA256
    assert _sha256(SCHEMA_V0_2_0) == FROZEN_SCHEMA_SHA256
    assert FROZEN_SCHEMA_SHA256 in ACCEPTED_SCHEMA_SHA256


def test_pin_contract_matches_the_verifier_pins() -> None:
    by_version = {entry["envelope_version"]: entry for entry in PIN_CONTRACT["pins"]}
    assert set(by_version) == set(ENVELOPE_SCHEMA_PINS)
    for version, digest in ENVELOPE_SCHEMA_PINS.items():
        assert by_version[version]["sha256"] == digest
    assert by_version["v0.2.0"]["status"] == "retained"
    assert by_version["v0.2.1"]["status"] == "added"


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_retained_v0_2_0_pin_still_verifies_historical_inputs(kind: str) -> None:
    receipt = V0_1_ADMISSION_RECEIPT if kind == "admission" else V0_1_OUTCOME_RECEIPT
    verification = verify_receipt(
        receipt,
        V0_1_TRUST_BUNDLE,
        schema_path=SCHEMA_V0_2_0,
        selected_profile=MCP_PROFILE,
    )
    assert verification.schema_digest is True
    assert verification.passed is True


def test_unpinned_schema_still_fails_the_schema_digest_verdict(tmp_path) -> None:
    tampered = tmp_path / "srs-envelope-unpinned.schema.json"
    schema = _load(SCHEMA_V0_2_1)
    schema["title"] = "Not a pinned artifact"
    tampered.write_text(json.dumps(schema), encoding="utf-8")

    verification = verify_receipt(
        V0_1_ADMISSION_RECEIPT,
        V0_1_TRUST_BUNDLE,
        schema_path=tampered,
        selected_profile=MCP_PROFILE,
    )
    assert verification.schema_digest is False
    assert "schema.digest_mismatch" in verification.failure_codes


@pytest.mark.parametrize("relative", sorted(S1_VECTOR_PINS))
def test_vendored_s1_origin_vectors_match_their_pins(relative: str) -> None:
    expected_sha256, expected_reading = S1_VECTOR_PINS[relative]
    path = VENDOR_VECTORS / relative
    assert _sha256(path) == expected_sha256
    assert read_subject_ref_origin(_load(path)) == expected_reading


def test_vendored_s1_vector_manifest_agrees_with_our_reader() -> None:
    manifest = _load(VENDOR_VECTORS / "manifest.json")
    assert manifest["schema"]["sha256"] == S1_SCHEMA_SHA256
    for entry in manifest["entries"]:
        receipt = _load(VENDOR_VECTORS / entry["path"])
        assert read_subject_ref_origin(receipt) == entry["expected_origin_reading"]
        assert (
            _sha256(VENDOR_VECTORS / entry["path"]) == entry["receipt_file_sha256"]
        )


# ---------------------------------------------------------------------------
# Frozen origin contract
# ---------------------------------------------------------------------------


def test_declared_origin_vocabulary_is_exactly_the_five_values() -> None:
    assert sro.DECLARED_ORIGINS == (
        "supplied_subject",
        "derived_from_session",
        "derived_from_request",
        "derived_from_supplied_correlation",
        "binding_minted",
    )


def test_not_declared_is_not_a_declared_origin() -> None:
    assert sro.NOT_DECLARED == "not_declared"
    assert sro.NOT_DECLARED not in sro.DECLARED_ORIGINS
    assert sro.is_declared_origin(sro.NOT_DECLARED) is False


def test_not_declared_never_enters_the_receipt_schema() -> None:
    for schema_path in (SCHEMA_V0_2_1, VENDOR_SCHEMA_V0_2_1, SCHEMA_V0_2_0):
        assert sro.NOT_DECLARED not in schema_path.read_text(encoding="utf-8")


def test_envelope_schema_enum_is_exactly_the_five_declared_values() -> None:
    schema = _load(SCHEMA_V0_2_1)
    assert schema["properties"]["subject_ref_origin"]["enum"] == list(DECLARED)


def test_origin_contract_pins_the_frozen_vocabulary() -> None:
    assert ORIGIN_CONTRACT["declared_values"] == list(DECLARED)
    assert ORIGIN_CONTRACT["absence_rendering"] == sro.NOT_DECLARED
    assert ORIGIN_CONTRACT["disclosure_values"] == list(sro.ORIGIN_DISCLOSURE_VALUES)
    assert ORIGIN_CONTRACT["report_field"] == dr2.ORIGIN_DISCLOSURE_FIELD


# ---------------------------------------------------------------------------
# Reader behavior (proofs 1, 2, 3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("declared", DECLARED)
def test_reader_discloses_each_declared_value_verbatim(declared: str) -> None:
    assert read_subject_ref_origin({"subject_ref_origin": declared}) == declared


def test_reader_renders_genuine_absence_as_not_declared() -> None:
    assert read_subject_ref_origin({}) == sro.NOT_DECLARED
    assert (
        read_subject_ref_origin({"subject_ref": "tool-call:x"}) == sro.NOT_DECLARED
    )


@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param(None, id="present_null"),
        pytest.param("not_declared", id="not_declared_as_a_value"),
        pytest.param("", id="empty_string"),
        pytest.param("SUPPLIED_SUBJECT", id="wrong_case"),
        pytest.param("supplied_subject ", id="trailing_space"),
        pytest.param("derived_from_somewhere_else", id="out_of_enum"),
        pytest.param(True, id="json_boolean"),
        pytest.param(7, id="json_number"),
        pytest.param(["supplied_subject"], id="json_array"),
        pytest.param({"value": "supplied_subject"}, id="json_object"),
    ],
)
def test_reader_refuses_to_launder_a_malformed_value_into_absence(malformed) -> None:
    with pytest.raises(MalformedSubjectRefOrigin):
        read_subject_ref_origin({"subject_ref_origin": malformed})


def test_reader_never_infers_origin_from_surrounding_fields() -> None:
    # Every field an inference could be tempted by, and no declared origin.
    receipt = {
        "subject_ref": "subject:operator-supplied:acct_0001",
        "logical_call_id": "call-1",
        "receipt_id": "urn:srs:receipt:admission:1",
        "issuer_id": "issuer:vcp:test",
        "runtime_instance_id": "runtime:dagr:1",
        "boundary_id": "boundary:dagr:1",
        "receipt_version": "srs.core.v5.1",
    }
    assert read_subject_ref_origin(receipt) == sro.NOT_DECLARED


def test_malformed_present_value_also_fails_the_envelope_verdict() -> None:
    receipt, _ = _case("supplied_subject")
    mutated = copy.deepcopy(receipt)
    mutated["subject_ref_origin"] = "derived_from_somewhere_else"

    verification = verify_receipt(
        mutated,
        V0_2_TRUST_BUNDLE,
        schema_path=SCHEMA_V0_2_1,
        selected_profile=MCP_PROFILE,
    )
    assert verification.envelope is False
    assert "envelope.schema_invalid" in verification.failure_codes

    with pytest.raises(MalformedSubjectRefOrigin):
        dr2.build_verification_report(
            mutated,
            verification,
            selected_profile=MCP_PROFILE,
            trust_bundle=V0_2_TRUST_BUNDLE,
            verifier_commit=VERIFIER_COMMIT,
            envelope_schema_sha256=_sha256(SCHEMA_V0_2_1),
        )


# ---------------------------------------------------------------------------
# v0.2 report schema (proof 8) and the disclosure/verdict boundary
# ---------------------------------------------------------------------------


def test_v0_2_report_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(V0_2_REPORT_SCHEMA)


def test_v0_2_report_schema_fails_closed() -> None:
    assert V0_2_REPORT_SCHEMA["additionalProperties"] is False


def test_v0_2_verdicts_are_still_exactly_the_eight_booleans() -> None:
    verdicts = V0_2_REPORT_SCHEMA["properties"]["verdicts"]
    assert verdicts["additionalProperties"] is False
    assert set(verdicts["required"]) == set(dr.VERDICT_FIELDS)
    assert set(verdicts["properties"]) == set(dr.VERDICT_FIELDS)
    assert all(
        spec == {"type": "boolean"} for spec in verdicts["properties"].values()
    )


def test_v0_2_chain_status_is_not_a_verdict() -> None:
    verdicts = V0_2_REPORT_SCHEMA["properties"]["verdicts"]
    assert "chain_status" not in verdicts["properties"]
    assert V0_2_REPORT_SCHEMA["properties"]["chain_status"]["enum"] == [
        "not_applicable"
    ]


def test_v0_2_origin_disclosure_is_not_a_verdict() -> None:
    verdicts = V0_2_REPORT_SCHEMA["properties"]["verdicts"]
    assert dr2.ORIGIN_DISCLOSURE_FIELD not in verdicts["properties"]
    assert dr2.ORIGIN_DISCLOSURE_FIELD in V0_2_REPORT_SCHEMA["properties"]
    assert dr2.ORIGIN_DISCLOSURE_FIELD in V0_2_REPORT_SCHEMA["required"]


def test_v0_2_origin_field_carries_exactly_the_six_disclosure_values() -> None:
    spec = V0_2_REPORT_SCHEMA["properties"][dr2.ORIGIN_DISCLOSURE_FIELD]
    assert spec["enum"] == list(sro.ORIGIN_DISCLOSURE_VALUES)
    assert spec["type"] == "string"


def test_v0_2_adds_exactly_one_field_over_v0_1() -> None:
    v0_1 = _load(V0_1_ROOT / "verification-report.schema.json")
    added = set(V0_2_REPORT_SCHEMA["properties"]) - set(v0_1["properties"])
    removed = set(v0_1["properties"]) - set(V0_2_REPORT_SCHEMA["properties"])
    assert added == {dr2.ORIGIN_DISCLOSURE_FIELD}
    assert removed == set()
    assert set(V0_2_REPORT_SCHEMA["required"]) - set(v0_1["required"]) == {
        dr2.ORIGIN_DISCLOSURE_FIELD
    }


@pytest.mark.parametrize("state", list(DECLARED) + [sro.NOT_DECLARED])
def test_origin_disclosure_as_a_ninth_verdict_fails_schema(state: str) -> None:
    _, report = _case(state)
    mutated = copy.deepcopy(report)
    mutated["verdicts"][dr2.ORIGIN_DISCLOSURE_FIELD] = state
    assert dr2.validate_verification_report(mutated) != []


def test_unknown_v0_2_report_field_fails_schema() -> None:
    _, report = _case("supplied_subject")
    mutated = copy.deepcopy(report)
    mutated["unexpected_field"] = "not part of the contract"
    assert dr2.validate_verification_report(mutated) != []


def test_out_of_vocabulary_disclosure_fails_schema() -> None:
    _, report = _case("supplied_subject")
    mutated = copy.deepcopy(report)
    mutated[dr2.ORIGIN_DISCLOSURE_FIELD] = "derived_from_somewhere_else"
    assert dr2.validate_verification_report(mutated) != []


def test_missing_disclosure_fails_schema() -> None:
    _, report = _case("supplied_subject")
    mutated = copy.deepcopy(report)
    del mutated[dr2.ORIGIN_DISCLOSURE_FIELD]
    assert dr2.validate_verification_report(mutated) != []


def test_v0_1_report_is_not_a_valid_v0_2_report() -> None:
    assert dr2.validate_verification_report(V0_1_ADMISSION_REPORT) != []


# ---------------------------------------------------------------------------
# Reports built from the input fixtures (proofs 1, 2, 8)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", list(DECLARED) + [sro.NOT_DECLARED])
def test_report_rebuilds_byte_identical(state: str) -> None:
    """Two builds of one input agree exactly, including the supplied commit."""

    receipt = _input_receipt(state)
    _, first = _build_v0_2(receipt, V0_2_TRUST_BUNDLE, SCHEMA_V0_2_1)
    _, second = _build_v0_2(receipt, V0_2_TRUST_BUNDLE, SCHEMA_V0_2_1)
    assert first == second
    assert first["verifier_commit"] == VERIFIER_COMMIT


@pytest.mark.parametrize("state", list(DECLARED) + [sro.NOT_DECLARED])
def test_built_report_validates_against_its_own_contract(state: str) -> None:
    _, report = _case(state)
    assert dr2.validate_verification_report(report) == []


@pytest.mark.parametrize("declared", DECLARED)
def test_each_declared_value_survives_into_the_report_unchanged(
    declared: str,
) -> None:
    receipt, report = _case(declared)
    assert receipt["subject_ref_origin"] == declared
    assert report[dr2.ORIGIN_DISCLOSURE_FIELD] == declared


def test_genuine_absence_input_produces_not_declared() -> None:
    receipt, report = _case(sro.NOT_DECLARED)
    assert "subject_ref_origin" not in receipt
    assert report[dr2.ORIGIN_DISCLOSURE_FIELD] == sro.NOT_DECLARED


def test_every_state_is_covered_and_hash_bound_to_its_input() -> None:
    """Each of the six states resolves to one report bound to its receipt."""

    disclosed = []
    digests = set()
    for state in list(DECLARED) + [sro.NOT_DECLARED]:
        receipt, report = _case(state)
        disclosed.append(report[dr2.ORIGIN_DISCLOSURE_FIELD])
        digests.add(dr2.verification_report_digest(report))

        assert report["receipt_artifact_hash"] == dr.receipt_artifact_hash(receipt)
        assert report["trust_bundle_digest"] == dr.trust_bundle_digest(
            V0_2_TRUST_BUNDLE
        )
        assert report[
            "verifier_configuration_digest"
        ] == dr.verifier_configuration_digest(
            selected_profile=MCP_PROFILE,
            envelope_schema_sha256=S1_SCHEMA_SHA256,
        )

    assert disclosed == list(sro.ORIGIN_DISCLOSURE_VALUES)
    assert len(digests) == len(disclosed)


def test_all_six_inputs_share_one_subject_ref_and_still_disclose_six_origins() -> None:
    subject_refs = set()
    disclosed = []
    for state in list(DECLARED) + [sro.NOT_DECLARED]:
        receipt, report = _case(state)
        subject_refs.add(receipt["subject_ref"])
        disclosed.append(report[dr2.ORIGIN_DISCLOSURE_FIELD])
    assert len(subject_refs) == 1
    assert disclosed == list(sro.ORIGIN_DISCLOSURE_VALUES)


# ---------------------------------------------------------------------------
# No origin value moves a verdict (proofs 5, 6)
# ---------------------------------------------------------------------------


def test_no_origin_value_moves_any_boolean_or_chain_status() -> None:
    baseline_verdicts = None
    baseline_chain = None
    for state in list(DECLARED) + [sro.NOT_DECLARED]:
        _, report = _case(state)
        if baseline_verdicts is None:
            baseline_verdicts = report["verdicts"]
            baseline_chain = report["chain_status"]
        assert report["verdicts"] == baseline_verdicts, state
        assert report["chain_status"] == baseline_chain, state
        assert report["failure_codes"] == [], state
    assert baseline_verdicts == {name: True for name in dr.VERDICT_FIELDS}
    assert baseline_chain == "not_applicable"


@pytest.mark.parametrize("declared", DECLARED)
def test_declared_origin_cannot_rescue_a_failing_receipt(declared: str) -> None:
    """A failing input stays failing whatever origin it declares."""

    receipt, _ = _case(sro.NOT_DECLARED)
    untrusted = copy.deepcopy(V0_2_TRUST_BUNDLE)
    untrusted["issuers"][0]["trusted"] = False

    _, absent_report = _build_v0_2(receipt, untrusted, SCHEMA_V0_2_1)

    declaring, _ = _case(declared)
    _, declared_report = _build_v0_2(declaring, untrusted, SCHEMA_V0_2_1)

    assert absent_report["verdicts"]["issuer_key_trusted"] is False
    assert declared_report["verdicts"]["issuer_key_trusted"] is False
    assert declared_report["verdicts"] == absent_report["verdicts"]
    assert declared_report["chain_status"] == absent_report["chain_status"]
    assert declared_report["failure_codes"] == absent_report["failure_codes"]
    assert declared_report[dr2.ORIGIN_DISCLOSURE_FIELD] == declared
    assert absent_report[dr2.ORIGIN_DISCLOSURE_FIELD] == sro.NOT_DECLARED
    assert dr2.validate_verification_report(declared_report) == []


def test_absence_cannot_downgrade_a_passing_receipt() -> None:
    receipt, report = _case(sro.NOT_DECLARED)
    verification, _ = _build_v0_2(receipt, V0_2_TRUST_BUNDLE, SCHEMA_V0_2_1)
    assert verification.passed is True
    assert report["verdicts"] == {name: True for name in dr.VERDICT_FIELDS}


# ---------------------------------------------------------------------------
# v0.1 / v0.2 parity (proofs 4, 5, 6)
# ---------------------------------------------------------------------------

_PARITY_CASES = [
    pytest.param("admission", "pass", id="admission_pass"),
    pytest.param("outcome", "pass", id="outcome_pass"),
    pytest.param("admission", "untrusted", id="admission_fail_untrusted"),
    pytest.param("outcome", "untrusted", id="outcome_fail_untrusted"),
    pytest.param("admission", "unresolved", id="admission_fail_unresolved"),
    pytest.param("outcome", "unresolved", id="outcome_fail_unresolved"),
    pytest.param("admission", "tampered", id="admission_fail_tampered"),
    pytest.param("outcome", "tampered", id="outcome_fail_tampered"),
]


def _parity_input(kind: str, mode: str) -> tuple[dict, dict]:
    receipt = copy.deepcopy(
        V0_1_ADMISSION_RECEIPT if kind == "admission" else V0_1_OUTCOME_RECEIPT
    )
    bundle = copy.deepcopy(V0_1_TRUST_BUNDLE)

    if mode == "untrusted":
        bundle["issuers"][0]["trusted"] = False
    elif mode == "unresolved":
        bundle["issuers"][0]["key_id"] = "issuer.substituted/receipt-signing/v1"
    elif mode == "tampered":
        receipt["issued_at"] = "2099-01-01T00:00:00Z"

    return receipt, bundle


@pytest.mark.parametrize("kind,mode", _PARITY_CASES)
def test_v0_1_and_v0_2_agree_on_everything_but_the_disclosure(
    kind: str, mode: str
) -> None:
    receipt, bundle = _parity_input(kind, mode)

    v1_verification, v1_report = _build_v0_1(receipt, bundle, SCHEMA_V0_2_0)
    v2_verification, v2_report = _build_v0_2(receipt, bundle, SCHEMA_V0_2_0)

    # Same pass/fail disposition.
    assert v1_verification.passed == v2_verification.passed

    # Same eight Booleans, and chain_status unchanged.
    assert v1_report["verdicts"] == v2_report["verdicts"]
    assert set(v2_report["verdicts"]) == set(dr.VERDICT_FIELDS)
    assert v1_report["chain_status"] == v2_report["chain_status"]

    # Only the version identifiers and the added disclosure differ.
    differing = {
        key
        for key in set(v1_report) | set(v2_report)
        if v1_report.get(key) != v2_report.get(key)
    }
    assert differing == {
        "report_version",
        "report_contract_id",
        dr2.ORIGIN_DISCLOSURE_FIELD,
    }

    # Both remain valid against their own contracts.
    assert dr.validate_verification_report(v1_report) == []
    assert dr2.validate_verification_report(v2_report) == []


@pytest.mark.parametrize("kind,mode", _PARITY_CASES)
def test_pre_existing_inputs_disclose_not_declared(kind: str, mode: str) -> None:
    receipt, bundle = _parity_input(kind, mode)
    _, v2_report = _build_v0_2(receipt, bundle, SCHEMA_V0_2_0)
    assert v2_report[dr2.ORIGIN_DISCLOSURE_FIELD] == sro.NOT_DECLARED


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_existing_v0_1_goldens_keep_their_exact_verdicts_under_v0_2(
    kind: str,
) -> None:
    golden = V0_1_ADMISSION_REPORT if kind == "admission" else V0_1_OUTCOME_REPORT
    receipt = V0_1_ADMISSION_RECEIPT if kind == "admission" else V0_1_OUTCOME_RECEIPT
    _, v2_report = _build_v0_2(receipt, V0_1_TRUST_BUNDLE, SCHEMA_V0_2_0)

    assert v2_report["verdicts"] == golden["verdicts"]
    assert v2_report["chain_status"] == golden["chain_status"]
    assert v2_report["failure_codes"] == golden["failure_codes"]
    assert v2_report["receipt_artifact_hash"] == golden["receipt_artifact_hash"]
    assert v2_report["trust_bundle_digest"] == golden["trust_bundle_digest"]
    assert (
        v2_report["verifier_configuration_digest"]
        == golden["verifier_configuration_digest"]
    )


def test_v0_2_builder_delegates_to_the_frozen_v0_1_builder() -> None:
    """Parity is structural: there is no second verdict path."""

    source = (
        ROOT / "arcs_verify" / "dagr_report_v0_2.py"
    ).read_text(encoding="utf-8")
    assert "_build_verification_report_v0_1" in source
    assert "VerificationReport()" not in source


# ---------------------------------------------------------------------------
# Import boundary (proof 9)
# ---------------------------------------------------------------------------

FORBIDDEN_IMPORT_ROOTS = {
    "dagr",
    "dagr_mcp",
    "dagr_runtime",
    "arcs_srs",
    "srs",
    "srs_emitter",
    "fastmcp",
    "mcp",
    "countervail",
}

_LANE_MODULES = (
    "arcs_verify/subject_ref_origin.py",
    "arcs_verify/dagr_report_v0_2.py",
    "arcs_verify/dagr_report.py",
    "arcs_verify/verifier.py",
    "arcs_verify/cli.py",
    "tools/generate_dagr_report_v0_2_goldens.py",
)


def _import_roots(path: Path) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".", 1)[0])
    return roots


@pytest.mark.parametrize("relative", _LANE_MODULES)
def test_no_emitter_package_is_imported(relative: str) -> None:
    roots = _import_roots(ROOT / relative)
    assert roots.isdisjoint(FORBIDDEN_IMPORT_ROOTS), sorted(
        roots & FORBIDDEN_IMPORT_ROOTS
    )


def test_origin_reader_imports_nothing_but_typing() -> None:
    """The reader recomputes from bytes; it has no dependencies to speak of."""

    roots = _import_roots(ROOT / "arcs_verify" / "subject_ref_origin.py")
    assert roots <= {"__future__", "typing"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", list(DECLARED) + [sro.NOT_DECLARED])
def test_cli_dagr_report_v0_2_emits_schema_valid_output(state, capsys) -> None:
    slug = SLUGS[state]
    code = cli_main(
        [
            "dagr-report-v0-2",
            str(V0_2_INPUTS / f"origin-{slug}-receipt.json"),
            "--keyring",
            str(V0_2_INPUTS / "trust-bundle.json"),
            "--profile",
            MCP_PROFILE,
            "--schema",
            str(SCHEMA_V0_2_1),
            "--verifier-commit",
            VERIFIER_COMMIT,
        ]
    )
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert dr2.validate_verification_report(report) == []
    assert report[dr2.ORIGIN_DISCLOSURE_FIELD] == state


def test_cli_dagr_report_v0_2_refuses_a_malformed_origin(tmp_path, capsys) -> None:
    receipt, _ = _case("supplied_subject")
    receipt["subject_ref_origin"] = "derived_from_somewhere_else"
    bad = tmp_path / "malformed-origin-receipt.json"
    bad.write_text(json.dumps(receipt), encoding="utf-8")

    code = cli_main(
        [
            "dagr-report-v0-2",
            str(bad),
            "--keyring",
            str(V0_2_INPUTS / "trust-bundle.json"),
            "--schema",
            str(SCHEMA_V0_2_1),
            "--verifier-commit",
            VERIFIER_COMMIT,
        ]
    )
    assert code == 2
    assert sro.NOT_DECLARED not in capsys.readouterr().out


def test_cli_dagr_report_v0_2_returns_failure_exit_code(tmp_path, capsys) -> None:
    untrusted = copy.deepcopy(V0_2_TRUST_BUNDLE)
    untrusted["issuers"][0]["trusted"] = False
    bundle = tmp_path / "untrusted-bundle.json"
    bundle.write_text(json.dumps(untrusted), encoding="utf-8")

    code = cli_main(
        [
            "dagr-report-v0-2",
            str(V0_2_INPUTS / "origin-binding-minted-receipt.json"),
            "--keyring",
            str(bundle),
            "--schema",
            str(SCHEMA_V0_2_1),
            "--verifier-commit",
            VERIFIER_COMMIT,
        ]
    )
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["verdicts"]["issuer_key_trusted"] is False
    assert report[dr2.ORIGIN_DISCLOSURE_FIELD] == "binding_minted"


def test_cli_dagr_report_v0_2_requires_verifier_commit() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_main(
            [
                "dagr-report-v0-2",
                str(V0_2_INPUTS / "origin-supplied-subject-receipt.json"),
                "--keyring",
                str(V0_2_INPUTS / "trust-bundle.json"),
            ]
        )
    assert exc_info.value.code == 2


def test_v0_1_cli_path_is_untouched(capsys) -> None:
    code = cli_main(
        [
            "dagr-report",
            str(V0_1_GOLDEN / "admission-receipt.json"),
            "--keyring",
            str(V0_1_GOLDEN / "trust-bundle.json"),
            "--profile",
            MCP_PROFILE,
            "--schema",
            str(SCHEMA_V0_2_0),
            "--verifier-commit",
            VERIFIER_COMMIT,
            "--execution-id",
            "exec:v0-2-lane-regression:0001",
            "--executed-at",
            "2026-07-31T00:00:00Z",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    report = payload["verification_report"]
    assert report["report_version"] == "v0.1"
    assert dr2.ORIGIN_DISCLOSURE_FIELD not in report
    assert dr.validate_verification_report(report) == []
