"""Direct contract gate for arcs_verify/contracts/dagr-srs-verification-report-v0-1/.

This is the single command that verifies the frozen v0.1 DAGR SRS
verification execution/report contract:

    python -m pytest tests/test_dagr_srs_report_contract.py -q

It checks contract-file presence, JSON Schema closure, exact golden hashes,
deterministic reports, deterministic execution records, and the required
hostile vectors. It exercises the actual existing verification path
(arcs_verify.verifier.verify_receipt) via arcs_verify.dagr_report -- it does
not define a second receipt verifier.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from arcs_verify import dagr_report as dr
from arcs_verify.cli import main as cli_main
from arcs_verify.verifier import MCP_PROFILE, RESULT_LIMIT, verify_receipt

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = dr._CONTRACT_ROOT
GOLDEN = CONTRACT_ROOT / "golden"
SCHEMA = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.0.schema.json"

VERIFIER_COMMIT = "da89ebe36f1e4d9921aeeb7ff12f377d6804e8f7"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


ADMISSION_RECEIPT = _load(GOLDEN / "admission-receipt.json")
OUTCOME_RECEIPT = _load(GOLDEN / "outcome-receipt.json")
TRUST_BUNDLE = _load(GOLDEN / "trust-bundle.json")
EXPECTATIONS = _load(GOLDEN / "expectations.json")
ADMISSION_REPORT = _load(GOLDEN / "admission-report.json")
OUTCOME_REPORT = _load(GOLDEN / "outcome-report.json")
ADMISSION_RECORD = _load(GOLDEN / "admission-execution-record.json")
OUTCOME_RECORD = _load(GOLDEN / "outcome-execution-record.json")

REPORT_SCHEMA = _load(CONTRACT_ROOT / "verification-report.schema.json")
EXECUTION_RECORD_SCHEMA = _load(
    CONTRACT_ROOT / "verification-execution-record.schema.json"
)


# ---------------------------------------------------------------------------
# Contract-file presence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relative",
    [
        "README.md",
        "execution-contract.json",
        "verification-report.schema.json",
        "verification-execution-record.schema.json",
        "receipt-hash-contract.json",
        "supported-receipt-contract.json",
        "golden/admission-receipt.json",
        "golden/admission-report.json",
        "golden/admission-execution-record.json",
        "golden/outcome-receipt.json",
        "golden/outcome-report.json",
        "golden/outcome-execution-record.json",
        "golden/trust-bundle.json",
        "golden/expectations.json",
    ],
)
def test_contract_file_present(relative: str) -> None:
    assert (CONTRACT_ROOT / relative).is_file(), relative


def test_golden_receipts_are_byte_identical_to_source_fixtures() -> None:
    source = (
        ROOT
        / "packs"
        / "srs.mcp.sdk_enforcement"
        / "v0.1"
        / "implementation"
        / "dagr-mcp-fastmcp-demo"
    )
    pairs = [
        ("admission-admitted.json", "admission-receipt.json"),
        ("outcome-result-returned.json", "outcome-receipt.json"),
        ("issuer-keys.json", "trust-bundle.json"),
    ]
    for source_name, golden_name in pairs:
        assert (source / source_name).read_bytes() == (
            GOLDEN / golden_name
        ).read_bytes(), golden_name


# ---------------------------------------------------------------------------
# Schema closure
# ---------------------------------------------------------------------------


def test_schemas_are_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(REPORT_SCHEMA)
    Draft202012Validator.check_schema(EXECUTION_RECORD_SCHEMA)


def test_report_schema_fails_closed_on_unknown_top_level_field() -> None:
    assert REPORT_SCHEMA["additionalProperties"] is False


def test_execution_record_schema_fails_closed_on_unknown_top_level_field() -> None:
    assert EXECUTION_RECORD_SCHEMA["additionalProperties"] is False


def test_report_schema_verdicts_are_exactly_the_eight_fields() -> None:
    verdicts_schema = REPORT_SCHEMA["properties"]["verdicts"]
    assert verdicts_schema["additionalProperties"] is False
    assert set(verdicts_schema["required"]) == set(dr.VERDICT_FIELDS)
    assert set(verdicts_schema["properties"]) == set(dr.VERDICT_FIELDS)


def test_report_schema_chain_status_is_not_inside_verdicts() -> None:
    verdicts_schema = REPORT_SCHEMA["properties"]["verdicts"]
    assert "chain_status" not in verdicts_schema["properties"]
    assert "chain_status" in REPORT_SCHEMA["properties"]


# ---------------------------------------------------------------------------
# Golden hashes, deterministic reports, deterministic execution records
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_golden_report_regenerates_byte_identical(kind: str) -> None:
    receipt = ADMISSION_RECEIPT if kind == "admission" else OUTCOME_RECEIPT
    golden_report = ADMISSION_REPORT if kind == "admission" else OUTCOME_REPORT
    golden_record = ADMISSION_RECORD if kind == "admission" else OUTCOME_RECORD

    verification = verify_receipt(
        receipt, TRUST_BUNDLE, schema_path=SCHEMA, selected_profile=MCP_PROFILE
    )
    report = dr.build_verification_report(
        receipt,
        verification,
        selected_profile=MCP_PROFILE,
        trust_bundle=TRUST_BUNDLE,
        verifier_commit=VERIFIER_COMMIT,
    )
    assert report == golden_report

    record = dr.build_verification_execution_record(
        report,
        execution_id=golden_record["execution_id"],
        executed_at=golden_record["executed_at"],
        verifier_commit=VERIFIER_COMMIT,
    )
    assert record == golden_record


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_golden_verification_passes(kind: str) -> None:
    report = ADMISSION_REPORT if kind == "admission" else OUTCOME_REPORT
    assert all(report["verdicts"].values()), report["verdicts"]
    assert report["chain_status"] == "not_applicable"
    assert report["failure_codes"] == []


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_golden_hashes_match_pinned_expectations(kind: str) -> None:
    entry = next(e for e in EXPECTATIONS["entries"] if e["receipt_kind"] == kind)
    report = ADMISSION_REPORT if kind == "admission" else OUTCOME_REPORT
    record = ADMISSION_RECORD if kind == "admission" else OUTCOME_RECORD

    assert report["receipt_artifact_hash"] == entry["receipt_artifact_hash"]
    assert report["trust_bundle_digest"] == entry["trust_bundle_digest"]
    assert (
        report["verifier_configuration_digest"]
        == entry["verifier_configuration_digest"]
    )
    assert (
        record["verification_report_digest"]
        == entry["verification_report_digest"]
    )
    assert report["verdicts"] == entry["verdicts"]
    assert report["chain_status"] == entry["chain_status"]


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_golden_report_validates_against_schema(kind: str) -> None:
    report = ADMISSION_REPORT if kind == "admission" else OUTCOME_REPORT
    assert dr.validate_verification_report(report) == []


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_golden_execution_record_validates_against_schema(kind: str) -> None:
    record = ADMISSION_RECORD if kind == "admission" else OUTCOME_RECORD
    assert dr.validate_verification_execution_record(record) == []


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_golden_execution_record_binds_to_its_report(kind: str) -> None:
    report = ADMISSION_REPORT if kind == "admission" else OUTCOME_REPORT
    record = ADMISSION_RECORD if kind == "admission" else OUTCOME_RECORD
    assert dr.check_execution_record_matches_report(record, report) == []


@pytest.mark.parametrize("kind", ["admission", "outcome"])
def test_golden_report_binds_to_its_receipt(kind: str) -> None:
    receipt = ADMISSION_RECEIPT if kind == "admission" else OUTCOME_RECEIPT
    report = ADMISSION_REPORT if kind == "admission" else OUTCOME_REPORT
    assert dr.check_report_matches_receipt(report, receipt) == []


# ---------------------------------------------------------------------------
# RFC 8785 conformance (not merely recursively sorted JSON)
# ---------------------------------------------------------------------------


def test_rfc8785_dependency_matches_official_vector() -> None:
    vectors = ROOT / "vendor" / "arcs-srs" / "vectors" / "rfc8785"
    input_doc = json.loads((vectors / "section-3.2.2-input.json").read_text())
    expected_canonical = (vectors / "section-3.2.2-canonical.json").read_bytes()
    assert rfc8785.dumps(input_doc) == expected_canonical.rstrip(b"\n")


# ---------------------------------------------------------------------------
# receipt_artifact_hash: insertion-order stability and change-sensitivity
# ---------------------------------------------------------------------------


def test_receipt_artifact_hash_stable_under_key_reordering() -> None:
    reordered = json.loads(
        json.dumps(ADMISSION_RECEIPT, sort_keys=False),
        object_pairs_hook=lambda pairs: dict(reversed(pairs)),
    )
    assert list(reordered) != list(ADMISSION_RECEIPT)  # sanity: order differs
    assert reordered == ADMISSION_RECEIPT  # sanity: same content
    assert dr.receipt_artifact_hash(reordered) == dr.receipt_artifact_hash(
        ADMISSION_RECEIPT
    )
    assert (
        dr.receipt_artifact_hash(reordered) == ADMISSION_REPORT["receipt_artifact_hash"]
    )


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda r: r.__setitem__("issued_at", "2026-07-12T13:00:00Z"), id="top_level_field"),
        pytest.param(
            lambda r: r["receipt_signature"].__setitem__("key_id", "issuer.other/receipt-signing/v9"),
            id="signature_key_id",
        ),
        pytest.param(
            lambda r: r["receipt_signature"].__setitem__(
                "signature", r["receipt_signature"]["signature"][:-2] + "aa"
            ),
            id="signature_bytes",
        ),
        pytest.param(
            lambda r: r["receipt_signature"].__setitem__("algorithm", "Ed448"),
            id="signature_algorithm",
        ),
    ],
)
def test_receipt_artifact_hash_changes_when_any_field_changes(mutate) -> None:
    mutated = copy.deepcopy(ADMISSION_RECEIPT)
    mutate(mutated)
    assert dr.receipt_artifact_hash(mutated) != dr.receipt_artifact_hash(
        ADMISSION_RECEIPT
    )


# ---------------------------------------------------------------------------
# trust_bundle_digest: member-order stability and substitution-sensitivity
# ---------------------------------------------------------------------------


def test_trust_bundle_digest_stable_under_member_order_variation() -> None:
    reordered = json.loads(
        json.dumps(TRUST_BUNDLE),
        object_pairs_hook=lambda pairs: dict(reversed(pairs)),
    )
    assert list(reordered) != list(TRUST_BUNDLE)
    assert dr.trust_bundle_digest(reordered) == dr.trust_bundle_digest(TRUST_BUNDLE)
    assert (
        dr.trust_bundle_digest(reordered) == ADMISSION_REPORT["trust_bundle_digest"]
    )


def test_trust_bundle_substitution_changes_digest_and_key_resolution() -> None:
    substitute = copy.deepcopy(TRUST_BUNDLE)
    substitute["issuers"][0]["key_id"] = "issuer.substituted/receipt-signing/v1"
    assert dr.trust_bundle_digest(substitute) != dr.trust_bundle_digest(TRUST_BUNDLE)

    verification = verify_receipt(
        ADMISSION_RECEIPT,
        substitute,
        schema_path=SCHEMA,
        selected_profile=MCP_PROFILE,
    )
    assert verification.issuer_key_resolved is False
    assert "key_id_unresolved" in verification.failure_codes


# ---------------------------------------------------------------------------
# Synthetic self-signed receipts: isolate signature-preserving vs
# signature-breaking mutations using a key this test suite controls.
# ---------------------------------------------------------------------------

_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PUBLIC_KEY = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
_KEY_ID = "issuer.dagr.report-contract/receipt-signing/v1"
_ISSUER_ID = "issuer:dagr:report-contract"

_SYNTHETIC_KEYRING = {
    "issuers": [
        {
            "issuer_id": _ISSUER_ID,
            "key_id": _KEY_ID,
            "algorithm": "Ed25519",
            "public_key": base64.urlsafe_b64encode(_PUBLIC_KEY)
            .decode("ascii")
            .rstrip("="),
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2036-01-01T00:00:00Z",
            "trusted": True,
        }
    ]
}


def _sign(envelope: dict) -> dict:
    signed = copy.deepcopy(envelope)
    signed["receipt_signature"] = {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": _KEY_ID,
        "signature": "",
    }
    preimage = copy.deepcopy(signed)
    del preimage["receipt_signature"]["signature"]
    raw_signature = _PRIVATE_KEY.sign(rfc8785.dumps(preimage))
    signed["receipt_signature"]["signature"] = (
        base64.urlsafe_b64encode(raw_signature).decode("ascii").rstrip("=")
    )
    return signed


def _base_admission() -> dict:
    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.mcp.sdk_enforcement",
        "profile_version": "v0.1",
        "receipt_id": "urn:srs:receipt:admission:report-contract-1",
        "receipt_type": "sdk_enforcement",
        "receipt_kind": "admission",
        "boundary_type": "mcp_tool_call",
        "protocol_binding": "mcp",
        "subject_ref": "tool-call:call-report-contract-1",
        "issuer_id": _ISSUER_ID,
        "runtime_instance_id": "runtime:dagr:report-contract",
        "boundary_id": "boundary:dagr:report-contract",
        "logical_call_id": "call-report-contract-1",
        "issued_at": "2026-07-12T12:00:00Z",
        "artifact_classes_covered": ["tool_call_admission"],
        "artifact_classes_excluded": [
            "raw_prompt",
            "raw_output",
            "raw_tool_arguments",
            "raw_tool_result",
        ],
        "attestation_limits": [
            "The receipt attests only to governance conditions at the named "
            "admission boundary."
        ],
        "extensions": {"mcp": {"binding_version": "fastmcp.middleware.v0.1"}},
        "requested_tool_name": "records_lookup",
        "tool_resolution_status": "not_observed",
        "argument_digest": "sha256:" + "0" * 64,
        "policy_pack_id": "policy:dagr:report-contract",
        "policy_pack_version": "v0.1",
        "disposition": "admitted",
    }


def _base_outcome() -> dict:
    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.mcp.sdk_enforcement",
        "profile_version": "v0.1",
        "receipt_id": "urn:srs:receipt:outcome:report-contract-1",
        "receipt_type": "sdk_enforcement",
        "receipt_kind": "outcome",
        "boundary_type": "mcp_tool_call",
        "protocol_binding": "mcp",
        "subject_ref": "tool-call:call-report-contract-1",
        "issuer_id": _ISSUER_ID,
        "runtime_instance_id": "runtime:dagr:report-contract",
        "boundary_id": "boundary:dagr:report-contract",
        "logical_call_id": "call-report-contract-1",
        "issued_at": "2026-07-12T12:00:01Z",
        "artifact_classes_covered": ["tool_call_outcome"],
        "artifact_classes_excluded": [
            "raw_prompt",
            "raw_output",
            "raw_tool_arguments",
            "raw_tool_result",
        ],
        "attestation_limits": [
            "The receipt attests only to governance conditions at the named "
            "admission boundary.",
            RESULT_LIMIT,
        ],
        "extensions": {"mcp": {"binding_version": "fastmcp.middleware.v0.1"}},
        "requested_tool_name": "records_lookup",
        "admission_receipt_ref": "urn:srs:receipt:admission:report-contract-1",
        "outcome": "result_returned",
        "result_digest": "sha256:" + "1" * 64,
    }


def _verify(receipt: dict):
    return verify_receipt(
        receipt, _SYNTHETIC_KEYRING, schema_path=SCHEMA, selected_profile=MCP_PROFILE
    )


def test_unknown_receipt_field_does_not_flip_verdicts_but_changes_hash() -> None:
    base = _base_outcome()
    signed_base = _sign(base)
    base_report = _verify(signed_base)
    assert base_report.passed, base_report.to_dict()

    mutated = copy.deepcopy(base)
    mutated["unexpected_extra_field"] = "harmless-but-unrecognized"
    signed_mutated = _sign(mutated)
    mutated_report = _verify(signed_mutated)
    assert mutated_report.passed, mutated_report.to_dict()

    assert dr.receipt_artifact_hash(signed_mutated) != dr.receipt_artifact_hash(
        signed_base
    )


def test_unsupported_receipt_version_fails_profile_and_signature_verdicts() -> None:
    receipt = _sign({**_base_admission(), "receipt_version": "srs.core.v9.9"})
    report = _verify(receipt)
    assert report.passed is False
    assert report.profile is False
    assert report.signature_valid is False
    assert "version_binding_mismatch" in report.failure_codes

    built = dr.build_verification_report(
        receipt,
        report,
        selected_profile=MCP_PROFILE,
        trust_bundle=_SYNTHETIC_KEYRING,
        verifier_commit=VERIFIER_COMMIT,
    )
    assert built["verdicts"]["profile"] is False
    assert built["verdicts"]["signature_valid"] is False


@pytest.mark.parametrize(
    "bad_profile",
    ["srs.mcp.sdk_enforcement.v0.2", "srs.mcp.sdk_enforcement.v99", "not-a-real-profile"],
)
def test_unsupported_profile_version_is_refused_by_report_builder(
    bad_profile: str,
) -> None:
    receipt = _sign(_base_admission())
    report = _verify(receipt)
    with pytest.raises(ValueError):
        dr.build_verification_report(
            receipt,
            report,
            selected_profile=bad_profile,
            trust_bundle=_SYNTHETIC_KEYRING,
            verifier_commit=VERIFIER_COMMIT,
        )


def test_malformed_signature_metadata_fails_signature_verdict_not_hash() -> None:
    receipt = _sign(_base_admission())
    del receipt["receipt_signature"]["canonicalization"]
    report = _verify(receipt)
    assert report.signature_valid is False
    assert "signature_object_invalid" in report.failure_codes


def test_altered_signature_value_fails_signature_and_changes_hash() -> None:
    original = _sign(_base_admission())
    altered = copy.deepcopy(original)
    sig = altered["receipt_signature"]["signature"]
    replacement = "A" if sig[10] != "A" else "B"
    altered["receipt_signature"]["signature"] = (
        sig[:10] + replacement + sig[11:]
    )

    report = _verify(altered)
    assert report.signature_valid is False
    assert "signature_invalid" in report.failure_codes
    assert dr.receipt_artifact_hash(altered) != dr.receipt_artifact_hash(original)


def test_altered_issuer_reference_fails_signature_and_changes_hash() -> None:
    original = _sign(_base_admission())
    altered = copy.deepcopy(original)
    altered["issuer_id"] = "issuer:dagr:impersonated"

    report = _verify(altered)
    assert report.signature_valid is False
    assert dr.receipt_artifact_hash(altered) != dr.receipt_artifact_hash(original)


def test_altered_receipt_disposition_fails_signature_and_changes_hash() -> None:
    original = _sign(_base_admission())
    altered = copy.deepcopy(original)
    altered["disposition"] = "refused"

    report = _verify(altered)
    assert report.signature_valid is False
    assert dr.receipt_artifact_hash(altered) != dr.receipt_artifact_hash(original)


def test_altered_outcome_linkage_fails_signature_and_changes_hash() -> None:
    original = _sign(_base_outcome())
    altered = copy.deepcopy(original)
    altered["admission_receipt_ref"] = "urn:srs:receipt:admission:someone-elses-call"

    report = _verify(altered)
    assert report.signature_valid is False
    assert dr.receipt_artifact_hash(altered) != dr.receipt_artifact_hash(original)


def test_failed_boolean_verdict_is_carried_by_a_valid_report() -> None:
    untrusted_keyring = copy.deepcopy(_SYNTHETIC_KEYRING)
    untrusted_keyring["issuers"][0]["trusted"] = False

    receipt = _sign(_base_admission())
    report = verify_receipt(
        receipt, untrusted_keyring, schema_path=SCHEMA, selected_profile=MCP_PROFILE
    )
    assert report.issuer_key_trusted is False
    assert report.passed is False

    built = dr.build_verification_report(
        receipt,
        report,
        selected_profile=MCP_PROFILE,
        trust_bundle=untrusted_keyring,
        verifier_commit=VERIFIER_COMMIT,
    )
    assert dr.validate_verification_report(built) == []
    assert built["verdicts"]["issuer_key_trusted"] is False


def test_missing_boolean_verdict_fails_schema() -> None:
    mutated = copy.deepcopy(ADMISSION_REPORT)
    del mutated["verdicts"]["signature_valid"]
    assert dr.validate_verification_report(mutated) != []


def test_non_boolean_verdict_fails_schema() -> None:
    mutated = copy.deepcopy(ADMISSION_REPORT)
    mutated["verdicts"]["signature_valid"] = "true"
    assert dr.validate_verification_report(mutated) != []


def test_chain_status_as_ninth_verdict_fails_schema() -> None:
    mutated = copy.deepcopy(ADMISSION_REPORT)
    mutated["verdicts"]["chain_status"] = "not_applicable"
    assert dr.validate_verification_report(mutated) != []


def test_unknown_report_field_fails_schema() -> None:
    mutated = copy.deepcopy(ADMISSION_REPORT)
    mutated["unexpected_field"] = "not part of the contract"
    assert dr.validate_verification_report(mutated) != []


def test_report_receipt_id_mismatch_is_detected() -> None:
    mutated = copy.deepcopy(ADMISSION_REPORT)
    mutated["receipt_id"] = "urn:srs:receipt:admission:someone-elses-receipt"
    mismatches = dr.check_report_matches_receipt(mutated, ADMISSION_RECEIPT)
    assert any("receipt_id" in m for m in mismatches)


def test_report_receipt_hash_mismatch_is_detected() -> None:
    mutated = copy.deepcopy(ADMISSION_REPORT)
    mutated["receipt_artifact_hash"] = "0" * 64
    mismatches = dr.check_report_matches_receipt(mutated, ADMISSION_RECEIPT)
    assert any("receipt_artifact_hash" in m for m in mismatches)


def test_execution_record_report_digest_mismatch_is_detected() -> None:
    mutated = copy.deepcopy(ADMISSION_RECORD)
    mutated["verification_report_digest"] = "0" * 64
    mismatches = dr.check_execution_record_matches_report(mutated, ADMISSION_REPORT)
    assert any("verification_report_digest" in m for m in mismatches)


def test_execution_record_verifier_commit_mismatch_is_detected() -> None:
    mutated = copy.deepcopy(ADMISSION_RECORD)
    mutated["verifier_commit"] = "1" * 40
    mismatches = dr.check_execution_record_matches_report(mutated, ADMISSION_REPORT)
    assert any("verifier_commit" in m for m in mismatches)


def test_json_insertion_order_variation_produces_identical_authoritative_hashes() -> None:
    receipt_reordered = json.loads(
        json.dumps(ADMISSION_RECEIPT),
        object_pairs_hook=lambda pairs: dict(reversed(pairs)),
    )
    bundle_reordered = json.loads(
        json.dumps(TRUST_BUNDLE),
        object_pairs_hook=lambda pairs: dict(reversed(pairs)),
    )
    assert dr.receipt_artifact_hash(receipt_reordered) == ADMISSION_REPORT[
        "receipt_artifact_hash"
    ]
    assert dr.trust_bundle_digest(bundle_reordered) == ADMISSION_REPORT[
        "trust_bundle_digest"
    ]


# ---------------------------------------------------------------------------
# CLI: the actual verifier entrypoint, exercising the real path end to end
# ---------------------------------------------------------------------------


def test_cli_dagr_report_subcommand_emits_schema_valid_output(capsys) -> None:
    code = cli_main(
        [
            "dagr-report",
            str(GOLDEN / "admission-receipt.json"),
            "--keyring",
            str(GOLDEN / "trust-bundle.json"),
            "--profile",
            MCP_PROFILE,
            "--schema",
            str(SCHEMA),
            "--verifier-commit",
            VERIFIER_COMMIT,
            "--execution-id",
            "exec:cli-test:0001",
            "--executed-at",
            "2026-07-21T00:00:00Z",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert dr.validate_verification_report(payload["verification_report"]) == []
    assert (
        dr.validate_verification_execution_record(
            payload["verification_execution_record"]
        )
        == []
    )
    assert (
        payload["verification_report"]["receipt_artifact_hash"]
        == ADMISSION_REPORT["receipt_artifact_hash"]
    )


def test_cli_dagr_report_requires_verifier_commit() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_main(
            [
                "dagr-report",
                str(GOLDEN / "admission-receipt.json"),
                "--keyring",
                str(GOLDEN / "trust-bundle.json"),
            ]
        )
    assert exc_info.value.code == 2


def test_cli_dagr_report_returns_verification_failure_exit_code(capsys) -> None:
    untrusted = copy.deepcopy(TRUST_BUNDLE)
    untrusted["issuers"][0]["trusted"] = False
    untrusted_path = GOLDEN / "_tmp_untrusted_bundle_for_test.json"
    untrusted_path.write_text(json.dumps(untrusted))
    try:
        code = cli_main(
            [
                "dagr-report",
                str(GOLDEN / "admission-receipt.json"),
                "--keyring",
                str(untrusted_path),
                "--profile",
                MCP_PROFILE,
                "--schema",
                str(SCHEMA),
                "--verifier-commit",
                VERIFIER_COMMIT,
                "--execution-id",
                "exec:cli-test:0002",
                "--executed-at",
                "2026-07-21T00:00:00Z",
            ]
        )
        assert code == 1
        payload = json.loads(capsys.readouterr().out)
        assert (
            payload["verification_report"]["verdicts"]["issuer_key_trusted"]
            is False
        )
    finally:
        untrusted_path.unlink()
