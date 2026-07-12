from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from arcs_verify.verifier import verify_receipt

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vendor/arcs-srs/vectors/signed-receipt-v0.1"
SCHEMA = ROOT / "vendor/arcs-srs/schemas/srs-envelope/v0.2.0/srs-envelope.schema.json"
KEYRING = json.loads((VECTORS / "trust/issuer-keys.json").read_text())
MANIFEST = json.loads((VECTORS / "manifest.json").read_text())

@pytest.mark.parametrize("entry", MANIFEST["entries"], ids=lambda e: e["path"])
def test_manifest_signature_expectations(entry):
    receipt = json.loads((VECTORS / entry["path"]).read_text())
    report = verify_receipt(receipt, KEYRING, schema_path=SCHEMA, selected_profile="srs.mcp.sdk_enforcement.v0.1")
    assert report.signature_valid is entry["expected_signature_valid"]


def test_valid_receipt_has_all_applicable_verdicts():
    receipt = json.loads((VECTORS / "valid/admission-admitted.json").read_text())
    report = verify_receipt(receipt, KEYRING, schema_path=SCHEMA, selected_profile="srs.mcp.sdk_enforcement.v0.1")
    assert report.passed, report.to_dict()
    assert report.chain_status == "not_applicable"


def test_trust_false_flips_only_trust_verdict():
    receipt = json.loads((VECTORS / "valid/admission-admitted.json").read_text())
    changed = copy.deepcopy(KEYRING)
    changed["issuers"][0]["trusted"] = False
    report = verify_receipt(receipt, changed, schema_path=SCHEMA, selected_profile="srs.mcp.sdk_enforcement.v0.1")
    assert report.signature_valid
    assert report.issuer_key_resolved
    assert not report.issuer_key_trusted
    assert "key_untrusted" in report.failure_codes


def test_outside_validity_flips_only_trust_verdict():
    receipt = json.loads((VECTORS / "valid/admission-admitted.json").read_text())
    changed = copy.deepcopy(KEYRING)
    changed["issuers"][0]["not_after"] = "2026-01-02T00:00:00Z"
    report = verify_receipt(receipt, changed, schema_path=SCHEMA, selected_profile="srs.mcp.sdk_enforcement.v0.1")
    assert report.signature_valid
    assert report.issuer_key_resolved
    assert not report.issuer_key_trusted


def test_raw_content_key_is_exact_and_nested():
    receipt = json.loads((VECTORS / "valid/admission-admitted.json").read_text())
    receipt["extensions"]["mcp"]["argument_digest"] = "sha256:ok"
    good = verify_receipt(receipt, KEYRING, schema_path=SCHEMA)
    assert good.raw_content_exclusion
    receipt["extensions"]["mcp"]["arguments"] = {"secret": True}
    bad = verify_receipt(receipt, KEYRING, schema_path=SCHEMA)
    assert not bad.raw_content_exclusion
    assert "raw_content.forbidden_key:arguments" in bad.failure_codes


def test_string_signature_is_legacy_unverified():
    receipt = json.loads((VECTORS / "valid/admission-admitted.json").read_text())
    receipt["receipt_signature"] = receipt["receipt_signature"]["signature"]
    report = verify_receipt(receipt, KEYRING, schema_path=SCHEMA)
    assert not report.signature_valid
    assert "legacy_unverified" in report.failure_codes


def test_machine_readable_pack_expectations_match_verifier():
    expected_path = ROOT / "packs/srs.mcp.sdk_enforcement/v0.1/expected/expectations.json"
    expectations = json.loads(expected_path.read_text())
    for item in expectations["entries"]:
        receipt = json.loads((VECTORS / item["path"]).read_text())
        report = verify_receipt(receipt, KEYRING, schema_path=SCHEMA, selected_profile="srs.mcp.sdk_enforcement.v0.1")
        assert report.signature_valid is item["signature_valid"]
        for code in item["expected_failure_codes"]:
            assert code in report.failure_codes
