import copy
import json
from pathlib import Path

from arcs_verify.verifier import MCP_PROFILE, verify_receipt

ROOT = Path(__file__).parents[1]
RECEIPT = ROOT / "packs" / "srs.mcp.sdk_enforcement" / "v0.1" / "normative" / "valid" / "admission-admitted.json"
KEYRING = ROOT / "packs" / "srs.mcp.sdk_enforcement" / "v0.1" / "normative" / "trust" / "issuer-keys.json"
SCHEMA = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.0.schema.json"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_identical_receipt_bytes_verify_identically_from_different_custody_paths(tmp_path):
    raw = RECEIPT.read_bytes()
    external = tmp_path / "external-store" / "receipt.json"
    counterpedia = tmp_path / "counterpedia-cache" / "receipt.json"
    external.parent.mkdir(parents=True)
    counterpedia.parent.mkdir(parents=True)
    external.write_bytes(raw)
    counterpedia.write_bytes(raw)

    keyring = _load(KEYRING)
    report_external = verify_receipt(
        _load(external), keyring, schema_path=SCHEMA, selected_profile=MCP_PROFILE
    ).to_dict()
    report_counterpedia = verify_receipt(
        _load(counterpedia), keyring, schema_path=SCHEMA, selected_profile=MCP_PROFILE
    ).to_dict()

    assert report_external == report_counterpedia
    assert report_external["passed"] is True


def test_publication_metadata_cannot_rescue_invalid_signature():
    receipt = _load(RECEIPT)
    keyring = _load(KEYRING)
    broken = copy.deepcopy(receipt)
    signature = broken["receipt_signature"]["signature"]
    replacement = "A" if signature[-1] != "A" else "B"
    broken["receipt_signature"]["signature"] = signature[:-1] + replacement

    publication_context = {
        "counterpedia_included": True,
        "counterpedia_standing": "published"
    }
    assert publication_context["counterpedia_included"] is True

    report = verify_receipt(
        broken, keyring, schema_path=SCHEMA, selected_profile=MCP_PROFILE
    )
    assert report.signature_valid is False
    assert report.passed is False
    assert "signature_invalid" in report.failure_codes


def test_counterpedia_absence_is_not_a_verifier_input():
    receipt = _load(RECEIPT)
    keyring = _load(KEYRING)
    publication_context = {"counterpedia_included": False}
    report = verify_receipt(
        receipt, keyring, schema_path=SCHEMA, selected_profile=MCP_PROFILE
    )
    assert publication_context["counterpedia_included"] is False
    assert report.passed is True
