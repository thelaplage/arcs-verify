"""DAGR MCP delivery-state Boolean governance contract.

The DAGR emitter records ``delivery_incomplete``, ``request_cancelled``, and
``execution_state_unknown`` as top-level Boolean governance facts. Those names
are deliberately chosen so they do NOT match the raw-content key pattern, which
means a properly re-signed receipt can smuggle raw tool-result material through
one of them unless ARCS independently type-checks the field. ARCS cannot trust
issuer-side validation, so it enforces the Boolean contract itself.
"""

from __future__ import annotations

import base64
import copy
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arcs_verify.verifier import (
    MCP_BOOLEAN_GOVERNANCE_FIELDS,
    MCP_PROFILE,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.0.schema.json"

KEY_ID = "issuer.dagr.boolean-guard/receipt-signing/v1"
ISSUER_ID = "issuer:dagr:boolean-guard"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# A single ephemeral trusted signing identity for the whole module. Every
# adversarial receipt is re-signed with it, so signature validity is never the
# reason a malicious receipt is rejected.
_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PUBLIC_KEY = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

KEYRING = {
    "issuers": [
        {
            "issuer_id": ISSUER_ID,
            "key_id": KEY_ID,
            "algorithm": "Ed25519",
            "public_key": _b64url(_PUBLIC_KEY),
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2036-01-01T00:00:00Z",
            "trusted": True,
        }
    ]
}


def _sign(envelope: dict) -> dict:
    """Attach a cryptographically valid Ed25519/JCS signature."""

    signed = copy.deepcopy(envelope)
    signed["receipt_signature"] = {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": KEY_ID,
        "signature": "",
    }
    preimage = copy.deepcopy(signed)
    del preimage["receipt_signature"]["signature"]
    signed["receipt_signature"]["signature"] = _b64url(
        _PRIVATE_KEY.sign(rfc8785.dumps(preimage))
    )
    return signed


def _base_outcome() -> dict:
    """A minimal, fully valid DAGR MCP indeterminate-outcome receipt.

    ``indeterminate`` is the outcome under which the DAGR binding attaches the
    delivery-state Boolean facts, so it is the honest carrier for these fields.
    """

    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.mcp.sdk_enforcement",
        "profile_version": "v0.1",
        "receipt_id": "urn:srs:receipt:outcome:boolean-guard-1",
        "receipt_type": "sdk_enforcement",
        "receipt_kind": "outcome",
        "boundary_type": "mcp_tool_call",
        "protocol_binding": "mcp",
        "subject_ref": "tool-call:call-boolean-guard-1",
        "issuer_id": ISSUER_ID,
        "runtime_instance_id": "runtime:dagr:boolean-guard",
        "boundary_id": "boundary:dagr:boolean-guard",
        "logical_call_id": "call-boolean-guard-1",
        "issued_at": "2026-07-11T20:00:01Z",
        "artifact_classes_covered": ["tool_call_outcome"],
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
        "retention_class_applied": "hash_only",
        "extensions": {"mcp": {"binding_version": "fastmcp.middleware.v0.1"}},
        "admission_receipt_ref": "urn:srs:receipt:admission:boolean-guard-1",
        "outcome": "indeterminate",
    }


def _verify(receipt: dict):
    return verify_receipt(
        receipt,
        KEYRING,
        schema_path=SCHEMA,
        selected_profile=MCP_PROFILE,
    )


# Raw tool-result material shaped like a fastmcp result projection. It carries
# no `result`-shaped key at the top level, so the only defense is the Boolean
# type guard on the governance field that holds it.
RAW_TOOL_RESULT_MATERIAL = {
    "content": [
        {"type": "text", "text": "PATIENT SSN 123-45-6789; full chart follows"}
    ],
    "structuredContent": {"records": [{"id": 1}]},
    "isError": False,
}


def test_registered_boolean_governance_fields_are_the_three_dagr_facts():
    assert set(MCP_BOOLEAN_GOVERNANCE_FIELDS) == {
        "delivery_incomplete",
        "request_cancelled",
        "execution_state_unknown",
    }


def test_governance_field_absent_passes():
    # Requirement 1: the field may be absent.
    report = _verify(_sign(_base_outcome()))
    assert report.passed, report.to_dict()


@pytest.mark.parametrize("field", MCP_BOOLEAN_GOVERNANCE_FIELDS)
@pytest.mark.parametrize("value", [True, False])
def test_boolean_governance_field_passes(field: str, value: bool):
    # Requirements 2-3: true and false both pass, for all three fields.
    receipt = _base_outcome()
    receipt[field] = value
    report = _verify(_sign(receipt))
    assert report.passed, report.to_dict()
    assert report.profile is True


@pytest.mark.parametrize("field", MCP_BOOLEAN_GOVERNANCE_FIELDS)
@pytest.mark.parametrize(
    "value",
    [
        "true",
        1,
        0,
        1.5,
        {"content": "raw"},
        ["raw"],
        None,
    ],
    ids=["string", "int-1", "int-0", "float", "object", "array", "null"],
)
def test_non_boolean_governance_field_fails_for_profile_reason(field, value):
    # Requirement 4: string, number, object, array, and null all fail, and the
    # failure is a profile/type reason -- never a signature failure -- on a
    # properly re-signed receipt (requirement 5).
    receipt = _base_outcome()
    receipt[field] = value
    report = _verify(_sign(receipt))

    assert report.signature_valid is True
    assert report.passed is False
    assert report.profile is False
    assert (
        f"profile.non_boolean_governance_field:{field}"
        in report.failure_codes
    )
    assert "signature_invalid" not in report.failure_codes


def test_resigned_delivery_incomplete_raw_material_rejected_independent_of_signature():
    """Acceptance proof.

    A cryptographically valid, re-signed receipt whose ``delivery_incomplete``
    field contains raw tool-result material is rejected by ARCS for a profile
    (registered-type) reason, independent of signature verification.
    """

    receipt = _base_outcome()
    receipt["delivery_incomplete"] = copy.deepcopy(RAW_TOOL_RESULT_MATERIAL)
    signed = _sign(receipt)

    report = _verify(signed)

    # The signature genuinely verifies: this is not a signature-invalidity catch.
    assert report.signature_valid is True
    assert report.issuer_key_resolved is True
    assert report.issuer_key_trusted is True

    # It still fails, for the registered-field type reason.
    assert report.passed is False
    assert report.profile is False
    assert (
        "profile.non_boolean_governance_field:delivery_incomplete"
        in report.failure_codes
    )
    assert not any(
        code in report.failure_codes
        for code in ("signature_invalid", "legacy_unverified")
    )


def test_all_three_fields_flagged_together_when_all_non_boolean():
    # Requirement 10: the three fields share one Boolean contract and are
    # covered consistently.
    receipt = _base_outcome()
    receipt["delivery_incomplete"] = "nope"
    receipt["request_cancelled"] = 1
    receipt["execution_state_unknown"] = {"x": "raw"}
    report = _verify(_sign(receipt))

    assert report.signature_valid is True
    assert report.profile is False
    for field in MCP_BOOLEAN_GOVERNANCE_FIELDS:
        assert (
            f"profile.non_boolean_governance_field:{field}"
            in report.failure_codes
        )


@pytest.mark.parametrize("raw_key", ["result", "tool_result", "raw_tool_result"])
def test_result_shaped_top_level_keys_still_fail(raw_key: str):
    # Requirement 8: genuine result-shaped keys continue to fail via
    # raw-content exclusion; the new guard does not exempt them.
    receipt = _base_outcome()
    receipt[raw_key] = {"any": "material"}
    report = _verify(_sign(receipt))

    assert report.signature_valid is True
    assert report.raw_content_exclusion is False
    assert report.passed is False


def test_nested_raw_result_material_still_fails():
    # Requirement 8: nested raw-result material remains caught by raw-content
    # exclusion, independent of the Boolean guard.
    receipt = _base_outcome()
    receipt["extensions"]["mcp"]["diagnostics"] = {
        "tool_result": {"body": "leaked"}
    }
    report = _verify(_sign(receipt))

    assert report.signature_valid is True
    assert report.raw_content_exclusion is False
    assert "raw_content.forbidden_key:tool_result" in report.failure_codes


def test_deceptive_result_shaped_governance_name_is_not_exempted():
    # Requirement 7-8: a deceptive result-shaped sibling name (not one of the
    # three registered Boolean facts) is NOT granted any exemption -- it is
    # still rejected by raw-content exclusion.
    receipt = _base_outcome()
    receipt["delivery_result"] = {"content": "raw"}
    report = _verify(_sign(receipt))

    assert report.signature_valid is True
    assert report.raw_content_exclusion is False
    assert report.passed is False
