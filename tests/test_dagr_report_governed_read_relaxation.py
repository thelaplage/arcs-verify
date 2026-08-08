"""The DAGR v0.1 report builder accepts the registered governed_read profile.

The builder previously hard-raised for every non-MCP profile via a blunt
``== MCP_PROFILE`` gate, which conflated a genuinely-unknown profile with a
registered one. Registering srs.activity.governed_read.v0.1 relaxes that gate to
a membership test: the registered profile is accepted, genuinely-unknown
profiles still raise, and MCP's own receipt-kind guard is byte-for-byte
unchanged (still only admission/outcome).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import arcs_verify.dagr_report as dr
from arcs_verify.verifier import (
    ACTIVITY_GOVERNED_READ_PROFILE,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vendor" / "arcs-srs" / "vectors" / "activity-governed-read-v0.1"
ENVELOPE_SCHEMA = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.1.schema.json"
EMPTY_KEYRING: dict[str, Any] = {"issuers": []}
VERIFIER_COMMIT = "test-commit"


def _load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def test_report_builder_accepts_registered_governed_read_profile() -> None:
    receipt = _load("valid/governed-read-admitted.json")
    verification = verify_receipt(
        receipt,
        EMPTY_KEYRING,
        schema_path=ENVELOPE_SCHEMA,
        selected_profile=ACTIVITY_GOVERNED_READ_PROFILE,
    )
    # Must not raise: the profile is registered and its kind is supported.
    report = dr.build_verification_report(
        receipt,
        verification,
        selected_profile=ACTIVITY_GOVERNED_READ_PROFILE,
        trust_bundle=EMPTY_KEYRING,
        verifier_commit=VERIFIER_COMMIT,
    )
    assert report["supported_receipt_contract_id"] == "srs.activity.governed_read"
    assert report["supported_receipt_contract_version"] == "v0.1"
    assert report["receipt_kind"] == "governed_read"


@pytest.mark.parametrize(
    "bad_profile",
    ["srs.mcp.sdk_enforcement.v0.2", "not-a-real-profile", "srs.connection.lifecycle.v0.1"],
)
def test_report_builder_still_raises_for_unknown_profile(bad_profile: str) -> None:
    receipt = _load("valid/governed-read-admitted.json")
    verification = verify_receipt(
        receipt,
        EMPTY_KEYRING,
        schema_path=ENVELOPE_SCHEMA,
        selected_profile=ACTIVITY_GOVERNED_READ_PROFILE,
    )
    with pytest.raises(ValueError):
        dr.build_verification_report(
            receipt,
            verification,
            selected_profile=bad_profile,
            trust_bundle=EMPTY_KEYRING,
            verifier_commit=VERIFIER_COMMIT,
        )


def test_report_builder_rejects_wrong_kind_for_governed_read() -> None:
    receipt = _load("valid/governed-read-admitted.json")
    receipt["receipt_kind"] = "admission"  # an MCP kind, invalid under this profile
    verification = verify_receipt(
        receipt,
        EMPTY_KEYRING,
        schema_path=ENVELOPE_SCHEMA,
        selected_profile=ACTIVITY_GOVERNED_READ_PROFILE,
    )
    with pytest.raises(ValueError):
        dr.build_verification_report(
            receipt,
            verification,
            selected_profile=ACTIVITY_GOVERNED_READ_PROFILE,
            trust_bundle=EMPTY_KEYRING,
            verifier_commit=VERIFIER_COMMIT,
        )
