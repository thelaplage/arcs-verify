from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from arcs_verify.verifier import (
    CONNECTION_PROFILE,
    MCP_PROFILE,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (
    ROOT
    / "arcs_verify"
    / "data"
    / "srs-envelope-v0.2.0.schema.json"
)

CONNECTION_ROOT = (
    ROOT
    / "tests"
    / "fixtures"
    / "connection_lifecycle"
)

CONNECTION_RECEIPT = CONNECTION_ROOT / "connect.json"
CONNECTION_KEYRING = CONNECTION_ROOT / "issuer-keys.json"
CONNECTION_SEMANTIC = (
    CONNECTION_ROOT
    / "semantic-field-change-fail.json"
)

MCP_ROOT = (
    ROOT
    / "packs"
    / "srs.mcp.sdk_enforcement"
    / "v0.1"
    / "implementation"
    / "dagr-mcp-fastmcp-demo"
)

MCP_RECEIPT = MCP_ROOT / "admission-admitted.json"
MCP_OUTCOME = MCP_ROOT / "outcome-result-returned.json"
MCP_KEYRING = MCP_ROOT / "issuer-keys.json"

GENERAL_LIMIT = (
    "The receipt establishes the governance conditions enforced at the named "
    "connection boundary for the declared lifecycle event. It does not "
    "establish provider-side behavior."
)

EVENT_LIMITS = {
    "connect": (
        "The receipt does not establish that the provider accepted, activated, "
        "maintained, or continued the connection."
    ),
    "scope_grant": (
        "The receipt does not establish that the provider enforced or honored "
        "the referenced scope set."
    ),
    "retention_selection": (
        "The receipt does not establish provider-side retention, deletion, "
        "legal-hold, or preservation behavior."
    ),
    "revoke": (
        "The receipt does not establish that provider credentials were "
        "invalidated or that provider-side access ceased."
    ),
    "delete": (
        "The receipt does not establish provider-side deletion, erasure, or "
        "destruction of provider-held data."
    ),
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify(
    receipt: dict,
    keyring: dict,
    profile: str,
):
    return verify_receipt(
        receipt,
        keyring,
        schema_path=SCHEMA,
        selected_profile=profile,
    )


def test_connection_fixture_source_digests_are_pinned():
    assert hashlib.sha256(
        CONNECTION_RECEIPT.read_bytes()
    ).hexdigest() == (
        "b6b1c18b9c1cad2e4941c1f514617e48"
        "fe63125897363c16f3d9d22d462589bc"
    )

    assert hashlib.sha256(
        CONNECTION_KEYRING.read_bytes()
    ).hexdigest() == (
        "f65c868656f2479d1233521f34313d25"
        "82b8ffb5cb853cc1c703db8dcc337fa9"
    )

    assert hashlib.sha256(
        CONNECTION_SEMANTIC.read_bytes()
    ).hexdigest() == (
        "826890a9c438b016d154307fc7e40f3a"
        "e3b3e6c31dbaf680520985b8e017de60"
    )


def test_same_verifier_accepts_mcp_and_connection_profiles():
    mcp = verify(
        load(MCP_RECEIPT),
        load(MCP_KEYRING),
        MCP_PROFILE,
    )
    connection = verify(
        load(CONNECTION_RECEIPT),
        load(CONNECTION_KEYRING),
        CONNECTION_PROFILE,
    )

    assert mcp.passed, mcp.to_dict()
    assert connection.passed, connection.to_dict()


def test_mcp_result_digest_remains_allowed_evidence():
    report = verify(
        load(MCP_OUTCOME),
        load(MCP_KEYRING),
        MCP_PROFILE,
    )

    assert report.passed, report.to_dict()
    assert report.raw_content_exclusion is True


@pytest.mark.parametrize(
    ("receipt_path", "keyring_path", "profile"),
    (
        (MCP_RECEIPT, MCP_KEYRING, MCP_PROFILE),
        (
            CONNECTION_RECEIPT,
            CONNECTION_KEYRING,
            CONNECTION_PROFILE,
        ),
    ),
)
def test_same_cli_surface_accepts_both_profiles(
    receipt_path: Path,
    keyring_path: Path,
    profile: str,
):
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            str(receipt_path),
            "--keyring",
            str(keyring_path),
            "--profile",
            profile,
            "--json",
        ],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["passed"] is True
    assert report["profile"] is True
    assert report["signature_valid"] is True


def test_connection_semantic_mutation_fails_signature_only():
    report = verify(
        load(CONNECTION_SEMANTIC),
        load(CONNECTION_KEYRING),
        CONNECTION_PROFILE,
    )

    assert report.profile is True
    assert report.signature_valid is False
    assert "signature_invalid" in report.failure_codes


def test_connection_profile_failure_is_separate_from_signature():
    receipt = load(CONNECTION_RECEIPT)
    del receipt["provider_ref"]

    report = verify(
        receipt,
        load(CONNECTION_KEYRING),
        CONNECTION_PROFILE,
    )

    assert report.profile is False
    assert report.signature_valid is False
    assert (
        "profile.connect_missing_provider_ref"
        in report.failure_codes
    )
    assert "signature_invalid" in report.failure_codes


def test_connection_raw_content_rejected_under_renamed_field():
    receipt = load(CONNECTION_RECEIPT)
    receipt["extensions"]["forum_projection"]["secret_value"] = (
        "opaque-looking-value"
    )

    report = verify(
        receipt,
        load(CONNECTION_KEYRING),
        CONNECTION_PROFILE,
    )

    assert report.raw_content_exclusion is False
    assert (
        "raw_content.forbidden_key:secret_value"
        in report.failure_codes
    )


def test_raw_named_digest_requires_sha256_evidence():
    receipt = load(CONNECTION_RECEIPT)
    receipt["extensions"]["forum_projection"]["credential_hash"] = (
        "not-a-digest"
    )

    report = verify(
        receipt,
        load(CONNECTION_KEYRING),
        CONNECTION_PROFILE,
    )

    assert report.raw_content_exclusion is False
    assert (
        "raw_content.invalid_digest_evidence:credential_hash"
        in report.failure_codes
    )


def test_sha256_digest_of_excluded_object_is_allowed_evidence():
    receipt = load(CONNECTION_RECEIPT)
    receipt["extensions"]["forum_projection"]["credential_hash"] = (
        "sha256:" + ("0" * 64)
    )

    report = verify(
        receipt,
        load(CONNECTION_KEYRING),
        CONNECTION_PROFILE,
    )

    assert report.raw_content_exclusion is True
    assert report.signature_valid is False


def test_renamed_bearer_token_value_is_rejected():
    receipt = load(CONNECTION_RECEIPT)
    receipt["extensions"]["forum_projection"]["opaque_value"] = (
        "Bearer abcdefghijklmnopqrstuvwxyz"
    )

    report = verify(
        receipt,
        load(CONNECTION_KEYRING),
        CONNECTION_PROFILE,
    )

    assert report.raw_content_exclusion is False
    assert "raw_content.prohibited_value" in report.failure_codes


@pytest.mark.parametrize(
    "kind",
    (
        "scope_grant",
        "retention_selection",
        "revoke",
        "delete",
    ),
)
def test_connection_profile_recognizes_all_lifecycle_kinds(
    kind: str,
):
    receipt = copy.deepcopy(load(CONNECTION_RECEIPT))
    receipt["receipt_kind"] = kind
    receipt["attestation_limits"] = [
        GENERAL_LIMIT,
        EVENT_LIMITS[kind],
    ]
    receipt.pop("provider_ref", None)

    if kind == "scope_grant":
        receipt["scope_refs"] = ["scope:forum:test"]

    if kind == "retention_selection":
        receipt["retention_class"] = "session"

    report = verify(
        receipt,
        load(CONNECTION_KEYRING),
        CONNECTION_PROFILE,
    )

    assert report.profile is True, report.failure_codes
    assert report.signature_valid is False


def test_unsupported_profile_selection_fails_closed():
    report = verify(
        load(CONNECTION_RECEIPT),
        load(CONNECTION_KEYRING),
        "srs.unknown.v0.1",
    )

    assert report.profile is False
    assert report.signature_valid is False
    assert "profile.unsupported_selection" in report.failure_codes
    assert "version_binding_mismatch" in report.failure_codes
