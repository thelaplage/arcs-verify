from __future__ import annotations

import ast
from pathlib import Path

from arcs_verify.external_profile import (
    EXTERNAL_PROFILE_SCHEMA_SHA256,
    SRS_VNEXT_ENVELOPE_SHA256,
    SRS_VNEXT_SOURCE_HEAD,
    external_profile_cross_field_findings,
)

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "arcs_verify" / "external_profile.py"


def _profile() -> dict:
    return {
        "schema": "srs.external-profile-declaration/v0.1",
        "profile_id": "org.counterpedia.srs.mcp_read.v1",
        "profile_version": "v1",
        "publisher_ref": "org.counterpedia",
        "compatible_envelopes": [
            {
                "published_version": "srs-envelope-v0-next",
                "sha256": SRS_VNEXT_ENVELOPE_SHA256,
            }
        ],
        "permitted_receipt_types": [
            "org.counterpedia.mcp.read.admission",
            "org.counterpedia.mcp.read.outcome",
        ],
        "receipt_type_classifications": [
            {
                "receipt_type": "org.counterpedia.mcp.read.admission",
                "receipt_class": "governance_decision",
                "receipt_kind": "admission",
            },
            {
                "receipt_type": "org.counterpedia.mcp.read.outcome",
                "receipt_class": "outcome",
                "receipt_kind": "outcome",
            },
        ],
        "extension_namespace": "org.counterpedia",
        "raw_content_posture": "hash_only",
        "signing_required": True,
        "attestation_limits_required": True,
        "unknown_profile_behavior": "preserve_identity_and_do_not_infer",
        "conformance_vectors_ref": "tests/fixtures/counterpedia-vnext.json",
    }


def test_reviewed_candidate_schema_pins_are_explicit() -> None:
    assert SRS_VNEXT_SOURCE_HEAD == "e22fd69218451a86cf639bcce4691f7e1d6975c9"
    assert SRS_VNEXT_ENVELOPE_SHA256 == "71a9b365eb7c3d320d173772f6b823bb2bc3c15174eef30f6038ea7b84bde967"
    assert EXTERNAL_PROFILE_SCHEMA_SHA256 == "342642f4b2f120541f2094a8aadc5d6de9b0ea4548a12363b05333c92f524eaf"


def test_counterpedia_style_namespaced_profile_has_no_cross_field_findings() -> None:
    assert external_profile_cross_field_findings(_profile()) == []


def test_unclassified_permitted_type_fails() -> None:
    profile = _profile()
    profile["permitted_receipt_types"].append("org.counterpedia.mcp.read.refusal")
    assert "profile.permitted_type_unclassified" in external_profile_cross_field_findings(profile)


def test_classification_for_undeclared_type_fails() -> None:
    profile = _profile()
    profile["receipt_type_classifications"].append(
        {
            "receipt_type": "org.counterpedia.mcp.read.secret",
            "receipt_class": "outcome",
            "receipt_kind": "outcome",
        }
    )
    assert "profile.classification_for_undeclared_type" in external_profile_cross_field_findings(profile)


def test_conflicting_duplicate_classification_fails() -> None:
    profile = _profile()
    profile["receipt_type_classifications"].append(
        {
            "receipt_type": "org.counterpedia.mcp.read.admission",
            "receipt_class": "outcome",
            "receipt_kind": "admission",
        }
    )
    assert "profile.conflicting_duplicate_classification" in external_profile_cross_field_findings(profile)


def test_v0_2_1_compatibility_cannot_smuggle_namespaced_type() -> None:
    profile = _profile()
    profile["compatible_envelopes"] = [
        {"published_version": "0.2.1", "sha256": "0" * 64}
    ]
    assert "profile.v0_2_1_permits_non_frozen_type" in external_profile_cross_field_findings(profile)


def test_verifier_imports_no_producer_runtime() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    forbidden = (
        "dagr_mcp",
        "dagr_mcp_core",
        "dagr_mcp_sdk_v2",
        "counterpedia",
        "arcs_srs",
    )
    assert not any(name.startswith(forbidden) for name in imported)
