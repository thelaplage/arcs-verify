from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ECOSYSTEM = ROOT / ".ecosystem"

EXPECTED_DECLARATIONS = {
    "REPOSITORY.yaml",
    "ARCHITECTURE_PASSPORT.yaml",
    "CAPABILITIES.yaml",
    "CONTRACTS.yaml",
    "DEPENDENCIES.yaml",
    "LANES.yaml",
    "COMPATIBILITY.yaml",
    "CONFORMANCE.yaml",
    "EXCEPTIONS.yaml",
    "RELEASE_STATE.yaml",
}

EXPECTED_DOCS = {
    "ARCHITECTURE_PASSPORT.md",
    "VERIFICATION_BOUNDARIES.md",
    "PRODUCT_PATH.md",
    "VERIFICATION_FINDINGS.md",
    "docs/ECOSYSTEM_PILOT_ADJUDICATION.md",
}


def _load_yaml_subset(name: str) -> dict:
    # The provisional declarations are kept in JSON-compatible YAML so this
    # repository does not need a YAML dependency before the shared schemas land.
    payload = json.loads((ECOSYSTEM / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_all_provisional_ecosystem_files_exist_and_parse() -> None:
    assert {path.name for path in ECOSYSTEM.glob("*.yaml")} == EXPECTED_DECLARATIONS
    for name in EXPECTED_DECLARATIONS:
        payload = _load_yaml_subset(name)
        assert payload["schema_status"] == (
            "provisional_pending_arcs_ecosystem_kit_validation"
        )
        assert payload["repository"] == "arcs-verify" or payload["repository"][
            "name"
        ] == "arcs-verify"


def test_required_pilot_documents_exist() -> None:
    for relative in EXPECTED_DOCS:
        assert (ROOT / relative).is_file(), relative


def test_repository_classification_excludes_producer_roles() -> None:
    payload = _load_yaml_subset("REPOSITORY.yaml")
    repository_types = set(payload["repository"]["types"])
    assert repository_types == {"verifier", "reference_app"}
    assert "emitter" not in repository_types
    assert "runtime_binding" not in repository_types
    assert payload["authority"]["srs_normative_authority"] is False
    assert payload["authority"]["public_truth_authority"] is False


def test_dagr_mcp_is_not_a_runtime_package_dependency() -> None:
    dependencies = _load_yaml_subset("DEPENDENCIES.yaml")
    runtime_names = {
        item["name"] for item in dependencies["runtime_package_dependencies"]
    }
    assert "DAGR MCP" not in runtime_names

    dagr_relationship = next(
        item
        for item in dependencies["producer_relationships_not_runtime_dependencies"]
        if item["name"] == "DAGR MCP"
    )
    assert dagr_relationship["runtime_package_dependency"] is False

    contracts = _load_yaml_subset("CONTRACTS.yaml")
    dagr_non_dependency = next(
        item for item in contracts["runtime_non_dependencies"] if item["name"] == "DAGR MCP"
    )
    assert dagr_non_dependency["imported_by_verifier"] is False


def test_chain_status_is_not_modeled_as_a_ninth_boolean() -> None:
    architecture = _load_yaml_subset("ARCHITECTURE_PASSPORT.yaml")
    signed_srs = architecture["result_semantics"]["signed_srs"]

    assert len(signed_srs["boolean_results"]) == 8
    assert "chain_status" not in signed_srs["boolean_results"]
    assert signed_srs["separate_status_results"] == ["chain_status"]
    assert signed_srs["chain_status_not_applicable_is_pass"] is False


def test_not_evaluated_is_preserved_as_a_distinct_result_value() -> None:
    architecture = _load_yaml_subset("ARCHITECTURE_PASSPORT.yaml")
    amnesiac = architecture["result_semantics"]["amnesiac_chain"]
    release_state = _load_yaml_subset("RELEASE_STATE.yaml")

    assert amnesiac["conclusion_domain"] == ["true", "false", "not_evaluated"]
    assert "authenticity_verified" in amnesiac["reserved_conclusions"]
    assert "signature_verified" in amnesiac["reserved_conclusions"]
    assert release_state["claims"]["converts_not_evaluated_to_pass"] is False


def test_srs_core_lineage_is_not_declared_public_release() -> None:
    compatibility = _load_yaml_subset("COMPATIBILITY.yaml")
    lineage = compatibility["srs_lineage"]

    assert lineage["receipt_version"] == "srs.core.v5.1"
    assert lineage["status"] == "internal_pre_public_lineage_compatibility_value"
    assert lineage["current_public_release"] is False


def test_lane_id_is_locally_unique() -> None:
    lanes = _load_yaml_subset("LANES.yaml")
    active = lanes["active_lane"]
    other_ids = [item["id"] for item in lanes["local_uniqueness_basis"]["other_current_lanes"]]
    lane_ids = [active["id"], *other_ids]

    assert active["id"] == "arcs-verify-ecosystem-doctrine-pilot-v0-1"
    assert len(lane_ids) == len(set(lane_ids))
    assert active["does_not_touch"] == [
        "verifier algorithms",
        "supported receipt profiles",
        "DAGR producer code",
        "runtime package dependencies",
    ]


def test_declaration_status_distinguishes_claims_from_evidence() -> None:
    capabilities = _load_yaml_subset("CAPABILITIES.yaml")

    assert capabilities["declaration_status"] == "declared"
    for capability in capabilities["capabilities"]:
        assert capability["implementation_claim"] == "declared"
        assert capability["verification_evidence"] == "verified_by_tests"
        assert capability["implementation_claim"] != capability["verification_evidence"]
