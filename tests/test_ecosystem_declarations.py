from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ECOSYSTEM = ROOT / ".ecosystem"

EXPECTED_DECLARATIONS = {
    "REPOSITORY.yaml",
    "ARCHITECTURE_PASSPORT.yaml",
    "AUTHORITY_REFERENCES.yaml",
    "CAPABILITY_BINDINGS.yaml",
    "CONTRACT_BINDINGS.yaml",
    "DEPENDENCIES.yaml",
    "LANES.yaml",
    "COMPATIBILITY_PROJECTION.yaml",
    "CONFORMANCE_PROJECTION.yaml",
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
    assert payload["architecture_model"]["status"] == "proposed_not_ratified"
    assert payload["architecture"]["primary_layer_id"] == "L6"
    assert payload["architecture"]["owning_layer"] == "independent_verification"
    assert payload["authority"]["implementation_behavior_authority"] is True
    assert payload["authority"]["standard_authority"] is False
    assert payload["authority"]["srs_normative_authority"] is False
    assert payload["authority"]["public_truth_authority"] is False


def test_authority_references_model_layer_and_srs_authority() -> None:
    authorities = _load_yaml_subset("AUTHORITY_REFERENCES.yaml")

    assert authorities["architecture_model"]["status"] == "proposed_not_ratified"
    assert authorities["architecture_model"]["order"] == [
        "Layer",
        "Authority",
        "Contracts",
        "Implementations",
        "Repositories",
    ]
    assert authorities["layer"]["primary_layer_id"] == "L6"
    assert authorities["layer"]["primary_layer_name"] == "independent_verification"
    assert authorities["layer"]["ratified_doctrine"] is False

    arcs_srs = next(
        item
        for item in authorities["authorities"]
        if item["id"] == "authority.arcs_srs"
    )
    assert arcs_srs["authority_type"] == "semantic_authority"
    assert "consumed SRS envelope schemas" in arcs_srs["applies_to"]
    assert "consumed SRS profile semantics" in arcs_srs["applies_to"]
    assert arcs_srs["public_ratification_claim"] is False

    arcs_verify = next(
        item
        for item in authorities["authorities"]
        if item["id"] == "authority.arcs_verify_implementation"
    )
    assert arcs_verify["authority_type"] == "repository_owned_implementation_behavior"
    assert arcs_verify["standard_authority"] is False
    assert arcs_verify["semantic_authority_for_srs"] is False


def test_authority_references_distinguish_result_boundary_states() -> None:
    authorities = _load_yaml_subset("AUTHORITY_REFERENCES.yaml")

    assert set(authorities["state_boundaries"]) == {
        "emitter_assertion",
        "independently_recomputed_finding",
        "not_evaluated",
        "not_applicable",
        "validation_error",
        "source_integrity_error",
    }
    assert authorities["compatibility_boundary"] == {
        "historical_vendored_bytes_are_compatibility_facts": True,
        "profile_pins_are_compatibility_facts": True,
        "public_ratification_claim": False,
    }


def test_dagr_mcp_is_not_a_runtime_package_dependency() -> None:
    dependencies = _load_yaml_subset("DEPENDENCIES.yaml")
    authorities = _load_yaml_subset("AUTHORITY_REFERENCES.yaml")
    runtime_names = {
        item["name"] for item in dependencies["runtime_package_dependencies"]
    }
    assert "DAGR MCP" not in runtime_names
    assert "DAGR MCP producer fixtures" not in runtime_names

    dagr_relationship = next(
        item
        for item in dependencies["producer_relationships_not_runtime_dependencies"]
        if item["name"] == "DAGR MCP producer fixtures"
    )
    assert dagr_relationship["runtime_package_dependency"] is False

    contracts = _load_yaml_subset("CONTRACT_BINDINGS.yaml")
    dagr_non_dependency = next(
        item
        for item in contracts["runtime_non_dependencies"]
        if item["name"] == "DAGR MCP"
    )
    assert dagr_non_dependency["imported_by_verifier"] is False

    producer_relationship = next(
        item
        for item in contracts["producer_relationships"]
        if item["name"] == "DAGR MCP producer fixtures"
    )
    assert producer_relationship["runtime_package_dependency"] is False

    dagr_counterpart = next(
        item
        for item in authorities["contract_counterparts"]
        if item["id"] == "counterpart.dagr_mcp"
    )
    assert dagr_counterpart["relationship"] == "producer_and_contract_counterpart"
    assert dagr_counterpart["imported_runtime_dependency"] is False


def test_countervail_receipt_ingest_is_downstream_consumer_only() -> None:
    dependencies = _load_yaml_subset("DEPENDENCIES.yaml")
    contracts = _load_yaml_subset("CONTRACT_BINDINGS.yaml")

    runtime_names = {
        item["name"] for item in dependencies["runtime_package_dependencies"]
    }
    assert "Countervail receipt-ingest verification contract" not in runtime_names

    dependency_consumer = next(
        item
        for item in dependencies["downstream_consumers"]
        if item["name"] == "Countervail receipt-ingest verification contract"
    )
    assert dependency_consumer["type"] == "downstream_consumer_relationship"
    assert dependency_consumer["local_contract_artifact_available"] is False

    contract_consumer = next(
        item
        for item in contracts["downstream_consumer_relationships"]
        if item["name"] == "Countervail receipt-ingest verification contract"
    )
    assert contract_consumer["relationship"] == "downstream_consumer_relationship"
    assert contract_consumer["local_contract_artifact_available"] is False


def test_garp_sdk_is_not_declared_without_consumed_shared_shapes() -> None:
    dependencies = _load_yaml_subset("DEPENDENCIES.yaml")
    runtime_names = {
        item["name"] for item in dependencies["runtime_package_dependencies"]
    }

    assert "garp-sdk" not in runtime_names
    assert dependencies["garp_sdk_policy"]["runtime_package_dependency"] is False
    assert dependencies["garp_sdk_policy"]["current_consumed_shared_shapes"] == []


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
    compatibility = _load_yaml_subset("COMPATIBILITY_PROJECTION.yaml")
    lineage = compatibility["srs_lineage"]

    assert lineage["receipt_version"] == "srs.core.v5.1"
    assert lineage["status"] == "internal_pre_public_lineage_compatibility_value"
    assert lineage["current_public_release"] is False
    assert compatibility["semantic_authority_for_consumed_srs_shapes"] == "arcs-srs"
    assert compatibility["compatibility_fact_boundary"][
        "historical_vendored_bytes_are_compatibility_facts"
    ] is True
    assert compatibility["compatibility_fact_boundary"][
        "profile_pins_are_compatibility_facts"
    ] is True
    assert compatibility["public_standard_ratification_claim"] is False


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
    capabilities = _load_yaml_subset("CAPABILITY_BINDINGS.yaml")

    assert capabilities["declaration_status"] == "declared"
    assert capabilities["authority_boundary"][
        "repository_implementation_behavior_authority"
    ] == "arcs-verify"
    assert capabilities["authority_boundary"][
        "srs_schema_profile_semantic_authority"
    ] == "arcs-srs"
    for capability in capabilities["capability_bindings"]:
        assert capability["implementation_claim"] == "declared"
        assert capability["verification_evidence"] == "verified_by_tests"
        assert capability["implementation_claim"] != capability["verification_evidence"]


def test_native_verifier_reports_are_repository_owned_outputs() -> None:
    contracts = _load_yaml_subset("CONTRACT_BINDINGS.yaml")
    output_contracts = [
        item
        for item in contracts["contract_bindings"]
        if item["role"] == "native_verifier_report_output"
    ]

    assert {
        item["id"] for item in output_contracts
    } == {
        "arcs_verify.signed_srs.report.v0_1",
        "srs.dagr_verification_report.v0.1",
        "srs.dagr_verification_report.v0.2",
        "arcs_verify.report.v0_1_1",
    }
    assert all(
        item["authority"] == "repository_owned_output_contract"
        for item in output_contracts
    )


def test_contract_bindings_separate_srs_authority_from_verifier_outputs() -> None:
    contracts = _load_yaml_subset("CONTRACT_BINDINGS.yaml")

    assert contracts["authority_boundary"][
        "consumed_srs_schema_profile_semantic_authority"
    ] == "arcs-srs"
    assert contracts["authority_boundary"][
        "repository_owned_output_authority"
    ] == "arcs-verify"

    srs_bindings = {
        item["id"]: item
        for item in contracts["contract_bindings"]
        if item["id"]
        in {
            "srs.envelope.schema.v0.2.0",
            "srs.envelope.schema.v0.2.1",
            "srs.mcp.sdk_enforcement",
            "srs.connection.lifecycle",
        }
    }
    assert {item["authority"] for item in srs_bindings.values()} == {"arcs-srs"}
