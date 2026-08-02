from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
ECOSYSTEM = ROOT / ".ecosystem"
KIT_SCHEMAS = Path.home() / "Developer/repos/arcs-ecosystem-kit/schemas"

SCHEMA_BACKED_DECLARATIONS = {
    "REPOSITORY.yaml": "ecosystem.repository.v0.1.schema.json",
    "ARCHITECTURE_PASSPORT.yaml": "ecosystem.architecture-passport.v0.1.schema.json",
    "AUTHORITY_REFERENCES.yaml": "ecosystem.authority-references.v0.1.schema.json",
    "CAPABILITY_BINDINGS.yaml": "ecosystem.capability-bindings.v0.1.schema.json",
    "CONTRACT_BINDINGS.yaml": "ecosystem.contract-bindings.v0.1.schema.json",
    "DEPENDENCIES.yaml": "ecosystem.dependencies.v0.1.schema.json",
    "LANES.yaml": "ecosystem.lanes.v0.1.schema.json",
    "COMPATIBILITY_PROJECTION.yaml": (
        "ecosystem.compatibility-projection.v0.1.schema.json"
    ),
    "CONFORMANCE_PROJECTION.yaml": (
        "ecosystem.conformance-projection.v0.1.schema.json"
    ),
    "EXCEPTIONS.yaml": "ecosystem.exceptions.v0.1.schema.json",
    "RELEASE_STATE.yaml": "ecosystem.release-state.v0.1.schema.json",
}

LOCAL_DECLARATIONS = {
    "BOUNDARIES.yaml",
    "RESPONSIBILITIES.yaml",
}

EXPECTED_DECLARATIONS = set(SCHEMA_BACKED_DECLARATIONS) | LOCAL_DECLARATIONS

EXPECTED_DOCS = {
    "ARCHITECTURE_PASSPORT.md",
    "VERIFICATION_BOUNDARIES.md",
    "PRODUCT_PATH.md",
    "VERIFICATION_FINDINGS.md",
    "docs/ECOSYSTEM_PILOT_ADJUDICATION.md",
}

EXPECTED_A0_A6_IDS = {
    "arcs.architecture.a0.reference-architecture.v0.1",
    "arcs.architecture.a1.constitutional-layer-model.v0.1",
    "arcs.architecture.a2.architectural-ontology.v0.1",
    "arcs.architecture.a3.authority-model.v0.1",
    "arcs.architecture.a4.repository-taxonomy.v0.1",
    "arcs.architecture.a5.federated-repository-development-doctrine.v0.1",
    "arcs.architecture.a6.ecosystem-coordination-doctrine.v0.1",
}

SIGNED_SRS_BOOLEAN_RESULTS = [
    "schema_digest",
    "envelope",
    "profile",
    "raw_content_exclusion",
    "signature_valid",
    "issuer_key_resolved",
    "issuer_key_trusted",
    "attestation_limits_present",
]


def _load_yaml_subset(name: str) -> dict:
    # The declarations are written as JSON-compatible YAML so the repository
    # does not need a YAML parser solely for declaration sanity tests.
    payload = json.loads((ECOSYSTEM / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _all_dependencies() -> list[dict]:
    return _load_yaml_subset("DEPENDENCIES.yaml")["dependencies"]


def test_all_ecosystem_files_exist_and_parse() -> None:
    assert {path.name for path in ECOSYSTEM.glob("*.yaml")} == EXPECTED_DECLARATIONS

    for name in EXPECTED_DECLARATIONS:
        payload = _load_yaml_subset(name)
        assert payload["repository"] == "arcs-verify" or payload["repository"][
            "name"
        ] == "arcs-verify"

    for name in LOCAL_DECLARATIONS:
        assert (
            _load_yaml_subset(name)["schema_status"]
            == "repository_local_no_arcs_ecosystem_kit_schema_v0_1"
        )


def test_schema_backed_declarations_validate_against_kit_v0_1() -> None:
    if not KIT_SCHEMAS.is_dir():
        pytest.skip("arcs-ecosystem-kit sibling checkout not available")

    for declaration_name, schema_name in SCHEMA_BACKED_DECLARATIONS.items():
        payload = _load_yaml_subset(declaration_name)
        schema = json.loads((KIT_SCHEMAS / schema_name).read_text(encoding="utf-8"))
        errors = sorted(
            Draft202012Validator(schema).iter_errors(payload),
            key=lambda error: list(error.path),
        )
        assert errors == [], declaration_name


def test_required_pilot_documents_exist() -> None:
    for relative in EXPECTED_DOCS:
        assert (ROOT / relative).is_file(), relative


def test_repository_classification_excludes_producer_roles() -> None:
    payload = _load_yaml_subset("REPOSITORY.yaml")
    repository_types = set(payload["repository"]["types"])

    assert repository_types == {"verifier", "reference_app"}
    assert "emitter" not in repository_types
    assert "runtime_binding" not in repository_types
    assert payload["constitutional_roles"]["primary_layer"] == "L6"
    assert payload["authority"]["status"] == "current_implementation"
    assert payload["authority"]["semantic_authority_for"] == [
        "native verifier-report output contracts only"
    ]
    assert "SRS normative authority" in payload["unowned_concerns"]


def test_a0_a6_inputs_are_declared_unratified_not_canonical() -> None:
    authority = _load_yaml_subset("AUTHORITY_REFERENCES.yaml")
    boundaries = _load_yaml_subset("BOUNDARIES.yaml")

    architecture_authority = next(
        item
        for item in authority["authorities"]
        if item["concern"] == "arcs_constitutional_architecture_inputs"
    )
    assert architecture_authority["assertion_status"] == "declared"
    assert architecture_authority["semantic_authority"]["repository"] == "garp-doctrine"
    assert {
        item["id"] for item in architecture_authority["evidence_refs"]
    } == EXPECTED_A0_A6_IDS
    assert all(
        "ratification_status unratified" in item["notes"]
        for item in architecture_authority["evidence_refs"]
    )

    assert {
        item["document_id"] for item in boundaries["architecture_inputs"]
    } == EXPECTED_A0_A6_IDS
    assert all(
        item["ratification_status"] == "unratified" and item["canonical"] is False
        for item in boundaries["architecture_inputs"]
    )


def test_arcs_srs_is_consumed_authority_and_arcs_verify_is_not_srs_authority() -> None:
    authorities = _load_yaml_subset("AUTHORITY_REFERENCES.yaml")
    contracts = _load_yaml_subset("CONTRACT_BINDINGS.yaml")
    responsibilities = _load_yaml_subset("RESPONSIBILITIES.yaml")

    srs_authority = next(
        item
        for item in authorities["authorities"]
        if item["concern"] == "srs_schema_profile_authority"
    )
    assert srs_authority["constitutional_layer"] == "L1"
    assert srs_authority["semantic_authority"]["repository"] == "arcs-srs"
    assert srs_authority["assertion_status"] == "validated"

    verifier_authority = next(
        item
        for item in authorities["authorities"]
        if item["concern"] == "arcs_verify_verifier_implementation"
    )
    assert verifier_authority["constitutional_layer"] == "L6"
    assert verifier_authority["semantic_authority"]["repository"] == "arcs-verify"
    assert "Verifier-owned behavior" in verifier_authority["notes"]

    consumed_srs_contracts = [
        item
        for item in contracts["consumed"]
        if item["semantic_authority"]["repository"] == "arcs-srs"
    ]
    assert {
        item["contract_id"] for item in consumed_srs_contracts
    } >= {
        "srs.envelope.schema.v0.2.0",
        "srs.envelope.schema.v0.2.1",
        "srs.mcp.sdk_enforcement.profile.v0_1",
    }
    assert responsibilities["authority_separation"]["arcs_verify"][
        "srs_authority"
    ] is False
    assert responsibilities["authority_separation"]["arcs_srs"][
        "public_ratification_claim_by_arcs_verify"
    ] is False


def test_dagr_and_countervail_are_not_runtime_dependencies() -> None:
    dependencies = _all_dependencies()
    runtime_repositories = {
        item["repository"]
        for item in dependencies
        if item["dependency_type"] == "runtime"
    }

    assert "dagr-mcp" not in runtime_repositories
    assert "countervail" not in runtime_repositories

    dagr = next(item for item in dependencies if item["repository"] == "dagr-mcp")
    assert dagr["dependency_type"] == "implementation"
    assert dagr["required"] is False
    assert "not imported runtime package dependencies" in dagr["reason"]

    countervail = next(
        item for item in dependencies if item["repository"] == "countervail"
    )
    assert countervail["dependency_type"] == "optional_consumer"
    assert countervail["required"] is False

    responsibilities = _load_yaml_subset("RESPONSIBILITIES.yaml")
    assert responsibilities["authority_separation"]["dagr_mcp"][
        "runtime_package_dependency"
    ] is False
    assert responsibilities["authority_separation"]["countervail"][
        "runtime_package_dependency"
    ] is False


def test_garp_sdk_is_only_referenced_for_genuine_shared_shapes() -> None:
    garp_sdk = next(item for item in _all_dependencies() if item["repository"] == "garp-sdk")
    responsibilities = _load_yaml_subset("RESPONSIBILITIES.yaml")

    assert garp_sdk["dependency_type"] == "optional_consumer"
    assert garp_sdk["required"] is False
    assert "genuinely consumed" in garp_sdk["reason"]
    assert responsibilities["authority_separation"]["garp_sdk"][
        "current_runtime_dependency"
    ] is False
    assert responsibilities["authority_separation"]["garp_sdk"][
        "current_consumed_shared_shapes"
    ] == []


def test_chain_status_is_not_modeled_as_a_ninth_boolean() -> None:
    boundaries = _load_yaml_subset("BOUNDARIES.yaml")
    signed_srs = boundaries["signed_srs_result_boundary"]
    contract = _load_yaml_subset("CONTRACT_BINDINGS.yaml")

    assert signed_srs["boolean_results"] == SIGNED_SRS_BOOLEAN_RESULTS
    assert "chain_status" not in signed_srs["boolean_results"]
    assert signed_srs["separate_status_results"] == ["chain_status"]
    assert signed_srs["chain_status_not_applicable_is_pass"] is False

    signed_report = next(
        item
        for item in contract["provided"]
        if item["contract_id"] == "arcs_verify.signed_srs.report.v0_1"
    )
    assert "eight Boolean results plus separate chain_status" in signed_report[
        "compatibility"
    ]["migration_notes"]


def test_not_evaluated_and_not_applicable_are_distinct_from_pass() -> None:
    boundaries = _load_yaml_subset("BOUNDARIES.yaml")
    amnesiac = boundaries["amnesiac_chain_result_boundary"]
    release = _load_yaml_subset("RELEASE_STATE.yaml")

    assert amnesiac["conclusion_domain"] == ["true", "false", "not_evaluated"]
    assert "authenticity_verified" in amnesiac["reserved_conclusions"]
    assert amnesiac["not_evaluated_is_pass"] is False
    assert amnesiac["not_evaluated_is_failure"] is False

    assert boundaries["result_state_boundaries"]["not_applicable"].endswith(
        "not PASS."
    )
    conformance = _load_yaml_subset("CONFORMANCE_PROJECTION.yaml")
    assert "not-applicable-preserved" in {
        gate["gate_id"] for gate in conformance["passed_gates"]
    }


def test_usage_and_source_integrity_errors_are_not_verification_findings() -> None:
    boundaries = _load_yaml_subset("BOUNDARIES.yaml")
    states = boundaries["result_state_boundaries"]

    assert set(states) == {
        "emitter_assertion",
        "independently_recomputed_finding",
        "not_evaluated",
        "not_applicable",
        "validation_error",
        "source_integrity_error",
    }
    assert states["validation_error"] != states["source_integrity_error"]
    assert "before reliable evaluation" in states["source_integrity_error"]


def test_srs_core_lineage_is_not_declared_public_release() -> None:
    compatibility = _load_yaml_subset("COMPATIBILITY_PROJECTION.yaml")
    responsibilities = _load_yaml_subset("RESPONSIBILITIES.yaml")

    srs_core = next(
        item
        for item in compatibility["srs_profiles"]
        if item["id"] == "srs.core"
    )
    assert srs_core["version"] == "v5.1"
    assert srs_core["historical_reference"] is True
    assert "not the current public SRS release" in srs_core["integrity"]["notes"]
    assert responsibilities["compatibility_fact_boundary"][
        "srs_core_v5_1_public_release_claim"
    ] is False


def test_lane_id_is_locally_unique_and_semantics_out_of_scope() -> None:
    lanes = _load_yaml_subset("LANES.yaml")["lanes"]
    lane_ids = [lane["lane_id"] for lane in lanes]
    active = next(
        lane
        for lane in lanes
        if lane["lane_id"] == "arcs-verify-ecosystem-doctrine-pilot-v0-1"
    )

    assert len(lane_ids) == len(set(lane_ids))
    assert active["status"] == "active"
    assert "verifier-semantics-unchanged" in {
        item["gate_id"] for item in active["completion_gates"]
    }
    assert "does not modify verifier algorithms" in active["notes"]


def test_declaration_status_distinguishes_claims_from_evidence() -> None:
    capabilities = _load_yaml_subset("CAPABILITY_BINDINGS.yaml")
    conformance = _load_yaml_subset("CONFORMANCE_PROJECTION.yaml")

    implemented = capabilities["declarations"]["implements"]
    assert implemented
    for binding in implemented:
        assert binding["relationship"] == "implements"
        assert binding["assertion_status"] == "validated"
        assert binding["native_mapping"]["assertion_status"] == "implemented"

    assert conformance["assertion_status"] == "validated"
    assert conformance["authority_repository"] == "garp-doctrine"
    assert "does not ratify" in conformance["integrity"]["notes"]


def test_native_verifier_reports_are_repository_owned_outputs() -> None:
    contracts = _load_yaml_subset("CONTRACT_BINDINGS.yaml")
    output_ids = {item["contract_id"] for item in contracts["provided"]}

    assert output_ids == {
        "arcs_verify.signed_srs.report.v0_1",
        "srs.dagr_verification_report.v0.1",
        "srs.dagr_verification_report.v0.2",
        "arcs_verify.report.v0_1_1",
    }
    assert all(
        item["semantic_authority"]["repository"] == "arcs-verify"
        for item in contracts["provided"]
    )
    assert all(
        item["contract_type"] == "verification_report"
        for item in contracts["provided"]
    )
