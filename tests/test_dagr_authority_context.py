from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json

import arcs_verify.dagr_authority_context as verifier
from arcs_verify.dagr_authority_context import (
    PINNED_GENESIS_DIGEST,
    verify_dagr_authority_context_same_genesis,
)


EXPECTED_CONTEXT_DIGEST = (
    "sha256:97e7190380ad0bed99166b45845e47b76c0646e0e38513038010449a59bbf922"
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


def _stable_payload_hash(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _context_digest(value: dict) -> str:
    provenance = value["authority_provenance"]
    preimage = (
        "DAGR-RESOLVED-AUTHORITY-CONTEXT-CANDIDATE-V0.1\n"
        f"schema={value['schema']}\n"
        f"domain={value['domain']}\n"
        f"transaction_id={value['transaction_id']}\n"
        f"transaction_digest={value['transaction_digest']}\n"
        f"operator_identity_ref={value['operator_identity_ref']}\n"
        f"authority_profile_ref={value['authority_profile_ref']}\n"
        f"review_role_count={len(value['review_roles'])}\n"
    )
    for index, role in enumerate(value["review_roles"]):
        preimage += f"review_role_{index}={role}\n"
    preimage += (
        f"authority_source={value['authority_source']}\n"
        f"authority_genesis_id={provenance['genesis_id']}\n"
        f"authority_genesis_digest={provenance['genesis_digest']}\n"
        f"authority_genesis_status={provenance['status']}\n"
        f"authority_effective_from={provenance['effective_from']}\n"
        f"authority_source_ref={provenance['authority_source_ref']}\n"
        f"supporting_review_ref={provenance['supporting_review_ref']}\n"
    )
    return "sha256:" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def _genesis() -> dict:
    return {
        "schema": "dagr.operator-authority-genesis/v0.1",
        "genesis_id": "dagr-merit-operator-authority-v0.1",
        "operator_identity_ref": "operator:thelaplage",
        "authority_profile_ref": "approver",
        "principal_class": "human_principal",
        "status": "active",
        "effective_from": "2026-08-29T17:05:43Z",
        "authority_source_ref": (
            "github:thelaplage/dagr-runtime#78:review-comment:5463723050:"
            "owner-ratification:2026-08-29"
        ),
        "supporting_review_ref": "github:thelaplage/dagr-runtime#77",
        "non_equivalences": [
            "operator authority != merit outcome",
            "resolver success != approve",
            "review eligibility != approve",
            "operator identity != requested_actor_label",
            "merit approval != institutional admission",
            "merit approval != factual truth",
        ],
        "genesis_digest": PINNED_GENESIS_DIGEST,
    }


def _context() -> dict:
    return {
        "authority_context_digest": EXPECTED_CONTEXT_DIGEST,
        "authority_profile_ref": "approver",
        "authority_provenance": {
            "authority_source_ref": (
                "github:thelaplage/dagr-runtime#78:review-comment:5463723050:"
                "owner-ratification:2026-08-29"
            ),
            "effective_from": "2026-08-29T17:05:43Z",
            "genesis_digest": PINNED_GENESIS_DIGEST,
            "genesis_id": "dagr-merit-operator-authority-v0.1",
            "status": "active",
            "supporting_review_ref": "github:thelaplage/dagr-runtime#77",
        },
        "authority_source": "operator_authority_profile",
        "domain": "action",
        "operator_identity_ref": "operator:thelaplage",
        "review_roles": ["approver", "auditor"],
        "schema": "dagr.resolved-authority-context-candidate/v0.1",
        "transaction_digest": (
            "sha256:2c307edb0f07dc837d9b845392d3247167ecf82a09ff611aeaea2d9ba55d6877"
        ),
        "transaction_id": "transaction:external-harness:fixture:001",
    }


def _verify(context: dict | None = None, genesis: dict | None = None):
    return verify_dagr_authority_context_same_genesis(
        context_bytes=_json_bytes(context or _context()),
        genesis_bytes=_json_bytes(genesis or _genesis()),
    )


def test_representative_candidate_and_governed_genesis_pass_narrowly() -> None:
    assert _context_digest(_context()) == EXPECTED_CONTEXT_DIGEST
    assert _stable_payload_hash(
        {key: value for key, value in _genesis().items() if key != "genesis_digest"}
    ) == PINNED_GENESIS_DIGEST

    report = _verify()
    assert report.passed is True
    assert report.same_genesis_binding is True
    assert report.context_schema_digest is True
    assert report.context_schema is True
    assert report.context_digest is True
    assert report.genesis_shape is True
    assert report.genesis_digest is True
    assert report.genesis_pin is True
    assert report.operator_identity_match is True
    assert report.authority_profile_match is True
    assert report.review_roles_match is True
    assert report.authority_source_match is True
    assert report.provenance_match is True
    assert report.failure_codes == []

    projection = report.to_dict()
    assert projection["producer_authorship"] == "not_evaluated"
    assert projection["ratification_status"] == "not_evaluated"
    assert projection["action_permission"] == "not_evaluated"
    assert projection["countervail_authorization"] == "not_evaluated"
    assert projection["execution"] == "not_evaluated"


def test_mutated_genesis_with_stale_digest_fails() -> None:
    genesis = _genesis()
    genesis["operator_identity_ref"] = "operator:attacker"

    report = _verify(genesis=genesis)
    assert report.passed is False
    assert report.genesis_digest is False
    assert report.genesis_pin is False
    assert "genesis.digest_mismatch" in report.failure_codes


def test_self_consistent_attacker_genesis_still_fails_independent_pin() -> None:
    genesis = _genesis()
    genesis["operator_identity_ref"] = "operator:attacker"
    payload = {key: value for key, value in genesis.items() if key != "genesis_digest"}
    genesis["genesis_digest"] = _stable_payload_hash(payload)
    assert genesis["genesis_digest"] != PINNED_GENESIS_DIGEST

    context = _context()
    context["operator_identity_ref"] = "operator:attacker"
    context["authority_provenance"]["genesis_digest"] = genesis["genesis_digest"]
    context["authority_context_digest"] = _context_digest(context)

    report = _verify(context=context, genesis=genesis)
    assert report.context_digest is True
    assert report.genesis_digest is True
    assert report.genesis_pin is False
    assert report.operator_identity_match is True
    assert report.provenance_match is True
    assert report.same_genesis_binding is False
    assert "genesis.independent_pin_mismatch" in report.failure_codes


def test_context_operator_mismatch_fails_even_with_fresh_context_digest() -> None:
    context = _context()
    context["operator_identity_ref"] = "operator:other"
    context["authority_context_digest"] = _context_digest(context)

    report = _verify(context=context)
    assert report.context_digest is True
    assert report.genesis_pin is True
    assert report.operator_identity_match is False
    assert report.same_genesis_binding is False
    assert "relation.operator_identity_mismatch" in report.failure_codes


def test_context_profile_and_review_roles_cannot_switch_source() -> None:
    context = _context()
    context["authority_profile_ref"] = "editor"
    context["review_roles"] = ["auditor"]
    context["authority_context_digest"] = _context_digest(context)

    report = _verify(context=context)
    assert report.context_schema is True
    assert report.context_digest is True
    assert report.authority_profile_match is False
    assert report.review_roles_match is False
    assert report.same_genesis_binding is False


def test_schema_valid_provenance_ref_mutation_fails_relation() -> None:
    context = _context()
    context["authority_provenance"]["supporting_review_ref"] = (
        "github:thelaplage/dagr-runtime#999"
    )
    context["authority_context_digest"] = _context_digest(context)

    report = _verify(context=context)
    assert report.context_schema is True
    assert report.context_digest is True
    assert report.provenance_match is False
    assert report.same_genesis_binding is False
    assert "relation.provenance_mismatch" in report.failure_codes


def test_context_review_role_drift_is_rejected_by_pinned_schema() -> None:
    context = _context()
    context["review_roles"] = ["auditor"]
    context["authority_context_digest"] = _context_digest(context)

    report = _verify(context=context)
    assert report.context_schema is False
    assert report.context_digest is False
    assert report.same_genesis_binding is False
    assert "context.schema_invalid" in report.failure_codes


def test_secret_or_unknown_fields_never_validate() -> None:
    context = _context()
    context["credential"] = "secret"
    report = _verify(context=context)
    assert report.context_schema is False
    assert report.passed is False

    genesis = _genesis()
    genesis["token"] = "secret"
    report = _verify(genesis=genesis)
    assert report.genesis_shape is False
    assert report.passed is False
    assert "genesis.closed_shape_mismatch" in report.failure_codes


def test_duplicate_json_keys_are_rejected_before_semantic_verification() -> None:
    context_bytes = _json_bytes(_context())
    duplicated = context_bytes[:-1] + b',"schema":"dagr.resolved-authority-context-candidate/v0.1"}'
    report = verify_dagr_authority_context_same_genesis(
        context_bytes=duplicated,
        genesis_bytes=_json_bytes(_genesis()),
    )
    assert report.passed is False
    assert "context.duplicate_key:schema" in report.failure_codes


def test_wrong_schema_bytes_fail_before_context_claims() -> None:
    report = verify_dagr_authority_context_same_genesis(
        context_bytes=_json_bytes(_context()),
        genesis_bytes=_json_bytes(_genesis()),
        context_schema_bytes=b"{}\n",
    )
    assert report.context_schema_digest is False
    assert report.context_schema is False
    assert report.passed is False
    assert "context_schema.digest_mismatch" in report.failure_codes


def test_verifier_has_no_dagr_producer_or_sdk_imports() -> None:
    tree = ast.parse(inspect.getsource(verifier))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    assert "dagr_runtime" not in imported_roots
    assert "dagr_sdk" not in imported_roots
