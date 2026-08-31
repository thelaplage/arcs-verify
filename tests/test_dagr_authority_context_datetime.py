from __future__ import annotations

import json

from arcs_verify.dagr_authority_context import (
    PINNED_GENESIS_DIGEST,
    verify_dagr_authority_context_same_genesis,
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


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


def _context(effective_from: str) -> dict:
    return {
        "authority_context_digest": (
            "sha256:97e7190380ad0bed99166b45845e47b76c0646e0e38513038010449a59bbf922"
        ),
        "authority_profile_ref": "approver",
        "authority_provenance": {
            "authority_source_ref": (
                "github:thelaplage/dagr-runtime#78:review-comment:5463723050:"
                "owner-ratification:2026-08-29"
            ),
            "effective_from": effective_from,
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


def _assert_schema_rejects(value: str) -> None:
    report = verify_dagr_authority_context_same_genesis(
        context_bytes=_json_bytes(_context(value)),
        genesis_bytes=_json_bytes(_genesis()),
    )
    assert report.context_schema_digest is True
    assert report.context_schema is False
    assert report.context_digest is False
    assert report.same_genesis_binding is False
    assert "context.schema_invalid" in report.failure_codes


def test_impossible_calendar_date_is_not_normalized() -> None:
    _assert_schema_rejects("2026-02-30T10:00:00Z")


def test_24_hour_clock_rollover_is_not_normalized() -> None:
    _assert_schema_rejects("2026-08-29T24:00:00Z")
