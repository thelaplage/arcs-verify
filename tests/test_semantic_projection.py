"""Conformance tests for the Counterpedia semantic-projection verifier.

The primary fixture is real output captured from the Counterpedia exporter as
bytes. No producer code is imported here; the verifier is exercised exactly the
way a downstream consumer would exercise it -- against serialized bytes.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from arcs_verify.semantic_projection import (
    Conclusion,
    SEMANTIC_PROJECTION_PROFILE,
    SEMANTIC_PROJECTION_REPORT_SCHEMA,
    verify_semantic_projection,
)

FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "semantic-projection"
    / "counterpedia-rendered-record.v0_1.json"
)


def load() -> dict:
    return json.loads(FIXTURE.read_text())


def test_real_exporter_output_conforms() -> None:
    report = verify_semantic_projection(load())
    assert report.passed is True
    assert report.findings == []


def test_report_shape_follows_house_conventions() -> None:
    data = verify_semantic_projection(load()).to_dict()
    assert data["schema"] == SEMANTIC_PROJECTION_REPORT_SCHEMA
    assert data["verification_profile"] == SEMANTIC_PROJECTION_PROFILE
    # NE-11: no permanently-pinned authority-shaped field. This report is not
    # an authority owner, so "no authority movement" must be structural
    # absence, not a none/zero-pinned field on the payload.
    assert "authority_movement" not in data
    # Independent conclusions, not one master Boolean.
    assert len(data["conclusions"]) == 9
    assert all(value == "true" for value in data["conclusions"].values())
    # chain_status-style distinct status, kept out of the Boolean set.
    assert "verification_reports_status" not in data["conclusions"]
    assert data["verification_reports_status"] == "absent"


def test_default_report_is_not_evaluated_and_not_passing() -> None:
    """NOT_EVALUATED is not PASS."""
    from arcs_verify.semantic_projection import SemanticProjectionReport

    report = SemanticProjectionReport()
    assert report.passed is False
    assert all(
        value == "not_evaluated" for value in report.to_dict()["conclusions"].values()
    )


def test_scope_and_limits_state_the_boundary() -> None:
    data = verify_semantic_projection(load()).to_dict()
    scope = data["scope"]
    for excluded in ("admission", "publication", "standing", "truth"):
        assert excluded in scope
    joined = " ".join(data["limits"])
    assert "NOT_EVALUATED is not PASS" in joined
    assert "emitter assertion" in joined or "not recomputed" in joined


@pytest.mark.parametrize(
    ("mutation", "conclusion_name"),
    [
        ({"schema": "something.else.v9"}, "schema_identity_declared"),
        ({"@context": "https://example.invalid/ns"}, "context_identity_declared"),
        ({"@type": "AnythingAtAll"}, "node_type_declared"),
        ({"@id": "_:blank"}, "subject_identity_stable"),
        ({"@id": ""}, "subject_identity_stable"),
        ({"authority_posture": "projection_only"}, "authority_posture_absent"),
        ({"authority_posture": "authoritative"}, "authority_posture_absent"),
        ({"source_schema_family": "not.the.owner"}, "source_schema_declared"),
        ({"source_schema_version": 1}, "source_schema_declared"),
        ({"title": ""}, "required_scalars_present"),
    ],
)
def test_each_defect_fails_its_own_conclusion(mutation, conclusion_name) -> None:
    projection = load()
    projection.update(mutation)
    report = verify_semantic_projection(projection)
    assert getattr(report, conclusion_name) is Conclusion.FALSE
    assert report.passed is False
    # Failure is localized: no other conclusion is dragged down with it.
    others = {
        name: value
        for name, value in report.to_dict()["conclusions"].items()
        if name != conclusion_name
    }
    assert all(value == "true" for value in others.values())


def test_unvalidated_context_no_longer_passes() -> None:
    """v0.1 checked only presence, so any @context value passed."""
    projection = load()
    projection["@context"] = "ANY-UNVALIDATED-CONTEXT"
    projection["@type"] = "AnythingAtAll"
    assert verify_semantic_projection(projection).passed is False


def test_producer_forbidden_key_is_rejected_here_too() -> None:
    """The producer rejects an `authority` key; the verifier must agree.

    v0.1 omitted `authority` from its denylist, so a projection the exporter
    would refuse to emit returned PASS.
    """
    projection = load()
    projection["authority"] = "ADMITTED_BY_ME"
    report = verify_semantic_projection(projection)
    assert report.no_authority_assertion is Conclusion.FALSE
    assert report.passed is False
    assert any(
        f.code == "FORBIDDEN_AUTHORITY_ASSERTION" for f in report.findings
    )


def test_pinned_fixture_has_no_authority_posture_at_any_depth() -> None:
    """NE-11 hostile-absence check on the pinned producer bytes themselves.

    `authority_posture` must be structurally absent from the fixture, not
    merely absent at the top level -- there is no depth at which a
    non-authority projection may carry this key.
    """

    def walk(node: object) -> None:
        if isinstance(node, dict):
            assert "authority_posture" not in node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(load())


def test_injected_authority_posture_fails_regardless_of_value() -> None:
    """A projection that (re-)adds `authority_posture` fails conformance no
    matter what value it carries: presence is the defect, not the value.

    NE-11: "no authority posture" on a non-authority artifact must be
    structural absence, never a none/value-pinned field -- so
    `authority_posture: "projection_only"` is exactly as non-conformant as
    `authority_posture: "authoritative"`.
    """
    for value in ("projection_only", "authoritative", "none", "", None):
        projection = load()
        projection["authority_posture"] = value
        report = verify_semantic_projection(projection)
        assert report.authority_posture_absent is Conclusion.FALSE
        assert report.passed is False
        assert any(
            f.code == "AUTHORITY_POSTURE_NOT_ABSENT" for f in report.findings
        )


def test_missing_required_collection_fails() -> None:
    projection = load()
    del projection["editions"]
    report = verify_semantic_projection(projection)
    assert report.required_collections_valid is Conclusion.FALSE
    assert any(f.code == "REQUIRED_FIELD_MISSING" for f in report.findings)


def test_malformed_collection_entry_fails() -> None:
    projection = load()
    projection["editions"] = [{"edition_id": "ed-1", "edition_number": "one",
                               "released_at": "2026-01-01T00:00:00Z"}]
    report = verify_semantic_projection(projection)
    assert report.required_collections_valid is Conclusion.FALSE
    assert any(f.code == "COLLECTION_FIELD_INVALID" for f in report.findings)


def test_boolean_is_not_accepted_as_an_integer() -> None:
    projection = load()
    projection["editions"] = [{"edition_id": "ed-1", "edition_number": True,
                               "released_at": "2026-01-01T00:00:00Z"}]
    assert verify_semantic_projection(projection).required_collections_valid is (
        Conclusion.FALSE
    )


def test_collection_must_be_an_array() -> None:
    projection = load()
    projection["sources"] = {"source_id": "s"}
    report = verify_semantic_projection(projection)
    assert report.required_collections_valid is Conclusion.FALSE
    assert any(f.code == "COLLECTION_SHAPE_INVALID" for f in report.findings)


def test_optional_verification_reports_absent_is_neither_pass_nor_fail() -> None:
    report = verify_semantic_projection(load())
    assert report.verification_reports_status == "absent"
    assert report.passed is True


def test_optional_verification_reports_valid_is_reported() -> None:
    projection = load()
    projection["verification_reports"] = [
        {
            "public_path": "/verification/report.json",
            "verification_profile": "srs.core.v5.1",
            "passed": True,
            "report_hash": "sha256:abc",
        }
    ]
    report = verify_semantic_projection(projection)
    assert report.verification_reports_status == "valid"
    assert report.passed is True


def test_optional_verification_reports_invalid_does_not_gate_passed() -> None:
    """An emitter assertion is not a recomputed finding.

    A malformed optional collection is reported as `invalid` and raises a
    finding, but it does not flip the gated structural conclusions.
    """
    projection = load()
    projection["verification_reports"] = [{"public_path": 42}]
    report = verify_semantic_projection(projection)
    assert report.verification_reports_status == "invalid"
    assert report.findings != []
    assert report.passed is True


def test_carried_passed_false_does_not_fail_conformance() -> None:
    """A projection carrying a failing upstream report is still conformant."""
    projection = load()
    projection["verification_reports"] = [
        {
            "public_path": "/verification/report.json",
            "verification_profile": "srs.core.v5.1",
            "passed": False,
            "report_hash": "sha256:abc",
        }
    ]
    report = verify_semantic_projection(projection)
    assert report.verification_reports_status == "valid"
    assert report.passed is True


def test_verifier_does_not_mutate_its_input() -> None:
    projection = load()
    before = copy.deepcopy(projection)
    verify_semantic_projection(projection)
    assert projection == before


def test_verifier_imports_no_producer_code() -> None:
    source = Path("arcs_verify/semantic_projection.py").read_text()
    for forbidden in ("counterpedia.", "import garpedia", "dagr"):
        assert f"import {forbidden}" not in source
