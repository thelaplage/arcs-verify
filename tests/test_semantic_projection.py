from copy import deepcopy

from arcs_verify.semantic_projection import verify_semantic_projection


def valid_projection():
    return {
        "@context": "https://counterpedia.org/ns/projection/v0.1",
        "@id": "cp:subject:theranos",
        "@type": "CounterpediaGovernedProjection",
        "schema": "counterpedia.semantic_projection.v0.1",
        "authority_posture": "projection_only",
        "record_type": "public_record",
        "claim_refs": ["claim:1"],
        "source_refs": ["source:1"],
        "history_refs": ["edition:1"],
        "verification_report_refs": ["verify:1"],
    }


def test_sem_01_conforming_projection_passes():
    report = verify_semantic_projection(valid_projection())
    assert report["status"] == "PASS"
    assert report["verification_kind"] == "semantic_projection_conformance"
    assert report["authority_movement"] == 0


def test_sem_02_missing_required_field_fails():
    projection = valid_projection()
    del projection["record_type"]
    report = verify_semantic_projection(projection)
    assert report["status"] == "FAIL"
    assert "REQUIRED_FIELD_MISSING" in {finding["code"] for finding in report["findings"]}


def test_sem_03_unknown_schema_fails_closed():
    projection = valid_projection()
    projection["schema"] = "unknown.v9"
    report = verify_semantic_projection(projection)
    assert "SEMANTIC_SCHEMA_UNKNOWN" in {finding["code"] for finding in report["findings"]}


def test_sem_04_malformed_reference_fails():
    projection = valid_projection()
    projection["source_refs"] = [""]
    report = verify_semantic_projection(projection)
    assert "INVALID_REFERENCE_SHAPE" in {finding["code"] for finding in report["findings"]}


def test_sem_05_authority_injection_fails():
    projection = valid_projection()
    projection["admitted"] = True
    report = verify_semantic_projection(projection)
    assert "FORBIDDEN_AUTHORITY_ASSERTION" in {finding["code"] for finding in report["findings"]}


def test_sem_06_result_is_deterministic():
    projection = valid_projection()
    assert verify_semantic_projection(projection) == verify_semantic_projection(projection)


def test_sem_07_verifier_does_not_mutate_input():
    projection = valid_projection()
    before = deepcopy(projection)
    verify_semantic_projection(projection)
    assert projection == before


def test_sem_08_pass_creates_no_governance_result():
    report = verify_semantic_projection(valid_projection())
    serialized = repr(report).lower()
    assert "admissiondecision" not in serialized
    assert "publishes" not in serialized
    assert "grants_standing" not in serialized


def test_sem_09_scope_is_explicitly_non_authoritative():
    scope = verify_semantic_projection(valid_projection())["scope"]
    assert "not evidence verification" in scope
    assert "admission" in scope
    assert "standing" in scope


def test_sem_11_blank_node_subject_fails_closed():
    projection = valid_projection()
    projection["@id"] = "_:b0"
    report = verify_semantic_projection(projection)
    assert "INVALID_REFERENCE_SHAPE" in {finding["code"] for finding in report["findings"]}
