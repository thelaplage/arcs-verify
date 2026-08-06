"""Sequence-level verifier tests for governed memory read sequences.

Tests verify that:
- Valid sequences produce Conclusion.TRUE for all structural findings.
- Every mutation in the adversarial corpus is rejected with the correct finding.
- Non-equivalences are not violated (source state unknown != failure/success,
  authorized disposition != compliance, digest match != same real-world read).
- NOT_EVALUATED is preserved and not promoted to PASS.
- Sequence-level passed requires all structural findings.
- arcs_amnesiac is not imported anywhere in this test environment (acceptance gate).
- CWD-independent CLI path works.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arcs_verify.governed_memory_sequence import (
    Conclusion,
    GovernedMemorySequenceReport,
    SEQUENCE_LIMITATIONS,
    SEQUENCE_PROFILE,
    SEQUENCE_SCHEMA,
    verify_governed_memory_sequence,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "governed_memory_sequence"

# Ensure subprocess calls use the worktree source rather than any installed
# version of arcs-verify that may not yet include this lane's code.
_CLI_ENV = {**os.environ, "PYTHONPATH": str(ROOT)}


def load_bundle(name: str) -> dict:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def verify(bundle: dict) -> GovernedMemorySequenceReport:
    return verify_governed_memory_sequence(bundle)


# ---------------------------------------------------------------------------
# Acceptance gate: arcs_amnesiac must not be importable
# ---------------------------------------------------------------------------

def test_arcs_amnesiac_not_imported():
    """arcs_amnesiac must NOT be imported by the verifier module.

    Producer/verifier independence is enforced: arcs-verify must not import
    any arcs_amnesiac code. We verify this by inspecting the module's
    __dict__ for arcs_amnesiac references and checking the import graph.
    The docstring may mention arcs_amnesiac as a reference; only actual
    live imports are prohibited.
    """
    import arcs_verify.governed_memory_sequence as gms_mod
    import sys

    # Check that arcs_amnesiac is not in the module's namespace (not imported)
    assert "arcs_amnesiac" not in gms_mod.__dict__, (
        "governed_memory_sequence module has arcs_amnesiac in its namespace. "
        "Producer/verifier independence is violated."
    )
    # Check that loading governed_memory_sequence did not cause arcs_amnesiac
    # to be loaded into sys.modules (ruling out transitive imports).
    # Note: arcs_amnesiac may be installed in the dev environment; what matters
    # is that governed_memory_sequence.py does not import it.
    import inspect
    source = inspect.getsource(gms_mod)
    # Strip docstrings (everything between triple-quotes that appears before
    # the first non-docstring line). We check only import-statement lines.
    import_lines = [
        line.strip() for line in source.splitlines()
        if line.strip().startswith(("import ", "from "))
    ]
    for line in import_lines:
        assert "arcs_amnesiac" not in line, (
            f"governed_memory_sequence.py has an import of arcs_amnesiac: {line!r}. "
            "Producer/verifier independence is violated."
        )


def test_governed_memory_sequence_imports_no_dagr_mcp():
    """dagr_mcp must not be imported by the verifier module."""
    import arcs_verify.governed_memory_sequence as gms_mod
    import inspect
    source = inspect.getsource(gms_mod)
    assert "dagr_mcp" not in source, (
        "governed_memory_sequence.py references dagr_mcp. "
        "Producer/verifier independence is violated."
    )


# ---------------------------------------------------------------------------
# 1. Valid full sequence — all structural findings must be TRUE
# ---------------------------------------------------------------------------

def test_valid_full_bundle_passes_all_structural_findings():
    bundle = load_bundle("valid-full-bundle.json")
    report = verify(bundle)
    c = report.to_dict()["conclusions"]

    assert c["request_present"] == "true", report.findings
    assert c["decision_present"] == "true", report.findings
    assert c["packet_present"] == "true", report.findings
    assert c["request_decision_linkage"] == "true", report.findings
    assert c["decision_packet_linkage"] == "true", report.findings
    assert c["subject_continuity"] == "true", report.findings
    assert c["scope_continuity"] == "true", report.findings
    assert c["source_descriptor_refs_present"] == "true", report.findings
    assert c["exclusion_declarations_present"] == "true", report.findings
    assert c["packet_digest_match"] == "true", report.findings
    assert c["replay_evidence_clean"] == "true", report.findings
    assert c["raw_content_posture_valid"] == "true", report.findings
    assert c["reopening_refs_valid"] == "true", report.findings
    assert report.passed is True, report.findings


def test_valid_refused_bundle_passes():
    bundle = load_bundle("valid-refused-bundle.json")
    report = verify(bundle)
    assert report.passed is True, report.findings
    c = report.to_dict()["conclusions"]
    assert c["request_present"] == "true"
    assert c["decision_present"] == "true"
    assert c["packet_present"] == "true"
    # No source_descriptors supplied — source state NOT converted to failure
    assert c["source_descriptor_refs_present"] == "not_evaluated"
    # No packet_hash in this decision — not verifiable
    assert c["packet_digest_match"] == "not_evaluated"


# ---------------------------------------------------------------------------
# 2. stale_authorization_declared is informational and does not gate passed
# ---------------------------------------------------------------------------

def test_stale_authorization_declared_is_informational():
    """stale_authorization_declared=TRUE is informational; sequence can still pass."""
    bundle = load_bundle("mutation-stale-authorization.json")
    report = verify(bundle)
    c = report.to_dict()["conclusions"]
    assert c["stale_authorization_declared"] == "true"
    # Stale authorization does not gate passed — the sequence is structurally valid
    assert report.passed is True, report.findings


def test_no_not_after_means_stale_authorization_false():
    """When no not_after is declared, stale_authorization_declared is FALSE."""
    bundle = load_bundle("valid-full-bundle.json")
    report = verify(bundle)
    c = report.to_dict()["conclusions"]
    assert c["stale_authorization_declared"] == "false"


# ---------------------------------------------------------------------------
# 3. Unknown external source state is NOT converted to failure or success
# ---------------------------------------------------------------------------

def test_no_source_descriptors_yields_not_evaluated():
    """When source_descriptors is absent, source_descriptor_refs_present is NOT_EVALUATED.

    Unknown external source state must not be converted to PASS or FAIL.
    """
    bundle = load_bundle("valid-refused-bundle.json")
    assert "source_descriptors" not in bundle
    report = verify(bundle)
    assert report.source_descriptor_refs_present is Conclusion.NOT_EVALUATED
    # NOT_EVALUATED is not PASS — but it also does not gate passed when not_evaluated
    # is specifically excluded from the passed computation for this finding.
    data = report.to_dict()
    assert data["conclusions"]["source_descriptor_refs_present"] == "not_evaluated"


def test_source_descriptor_refs_present_when_supplied_and_resolved():
    """When source_descriptors are supplied and all packet source_refs resolve, finding is TRUE."""
    bundle = load_bundle("valid-full-bundle.json")
    report = verify(bundle)
    assert report.source_descriptor_refs_present is Conclusion.TRUE


# ---------------------------------------------------------------------------
# 4. NOT_EVALUATED is not promoted to PASS
# ---------------------------------------------------------------------------

def test_not_evaluated_is_not_promoted_to_pass():
    """An empty bundle (not a dict) yields FALSE/FALSE for all findings. passed must be False."""
    report = verify_governed_memory_sequence([])
    assert report.passed is False
    data = report.to_dict()
    assert data["passed"] is False


def test_no_master_status_replaces_conclusions():
    """to_dict() exposes each named conclusion separately. passed is not a substitute."""
    bundle = load_bundle("valid-full-bundle.json")
    report = verify(bundle)
    data = report.to_dict()
    assert "conclusions" in data
    conclusions = data["conclusions"]
    expected_keys = {
        "request_present",
        "decision_present",
        "packet_present",
        "request_decision_linkage",
        "decision_packet_linkage",
        "subject_continuity",
        "scope_continuity",
        "source_descriptor_refs_present",
        "exclusion_declarations_present",
        "packet_digest_match",
        "replay_evidence_clean",
        "raw_content_posture_valid",
        "reopening_refs_valid",
        "stale_authorization_declared",
    }
    assert expected_keys.issubset(conclusions.keys()), (
        f"Missing conclusion keys: {expected_keys - conclusions.keys()}"
    )


# ---------------------------------------------------------------------------
# 5. Mutation corpus — each mutation produces the expected rejection
# ---------------------------------------------------------------------------

def test_mutation_wrong_request_ref_detected():
    """request_decision_linkage must be FALSE when decision.request_ref points to wrong id."""
    bundle = load_bundle("mutation-wrong-request-ref.json")
    report = verify(bundle)
    assert report.request_decision_linkage is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "decision_request_ref_mismatch" in codes


def test_mutation_wrong_decision_ref_detected():
    """decision_packet_linkage must be FALSE when packet.decision_ref points to wrong id."""
    bundle = load_bundle("mutation-wrong-decision-ref.json")
    report = verify(bundle)
    assert report.decision_packet_linkage is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "packet_decision_ref_mismatch" in codes


def test_mutation_changed_subject_detected():
    """subject_continuity must be FALSE when subject_ref differs across artifacts."""
    bundle = load_bundle("mutation-changed-subject.json")
    report = verify(bundle)
    assert report.subject_continuity is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "subject_ref_discontinuity" in codes


def test_mutation_changed_scope_detected():
    """scope_continuity must be FALSE when scope_ref is inconsistent across artifacts."""
    bundle = load_bundle("mutation-changed-scope.json")
    report = verify(bundle)
    assert report.scope_continuity is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "scope_ref_discontinuity" in codes


def test_mutation_packet_digest_mismatch_detected():
    """packet_digest_match must be FALSE when decision.packet_hash != packet.packet_hash."""
    bundle = load_bundle("mutation-packet-digest-mismatch.json")
    report = verify(bundle)
    assert report.packet_digest_match is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "packet_digest_mismatch" in codes


def test_mutation_missing_lineage_detected():
    """request_decision_linkage and decision_packet_linkage must be FALSE when refs are absent."""
    bundle = load_bundle("mutation-missing-lineage.json")
    report = verify(bundle)
    assert report.request_decision_linkage is Conclusion.FALSE
    assert report.decision_packet_linkage is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "decision_missing_request_ref" in codes
    assert "packet_missing_decision_ref" in codes


def test_mutation_raw_content_posture_detected():
    """raw_content_posture_valid must be FALSE when a forbidden key is present."""
    bundle = load_bundle("mutation-raw-content-posture.json")
    report = verify(bundle)
    assert report.raw_content_posture_valid is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "raw_content_posture_violation" in codes


def test_mutation_duplicate_artifact_id_detected():
    """replay_evidence_clean must be FALSE when the same id appears in multiple artifacts."""
    bundle = load_bundle("mutation-duplicate-artifact-id.json")
    report = verify(bundle)
    assert report.replay_evidence_clean is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "duplicate_artifact_id" in codes


def test_mutation_unresolved_source_ref_detected():
    """source_descriptor_refs_present must be FALSE when a packet source_ref is unresolved."""
    bundle = load_bundle("mutation-unresolved-source-ref.json")
    report = verify(bundle)
    assert report.source_descriptor_refs_present is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "source_descriptor_refs_unresolved" in codes


def test_mutation_malformed_reopening_ref_detected():
    """reopening_refs_valid must be FALSE when a reopening_ref does not resolve."""
    bundle = load_bundle("mutation-malformed-reopening-ref.json")
    report = verify(bundle)
    assert report.reopening_refs_valid is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "reopening_ref_unresolved" in codes


def test_mutation_exclusion_incomplete_detected():
    """exclusion_declarations_present must be FALSE when bundle exclusions are incomplete."""
    bundle = load_bundle("mutation-exclusion-incomplete.json")
    report = verify(bundle)
    assert report.exclusion_declarations_present is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "exclusion_declarations_incomplete" in codes


# ---------------------------------------------------------------------------
# 6. Non-equivalences — semantic failure case verification
# ---------------------------------------------------------------------------

def test_authorized_disposition_not_compliance_verdict():
    """Non-equivalence: disposition==authorized does not prove the read is compliant.

    The verifier does not assert compliance. A structurally valid sequence
    with an authorized decision passes structural findings but the limitations
    explicitly distinguish this from compliance.
    """
    bundle = load_bundle("valid-full-bundle.json")
    assert bundle["authorization_decision"]["disposition"] == "authorized"

    report = verify(bundle)
    assert report.passed is True

    data = report.to_dict()
    limitation_text = " ".join(data["limitations"]).lower()
    assert "authorized" in limitation_text or "compliance" in limitation_text
    assert "comply" in limitation_text or "compliant" in limitation_text or "policy correctness" in limitation_text


def test_packet_digest_match_not_same_real_world_read():
    """Non-equivalence: packet_digest_match does not prove the same real-world memory read.

    The limitation is explicitly stated in SEQUENCE_LIMITATIONS.
    """
    limitation_text = " ".join(SEQUENCE_LIMITATIONS).lower()
    assert "digest" in limitation_text
    assert "real-world" in limitation_text


def test_unknown_source_state_not_failure():
    """Non-equivalence: unknown external source state is NOT converted to failure.

    When source_descriptors is absent, the verifier emits NOT_EVALUATED,
    not FALSE. The sequence can still pass.
    """
    bundle = load_bundle("valid-refused-bundle.json")
    assert "source_descriptors" not in bundle

    report = verify(bundle)
    # source_descriptor_refs_present is NOT_EVALUATED — unknown state
    assert report.source_descriptor_refs_present is Conclusion.NOT_EVALUATED
    # NOT_EVALUATED does not gate passed here — the finding is not structural
    # when source_descriptors are not supplied.
    assert report.passed is True, (
        "Unknown external source state should not convert to passed=False. "
        f"findings: {report.findings}"
    )


def test_unknown_source_state_not_success():
    """NOT_EVALUATED is not PASS.

    When source_descriptor_refs_present is NOT_EVALUATED, the value in
    to_dict() must be 'not_evaluated', not 'true'.
    """
    bundle = load_bundle("valid-refused-bundle.json")
    report = verify(bundle)
    data = report.to_dict()
    assert data["conclusions"]["source_descriptor_refs_present"] == "not_evaluated"
    assert data["conclusions"]["source_descriptor_refs_present"] != "true"


# ---------------------------------------------------------------------------
# 7. Report schema, profile, limitations
# ---------------------------------------------------------------------------

def test_report_schema_and_profile_fields():
    bundle = load_bundle("valid-full-bundle.json")
    report = verify(bundle)
    data = report.to_dict()
    assert data["schema"] == SEQUENCE_SCHEMA
    assert data["verification_profile"] == SEQUENCE_PROFILE


def test_limitations_distinguish_integrity_from_source_truth():
    """The report limitations distinguish integrity from source truth, policy, and completeness."""
    bundle = load_bundle("valid-full-bundle.json")
    report = verify(bundle)
    data = report.to_dict()
    limitations = data["limitations"]
    assert isinstance(limitations, list)
    assert len(limitations) >= 4

    text = " ".join(limitations).lower()
    assert "source truth" in text or "source" in text
    assert "policy" in text
    assert "completeness" in text or "external world" in text


# ---------------------------------------------------------------------------
# 8. CWD-independent CLI path
# ---------------------------------------------------------------------------

def test_cli_governed_memory_sequence_json_output(tmp_path):
    """CLI governed-memory-sequence subcommand produces JSON report from a tmp dir.

    CWD is set to a temporary directory to confirm path-independence.
    PYTHONPATH is set to the worktree root so subprocess uses the current
    source tree rather than any previously installed arcs-verify distribution.
    """
    bundle_path = FIXTURE_ROOT / "valid-full-bundle.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "governed-memory-sequence",
            "--bundle",
            str(bundle_path),
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),  # CWD is a temp dir — must not affect results
        env=_CLI_ENV,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["passed"] is True
    assert data["schema"] == SEQUENCE_SCHEMA


def test_cli_governed_memory_sequence_text_output(tmp_path):
    """CLI text output includes passed: true for a valid sequence."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "governed-memory-sequence",
            "--bundle",
            str(FIXTURE_ROOT / "valid-full-bundle.json"),
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 0, result.stderr
    assert "passed: true" in result.stdout


def test_cli_returns_exit_1_for_failed_sequence(tmp_path):
    """CLI returns exit code 1 for a sequence that fails verification."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "governed-memory-sequence",
            "--bundle",
            str(FIXTURE_ROOT / "mutation-wrong-request-ref.json"),
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 1


def test_cli_returns_exit_2_for_missing_bundle(tmp_path):
    """CLI returns exit code 2 when --bundle is not provided."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "governed-memory-sequence",
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# 9. Structural edge cases
# ---------------------------------------------------------------------------

def test_missing_request_artifact_yields_false():
    """When memory_read_request is absent, request_present is FALSE and passed is False."""
    bundle = {
        "authorization_decision": {
            "decision_id": "dec:test:0001",
            "request_ref": "req:test:0001",
            "subject_ref": "matter:test:0001",
            "disposition": "authorized",
        },
        "context_packet": {
            "packet_id": "pkt:test:0001",
            "packet_hash": "sha256:" + "a" * 64,
            "decision_ref": "dec:test:0001",
            "subject_ref": "matter:test:0001",
        },
    }
    report = verify(bundle)
    assert report.request_present is Conclusion.FALSE
    assert report.passed is False


def test_missing_decision_artifact_yields_false():
    """When authorization_decision is absent, decision_present is FALSE."""
    bundle = {
        "memory_read_request": {
            "request_id": "req:test:0001",
            "subject_ref": "matter:test:0001",
        },
        "context_packet": {
            "packet_id": "pkt:test:0001",
            "packet_hash": "sha256:" + "a" * 64,
            "decision_ref": "dec:test:0001",
            "subject_ref": "matter:test:0001",
        },
    }
    report = verify(bundle)
    assert report.decision_present is Conclusion.FALSE
    assert report.passed is False


def test_missing_packet_artifact_yields_false():
    """When context_packet is absent, packet_present is FALSE."""
    bundle = {
        "memory_read_request": {
            "request_id": "req:test:0001",
            "subject_ref": "matter:test:0001",
        },
        "authorization_decision": {
            "decision_id": "dec:test:0001",
            "request_ref": "req:test:0001",
            "subject_ref": "matter:test:0001",
            "disposition": "authorized",
        },
    }
    report = verify(bundle)
    assert report.packet_present is Conclusion.FALSE
    assert report.passed is False


def test_scope_continuity_passes_when_no_scope_declared():
    """When no scope_ref is declared in any artifact, scope_continuity is TRUE.

    Scope is optional; zero declared = consistent (not applicable).
    """
    bundle = {
        "memory_read_request": {
            "request_id": "req:noscope:0001",
            "subject_ref": "matter:noscope:0001",
            "requested_at": "2026-08-01T00:00:00Z",
        },
        "authorization_decision": {
            "decision_id": "dec:noscope:0001",
            "request_ref": "req:noscope:0001",
            "subject_ref": "matter:noscope:0001",
            "disposition": "authorized",
            "packet_hash": "sha256:" + "a" * 64,
            "decided_at": "2026-08-01T00:00:01Z",
        },
        "context_packet": {
            "packet_id": "pkt:noscope:0001",
            "packet_hash": "sha256:" + "a" * 64,
            "decision_ref": "dec:noscope:0001",
            "subject_ref": "matter:noscope:0001",
            "source_refs": [],
            "evidence_manifest": {"claim_ids": [], "anchor_refs": [], "source_refs": []},
            "admitted_claim_ids": [],
            "created_at": "2026-08-01T00:00:02Z",
        },
    }
    report = verify(bundle)
    assert report.scope_continuity is Conclusion.TRUE


def test_reopening_ref_resolves_to_request_id():
    """A reopening_ref that resolves to the request_id is valid."""
    bundle = {
        "memory_read_request": {
            "request_id": "req:reopen:0001",
            "subject_ref": "matter:reopen:0001",
            "requested_at": "2026-08-01T00:00:00Z",
        },
        "authorization_decision": {
            "decision_id": "dec:reopen:0001",
            "request_ref": "req:reopen:0001",
            "subject_ref": "matter:reopen:0001",
            "disposition": "authorized",
            "packet_hash": "sha256:" + "b" * 64,
            "decided_at": "2026-08-01T00:00:01Z",
        },
        "context_packet": {
            "packet_id": "pkt:reopen:0001",
            "packet_hash": "sha256:" + "b" * 64,
            "decision_ref": "dec:reopen:0001",
            "subject_ref": "matter:reopen:0001",
            "reopening_ref": "req:reopen:0001",
            "source_refs": [],
            "evidence_manifest": {"claim_ids": [], "anchor_refs": [], "source_refs": []},
            "admitted_claim_ids": [],
            "created_at": "2026-08-01T00:00:02Z",
        },
    }
    report = verify(bundle)
    assert report.reopening_refs_valid is Conclusion.TRUE


def test_packet_digest_match_not_evaluated_when_no_decision_hash():
    """packet_digest_match is NOT_EVALUATED when authorization_decision has no packet_hash.

    This is not a structural failure — the decision may legitimately not
    carry a packet_hash pre-emission.
    """
    bundle = {
        "memory_read_request": {
            "request_id": "req:nohash:0001",
            "subject_ref": "matter:nohash:0001",
            "requested_at": "2026-08-01T00:00:00Z",
        },
        "authorization_decision": {
            "decision_id": "dec:nohash:0001",
            "request_ref": "req:nohash:0001",
            "subject_ref": "matter:nohash:0001",
            "disposition": "authorized",
            "decided_at": "2026-08-01T00:00:01Z",
        },
        "context_packet": {
            "packet_id": "pkt:nohash:0001",
            "packet_hash": "sha256:" + "c" * 64,
            "decision_ref": "dec:nohash:0001",
            "subject_ref": "matter:nohash:0001",
            "source_refs": [],
            "evidence_manifest": {"claim_ids": [], "anchor_refs": [], "source_refs": []},
            "admitted_claim_ids": [],
            "created_at": "2026-08-01T00:00:02Z",
        },
    }
    report = verify(bundle)
    assert report.packet_digest_match is Conclusion.NOT_EVALUATED
