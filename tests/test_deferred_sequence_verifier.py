"""Sequence-level verifier tests for srs.deferred_operation.v0.1.

Tests verify that:
- Valid sequences produce Conclusion.TRUE for all structural findings.
- Every mutation in the adversarial corpus is rejected with the correct finding.
- Non-equivalences from the profile spec §7 are not violated.
- NOT_EVALUATED is preserved and not promoted to PASS.
- Sequence-level passed requires all structural findings.
- producer packages are not imported (acceptance gate).
- CWD-independent CLI path works.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arcs_verify.deferred_sequence import (
    Conclusion,
    DeferredSequenceReport,
    verify_deferred_sequence,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "deferred_sequence"
SIGNED_KEYRING_PATH = FIXTURE_ROOT / "issuer-keys.json"
SCHEMA_V021 = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.1.schema.json"

# Ensure subprocess calls use the worktree source rather than any installed
# version of arcs-verify that may not yet include this lane's code.
_CLI_ENV = {**os.environ, "PYTHONPATH": str(ROOT)}


def load_seq(name: str) -> list[dict]:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def load_keyring() -> dict:
    return json.loads(SIGNED_KEYRING_PATH.read_text(encoding="utf-8"))


def verify(receipts, keyring=None):
    if keyring is None:
        keyring = load_keyring()
    return verify_deferred_sequence(receipts, keyring, schema_path=SCHEMA_V021)


# ---------------------------------------------------------------------------
# Acceptance gate: producer packages absent
# ---------------------------------------------------------------------------

def test_producer_packages_absent():
    """dagr_mcp and arcs_srs must not be importable in this environment."""
    for pkg in ("dagr_mcp", "arcs_srs"):
        spec = importlib.util.find_spec(pkg)
        assert spec is None, (
            f"Producer package {pkg!r} is present in the verifier environment. "
            "Producer/verifier independence is violated."
        )


# ---------------------------------------------------------------------------
# 1. Valid full sequence (defer → condition → terminal_admitted → outcome)
# ---------------------------------------------------------------------------

def test_valid_full_sequence_passes_all_structural_findings():
    seq = load_seq("valid-full-sequence.json")
    report = verify(seq)
    c = report.to_dict()["conclusions"]

    assert c["event_presence"] == "true", report.findings
    assert c["sequence_id_continuity"] == "true", report.findings
    assert c["predecessor_linkage"] == "true", report.findings
    assert c["defer_receipt_linkage"] == "true", report.findings
    assert c["condition_receipt_linkage"] == "true", report.findings
    assert c["operation_digest_continuity"] == "true", report.findings
    assert c["response_expiry_honoured"] == "true", report.findings
    assert c["terminal_state_present"] == "true", report.findings
    assert c["terminal_disposition_valid"] == "true", report.findings
    assert c["refused_has_no_execution_outcome"] == "true", report.findings
    assert c["outcome_links_admitted_terminal"] == "true", report.findings
    assert c["replay_clean"] == "true", report.findings
    assert c["individual_receipts_valid"] == "true", report.findings
    assert report.passed is True, report.findings


def test_valid_full_sequence_signature_findings_present():
    """Per-receipt signature findings are included in individual_receipt_reports."""
    seq = load_seq("valid-full-sequence.json")
    report = verify(seq)
    assert len(report.individual_receipt_reports) == 4
    for item in report.individual_receipt_reports:
        single = item["report"]
        # Signature findings are present per-receipt
        assert "signature_valid" in single
        assert "issuer_key_resolved" in single
        assert "issuer_key_trusted" in single
        # With the real keyring, these must pass
        assert single["signature_valid"] is True, item
        assert single["issuer_key_resolved"] is True, item
        assert single["issuer_key_trusted"] is True, item


# ---------------------------------------------------------------------------
# 2. Valid refused sequence (defer → condition → terminal_refused, no outcome)
# ---------------------------------------------------------------------------

def test_valid_refused_sequence_passes():
    seq = load_seq("valid-refused-sequence.json")
    report = verify(seq)
    assert report.passed is True, report.findings
    c = report.to_dict()["conclusions"]
    assert c["terminal_state_present"] == "true"
    assert c["terminal_disposition_valid"] == "true"
    assert c["refused_has_no_execution_outcome"] == "true"


def test_valid_refused_sequence_no_outcome_present():
    """A refused sequence with no execution_outcome must pass."""
    seq = load_seq("valid-refused-sequence.json")
    kinds = [r.get("receipt_kind") for r in seq]
    assert "execution_outcome" not in kinds
    report = verify(seq)
    assert report.refused_has_no_execution_outcome is Conclusion.TRUE


# ---------------------------------------------------------------------------
# 3. receipt_gap_disclosed is informational and does not gate passed
# ---------------------------------------------------------------------------

def test_receipt_gap_disclosed_is_informational():
    """
    receipt_gap_disclosed is informational. A sequence without a receipt_gap
    has receipt_gap_disclosed=false but can still pass.
    """
    seq = load_seq("valid-full-sequence.json")
    report = verify(seq)
    c = report.to_dict()["conclusions"]
    # No gap in this sequence
    assert c["receipt_gap_disclosed"] == "false"
    # But the sequence still passes
    assert report.passed is True


# ---------------------------------------------------------------------------
# 4. NOT_EVALUATED is never promoted to PASS
# ---------------------------------------------------------------------------

def test_not_evaluated_is_not_promoted_to_pass():
    """
    An empty receipt list yields all NOT_EVALUATED or FALSE.
    passed must be False.
    """
    report = verify_deferred_sequence([], load_keyring(), schema_path=SCHEMA_V021)
    assert report.passed is False
    data = report.to_dict()
    assert data["passed"] is False


def test_no_master_status_replaces_conclusions():
    """to_dict() exposes each named conclusion separately. passed is not a substitute."""
    seq = load_seq("valid-full-sequence.json")
    report = verify(seq)
    data = report.to_dict()
    assert "conclusions" in data
    conclusions = data["conclusions"]
    expected_keys = {
        "event_presence",
        "sequence_id_continuity",
        "predecessor_linkage",
        "defer_receipt_linkage",
        "condition_receipt_linkage",
        "operation_digest_continuity",
        "response_expiry_honoured",
        "terminal_state_present",
        "terminal_disposition_valid",
        "refused_has_no_execution_outcome",
        "outcome_links_admitted_terminal",
        "replay_clean",
        "individual_receipts_valid",
        "receipt_gap_disclosed",
    }
    assert expected_keys.issubset(conclusions.keys()), (
        f"Missing conclusion keys: {expected_keys - conclusions.keys()}"
    )


# ---------------------------------------------------------------------------
# 5. Mutation corpus — each mutation produces the expected rejection
# ---------------------------------------------------------------------------

def test_mutation_wrong_sequence_id_detected():
    """sequence_id_continuity must be FALSE when one receipt carries a different sequence_id."""
    seq = load_seq("mutation-wrong-sequence-id.json")
    report = verify(seq)
    assert report.sequence_id_continuity is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "sequence_id_discontinuity" in codes


def test_mutation_wrong_predecessor_ref_detected():
    """predecessor_linkage must be FALSE when predecessor_receipt_ref points to the wrong id."""
    seq = load_seq("mutation-wrong-predecessor-ref.json")
    report = verify(seq)
    assert report.predecessor_linkage is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "predecessor_ref_mismatch" in codes


def test_mutation_wrong_defer_receipt_ref_detected():
    """defer_receipt_linkage must be FALSE when defer_receipt_ref points to the wrong id."""
    seq = load_seq("mutation-wrong-defer-receipt-ref.json")
    report = verify(seq)
    assert report.defer_receipt_linkage is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "defer_receipt_ref_mismatch" in codes


def test_mutation_wrong_condition_receipt_ref_detected():
    """condition_receipt_linkage must be FALSE when condition_receipt_ref is wrong."""
    seq = load_seq("mutation-wrong-condition-receipt-ref.json")
    report = verify(seq)
    assert report.condition_receipt_linkage is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "condition_receipt_ref_mismatch" in codes


def test_mutation_duplicate_receipt_id_detected():
    """replay_clean must be FALSE when a receipt_id appears more than once."""
    seq = load_seq("mutation-duplicate-receipt-id.json")
    report = verify(seq)
    assert report.replay_clean is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "duplicate_receipt_id" in codes


def test_mutation_missing_operation_digest_detected():
    """operation_digest_continuity must be FALSE when a required operation_digest is absent."""
    seq = load_seq("mutation-missing-operation-digest.json")
    report = verify(seq)
    assert report.operation_digest_continuity is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "missing_operation_digest" in codes


def test_mutation_terminal_deferred_disposition_detected():
    """terminal_disposition_valid must be FALSE for disposition=deferred_for_review."""
    seq = load_seq("mutation-terminal-deferred-disposition.json")
    report = verify(seq)
    assert report.terminal_disposition_valid is Conclusion.FALSE
    assert report.passed is False
    # Also caught by individual receipt profile check
    codes = [f.code for f in report.findings]
    assert any(
        "terminal_admission_invalid_disposition" in c for c in codes
    ), codes


def test_mutation_outcome_after_refused_detected():
    """refused_has_no_execution_outcome must be FALSE when outcome links to refused terminal."""
    seq = load_seq("mutation-outcome-after-refused.json")
    report = verify(seq)
    assert report.refused_has_no_execution_outcome is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "execution_outcome_after_refused_terminal" in codes


def test_mutation_expired_followed_by_reevaluation_detected():
    """response_expiry_honoured must be FALSE when expired condition is followed by reevaluation."""
    seq = load_seq("mutation-expired-followed-by-reevaluation.json")
    report = verify(seq)
    assert report.response_expiry_honoured is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "expired_condition_followed_by_reevaluation" in codes


# ---------------------------------------------------------------------------
# 6. Non-equivalences from profile spec §7 — semantic failure cases
# ---------------------------------------------------------------------------

def test_approved_condition_not_admissibility_verdict():
    """
    Non-equivalence §7: condition_response.response_status == approved
    does NOT make the operation admissible. The sequence verifier does not
    assert admissibility. Passing sequence_id_continuity etc. does not
    imply admission.
    """
    seq = load_seq("valid-full-sequence.json")
    # The condition_response in this sequence has response_status=approved.
    cond = next(r for r in seq if r["receipt_kind"] == "condition_response")
    assert cond["response_status"] == "approved"

    report = verify(seq)
    # Sequence passes structurally
    assert report.passed is True
    # But the report includes an explicit limitation about this
    data = report.to_dict()
    limitation_texts = " ".join(data["limitations"])
    assert "approved" in limitation_texts.lower()
    assert "admissible" in limitation_texts.lower()


def test_terminal_admission_present_not_sequence_complete():
    """
    Non-equivalence §7: terminal_admission present ≠ sequence complete.
    The refused sequence has a terminal but no execution_outcome — it is
    a valid terminal state, not an incomplete sequence.
    """
    seq = load_seq("valid-refused-sequence.json")
    report = verify(seq)
    assert report.terminal_state_present is Conclusion.TRUE
    assert report.passed is True
    # No execution_outcome is present — sequence is complete (refused terminal)
    kinds = [r["receipt_kind"] for r in seq]
    assert "execution_outcome" not in kinds


def test_receipt_gap_present_not_sequence_valid():
    """
    Non-equivalence §7: receipt_gap present ≠ sequence valid.
    A sequence containing only a defer_request and receipt_gap (no terminal)
    must fail terminal_state_present.
    """
    keyring = load_keyring()
    seq = load_seq("valid-full-sequence.json")
    # Build a sequence with a gap but no terminal
    defer = seq[0]
    gap_receipt = {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.deferred_operation",
        "profile_version": "v0.1",
        "receipt_id": "gap-only-0001",
        "receipt_type": "provenance",
        "receipt_kind": "receipt_gap",
        "boundary_type": "mcp_tool_call",
        "protocol_binding": "mcp",
        "subject_ref": "fixture:deferred-op-signed-subject",
        "issuer_id": "issuer.test/deferred-op/2026-01",
        "issued_at": "2026-01-01T01:00:00Z",
        "sequence_id": defer["sequence_id"],
        "predecessor_receipt_ref": defer["receipt_id"],
        "gap_reason": "Emitter transient failure during review window",
        "artifact_classes_covered": ["trace"],
        "artifact_classes_excluded": [
            "raw_prompt",
            "raw_output",
            "raw_tool_arguments",
            "raw_tool_result",
        ],
        "attestation_limits": [
            "The receipt establishes the declared event role and associated "
            "metadata at the time of issuance. It does not independently "
            "establish that the governed operation executed, that conditions "
            "were actually met, or that the sequence is complete. Receipt "
            "presence is not equivalent to operational compliance."
        ],
        "extensions": {},
        "receipt_signature": {
            "algorithm": "Ed25519",
            "canonicalization": "RFC8785-JCS",
            "key_id": "issuer.test/deferred-op/2026-01",
            "signature": (
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
        },
    }
    incomplete_seq = [defer, gap_receipt]
    report = verify_deferred_sequence(
        incomplete_seq, keyring, schema_path=SCHEMA_V021
    )
    # receipt_gap is disclosed
    assert report.receipt_gap_disclosed is Conclusion.TRUE
    # But sequence is NOT complete — no terminal_admission
    assert report.terminal_state_present is Conclusion.FALSE
    assert report.passed is False


def test_operation_digest_match_not_same_real_world_operation():
    """
    Non-equivalence §7: operation_digest match ≠ same real-world operation.
    The verifier checks digest *presence* (sha256: format), not equivalence
    across receipts — because digest equality is an emitter claim, not
    independently verifiable from structure.
    """
    # The valid sequence has different operation_digest values across kinds
    # (defer uses OP_DIGEST, terminal uses OP_DIGEST2). This is structurally
    # valid — the verifier must not assert cross-receipt digest equality.
    seq = load_seq("valid-full-sequence.json")
    defer_digest = next(
        r for r in seq if r["receipt_kind"] == "defer_request"
    )["operation_digest"]
    terminal_digest = next(
        r for r in seq if r["receipt_kind"] == "terminal_admission"
    )["operation_digest"]

    # Confirm the fixture intentionally has different digests
    assert defer_digest != terminal_digest, (
        "Test fixture should use distinct operation_digests to confirm the "
        "verifier does not enforce cross-receipt digest equality"
    )

    # The sequence must pass structural checks despite different digest values
    report = verify(seq)
    assert report.operation_digest_continuity is Conclusion.TRUE
    assert report.passed is True


# ---------------------------------------------------------------------------
# 7. Sequence integrity distinguishes from policy correctness
# ---------------------------------------------------------------------------

def test_limitations_distinguish_sequence_integrity_from_policy():
    """
    The sequence report limitations explicitly distinguish sequence integrity
    from policy correctness, human intent, and side-effect reality.
    """
    seq = load_seq("valid-full-sequence.json")
    report = verify(seq)
    data = report.to_dict()
    limitations = data["limitations"]
    assert isinstance(limitations, list)
    assert len(limitations) >= 3

    text = " ".join(limitations).lower()
    # Distinguishes policy correctness
    assert "policy" in text
    # Distinguishes human intent
    assert "intent" in text
    # Distinguishes side-effect reality
    assert "side-effect" in text or "underlying operation" in text


# ---------------------------------------------------------------------------
# 8. CWD-independent CLI path
# ---------------------------------------------------------------------------

def test_cli_deferred_sequence_json_output(tmp_path):
    """CLI deferred-sequence subcommand produces JSON report from a tmp dir.

    CWD is set to a temporary directory to confirm path-independence.
    PYTHONPATH is set to the worktree root so subprocess uses the current
    source tree rather than any previously installed arcs-verify distribution.
    """
    seq_path = FIXTURE_ROOT / "valid-full-sequence.json"
    keyring_path = SIGNED_KEYRING_PATH
    schema_path = SCHEMA_V021

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "deferred-sequence",
            "--sequence",
            str(seq_path),
            "--keyring",
            str(keyring_path),
            "--schema",
            str(schema_path),
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
    assert data["schema"] == "arcs_verify.deferred_sequence_report.v0_1"


def test_cli_deferred_sequence_text_output(tmp_path):
    """CLI text output includes passed: true for a valid sequence."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "deferred-sequence",
            "--sequence",
            str(FIXTURE_ROOT / "valid-full-sequence.json"),
            "--keyring",
            str(SIGNED_KEYRING_PATH),
            "--schema",
            str(SCHEMA_V021),
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
            "deferred-sequence",
            "--sequence",
            str(FIXTURE_ROOT / "mutation-wrong-sequence-id.json"),
            "--keyring",
            str(SIGNED_KEYRING_PATH),
            "--schema",
            str(SCHEMA_V021),
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 1


def test_cli_deferred_sequence_individual_receipts_mode(tmp_path):
    """CLI --receipts mode loads individual files in declared order."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "deferred-sequence",
            "--receipts",
            str(FIXTURE_ROOT / "defer-signed.json"),
            str(FIXTURE_ROOT / "condition-response-signed.json"),
            str(FIXTURE_ROOT / "terminal-admitted-signed.json"),
            str(FIXTURE_ROOT / "execution-outcome-signed.json"),
            "--keyring",
            str(SIGNED_KEYRING_PATH),
            "--schema",
            str(SCHEMA_V021),
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["passed"] is True


# ---------------------------------------------------------------------------
# 9. Report schema and verification_profile fields are present
# ---------------------------------------------------------------------------

def test_report_schema_field_present():
    seq = load_seq("valid-full-sequence.json")
    report = verify(seq)
    data = report.to_dict()
    assert data["schema"] == "arcs_verify.deferred_sequence_report.v0_1"
    assert data["verification_profile"] == "srs.deferred_operation.v0.1"


# ---------------------------------------------------------------------------
# 10. Empty sequence yields FALSE not_evaluated preservation
# ---------------------------------------------------------------------------

def test_empty_sequence_all_conclusions_false():
    report = verify_deferred_sequence([], load_keyring(), schema_path=SCHEMA_V021)
    data = report.to_dict()
    assert data["passed"] is False
    # event_presence should be FALSE (explicitly set)
    assert data["conclusions"]["event_presence"] == "false"
