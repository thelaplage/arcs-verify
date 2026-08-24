"""
tests/test_federation_replay.py — FEDERATION-REPLAY0 offline federation replay
verifier.

Tests verify:
  - digest-binding recomputation against caller-supplied literal bytes
  - permanent non-findings: authority_effect="none", truth_verified="not_evaluated"
    on every code path, including structural failure
  - NOT_EVALUATED never collapses into PASS: missing bytes, and a run with
    zero artifact rows, are both NOT_EVALUATED, never PASS
  - structural rejection paths: malformed envelope, missing run_id, malformed
    artifacts field, malformed artifact_bytes, malformed rows
  - mutation tests: a tampered digest flips that row and the run to FAIL
  - independence: no producer repository is imported by this module
"""

from __future__ import annotations

import copy
import sys

import pytest

from arcs_verify.federation_replay import (
    FAIL,
    NOT_EVALUATED,
    PASS,
    ArtifactReplayCheck,
    FederationReplayReport,
    replay_federation_run,
    sha256_bytes,
)

# ── independence check ───────────────────────────────────────────────────────


def test_no_producer_import_in_federation_replay() -> None:
    """Verifier must not import any producer repository — issuer/verifier
    independence. Federation producers span multiple repos in this wave."""
    import arcs_verify.federation_replay  # noqa: F401

    forbidden_prefixes = (
        "counterpedia_agent",
        "counterpedia_registry",
        "harness_prototypes",
        "dagr_mcp",
        "dagr_ingest",
        "arcs_srs",
    )
    for name in sys.modules:
        for prefix in forbidden_prefixes:
            assert not (name == prefix or name.startswith(prefix + ".")), (
                f"producer module {name!r} was imported — independence violated"
            )


def test_module_source_has_no_producer_import_statement() -> None:
    """AST-level check: no actual `import`/`from` statement names a producer
    package. Prose in the module's own independence-contract docstring
    legitimately names these packages, so a plain substring search would
    false-positive on the documentation itself."""
    import ast
    import pathlib

    src = (
        pathlib.Path(__file__).parent.parent
        / "arcs_verify"
        / "federation_replay.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(src)

    forbidden_prefixes = (
        "counterpedia",
        "harness_prototypes",
        "dagr_mcp",
        "dagr_ingest",
    )
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    for name in imported:
        for prefix in forbidden_prefixes:
            assert not (name == prefix or name.startswith(prefix + ".")), (
                f"forbidden producer import found: {name!r}"
            )


# ── fixtures ──────────────────────────────────────────────────────────────────


def _good_envelope(*refs_digests_kinds):
    return {
        "run_id": "run:1",
        "artifacts": [
            {"kind": kind, "ref": ref, "digest": digest}
            for ref, digest, kind in refs_digests_kinds
        ],
    }


# ── original stub-preserved behavior ──────────────────────────────────────────


def test_replay_pass_fail_and_not_evaluated() -> None:
    good = b"good"
    bad = b"bad"
    env = {
        "run_id": "run:1",
        "artifacts": [
            {"kind": "srs", "ref": "a", "digest": sha256_bytes(good)},
            {"kind": "registry", "ref": "b", "digest": sha256_bytes(bad)},
            {"kind": "memory", "ref": "c", "digest": "sha256:" + "0" * 64},
        ],
    }
    r = replay_federation_run(env, {"a": good, "b": b"tampered"})
    assert [c.status for c in r.checks] == [PASS, FAIL, NOT_EVALUATED]
    assert r.overall_status == FAIL
    assert r.authority_effect == "none"


def test_missing_only_is_not_evaluated_not_failure() -> None:
    r = replay_federation_run(
        {"run_id": "run:2", "artifacts": [{"kind": "x", "ref": "x", "digest": "sha256:" + "0" * 64}]},
        {},
    )
    assert r.overall_status == NOT_EVALUATED


# ── golden path ────────────────────────────────────────────────────────────────


class TestGoldenReplay:
    def test_all_pass(self):
        good_a, good_b = b"artifact-a", b"artifact-b"
        env = _good_envelope(
            ("a", sha256_bytes(good_a), "srs"),
            ("b", sha256_bytes(good_b), "registry"),
        )
        report = replay_federation_run(env, {"a": good_a, "b": good_b})
        assert report.overall_status == PASS
        assert report.artifacts_total == 2
        assert report.artifacts_passed == 2
        assert report.artifacts_failed == 0
        assert report.artifacts_not_evaluated == 0
        assert [c.status for c in report.checks] == [PASS, PASS]

    def test_bytearray_input_accepted(self):
        payload = b"artifact-c"
        env = _good_envelope(("c", sha256_bytes(payload), "memory"))
        report = replay_federation_run(env, {"c": bytearray(payload)})
        assert report.overall_status == PASS

    def test_run_id_preserved(self):
        env = _good_envelope(("a", sha256_bytes(b"x"), "srs"))
        report = replay_federation_run(env, {"a": b"x"})
        assert report.run_id == "run:1"

    def test_to_dict_shape(self):
        env = _good_envelope(("a", sha256_bytes(b"x"), "srs"))
        d = replay_federation_run(env, {"a": b"x"}).to_dict()
        assert d["overall_status"] == PASS
        assert d["authority_effect"] == "none"
        assert d["truth_verified"] == "not_evaluated"
        assert d["failure_code"] is None
        assert d["failure_detail"] is None
        assert isinstance(d["checks"], list)
        assert d["checks"][0]["status"] == PASS
        assert "replayable != authorized" in d["non_equivalences"]


# ── vacuous run guard ────────────────────────────────────────────────────────


class TestVacuousRun:
    def test_zero_artifacts_is_not_evaluated_not_pass(self):
        report = replay_federation_run({"run_id": "run:empty", "artifacts": []}, {})
        assert report.overall_status == NOT_EVALUATED
        assert report.artifacts_total == 0
        assert report.checks == ()

    def test_zero_artifacts_still_carries_permanent_non_findings(self):
        report = replay_federation_run({"run_id": "run:empty", "artifacts": []}, {})
        assert report.authority_effect == "none"
        assert report.truth_verified == "not_evaluated"


# ── row-level structural rejection ──────────────────────────────────────────


class TestRowStructuralRejection:
    def test_row_not_a_mapping_fails(self):
        env = {"run_id": "run:1", "artifacts": ["not-a-dict"]}
        report = replay_federation_run(env, {})
        assert report.overall_status == FAIL
        assert report.checks[0].status == FAIL
        assert "not a mapping" in report.checks[0].reason

    def test_row_missing_ref_fails(self):
        env = {"run_id": "run:1", "artifacts": [{"kind": "srs", "digest": "sha256:" + "0" * 64}]}
        report = replay_federation_run(env, {})
        assert report.checks[0].status == FAIL
        assert "ref" in report.checks[0].reason

    def test_row_empty_ref_fails(self):
        env = {"run_id": "run:1", "artifacts": [{"kind": "srs", "ref": "", "digest": "sha256:" + "0" * 64}]}
        report = replay_federation_run(env, {})
        assert report.checks[0].status == FAIL

    def test_row_malformed_digest_fails(self):
        env = {"run_id": "run:1", "artifacts": [{"kind": "srs", "ref": "a", "digest": "not-a-digest"}]}
        report = replay_federation_run(env, {"a": b"x"})
        assert report.checks[0].status == FAIL
        assert "malformed" in report.checks[0].reason

    def test_row_missing_digest_fails(self):
        env = {"run_id": "run:1", "artifacts": [{"kind": "srs", "ref": "a"}]}
        report = replay_federation_run(env, {"a": b"x"})
        assert report.checks[0].status == FAIL

    def test_row_uppercase_digest_hex_fails(self):
        # digest format is pinned lowercase hex; uppercase is malformed, not
        # silently normalized.
        digest = sha256_bytes(b"x").upper().replace("SHA256", "sha256")
        env = {"run_id": "run:1", "artifacts": [{"kind": "srs", "ref": "a", "digest": digest}]}
        report = replay_federation_run(env, {"a": b"x"})
        assert report.checks[0].status == FAIL

    def test_non_bytes_artifact_payload_fails_not_crashes(self):
        env = _good_envelope(("a", "sha256:" + "0" * 64, "srs"))
        report = replay_federation_run(env, {"a": "not-bytes"})
        assert report.checks[0].status == FAIL
        assert "raw bytes" in report.checks[0].reason


# ── mutation tests ─────────────────────────────────────────────────────────────


class TestMutatedDigest:
    def test_tampered_bytes_flip_row_and_run_to_fail(self):
        good = b"artifact"
        env = _good_envelope(("a", sha256_bytes(good), "srs"))
        report = replay_federation_run(env, {"a": b"tampered"})
        assert report.checks[0].status == FAIL
        assert report.checks[0].reason == "digest mismatch"
        assert report.overall_status == FAIL

    def test_one_bad_row_among_many_fails_whole_run(self):
        good = b"g"
        env = _good_envelope(
            ("a", sha256_bytes(good), "srs"),
            ("b", sha256_bytes(good), "registry"),
        )
        env = copy.deepcopy(env)
        report = replay_federation_run(env, {"a": good, "b": b"different"})
        statuses = [c.status for c in report.checks]
        assert statuses == [PASS, FAIL]
        assert report.overall_status == FAIL


# ── envelope-level structural rejection ─────────────────────────────────────


class TestEnvelopeStructuralRejection:
    def test_envelope_not_a_mapping(self):
        report = replay_federation_run("not-a-dict", {})  # type: ignore[arg-type]
        assert report.failure_code == "invalid_envelope"
        assert report.overall_status == FAIL
        assert report.run_id == ""

    def test_missing_run_id(self):
        report = replay_federation_run({"artifacts": []}, {})
        assert report.failure_code == "missing_run_id"

    def test_empty_string_run_id(self):
        report = replay_federation_run({"run_id": "", "artifacts": []}, {})
        assert report.failure_code == "missing_run_id"

    def test_non_string_run_id(self):
        report = replay_federation_run({"run_id": 123, "artifacts": []}, {})
        assert report.failure_code == "missing_run_id"

    def test_artifact_bytes_not_a_mapping(self):
        report = replay_federation_run(
            {"run_id": "run:1", "artifacts": []}, "not-a-mapping"  # type: ignore[arg-type]
        )
        assert report.failure_code == "invalid_artifact_bytes"
        assert report.run_id == "run:1"

    def test_artifacts_field_missing(self):
        report = replay_federation_run({"run_id": "run:1"}, {})
        assert report.failure_code == "invalid_artifacts_field"

    def test_artifacts_field_not_a_list(self):
        report = replay_federation_run({"run_id": "run:1", "artifacts": "srs"}, {})
        assert report.failure_code == "invalid_artifacts_field"

    def test_artifacts_field_bytes_rejected(self):
        # bytes is technically a Sequence — must be explicitly excluded.
        report = replay_federation_run({"run_id": "run:1", "artifacts": b"srs"}, {})
        assert report.failure_code == "invalid_artifacts_field"


# ── permanent non-findings on every path ────────────────────────────────────


class TestPermanentNonFindings:
    def test_structural_failure_still_sets_non_findings(self):
        report = replay_federation_run("nope", {})  # type: ignore[arg-type]
        assert report.authority_effect == "none"
        assert report.truth_verified == "not_evaluated"

    def test_digest_mismatch_still_sets_non_findings(self):
        env = _good_envelope(("a", sha256_bytes(b"good"), "srs"))
        report = replay_federation_run(env, {"a": b"bad"})
        assert report.authority_effect == "none"
        assert report.truth_verified == "not_evaluated"

    def test_pass_path_still_sets_non_findings(self):
        env = _good_envelope(("a", sha256_bytes(b"good"), "srs"))
        report = replay_federation_run(env, {"a": b"good"})
        assert report.authority_effect == "none"
        assert report.truth_verified == "not_evaluated"

    def test_non_equivalences_present_on_every_path(self):
        for report in (
            replay_federation_run("nope", {}),  # type: ignore[arg-type]
            replay_federation_run({"run_id": "run:1", "artifacts": []}, {}),
            replay_federation_run(
                _good_envelope(("a", sha256_bytes(b"x"), "srs")), {"a": b"x"}
            ),
        ):
            assert "replayable != authorized" in report.non_equivalences
            assert "replayable != admitted" in report.non_equivalences


# ── dataclass sanity ─────────────────────────────────────────────────────────


def test_artifact_replay_check_to_dict():
    check = ArtifactReplayCheck(ref="a", kind="srs", status=PASS, reason="")
    assert check.to_dict() == {"ref": "a", "kind": "srs", "status": PASS, "reason": ""}


def test_sha256_bytes_format():
    digest = sha256_bytes(b"hello")
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
