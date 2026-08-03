"""First-run proof-pack: pinned digests, journey wiring, and refusal semantics.

These tests read bytes only. They import no producer or emitter code; the
digests and the verdict vectors are checked against what the verifier itself
computes from the fixture files.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import rfc8785

from arcs_verify.verifier import verify_receipt

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "arcs_verify/data/srs-envelope-v0.2.0.schema.json"
PACK = ROOT / "packs" / "srs.mcp.sdk_enforcement" / "v0.1"
FIXTURES = PACK / "implementation" / "dagr-mcp-first-run"
PACK_MANIFEST_PATH = PACK / "proof-pack-manifest.json"

GENERATOR_COMMIT = "362f7a565a3813924892b0fb7da046b63b1b080a"

# The pinned producer: the exact dagr-mcp commit and tree the captured bytes
# were generated from. GENERATOR_COMMIT above authored the producer and is an
# ancestor of this commit; the producer sources are identical between them.
PRODUCER_COMMIT = "acb6943b63da51e5513d9ab4906e02d41069328d"
PRODUCER_TREE = "493d78b300567418f3464288d978385f9519e788"
PRODUCER_COMMAND = (
    "python -m dagr_mcp.demo first-run --capture --output ./dagr-first-run-output"
)

MUTATION_NAME = "admitted-admission-disposition-flip.json"

ADMITTED_ADMISSION = "urn_srs_receipt_admission_first-run-capture-0001.json"
ADMITTED_OUTCOME = "urn_srs_receipt_outcome_first-run-capture-0001.json"
REFUSED_ADMISSION = "urn_srs_receipt_admission_first-run-capture-0002.json"

MUTATION_PATH = "normative/mutations/semantic-field-change-fail.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


MANIFEST = _load(FIXTURES / "manifest.json")
PACK_MANIFEST = _load(PACK_MANIFEST_PATH)
SIDE_EFFECTS = _load(FIXTURES / "side_effects.json")


def _canonical_preimage_sha256(receipt: dict[str, Any]) -> str:
    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]
    return hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()


@pytest.mark.parametrize(
    "entry", MANIFEST["entries"], ids=[e["path"] for e in MANIFEST["entries"]]
)
def test_pinned_digests_match_the_fixture_bytes(entry: dict[str, Any]) -> None:
    path = FIXTURES / entry["path"]
    receipt = _load(path)

    assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["receipt_file_sha256"]
    assert _canonical_preimage_sha256(receipt) == entry["canonical_preimage_sha256"]
    assert receipt["receipt_id"] == entry["receipt_id"]
    assert entry["generator_commit"] == GENERATOR_COMMIT


def test_pinned_public_key_digest_matches_the_keyring() -> None:
    keyring_path = FIXTURES / "issuer-keys.json"
    keyring = _load(keyring_path)

    assert (
        hashlib.sha256(keyring_path.read_bytes()).hexdigest()
        == MANIFEST["keyring_sha256"]
    )

    by_key_id = {}
    for issuer in keyring["issuers"]:
        encoded = issuer["public_key"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        by_key_id[issuer["key_id"]] = hashlib.sha256(raw).hexdigest()

    for entry in MANIFEST["entries"]:
        receipt = _load(FIXTURES / entry["path"])
        key_id = receipt["receipt_signature"]["key_id"]
        assert by_key_id[key_id] == entry["public_key_sha256"]


def test_side_effects_digest_is_pinned() -> None:
    digest = hashlib.sha256((FIXTURES / "side_effects.json").read_bytes()).hexdigest()
    assert digest == MANIFEST["side_effects_sha256"]


def _verify(name: str) -> dict[str, Any]:
    report = verify_receipt(
        _load(FIXTURES / name),
        _load(FIXTURES / "issuer-keys.json"),
        schema_path=SCHEMA_PATH,
        selected_profile="srs.mcp.sdk_enforcement.v0.1",
    )
    return report.to_dict()


def test_refused_admission_receipt_verifies_as_authentic() -> None:
    """A refusal is recorded by a valid receipt; verifying it PASSES.

    Enforcement is not proven by this receipt failing verification. It is
    proven by this receipt being authentic *and* by the producer's observed
    record showing the native action did not run.
    """
    receipt = _load(FIXTURES / REFUSED_ADMISSION)
    assert receipt["disposition"] == "refused"
    assert receipt["reason_code"] == "policy_refused"

    actual = _verify(REFUSED_ADMISSION)
    assert actual["signature_valid"] is True
    assert actual["failure_codes"] == []
    assert actual["chain_status"] == "not_applicable"


@pytest.mark.parametrize(
    "verdict_key", ["signature_valid", "issuer_key_trusted", "raw_content_exclusion"]
)
def test_negative_control_on_the_refused_fixture(verdict_key: str) -> None:
    """Flipping any declared verdict for the refused receipt must be detected.

    Without this, `signature_valid: true` on a refused receipt could be a
    declaration nothing actually checks.
    """
    actual = _verify(REFUSED_ADMISSION)
    declared = {
        entry["path"]: entry
        for entry in _load(FIXTURES / "expectations.json")["receipts"]
    }[REFUSED_ADMISSION]["verdicts"]

    assert actual[verdict_key] == declared[verdict_key]
    assert actual[verdict_key] != (not declared[verdict_key])


def test_negative_control_detects_tampered_refused_receipt() -> None:
    """Mutating the refused receipt's bytes must break its signature."""
    receipt = _load(FIXTURES / REFUSED_ADMISSION)
    receipt["disposition"] = "admitted"

    report = verify_receipt(
        receipt,
        _load(FIXTURES / "issuer-keys.json"),
        schema_path=SCHEMA_PATH,
        selected_profile="srs.mcp.sdk_enforcement.v0.1",
    ).to_dict()

    assert report["signature_valid"] is False
    assert "signature_invalid" in report["failure_codes"]


def test_mutation_is_derived_from_a_captured_receipt() -> None:
    """The mutation changes exactly one signed field of a captured receipt."""
    declared = MANIFEST["mutation"]
    mutated = _load(FIXTURES / declared["path"])
    source = _load(FIXTURES / declared["source_receipt"])

    assert declared["source_receipt"] == ADMITTED_ADMISSION
    assert declared["json_pointer"] == "/disposition"

    # Exactly one field differs, and it is the declared one.
    differing = {k for k in set(mutated) | set(source) if mutated.get(k) != source.get(k)}
    assert differing == {"disposition"}
    assert source["disposition"] == declared["changed_from"] == "admitted"
    assert mutated["disposition"] == declared["changed_to"] == "refused"

    # The signature is carried over untouched: the failure must come from the
    # mutated field, not from re-signing or from corrupted trust material.
    assert mutated["receipt_signature"] == source["receipt_signature"]


def test_mutation_fails_with_signature_invalid_only() -> None:
    """The mutation fails on signature alone; structure and trust still pass."""
    declared = MANIFEST["mutation"]
    mutated = _load(FIXTURES / declared["path"])

    report = verify_receipt(
        mutated,
        _load(FIXTURES / "issuer-keys.json"),
        schema_path=SCHEMA_PATH,
        selected_profile="srs.mcp.sdk_enforcement.v0.1",
    ).to_dict()

    assert report["signature_valid"] is False
    assert report["failure_codes"] == ["signature_invalid"]
    assert report["passed"] is False

    # Trust material and structure are untouched, so these must still hold.
    assert report["envelope"] is True
    assert report["profile"] is True
    assert report["issuer_key_trusted"] is True
    assert report["raw_content_exclusion"] is True


def test_permanent_normative_mutation_vector_is_still_asserted() -> None:
    """The WP2A standard vector keeps its own independent expectation."""
    normative = _load(PACK / "expected" / "expectations.json")
    declared = {entry["path"]: entry for entry in normative["entries"]}
    entry = declared["mutations/semantic-field-change-fail.json"]
    assert entry["signature_valid"] is False
    assert entry["expected_failure_codes"] == ["signature_invalid"]
    assert (PACK / MUTATION_PATH).is_file()


def test_journey_covers_admitted_refused_and_mutation() -> None:
    steps = [step["step"] for step in PACK_MANIFEST["journey"]]
    assert steps == ["admitted", "refused", "mutation"]

    admitted = PACK_MANIFEST["journey"][0]["evidence"]["receipts"]
    assert admitted == [
        f"implementation/dagr-mcp-first-run/{ADMITTED_ADMISSION}",
        f"implementation/dagr-mcp-first-run/{ADMITTED_OUTCOME}",
    ]
    refused = PACK_MANIFEST["journey"][1]["evidence"]["receipts"]
    assert refused == [f"implementation/dagr-mcp-first-run/{REFUSED_ADMISSION}"]

    for step in PACK_MANIFEST["journey"]:
        for relative in step["evidence"]["receipts"]:
            assert (PACK / relative).is_file()
        assert (PACK / step["evidence"]["expectations"]).is_file()


def test_mfd_frontdoor_01_linkage_traces_producer_to_verifier() -> None:
    """The producer's observed record and the verified bytes name the same call."""
    linkage = PACK_MANIFEST["mfd_frontdoor_01_linkage"]
    scenarios = SIDE_EFFECTS["scenarios"]

    assert linkage["chain"] == SIDE_EFFECTS["mfd_frontdoor_01_linkage"]

    admitted_admission = _load(FIXTURES / ADMITTED_ADMISSION)
    admitted_outcome = _load(FIXTURES / ADMITTED_OUTCOME)
    refused_admission = _load(FIXTURES / REFUSED_ADMISSION)

    # Producer-declared refs resolve to the receipt bytes the verifier checked.
    assert (
        scenarios["admitted"]["admission_receipt_ref"]
        == admitted_admission["receipt_id"]
        == linkage["admission_receipt_ref"]
    )
    assert (
        scenarios["admitted"]["outcome_receipt_ref"]
        == admitted_outcome["receipt_id"]
        == linkage["outcome_receipt_ref"]
    )
    assert (
        scenarios["refused"]["admission_receipt_ref"]
        == refused_admission["receipt_id"]
        == linkage["refused_admission_receipt_ref"]
    )

    # The outcome receipt binds back to its own admission receipt.
    assert admitted_outcome["admission_receipt_ref"] == admitted_admission["receipt_id"]

    # Both scenarios name the same front-door action, on distinct calls.
    assert (
        admitted_admission["requested_tool_name"]
        == refused_admission["requested_tool_name"]
        == linkage["requested_tool_name"]
    )
    assert admitted_admission["logical_call_id"] == linkage["logical_call_id_admitted"]
    assert refused_admission["logical_call_id"] == linkage["logical_call_id_refused"]
    assert admitted_outcome["logical_call_id"] == admitted_admission["logical_call_id"]
    assert admitted_admission["logical_call_id"] != refused_admission["logical_call_id"]

    # Same proposed action in both scenarios: identical argument digest.
    assert admitted_admission["argument_digest"] == refused_admission["argument_digest"]


def test_non_execution_is_a_delta_not_an_absolute_count() -> None:
    """The sentinel counter is shared across the sequence, so delta is the proof."""
    refused = SIDE_EFFECTS["scenarios"]["refused"]

    assert refused["native_action_executed"] is False
    assert refused["governed_ok"] is False
    assert refused["failure_reason"] == "denied"
    assert refused["policy_decision"] == "deny"
    assert refused["outcome_receipt_ref"] is None

    before = refused["inner_invocation_count_before"]
    after = refused["inner_invocation_count_after"]
    assert after - before == 0
    # Explicitly NOT `== 0`: the counter carries over from the admitted run.
    assert before == 1

    admitted = SIDE_EFFECTS["scenarios"]["admitted"]
    assert admitted["native_action_executed"] is True
    assert admitted["governed_ok"] is True
    assert admitted["policy_decision"] == "allow"
    assert (
        admitted["inner_invocation_count_after"]
        - admitted["inner_invocation_count_before"]
        == 1
    )


def test_pack_claims_no_conformance_level() -> None:
    blob = json.dumps(PACK_MANIFEST) + (FIXTURES / "README.md").read_text(
        encoding="utf-8"
    )
    for forbidden in ("Level C", "Level D"):
        assert forbidden not in blob


def test_runtime_package_contains_no_producer_imports() -> None:
    """The verifier runtime never imports the emitter that produced these bytes."""
    sources = sorted((ROOT / "arcs_verify").rglob("*.py"))
    assert sources
    blob = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    for producer in ("dagr_mcp", "dagr_mcp_service", "dagr_mcp_sdk_binding"):
        assert f"import {producer}" not in blob
        assert f"from {producer}" not in blob


def test_fixture_directory_ships_bytes_only() -> None:
    """The fixture set is evidence, not code: no importable module lands here."""
    assert not list(FIXTURES.rglob("*.py"))
    assert sorted(p.relative_to(FIXTURES).as_posix() for p in FIXTURES.rglob("*") if p.is_file()) == sorted(
        [
            "README.md",
            ADMITTED_ADMISSION,
            REFUSED_ADMISSION,
            ADMITTED_OUTCOME,
            "digests.json",
            "expectations.json",
            "issuer-keys.json",
            "manifest.json",
            "quickstart.txt",
            "side_effects.json",
            f"mutations/{MUTATION_NAME}",
            f"verification/{ADMITTED_ADMISSION}",
            f"verification/{ADMITTED_OUTCOME}",
            f"verification/{REFUSED_ADMISSION}",
            f"verification/{MUTATION_NAME}",
        ]
    )


def test_pinned_producer_commit_and_tree_are_recorded_exactly() -> None:
    """Both manifests name the same pinned producer commit, tree and command."""
    for producer in (MANIFEST["producer"], PACK_MANIFEST["producer"]):
        assert producer["repo"] == "dagr-mcp"
        assert producer["commit"] == PRODUCER_COMMIT
        assert producer["tree"] == PRODUCER_TREE
        assert producer["source_commit"] == GENERATOR_COMMIT
        assert producer["capture_mode"] is True

    assert MANIFEST["producer"]["command"] == PRODUCER_COMMAND
    assert PACK_MANIFEST["producer"]["command"] == PRODUCER_COMMAND

    # Every per-receipt entry still attributes itself to the authoring commit.
    for entry in MANIFEST["entries"]:
        assert entry["generator_commit"] == GENERATOR_COMMIT


@pytest.mark.parametrize(
    "relative", sorted(_load(FIXTURES / "digests.json")["artifacts"])
)
def test_every_declared_digest_recomputes(relative: str) -> None:
    declared = _load(FIXTURES / "digests.json")["artifacts"][relative]
    path = FIXTURES / relative
    assert path.is_file(), f"declared artifact missing: {relative}"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == declared


def test_digest_inventory_declares_every_committed_artifact() -> None:
    """No undeclared artifact may sit in the pack directory."""
    declared = set(_load(FIXTURES / "digests.json")["artifacts"])
    on_disk = {
        p.relative_to(FIXTURES).as_posix()
        for p in FIXTURES.rglob("*")
        if p.is_file() and p.name != "digests.json"
    }
    assert declared == on_disk


@pytest.mark.parametrize(
    "name", [ADMITTED_ADMISSION, ADMITTED_OUTCOME, REFUSED_ADMISSION]
)
def test_committed_verification_result_matches_the_live_verifier(name: str) -> None:
    """The committed report is what this verifier actually produces today."""
    record = _load(FIXTURES / "verification" / name)
    assert record["subject"] == name
    assert record["subject_role"] == "captured_receipt"
    assert record["profile"] == "srs.mcp.sdk_enforcement.v0.1"
    assert record["result"] == _verify(name)
    assert record["result"]["passed"] is True
    assert record["result"]["failure_codes"] == []


def test_committed_mutation_result_matches_the_live_verifier() -> None:
    record = _load(FIXTURES / "verification" / MUTATION_NAME)
    mutated = _load(FIXTURES / "mutations" / MUTATION_NAME)

    report = verify_receipt(
        mutated,
        _load(FIXTURES / "issuer-keys.json"),
        schema_path=SCHEMA_PATH,
        selected_profile="srs.mcp.sdk_enforcement.v0.1",
    ).to_dict()

    assert record["result"] == report
    assert record["result"]["failure_codes"] == ["signature_invalid"]


def test_committed_artifacts_contain_no_machine_local_paths() -> None:
    """Nothing in the pack may leak a home directory, temp dir or username."""
    # Assembled rather than written literally so this test does not itself
    # trip tools/check_public_release.py's absolute-path scanner (PR003).
    sep = "/"
    forbidden = tuple(
        sep + part + sep
        for part in ("Users", "home", "tmp", "var" + sep + "folders")
    ) + (sep + "private" + sep + "tmp",)
    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in text, f"{path.name} leaks {needle!r}"


def test_derived_artifacts_regenerate_identically() -> None:
    """`--check` must be clean: the committed derived half is reproducible."""
    result = subprocess.run(
        [sys.executable, "tools/generate_first_run_proof_pack.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_verifier_declares_no_producer_dependency() -> None:
    """dagr-mcp is not a runtime or test dependency of the verifier."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dagr-mcp" not in pyproject
    assert "dagr_mcp" not in pyproject
