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


def test_mutation_step_is_referenced_not_regenerated() -> None:
    steps = {step["step"]: step for step in PACK_MANIFEST["journey"]}
    mutation = steps["mutation"]

    assert mutation["evidence"]["receipts"] == [MUTATION_PATH]
    assert mutation["expected_signature_valid"] is False
    assert mutation["expected_failure_codes"] == ["signature_invalid"]

    # The expectation is asserted by the normative set, not restated here.
    normative = _load(PACK / "expected" / "expectations.json")
    declared = {entry["path"]: entry for entry in normative["entries"]}
    entry = declared["mutations/semantic-field-change-fail.json"]
    assert entry["signature_valid"] is False
    assert entry["expected_failure_codes"] == ["signature_invalid"]

    # And the fixture it points at is a real file under normative/.
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
    assert sorted(p.name for p in FIXTURES.iterdir()) == sorted(
        [
            "README.md",
            ADMITTED_ADMISSION,
            REFUSED_ADMISSION,
            ADMITTED_OUTCOME,
            "expectations.json",
            "issuer-keys.json",
            "manifest.json",
            "quickstart.txt",
            "side_effects.json",
        ]
    )


def test_verifier_declares_no_producer_dependency() -> None:
    """dagr-mcp is not a runtime or test dependency of the verifier."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dagr-mcp" not in pyproject
    assert "dagr_mcp" not in pyproject
