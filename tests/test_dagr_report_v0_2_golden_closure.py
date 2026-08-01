"""Closure gate for the authoritative v0.2 report goldens.

    python -m pytest tests/test_dagr_report_v0_2_golden_closure.py -q

The implementation merged as squash commit
``c26af32fcb638489217f4cb43845eca7b2824516``. The post-merge closure lane
generated the authoritative goldens against exactly that commit and committed
them under ``golden/``. This module reads those committed bytes and proves:

 1. all six reports carry exactly the implementation merge commit;
 2. ``expectations.json`` carries the same exact commit;
 3. regeneration into a temporary directory is byte-identical to ``golden/``;
 4. every generated file's sha256 matches ``golden-digest-manifest.json``;
 5. all six reports validate against the v0.2 report contract;
 6. the five declared values survive into the goldens unchanged;
 7. genuine absence renders ``not_declared``;
 8. a malformed present origin fails and never yields a ``not_declared`` report;
 9. all eight Boolean verdicts are unchanged across all six goldens;
10. ``chain_status`` is unchanged and is not a ninth verdict;
11. v0.1/v0.2 pass/fail parity is exact on the golden receipts;
12. the golden receipt inputs are byte-identical to ``input-fixtures/``.

Closure changes no verifier behavior, so the frozen v0.1 digests, the two
envelope schema pins, and the no-emitter-import rule keep their existing gate in
``tests/test_dagr_srs_report_contract_v0_2.py``; the two schema pins are
restated here because closure would be worthless if a pin had moved underneath
it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from arcs_verify import dagr_report as dr
from arcs_verify import dagr_report_v0_2 as dr2
from arcs_verify import subject_ref_origin as sro
from arcs_verify.subject_ref_origin import MalformedSubjectRefOrigin
from arcs_verify.verifier import MCP_PROFILE, verify_receipt

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "tools" / "generate_dagr_report_v0_2_goldens.py"

V0_2_ROOT = dr2._CONTRACT_ROOT
GOLDEN = V0_2_ROOT / "golden"
INPUTS = V0_2_ROOT / "input-fixtures"
MANIFEST_PATH = V0_2_ROOT / "golden-digest-manifest.json"

SCHEMA_V0_2_1 = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.1.schema.json"

#: The exact implementation squash-merge commit. Every authoritative report and
#: ``expectations.json`` carries this value and no other.
IMPLEMENTATION_MERGE_COMMIT = "c26af32fcb638489217f4cb43845eca7b2824516"

#: Restated pins. Closure is a no-behavior lane; if either had moved, the
#: goldens would be pinning a different verifier.
S1_SCHEMA_V0_2_1_SHA256 = (
    "2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"
)
RETAINED_SCHEMA_V0_2_0_SHA256 = (
    "d03aad1d5517e2acb65d5c866905aed7219bcbbfadd1a4a97eac546dd23f0333"
)

STATES = list(sro.DECLARED_ORIGINS) + [sro.NOT_DECLARED]
SLUGS = {state: state.replace("_", "-") for state in STATES}

RECEIPT_INPUT_NAMES = [f"origin-{SLUGS[state]}-receipt.json" for state in STATES] + [
    "trust-bundle.json"
]


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digests(directory: Path) -> dict[str, str]:
    return {
        path.name: _sha256(path)
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_dagr_report_v0_2_goldens", GENERATOR_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _load_generator()

MANIFEST = _load(MANIFEST_PATH)
EXPECTATIONS = _load(GOLDEN / "expectations.json")
TRUST_BUNDLE = _load(GOLDEN / "trust-bundle.json")


def _golden_receipt(state: str) -> dict:
    return _load(GOLDEN / f"origin-{SLUGS[state]}-receipt.json")


def _golden_report(state: str) -> dict:
    return _load(GOLDEN / f"origin-{SLUGS[state]}-report.json")


def _entry(state: str) -> dict:
    declared = None if state == sro.NOT_DECLARED else state
    matches = [
        item
        for item in EXPECTATIONS["entries"]
        if item["declared_subject_ref_origin"] == declared
    ]
    assert len(matches) == 1, state
    return matches[0]


# ---------------------------------------------------------------------------
# Proofs 1 and 2: the execution-identity claim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", STATES)
def test_every_golden_report_carries_the_implementation_merge_commit(
    state: str,
) -> None:
    assert _golden_report(state)["verifier_commit"] == IMPLEMENTATION_MERGE_COMMIT


def test_exactly_six_golden_reports_exist() -> None:
    assert sorted(path.name for path in GOLDEN.glob("*-report.json")) == sorted(
        f"origin-{SLUGS[state]}-report.json" for state in STATES
    )


def test_expectations_carries_the_implementation_merge_commit() -> None:
    assert EXPECTATIONS["verifier_commit"] == IMPLEMENTATION_MERGE_COMMIT
    assert EXPECTATIONS["contract"] == dr2.REPORT_CONTRACT_ID


def test_no_other_verifier_commit_appears_in_the_golden_surface() -> None:
    claimed = set()
    for path in sorted(GOLDEN.iterdir()):
        payload = _load(path)
        if isinstance(payload, dict) and "verifier_commit" in payload:
            claimed.add(payload["verifier_commit"])
    assert claimed == {IMPLEMENTATION_MERGE_COMMIT}


# ---------------------------------------------------------------------------
# Proof 3: regeneration drift
# ---------------------------------------------------------------------------


def test_regeneration_is_byte_identical_to_the_committed_goldens(tmp_path) -> None:
    out = tmp_path / "regenerated"
    GEN.generate(
        verifier_commit=IMPLEMENTATION_MERGE_COMMIT, output_dir=out
    )

    committed = _tree_digests(GOLDEN)
    assert _tree_digests(out) == committed
    # 6 receipts + 6 reports + trust bundle + expectations.
    assert len(committed) == 14

    for name in committed:
        assert (out / name).read_bytes() == (GOLDEN / name).read_bytes(), name


# ---------------------------------------------------------------------------
# Proof 4: the digest manifest
# ---------------------------------------------------------------------------


def test_manifest_pins_every_generated_file_and_nothing_else() -> None:
    on_disk = {f"golden/{name}" for name in _tree_digests(GOLDEN)}
    assert set(MANIFEST["files"]) == on_disk
    assert MANIFEST["file_count"] == len(on_disk) == 14
    assert MANIFEST["digest_algorithm"] == "sha256"


def test_every_generated_file_matches_its_pinned_digest() -> None:
    for relative, digest in sorted(MANIFEST["files"].items()):
        path = V0_2_ROOT / relative
        assert _sha256(path) == digest, relative


def test_manifest_records_the_implementation_merge_commit() -> None:
    assert MANIFEST["implementation_merge_commit"] == IMPLEMENTATION_MERGE_COMMIT
    assert MANIFEST["verifier_commit"] == IMPLEMENTATION_MERGE_COMMIT
    assert MANIFEST["report_contract_id"] == dr2.REPORT_CONTRACT_ID
    assert MANIFEST["generator"] == "tools/generate_dagr_report_v0_2_goldens.py"
    assert f"--verifier-commit {IMPLEMENTATION_MERGE_COMMIT}" in (
        MANIFEST["generator_command"]
    )
    assert set(MANIFEST["verifier_commit_carrying_files"]) == {
        "golden/expectations.json"
    } | {f"golden/origin-{SLUGS[state]}-report.json" for state in STATES}


# ---------------------------------------------------------------------------
# Proof 5: the goldens validate against their own contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", STATES)
def test_golden_report_validates_against_the_v0_2_contract(state: str) -> None:
    assert dr2.validate_verification_report(_golden_report(state)) == []


@pytest.mark.parametrize("state", STATES)
def test_golden_report_rebuilds_byte_identical_from_its_receipt(state: str) -> None:
    receipt = _golden_receipt(state)
    verification = verify_receipt(
        receipt,
        TRUST_BUNDLE,
        schema_path=SCHEMA_V0_2_1,
        selected_profile=MCP_PROFILE,
    )
    rebuilt = dr2.build_verification_report(
        receipt,
        verification,
        selected_profile=MCP_PROFILE,
        trust_bundle=TRUST_BUNDLE,
        verifier_commit=IMPLEMENTATION_MERGE_COMMIT,
        envelope_schema_sha256=_sha256(SCHEMA_V0_2_1),
    )
    assert rebuilt == _golden_report(state)


# ---------------------------------------------------------------------------
# Proofs 6 and 7: the disclosure the goldens carry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("declared", sorted(sro.DECLARED_ORIGINS))
def test_each_declared_value_survives_into_the_golden_unchanged(
    declared: str,
) -> None:
    receipt = _golden_receipt(declared)
    assert receipt["subject_ref_origin"] == declared
    report = _golden_report(declared)
    assert report[dr2.ORIGIN_DISCLOSURE_FIELD] == declared
    assert _entry(declared)["subject_ref_origin_disclosed"] == declared


def test_golden_genuine_absence_renders_not_declared() -> None:
    receipt = _golden_receipt(sro.NOT_DECLARED)
    assert "subject_ref_origin" not in receipt
    report = _golden_report(sro.NOT_DECLARED)
    assert report[dr2.ORIGIN_DISCLOSURE_FIELD] == sro.NOT_DECLARED
    assert _entry(sro.NOT_DECLARED)["subject_ref_origin_disclosed"] == (
        sro.NOT_DECLARED
    )


def test_the_six_goldens_disclose_six_distinct_origins_from_one_subject_ref() -> None:
    subject_refs = {_golden_receipt(state)["subject_ref"] for state in STATES}
    assert len(subject_refs) == 1
    assert {
        _golden_report(state)[dr2.ORIGIN_DISCLOSURE_FIELD] for state in STATES
    } == set(STATES)


# ---------------------------------------------------------------------------
# Proof 8: a malformed present value never becomes a golden-shaped report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param(None, id="present_null"),
        pytest.param("", id="empty_string"),
        pytest.param("supplied", id="truncated_token"),
        pytest.param("SUPPLIED_SUBJECT", id="uppercase_token"),
        pytest.param("not_declared", id="report_rendering_as_receipt_value"),
        pytest.param(["supplied_subject"], id="non_string_type"),
    ],
)
def test_malformed_present_origin_fails_and_yields_no_report(malformed) -> None:
    receipt = _golden_receipt(sro.NOT_DECLARED)
    receipt["subject_ref_origin"] = malformed

    verification = verify_receipt(
        receipt,
        TRUST_BUNDLE,
        schema_path=SCHEMA_V0_2_1,
        selected_profile=MCP_PROFILE,
    )
    with pytest.raises(MalformedSubjectRefOrigin):
        dr2.build_verification_report(
            receipt,
            verification,
            selected_profile=MCP_PROFILE,
            trust_bundle=TRUST_BUNDLE,
            verifier_commit=IMPLEMENTATION_MERGE_COMMIT,
            envelope_schema_sha256=_sha256(SCHEMA_V0_2_1),
        )


# ---------------------------------------------------------------------------
# Proofs 9 and 10: verdicts and chain_status are untouched by closure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", STATES)
def test_golden_verdicts_are_the_same_eight_booleans(state: str) -> None:
    verdicts = _golden_report(state)["verdicts"]
    assert set(verdicts) == set(dr.VERDICT_FIELDS)
    assert len(verdicts) == 8
    assert all(value is True for value in verdicts.values())
    assert verdicts == _entry(state)["verdicts"]


def test_no_golden_origin_value_moves_any_verdict() -> None:
    assert len({json.dumps(_golden_report(s)["verdicts"], sort_keys=True) for s in STATES}) == 1


@pytest.mark.parametrize("state", STATES)
def test_golden_chain_status_is_unchanged_and_not_a_ninth_verdict(state: str) -> None:
    report = _golden_report(state)
    assert report["chain_status"] == "not_applicable"
    assert "chain_status" not in report["verdicts"]
    assert dr2.ORIGIN_DISCLOSURE_FIELD not in report["verdicts"]
    assert _entry(state)["chain_status"] == "not_applicable"


# ---------------------------------------------------------------------------
# Proof 11: v0.1 / v0.2 parity on the golden receipts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", STATES)
def test_v0_1_and_v0_2_agree_on_everything_but_the_disclosure(state: str) -> None:
    receipt = _golden_receipt(state)
    verification = verify_receipt(
        receipt,
        TRUST_BUNDLE,
        schema_path=SCHEMA_V0_2_1,
        selected_profile=MCP_PROFILE,
    )
    v0_1 = dr.build_verification_report(
        receipt,
        verification,
        selected_profile=MCP_PROFILE,
        trust_bundle=TRUST_BUNDLE,
        verifier_commit=IMPLEMENTATION_MERGE_COMMIT,
        envelope_schema_sha256=_sha256(SCHEMA_V0_2_1),
    )
    v0_2 = _golden_report(state)

    assert verification.passed is True
    assert v0_1["verdicts"] == v0_2["verdicts"]
    assert v0_1["chain_status"] == v0_2["chain_status"]

    differing = {
        key for key in set(v0_1) | set(v0_2) if v0_1.get(key) != v0_2.get(key)
    }
    assert differing == {
        dr2.ORIGIN_DISCLOSURE_FIELD,
        "report_version",
        "report_contract_id",
    }


# ---------------------------------------------------------------------------
# Proof 12: closure did not disturb the generator inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", RECEIPT_INPUT_NAMES)
def test_golden_receipt_inputs_match_the_input_fixtures_byte_for_byte(
    name: str,
) -> None:
    assert (GOLDEN / name).read_bytes() == (INPUTS / name).read_bytes()


def test_input_fixtures_gain_no_reports_or_expectations() -> None:
    names = {path.name for path in INPUTS.iterdir()}
    assert not any(name.endswith("-report.json") for name in names)
    assert "expectations.json" not in names


# ---------------------------------------------------------------------------
# Restated pins: closure moved no schema
# ---------------------------------------------------------------------------


def test_schema_pins_are_unmoved_under_closure() -> None:
    assert _sha256(SCHEMA_V0_2_1) == S1_SCHEMA_V0_2_1_SHA256
    assert _sha256(
        ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.0.schema.json"
    ) == RETAINED_SCHEMA_V0_2_0_SHA256

    for state in STATES:
        entry = _entry(state)
        assert entry["envelope_schema_sha256"] == S1_SCHEMA_V0_2_1_SHA256
        assert entry["envelope_schema_version"] == "v0.2.1"
