"""Package integrity and provenance for the stranger0 acceptance package.

These tests need no receiver process. They check that the catalog is coherent,
that every committed byte string is accounted for, and that every derived
hostile receipt really is its pinned source plus exactly the recorded edits.
The signer that produced the re-signed variants is deliberately not in this
repository, so provenance is replayed here WITHOUT signing: apply the recorded
edits to the pinned source and compare everything except the signature value.
"""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from stranger0_support import CASES, PINNED, REPO, S0, load_script

orchestrator = load_script("stranger0_orchestrator_for_package_tests", S0 / "run_stranger0.py")
catalog = json.loads((CASES / "cases.json").read_text())
artifacts_doc = json.loads((CASES / "artifacts.json").read_text())
artifacts = artifacts_doc["artifacts"]
manifest = json.loads((PINNED / "manifest.json").read_text())
pinned_digest = {e["path"]: e["receipt_file_sha256"] for e in manifest["entries"]}

# The families the lane brief requires, written out here on purpose.
REQUIRED_FAMILIES = {
    "body_tamper_after_signing",
    "wrong_key",
    "self_trust_embedded_key",
    "unknown_version_profile",
    "chain_link",
    "duplicate_replay",
    "refused_deferred_honesty",
    "metadata_only_violation",
    "valid_but_declined",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resolve(ref: str):
    return orchestrator.resolve(catalog, ref)


def by_id():
    return {c["case_id"]: c for c in catalog["cases"]}


# ----------------------------------------------------------------------------- catalog coherence
def test_case_ids_are_unique_and_roles_known():
    ids = [c["case_id"] for c in catalog["cases"]]
    assert len(ids) == len(set(ids))
    assert {c["role"] for c in catalog["cases"]} == {"control", "counterfactual_control", "negative"}


def test_every_referenced_file_exists_and_expectations_cover_every_receipt():
    for case in catalog["cases"]:
        assert resolve(case["trust_input"]).is_file(), case["case_id"]
        assert len(case["expect"]) == len(case["receipts"]), case["case_id"]
        for ref in case["receipts"]:
            assert resolve(ref).is_file(), (case["case_id"], ref)


def test_required_hostile_families_are_all_present_with_negatives():
    present = {c["family"] for c in catalog["cases"] if c["role"] == "negative"}
    assert REQUIRED_FAMILIES <= present, REQUIRED_FAMILIES - present


def test_every_negative_has_a_positive_control_that_relies_on_every_receipt():
    cases = by_id()
    for case in catalog["cases"]:
        if case["role"] != "negative":
            continue
        assert case.get("controls"), f"{case['case_id']} has no positive control"
        for control_id in case["controls"]:
            control = cases[control_id]
            assert control["role"] in {"control", "counterfactual_control"}
            assert all(e["decision"] == "rely" and e["verifier_passed"] is True for e in control["expect"]), control_id
        # an isolation claim is made for each control and is checked against the real inputs
        assert {i["control"] for i in case["isolation"]} == set(case["controls"]), case["case_id"]


def test_isolation_claims_match_the_actual_inputs():
    cases = by_id()
    for case in catalog["cases"]:
        for claim in case.get("isolation", []):
            control = cases[claim["control"]]
            same_bytes = [sha(resolve(r).read_bytes()) for r in case["receipts"]] == [sha(resolve(r).read_bytes()) for r in control["receipts"]]
            same_trust = sha(resolve(case["trust_input"]).read_bytes()) == sha(resolve(control["trust_input"]).read_bytes())
            assert same_bytes == claim["same_receipt_bytes"], (case["case_id"], claim)
            assert same_trust == claim["same_trust_input"], (case["case_id"], claim)


def test_every_negative_expects_a_non_rely_decision_for_the_hostile_receipt():
    for case in catalog["cases"]:
        if case["role"] == "negative":
            assert any(e["decision"] != "rely" for e in case["expect"]), case["case_id"]


def test_every_expected_do_not_rely_names_a_reason_token_and_every_verifier_failure_names_a_code():
    for case in catalog["cases"]:
        for e in case["expect"]:
            if e["decision"] != "rely":
                assert e["reason_tokens"], case["case_id"]
            if e["verifier_passed"] is False:
                assert e["failed_checks"] and e["verifier_failure_codes"], case["case_id"]


# ----------------------------------------------------------------------------- byte accounting
def test_artifact_digests_match_files_and_no_stray_files():
    for name, meta in artifacts.items():
        assert sha((S0 / name).read_bytes()) == meta["sha256"], name
    on_disk = {p.relative_to(S0).as_posix() for sub in ("receipts", "trust") for p in (CASES / sub).glob("*.json")}
    assert on_disk == set(artifacts), on_disk ^ set(artifacts)


def test_pinned_originals_still_match_their_pinned_manifest():
    for entry in manifest["entries"]:
        assert sha((PINNED / entry["path"]).read_bytes()) == entry["receipt_file_sha256"], entry["path"]


def test_catalog_uses_pinned_originals_in_place_and_never_a_copy():
    used = {ref for c in catalog["cases"] for ref in c["receipts"] if ref.startswith("pinned:")}
    assert used
    for ref in used:
        assert resolve(ref).is_relative_to(PINNED)
    assert not list(CASES.rglob("admission-admitted.json"))


# ----------------------------------------------------------------------------- provenance replay (no signer needed)
def apply_edits(doc, edits):
    out = copy.deepcopy(doc)
    for edit in edits:
        node = out
        for key in edit["path"][:-1]:
            node = node[key]
        if edit["op"] == "set":
            node[edit["path"][-1]] = edit["value"]
        elif edit["op"] == "delete":
            del node[edit["path"][-1]]
        else:  # pragma: no cover
            raise AssertionError(edit)
    return out


def without_signature(doc):
    doc = copy.deepcopy(doc)
    doc["receipt_signature"]["signature"] = None
    return doc


DERIVED = {name: meta for name, meta in artifacts.items() if meta["kind"] == "derived_from_pinned_receipt"}


def test_there_are_derived_artifacts():
    assert len(DERIVED) >= 13


@pytest.mark.parametrize("name", sorted(DERIVED))
def test_derived_receipt_is_its_pinned_source_plus_exactly_the_recorded_edits(name):
    meta = DERIVED[name]
    source_path = REPO / meta["source"]
    source_rel = source_path.relative_to(PINNED).as_posix()
    assert meta["source_sha256"] == pinned_digest[source_rel] == sha(source_path.read_bytes())
    source = json.loads(source_path.read_text())
    derived = json.loads((S0 / name).read_text())
    expected = apply_edits(source, meta["edits"])
    if meta["resigned_with"] is None:
        # tamper-after-signing: the signature must be the source's own, untouched
        assert derived == expected
        assert derived["receipt_signature"]["signature"] == source["receipt_signature"]["signature"]
    else:
        assert without_signature(derived) == without_signature(expected)
        assert derived["receipt_signature"]["signature"] != source["receipt_signature"]["signature"]
        assert len(meta["resigned_with"]["public_key"]) == 43   # raw Ed25519 public key, base64url without padding


@pytest.mark.parametrize("name", sorted(DERIVED))
def test_every_edit_changes_something(name):
    source = json.loads((REPO / DERIVED[name]["source"]).read_text())
    assert apply_edits(source, DERIVED[name]["edits"]) != source


def test_tamper_case_changes_exactly_one_field_and_keeps_the_signature():
    meta = DERIVED["cases/receipts/n-tamper-refused-to-admitted.json"]
    assert meta["edits"] == [{"op": "set", "path": ["disposition"], "value": "admitted"}]
    assert meta["resigned_with"] is None


# ----------------------------------------------------------------------------- trust inputs
TRUST_FILES = sorted((CASES / "trust").glob("*.json"))


def test_default_trust_input_holds_the_pinned_issuer_entry_verbatim():
    pinned_keyring = json.loads((PINNED / "trust" / "issuer-keys.json").read_text())
    default = json.loads((CASES / "trust" / "receiver-default.json").read_text())
    assert default["keyring"]["issuers"][0] == pinned_keyring["issuers"][0]
    assert default["keyring"]["trust_bundle_version"] == pinned_keyring["trust_bundle_version"]


@pytest.mark.parametrize("path", TRUST_FILES, ids=lambda p: p.name)
def test_trust_inputs_carry_public_keys_only(path):
    doc = json.loads(path.read_text())
    for entry in doc["keyring"]["issuers"]:
        assert set(entry) == {"algorithm", "issuer_id", "key_id", "not_after", "not_before", "public_key", "trusted"}


def test_counterfactual_trust_input_differs_from_default_only_by_the_added_key():
    default = json.loads((CASES / "trust" / "receiver-default.json").read_text())
    cf = json.loads((CASES / "trust" / "receiver-counterfactual-selftrust.json").read_text())
    assert cf["keyring"]["issuers"][:2] == default["keyring"]["issuers"]
    assert len(cf["keyring"]["issuers"]) == 3
    assert {k: v for k, v in cf.items() if k != "keyring"} == {k: v for k, v in default.items() if k != "keyring"}


def test_the_self_claimed_key_is_not_in_any_non_counterfactual_trust_input():
    receipt = json.loads((CASES / "receipts" / "s0-selfclaimed-key.json").read_text())
    claimed = receipt["extensions"]["stranger0_claimed_issuer_key"]["public_key"]
    holders = [p.name for p in TRUST_FILES if claimed in p.read_text()]
    assert holders == ["receiver-counterfactual-selftrust.json"]


# ----------------------------------------------------------------------------- package sums
def test_package_sums_are_current():
    assert orchestrator.check_package_sums() == []
