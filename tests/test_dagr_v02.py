"""
Tests for arcs_verify.dagr_v02 — DAGR-INDEPENDENT-VERIFY0 (Lane 03).

All fixtures are well-formed DAGR v0.2 receipts — exactly the eleven fields
defined by dagr-spec Lane 02 (DAGR-RECEIPT-SCHEMA0). No invented fields
(vocabulary, state, decision_ref.state) are present.

Reference receipt_digest value sourced from the Lane 02 conformance vector
"valid-action-receipt" at dagr-spec eac1ac7:
  sha256:29a7043f18e311f04f0a0548ecc092a7c3a41f1854aa54e62d4e2aa39e5a5c43

Coverage:
  TC-01  Valid action-domain receipt → all five findings True
  TC-02  Valid evidence-domain receipt → all five findings True
  TC-03  Wrong schema fails schema_matches; other independent findings unaffected
  TC-04  Unknown domain fails domain_qualified
  TC-05  decision_ref.domain != receipt.domain fails decision_domain_matches
         even when receipt_digest is correctly recomputed over the mismatched payload
  TC-06  Uppercase digest prefix fails digest_algorithm_valid
  TC-07  Digest too short fails digest_algorithm_valid
  TC-08  Field mutation without digest recomputation fails receipt_digest_match
  TC-09  Attacker recomputes digest → receipt structurally valid; not authenticated
  TC-10  Cross-domain redigest → both receipts valid; digests differ
  TC-11  Non-dict input → all five findings False (no crash)
  TC-12  Extra top-level fields not needed for PASS; real receipts lack them
  TC-13  Trailing newline in digest rejected by fullmatch guard
"""

import copy
import hashlib

import pytest

from arcs_verify.dagr_v02 import verify_dagr_receipt, RECEIPT_SCHEMA_V01


# ── fixture builder ───────────────────────────────────────────────────────────

def _d(char: str) -> str:
    return "sha256:" + char * 64


def _compute_receipt_digest(receipt: dict) -> str:
    """
    Recompute receipt_digest locally for fixture construction.
    Mirrors the preimage spec exactly; does NOT import verifier internals.
    """
    dr = receipt["decision_ref"]
    cr = receipt["contract_ref"]
    lines = [
        "DAGR-RECEIPT-V0.1",
        f"schema={receipt['schema']}",
        f"receipt_id={receipt['receipt_id']}",
        f"domain={receipt['domain']}",
        f"producer_id={receipt['producer_id']}",
        f"producer_version={receipt['producer_version']}",
        f"issued_at={receipt['issued_at']}",
        f"subject_digest={receipt['subject_digest']}",
        f"input_digest={receipt['input_digest']}",
        f"decision_domain={dr['domain']}",
        f"decision_vocabulary={dr['vocabulary']}",
        f"decision_digest={dr['digest']}",
        f"contract_id={cr['contract_id']}",
        f"contract_digest={cr['digest']}",
    ]
    return "sha256:" + hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def _action_receipt() -> dict:
    r = {
        "schema": "dagr.receipt/v0.1",
        "receipt_id": "rcpt-action-0001",
        "domain": "action",
        "producer_id": "countervail-control-plane",
        "producer_version": "0.1.0",
        "issued_at": "2026-08-20T06:15:00Z",
        "subject_digest": _d("1"),
        "input_digest": _d("2"),
        "decision_ref": {
            "domain": "action",
            "vocabulary": "dagr.action-decision/v0.1",
            "digest": _d("3"),
        },
        "contract_ref": {
            "contract_id": "countervail.fsi.mnpi.v0_1",
            "digest": _d("4"),
        },
    }
    r["receipt_digest"] = _compute_receipt_digest(r)
    return r


def _evidence_receipt() -> dict:
    r = {
        "schema": "dagr.receipt/v0.1",
        "receipt_id": "rcpt-evidence-0001",
        "domain": "evidence",
        "producer_id": "counterpedia-ingest",
        "producer_version": "0.2.0",
        "issued_at": "2026-08-20T09:00:00Z",
        "subject_digest": _d("a"),
        "input_digest": _d("b"),
        "decision_ref": {
            "domain": "evidence",
            "vocabulary": "counterpedia.evidence-decision/v0.1",
            "digest": _d("c"),
        },
        "contract_ref": {
            "contract_id": "counterpedia.evidence.v0_1",
            "digest": _d("d"),
        },
    }
    r["receipt_digest"] = _compute_receipt_digest(r)
    return r


# ── TC-01: valid action receipt ───────────────────────────────────────────────

def test_tc01_valid_action_receipt_all_true():
    r = _action_receipt()
    # Pin against Lane 02 conformance vector at dagr-spec eac1ac7
    assert r["receipt_digest"] == "sha256:29a7043f18e311f04f0a0548ecc092a7c3a41f1854aa54e62d4e2aa39e5a5c43"
    result = verify_dagr_receipt(r)
    assert result["schema_matches"] is True
    assert result["domain_qualified"] is True
    assert result["decision_domain_matches"] is True
    assert result["digest_algorithm_valid"] is True
    assert result["receipt_digest_match"] is True


# ── TC-02: valid evidence receipt ─────────────────────────────────────────────

def test_tc02_valid_evidence_receipt_all_true():
    result = verify_dagr_receipt(_evidence_receipt())
    assert result["schema_matches"] is True
    assert result["domain_qualified"] is True
    assert result["decision_domain_matches"] is True
    assert result["digest_algorithm_valid"] is True
    assert result["receipt_digest_match"] is True


# ── TC-03: wrong schema fails schema_matches independently ───────────────────

def test_tc03_wrong_schema_fails_schema_matches():
    r = _action_receipt()
    r["schema"] = "dagr.state-ref/v0.2"
    r["receipt_digest"] = _compute_receipt_digest(r)
    result = verify_dagr_receipt(r)
    assert result["schema_matches"] is False
    assert result["receipt_digest_match"] is True  # digest independently valid


def test_tc03b_schema_must_match_exact_const():
    assert RECEIPT_SCHEMA_V01 == "dagr.receipt/v0.1"
    r = _action_receipt()
    r["schema"] = "dagr.receipt/v0.2"  # future version — not this lane
    r["receipt_digest"] = _compute_receipt_digest(r)
    result = verify_dagr_receipt(r)
    assert result["schema_matches"] is False


# ── TC-04: unknown domain ─────────────────────────────────────────────────────

def test_tc04_unknown_domain_fails_domain_qualified():
    r = _action_receipt()
    r["domain"] = "belief"
    r["decision_ref"]["domain"] = "belief"
    r["receipt_digest"] = _compute_receipt_digest(r)
    result = verify_dagr_receipt(r)
    assert result["domain_qualified"] is False
    assert result["schema_matches"] is True


# ── TC-05: decision domain mismatch ──────────────────────────────────────────

def test_tc05_decision_domain_mismatch_fails_even_with_valid_digest():
    """
    receipt.domain=action, decision_ref.domain=memory.
    Digest correctly recomputed over the mismatched payload — digest valid,
    domain alignment still fails independently.
    """
    r = _action_receipt()
    r["decision_ref"] = dict(r["decision_ref"])
    r["decision_ref"]["domain"] = "memory"
    r["decision_ref"]["vocabulary"] = "amnesiac.memory-decision/v0.1"
    r["receipt_digest"] = _compute_receipt_digest(r)
    result = verify_dagr_receipt(r)
    assert result["decision_domain_matches"] is False
    assert result["receipt_digest_match"] is True
    assert result["domain_qualified"] is True


# ── TC-06: uppercase digest prefix ───────────────────────────────────────────

def test_tc06_uppercase_digest_prefix_fails():
    r = _action_receipt()
    r["input_digest"] = "SHA256:" + "2" * 64
    result = verify_dagr_receipt(r)
    assert result["digest_algorithm_valid"] is False


# ── TC-07: digest too short ───────────────────────────────────────────────────

def test_tc07_short_digest_fails():
    r = _action_receipt()
    r["subject_digest"] = "sha256:" + "1" * 63  # one char short
    result = verify_dagr_receipt(r)
    assert result["digest_algorithm_valid"] is False


# ── TC-08: field mutation without recomputation ───────────────────────────────

@pytest.mark.parametrize("field,new_value", [
    ("producer_id", "attacker.example"),
    ("producer_version", "9.9.9"),
    ("issued_at", "2026-08-20T06:16:00Z"),
    ("subject_digest", _d("e")),
    ("input_digest", _d("f")),
])
def test_tc08_top_level_mutation_without_redigest_fails(field, new_value):
    r = _action_receipt()
    r[field] = new_value
    result = verify_dagr_receipt(r)
    assert result["receipt_digest_match"] is False


def test_tc08b_decision_ref_digest_mutation_fails():
    r = _action_receipt()
    r["decision_ref"] = dict(r["decision_ref"])
    r["decision_ref"]["digest"] = _d("9")
    result = verify_dagr_receipt(r)
    assert result["receipt_digest_match"] is False


def test_tc08c_contract_ref_digest_mutation_fails():
    r = _action_receipt()
    r["contract_ref"] = dict(r["contract_ref"])
    r["contract_ref"]["digest"] = _d("8")
    result = verify_dagr_receipt(r)
    assert result["receipt_digest_match"] is False


def test_tc08d_contract_id_mutation_fails():
    r = _action_receipt()
    r["contract_ref"] = dict(r["contract_ref"])
    r["contract_ref"]["contract_id"] = "tampered.contract.v0_1"
    result = verify_dagr_receipt(r)
    assert result["receipt_digest_match"] is False


# ── TC-09: attacker recomputes digest ────────────────────────────────────────

def test_tc09_attacker_recomputed_receipt_structurally_valid_not_authenticated():
    """
    Attacker changes producer_id and correctly recomputes receipt_digest.
    receipt_digest_match=True. This does NOT establish producer authentication.
    """
    r = _action_receipt()
    r["producer_id"] = "attacker.example"
    r["receipt_digest"] = _compute_receipt_digest(r)
    result = verify_dagr_receipt(r)
    assert result["schema_matches"] is True
    assert result["domain_qualified"] is True
    assert result["receipt_digest_match"] is True
    # Document what is NOT established by the five findings:
    non_conferred = {"producer_authentication", "truth", "authorization", "trusted_time"}
    assert len(non_conferred) == 4


# ── TC-10: cross-domain redigest ──────────────────────────────────────────────

def test_tc10_cross_domain_redigest_is_new_receipt_not_equivalence():
    action = _action_receipt()
    memory = copy.deepcopy(action)
    memory["domain"] = "memory"
    memory["decision_ref"]["domain"] = "memory"
    memory["decision_ref"]["vocabulary"] = "amnesiac.memory-decision/v0.1"
    memory["receipt_digest"] = _compute_receipt_digest(memory)

    r_action = verify_dagr_receipt(action)
    r_memory = verify_dagr_receipt(memory)

    assert r_action["receipt_digest_match"] is True
    assert r_memory["receipt_digest_match"] is True
    assert r_action["domain_qualified"] is True
    assert r_memory["domain_qualified"] is True
    assert action["receipt_digest"] != memory["receipt_digest"]
    assert action["domain"] != memory["domain"]


# ── TC-11: non-dict input ─────────────────────────────────────────────────────

@pytest.mark.parametrize("bad_input", [None, "string", 42, [], True])
def test_tc11_non_dict_input_all_false_no_crash(bad_input):
    result = verify_dagr_receipt(bad_input)
    assert result["schema_matches"] is False
    assert result["domain_qualified"] is False
    assert result["decision_domain_matches"] is False
    assert result["digest_algorithm_valid"] is False
    assert result["receipt_digest_match"] is False


# ── TC-12: real Lane 02 receipts have no invented fields ─────────────────────

def test_tc12_real_lane02_receipt_has_no_top_level_vocabulary_or_state():
    r = _action_receipt()
    assert "vocabulary" not in r
    assert "state" not in r
    assert "state" not in r["decision_ref"]
    result = verify_dagr_receipt(r)
    # Assert all five boolean findings are True; dagr_constitution_id is a non-boolean
    # metadata field added by L11 and is excluded from the boolean sweep.
    _BOOLEAN_FINDING_KEYS = (
        "schema_matches", "domain_qualified", "decision_domain_matches",
        "digest_algorithm_valid", "receipt_digest_match",
    )
    assert all(result[k] is True for k in _BOOLEAN_FINDING_KEYS)


# ── TC-13: trailing newline in digest rejected by fullmatch ───────────────────

def test_tc13_digest_with_trailing_newline_fails():
    r = _action_receipt()
    r["input_digest"] = "sha256:" + "2" * 64 + "\n"
    result = verify_dagr_receipt(r)
    assert result["digest_algorithm_valid"] is False
