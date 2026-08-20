"""
Tests for arcs_verify.dagr_v02 — DAGR-INDEPENDENT-VERIFY0 (Lane 03).

Coverage:
  TC-01  Valid evidence-domain receipt → all applicable fields True
  TC-02  decision_ref.domain != receipt.domain → decision_domain_matches False
  TC-03  Wrong receipt_digest → receipt_digest_match False
  TC-04  Unknown action token → action_vocabulary_closed False
  TC-05  Missing domain field → domain_qualified False
  TC-06  Cross-domain name-collision: same state token, different domains → both valid

not_evaluated is never a valid return value.
None is not PASS — callers must check `is True`, not truthiness.
"""

import copy
import hashlib

import pytest

from arcs_verify.dagr_v02 import verify_dagr_receipt


# ── fixture builders ──────────────────────────────────────────────────────────

def _make_digest(char: str) -> str:
    return "sha256:" + char * 64


def _compute_receipt_digest(receipt: dict) -> str:
    """
    Recompute receipt_digest from the preimage, mirroring the verifier logic.
    Used only to build test fixtures — NOT imported from the verifier internals.
    """
    decision_ref = receipt["decision_ref"]
    contract_ref = receipt["contract_ref"]
    PREIMAGE_FIELDS = [
        ("schema", receipt["schema"]),
        ("receipt_id", receipt["receipt_id"]),
        ("domain", receipt["domain"]),
        ("producer_id", receipt["producer_id"]),
        ("producer_version", receipt["producer_version"]),
        ("issued_at", receipt["issued_at"]),
        ("subject_digest", receipt["subject_digest"]),
        ("input_digest", receipt["input_digest"]),
        ("decision_domain", decision_ref["domain"]),
        ("decision_vocabulary", decision_ref["vocabulary"]),
        ("decision_digest", decision_ref["digest"]),
        ("contract_id", contract_ref["contract_id"]),
        ("contract_digest", contract_ref["digest"]),
    ]
    lines = ["DAGR-RECEIPT-V0.1"] + [f"{k}={v}" for k, v in PREIMAGE_FIELDS]
    preimage = "\n".join(lines) + "\n"
    return "sha256:" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def _base_evidence_receipt() -> dict:
    r = {
        "schema": "dagr.state-ref/v0.2",
        "receipt_id": "rec-001",
        "domain": "evidence",
        "vocabulary": "evidence/v0.1",
        "state": "ADMITTED",
        "producer_id": "test-producer",
        "producer_version": "0.1.0",
        "issued_at": "2026-08-20T00:00:00Z",
        "subject_digest": _make_digest("a"),
        "input_digest": _make_digest("b"),
        "decision_ref": {
            "domain": "evidence",
            "vocabulary": "evidence/v0.1",
            "state": "ADMITTED",
            "digest": _make_digest("c"),
        },
        "contract_ref": {
            "contract_id": "evidence-contract-v0.1",
            "digest": _make_digest("d"),
        },
    }
    r["receipt_digest"] = _compute_receipt_digest(r)
    return r


def _base_action_receipt() -> dict:
    r = {
        "schema": "dagr.state-ref/v0.2",
        "receipt_id": "rec-action-001",
        "domain": "action",
        "vocabulary": "action/v0.1",
        "state": "Resolved",
        "producer_id": "test-producer",
        "producer_version": "0.1.0",
        "issued_at": "2026-08-20T00:00:00Z",
        "subject_digest": _make_digest("a"),
        "input_digest": _make_digest("b"),
        "decision_ref": {
            "domain": "action",
            "vocabulary": "action/v0.1",
            "state": "permitted",
            "digest": _make_digest("c"),
        },
        "contract_ref": {
            "contract_id": "action-contract-v0.1",
            "digest": _make_digest("d"),
        },
    }
    r["receipt_digest"] = _compute_receipt_digest(r)
    return r


# ── TC-01: valid evidence-domain receipt ─────────────────────────────────────

def test_tc01_valid_evidence_receipt_all_true():
    receipt = _base_evidence_receipt()
    result = verify_dagr_receipt(receipt)

    assert result["schema_present"] is True
    assert result["domain_qualified"] is True
    assert result["vocabulary_valid"] is True
    assert result["state_scoped"] is True
    assert result["decision_domain_matches"] is True
    # evidence domain → action_vocabulary_closed is None (not applicable)
    assert result["action_vocabulary_closed"] is None, (
        "None expected for non-action domain; None is NOT PASS"
    )
    assert result["digest_algorithm_valid"] is True
    assert result["receipt_digest_match"] is True


# ── TC-02: decision_ref.domain != receipt.domain ──────────────────────────────

def test_tc02_decision_domain_mismatch():
    receipt = _base_evidence_receipt()
    receipt["decision_ref"] = dict(receipt["decision_ref"])
    receipt["decision_ref"]["domain"] = "memory"   # mismatch: receipt.domain=evidence
    # recompute digest so only decision_domain_matches is False
    receipt["receipt_digest"] = _compute_receipt_digest(receipt)

    result = verify_dagr_receipt(receipt)
    assert result["decision_domain_matches"] is False
    # other structural checks still pass
    assert result["domain_qualified"] is True
    assert result["schema_present"] is True


# ── TC-03: wrong receipt_digest ───────────────────────────────────────────────

def test_tc03_wrong_receipt_digest():
    receipt = _base_evidence_receipt()
    # Corrupt the digest (last char flipped)
    original = receipt["receipt_digest"]
    last = original[-1]
    flipped = "0" if last != "0" else "1"
    receipt["receipt_digest"] = original[:-1] + flipped

    result = verify_dagr_receipt(receipt)
    assert result["receipt_digest_match"] is False
    # Structural fields still fine
    assert result["domain_qualified"] is True


# ── TC-04: unknown action token ───────────────────────────────────────────────

def test_tc04_unknown_action_token():
    receipt = _base_action_receipt()
    receipt["decision_ref"] = dict(receipt["decision_ref"])
    receipt["decision_ref"]["state"] = "permitted_with_prejudice"  # not in frozen vocab
    receipt["receipt_digest"] = _compute_receipt_digest(receipt)

    result = verify_dagr_receipt(receipt)
    assert result["action_vocabulary_closed"] is False
    # Domain is action, so it must be bool not None
    assert isinstance(result["action_vocabulary_closed"], bool)
    assert result["domain_qualified"] is True


# ── TC-05: missing domain → domain_qualified False ────────────────────────────

def test_tc05_missing_domain_field():
    receipt = _base_evidence_receipt()
    del receipt["domain"]

    result = verify_dagr_receipt(receipt)
    assert result["domain_qualified"] is False
    # decision_domain_matches also False because domain is absent
    assert result["decision_domain_matches"] is False


# ── TC-06: cross-domain name-collision ────────────────────────────────────────

def test_tc06_cross_domain_name_collision_both_valid():
    """
    The same state token ("ADMITTED") appears in both evidence and memory
    domains. Each receipt is independently valid; identity differs by domain.
    NON-EQUIVALENCE IS NORMATIVE.
    """
    evidence_receipt = _base_evidence_receipt()
    # evidence.ADMITTED

    memory_receipt = {
        "schema": "dagr.state-ref/v0.2",
        "receipt_id": "rec-memory-001",
        "domain": "memory",
        "vocabulary": "memory/v0.1",
        "state": "ADMITTED",          # same token, different domain
        "producer_id": "test-producer",
        "producer_version": "0.1.0",
        "issued_at": "2026-08-20T00:00:00Z",
        "subject_digest": _make_digest("e"),
        "input_digest": _make_digest("f"),
        "decision_ref": {
            "domain": "memory",
            "vocabulary": "memory/v0.1",
            "state": "ADMITTED",
            "digest": _make_digest("g"),
        },
        "contract_ref": {
            "contract_id": "memory-contract-v0.1",
            "digest": _make_digest("h"),
        },
    }
    memory_receipt["receipt_digest"] = _compute_receipt_digest(memory_receipt)

    ev_result = verify_dagr_receipt(evidence_receipt)
    mem_result = verify_dagr_receipt(memory_receipt)

    # Both structurally valid
    assert ev_result["domain_qualified"] is True
    assert mem_result["domain_qualified"] is True
    assert ev_result["decision_domain_matches"] is True
    assert mem_result["decision_domain_matches"] is True
    assert ev_result["receipt_digest_match"] is True
    assert mem_result["receipt_digest_match"] is True

    # Neither is action domain → action_vocabulary_closed is None for both
    assert ev_result["action_vocabulary_closed"] is None
    assert mem_result["action_vocabulary_closed"] is None

    # Receipts are distinct objects — same state token does not conflate identity
    assert evidence_receipt["domain"] != memory_receipt["domain"]
    assert evidence_receipt["receipt_digest"] != memory_receipt["receipt_digest"]


# ── TC-07: valid action receipt, all permitted tokens ─────────────────────────

@pytest.mark.parametrize("token", [
    "permitted",
    "permitted_with_constraints",
    "review_required",
    "refused",
])
def test_tc07_all_valid_action_tokens(token: str):
    receipt = _base_action_receipt()
    receipt["decision_ref"] = dict(receipt["decision_ref"])
    receipt["decision_ref"]["state"] = token
    receipt["receipt_digest"] = _compute_receipt_digest(receipt)

    result = verify_dagr_receipt(receipt)
    assert result["action_vocabulary_closed"] is True
    assert result["domain_qualified"] is True
    assert result["receipt_digest_match"] is True


# ── TC-08: None is not PASS ───────────────────────────────────────────────────

def test_tc08_none_is_not_pass():
    """
    Confirm that callers who check truthiness rather than `is True` would be
    misled by None — this test documents the invariant structurally.
    """
    receipt = _base_evidence_receipt()
    result = verify_dagr_receipt(receipt)

    av = result["action_vocabulary_closed"]
    assert av is None            # not applicable for non-action domain
    assert not (av is True)      # None is NOT PASS
    assert bool(av) is False     # truthiness check would falsely imply failure — caller must use `is True`


# ── TC-09: bad vocabulary pattern → vocabulary_valid False ───────────────────

@pytest.mark.parametrize("bad_vocab", [
    "Evidence/v0.1",    # uppercase
    "evidence",          # no version suffix
    "evidence/0.1",     # missing 'v'
    "/v0.1",             # no name part
    "evidence/v",        # no version digits
])
def test_tc09_invalid_vocabulary_patterns(bad_vocab: str):
    receipt = _base_evidence_receipt()
    receipt["vocabulary"] = bad_vocab

    result = verify_dagr_receipt(receipt)
    assert result["vocabulary_valid"] is False


# ── TC-10: bad state token → state_scoped False ───────────────────────────────

@pytest.mark.parametrize("bad_state", [
    "",           # empty
    "0ADMITTED",  # starts with digit
    "-ADMITTED",  # starts with hyphen
])
def test_tc10_invalid_state_patterns(bad_state: str):
    receipt = _base_evidence_receipt()
    receipt["state"] = bad_state
    receipt["receipt_digest"] = _compute_receipt_digest(receipt)

    result = verify_dagr_receipt(receipt)
    assert result["state_scoped"] is False
