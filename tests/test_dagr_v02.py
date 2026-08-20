"""
Tests for arcs_verify.dagr_v02 — DAGR-INDEPENDENT-VERIFY0 (Lane 03).

Coverage:
  TC-01  Valid evidence-domain receipt → all applicable findings True; action_vocabulary_closed None
  TC-02  decision_ref.domain != receipt.domain → decision_domain_aligned False
  TC-03  Wrong receipt_digest → receipt_digest_match False
  TC-04  Action-domain receipt → action_vocabulary_closed is None (not_evaluated for all domains)
  TC-05  Missing domain field → domain_qualified False
  TC-06  Cross-domain name-collision: same vocabulary token, different domains → both valid (NEQ)
  TC-07  vocabulary_declared: valid decision_ref.vocabulary patterns accepted
  TC-08  None is not PASS
  TC-09  vocabulary_declared: invalid decision_ref.vocabulary patterns rejected
  TC-10  schema_valid: wrong schema string → schema_valid False
  TC-11  schema_valid: correct schema string → schema_valid True

not_evaluated is never a valid return value.
None is not PASS — callers must check `is True`, not truthiness.
"""

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
    """
    Minimal valid evidence-domain receipt conforming to the Lane-02 spec.
    No top-level vocabulary or state fields. decision_ref has no state field.
    """
    r = {
        "schema": "dagr.receipt/v0.1",
        "receipt_id": "rec-001",
        "domain": "evidence",
        "producer_id": "test-producer",
        "producer_version": "0.1.0",
        "issued_at": "2026-08-20T00:00:00Z",
        "subject_digest": _make_digest("a"),
        "input_digest": _make_digest("b"),
        "decision_ref": {
            "domain": "evidence",
            "vocabulary": "evidence/v0.1",
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
    """
    Minimal valid action-domain receipt conforming to the Lane-02 spec.
    No top-level vocabulary or state fields. decision_ref has no state field.
    The decision record's actual state is opaque — only its digest is carried.
    """
    r = {
        "schema": "dagr.receipt/v0.1",
        "receipt_id": "rec-action-001",
        "domain": "action",
        "producer_id": "test-producer",
        "producer_version": "0.1.0",
        "issued_at": "2026-08-20T00:00:00Z",
        "subject_digest": _make_digest("a"),
        "input_digest": _make_digest("b"),
        "decision_ref": {
            "domain": "action",
            "vocabulary": "action/v0.1",
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

    assert result["schema_valid"] is True
    assert result["domain_qualified"] is True
    assert result["vocabulary_declared"] is True
    assert result["decision_domain_aligned"] is True
    # evidence domain → action_vocabulary_closed is None (not_evaluated — membership opaque)
    assert result["action_vocabulary_closed"] is None, (
        "None expected for all domains; None is NOT PASS"
    )
    assert result["digests_well_formed"] is True
    assert result["receipt_digest_match"] is True


# ── TC-02: decision_ref.domain != receipt.domain ──────────────────────────────

def test_tc02_decision_domain_mismatch():
    receipt = _base_evidence_receipt()
    receipt["decision_ref"] = dict(receipt["decision_ref"])
    receipt["decision_ref"]["domain"] = "memory"   # mismatch: receipt.domain=evidence
    # recompute digest so only decision_domain_aligned is False
    receipt["receipt_digest"] = _compute_receipt_digest(receipt)

    result = verify_dagr_receipt(receipt)
    assert result["decision_domain_aligned"] is False
    # other structural checks still pass
    assert result["domain_qualified"] is True
    assert result["schema_valid"] is True


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


# ── TC-04: action-domain receipt → action_vocabulary_closed is None ───────────

def test_tc04_action_domain_vocabulary_closed_not_evaluated():
    """
    Even for the action domain, action_vocabulary_closed must be None
    (not_evaluated). Membership in the decision vocabulary requires the
    decision preimage, which is not present in receipt bytes — only the
    decision_digest is. Do NOT infer membership from decision_ref fields.
    """
    receipt = _base_action_receipt()
    result = verify_dagr_receipt(receipt)

    assert result["action_vocabulary_closed"] is None, (
        "action_vocabulary_closed must be None (not_evaluated) for action domain; "
        "membership is opaque from receipt bytes alone"
    )
    assert result["domain_qualified"] is True
    assert result["schema_valid"] is True


# ── TC-05: missing domain → domain_qualified False ────────────────────────────

def test_tc05_missing_domain_field():
    receipt = _base_evidence_receipt()
    del receipt["domain"]

    result = verify_dagr_receipt(receipt)
    assert result["domain_qualified"] is False
    # decision_domain_aligned also False because domain is absent
    assert result["decision_domain_aligned"] is False


# ── TC-06: cross-domain name-collision ────────────────────────────────────────

def test_tc06_cross_domain_name_collision_both_valid():
    """
    The same vocabulary token ("evidence/v0.1" vs "memory/v0.1") appears in
    both evidence and memory domains. Each receipt is independently valid;
    identity differs by domain. NON-EQUIVALENCE IS NORMATIVE.
    """
    evidence_receipt = _base_evidence_receipt()

    memory_receipt = {
        "schema": "dagr.receipt/v0.1",
        "receipt_id": "rec-memory-001",
        "domain": "memory",
        "producer_id": "test-producer",
        "producer_version": "0.1.0",
        "issued_at": "2026-08-20T00:00:00Z",
        "subject_digest": _make_digest("e"),
        "input_digest": _make_digest("f"),
        "decision_ref": {
            "domain": "memory",
            "vocabulary": "memory/v0.1",   # same pattern structure, different domain
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
    assert ev_result["decision_domain_aligned"] is True
    assert mem_result["decision_domain_aligned"] is True
    assert ev_result["receipt_digest_match"] is True
    assert mem_result["receipt_digest_match"] is True
    assert ev_result["vocabulary_declared"] is True
    assert mem_result["vocabulary_declared"] is True

    # action_vocabulary_closed is None for all non-action (and all action) domains
    assert ev_result["action_vocabulary_closed"] is None
    assert mem_result["action_vocabulary_closed"] is None

    # Receipts are distinct objects — same vocabulary pattern does not conflate identity
    assert evidence_receipt["domain"] != memory_receipt["domain"]
    assert evidence_receipt["receipt_digest"] != memory_receipt["receipt_digest"]


# ── TC-07: vocabulary_declared reads from decision_ref.vocabulary ─────────────

@pytest.mark.parametrize("vocab", [
    "evidence/v0.1",
    "action/v0.1",
    "memory/v1.0",
    "my.vocab-pack/v12.3",
    "x/v0.0",
])
def test_tc07_valid_decision_ref_vocabulary_accepted(vocab: str):
    """
    vocabulary_declared validates decision_ref.vocabulary (not a top-level field).
    Valid patterns must be accepted.
    """
    receipt = _base_evidence_receipt()
    receipt["decision_ref"] = dict(receipt["decision_ref"])
    receipt["decision_ref"]["vocabulary"] = vocab
    receipt["receipt_digest"] = _compute_receipt_digest(receipt)

    result = verify_dagr_receipt(receipt)
    assert result["vocabulary_declared"] is True, (
        f"Expected vocabulary_declared True for valid vocab '{vocab}'"
    )
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
    assert av is None            # not_evaluated for all domains
    assert not (av is True)      # None is NOT PASS
    assert bool(av) is False     # truthiness check would falsely imply failure — caller must use `is True`


# ── TC-09: bad decision_ref.vocabulary pattern → vocabulary_declared False ────

@pytest.mark.parametrize("bad_vocab", [
    "Evidence/v0.1",    # uppercase
    "evidence",          # no version suffix
    "evidence/0.1",     # missing 'v'
    "/v0.1",             # no name part
    "evidence/v",        # no version digits
])
def test_tc09_invalid_decision_ref_vocabulary_patterns(bad_vocab: str):
    """
    vocabulary_declared reads from decision_ref.vocabulary.
    Invalid patterns in that field must be rejected.
    """
    receipt = _base_evidence_receipt()
    receipt["decision_ref"] = dict(receipt["decision_ref"])
    receipt["decision_ref"]["vocabulary"] = bad_vocab
    # receipt_digest will not match after mutation; that is acceptable —
    # vocabulary_declared is independent of receipt_digest_match

    result = verify_dagr_receipt(receipt)
    assert result["vocabulary_declared"] is False, (
        f"Expected vocabulary_declared False for bad vocab '{bad_vocab}'"
    )


# ── TC-10: schema_valid exact-match ──────────────────────────────────────────

@pytest.mark.parametrize("bad_schema", [
    "dagr-receipt/v0.1",   # dash instead of dot
    "dagr.receipt/v0.2",   # wrong version
    "dagr.state-ref/v0.2", # old wrong constant
    "",                     # empty string
    "dagr.receipt/v0.1 ",  # trailing space
    "DAGR.RECEIPT/V0.1",   # uppercase
])
def test_tc10_wrong_schema_rejected(bad_schema: str):
    receipt = _base_evidence_receipt()
    receipt["schema"] = bad_schema
    # do not recompute receipt_digest — schema_valid is independent

    result = verify_dagr_receipt(receipt)
    assert result["schema_valid"] is False, (
        f"Expected schema_valid False for schema '{bad_schema}'"
    )


# ── TC-11: correct schema accepted ───────────────────────────────────────────

def test_tc11_correct_schema_accepted():
    receipt = _base_evidence_receipt()
    assert receipt["schema"] == "dagr.receipt/v0.1"

    result = verify_dagr_receipt(receipt)
    assert result["schema_valid"] is True
