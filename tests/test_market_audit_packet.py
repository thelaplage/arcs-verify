"""
tests/test_market_audit_packet.py — MARKET-AUDIT-PACKET0: portable native-ref
audit packet for independent market-transaction replay.

Coverage:
  T01  incomplete packet stays non-authoritative (original contract)
  T02  complete packet with well-formed native refs → complete=True, no malformed
  T03  present-but-malformed ref is reported separately from missing
  T04  authority/truth/admission fields are structurally absent from completeness
  T05  injecting an authority-shaped keyword at construction fails closed (TypeError)
  T06  packet is frozen — attempted mutation raises
  T07  digest is stable under artifact_refs key-order permutation
  T08  digest changes when any ref value changes (tamper-sensitive)
  T09  is_native_ref accepts only well-formed sha256 refs
  T10  independent recomputation from a plain dict matches packet.digest()
  T11  verify_packet_digest: valid self-declared digest → digest_valid=True
  T12  verify_packet_digest: tampered ref after declaration → digest_valid=False
  T13  verify_packet_digest: no declared digest → digest_valid=None (not False)
  T14  non_equivalences present on every audit_completeness result
  T15  independence: no producer/DAGR import in the module
"""

from __future__ import annotations

import sys

import pytest

from arcs_verify.market_audit_packet import (
    REQUIRED,
    MarketAuditPacket,
    audit_completeness,
    is_native_ref,
    recompute_packet_digest,
    ref_format_findings,
    verify_packet_digest,
)


def _ref(label: str) -> str:
    """A syntactically valid native ref derived from a label, for fixtures."""
    import hashlib
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _complete_refs() -> dict[str, str]:
    return {key: _ref(key) for key in REQUIRED}


# ── T01: original contract — incomplete packet stays non-authoritative ───────

def test_incomplete_packet_stays_non_authoritative():
    p = MarketAuditPacket('p1', {'offer': 'o', 'authorization': 'a'}, '2026-08-23T00:00:00Z')
    r = audit_completeness(p)
    assert r['complete'] is False
    assert 'authority_effect' not in r


# ── T02: complete packet with well-formed native refs ─────────────────────────

def test_complete_packet_with_native_refs():
    p = MarketAuditPacket('p2', _complete_refs(), '2026-08-23T00:00:00Z')
    r = audit_completeness(p)
    assert r['complete'] is True
    assert r['missing'] == []
    assert r['malformed_refs'] == []


# ── T03: present-but-malformed ref reported separately from missing ──────────

def test_malformed_ref_reported_separately_from_missing():
    refs = _complete_refs()
    refs['offer'] = 'not-a-native-ref'
    p = MarketAuditPacket('p3', refs, '2026-08-23T00:00:00Z')
    r = audit_completeness(p)
    assert r['complete'] is True  # presence-only
    assert r['missing'] == []
    assert r['malformed_refs'] == ['offer']


# ── T04: authority/truth/admission fields are structurally absent ────────────

def test_completeness_has_no_authority_fields():
    p = MarketAuditPacket('p4', {}, '2026-08-23T00:00:00Z')
    r = audit_completeness(p)
    assert 'authority_effect' not in r
    assert 'truth_effect' not in r
    assert 'admission_effect' not in r


def test_packet_object_has_no_authority_attributes():
    p = MarketAuditPacket('p4b', {}, '2026-08-23T00:00:00Z')
    assert not hasattr(p, 'authority_effect')
    assert not hasattr(p, 'truth_effect')
    assert not hasattr(p, 'admission_effect')


def test_body_and_to_dict_carry_no_authority_fields():
    p = MarketAuditPacket('p4c', _complete_refs(), '2026-08-23T00:00:00Z')
    for key in ('authority_effect', 'truth_effect', 'admission_effect'):
        assert key not in p.body()
        assert key not in p.to_dict()


# ── T05: injecting an authority-shaped keyword fails closed ──────────────────

@pytest.mark.parametrize(
    "field,value",
    [
        ("authority_effect", "none"),
        ("authority_effect", "admitted"),
        ("truth_effect", "none"),
        ("admission_effect", "none"),
        ("trusted", True),
        ("admitted", True),
        ("authorized", True),
        ("standing", "good"),
    ],
)
def test_authority_shaped_injection_fails_closed(field, value):
    """No authority-shaped keyword is a declared field on MarketAuditPacket
    (structural absence per NE-11), so any attempt to inject one at
    construction — whether pinned to "none" or promoted to an admitting
    value — is rejected by the dataclass itself: `TypeError` for an
    undeclared keyword argument. Absence is enforced, not merely defaulted.
    """
    kwargs = {
        "packet_id": "p5",
        "artifact_refs": {},
        "created_at": "2026-08-23T00:00:00Z",
        field: value,
    }
    with pytest.raises(TypeError):
        MarketAuditPacket(**kwargs)


# ── T06: frozen — attempted mutation raises ───────────────────────────────────

def test_packet_is_frozen():
    p = MarketAuditPacket('p6', {}, '2026-08-23T00:00:00Z')
    with pytest.raises(Exception):
        p.packet_id = "mutated"  # type: ignore[misc]


def test_packet_is_frozen_even_against_nonexistent_authority_attribute():
    """A frozen dataclass rejects ALL attribute assignment, so a post-hoc
    attempt to bolt an authority-shaped attribute onto an existing instance
    is also blocked — belt-and-suspenders alongside construction-time
    rejection in test_authority_shaped_injection_fails_closed."""
    p = MarketAuditPacket('p6b', {}, '2026-08-23T00:00:00Z')
    with pytest.raises(Exception):
        p.authority_effect = "granted"  # type: ignore[misc,attr-defined]


# ── T07: digest stable under key-order permutation ────────────────────────────

def test_digest_stable_under_key_order():
    refs = _complete_refs()
    items = list(refs.items())
    p_forward = MarketAuditPacket('p7', dict(items), '2026-08-23T00:00:00Z')
    p_reversed = MarketAuditPacket('p7', dict(reversed(items)), '2026-08-23T00:00:00Z')
    assert p_forward.digest() == p_reversed.digest()


# ── T08: digest changes when a ref value changes ─────────────────────────────

def test_digest_changes_on_tamper():
    refs = _complete_refs()
    p_original = MarketAuditPacket('p8', dict(refs), '2026-08-23T00:00:00Z')
    refs['offer'] = _ref('tampered-offer')
    p_tampered = MarketAuditPacket('p8', refs, '2026-08-23T00:00:00Z')
    assert p_original.digest() != p_tampered.digest()


# ── T09: is_native_ref format discipline ──────────────────────────────────────

def test_is_native_ref_format_discipline():
    assert is_native_ref(_ref('valid')) is True
    assert is_native_ref('not-a-ref') is False
    assert is_native_ref('sha256:' + 'g' * 64) is False  # non-hex
    assert is_native_ref('sha256:' + 'AB' * 32) is False  # uppercase hex rejected
    assert is_native_ref('sha256:' + 'a' * 63) is False  # wrong length
    assert is_native_ref(None) is False
    assert is_native_ref(12345) is False


def test_ref_format_findings_per_category():
    refs = _complete_refs()
    refs['offer'] = 'not-a-native-ref'
    p = MarketAuditPacket('p9', refs, '2026-08-23T00:00:00Z')
    findings = ref_format_findings(p)
    assert findings['offer'] is False
    assert findings['discovery'] is True


# ── T10: independent recomputation from a plain dict ─────────────────────────

def test_recompute_packet_digest_matches_instance_digest():
    p = MarketAuditPacket('p10', _complete_refs(), '2026-08-23T00:00:00Z')
    assert recompute_packet_digest(p.body()) == p.digest()


# ── T11–T13: verify_packet_digest ─────────────────────────────────────────────

def test_verify_packet_digest_valid():
    p = MarketAuditPacket('p11', _complete_refs(), '2026-08-23T00:00:00Z')
    serialized = p.to_dict()
    result = verify_packet_digest(serialized)
    assert result['digest_valid'] is True
    assert result['recomputed_digest'] == serialized['packet_digest']


def test_verify_packet_digest_tampered():
    p = MarketAuditPacket('p12', _complete_refs(), '2026-08-23T00:00:00Z')
    serialized = p.to_dict()
    serialized['artifact_refs'] = dict(serialized['artifact_refs'])
    serialized['artifact_refs']['offer'] = _ref('tampered')
    result = verify_packet_digest(serialized)
    assert result['digest_valid'] is False


def test_verify_packet_digest_absent_declaration_is_not_false():
    p = MarketAuditPacket('p13', _complete_refs(), '2026-08-23T00:00:00Z')
    body_only = p.body()  # no packet_digest key at all
    result = verify_packet_digest(body_only)
    assert result['digest_valid'] is None


def test_verify_packet_digest_rejects_non_dict():
    result = verify_packet_digest("not-a-dict")  # type: ignore[arg-type]
    assert result['digest_valid'] is False


# ── T14: non_equivalences always present ──────────────────────────────────────

def test_non_equivalences_present_on_completeness():
    p = MarketAuditPacket('p14', {}, '2026-08-23T00:00:00Z')
    r = audit_completeness(p)
    assert "audit_complete != authorized" in r['non_equivalences']
    assert "audit_complete != admitted" in r['non_equivalences']
    assert "packet_digest_valid != real-world transaction occurred" in r['non_equivalences']
    assert "native_ref_present != referenced content verified" in r['non_equivalences']


# ── T15: independence — no producer/DAGR import in the module ────────────────

def test_no_producer_import_in_module():
    import arcs_verify.market_audit_packet  # noqa: F401
    banned_prefixes = ("dagr", "garp_sdk", "garp_core", "garp_local", "countergraph", "counterpedia")
    for name in sys.modules:
        if any(name == prefix or name.startswith(prefix + ".") for prefix in banned_prefixes):
            pytest.fail(f"producer module {name!r} imported — independence violated")
