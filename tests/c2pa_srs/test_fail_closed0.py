"""HARDEN0-P2: hostile receipt bytes fail closed, deterministically, without raising.

Constructed receipts only; no producer import. The first test class pins the original
defect: a correctly signed receipt that nests a little over 900 levels made
``verify_test_signed_observation`` raise ``RecursionError`` from ``copy.deepcopy``
(and, deeper, from JCS canonicalization) instead of returning a finding.

Rules asserted throughout: a malformed receipt never yields ``signature_valid`` or
``issuer_key_trusted`` ``pass``, never an authenticated or operational finding, and
genuine programmer errors still raise ``TypeError``.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import types

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arcs_verify import c2pa_test_signature0 as mod
from arcs_verify.c2pa_test_signature0 import (
    APPROVED_UNSIGNED_SHA256,
    MAX_RECEIPT_BYTES,
    MAX_RECEIPT_NESTING_DEPTH,
    MAX_SOURCE_BYTES,
    TEST_ISSUER,
    TEST_KEY_ID_PREFIX,
    TestReceiverKey,
    verify_and_replay_test_signed_observation,
    verify_test_signed_observation,
)

from . import material as m
from .test_receiver_binding0 import build_receipt, new_key, selected, sign, source_bytes

NESTING = "receipt_nesting_excessive"


def nested_list(depth: int) -> str:
    return "[" * depth + "]" * depth


def nested_object(depth: int) -> str:
    return '{"a":' * depth + "0" + "}" * depth


def container_depth(value) -> int:
    best, stack = 0, [(value, 1)]
    while stack:
        node, depth = stack.pop()
        best = max(best, depth)
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))
    return best


def base_doc():
    data = source_bytes("positive")
    declared = "sha256:" + hashlib.sha256(data).hexdigest()
    key, public, fingerprint = new_key()
    return build_receipt(declared, fingerprint), key, public, data


def sign_without_copy(doc: dict, key: Ed25519PrivateKey) -> bytes:
    """Sign like ``sign`` but without ``copy.deepcopy``, which itself recurses.

    Mutates ``doc``. Needed only to build a genuinely signed, deeply nested receipt.
    """
    doc["receipt_signature"].pop("signature", None)
    signature = key.sign(rfc8785.dumps(doc))
    doc["receipt_signature"]["signature"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return rfc8785.dumps(doc)


def dummy_signature() -> str:
    return base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")


def with_tail(doc: dict, tail: str) -> bytes:
    """Hand-assemble a receipt wire form: a well-formed prefix plus a hostile member.

    The hostile member cannot go through ``rfc8785``/``json.dumps`` because the point
    is to deliver content those serializers refuse.
    """
    doc = copy.deepcopy(doc)
    doc["receipt_signature"]["signature"] = dummy_signature()
    text = json.dumps(doc)
    return (text[:-1] + "," + tail + "}").encode("utf-8")


def assert_fails_closed(result, *codes: str) -> None:
    assert result.failure_codes == codes
    assert result.signature_valid == "not_evaluated"
    assert result.issuer_key_resolved == "not_evaluated"
    assert result.issuer_key_trusted == "not_evaluated"
    assert result.receipt_identity != "pass"
    report = result.as_dict()
    assert report["issuer_standing"] == "not_evaluated"
    assert report["operational_issuance"] == "not_authorized"
    json.dumps(report)  # the report itself is always serializable


# --------------------------------------------------------------------------------------
# The reproduced defect: RecursionError escaping verify_test_signed_observation.
# --------------------------------------------------------------------------------------


def test_correctly_signed_receipt_nested_900_deep_no_longer_raises_recursion_error():
    """Pre-fix: ``copy.deepcopy`` raised RecursionError for this exact input."""
    doc, key, public, data = base_doc()
    doc["extensions"]["vendor"] = json.loads(nested_list(900))
    wire = sign_without_copy(doc, key)  # JCS copes at 900, so the signature is genuine
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert_fails_closed(result, NESTING)
    assert result.source_integrity == "not_evaluated"
    assert result.identity_failure_codes == ("receipt_identity_not_assessed",)


@pytest.mark.parametrize("depth", [MAX_RECEIPT_NESTING_DEPTH + 1, 900, 1_100, 5_000, 100_000])
@pytest.mark.parametrize("shape", [nested_list, nested_object])
@pytest.mark.parametrize("position", ["root", "member", "extension"])
def test_extreme_nesting_is_refused_everywhere_it_can_hide(depth, shape, position):
    doc, _, _, data = base_doc()
    nested = shape(depth)
    if position == "root":
        wire = nested.encode()
    elif position == "member":
        wire = with_tail(doc, '"extra":' + nested)
    else:
        text = json.dumps(doc)
        wire = text.replace('"key_scope"', '"deep":' + nested + ',"key_scope"').encode()
    assert len(wire) <= MAX_RECEIPT_BYTES
    result = verify_test_signed_observation(wire, selected_test_keys={}, source_bytes=data)
    assert_fails_closed(result, NESTING)


def test_nesting_bomb_at_the_one_mib_limit_is_refused_not_crashed():
    wire = (b"[" * (MAX_RECEIPT_BYTES // 2)) + (b"]" * (MAX_RECEIPT_BYTES // 2))
    assert len(wire) == MAX_RECEIPT_BYTES
    assert_fails_closed(verify_test_signed_observation(wire, selected_test_keys={}), NESTING)


def test_bomb_of_unclosed_openers_is_refused():
    wire = b"[" * 200_000
    assert_fails_closed(verify_test_signed_observation(wire, selected_test_keys={}), NESTING)


@pytest.mark.parametrize("offset", [0, 1])
def test_the_depth_limit_is_exact(offset):
    doc, key, public, data = base_doc()
    # root(1) > extensions(2) > vendor(3) > ... : build to reach exactly limit + offset.
    inner = MAX_RECEIPT_NESTING_DEPTH + offset - 2
    doc["extensions"]["vendor"] = json.loads(nested_list(inner))
    assert container_depth(doc) == MAX_RECEIPT_NESTING_DEPTH + offset
    wire = sign(doc, key)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    if offset == 0:
        assert result.failure_codes == ()
        assert result.signature_valid == "pass"
    else:
        assert_fails_closed(result, NESTING)


def test_brackets_and_escaped_quotes_inside_strings_are_not_nesting():
    doc, key, public, data = base_doc()
    doc["extensions"]["vendor"] = {"text": "[{" * 5_000 + '\\"' + "]}" * 5_000 + '"[[['}
    wire = sign(doc, key)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.failure_codes == ()
    assert result.signature_valid == "pass"
    assert result.source_integrity == "pass"
    assert result.receipt_identity == "pass"


def test_parser_recursion_error_maps_to_a_finding_not_an_exception(monkeypatch):
    def exhausted(*args, **kwargs):
        raise RecursionError("simulated parser stack exhaustion")

    monkeypatch.setattr(mod, "json", types.SimpleNamespace(loads=exhausted))
    wire = json.dumps({"receipt_version": "srs.core.v5.1"}).encode()
    assert_fails_closed(verify_test_signed_observation(wire, selected_test_keys={}), NESTING)


def test_canonicalizer_recursion_error_maps_to_a_finding_not_an_exception(monkeypatch):
    doc, key, public, data = base_doc()
    wire = sign(doc, key)

    def exhausted(*args, **kwargs):
        raise RecursionError("simulated canonicalizer stack exhaustion")

    monkeypatch.setattr(mod.rfc8785, "dumps", exhausted)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.failure_codes == ("preimage_canonicalization_failed",)
    assert result.signature_valid == "not_evaluated"
    assert result.issuer_key_resolved == "not_evaluated"
    assert result.issuer_key_trusted == "not_evaluated"
    assert result.receipt_identity != "pass"


def test_the_integrated_replay_also_fails_closed_on_a_nesting_bomb():
    wire = nested_list(100_000).encode()
    out = verify_and_replay_test_signed_observation(
        wire, m.evidence_for(), selected_test_keys={}, source_bytes=source_bytes("positive"),
    )
    assert out["signature_test"]["failure_codes"] == [NESTING]
    assert out["signature_test"]["signature_valid"] == "not_evaluated"
    assert out["native_stopped_at"] == "input_parse"
    assert out["native_replay"]["pipeline"]["stages"]["input_parse"]["status"] == "refused"


# --------------------------------------------------------------------------------------
# Malformed JSON and bytes.
# --------------------------------------------------------------------------------------

MALFORMED = {
    "empty": b"",
    "whitespace_only": b" \n\t ",
    "truncated_object": b'{"receipt_version":',
    "truncated_string": b'{"a":"unterminated',
    "trailing_garbage": b'{"a":1} garbage',
    "two_documents": b"{}{}",
    "single_quotes": b"{'a':1}",
    "trailing_comma": b'{"a":1,}',
    "unquoted_key": b"{a:1}",
    "control_char_in_string": b'{"a":"x\ty"}',
    "bad_escape": b'{"a":"\\q"}',
    "nan": b'{"a":NaN}',
    "infinity": b'{"a":Infinity}',
    "negative_infinity": b'{"a":-Infinity}',
    "duplicate_member_root": b'{"a":1,"a":2}',
    "duplicate_member_nested": b'{"a":{"b":1,"b":1}}',
    "duplicate_member_in_array": b'{"a":[{"b":1,"b":2}]}',
    "duplicate_via_escape": b'{"a":1,"\\u0061":2}',
    "bom_prefix": b'\xef\xbb\xbf{"a":1}',
    "invalid_utf8_continuation": b'{"a":"\xff"}',
    "invalid_utf8_overlong": b'{"a":"\xc0\x80"}',
    "invalid_utf8_truncated": b'{"a":"\xe2\x82"}',
    "invalid_utf8_encoded_surrogate": b'{"a":"\xed\xa0\x80"}',
    "utf16_input": '{"a":1}'.encode("utf-16"),
    "nul_bytes": b'{"a":1}\x00',
    "oversized_integer_literal": b'{"a":' + b"9" * 6_000 + b"}",
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_bytes_yield_an_explicit_non_passing_finding(name):
    result = verify_test_signed_observation(
        MALFORMED[name], selected_test_keys={}, source_bytes=source_bytes("positive"),
    )
    assert_fails_closed(result, "receipt_parse_invalid")
    assert result.source_integrity == "not_evaluated"
    assert result.identity_failure_codes == ("receipt_identity_not_assessed",)
    assert result.signed_receipt_sha256 == "sha256:" + hashlib.sha256(MALFORMED[name]).hexdigest()


@pytest.mark.parametrize("wire", [b"[]", b"null", b"true", b"1", b'"text"', b"[[1]]"])
def test_non_object_roots_are_refused(wire):
    assert_fails_closed(verify_test_signed_observation(wire, selected_test_keys={}), "receipt_object_invalid")


def test_duplicate_member_in_an_otherwise_valid_signed_receipt_is_refused():
    doc, key, public, data = base_doc()
    wire = sign(doc, key).decode()
    wire = wire.replace('"profile_id"', '"profile_id":"srs.c2pa.validation_observation","profile_id"', 1)
    result = verify_test_signed_observation(
        wire.encode(), selected_test_keys=selected(public), source_bytes=data,
    )
    assert_fails_closed(result, "receipt_parse_invalid")


# --------------------------------------------------------------------------------------
# Values that parse but cannot be canonicalized (the invalid-JCS-input family).
# --------------------------------------------------------------------------------------

UNCANONICALIZABLE = {
    "lone_surrogate_value": r'"extra":"\ud800"',
    "lone_low_surrogate_value": r'"extra":"\udc00"',
    "lone_surrogate_member_name": r'"\ud800":1',
    "float_overflow_to_infinity": '"extra":1e999',
    "negative_float_overflow": '"extra":-1e999',
    "integer_beyond_2_53": '"extra":9007199254740993',
    "negative_integer_beyond_2_53": '"extra":-9007199254740993',
    "very_large_integer": '"extra":' + "9" * 4_000,
}


@pytest.mark.parametrize("name", sorted(UNCANONICALIZABLE))
def test_uncanonicalizable_values_never_reach_signature_verification(name):
    doc, _, public, data = base_doc()
    wire = with_tail(doc, UNCANONICALIZABLE[name])
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    # Parsing succeeded, admission succeeded, and the signature object is well formed;
    # only the preimage fails. No cryptographic or trust finding may be produced.
    assert_fails_closed(result, "preimage_canonicalization_failed")
    assert result.source_integrity == "pass"  # independent: bytes match an admitted reference
    assert result.receipt_identity == "not_evaluated"


@pytest.mark.parametrize("literal", ["1.5e-7", "-0.0", "0", "123456789012345", "1E2"])
def test_ordinary_numbers_still_canonicalize(literal):
    doc, _, public, data = base_doc()
    result = verify_test_signed_observation(
        with_tail(doc, '"extra":' + literal), selected_test_keys=selected(public), source_bytes=data,
    )
    assert result.failure_codes == ("signature_invalid",)  # dummy signature: crypto ran
    assert result.signature_valid == "fail"


# --------------------------------------------------------------------------------------
# Receipt-controlled data is never echoed into a finding.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("hostile", [
    [[1, 2], {"a": "b"}], {"nested": {"deep": [1]}}, 7, True, "x" * 100_000, "sha256:zz",
    "sha256:" + "A" * 64, "sha256:" + "a" * 63, "sha256:" + "a" * 65, "sha256:" + "a" * 64 + "\n",
])
def test_hostile_source_reference_is_not_echoed(hostile):
    doc, _, _, data = base_doc()
    doc["extensions"]["dagr_ingest_test_signature0"]["original_observation_sha256"] = hostile
    wire = sign(doc, Ed25519PrivateKey.generate()) if _jcs_ok(doc) else json.dumps(doc).encode()
    result = verify_test_signed_observation(wire, selected_test_keys={}, source_bytes=data)
    assert result.source_unsigned_sha256 is None
    assert result.as_dict()["source_unsigned_sha256"] is None
    assert result.signature_valid == "not_evaluated"
    assert result.source_integrity != "pass"
    assert len(json.dumps(result.as_dict())) < 2_000


def _jcs_ok(doc) -> bool:
    try:
        rfc8785.dumps(doc)
        return True
    except ValueError:
        return False


def test_well_formed_source_reference_is_still_echoed():
    doc, key, public, data = base_doc()
    wire = sign(doc, key)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.source_unsigned_sha256 == "sha256:" + hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------------------
# Boundary sizes and the programmer-error contract.
# --------------------------------------------------------------------------------------


def test_receipt_of_exactly_one_mib_is_assessed_not_rejected_as_oversize():
    wire = b"[]" + b" " * (MAX_RECEIPT_BYTES - 2)
    assert len(wire) == MAX_RECEIPT_BYTES
    assert_fails_closed(verify_test_signed_observation(wire, selected_test_keys={}), "receipt_object_invalid")


def test_receipt_one_byte_over_the_limit_is_a_programmer_error():
    with pytest.raises(TypeError, match="1 MiB"):
        verify_test_signed_observation(b" " * (MAX_RECEIPT_BYTES + 1), selected_test_keys={})


def test_valid_signed_receipt_padded_to_the_limit_still_verifies():
    doc, key, public, data = base_doc()
    wire = sign(doc, key)
    padded = wire + b" " * (MAX_RECEIPT_BYTES - len(wire))
    result = verify_test_signed_observation(padded, selected_test_keys=selected(public), source_bytes=data)
    assert result.failure_codes == ()
    assert result.signature_valid == "pass"


def test_source_of_exactly_eight_mib_is_hashed_and_fails_the_comparison():
    doc, key, public, _ = base_doc()
    result = verify_test_signed_observation(
        sign(doc, key), selected_test_keys=selected(public), source_bytes=b"\0" * MAX_SOURCE_BYTES,
    )
    assert result.source_integrity == "fail"
    assert result.source_failure_codes == ("source_digest_mismatch",)


def test_source_one_byte_over_eight_mib_is_a_programmer_error_even_for_a_hostile_receipt():
    with pytest.raises(TypeError, match="8 MiB"):
        verify_test_signed_observation(
            nested_list(10_000).encode(), selected_test_keys={}, source_bytes=b"\0" * (MAX_SOURCE_BYTES + 1),
        )


@pytest.mark.parametrize("bad", [
    bytearray(b"{}"), memoryview(b"{}"), "{}", None, 7, [b"{}"],
])
def test_wrong_receipt_argument_types_still_raise(bad):
    with pytest.raises(TypeError):
        verify_test_signed_observation(bad, selected_test_keys={})


@pytest.mark.parametrize("bad", [bytearray(b"x"), memoryview(b"x"), "x", 7])
def test_wrong_source_argument_types_still_raise_even_for_unparseable_receipts(bad):
    for wire in (b"not json", nested_list(1_000).encode(), b"[]"):
        with pytest.raises(TypeError):
            verify_test_signed_observation(wire, selected_test_keys={}, source_bytes=bad)


@pytest.mark.parametrize("bad", [None, [], "keys", 3, ("a", "b")])
def test_non_mapping_key_selection_still_raises(bad):
    with pytest.raises(TypeError):
        verify_test_signed_observation(b"{}", selected_test_keys=bad)


# --------------------------------------------------------------------------------------
# Verification semantics stay independent and the preimage is unchanged.
# --------------------------------------------------------------------------------------


def test_preimage_equals_the_deepcopy_construction_it_replaced():
    """Signing the reference construction (deepcopy, delete signature, JCS) verifies."""
    doc, key, public, data = base_doc()
    doc["extensions"]["vendor"] = {
        "unicode": "café \U0001f600", "nums": [1, 2.5, -0.0, 1e21, 1e-7], "nested": [[{"k": [None, True]}]],
    }
    signed = copy.deepcopy(doc)
    reference = copy.deepcopy(signed)
    signature_value = base64.urlsafe_b64encode(key.sign(rfc8785.dumps(reference))).decode().rstrip("=")
    signed["receipt_signature"]["signature"] = signature_value
    wire = rfc8785.dumps(signed)
    before = bytes(wire)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert wire == before
    assert result.signature_valid == "pass"
    assert result.issuer_key_resolved == "pass"
    assert result.issuer_key_trusted == "pass"
    assert result.source_integrity == "pass"
    assert result.receipt_identity == "pass"
    assert result.failure_codes == ()


def test_signed_member_other_than_the_signature_is_still_covered_by_the_preimage():
    doc, key, public, data = base_doc()
    wire = sign(doc, key).decode().replace('"native_validation_state":"Invalid"', '"native_validation_state":"Valid"')
    result = verify_test_signed_observation(wire.encode(), selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "fail"
    assert result.failure_codes == ("signature_invalid",)


@pytest.mark.parametrize("name", sorted(MALFORMED) + sorted(UNCANONICALIZABLE))
def test_no_hostile_input_yields_any_pass_on_the_authenticated_axes(name):
    doc, _, public, data = base_doc()
    wire = MALFORMED[name] if name in MALFORMED else with_tail(doc, UNCANONICALIZABLE[name])
    result = verify_test_signed_observation(
        wire, selected_test_keys=selected(public, trusted=True), source_bytes=data,
    )
    assert "pass" not in (result.signature_valid, result.issuer_key_resolved, result.issuer_key_trusted)
    assert result.receipt_identity != "pass"
    assert result.failure_codes


def test_independent_findings_survive_a_failed_signature():
    """Signature failure does not erase or promote the other findings."""
    doc, _, public, data = base_doc()
    result = verify_test_signed_observation(
        with_tail(doc, '"extra":1'), selected_test_keys=selected(public), source_bytes=data,
    )
    assert result.signature_valid == "fail"
    assert result.issuer_key_resolved == "pass"
    assert result.issuer_key_trusted == "pass"
    assert result.source_integrity == "pass"
    assert result.receipt_identity == "pass"  # a consistency label, never authentication


def test_key_resolution_failure_for_a_clean_receipt_is_unchanged():
    doc, key, _, data = base_doc()
    result = verify_test_signed_observation(sign(doc, key), selected_test_keys={}, source_bytes=data)
    assert result.failure_codes == ("key_id_unresolved",)
    assert (result.signature_valid, result.issuer_key_resolved, result.issuer_key_trusted) == (
        "not_evaluated", "fail", "not_evaluated",
    )


def test_selected_key_validation_is_unchanged_for_hostile_key_material():
    doc, key, public, data = base_doc()
    wire = sign(doc, key)
    key_id = TEST_KEY_ID_PREFIX + hashlib.sha256(public).hexdigest()
    bad = {key_id: TestReceiverKey(issuer_id=TEST_ISSUER, public_key_raw=b"short", trusted_for_test=True)}
    result = verify_test_signed_observation(wire, selected_test_keys=bad, source_bytes=data)
    assert result.failure_codes == ("public_key_invalid",)
    assert result.signature_valid == "not_evaluated"


def test_all_admitted_source_digests_remain_frozen():
    assert len(APPROVED_UNSIGNED_SHA256) == 3
