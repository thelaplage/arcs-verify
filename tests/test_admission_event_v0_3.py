from __future__ import annotations

import ast
import base64
import copy
import inspect

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import arcs_verify.admission_event_v0_3 as admission_event_v03
from arcs_verify.admission_event_v0_3 import (
    compare_content_digests,
    verify_admission_event_v0_3_receipt,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base_body() -> dict:
    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.activity.admission_event",
        "profile_version": "v0.3",
        "receipt_id": "activity-admission-event-v03-test-0001",
        "receipt_type": "provenance",
        "receipt_kind": "admission_event",
        "boundary_type": "admission_event_boundary",
        "protocol_binding": "counterpedia-admission-chain",
        "subject_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0001",
        "issuer_id": "issuer.test/admission-event/2026-08",
        "runtime_instance_id": "runtime-admission-event-v03-test-0001",
        "boundary_id": "boundary-admission-event-v03-test-0001",
        "issued_at": "2026-08-28T05:30:00Z",
        "visibility": "PRIVATE_ORG",
        "namespace_authority_ref": "urn:counterpedia:authority:operator:test",
        "subject_record_ref": "urn:counterpedia:record:CP-EXAMPLE-0001",
        "subject_edition_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0001",
        "standing_act": "ADMITTED",
        "governed_result_ref": "urn:dagr:final-admission-decision:example-v03-0001",
        "governed_result_digest": "sha256:" + "1" * 64,
        "policy_profile_ref": "urn:dagr:policy:institutional-admission:v0.1",
        "policy_digest": "sha256:" + "2" * 64,
        "disposition_id": "disposition:institutional-admission:example-v03-0001",
        "disposition_digest": "sha256:" + "3" * 64,
        "basis_refs": ["sha256:" + "4" * 64],
        "artifact_classes_covered": [
            "admission_event_record",
            "subject_edition_identity",
            "governed_result_identity",
            "policy_identity",
        ],
        "artifact_classes_excluded": [
            "subject_content_bytes",
            "evidence_content_bytes",
            "universal_truth",
            "downstream_reliance",
        ],
        "attestation_limits": [admission_event_v03.v01.ATTESTATION_LIMIT],
        "machine_limitations": [{"code": "CONTENT_NOT_VERIFIED"}],
        "extensions": {},
    }


def _superseded_body(*, supersession_extra: dict | None = None) -> dict:
    body = _base_body()
    predecessor = "event:counterpedia:admission:CP-EXAMPLE-0001:0001"
    successor = "event:counterpedia:admission:CP-EXAMPLE-0001:0002"
    owner_binding = "counterpedia:admission-supersession-binding:CP-EXAMPLE-0001:0001:0002"
    supersession = {
        "kind": "replacement_admission",
        "predecessor_event_ref": predecessor,
        "predecessor_event_core_digest": "sha256:" + "5" * 64,
        "successor_event_ref": successor,
        "successor_event_core_digest": "sha256:" + "6" * 64,
        "successor_subject_record_ref": body["subject_record_ref"],
        "successor_subject_edition_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0002",
        "semantic_owner_binding_ref": owner_binding,
        "semantic_owner_binding_digest": "sha256:" + "7" * 64,
    }
    if supersession_extra:
        supersession.update(supersession_extra)
    body.update(
        {
            "receipt_id": "activity-admission-event-v03-test-superseded-0001",
            "standing_act": "SUPERSEDED",
            "governed_result_ref": "urn:dagr:final-admission-decision:example-v03-successor-0002",
            "basis_refs": [predecessor, successor, owner_binding, "sha256:" + "4" * 64],
            "attestation_limits": [
                admission_event_v03.v01.ATTESTATION_LIMIT,
                admission_event_v03.v02.SUPERSESSION_LIMIT,
            ],
            "extensions": {"supersession": supersession},
        }
    )
    return body


def _sign(body: dict, *, private_key: Ed25519PrivateKey | None = None):
    private_key = private_key or Ed25519PrivateKey.generate()
    receipt = copy.deepcopy(body)
    receipt["receipt_signature"] = {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": "key.test/admission-event-v03/1",
        "signature": "",
    }
    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]
    receipt["receipt_signature"]["signature"] = _b64url(private_key.sign(rfc8785.dumps(preimage)))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = {
        "trust_bundle_version": "srs.trust_bundle.v0.1",
        "issuers": [
            {
                "issuer_id": body["issuer_id"],
                "key_id": "key.test/admission-event-v03/1",
                "algorithm": "Ed25519",
                "public_key": _b64url(public_key),
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "trusted": True,
            }
        ],
    }
    return receipt, keyring, private_key


PRED_DIGEST = "sha256:" + "a" * 64
SUCC_DIGEST_SAME = "sha256:" + "a" * 64
SUCC_DIGEST_DIFFERENT = "sha256:" + "b" * 64


# ---------------------------------------------------------------------------
# Baseline: v0.3 still validates like v0.2 for the unchanged axes.
# ---------------------------------------------------------------------------


def test_valid_signed_admitted_v03_passes_without_supersession_extension() -> None:
    receipt, keyring, _ = _sign(_base_body())
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.passed is True
    assert report.profile_schema_digest is True
    assert report.profile is True
    assert report.supersession_binding is True
    assert report.signature_valid is True
    # No supersession extension at all -> both sides absent, never MATCH.
    assert report.content_digest_comparison == admission_event_v03.NOT_EVALUATED
    assert report.content_digest_comparison_reason == admission_event_v03.CONTENT_DIGEST_ABSENT


def test_valid_signed_superseded_v03_without_content_digests_passes_and_is_not_evaluated() -> None:
    receipt, keyring, _ = _sign(_superseded_body())
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.passed is True
    assert report.failure_codes == []
    assert report.supersession_binding is True
    # Content-digest fields are OPTIONAL; omitting them must not fail the receipt.
    assert report.content_digest_comparison == admission_event_v03.NOT_EVALUATED
    assert report.content_digest_comparison_reason == admission_event_v03.CONTENT_DIGEST_ABSENT


def test_vendored_profile_bytes_are_exact_source_blob() -> None:
    data = admission_event_v03.PROFILE_SCHEMA_PATH.read_bytes()
    assert admission_event_v03.v02._git_blob_sha1(data) == admission_event_v03.PROFILE_SOURCE_BLOB_SHA1
    assert admission_event_v03.PROFILE_SOURCE_HEAD == "965d080c6fd2e2378221eaaad2862b1ec0e17f47"
    assert admission_event_v03.PROFILE_SOURCE_BLOB_SHA1 == "6f0f4228187137ebbf2b8486d982f1ebc6291d59"


# ---------------------------------------------------------------------------
# Tri-state content_digest_comparison — hostile/edge coverage.
# ---------------------------------------------------------------------------


def test_both_present_different_digests_diverges() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
            "predecessor_captured_bytes_digest_source": "LIVE_CAPTURE",
            "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
        }
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.DIVERGED
    assert report.content_digest_comparison_reason is None
    # DIVERGED is a disclosed structural fact, not a validity failure.
    assert report.passed is True


def test_both_present_equal_digests_match() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_SAME,
            "predecessor_captured_bytes_digest_source": "LIVE_CAPTURE",
            "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
        }
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.MATCH
    assert report.content_digest_comparison_reason is None
    assert report.passed is True


def test_predecessor_absent_is_not_evaluated() -> None:
    body = _superseded_body(
        supersession_extra={"successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT}
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.NOT_EVALUATED
    assert report.content_digest_comparison_reason == admission_event_v03.CONTENT_DIGEST_ABSENT
    # Absence is never silently upgraded to MATCH.
    assert report.content_digest_comparison != admission_event_v03.MATCH


def test_successor_absent_is_not_evaluated() -> None:
    body = _superseded_body(
        supersession_extra={"predecessor_captured_bytes_digest": PRED_DIGEST}
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.NOT_EVALUATED
    assert report.content_digest_comparison_reason == admission_event_v03.CONTENT_DIGEST_ABSENT
    assert report.content_digest_comparison != admission_event_v03.MATCH


def test_both_absent_is_not_evaluated_never_match() -> None:
    body = _superseded_body()
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.NOT_EVALUATED
    assert report.content_digest_comparison_reason == admission_event_v03.CONTENT_DIGEST_ABSENT


# ---------------------------------------------------------------------------
# Provenance gate: MATCH/DIVERGED require BOTH digests AND BOTH digest_source
# qualifiers present. A missing digest_source (not a false
# bytes_currently_retrievable) is its own NOT_EVALUATED reason.
# ---------------------------------------------------------------------------


def test_both_digests_and_both_sources_present_and_different_diverges() -> None:
    comparison, reason = compare_content_digests(
        _superseded_body(
            supersession_extra={
                "predecessor_captured_bytes_digest": PRED_DIGEST,
                "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
                "predecessor_captured_bytes_digest_source": "LIVE_CAPTURE",
                "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
            }
        )
    )
    assert comparison == admission_event_v03.DIVERGED
    assert reason is None


def test_both_digests_and_both_sources_present_and_equal_matches() -> None:
    comparison, reason = compare_content_digests(
        _superseded_body(
            supersession_extra={
                "predecessor_captured_bytes_digest": PRED_DIGEST,
                "successor_captured_bytes_digest": SUCC_DIGEST_SAME,
                "predecessor_captured_bytes_digest_source": "LIVE_CAPTURE",
                "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
            }
        )
    )
    assert comparison == admission_event_v03.MATCH
    assert reason is None


def test_digests_present_but_source_missing_on_both_sides_is_provenance_absent() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
        }
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.NOT_EVALUATED
    assert report.content_digest_comparison_reason == admission_event_v03.CONTENT_DIGEST_PROVENANCE_ABSENT
    assert report.content_digest_comparison not in (admission_event_v03.MATCH, admission_event_v03.DIVERGED)


def test_digests_present_but_successor_source_missing_is_provenance_absent() -> None:
    comparison, reason = compare_content_digests(
        _superseded_body(
            supersession_extra={
                "predecessor_captured_bytes_digest": PRED_DIGEST,
                "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
                "predecessor_captured_bytes_digest_source": "LIVE_CAPTURE",
                # successor source deliberately omitted
            }
        )
    )
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_PROVENANCE_ABSENT


def test_digests_present_but_predecessor_source_missing_is_provenance_absent() -> None:
    comparison, reason = compare_content_digests(
        _superseded_body(
            supersession_extra={
                "predecessor_captured_bytes_digest": PRED_DIGEST,
                "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
                # predecessor source deliberately omitted
                "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
            }
        )
    )
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_PROVENANCE_ABSENT


def test_absent_digest_check_takes_priority_over_provenance_check() -> None:
    # Predecessor digest itself absent (and no sources at all) -> the digest
    # absence reason wins; provenance-absent is only reachable once both
    # digests are present and well-formed.
    comparison, reason = compare_content_digests(
        _superseded_body(
            supersession_extra={"successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT}
        )
    )
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_ABSENT


def test_bytes_currently_retrievable_false_is_not_part_of_the_provenance_gate() -> None:
    # Both digests + both sources present; retrievable=false on both sides.
    # This must NOT be coerced to NOT_EVALUATED -- only a *missing*
    # digest_source triggers the provenance gate, never a false
    # bytes_currently_retrievable.
    comparison, reason = compare_content_digests(
        _superseded_body(
            supersession_extra={
                "predecessor_captured_bytes_digest": PRED_DIGEST,
                "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
                "predecessor_captured_bytes_digest_source": "HISTORICAL_CAPTURE_RECORD",
                "successor_captured_bytes_digest_source": "HISTORICAL_CAPTURE_RECORD",
                "predecessor_bytes_currently_retrievable": False,
                "successor_bytes_currently_retrievable": False,
            }
        )
    )
    assert comparison == admission_event_v03.DIVERGED
    assert reason is None


def test_malformed_uppercase_hex_is_not_evaluated() -> None:
    malformed = "sha256:" + "A" * 64
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": malformed,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_MALFORMED


def test_malformed_short_hex_is_not_evaluated() -> None:
    malformed = "sha256:" + "a" * 10
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": malformed,
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_MALFORMED


def test_malformed_missing_prefix_is_not_evaluated() -> None:
    malformed = "a" * 64  # missing "sha256:" prefix
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": malformed,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_MALFORMED


def test_malformed_digest_report_via_full_verify_is_not_evaluated_not_match() -> None:
    malformed = "sha256:" + "Z" * 64
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": malformed,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
        }
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.NOT_EVALUATED
    assert report.content_digest_comparison_reason == admission_event_v03.CONTENT_DIGEST_MALFORMED
    assert report.content_digest_comparison != admission_event_v03.MATCH


# ---------------------------------------------------------------------------
# Owner AMEND -- structural-absence discipline: a digest key that is PRESENT
# but wrong-typed/null/empty is MALFORMED, never ABSENT. Absence is reserved
# for a genuinely missing key.
# ---------------------------------------------------------------------------


def test_digest_present_as_integer_is_malformed_not_absent() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": 123,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_MALFORMED
    assert reason != admission_event_v03.CONTENT_DIGEST_ABSENT


def test_digest_present_as_null_is_malformed_not_absent() -> None:
    body = _superseded_body(
        supersession_extra={
            # Key is PRESENT with value None -- this must never be conflated
            # with a genuinely missing key.
            "predecessor_captured_bytes_digest": None,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_MALFORMED
    assert reason != admission_event_v03.CONTENT_DIGEST_ABSENT


def test_digest_present_as_empty_string_is_malformed_not_absent() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": "",
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_MALFORMED
    assert reason != admission_event_v03.CONTENT_DIGEST_ABSENT


def test_digest_present_as_object_is_malformed_not_absent() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": {"nested": "object"},
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_MALFORMED
    assert reason != admission_event_v03.CONTENT_DIGEST_ABSENT


def test_digest_key_truly_missing_is_still_absent() -> None:
    # Contrast case: the key is genuinely absent (never set at all), so this
    # must remain CONTENT_DIGEST_ABSENT, not MALFORMED.
    body = _superseded_body(
        supersession_extra={"successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT}
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_ABSENT
    assert reason != admission_event_v03.CONTENT_DIGEST_MALFORMED


# ---------------------------------------------------------------------------
# Owner AMEND -- provenance source must be a recognized enum value, not
# merely nonempty. A present-but-unrecognized source is
# CONTENT_DIGEST_PROVENANCE_INVALID, never conflated with
# CONTENT_DIGEST_PROVENANCE_ABSENT.
# ---------------------------------------------------------------------------


def test_source_present_but_unrecognized_value_is_provenance_invalid() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
            "predecessor_captured_bytes_digest_source": "whatever",
            "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_PROVENANCE_INVALID
    assert reason != admission_event_v03.CONTENT_DIGEST_PROVENANCE_ABSENT


def test_source_missing_is_provenance_absent_not_invalid() -> None:
    # Contrast case: a genuinely missing source key must remain
    # CONTENT_DIGEST_PROVENANCE_ABSENT, not INVALID.
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
            "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
            # predecessor source key deliberately never set
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_PROVENANCE_ABSENT
    assert reason != admission_event_v03.CONTENT_DIGEST_PROVENANCE_INVALID


def test_source_present_as_wrong_type_is_provenance_invalid() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
            "predecessor_captured_bytes_digest_source": "LIVE_CAPTURE",
            "successor_captured_bytes_digest_source": 42,
        }
    )
    comparison, reason = compare_content_digests(body)
    assert comparison == admission_event_v03.NOT_EVALUATED
    assert reason == admission_event_v03.CONTENT_DIGEST_PROVENANCE_INVALID


def test_source_invalid_via_full_verify_is_not_evaluated_not_match_not_diverged() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
            "predecessor_captured_bytes_digest_source": "whatever",
            "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
        }
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.NOT_EVALUATED
    assert report.content_digest_comparison_reason == admission_event_v03.CONTENT_DIGEST_PROVENANCE_INVALID
    assert report.content_digest_comparison not in (admission_event_v03.MATCH, admission_event_v03.DIVERGED)
    # The raw (invalid) source value is still surfaced verbatim -- disclosure
    # of what's on the wire, not silently dropped.
    assert report.predecessor_captured_bytes_digest_source == "whatever"


# ---------------------------------------------------------------------------
# Honest-B shape: historical capture, bytes no longer retrievable, digests
# diverge. Must disclose DIVERGED plus the evidence qualifiers, verbatim --
# never upgraded to any authenticity/re-hash claim.
# ---------------------------------------------------------------------------


def test_honest_b_historical_capture_not_retrievable_diverges_with_qualifiers_surfaced() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": "sha256:" + "b503e976" + "0" * 56,
            "successor_captured_bytes_digest": "sha256:" + "4f591641" + "0" * 56,
            "predecessor_captured_bytes_digest_source": "HISTORICAL_CAPTURE_RECORD",
            "successor_captured_bytes_digest_source": "HISTORICAL_CAPTURE_RECORD",
            "predecessor_bytes_currently_retrievable": False,
            "successor_bytes_currently_retrievable": False,
        }
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)

    assert report.content_digest_comparison == admission_event_v03.DIVERGED
    assert report.content_digest_comparison_reason is None
    assert report.predecessor_captured_bytes_digest_source == "HISTORICAL_CAPTURE_RECORD"
    assert report.successor_captured_bytes_digest_source == "HISTORICAL_CAPTURE_RECORD"
    assert report.predecessor_bytes_currently_retrievable is False
    assert report.successor_bytes_currently_retrievable is False
    # Nothing in this report claims the bytes were re-hashed, re-fetched, or
    # that the digest is authenticated -- only the literal comparison + the
    # qualifiers already on the wire are surfaced.
    report_dict = report.to_dict()
    forbidden_substrings = ("rehash", "re-hash", "authentic", "verified_bytes", "re_fetch")
    for key, value in report_dict.items():
        if isinstance(value, str):
            lowered = value.lower()
            for token in forbidden_substrings:
                assert token not in lowered, (key, value)


def test_evidence_qualifiers_absent_when_supersession_extension_absent() -> None:
    receipt, keyring, _ = _sign(_base_body())
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.predecessor_captured_bytes_digest_source is None
    assert report.successor_captured_bytes_digest_source is None
    assert report.predecessor_bytes_currently_retrievable is None
    assert report.successor_bytes_currently_retrievable is None


# ---------------------------------------------------------------------------
# No standing/authority inference from the comparison.
# ---------------------------------------------------------------------------


def test_no_standing_or_authority_field_emitted_from_comparison() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
            "predecessor_captured_bytes_digest_source": "LIVE_CAPTURE",
            "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
        }
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.DIVERGED
    report_dict = report.to_dict()
    for forbidden in admission_event_v03.v02.AUTHORITY_SHAPED_KEYS:
        assert forbidden not in report_dict
    # The comparison output itself carries no authority/standing vocabulary.
    assert set(report_dict) & admission_event_v03.v02.AUTHORITY_SHAPED_KEYS == set()


def test_divergence_does_not_alter_standing_act_or_supersession_binding_fields() -> None:
    body = _superseded_body(
        supersession_extra={
            "predecessor_captured_bytes_digest": PRED_DIGEST,
            "successor_captured_bytes_digest": SUCC_DIGEST_DIFFERENT,
            "predecessor_captured_bytes_digest_source": "LIVE_CAPTURE",
            "successor_captured_bytes_digest_source": "LIVE_CAPTURE",
        }
    )
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    assert report.content_digest_comparison == admission_event_v03.DIVERGED
    # Divergence must not be laundered into a same-lineage/binding claim change
    # -- supersession_binding continues to reflect only the unchanged v0.2
    # lineage rules, independent of content_digest_comparison.
    assert report.supersession_binding is True
    assert report.verified_supersession is not None
    assert report.verified_supersession.get("kind") == "replacement_admission"


# ---------------------------------------------------------------------------
# v0.1 / v0.2 verifiers remain green and untouched by this addition.
# ---------------------------------------------------------------------------


def test_reason_vocabulary_is_exactly_five_values() -> None:
    assert {
        admission_event_v03.CONTENT_DIGEST_ABSENT,
        admission_event_v03.CONTENT_DIGEST_MALFORMED,
        admission_event_v03.CONTENT_DIGEST_PROVENANCE_ABSENT,
        admission_event_v03.CONTENT_DIGEST_PROVENANCE_INVALID,
    } == {
        "CONTENT_DIGEST_ABSENT",
        "CONTENT_DIGEST_MALFORMED",
        "CONTENT_DIGEST_PROVENANCE_ABSENT",
        "CONTENT_DIGEST_PROVENANCE_INVALID",
    }
    # Plus `null` (None) for MATCH/DIVERGED -- five total reason states.


def test_v01_v02_modules_are_unmodified_siblings() -> None:
    # v0.3 imports v0.1/v0.2 for reuse; it must not monkeypatch or redefine
    # their exported names.
    assert admission_event_v03.v01.PROFILE_VERSION == "v0.1"
    assert admission_event_v03.v02.PROFILE_VERSION == "v0.2"
    assert not hasattr(admission_event_v03.v02, "content_digest_comparison")
    assert not hasattr(admission_event_v03.v01, "content_digest_comparison")


# ---------------------------------------------------------------------------
# Producer/verifier independence.
# ---------------------------------------------------------------------------


def test_v03_verifier_imports_no_producer_runtime() -> None:
    tree = ast.parse(inspect.getsource(admission_event_v03))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not [name for name in imported if name.startswith("dagr_runtime")]
    assert not [name for name in imported if name.startswith("dagr_mcp")]
    assert not [name for name in imported if name.startswith("counterpedia")]
    assert not [name for name in imported if name.startswith("arcs_srs")]
