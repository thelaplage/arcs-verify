"""C2PA-SIGVERIFY0: independent test-only SRS signature findings.

This module never imports producer code, fetches key material, signs, selects
issuer standing, or changes the C2PA native verifier. The caller explicitly
supplies public keys and their TEST-ONLY trust decision. Cryptographic validity,
key resolution and key trust are distinct findings. An Ed25519 PASS is not
content truth, native signer trust, TSA trust or operational issuer authority.

SRS signing contract: Ed25519 over RFC8785-JCS of the complete receipt with
only receipt_signature.signature removed. All other fields remain signed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE_ID = "srs.c2pa.validation_observation"
PROFILE_VERSION = "v0.1"
RECEIPT_VERSION = "srs.core.v5.1"
TEST_ISSUER = "issuer.TEST-NON-OPERATIONAL.dagr-ingest/c2pa-observation-provisional"
TEST_KEY_ID_PREFIX = TEST_ISSUER + "/receipt-signing/test-only/"
TEST_EXTENSION = "dagr_ingest_test_signature0"
APPROVED_UNSIGNED_SHA256 = frozenset({
    "32a0ebd9cb47edd093f15eba1db1eb43c3130bb32bda645016ee2f7a337cbb22",
    "6b9f1219499da201c341cb45974ea2e3f0807a922c532967e297615a90c6a3da",
    "d4818c21c319b417110b067c423ca8ecfddf7f367591111f9a1fc2527ff26982",
})
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class TestReceiverKey:
    """Explicit receiver-selected TEST public key; not an operational trust bundle."""
    issuer_id: str
    public_key_raw: bytes
    trusted_for_test: bool = False


@dataclass(frozen=True)
class TestSignatureFinding:
    signature_valid: str
    issuer_key_resolved: str
    issuer_key_trusted: str
    failure_codes: tuple[str, ...]
    signed_receipt_sha256: str
    source_unsigned_sha256: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": "offline_non_operational_test_only",
            "signature_valid": self.signature_valid,
            "issuer_key_resolved": self.issuer_key_resolved,
            "issuer_key_trusted": self.issuer_key_trusted,
            "failure_codes": list(self.failure_codes),
            "signed_receipt_sha256": self.signed_receipt_sha256,
            "source_unsigned_sha256": self.source_unsigned_sha256,
            "issuer_standing": "not_evaluated",
            "content_truth": "not_evaluated",
            "native_c2pa_signer_trust": "not_evaluated",
            "independent_tsa_trust": "not_evaluated",
            "operational_issuance": "not_authorized",
        }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON member")
        obj[key] = value
    return obj


def _reject_nonfinite(value: str) -> None:
    raise ValueError("nonfinite JSON value")


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise ValueError("signature_encoding_invalid")
    padding = "=" * ((-len(value)) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise ValueError("signature_encoding_invalid") from exc
    if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("signature_encoding_invalid")
    return raw


def _finding(
    receipt_bytes: bytes, valid: str, resolved: str, trusted: str,
    codes: list[str], source: str | None = None,
) -> TestSignatureFinding:
    return TestSignatureFinding(
        signature_valid=valid,
        issuer_key_resolved=resolved,
        issuer_key_trusted=trusted,
        failure_codes=tuple(dict.fromkeys(codes)),
        signed_receipt_sha256="sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
        source_unsigned_sha256=source,
    )


def verify_test_signed_observation(
    signed_receipt_bytes: bytes,
    *,
    selected_test_keys: Mapping[str, TestReceiverKey],
) -> TestSignatureFinding:
    """Verify an exact signed test derivative using only caller-selected key inputs.

    No implicit key resolution, no trust-list or network access, and no producer
    implementation import. A trusted_for_test key grants only local test-bundle
    trust, not trusted operational issuance or C2PA signer trust.
    """
    if type(signed_receipt_bytes) is not bytes or len(signed_receipt_bytes) > 1024 * 1024:
        raise TypeError("signed_receipt_bytes must be bytes of at most 1 MiB")
    if not isinstance(selected_test_keys, Mapping):
        raise TypeError("selected_test_keys must be an explicit receiver mapping")
    try:
        receipt = json.loads(
            signed_receipt_bytes.decode("utf-8"),
            object_pairs_hook=_unique_object, parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, ValueError, TypeError):
        return _finding(signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated", ["receipt_parse_invalid"])
    if not isinstance(receipt, dict):
        return _finding(signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated", ["receipt_object_invalid"])
    source = None
    ext = receipt.get("extensions")
    proof = ext.get(TEST_EXTENSION) if isinstance(ext, dict) else None
    if isinstance(proof, dict):
        source = proof.get("original_observation_sha256")
    if (
        receipt.get("profile_id") != PROFILE_ID
        or receipt.get("profile_version") != PROFILE_VERSION
        or receipt.get("receipt_version") != RECEIPT_VERSION
        or receipt.get("issuer_id") != TEST_ISSUER
        or not isinstance(source, str)
        or not source.startswith("sha256:")
        or source[7:] not in APPROVED_UNSIGNED_SHA256
        or not isinstance(proof, dict)
        or proof.get("issuer_status") != "test_non_operational"
        or proof.get("key_scope") != "ephemeral_memory_only"
    ):
        return _finding(signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated", ["test_provenance_not_admitted"], source)
    signature = receipt.get("receipt_signature")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "canonicalization", "key_id", "signature"}:
        return _finding(signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated", ["signature_object_invalid"], source)
    if (
        signature.get("algorithm") != "Ed25519"
        or signature.get("canonicalization") != "RFC8785-JCS"
        or not isinstance(signature.get("key_id"), str)
        or not signature["key_id"].startswith(TEST_KEY_ID_PREFIX)
        or not re.fullmatch(r"[0-9a-f]{64}", signature["key_id"][len(TEST_KEY_ID_PREFIX):])
    ):
        return _finding(signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated", ["signature_object_invalid"], source)
    try:
        sigbytes = _decode_signature(signature.get("signature"))
        preimage_obj = copy.deepcopy(receipt)
        del preimage_obj["receipt_signature"]["signature"]
        preimage = rfc8785.dumps(preimage_obj)
    except ValueError as exc:
        code = "signature_encoding_invalid" if str(exc) == "signature_encoding_invalid" else "preimage_canonicalization_failed"
        return _finding(signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated", [code], source)
    except (TypeError, OverflowError):
        return _finding(signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated", ["preimage_canonicalization_failed"], source)

    selected = selected_test_keys.get(signature["key_id"])
    if selected is None:
        return _finding(signed_receipt_bytes, "not_evaluated", "fail", "not_evaluated", ["key_id_unresolved"], source)
    if not isinstance(selected, TestReceiverKey) or type(selected.public_key_raw) is not bytes or len(selected.public_key_raw) != 32:
        return _finding(signed_receipt_bytes, "not_evaluated", "fail", "not_evaluated", ["public_key_invalid"], source)
    if signature["key_id"] != TEST_KEY_ID_PREFIX + hashlib.sha256(selected.public_key_raw).hexdigest():
        return _finding(signed_receipt_bytes, "not_evaluated", "fail", "not_evaluated", ["key_id_public_key_mismatch"], source)
    trusted = selected.issuer_id == TEST_ISSUER and selected.trusted_for_test is True
    trust_state = "pass" if trusted else "fail"
    codes: list[str] = [] if trusted else ["key_untrusted_for_test"]
    try:
        Ed25519PublicKey.from_public_bytes(selected.public_key_raw).verify(sigbytes, preimage)
        sig_state = "pass"
    except (InvalidSignature, ValueError):
        sig_state = "fail"
        codes.insert(0, "signature_invalid")
    return _finding(signed_receipt_bytes, sig_state, "pass", trust_state, codes, source)


def verify_and_replay_test_signed_observation(
    signed_receipt_bytes: bytes,
    evidence: Any,
    *,
    selected_test_keys: Mapping[str, TestReceiverKey],
    executable: str | None = None,
) -> dict[str, Any]:
    """Separate signed receipt findings from the existing native C2PA replay.

    Even a failing/unresolved signature never becomes native validation success.
    The original bridge still evaluates correspondence, the provisional profile,
    independent native recomputation, and per-axis limitations on its own.
    """
    from .c2pa_srs_observed import consume_observation

    signature = verify_test_signed_observation(
        signed_receipt_bytes, selected_test_keys=selected_test_keys,
    )
    native = consume_observation(signed_receipt_bytes, evidence, executable=executable)
    return {
        "signature_test": signature.as_dict(),
        "native_replay": native.report,
        "native_stopped_at": native.stopped_at,
        "scope": "independent_axes_no_aggregate_result",
        "operational_issuer": "none_selected",
    }
