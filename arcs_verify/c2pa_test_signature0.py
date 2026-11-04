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
TEST_RECEIPT_ID_PREFIX = "dagr-ingest-c2pa-TEST-SIGNED-"
_RECEIPT_ID = re.compile(r"^dagr-ingest-c2pa-TEST-SIGNED-[0-9a-f]{16}-[0-9a-f]{16}$")
MAX_SOURCE_BYTES = 8 * 1024 * 1024


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
    source_integrity: str
    receipt_identity: str
    failure_codes: tuple[str, ...]
    source_failure_codes: tuple[str, ...]
    identity_failure_codes: tuple[str, ...]
    signed_receipt_sha256: str
    source_unsigned_sha256: str | None
    verified_source_sha256: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": "offline_non_operational_test_only",
            "signature_valid": self.signature_valid,
            "issuer_key_resolved": self.issuer_key_resolved,
            "issuer_key_trusted": self.issuer_key_trusted,
            "source_integrity": self.source_integrity,
            "receipt_identity": self.receipt_identity,
            "failure_codes": list(self.failure_codes),
            "source_failure_codes": list(self.source_failure_codes),
            "identity_failure_codes": list(self.identity_failure_codes),
            "signed_receipt_sha256": self.signed_receipt_sha256,
            "source_unsigned_sha256": self.source_unsigned_sha256,
            "verified_source_sha256": self.verified_source_sha256,
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
    *,
    source_state: str = "not_evaluated",
    identity_state: str = "not_evaluated",
    source_codes: tuple[str, ...] = (),
    identity_codes: tuple[str, ...] = (),
    verified_source: str | None = None,
) -> TestSignatureFinding:
    return TestSignatureFinding(
        signature_valid=valid,
        issuer_key_resolved=resolved,
        issuer_key_trusted=trusted,
        source_integrity=source_state,
        receipt_identity=identity_state,
        failure_codes=tuple(dict.fromkeys(codes)),
        source_failure_codes=tuple(dict.fromkeys(source_codes)),
        identity_failure_codes=tuple(dict.fromkeys(identity_codes)),
        signed_receipt_sha256="sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
        source_unsigned_sha256=source,
        verified_source_sha256=None if verified_source is None else "sha256:" + verified_source,
    )


def _assess_source(
    source_bytes: bytes | None, declared: str | None,
) -> tuple[str, str | None, tuple[str, ...]]:
    """Recompute the source digest from the bytes the receiver supplied.

    A declared hash on its own never establishes source integrity: without bytes the
    finding stays ``not_evaluated``. The returned digest is the locally recomputed
    one, never a value echoed from the receipt.
    """
    if source_bytes is None:
        return "not_evaluated", None, ("source_bytes_missing",)
    if type(source_bytes) is not bytes:
        raise TypeError("source_bytes must be bytes")
    if len(source_bytes) > MAX_SOURCE_BYTES:
        raise TypeError("source_bytes must be at most 8 MiB")
    digest = hashlib.sha256(source_bytes).hexdigest()
    if not isinstance(declared, str) or not declared.startswith("sha256:"):
        return "not_evaluated", digest, ("source_reference_invalid",)
    if declared[7:] != digest:
        return "fail", digest, ("source_digest_mismatch",)
    return "pass", digest, ()


def _assess_identity(
    receipt_id: Any, verified_source_digest: str | None, key_fingerprint: str | None,
    source_state: str,
) -> tuple[str, tuple[str, ...]]:
    """Recompute the expected test receipt id from the verified source and selected key.

    The id binds a truncated source digest to a truncated key fingerprint. It is a
    consistency label, not an authentication proof: a forger can write any id into a
    receipt they sign. It can only be recomputed once the source bytes are verified and
    a key is resolved, so an unverified source yields ``not_evaluated``.
    """
    if not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id):
        return "fail", ("receipt_id_malformed",)
    if source_state != "pass" or verified_source_digest is None or key_fingerprint is None:
        return "not_evaluated", ("receipt_identity_unverified",)
    expected = TEST_RECEIPT_ID_PREFIX + verified_source_digest[-16:] + "-" + key_fingerprint[:16]
    if receipt_id == expected:
        return "pass", ()
    return "fail", ("receipt_id_mismatch",)


def verify_test_signed_observation(
    signed_receipt_bytes: bytes,
    *,
    selected_test_keys: Mapping[str, TestReceiverKey],
    source_bytes: bytes | None = None,
) -> TestSignatureFinding:
    """Verify an exact signed test derivative using only caller-selected key inputs.

    No implicit key resolution, no trust-list or network access, and no producer
    implementation import. A trusted_for_test key grants only local test-bundle
    trust, not trusted operational issuance or C2PA signer trust.

    ``source_bytes`` are the unsigned observation bytes the receiver holds. When
    supplied they are hashed locally and compared with the signed source reference;
    when absent the source finding is ``not_evaluated`` and the receipt identity
    cannot be recomputed. Source integrity and receipt identity are reported beside
    signature validity and never promote it.
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
        source_state, source_digest, source_codes = _assess_source(source_bytes, None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated",
            ["receipt_parse_invalid"], None,
            source_state=source_state, source_codes=source_codes,
            identity_state="not_evaluated", identity_codes=("receipt_identity_not_assessed",),
            verified_source=source_digest,
        )
    if not isinstance(receipt, dict):
        source_state, source_digest, source_codes = _assess_source(source_bytes, None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated",
            ["receipt_object_invalid"], None,
            source_state=source_state, source_codes=source_codes,
            identity_state="not_evaluated", identity_codes=("receipt_identity_not_assessed",),
            verified_source=source_digest,
        )

    source = None
    ext = receipt.get("extensions")
    proof = ext.get(TEST_EXTENSION) if isinstance(ext, dict) else None
    if isinstance(proof, dict):
        source = proof.get("original_observation_sha256")
    source_state, source_digest, source_codes = _assess_source(source_bytes, source)

    def _identity(key_fingerprint: str | None) -> tuple[str, tuple[str, ...]]:
        return _assess_identity(receipt.get("receipt_id"), source_digest, key_fingerprint, source_state)

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
        identity_state, identity_codes = _identity(None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated",
            ["test_provenance_not_admitted"], source,
            source_state=source_state, source_codes=source_codes,
            identity_state=identity_state, identity_codes=identity_codes,
            verified_source=source_digest,
        )
    signature = receipt.get("receipt_signature")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "canonicalization", "key_id", "signature"}:
        identity_state, identity_codes = _identity(None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated",
            ["signature_object_invalid"], source,
            source_state=source_state, source_codes=source_codes,
            identity_state=identity_state, identity_codes=identity_codes,
            verified_source=source_digest,
        )
    if (
        signature.get("algorithm") != "Ed25519"
        or signature.get("canonicalization") != "RFC8785-JCS"
        or not isinstance(signature.get("key_id"), str)
        or not signature["key_id"].startswith(TEST_KEY_ID_PREFIX)
        or not re.fullmatch(r"[0-9a-f]{64}", signature["key_id"][len(TEST_KEY_ID_PREFIX):])
    ):
        identity_state, identity_codes = _identity(None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated",
            ["signature_object_invalid"], source,
            source_state=source_state, source_codes=source_codes,
            identity_state=identity_state, identity_codes=identity_codes,
            verified_source=source_digest,
        )
    try:
        sigbytes = _decode_signature(signature.get("signature"))
        preimage_obj = copy.deepcopy(receipt)
        del preimage_obj["receipt_signature"]["signature"]
        preimage = rfc8785.dumps(preimage_obj)
    except ValueError as exc:
        code = "signature_encoding_invalid" if str(exc) == "signature_encoding_invalid" else "preimage_canonicalization_failed"
        identity_state, identity_codes = _identity(None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated",
            [code], source,
            source_state=source_state, source_codes=source_codes,
            identity_state=identity_state, identity_codes=identity_codes,
            verified_source=source_digest,
        )
    except (TypeError, OverflowError):
        identity_state, identity_codes = _identity(None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "not_evaluated", "not_evaluated",
            ["preimage_canonicalization_failed"], source,
            source_state=source_state, source_codes=source_codes,
            identity_state=identity_state, identity_codes=identity_codes,
            verified_source=source_digest,
        )

    selected = selected_test_keys.get(signature["key_id"])
    if selected is None:
        identity_state, identity_codes = _identity(None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "fail", "not_evaluated",
            ["key_id_unresolved"], source,
            source_state=source_state, source_codes=source_codes,
            identity_state=identity_state, identity_codes=identity_codes,
            verified_source=source_digest,
        )
    if not isinstance(selected, TestReceiverKey) or type(selected.public_key_raw) is not bytes or len(selected.public_key_raw) != 32:
        identity_state, identity_codes = _identity(None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "fail", "not_evaluated",
            ["public_key_invalid"], source,
            source_state=source_state, source_codes=source_codes,
            identity_state=identity_state, identity_codes=identity_codes,
            verified_source=source_digest,
        )
    key_fingerprint = hashlib.sha256(selected.public_key_raw).hexdigest()
    if signature["key_id"] != TEST_KEY_ID_PREFIX + key_fingerprint:
        identity_state, identity_codes = _identity(None)
        return _finding(
            signed_receipt_bytes, "not_evaluated", "fail", "not_evaluated",
            ["key_id_public_key_mismatch"], source,
            source_state=source_state, source_codes=source_codes,
            identity_state=identity_state, identity_codes=identity_codes,
            verified_source=source_digest,
        )
    trusted = selected.issuer_id == TEST_ISSUER and selected.trusted_for_test is True
    trust_state = "pass" if trusted else "fail"
    codes: list[str] = [] if trusted else ["key_untrusted_for_test"]
    try:
        Ed25519PublicKey.from_public_bytes(selected.public_key_raw).verify(sigbytes, preimage)
        sig_state = "pass"
    except (InvalidSignature, ValueError):
        sig_state = "fail"
        codes.insert(0, "signature_invalid")
    identity_state, identity_codes = _identity(key_fingerprint)
    return _finding(
        signed_receipt_bytes, sig_state, "pass", trust_state, codes, source,
        source_state=source_state, source_codes=source_codes,
        identity_state=identity_state, identity_codes=identity_codes,
        verified_source=source_digest,
    )


def verify_and_replay_test_signed_observation(
    signed_receipt_bytes: bytes,
    evidence: Any,
    *,
    selected_test_keys: Mapping[str, TestReceiverKey],
    source_bytes: bytes | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    """Separate signed receipt findings from the existing native C2PA replay.

    Even a failing/unresolved signature never becomes native validation success.
    The original bridge still evaluates correspondence, the provisional profile,
    independent native recomputation, and per-axis limitations on its own.

    ``source_bytes`` are forwarded to the signature finding so source integrity and
    receipt identity are assessed from receiver-supplied bytes, not from declared
    fields alone.
    """
    from .c2pa_srs_observed import consume_observation

    signature = verify_test_signed_observation(
        signed_receipt_bytes, selected_test_keys=selected_test_keys,
        source_bytes=source_bytes,
    )
    native = consume_observation(signed_receipt_bytes, evidence, executable=executable)
    return {
        "signature_test": signature.as_dict(),
        "native_replay": native.report,
        "native_stopped_at": native.stopped_at,
        "scope": "independent_axes_no_aggregate_result",
        "operational_issuer": "none_selected",
    }
