from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

FROZEN_SCHEMA_SHA256 = "d03aad1d5517e2acb65d5c866905aed7219bcbbfadd1a4a97eac546dd23f0333"
PROFILE_ID = "srs.mcp.sdk_enforcement"
PROFILE_VERSION = "v0.1"
RECEIPT_VERSION = "srs.core.v5.1"
SIGNATURE_FAILURE_CODES = {
    "preimage_canonicalization_failed",
    "signature_invalid",
    "key_id_unresolved",
    "key_untrusted",
    "version_binding_mismatch",
    "signature_object_invalid",
    "signature_encoding_invalid",
    "public_key_encoding_invalid",
    "legacy_unverified",
}
RAW_KEYS = {
    "prompt_text", "transcript", "raw_payload", "tool_arguments", "arguments",
    "result_body", "headers", "prompt", "raw_prompt", "raw_output", "result",
    "tool_result", "request_body", "response_body", "access_token", "private_key",
}
PRIVATE_MARKERS = (
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "/" + "private" + "/" + "var",
    "C:" + "\\" + "\\",
    "~" + "/" + "garp-",
    "~" + "/" + "arcs-anchor",
)
REQUIRED_COMMON = {
    "receipt_version", "profile_id", "profile_version", "receipt_id", "receipt_type",
    "receipt_kind", "boundary_type", "protocol_binding", "subject_ref", "issuer_id",
    "runtime_instance_id", "boundary_id", "logical_call_id", "issued_at",
    "artifact_classes_covered", "artifact_classes_excluded", "attestation_limits",
    "extensions", "receipt_signature",
}
SIGNATURE_MEMBERS = {"algorithm", "canonicalization", "key_id", "signature"}
RESULT_LIMIT = (
    "The receipt establishes the request, admission disposition, and semantic result "
    "returned at the configured boundary. It does not independently establish that "
    "the underlying tool body executed for this invocation, because middleware such "
    "as caches may satisfy a call without handler execution."
)
TASK_LIMIT = (
    "The receipt establishes admission and submission to the configured task backend. "
    "It does not establish execution or completion."
)

@dataclass(slots=True)
class VerificationReport:
    schema_digest: bool = False
    envelope: bool = False
    profile: bool = False
    raw_content_exclusion: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    attestation_limits_present: bool = False
    chain_status: str = "not_applicable"
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all((
            self.schema_digest, self.envelope, self.profile,
            self.raw_content_exclusion, self.signature_valid,
            self.issuer_key_resolved, self.issuer_key_trusted,
            self.attestation_limits_present,
        )) and self.chain_status == "not_applicable"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["passed"] = self.passed
        return data


def _b64url_decode(value: str, *, code: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(code)
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(code) from exc


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _walk(value: Any) -> Iterable[tuple[str | None, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield None, item
            yield from _walk(item)


def _profile_errors(receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_COMMON - receipt.keys())
    if missing:
        errors.append("profile.missing_required:" + ",".join(missing))
    expected = {
        "receipt_version": RECEIPT_VERSION,
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "receipt_type": "sdk_enforcement",
        "boundary_type": "mcp_tool_call",
        "protocol_binding": "mcp",
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"profile.invalid_{key}")
    kind = receipt.get("receipt_kind")
    if kind == "admission":
        for key in ("requested_tool_name", "tool_resolution_status", "argument_digest", "policy_pack_id", "policy_pack_version", "disposition"):
            if key not in receipt:
                errors.append(f"profile.admission_missing_{key}")
        disposition = receipt.get("disposition")
        if disposition not in {"admitted", "refused", "deferred_for_review"}:
            errors.append("profile.invalid_disposition")
        if disposition == "deferred_for_review":
            if not receipt.get("review_object_ref"):
                errors.append("profile.deferred_missing_review_object_ref")
            if receipt.get("retry_contract") != "retry_after_approval":
                errors.append("profile.deferred_invalid_retry_contract")
    elif kind == "outcome":
        if not receipt.get("admission_receipt_ref"):
            errors.append("profile.outcome_missing_admission_receipt_ref")
        outcome = receipt.get("outcome")
        if outcome not in {"result_returned", "error_returned", "exception", "task_submitted", "indeterminate"}:
            errors.append("profile.invalid_outcome")
        if outcome in {"result_returned", "error_returned"}:
            if not receipt.get("result_digest"):
                errors.append("profile.result_missing_digest")
            if RESULT_LIMIT not in receipt.get("attestation_limits", []):
                errors.append("profile.result_missing_attestation_limit")
        if outcome == "task_submitted" and TASK_LIMIT not in receipt.get("attestation_limits", []):
            errors.append("profile.task_missing_attestation_limit")
    else:
        errors.append("profile.invalid_receipt_kind")
    if receipt.get("tool_resolution_status") == "not_observed" and "resolved_tool_ref" in receipt:
        errors.append("profile.resolution_ref_for_not_observed")
    excluded = set(receipt.get("artifact_classes_excluded") or [])
    if not {"raw_prompt", "raw_output", "raw_tool_arguments", "raw_tool_result"}.issubset(excluded):
        errors.append("profile.raw_artifact_exclusions_missing")
    return errors


def verify_receipt(receipt: dict[str, Any], keyring: dict[str, Any], *, schema_path: Path, selected_profile: str | None = None) -> VerificationReport:
    report = VerificationReport()
    schema_bytes = schema_path.read_bytes()
    report.schema_digest = hashlib.sha256(schema_bytes).hexdigest() == FROZEN_SCHEMA_SHA256
    if not report.schema_digest:
        report.failure_codes.append("schema.digest_mismatch")
    schema = json.loads(schema_bytes)
    schema_errors = sorted(Draft202012Validator(schema).iter_errors(receipt), key=lambda e: list(e.path))
    report.envelope = not schema_errors
    for error in schema_errors:
        report.failure_codes.append("envelope.schema_invalid")
        report.details.append(error.message)

    profile_errors = _profile_errors(receipt)
    if selected_profile and selected_profile != f"{PROFILE_ID}.{PROFILE_VERSION}":
        profile_errors.append("profile.unsupported_selection")
    report.profile = not profile_errors
    report.failure_codes.extend(profile_errors)

    raw_errors: list[str] = []
    for key, value in _walk(receipt):
        if key in RAW_KEYS:
            raw_errors.append(f"raw_content.forbidden_key:{key}")
        if isinstance(value, str) and any(marker in value for marker in PRIVATE_MARKERS):
            raw_errors.append("raw_content.private_reference")
    report.raw_content_exclusion = not raw_errors
    report.failure_codes.extend(raw_errors)

    limits = receipt.get("attestation_limits")
    report.attestation_limits_present = isinstance(limits, list) and bool(limits) and all(isinstance(x, str) and x.strip() for x in limits)
    if not report.attestation_limits_present:
        report.failure_codes.append("attestation.missing_or_empty")

    sig = receipt.get("receipt_signature")
    if isinstance(sig, str):
        report.failure_codes.append("legacy_unverified")
        return _dedupe(report)
    if not isinstance(sig, dict) or set(sig) != SIGNATURE_MEMBERS or sig.get("algorithm") != "Ed25519" or sig.get("canonicalization") != "RFC8785-JCS":
        report.failure_codes.append("signature_object_invalid")
        return _dedupe(report)

    key_id = sig.get("key_id")
    entries = keyring.get("issuers", []) if isinstance(keyring, dict) else []
    entry = next((item for item in entries if isinstance(item, dict) and item.get("key_id") == key_id), None)
    report.issuer_key_resolved = entry is not None
    if entry is None:
        report.failure_codes.append("key_id_unresolved")
        return _dedupe(report)

    try:
        public_key_bytes = _b64url_decode(entry.get("public_key"), code="public_key_encoding_invalid")
        signature_bytes = _b64url_decode(sig.get("signature"), code="signature_encoding_invalid")
        if len(public_key_bytes) != 32:
            raise ValueError("public_key_encoding_invalid")
        if len(signature_bytes) != 64:
            raise ValueError("signature_encoding_invalid")
    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return _dedupe(report)

    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]
    try:
        canonical = rfc8785.dumps(preimage)
    except Exception:
        report.failure_codes.append("preimage_canonicalization_failed")
        return _dedupe(report)
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, canonical)
        report.signature_valid = True
    except InvalidSignature:
        report.failure_codes.append("signature_invalid")

    if receipt.get("receipt_version") != RECEIPT_VERSION or receipt.get("profile_id") != PROFILE_ID or receipt.get("profile_version") != PROFILE_VERSION:
        report.failure_codes.append("version_binding_mismatch")
        report.signature_valid = False

    try:
        issued_at = _parse_time(receipt["issued_at"])
        trusted = entry.get("trusted") is True and entry.get("issuer_id") == receipt.get("issuer_id")
        trusted = trusted and _parse_time(entry["not_before"]) <= issued_at <= _parse_time(entry["not_after"])
    except Exception:
        trusted = False
    report.issuer_key_trusted = bool(trusted)
    if not report.issuer_key_trusted:
        report.failure_codes.append("key_untrusted")
    return _dedupe(report)


def _dedupe(report: VerificationReport) -> VerificationReport:
    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report
