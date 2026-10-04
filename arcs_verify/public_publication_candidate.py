"""Candidate-only verifier for the unratified public-publication SRS profile.

This module preserves the historical pre-registration candidate verifier.
It independently evaluates full signed SRS receipts against the exact
srs.activity.public_publication.v0.1 candidate contract pinned from arcs-srs.
The same profile slug may now be registered by a later, separately pinned
supported-profile path; that does not rewrite this module's candidate authority.

A candidate_conformant result means only that the supplied serialized receipt
satisfies the pinned candidate structure plus the independently recomputed SRS
envelope/signature/trust axes. It does not ratify the profile, authorize a
publication, establish publication rights, establish factual truth, or prove
destination persistence.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from .verifier import (
    SIGNATURE_MEMBERS,
    _b64url_decode,
    _contains_prohibited_value,
    _parse_time,
    _raw_content_failure,
    _walk,
)

CANDIDATE_PROFILE = "srs.activity.public_publication.v0.1"
CANDIDATE_SOURCE_REPOSITORY = "thelaplage/arcs-srs"
CANDIDATE_SOURCE_COMMIT = "5bab1cf1910dd6e8e489e6ba2c4511db8aca4cfc"
CANDIDATE_SOURCE_BLOB = "3c07f38239221eacbdea4e94a3f251d8ac9404c3"
ENVELOPE_V021_SHA256 = (
    "2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"
)

_DATA = Path(__file__).resolve().parent / "data"
_CONTRACT_PATH = _DATA / "srs.activity.public_publication.v0.1.candidate.json"
_SCHEMA_PATH = _DATA / "srs-envelope-v0.2.1.schema.json"


def _is_ref(value: Any) -> bool:
    if not isinstance(value, str) or ":" not in value:
        return False
    scheme, rest = value.split(":", 1)
    return bool(scheme) and scheme[0].isalpha() and all(
        ch.isalnum() or ch in "._-" for ch in scheme
    ) and bool(rest)


def _is_sha256_ref(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value[7:]
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def load_candidate_contract() -> dict[str, Any]:
    contract = json.loads(_CONTRACT_PATH.read_text(encoding="utf-8"))
    if (
        contract.get("status") != "proposed"
        or contract.get("ratification_status") != "unratified"
        or contract.get("supported") is not False
        or contract.get("profile_slug") != CANDIDATE_PROFILE
    ):
        raise ValueError("candidate contract posture invalid")
    return contract


@dataclass(slots=True)
class PublicPublicationCandidateReport:
    schema_digest: bool = False
    envelope: bool = False
    candidate_profile: bool = False
    raw_content_exclusion: bool = False
    attestation_limits_present: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    profile_id: str = "srs.activity.public_publication"
    profile_version: str = "v0.1"
    profile_status: str = "proposed"
    ratification_status: str = "unratified"
    supported_profile: bool = False
    candidate_source_repository: str = CANDIDATE_SOURCE_REPOSITORY
    candidate_source_commit: str = CANDIDATE_SOURCE_COMMIT
    candidate_source_blob: str = CANDIDATE_SOURCE_BLOB

    @property
    def candidate_conformant(self) -> bool:
        return all(
            (
                self.schema_digest,
                self.envelope,
                self.candidate_profile,
                self.raw_content_exclusion,
                self.attestation_limits_present,
                self.signature_valid,
                self.issuer_key_resolved,
                self.issuer_key_trusted,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["candidate_conformant"] = self.candidate_conformant
        return data


def candidate_profile_errors(
    receipt: dict[str, Any],
    contract: dict[str, Any] | None = None,
) -> list[str]:
    c = contract or load_candidate_contract()
    errors: list[str] = []

    fixed = c["fixed_values"]
    for field in (
        "receipt_version",
        "profile_id",
        "profile_version",
        "receipt_type",
        "receipt_kind",
        "boundary_type",
        "egress_class",
    ):
        if receipt.get(field) != fixed[field]:
            errors.append(f"public_publication.fixed_value:{field}")

    if receipt.get("subject_ref") != receipt.get("artifact_ref"):
        errors.append("public_publication.subject_ref_mismatch")

    if not _is_ref(receipt.get("artifact_ref")):
        errors.append("public_publication.artifact_ref_invalid")
    if not _is_sha256_ref(receipt.get("artifact_digest")):
        errors.append("public_publication.artifact_digest_invalid")
    if not _is_ref(receipt.get("artifact_manifest_ref")):
        errors.append("public_publication.artifact_manifest_ref_invalid")
    if not _is_sha256_ref(receipt.get("artifact_manifest_digest")):
        errors.append("public_publication.artifact_manifest_digest_invalid")

    def required_ref(field: str) -> str | None:
        if field not in receipt:
            errors.append(f"public_publication.{field}_missing")
            return None
        value = receipt[field]
        if not _is_ref(value):
            errors.append(f"public_publication.{field}_invalid")
            return None
        return value

    proposal_ref = required_ref("proposal_ref")
    decision_ref = required_ref("decision_ref")
    outcome_ref = required_ref("outcome_ref")

    disposition = receipt.get("publication_disposition")
    if disposition not in c["publication_dispositions"]:
        errors.append("public_publication.disposition_invalid")

    failure_code = receipt.get("failure_code")
    if failure_code is not None and failure_code not in c["failure_codes"]:
        errors.append("public_publication.failure_code_invalid")

    authority_basis_ref: str | None = None
    if "authority_basis_ref" not in receipt:
        errors.append("public_publication.authority_basis_ref_missing")
    else:
        value = receipt["authority_basis_ref"]
        if value is None:
            if not (
                disposition == "refused"
                and failure_code == "authority_basis_missing"
            ):
                errors.append("public_publication.authority_basis_ref_null_not_allowed")
        elif _is_ref(value):
            authority_basis_ref = value
        else:
            errors.append("public_publication.authority_basis_ref_invalid")

    actor_ref: str | None = None
    if "actor_ref" not in receipt:
        if not (
            disposition == "refused"
            and failure_code == "actor_attribution_missing"
        ):
            errors.append("public_publication.actor_ref_missing")
    else:
        value = receipt["actor_ref"]
        if _is_ref(value):
            actor_ref = value
        else:
            errors.append("public_publication.actor_ref_invalid")

    execution_ref: str | None = None
    if "execution_ref" not in receipt:
        errors.append("public_publication.execution_ref_field_missing")
    else:
        value = receipt["execution_ref"]
        if disposition == "refused":
            if value is not None:
                errors.append("public_publication.refused_requires_no_execution")
        elif _is_ref(value):
            execution_ref = value
        else:
            errors.append("public_publication.execution_ref_invalid")

    if receipt.get("destination_class") not in c["destination_classes"]:
        errors.append("public_publication.destination_class_invalid")
    if not _is_ref(receipt.get("destination_ref")):
        errors.append("public_publication.destination_ref_invalid")

    revision = receipt.get("published_revision_ref")
    if disposition == "published":
        if authority_basis_ref is None:
            errors.append("public_publication.published_requires_authority")
        if actor_ref is None:
            errors.append("public_publication.published_requires_actor")
        if execution_ref is None:
            errors.append("public_publication.published_requires_execution")
        if not _is_ref(revision):
            errors.append("public_publication.published_requires_revision")
        if failure_code is not None:
            errors.append("public_publication.published_requires_no_failure")
    elif disposition == "refused":
        if revision is not None:
            errors.append("public_publication.refused_requires_no_revision")
        if failure_code not in c["refusal_failure_codes"]:
            errors.append("public_publication.refused_failure_code_invalid")
    elif disposition == "failed":
        if authority_basis_ref is None:
            errors.append("public_publication.failed_requires_authority")
        if actor_ref is None:
            errors.append("public_publication.failed_requires_actor")
        if execution_ref is None:
            errors.append("public_publication.failed_requires_execution")
        if revision is not None:
            errors.append("public_publication.failed_requires_no_revision")
        if failure_code not in c["execution_failure_codes"]:
            errors.append("public_publication.failed_failure_code_invalid")

    semantic_refs = [
        actor_ref,
        proposal_ref,
        authority_basis_ref,
        decision_ref,
        execution_ref,
        outcome_ref,
    ]
    present_refs = [ref for ref in semantic_refs if ref is not None]
    if len(present_refs) != len(set(present_refs)):
        errors.append("public_publication.semantic_identity_collapse")

    covered = set(receipt.get("artifact_classes_covered") or [])
    for required in c["required_covered_classes"]:
        if required not in covered:
            errors.append(f"public_publication.covered_class_missing:{required}")

    excluded = set(receipt.get("artifact_classes_excluded") or [])
    for required in c["required_excluded_classes"]:
        if required not in excluded:
            errors.append(f"public_publication.excluded_class_missing:{required}")

    limits = receipt.get("attestation_limits")
    if (
        not isinstance(limits, list)
        or not all(isinstance(item, str) for item in limits)
        or c["required_attestation_limit"] not in limits
    ):
        errors.append("public_publication.attestation_limit_missing")

    for forbidden in c["forbidden_top_level_fields"]:
        if forbidden in receipt:
            errors.append(f"public_publication.forbidden_field:{forbidden}")

    return list(dict.fromkeys(errors))


def verify_public_publication_candidate(
    receipt: dict[str, Any],
    keyring: dict[str, Any],
    *,
    schema_path: Path | None = None,
) -> PublicPublicationCandidateReport:
    report = PublicPublicationCandidateReport()
    contract = load_candidate_contract()
    schema_file = schema_path or _SCHEMA_PATH

    schema_bytes = schema_file.read_bytes()
    report.schema_digest = hashlib.sha256(schema_bytes).hexdigest() == ENVELOPE_V021_SHA256
    if not report.schema_digest:
        report.failure_codes.append("schema.digest_mismatch")

    schema = json.loads(schema_bytes)
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(receipt),
        key=lambda error: list(error.path),
    )
    report.envelope = not schema_errors
    if schema_errors:
        report.failure_codes.append("envelope.schema_invalid")
        report.details.extend(error.message for error in schema_errors)

    profile_errors = candidate_profile_errors(receipt, contract)
    report.candidate_profile = not profile_errors
    report.failure_codes.extend(profile_errors)

    raw_errors: list[str] = []
    for key, value in _walk(receipt):
        if key is not None:
            failure = _raw_content_failure(key, value)
            if failure is not None:
                raw_errors.append(failure)
        if isinstance(value, str) and _contains_prohibited_value(value):
            raw_errors.append("raw_content.prohibited_value")
    report.raw_content_exclusion = not raw_errors
    report.failure_codes.extend(raw_errors)

    limits = receipt.get("attestation_limits")
    report.attestation_limits_present = (
        isinstance(limits, list)
        and contract["required_attestation_limit"] in limits
    )
    if not report.attestation_limits_present:
        report.failure_codes.append("attestation.required_limit_missing")

    signature = receipt.get("receipt_signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != SIGNATURE_MEMBERS
        or signature.get("algorithm") != "Ed25519"
        or signature.get("canonicalization") != "RFC8785-JCS"
    ):
        report.failure_codes.append("signature_object_invalid")
        return report

    key_id = signature.get("key_id")
    entries = keyring.get("issuers", []) if isinstance(keyring, dict) else []
    entry = next(
        (
            item
            for item in entries
            if isinstance(item, dict) and item.get("key_id") == key_id
        ),
        None,
    )
    report.issuer_key_resolved = entry is not None
    if entry is None:
        report.failure_codes.append("key_id_unresolved")
        return report

    try:
        public_key_bytes = _b64url_decode(
            entry.get("public_key"),
            code="public_key_encoding_invalid",
        )
        signature_bytes = _b64url_decode(
            signature.get("signature"),
            code="signature_encoding_invalid",
        )
        if len(public_key_bytes) != 32:
            raise ValueError("public_key_encoding_invalid")
        if len(signature_bytes) != 64:
            raise ValueError("signature_encoding_invalid")
    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return report

    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]
    try:
        canonical = rfc8785.dumps(preimage)
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes,
            canonical,
        )
        report.signature_valid = True
    except (InvalidSignature, ValueError, TypeError):
        report.failure_codes.append("signature_invalid")

    try:
        issued_at = _parse_time(receipt["issued_at"])
        trusted = (
            entry.get("trusted") is True
            and entry.get("issuer_id") == receipt.get("issuer_id")
            and _parse_time(entry["not_before"])
            <= issued_at
            <= _parse_time(entry["not_after"])
        )
    except Exception:
        trusted = False
    report.issuer_key_trusted = bool(trusted)
    if not report.issuer_key_trusted:
        report.failure_codes.append("key_untrusted")

    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report
