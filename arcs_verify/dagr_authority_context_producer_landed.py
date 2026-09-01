"""Compatibility repair for the landed DAGR authority-context producer receipt.

The original independent verifier was reviewed against a pre-hardening receipt
candidate that carried ``subject_ref_origin=binding_minted`` and a caller-supplied
``runtime_instance_id``.  The canonical dagr-runtime emitter later hardened that
surface before landing:

* subject_ref is caller supplied and truthfully labelled ``supplied_subject``;
* no governed runtime-instance identity exists, so ``runtime_instance_id`` is
  omitted rather than caller invented.

SRS envelope v0.2.1 permits both choices.  This module does not reimplement any
cryptographic, trust, schema, artifact, context, or projection verification.  It
runs the original verifier over the exact unmodified serialized receipt so its
Ed25519/RFC8785 verification remains authoritative, then replaces only the stale
profile-surface predicate with the exact landed surface.

No PASS from this module establishes same-genesis binding, Countervail
InvocationAuthority, action permission, execution, truth, or receiver custody.
"""
from __future__ import annotations

from typing import Any

from arcs_verify import dagr_authority_context_producer as base


_LANDED_TOP_LEVEL_FIELDS = frozenset(
    {
        "receipt_version",
        "profile_id",
        "profile_version",
        "receipt_id",
        "receipt_type",
        "receipt_kind",
        "boundary_type",
        "protocol_binding",
        "subject_ref",
        "subject_ref_origin",
        "issuer_id",
        "issued_at",
        "artifact_classes_covered",
        "artifact_classes_excluded",
        "attestation_limits",
        "extensions",
        "receipt_signature",
    }
)

_LANDED_EXPECTED_RECEIPT_FIELDS = {
    "receipt_version": base.SRS_RECEIPT_VERSION,
    "profile_id": base.PROFILE_ID,
    "profile_version": base.PROFILE_VERSION,
    "receipt_type": base.RECEIPT_TYPE,
    "receipt_kind": base.RECEIPT_KIND,
    "boundary_type": "artifact_emission",
    "protocol_binding": "dagr-runtime",
    "subject_ref_origin": "supplied_subject",
}

# These are the only failures the pre-hardening verifier is expected to add
# solely because its frozen profile-surface predicate is stale.  They are
# removed only after the landed predicate independently passes.
_STALE_PRE_HARDENING_SURFACE_FAILURES = frozenset(
    {
        "profile.top_level_surface_mismatch",
        "receipt.subject_ref_origin_mismatch",
    }
)


def _landed_profile_binding_findings(receipt: Any) -> list[str]:
    if not isinstance(receipt, dict):
        return ["input.not_object"]
    findings: list[str] = []
    if set(receipt) != _LANDED_TOP_LEVEL_FIELDS:
        findings.append("profile.top_level_surface_mismatch")
    for key, expected in _LANDED_EXPECTED_RECEIPT_FIELDS.items():
        if receipt.get(key) != expected:
            findings.append(f"receipt.{key}_mismatch")
    subject_ref = receipt.get("subject_ref")
    if not isinstance(subject_ref, str) or not subject_ref:
        findings.append("receipt.subject_ref_invalid")
    return findings


def _recompute_authorship(
    report: base.DagrAuthorityContextProducerVerificationReport,
) -> bool:
    return all(
        (
            report.envelope_schema_digest,
            report.profile_schema_digest,
            report.profile_declaration_digest,
            report.extension_schema_digest,
            report.context_schema_digest,
            report.envelope,
            report.profile_declaration,
            report.profile_cross_field,
            report.profile_binding,
            report.extension_schema,
            report.context_schema,
            report.context_digest,
            report.artifact_digest,
            report.projection_binding,
            report.attestation_limits,
            report.raw_content_exclusion,
            report.prohibited_claims_absent,
            report.signature_valid,
            report.issuer_key_resolved,
            report.issuer_key_trusted,
        )
    )


def verify_dagr_authority_context_producer_receipt(
    *,
    receipt_bytes: bytes,
    context_artifact_bytes: bytes,
    keyring: dict[str, Any],
    envelope_schema_bytes: bytes | None = None,
    profile_schema_bytes: bytes | None = None,
    profile_declaration_bytes: bytes | None = None,
    extension_schema_bytes: bytes | None = None,
    context_schema_bytes: bytes | None = None,
) -> base.DagrAuthorityContextProducerVerificationReport:
    """Verify one receipt against the exact landed dagr-runtime surface.

    The base verifier always sees the original bytes.  This function alters no
    receipt, signature preimage, trust material, schema bytes, or artifact bytes.
    """

    report = base.verify_dagr_authority_context_producer_receipt(
        receipt_bytes=receipt_bytes,
        context_artifact_bytes=context_artifact_bytes,
        keyring=keyring,
        envelope_schema_bytes=envelope_schema_bytes,
        profile_schema_bytes=profile_schema_bytes,
        profile_declaration_bytes=profile_declaration_bytes,
        extension_schema_bytes=extension_schema_bytes,
        context_schema_bytes=context_schema_bytes,
    )

    try:
        receipt = base._strict_json_loads(receipt_bytes, label="receipt")
    except ValueError:
        # The base verifier already records the exact parse failure.
        return report

    findings = _landed_profile_binding_findings(receipt)
    report.profile_binding = bool(not findings and report.profile_cross_field)

    if report.profile_binding:
        report.failure_codes = [
            code
            for code in report.failure_codes
            if code not in _STALE_PRE_HARDENING_SURFACE_FAILURES
        ]
    else:
        report.failure_codes.extend(findings)

    report.producer_authorship_established = _recompute_authorship(report)
    return base._dedupe(report)


__all__ = [
    "verify_dagr_authority_context_producer_receipt",
]
