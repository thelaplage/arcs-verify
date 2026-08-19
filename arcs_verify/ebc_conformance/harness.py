"""Provisional conformance harness for candidate EBC vectors.

NON-NORMATIVE / PROVISIONAL -- see the package README for the full scope
statement. In short: this module recomputes digests declared by a candidate
EBC vector (horizon / context / omission / boundary / doctrine-manifest /
execution-commitment) from the vector's own bytes, using an independently
reimplemented canonicalization scheme (``arcs_verify.ebc_conformance.canonical``),
and reports per-check PASS / FAIL / NOT_EVALUATED conclusions plus a list of
findings.

This is deliberately NOT the ``VerificationReport`` used elsewhere in this
repository for SRS receipts (``arcs_verify.verifier.VerificationReport``). It
shares no class, no field vocabulary, and no ``passed`` contract with it. An
EBC conformance PASS means only: the declared digests are byte-reproducible
under this scheme and the cross-artifact digest references are internally
consistent. It does NOT mean the receipt is admitted, trusted, has standing,
or is true -- those questions have no answer here, by design (see README).

This module imports no producer code, is not imported by any admission or
execution path in this repository, and is not exported from
``arcs_verify.__init__``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from arcs_verify.ebc_conformance import canonical

EBC_CONFORMANCE_REPORT_SCHEMA = "arcs.verify.ebc_conformance_report.v0.1.provisional"
EBC_CANDIDATE_ID = "dagr.candidates.epistemic-boundary-commitment.v0.1"

# Field names that would encode an authority/admission/standing verdict onto a
# horizon-shaped projection. Their presence is flagged as an out-of-scope
# field, never silently accepted -- mirroring FORBIDDEN_AUTHORITY_KEYS in
# arcs_verify.semantic_projection, which this harness deliberately follows for
# the same reason: a structural conformance check must not become a backdoor
# authority channel.
FORBIDDEN_HORIZON_KEYS = frozenset(
    {
        "standing",
        "admit",
        "admitted",
        "verified",
        "trusted",
        "published",
        "authority",
        "authority_state",
        "grant_standing",
    }
)

REQUIRED_HORIZON_FIELDS: tuple[str, ...] = (
    "as_of",
    "scope_ref",
    "included_fields",
    "excluded_fields",
)
REQUIRED_CONTEXT_FIELDS: tuple[str, ...] = ("query_ref", "content_ref")
REQUIRED_OMISSION_FIELDS: tuple[str, ...] = ("horizon_digest", "reasons")
REQUIRED_DOCTRINE_MANIFEST_FIELDS: tuple[str, ...] = ("candidate_id", "clauses")
REQUIRED_BOUNDARY_FIELDS: tuple[str, ...] = (
    "horizon_digest",
    "context_digest",
    "omission_digest",
    "doctrine_manifest_digest",
)
REQUIRED_COMMITMENT_FIELDS: tuple[str, ...] = (
    "boundary_digest",
    "pre_commit_ref",
    "output_ref",
)


class EBCConclusion(str, Enum):
    TRUE = "true"
    FALSE = "false"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class EBCFinding:
    code: str
    detail: str


def _present(container: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return all(k in container and container[k] is not None for k in keys)


@dataclass(slots=True)
class EBCConformanceReport:
    """Independent, per-check conformance conclusions for one EBC vector.

    Every field is a distinct ``EBCConclusion`` (or, for ``witness_status``, a
    tri-state string mirroring the optional-collection convention used by
    ``SemanticProjectionReport.verification_reports_status``). There is no
    single master verdict field named after this repository's
    ``VerificationReport``; ``reproducible`` below is this report's own,
    separately named, narrowly scoped aggregate -- cryptographic
    reproducibility and cross-reference consistency ONLY, never truth,
    admission, or standing.
    """

    horizon_digest_reproducible: EBCConclusion = EBCConclusion.NOT_EVALUATED
    horizon_required_fields_present: EBCConclusion = EBCConclusion.NOT_EVALUATED
    horizon_no_out_of_scope_fields: EBCConclusion = EBCConclusion.NOT_EVALUATED
    context_digest_reproducible: EBCConclusion = EBCConclusion.NOT_EVALUATED
    context_required_fields_present: EBCConclusion = EBCConclusion.NOT_EVALUATED
    omission_digest_reproducible: EBCConclusion = EBCConclusion.NOT_EVALUATED
    omission_binds_declared_horizon: EBCConclusion = EBCConclusion.NOT_EVALUATED
    doctrine_manifest_digest_reproducible: EBCConclusion = EBCConclusion.NOT_EVALUATED
    boundary_digest_reproducible: EBCConclusion = EBCConclusion.NOT_EVALUATED
    boundary_references_consistent: EBCConclusion = EBCConclusion.NOT_EVALUATED
    commitment_digest_reproducible: EBCConclusion = EBCConclusion.NOT_EVALUATED
    commitment_has_precommit_reference: EBCConclusion = EBCConclusion.NOT_EVALUATED
    all_digests_well_formed: EBCConclusion = EBCConclusion.NOT_EVALUATED

    # Optional witness material: presence/shape only, non-gating -- mirrors
    # SemanticProjectionReport.verification_reports_status.
    witness_status: str = "not_evaluated"

    findings: list[EBCFinding] = field(default_factory=list)

    @property
    def reproducible(self) -> bool:
        """Narrow aggregate: every gated check concluded TRUE.

        Named ``reproducible`` -- not ``passed`` -- to avoid inviting the
        reading that this means admitted, trusted, or true. See the module
        and README docstrings.
        """
        gated = (
            self.horizon_digest_reproducible,
            self.horizon_required_fields_present,
            self.horizon_no_out_of_scope_fields,
            self.context_digest_reproducible,
            self.context_required_fields_present,
            self.omission_digest_reproducible,
            self.omission_binds_declared_horizon,
            self.doctrine_manifest_digest_reproducible,
            self.boundary_digest_reproducible,
            self.boundary_references_consistent,
            self.commitment_digest_reproducible,
            self.commitment_has_precommit_reference,
            self.all_digests_well_formed,
        )
        return all(c is EBCConclusion.TRUE for c in gated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": EBC_CONFORMANCE_REPORT_SCHEMA,
            "candidate_id": EBC_CANDIDATE_ID,
            "provisional": True,
            "conclusions": {
                "horizon_digest_reproducible": self.horizon_digest_reproducible.value,
                "horizon_required_fields_present": self.horizon_required_fields_present.value,
                "horizon_no_out_of_scope_fields": self.horizon_no_out_of_scope_fields.value,
                "context_digest_reproducible": self.context_digest_reproducible.value,
                "context_required_fields_present": self.context_required_fields_present.value,
                "omission_digest_reproducible": self.omission_digest_reproducible.value,
                "omission_binds_declared_horizon": self.omission_binds_declared_horizon.value,
                "doctrine_manifest_digest_reproducible": self.doctrine_manifest_digest_reproducible.value,
                "boundary_digest_reproducible": self.boundary_digest_reproducible.value,
                "boundary_references_consistent": self.boundary_references_consistent.value,
                "commitment_digest_reproducible": self.commitment_digest_reproducible.value,
                "commitment_has_precommit_reference": self.commitment_has_precommit_reference.value,
                "all_digests_well_formed": self.all_digests_well_formed.value,
            },
            "witness_status": self.witness_status,
            "reproducible": self.reproducible,
            "findings": [{"code": f.code, "detail": f.detail} for f in self.findings],
        }


def verify_ebc_vector(vector: dict[str, Any]) -> EBCConformanceReport:
    """Independently recompute and cross-check one candidate EBC vector.

    ``vector`` is expected to carry ``horizon``, ``context``, ``omission``,
    ``doctrine_manifest``, ``boundary``, and ``execution_commitment`` objects,
    each with a declared ``digest`` field, plus an optional ``witness`` object.
    Missing top-level sections leave their checks NOT_EVALUATED (never FALSE,
    never coerced to TRUE) and are recorded as findings.
    """
    report = EBCConformanceReport()
    all_digests: list[Any] = []
    findings: list[EBCFinding] = []

    horizon = vector.get("horizon")
    if isinstance(horizon, dict):
        if _present(horizon, REQUIRED_HORIZON_FIELDS):
            report.horizon_required_fields_present = EBCConclusion.TRUE
        else:
            report.horizon_required_fields_present = EBCConclusion.FALSE
            missing = [k for k in REQUIRED_HORIZON_FIELDS if k not in horizon or horizon[k] is None]
            findings.append(
                EBCFinding("horizon_incomplete", f"horizon missing required field(s): {missing}")
            )

        forbidden_present = sorted(FORBIDDEN_HORIZON_KEYS & horizon.keys())
        if forbidden_present:
            report.horizon_no_out_of_scope_fields = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "horizon_out_of_scope_field",
                    f"horizon carries out-of-scope authority/standing field(s): {forbidden_present}; "
                    "a horizon/Countergraph-style projection has no authority to assert standing",
                )
            )
        else:
            report.horizon_no_out_of_scope_fields = EBCConclusion.TRUE

        declared_horizon_digest = horizon.get("digest")
        all_digests.append(declared_horizon_digest)
        recomputed_horizon_digest = canonical.horizon_hash(horizon)
        if declared_horizon_digest == recomputed_horizon_digest:
            report.horizon_digest_reproducible = EBCConclusion.TRUE
        else:
            report.horizon_digest_reproducible = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "horizon_digest_mismatch",
                    f"declared={declared_horizon_digest!r} recomputed={recomputed_horizon_digest!r}",
                )
            )
    else:
        findings.append(EBCFinding("horizon_absent", "vector has no horizon section"))
        recomputed_horizon_digest = None

    context = vector.get("context")
    if isinstance(context, dict):
        report.context_required_fields_present = (
            EBCConclusion.TRUE if _present(context, REQUIRED_CONTEXT_FIELDS) else EBCConclusion.FALSE
        )
        if report.context_required_fields_present is EBCConclusion.FALSE:
            findings.append(EBCFinding("context_incomplete", "context missing required field(s)"))

        declared_context_digest = context.get("digest")
        all_digests.append(declared_context_digest)
        recomputed_context_digest = canonical.context_hash(context)
        if declared_context_digest == recomputed_context_digest:
            report.context_digest_reproducible = EBCConclusion.TRUE
        else:
            report.context_digest_reproducible = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "context_digest_mismatch",
                    f"declared={declared_context_digest!r} recomputed={recomputed_context_digest!r}",
                )
            )
    else:
        findings.append(EBCFinding("context_absent", "vector has no context section"))
        recomputed_context_digest = None

    omission = vector.get("omission")
    if isinstance(omission, dict):
        if not _present(omission, REQUIRED_OMISSION_FIELDS):
            findings.append(EBCFinding("omission_incomplete", "omission missing required field(s)"))

        declared_omission_digest = omission.get("digest")
        all_digests.append(declared_omission_digest)
        recomputed_omission_digest = canonical.omission_hash(omission)
        if declared_omission_digest == recomputed_omission_digest:
            report.omission_digest_reproducible = EBCConclusion.TRUE
        else:
            report.omission_digest_reproducible = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "omission_digest_mismatch",
                    f"declared={declared_omission_digest!r} recomputed={recomputed_omission_digest!r}; "
                    "this includes the omission's reasons -- a mutated omission reason changes the "
                    "omission root and is caught here",
                )
            )

        all_digests.append(omission.get("horizon_digest"))
        omission_horizon_ref = omission.get("horizon_digest")
        if recomputed_horizon_digest is not None and omission_horizon_ref == recomputed_horizon_digest:
            report.omission_binds_declared_horizon = EBCConclusion.TRUE
        elif recomputed_horizon_digest is None:
            report.omission_binds_declared_horizon = EBCConclusion.NOT_EVALUATED
        else:
            report.omission_binds_declared_horizon = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "omission_horizon_binding_mismatch",
                    f"omission.horizon_digest={omission_horizon_ref!r} does not match the "
                    f"independently recomputed horizon digest={recomputed_horizon_digest!r}",
                )
            )
    else:
        findings.append(EBCFinding("omission_absent", "vector has no omission section"))
        recomputed_omission_digest = None

    doctrine_manifest = vector.get("doctrine_manifest")
    if isinstance(doctrine_manifest, dict):
        if not _present(doctrine_manifest, REQUIRED_DOCTRINE_MANIFEST_FIELDS):
            findings.append(
                EBCFinding("doctrine_manifest_incomplete", "doctrine_manifest missing required field(s)")
            )

        declared_manifest_digest = doctrine_manifest.get("digest")
        all_digests.append(declared_manifest_digest)
        recomputed_manifest_digest = canonical.doctrine_manifest_hash(doctrine_manifest)
        if declared_manifest_digest == recomputed_manifest_digest:
            report.doctrine_manifest_digest_reproducible = EBCConclusion.TRUE
        else:
            report.doctrine_manifest_digest_reproducible = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "doctrine_manifest_digest_mismatch",
                    f"declared={declared_manifest_digest!r} recomputed={recomputed_manifest_digest!r}",
                )
            )
    else:
        findings.append(
            EBCFinding("doctrine_manifest_absent", "vector has no doctrine_manifest section")
        )
        recomputed_manifest_digest = None

    boundary = vector.get("boundary")
    recomputed_boundary_digest = None
    if isinstance(boundary, dict):
        if not _present(boundary, REQUIRED_BOUNDARY_FIELDS):
            findings.append(EBCFinding("boundary_incomplete", "boundary missing required field(s)"))

        declared_boundary_digest = boundary.get("digest")
        all_digests.append(declared_boundary_digest)
        for ref_key in REQUIRED_BOUNDARY_FIELDS:
            all_digests.append(boundary.get(ref_key))
        recomputed_boundary_digest = canonical.boundary_hash(boundary)
        if declared_boundary_digest == recomputed_boundary_digest:
            report.boundary_digest_reproducible = EBCConclusion.TRUE
        else:
            report.boundary_digest_reproducible = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "boundary_digest_mismatch",
                    f"declared={declared_boundary_digest!r} recomputed={recomputed_boundary_digest!r}; "
                    "this also catches a boundary digest computed under the wrong domain prefix, since "
                    "this harness always recomputes under DAGR-BOUNDARY-V0.1:",
                )
            )

        reference_checks = {
            "horizon_digest": recomputed_horizon_digest,
            "context_digest": recomputed_context_digest,
            "omission_digest": recomputed_omission_digest,
            "doctrine_manifest_digest": recomputed_manifest_digest,
        }
        mismatches = []
        any_unevaluated = False
        for key, recomputed_value in reference_checks.items():
            if recomputed_value is None:
                any_unevaluated = True
                continue
            if boundary.get(key) != recomputed_value:
                mismatches.append(key)
        if mismatches:
            report.boundary_references_consistent = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "boundary_reference_mismatch",
                    f"boundary field(s) do not match independently recomputed digests: {mismatches}",
                )
            )
        elif any_unevaluated:
            report.boundary_references_consistent = EBCConclusion.NOT_EVALUATED
        else:
            report.boundary_references_consistent = EBCConclusion.TRUE
    else:
        findings.append(EBCFinding("boundary_absent", "vector has no boundary section"))

    commitment = vector.get("execution_commitment")
    if isinstance(commitment, dict):
        if not _present(commitment, REQUIRED_COMMITMENT_FIELDS):
            findings.append(
                EBCFinding("commitment_incomplete", "execution_commitment missing required field(s)")
            )

        declared_commitment_digest = commitment.get("digest")
        all_digests.append(declared_commitment_digest)
        recomputed_commitment_digest = canonical.commitment_hash(commitment)
        if declared_commitment_digest == recomputed_commitment_digest:
            report.commitment_digest_reproducible = EBCConclusion.TRUE
        else:
            report.commitment_digest_reproducible = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "commitment_digest_mismatch",
                    f"declared={declared_commitment_digest!r} recomputed={recomputed_commitment_digest!r}",
                )
            )

        all_digests.append(commitment.get("boundary_digest"))
        all_digests.append(commitment.get("output_ref"))
        if commitment.get("pre_commit_ref") is not None:
            all_digests.append(commitment.get("pre_commit_ref"))

        pre_commit_ref = commitment.get("pre_commit_ref")
        if pre_commit_ref and canonical.is_well_formed_digest(pre_commit_ref):
            report.commitment_has_precommit_reference = EBCConclusion.TRUE
        else:
            report.commitment_has_precommit_reference = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "commitment_missing_precommit_reference",
                    "execution_commitment is presented without a well-formed pre_commit_ref -- an "
                    "output/execution commitment must reference a corresponding pre-commit",
                )
            )
    else:
        findings.append(
            EBCFinding("execution_commitment_absent", "vector has no execution_commitment section")
        )

    witness = vector.get("witness")
    if witness is None:
        report.witness_status = "absent"
    elif isinstance(witness, dict):
        report.witness_status = "present"
    else:
        report.witness_status = "invalid"
        findings.append(EBCFinding("witness_invalid", "witness section is present but not an object"))

    checked_digests = [d for d in all_digests if d is not None]
    if checked_digests:
        malformed = [d for d in checked_digests if not canonical.is_well_formed_digest(d)]
        if malformed:
            report.all_digests_well_formed = EBCConclusion.FALSE
            findings.append(
                EBCFinding(
                    "malformed_digest_format",
                    f"{len(malformed)} declared digest(s) are not well-formed sha256: hex digests: {malformed}",
                )
            )
        else:
            report.all_digests_well_formed = EBCConclusion.TRUE

    report.findings = findings
    return report
