"""Semantic projection conformance for Counterpedia JSON-LD projections.

Scope
-----
This verifier checks the *structural conformance* of a supplied Counterpedia
semantic projection against the projection contract it declares. That is all it
checks and all a PASS means.

Boundary
--------
- semantic validation is not evidence verification
- semantic validation is not admission
- semantic validation is not publication
- semantic validation is not standing
- semantic validation is not truth

A conforming projection may still describe a record that is unadmitted,
unpublished, unverified, or wrong. Conformance says the bytes are shaped as the
contract requires; it says nothing about what they assert.

This module imports no producer code. It validates supplied bytes only, and it
resolves no remote context, ontology, or schema.

Limits
------
- NOT_EVALUATED is not PASS. not_applicable is not PASS.
- Conformance of a projection is not conformance of the record it projects.
- The producer's own declarations (``authority_posture``, ``source_schema_*``)
  are checked for presence and value, not corroborated against the record.
- ``verification_reports[].passed`` is the upstream verifier's assertion as
  carried by the projection. This module neither recomputes it nor gates on it;
  an emitter assertion is not a recomputed finding.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

SEMANTIC_PROJECTION_REPORT_SCHEMA = "arcs.verify.semantic_projection_report.v0.1"
SEMANTIC_PROJECTION_PROFILE = "counterpedia.semantic_projection.v0.1"

# Values the projection contract pins. Checked as declared bytes; this module
# imports nothing from the producer to obtain them.
EXPECTED_SCHEMA = "counterpedia.semantic_projection.v0.1"
EXPECTED_CONTEXT = "https://counterpedia.org/ns/projection/v0.1"
EXPECTED_TYPE = "CounterpediaRenderedRecordProjection"
EXPECTED_SOURCE_SCHEMA_FAMILY = "garpedia.rendered_record"
EXPECTED_SOURCE_SCHEMA_VERSION = 2
EXPECTED_POSTURE = "projection_only"

SEMANTIC_PROJECTION_LIMITS: tuple[str, ...] = (
    "Semantic projection conformance is not evidence verification, admission, "
    "publication, standing, or truth.",
    "A conforming projection may describe an unadmitted, unpublished, or "
    "unverified record.",
    "verification_reports[].passed is carried from the projection as an "
    "emitter assertion; it is not recomputed here and does not gate passed.",
    "NOT_EVALUATED is not PASS. not_applicable is not PASS.",
)

# Aligned with the producer's own guard so a projection cannot be rejected by
# the exporter and accepted here.
FORBIDDEN_AUTHORITY_KEYS = frozenset(
    {
        "admit",
        "admitted",
        "verified",
        "published",
        "standing",
        "grant_standing",
        "authority",
        "authority_state",
    }
)

REQUIRED_SCALARS: tuple[str, ...] = (
    "page_id",
    "route_slug",
    "slug",
    "title",
    "status",
    "corpus_lifecycle",
    "anchor_resolution_status",
    "rendered_at",
    "current_edition",
)

# collection name -> ((string keys...), (non-string key, expected type)...)
REQUIRED_COLLECTIONS: dict[str, tuple[tuple[str, ...], tuple[tuple[str, type], ...]]] = {
    "editions": (("edition_id", "released_at"), (("edition_number", int),)),
    "sources": (("source_id", "source_type", "publication_status"), ()),
    "entities": (("entity_id", "entity_kind"), ()),
    "cross_references": (
        ("cross_reference_id", "target_record_id", "relationship_type"),
        (),
    ),
    "citation_spans": (
        ("span_id", "source_id", "supports_section_id", "verification_state"),
        (),
    ),
    "projections": (
        ("projection_id", "compression_kind"),
        (("reversible_to_record", bool),),
    ),
    "lineage": (("event_id", "occurred_at", "event_type"), ()),
}

OPTIONAL_COLLECTIONS: dict[str, tuple[tuple[str, ...], tuple[tuple[str, type], ...]]] = {
    "verification_reports": (
        ("public_path", "verification_profile", "report_hash"),
        (("passed", bool),),
    ),
}


class Conclusion(str, Enum):
    TRUE = "true"
    FALSE = "false"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class SemanticProjectionFinding:
    code: str
    detail: str


@dataclass(slots=True)
class SemanticProjectionReport:
    """Independent conformance findings for one semantic projection.

    No single master status replaces the findings. ``passed`` requires every
    gated structural conclusion to be TRUE. ``verification_reports_status`` is
    reported separately and does not gate ``passed`` -- an absent optional
    collection is not a failure, and it is not a pass either.
    """

    schema_identity_declared: Conclusion = Conclusion.NOT_EVALUATED
    context_identity_declared: Conclusion = Conclusion.NOT_EVALUATED
    node_type_declared: Conclusion = Conclusion.NOT_EVALUATED
    subject_identity_stable: Conclusion = Conclusion.NOT_EVALUATED
    projection_posture_declared: Conclusion = Conclusion.NOT_EVALUATED
    source_schema_declared: Conclusion = Conclusion.NOT_EVALUATED
    required_scalars_present: Conclusion = Conclusion.NOT_EVALUATED
    required_collections_valid: Conclusion = Conclusion.NOT_EVALUATED
    no_authority_assertion: Conclusion = Conclusion.NOT_EVALUATED

    # Distinct status, not a Boolean conclusion: "valid" | "absent" | "invalid".
    verification_reports_status: str = "not_evaluated"

    findings: list[SemanticProjectionFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(
            c is Conclusion.TRUE
            for c in (
                self.schema_identity_declared,
                self.context_identity_declared,
                self.node_type_declared,
                self.subject_identity_stable,
                self.projection_posture_declared,
                self.source_schema_declared,
                self.required_scalars_present,
                self.required_collections_valid,
                self.no_authority_assertion,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SEMANTIC_PROJECTION_REPORT_SCHEMA,
            "verification_profile": SEMANTIC_PROJECTION_PROFILE,
            "findings": [
                {"code": f.code, "detail": f.detail} for f in self.findings
            ],
            "conclusions": {
                "schema_identity_declared": self.schema_identity_declared.value,
                "context_identity_declared": self.context_identity_declared.value,
                "node_type_declared": self.node_type_declared.value,
                "subject_identity_stable": self.subject_identity_stable.value,
                "projection_posture_declared": self.projection_posture_declared.value,
                "source_schema_declared": self.source_schema_declared.value,
                "required_scalars_present": self.required_scalars_present.value,
                "required_collections_valid": self.required_collections_valid.value,
                "no_authority_assertion": self.no_authority_assertion.value,
            },
            "verification_reports_status": self.verification_reports_status,
            "passed": self.passed,
            "scope": (
                "semantic projection conformance only; not evidence "
                "verification, admission, publication, standing, or truth"
            ),
            "limits": list(SEMANTIC_PROJECTION_LIMITS),
        }


def _check_collection(
    name: str,
    value: Any,
    string_keys: tuple[str, ...],
    typed_keys: tuple[tuple[str, type], ...],
    findings: list[SemanticProjectionFinding],
) -> bool:
    if not isinstance(value, list):
        findings.append(
            SemanticProjectionFinding(
                "COLLECTION_SHAPE_INVALID", f"{name} must be an array"
            )
        )
        return False

    ok = True
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            findings.append(
                SemanticProjectionFinding(
                    "COLLECTION_SHAPE_INVALID",
                    f"{name}[{index}] must be an object",
                )
            )
            ok = False
            continue
        for key in string_keys:
            entry = item.get(key)
            if not isinstance(entry, str) or not entry:
                findings.append(
                    SemanticProjectionFinding(
                        "COLLECTION_FIELD_INVALID",
                        f"{name}[{index}].{key} must be a non-empty string",
                    )
                )
                ok = False
        for key, expected_type in typed_keys:
            entry = item.get(key)
            # bool is a subclass of int; reject that conflation explicitly.
            if not isinstance(entry, expected_type) or (
                expected_type is int and isinstance(entry, bool)
            ):
                findings.append(
                    SemanticProjectionFinding(
                        "COLLECTION_FIELD_INVALID",
                        f"{name}[{index}].{key} must be {expected_type.__name__}",
                    )
                )
                ok = False
    return ok


def verify_semantic_projection(
    projection: Mapping[str, Any],
) -> SemanticProjectionReport:
    """Validate one semantic projection's structural conformance.

    Returns a report of independent conclusions. The input is never mutated;
    an attempted mutation is a hard error rather than a finding.
    """
    before = deepcopy(projection)
    report = SemanticProjectionReport()
    findings = report.findings

    def conclude(ok: bool, code: str, detail: str) -> Conclusion:
        if ok:
            return Conclusion.TRUE
        findings.append(SemanticProjectionFinding(code, detail))
        return Conclusion.FALSE

    report.schema_identity_declared = conclude(
        projection.get("schema") == EXPECTED_SCHEMA,
        "SEMANTIC_SCHEMA_UNKNOWN",
        f"schema must be {EXPECTED_SCHEMA}",
    )
    report.context_identity_declared = conclude(
        projection.get("@context") == EXPECTED_CONTEXT,
        "CONTEXT_IDENTITY_INVALID",
        f"@context must be {EXPECTED_CONTEXT}",
    )
    report.node_type_declared = conclude(
        projection.get("@type") == EXPECTED_TYPE,
        "NODE_TYPE_INVALID",
        f"@type must be {EXPECTED_TYPE}",
    )

    subject = projection.get("@id")
    report.subject_identity_stable = conclude(
        isinstance(subject, str) and bool(subject) and not subject.startswith("_:"),
        "SUBJECT_IDENTITY_INVALID",
        "@id must be a stable non-blank governed identifier",
    )

    report.projection_posture_declared = conclude(
        projection.get("authority_posture") == EXPECTED_POSTURE,
        "INVALID_PROJECTION_POSTURE",
        f"authority_posture must be {EXPECTED_POSTURE}",
    )

    report.source_schema_declared = conclude(
        projection.get("source_schema_family") == EXPECTED_SOURCE_SCHEMA_FAMILY
        and projection.get("source_schema_version") == EXPECTED_SOURCE_SCHEMA_VERSION,
        "SOURCE_SCHEMA_UNDECLARED",
        "source_schema_family/source_schema_version must identify the "
        "owning record contract",
    )

    missing = [
        name
        for name in REQUIRED_SCALARS
        if not isinstance(projection.get(name), str) or not projection.get(name)
    ]
    for name in missing:
        findings.append(
            SemanticProjectionFinding(
                "REQUIRED_FIELD_MISSING",
                f"required field missing or not a non-empty string: {name}",
            )
        )
    report.required_scalars_present = (
        Conclusion.TRUE if not missing else Conclusion.FALSE
    )

    collections_ok = True
    for name, (string_keys, typed_keys) in REQUIRED_COLLECTIONS.items():
        if name not in projection:
            findings.append(
                SemanticProjectionFinding(
                    "REQUIRED_FIELD_MISSING", f"required collection missing: {name}"
                )
            )
            collections_ok = False
            continue
        if not _check_collection(
            name, projection[name], string_keys, typed_keys, findings
        ):
            collections_ok = False
    report.required_collections_valid = (
        Conclusion.TRUE if collections_ok else Conclusion.FALSE
    )

    present_forbidden = sorted(FORBIDDEN_AUTHORITY_KEYS.intersection(projection.keys()))
    for key in present_forbidden:
        findings.append(
            SemanticProjectionFinding(
                "FORBIDDEN_AUTHORITY_ASSERTION",
                f"projection may not assert authority field: {key}",
            )
        )
    report.no_authority_assertion = (
        Conclusion.TRUE if not present_forbidden else Conclusion.FALSE
    )

    # Optional collection: absent is neither pass nor fail, and is reported as
    # its own status rather than folded into the gated conclusions.
    name, (string_keys, typed_keys) = next(iter(OPTIONAL_COLLECTIONS.items()))
    if name not in projection:
        report.verification_reports_status = "absent"
    elif _check_collection(name, projection[name], string_keys, typed_keys, findings):
        report.verification_reports_status = "valid"
    else:
        report.verification_reports_status = "invalid"

    if projection != before:
        raise RuntimeError("semantic projection verifier mutated its input")

    return report
