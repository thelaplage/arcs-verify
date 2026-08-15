from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

SEMANTIC_PROJECTION_SCHEMA = "counterpedia.semantic_projection.v0.1"
SEMANTIC_VALIDATION_KIND = "semantic_projection_conformance"

FORBIDDEN_AUTHORITY_KEYS = {
    "admit",
    "admitted",
    "verified",
    "published",
    "standing",
    "grant_standing",
    "authority_state",
}


@dataclass(frozen=True)
class SemanticProjectionFinding:
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def verify_semantic_projection(projection: Mapping[str, Any]) -> dict[str, Any]:
    """Validate projection conformance only; never evidentiary or governance state."""
    before = deepcopy(projection)
    findings: list[SemanticProjectionFinding] = []

    if projection.get("schema") != SEMANTIC_PROJECTION_SCHEMA:
        findings.append(SemanticProjectionFinding(
            "SEMANTIC_SCHEMA_UNKNOWN", "schema", "unsupported semantic projection schema"
        ))

    required = ("@context", "@id", "@type", "schema", "authority_posture", "record_type")
    for field in required:
        if field not in projection:
            findings.append(SemanticProjectionFinding(
                "REQUIRED_FIELD_MISSING", field, f"required field missing: {field}"
            ))

    if projection.get("authority_posture") != "projection_only":
        findings.append(SemanticProjectionFinding(
            "INVALID_PROJECTION_POSTURE",
            "authority_posture",
            "semantic projection must be explicitly projection_only",
        ))

    subject = projection.get("@id")
    if "@id" in projection and (not isinstance(subject, str) or not subject or subject.startswith("_:")):
        findings.append(SemanticProjectionFinding(
            "INVALID_REFERENCE_SHAPE", "@id", "governed subject identity must be a stable non-blank string"
        ))

    for key in sorted(FORBIDDEN_AUTHORITY_KEYS.intersection(projection.keys())):
        findings.append(SemanticProjectionFinding(
            "FORBIDDEN_AUTHORITY_ASSERTION", key, f"projection may not assert authority field: {key}"
        ))

    for field in ("claim_refs", "source_refs", "history_refs", "verification_report_refs"):
        value = projection.get(field, [])
        if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
            findings.append(SemanticProjectionFinding(
                "INVALID_REFERENCE_SHAPE", field, f"{field} must be an array of non-empty strings"
            ))

    if projection != before:
        raise RuntimeError("semantic projection verifier mutated its input")

    return {
        "schema": "arcs.verify.semantic_projection_report.v0.1",
        "verification_kind": SEMANTIC_VALIDATION_KIND,
        "status": "PASS" if not findings else "FAIL",
        "scope": "semantic projection conformance only; not evidence verification, admission, publication, standing, or truth",
        "findings": [finding.to_dict() for finding in findings],
        "authority_movement": 0,
    }
