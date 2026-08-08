"""Independent sequence-level verifier for dagr.ingest_run.v0.1 sequences.

This module recomputes structural, linkage, digest-continuity, and coverage
findings for a DAGR ingest run sequence from serialized artifacts:
  - a dagr.ingest_run.v0.1 neutral run document,
  - a D4-produced SRS receipt-set manifest (dagr-ingest.srs-receipt-set.v0.1),
  - the individual SRS receipt files enumerated in the manifest, and
  - the SRS profile manifest file (for pin verification).

Authority boundaries
--------------------
- This verifier operates on *serialized bytes only* (deserialized from JSON).
  It does not import dagr_ingest, garp_ingest, or any D4/D3 producer code.
- Findings are independently recomputed from the supplied artifacts.
  They are not emitter assertions.
- Sequence integrity does not prove the underlying ingest event occurred.
- Sequence integrity does not prove source truth or content completeness.
- Sequence integrity does not prove policy correctness.
- Profile-manifest pin match does not prove the receipts satisfy the profile;
  profile conformance is a separate concern not evaluated by this verifier.
- NOT_EVALUATED is not PASS. not_applicable is not PASS.

Independent findings produced
-----------------------------
- run_doc_schema: run_doc["schema"] == "dagr.ingest_run.v0.1"
- boundary_declarations: run_doc["boundary"]["no_arcs_srs"],
  no_receipts_issued, and no_network are all True
- receipt_set_manifest_schema: manifest["schema"] == "dagr-ingest.srs-receipt-set.v0.1"
- run_id_linkage: manifest["run_id"] == run_doc["run_id"]
- profile_manifest_pin: independently recomputed sha256 of the profile
  manifest file matches manifest["profile_manifest_sha256"]
- per_receipt_checks: for each "emitted" entry:
    receipt_file_present, receipt_parse, protocol_binding,
    subject_ref_manifest, subject_binding, corpus_manifest_ref,
    raw_content_absent, artifact_classes_excluded
- unique_artifact_coverage: every run_doc["unique_artifacts"] entry with
  parser_id non-null and is_duplicate_content == False appears in the
  manifest as emitted
- duplicate_posture: entries with is_duplicate_content == True do not appear
  as emitted
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

SEQUENCE_SCHEMA = "arcs_verify.ingest_run_sequence_report.v0_1"
SEQUENCE_PROFILE = "arcs_verify.ingest_run_sequence.v0_1"

RUN_DOC_SCHEMA = "dagr.ingest_run.v0.1"
RECEIPT_SET_MANIFEST_SCHEMA = "dagr-ingest.srs-receipt-set.v0.1"
EXPECTED_PROTOCOL_BINDING = "dagr-ingest/v0.1"

# Required boundary declarations in run_doc["boundary"]
REQUIRED_BOUNDARY_DECLARATIONS: tuple[str, ...] = (
    "no_arcs_srs",
    "no_receipts_issued",
    "no_network",
)

# Raw content field names that must not appear in any emitted SRS receipt.
# Reproduced here independently from D4 so the verifier imports no producer code.
FORBIDDEN_RAW_RECEIPT_FIELDS: frozenset[str] = frozenset({
    "raw_publication_bytes",
    "raw_frontmatter_yaml",
    "raw_body_text",
})

# Artifact classes that must be present in artifact_classes_excluded for every
# emitted dagr-ingest/v0.1 receipt.
REQUIRED_EXCLUSIONS: frozenset[str] = frozenset({
    "raw_publication_bytes",
    "raw_frontmatter_yaml",
    "raw_body_text",
})

SEQUENCE_LIMITATIONS: list[str] = [
    (
        "Sequence integrity does not prove the underlying ingest event occurred. "
        "A structurally valid sequence does not establish that the files were "
        "read, parsed, or ingested at the declared time."
    ),
    (
        "Sequence integrity does not prove source truth or content completeness. "
        "The verifier does not retrieve or inspect the referenced publication "
        "artifacts."
    ),
    (
        "Sequence integrity does not prove policy correctness. A structurally "
        "valid sequence may not satisfy the governing policy pack."
    ),
    (
        "Profile-manifest pin match does not prove the receipts satisfy the "
        "profile. Profile conformance is a separate concern that the sequence "
        "verifier deliberately does not evaluate."
    ),
    (
        "run_doc boundary declarations are checked structurally — the verifier "
        "confirms they are present and True but does not independently verify "
        "that the run was actually isolated from those systems."
    ),
    (
        "NOT_EVALUATED is not PASS. not_applicable is not PASS."
    ),
]


class Conclusion(str, Enum):
    TRUE = "true"
    FALSE = "false"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class SequenceFinding:
    code: str
    detail: str


@dataclass(slots=True)
class IngestRunSequenceReport:
    """Independent findings for a dagr.ingest_run.v0.1 sequence.

    No single master status replaces findings. ``passed`` requires all
    structural findings to be TRUE. Findings that are NOT_EVALUATED do not
    gate passed, but FALSE does.
    """

    # Run document findings
    run_doc_schema: Conclusion = Conclusion.NOT_EVALUATED
    boundary_declarations: Conclusion = Conclusion.NOT_EVALUATED

    # Manifest linkage findings
    receipt_set_manifest_schema: Conclusion = Conclusion.NOT_EVALUATED
    run_id_linkage: Conclusion = Conclusion.NOT_EVALUATED
    profile_manifest_pin: Conclusion = Conclusion.NOT_EVALUATED

    # Per-receipt findings (aggregated)
    receipt_file_present: Conclusion = Conclusion.NOT_EVALUATED
    receipt_parse: Conclusion = Conclusion.NOT_EVALUATED
    protocol_binding: Conclusion = Conclusion.NOT_EVALUATED
    subject_ref_manifest: Conclusion = Conclusion.NOT_EVALUATED
    subject_binding: Conclusion = Conclusion.NOT_EVALUATED
    corpus_manifest_ref: Conclusion = Conclusion.NOT_EVALUATED
    raw_content_absent: Conclusion = Conclusion.NOT_EVALUATED
    artifact_classes_excluded: Conclusion = Conclusion.NOT_EVALUATED

    # Coverage findings
    unique_artifact_coverage: Conclusion = Conclusion.NOT_EVALUATED
    duplicate_posture: Conclusion = Conclusion.NOT_EVALUATED

    findings: list[SequenceFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        def _gates(c: Conclusion) -> bool:
            return c is not Conclusion.FALSE

        return (
            self.run_doc_schema is Conclusion.TRUE
            and self.boundary_declarations is Conclusion.TRUE
            and self.receipt_set_manifest_schema is Conclusion.TRUE
            and self.run_id_linkage is Conclusion.TRUE
            and self.profile_manifest_pin is Conclusion.TRUE
            and _gates(self.receipt_file_present)
            and _gates(self.receipt_parse)
            and _gates(self.protocol_binding)
            and _gates(self.subject_ref_manifest)
            and _gates(self.subject_binding)
            and _gates(self.corpus_manifest_ref)
            and _gates(self.raw_content_absent)
            and _gates(self.artifact_classes_excluded)
            and _gates(self.unique_artifact_coverage)
            and _gates(self.duplicate_posture)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SEQUENCE_SCHEMA,
            "verification_profile": SEQUENCE_PROFILE,
            "findings": [
                {"code": f.code, "detail": f.detail}
                for f in self.findings
            ],
            "conclusions": {
                "run_doc_schema": self.run_doc_schema.value,
                "boundary_declarations": self.boundary_declarations.value,
                "receipt_set_manifest_schema": (
                    self.receipt_set_manifest_schema.value
                ),
                "run_id_linkage": self.run_id_linkage.value,
                "profile_manifest_pin": self.profile_manifest_pin.value,
                "receipt_file_present": self.receipt_file_present.value,
                "receipt_parse": self.receipt_parse.value,
                "protocol_binding": self.protocol_binding.value,
                "subject_ref_manifest": self.subject_ref_manifest.value,
                "subject_binding": self.subject_binding.value,
                "corpus_manifest_ref": self.corpus_manifest_ref.value,
                "raw_content_absent": self.raw_content_absent.value,
                "artifact_classes_excluded": (
                    self.artifact_classes_excluded.value
                ),
                "unique_artifact_coverage": self.unique_artifact_coverage.value,
                "duplicate_posture": self.duplicate_posture.value,
            },
            "passed": self.passed,
            "limitations": SEQUENCE_LIMITATIONS,
        }


def _fail(
    report: IngestRunSequenceReport,
    code: str,
    detail: str,
) -> None:
    report.findings.append(SequenceFinding(code=code, detail=detail))


def verify_ingest_run_sequence(
    run_doc_path: Path,
    receipt_set_manifest_path: Path,
    receipts_dir: Path,
    profile_manifest_path: Path,
) -> IngestRunSequenceReport:
    """Independently verify the linkage between a dagr.ingest_run.v0.1 run
    document, a D4-produced SRS receipt-set manifest, and the individual
    SRS receipts.

    Parameters
    ----------
    run_doc_path:
        Path to the dagr.ingest_run.v0.1 run document JSON file.
    receipt_set_manifest_path:
        Path to the dagr-ingest.srs-receipt-set.v0.1 manifest JSON file.
    receipts_dir:
        Directory containing the individual receipt JSON files referenced
        by the manifest's receipts array.
    profile_manifest_path:
        Path to the SRS profile manifest file whose sha256 is pinned in
        the receipt-set manifest.
    """
    report = IngestRunSequenceReport()

    # -----------------------------------------------------------------------
    # Load run document
    # -----------------------------------------------------------------------
    try:
        run_doc_text = run_doc_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fail(report, "INGEST_RUN_SCHEMA_MISMATCH", f"run doc unreadable: {exc}")
        report.run_doc_schema = Conclusion.FALSE
        _propagate_false_early(report)
        return report

    try:
        run_doc: dict[str, Any] = json.loads(run_doc_text)
    except json.JSONDecodeError as exc:
        _fail(report, "INGEST_RUN_SCHEMA_MISMATCH", f"run doc malformed JSON: {exc}")
        report.run_doc_schema = Conclusion.FALSE
        _propagate_false_early(report)
        return report

    if not isinstance(run_doc, dict):
        _fail(
            report,
            "INGEST_RUN_SCHEMA_MISMATCH",
            "run doc is not a JSON object",
        )
        report.run_doc_schema = Conclusion.FALSE
        _propagate_false_early(report)
        return report

    # -----------------------------------------------------------------------
    # Check 1: Run doc schema discriminator
    # -----------------------------------------------------------------------
    run_schema = run_doc.get("schema")
    if run_schema != RUN_DOC_SCHEMA:
        _fail(
            report,
            "INGEST_RUN_SCHEMA_MISMATCH",
            (
                f"run_doc[\"schema\"] == {run_schema!r}; "
                f"expected {RUN_DOC_SCHEMA!r}"
            ),
        )
        report.run_doc_schema = Conclusion.FALSE
    else:
        report.run_doc_schema = Conclusion.TRUE

    # -----------------------------------------------------------------------
    # Check 2: Run boundary declarations
    # -----------------------------------------------------------------------
    boundary = run_doc.get("boundary")
    boundary_ok = True
    if not isinstance(boundary, dict):
        _fail(
            report,
            "INGEST_RUN_BOUNDARY_VIOLATION",
            "run_doc[\"boundary\"] is absent or not an object",
        )
        boundary_ok = False
    else:
        for key in REQUIRED_BOUNDARY_DECLARATIONS:
            if boundary.get(key) is not True:
                _fail(
                    report,
                    "INGEST_RUN_BOUNDARY_VIOLATION",
                    (
                        f"run_doc[\"boundary\"][\"{key}\"] is not True "
                        f"(got {boundary.get(key)!r})"
                    ),
                )
                boundary_ok = False

    report.boundary_declarations = (
        Conclusion.TRUE if boundary_ok else Conclusion.FALSE
    )

    # -----------------------------------------------------------------------
    # Load receipt-set manifest
    # -----------------------------------------------------------------------
    try:
        manifest_text = receipt_set_manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            f"manifest unreadable: {exc}",
        )
        report.receipt_set_manifest_schema = Conclusion.FALSE
        _propagate_false_on_missing_manifest(report)
        return report

    try:
        manifest: dict[str, Any] = json.loads(manifest_text)
    except json.JSONDecodeError as exc:
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            f"manifest malformed JSON: {exc}",
        )
        report.receipt_set_manifest_schema = Conclusion.FALSE
        _propagate_false_on_missing_manifest(report)
        return report

    if not isinstance(manifest, dict):
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            "manifest is not a JSON object",
        )
        report.receipt_set_manifest_schema = Conclusion.FALSE
        _propagate_false_on_missing_manifest(report)
        return report

    # -----------------------------------------------------------------------
    # Check 3: Receipt-set manifest schema
    # -----------------------------------------------------------------------
    manifest_schema = manifest.get("schema")
    if manifest_schema != RECEIPT_SET_MANIFEST_SCHEMA:
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            (
                f"manifest[\"schema\"] == {manifest_schema!r}; "
                f"expected {RECEIPT_SET_MANIFEST_SCHEMA!r}"
            ),
        )
        report.receipt_set_manifest_schema = Conclusion.FALSE
    else:
        report.receipt_set_manifest_schema = Conclusion.TRUE

    # -----------------------------------------------------------------------
    # Check 4: Run ID linkage
    # -----------------------------------------------------------------------
    run_id = run_doc.get("run_id")
    manifest_run_id = manifest.get("run_id")
    if run_id != manifest_run_id:
        _fail(
            report,
            "RUN_ID_MISMATCH",
            (
                f"manifest[\"run_id\"] == {manifest_run_id!r}; "
                f"run_doc[\"run_id\"] == {run_id!r}"
            ),
        )
        report.run_id_linkage = Conclusion.FALSE
    else:
        report.run_id_linkage = Conclusion.TRUE

    # -----------------------------------------------------------------------
    # Check 5: Profile manifest pin (independently recompute sha256)
    # -----------------------------------------------------------------------
    try:
        profile_manifest_bytes = profile_manifest_path.read_bytes()
    except OSError as exc:
        _fail(
            report,
            "PROFILE_MANIFEST_PIN_MISMATCH",
            f"profile manifest unreadable: {exc}",
        )
        report.profile_manifest_pin = Conclusion.FALSE
    else:
        actual_sha256 = hashlib.sha256(profile_manifest_bytes).hexdigest()
        declared_sha256 = manifest.get("profile_manifest_sha256", "")
        if actual_sha256 != declared_sha256:
            _fail(
                report,
                "PROFILE_MANIFEST_PIN_MISMATCH",
                (
                    f"profile manifest sha256 recomputed as {actual_sha256!r}; "
                    f"manifest declares {declared_sha256!r}"
                ),
            )
            report.profile_manifest_pin = Conclusion.FALSE
        else:
            report.profile_manifest_pin = Conclusion.TRUE

    # -----------------------------------------------------------------------
    # Check 6: Per-receipt checks for "emitted" entries
    # -----------------------------------------------------------------------
    receipts_list = manifest.get("receipts")
    if not isinstance(receipts_list, list):
        # No receipts array — per-receipt findings are NOT_EVALUATED
        # (structure cannot be verified if array is absent)
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            "manifest[\"receipts\"] is absent or not an array",
        )
        # These remain NOT_EVALUATED — we don't know if there should be receipts
        # Mark manifest schema as false since the required field is missing
        if report.receipt_set_manifest_schema is Conclusion.TRUE:
            report.receipt_set_manifest_schema = Conclusion.FALSE
        receipts_list = []

    emitted_entries = [
        e for e in receipts_list
        if isinstance(e, dict) and e.get("status") == "emitted"
    ]

    # Per-receipt aggregated conclusion trackers
    file_present_ok = True
    parse_ok = True
    protocol_binding_ok = True
    subject_ref_manifest_ok = True
    subject_binding_ok = True
    corpus_manifest_ref_ok = True
    raw_content_ok = True
    exclusions_ok = True

    has_emitted = bool(emitted_entries)

    for entry in emitted_entries:
        receipt_file = entry.get("receipt_file")
        entry_subject = entry.get("subject")

        # 6a: Receipt file exists
        if not isinstance(receipt_file, str) or not receipt_file:
            file_present_ok = False
            _fail(
                report,
                "RECEIPT_FILE_MISSING",
                f"emitted entry has no receipt_file: {entry!r}",
            )
            continue

        receipt_path = receipts_dir / receipt_file
        if not receipt_path.is_file():
            file_present_ok = False
            _fail(
                report,
                "RECEIPT_FILE_MISSING",
                f"receipt file not found: {receipt_path}",
            )
            continue

        # 6b: Parse receipt JSON
        try:
            receipt_text = receipt_path.read_text(encoding="utf-8")
        except OSError as exc:
            parse_ok = False
            _fail(
                report,
                "RECEIPT_PARSE_ERROR",
                f"receipt {receipt_file!r} unreadable: {exc}",
            )
            continue

        try:
            receipt: dict[str, Any] = json.loads(receipt_text)
        except json.JSONDecodeError as exc:
            parse_ok = False
            _fail(
                report,
                "RECEIPT_PARSE_ERROR",
                f"receipt {receipt_file!r} malformed JSON: {exc}",
            )
            continue

        if not isinstance(receipt, dict):
            parse_ok = False
            _fail(
                report,
                "RECEIPT_PARSE_ERROR",
                f"receipt {receipt_file!r} is not a JSON object",
            )
            continue

        # 6c: protocol_binding == "dagr-ingest/v0.1"
        pb = receipt.get("protocol_binding")
        if pb != EXPECTED_PROTOCOL_BINDING:
            protocol_binding_ok = False
            _fail(
                report,
                "PROTOCOL_BINDING_MISMATCH",
                (
                    f"receipt {receipt_file!r} protocol_binding == {pb!r}; "
                    f"expected {EXPECTED_PROTOCOL_BINDING!r}"
                ),
            )

        # 6d: receipt["subject_ref"] == entry["subject"]
        receipt_subject_ref = receipt.get("subject_ref")
        if receipt_subject_ref != entry_subject:
            subject_ref_manifest_ok = False
            _fail(
                report,
                "SUBJECT_REF_MANIFEST_MISMATCH",
                (
                    f"receipt {receipt_file!r} subject_ref == {receipt_subject_ref!r}; "
                    f"manifest entry subject == {entry_subject!r}"
                ),
            )

        # 6e: receipt["subject_ref"] == receipt["publication_artifact_id"]
        pub_artifact_id = receipt.get("publication_artifact_id")
        if receipt_subject_ref != pub_artifact_id:
            subject_binding_ok = False
            _fail(
                report,
                "SUBJECT_BINDING_MISMATCH",
                (
                    f"receipt {receipt_file!r}: "
                    f"subject_ref == {receipt_subject_ref!r} "
                    f"but publication_artifact_id == {pub_artifact_id!r}"
                ),
            )

        # 6f: receipt["corpus_manifest_ref"] == "sha256:" + run_doc["run_id"]
        expected_corpus_manifest_ref = (
            f"sha256:{run_id}" if isinstance(run_id, str) else None
        )
        actual_corpus_manifest_ref = receipt.get("corpus_manifest_ref")
        if actual_corpus_manifest_ref != expected_corpus_manifest_ref:
            corpus_manifest_ref_ok = False
            _fail(
                report,
                "CORPUS_MANIFEST_REF_MISMATCH",
                (
                    f"receipt {receipt_file!r}: "
                    f"corpus_manifest_ref == {actual_corpus_manifest_ref!r}; "
                    f"expected {expected_corpus_manifest_ref!r}"
                ),
            )

        # 6g: No raw content fields present
        for raw_field in FORBIDDEN_RAW_RECEIPT_FIELDS:
            if raw_field in receipt:
                raw_content_ok = False
                _fail(
                    report,
                    "RAW_CONTENT_PRESENT",
                    (
                        f"receipt {receipt_file!r} contains forbidden "
                        f"raw-content field: {raw_field!r}"
                    ),
                )

        # 6h: artifact_classes_excluded contains all three required exclusions
        excluded = receipt.get("artifact_classes_excluded")
        if not isinstance(excluded, list):
            exclusions_ok = False
            _fail(
                report,
                "MISSING_REQUIRED_EXCLUSION",
                (
                    f"receipt {receipt_file!r}: "
                    "artifact_classes_excluded is absent or not a list"
                ),
            )
        else:
            excluded_set = set(excluded)
            for req_excl in sorted(REQUIRED_EXCLUSIONS):
                if req_excl not in excluded_set:
                    exclusions_ok = False
                    _fail(
                        report,
                        "MISSING_REQUIRED_EXCLUSION",
                        (
                            f"receipt {receipt_file!r}: "
                            f"artifact_classes_excluded missing {req_excl!r}"
                        ),
                    )

    # Assign per-receipt aggregated conclusions.
    # If there are no emitted entries, leave as NOT_EVALUATED.
    if has_emitted:
        report.receipt_file_present = (
            Conclusion.TRUE if file_present_ok else Conclusion.FALSE
        )
        report.receipt_parse = (
            Conclusion.TRUE if parse_ok else Conclusion.FALSE
        )
        report.protocol_binding = (
            Conclusion.TRUE if protocol_binding_ok else Conclusion.FALSE
        )
        report.subject_ref_manifest = (
            Conclusion.TRUE if subject_ref_manifest_ok else Conclusion.FALSE
        )
        report.subject_binding = (
            Conclusion.TRUE if subject_binding_ok else Conclusion.FALSE
        )
        report.corpus_manifest_ref = (
            Conclusion.TRUE if corpus_manifest_ref_ok else Conclusion.FALSE
        )
        report.raw_content_absent = (
            Conclusion.TRUE if raw_content_ok else Conclusion.FALSE
        )
        report.artifact_classes_excluded = (
            Conclusion.TRUE if exclusions_ok else Conclusion.FALSE
        )

    # -----------------------------------------------------------------------
    # Check 7: Unique-artifact coverage
    # -----------------------------------------------------------------------
    unique_artifacts = run_doc.get("unique_artifacts")
    if unique_artifacts is None:
        # NOT_EVALUATED when unique_artifacts list is absent
        report.unique_artifact_coverage = Conclusion.NOT_EVALUATED
    elif not isinstance(unique_artifacts, list):
        _fail(
            report,
            "UNIQUE_ARTIFACT_NOT_COVERED",
            "run_doc[\"unique_artifacts\"] is not a list",
        )
        report.unique_artifact_coverage = Conclusion.FALSE
    else:
        # Build set of subjects that appear as emitted in manifest
        emitted_subjects: set[str] = {
            e.get("subject", "")
            for e in receipts_list
            if isinstance(e, dict) and e.get("status") == "emitted"
        }

        coverage_ok = True
        for artifact in unique_artifacts:
            if not isinstance(artifact, dict):
                continue
            parser_id = artifact.get("parser_id")
            is_dup = artifact.get("is_duplicate_content", False)
            if parser_id is not None and not is_dup:
                # This artifact should appear as emitted
                artifact_subject = artifact.get("subject")
                if not isinstance(artifact_subject, str) or not artifact_subject:
                    # Cannot determine subject — skip (not a coverage violation)
                    continue
                if artifact_subject not in emitted_subjects:
                    coverage_ok = False
                    _fail(
                        report,
                        "UNIQUE_ARTIFACT_NOT_COVERED",
                        (
                            f"unique_artifact subject={artifact_subject!r} "
                            "has parser_id and is not a duplicate, "
                            "but does not appear as emitted in the manifest"
                        ),
                    )

        report.unique_artifact_coverage = (
            Conclusion.TRUE if coverage_ok else Conclusion.FALSE
        )

    # -----------------------------------------------------------------------
    # Check 8: Duplicate posture
    # -----------------------------------------------------------------------
    if not isinstance(unique_artifacts, list):
        # Cannot check posture without unique_artifacts list
        if unique_artifacts is None:
            report.duplicate_posture = Conclusion.NOT_EVALUATED
        # else already set to FALSE above, leave as FALSE
    else:
        # Build set of subjects that appear as emitted
        emitted_subjects_dup: set[str] = {
            e.get("subject", "")
            for e in receipts_list
            if isinstance(e, dict) and e.get("status") == "emitted"
        }

        dup_ok = True
        for artifact in unique_artifacts:
            if not isinstance(artifact, dict):
                continue
            is_dup = artifact.get("is_duplicate_content", False)
            if is_dup:
                artifact_subject = artifact.get("subject")
                if isinstance(artifact_subject, str) and artifact_subject:
                    if artifact_subject in emitted_subjects_dup:
                        dup_ok = False
                        _fail(
                            report,
                            "DUPLICATE_POSTURE_VIOLATION",
                            (
                                f"unique_artifact subject={artifact_subject!r} "
                                "has is_duplicate_content=True but appears "
                                "as emitted in the manifest"
                            ),
                        )

        report.duplicate_posture = (
            Conclusion.TRUE if dup_ok else Conclusion.FALSE
        )

    return report


def _propagate_false_early(report: IngestRunSequenceReport) -> None:
    """When the run doc is unreadable, mark all dependent findings FALSE."""
    for attr in (
        "boundary_declarations",
        "receipt_set_manifest_schema",
        "run_id_linkage",
        "profile_manifest_pin",
        "receipt_file_present",
        "receipt_parse",
        "protocol_binding",
        "subject_ref_manifest",
        "subject_binding",
        "corpus_manifest_ref",
        "raw_content_absent",
        "artifact_classes_excluded",
        "unique_artifact_coverage",
        "duplicate_posture",
    ):
        if getattr(report, attr) is Conclusion.NOT_EVALUATED:
            setattr(report, attr, Conclusion.FALSE)


def _propagate_false_on_missing_manifest(report: IngestRunSequenceReport) -> None:
    """When the manifest is unreadable, mark manifest-dependent findings FALSE."""
    for attr in (
        "run_id_linkage",
        "profile_manifest_pin",
        "receipt_file_present",
        "receipt_parse",
        "protocol_binding",
        "subject_ref_manifest",
        "subject_binding",
        "corpus_manifest_ref",
        "raw_content_absent",
        "artifact_classes_excluded",
        "unique_artifact_coverage",
        "duplicate_posture",
    ):
        if getattr(report, attr) is Conclusion.NOT_EVALUATED:
            setattr(report, attr, Conclusion.FALSE)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def build_parser() -> "argparse.ArgumentParser":
    import argparse

    parser = argparse.ArgumentParser(
        prog="arcs-verify ingest-run-sequence",
        description=(
            "Independently verify the linkage between a dagr.ingest_run.v0.1 "
            "run document, a D4-produced SRS receipt-set manifest, and the "
            "individual SRS receipts. Imports no dagr_ingest producer code."
        ),
    )
    parser.add_argument(
        "--run-doc",
        required=True,
        type=Path,
        metavar="RUN_DOC_JSON",
        help="Path to the dagr.ingest_run.v0.1 run document JSON file.",
    )
    parser.add_argument(
        "--receipt-set-manifest",
        required=True,
        type=Path,
        metavar="MANIFEST_JSON",
        help=(
            "Path to the dagr-ingest.srs-receipt-set.v0.1 "
            "receipt-set manifest JSON file."
        ),
    )
    parser.add_argument(
        "--receipts-dir",
        required=True,
        type=Path,
        metavar="RECEIPTS_DIR",
        help="Directory containing the individual receipt JSON files.",
    )
    parser.add_argument(
        "--profile-manifest",
        required=True,
        type=Path,
        metavar="PROFILE_MANIFEST_JSON",
        help=(
            "Path to the SRS profile manifest file whose sha256 is pinned "
            "in the receipt-set manifest."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit report as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    for attr, label in (
        ("run_doc", "--run-doc"),
        ("receipt_set_manifest", "--receipt-set-manifest"),
        ("receipts_dir", "--receipts-dir"),
        ("profile_manifest", "--profile-manifest"),
    ):
        p: Path = getattr(args, attr)
        if attr == "receipts_dir":
            if not p.is_dir():
                sys.stderr.write(f"error: {label} is not a directory: {p}\n")
                return 2
        else:
            if not p.is_file():
                sys.stderr.write(f"error: {label} not found: {p}\n")
                return 2

    report = verify_ingest_run_sequence(
        run_doc_path=args.run_doc,
        receipt_set_manifest_path=args.receipt_set_manifest,
        receipts_dir=args.receipts_dir,
        profile_manifest_path=args.profile_manifest,
    )
    data = report.to_dict()

    if args.as_json:
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"profile: {data['verification_profile']}")
        conclusions = data["conclusions"]
        for name, value in conclusions.items():
            print(f"{name}: {value.upper()}")
        print(f"passed: {str(data['passed']).lower()}")
        for finding in data["findings"]:
            print(f"finding: {finding['code']}: {finding['detail']}")

    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
