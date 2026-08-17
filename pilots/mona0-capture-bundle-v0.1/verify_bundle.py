#!/usr/bin/env python3
"""Independent verifier for the serialized MONA0-CAPTURE1 object bundle.

This module imports no acquisition producer implementation. It verifies only
properties recomputable from the supplied producer-facts JSON, object-manifest JSON,
and content-addressed object files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPORT_SCHEMA = "arcs.verify.mona0.capture_bundle_report.v0.1"
FACTS_SCHEMA = "counterpedia.mona0.capture1.v0.1"
MANIFEST_SCHEMA = "counterpedia.mona0.capture1_object_manifest.v0.1"
PROOFCASE = "MONA0-CAPTURE1"
PRODUCER_REPOSITORY = "thelaplage/counterpedia-acquisition"
PRODUCER_SURFACE = "acquisition.mcp_surface.v0.1"
PRODUCER_TOOL = "acquisition.capture_url"
VERIFIER_REPOSITORY = "thelaplage/arcs-verify"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_ADDRESS_RE = re.compile(r"^sha256:([0-9a-f]{64})$")

GATING_FIELDS = (
    "producer_lineage_consistent",
    "manifest_contract_consistent",
    "receipt_object_bindings_valid",
    "object_bytes_integrity_valid",
    "capture_topology_valid",
    "authority_boundary_valid",
)


class SourceError(Exception):
    """Unreadable or malformed verifier input. This is not a verdict."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SourceError(f"cannot read {path}: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SourceError(f"malformed JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SourceError(f"top-level JSON must be an object: {path}")
    return value


def _sha256_address(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _expected_relative_path(address: str) -> str | None:
    match = SHA256_ADDRESS_RE.fullmatch(address)
    if match is None:
        return None
    digest = match.group(1)
    return f"{digest[:2]}/{digest[2:]}"


def _safe_object_path(root: Path, relative_path: str) -> Path | None:
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    root_resolved = root.resolve()
    path_resolved = (root / candidate).resolve()
    if not path_resolved.is_relative_to(root_resolved):
        return None
    return path_resolved


def verify_bundle(
    facts: dict[str, Any],
    manifest: dict[str, Any],
    object_store_root: Path,
    *,
    verifier_revision: str,
) -> dict[str, Any]:
    if REVISION_RE.fullmatch(verifier_revision) is None:
        raise SourceError("verifier_revision must be an exact 40-hex commit")

    conclusions: dict[str, bool | str] = {
        "producer_lineage_consistent": True,
        "manifest_contract_consistent": True,
        "receipt_object_bindings_valid": True,
        "object_bytes_integrity_valid": True,
        "capture_topology_valid": True,
        "authority_boundary_valid": True,
        "authenticity_verified": "not_evaluated",
        "claim_truth_verified": "not_evaluated",
        "source_independence_verified": "not_evaluated",
        "signature_verified": "not_evaluated",
    }
    failures: set[str] = set()

    def fail(field: str, code: str) -> None:
        conclusions[field] = False
        failures.add(code)

    # ------------------------------------------------------------------
    # Producer lineage and top-level contracts.
    # ------------------------------------------------------------------
    if facts.get("schema_version") != FACTS_SCHEMA:
        fail("producer_lineage_consistent", "facts.schema_invalid")
    if facts.get("proofcase_id") != PROOFCASE:
        fail("producer_lineage_consistent", "facts.proofcase_invalid")

    producer = facts.get("producer")
    if not isinstance(producer, dict):
        producer = {}
        fail("producer_lineage_consistent", "facts.producer_missing")
    producer_revision = producer.get("revision")
    if producer.get("repository") != PRODUCER_REPOSITORY:
        fail("producer_lineage_consistent", "producer.repository_mismatch")
    if not isinstance(producer_revision, str) or REVISION_RE.fullmatch(producer_revision) is None:
        fail("producer_lineage_consistent", "producer.revision_invalid")
    if producer.get("surface") != PRODUCER_SURFACE:
        fail("producer_lineage_consistent", "producer.surface_mismatch")
    if producer.get("tool") != PRODUCER_TOOL:
        fail("producer_lineage_consistent", "producer.tool_mismatch")

    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        fail("manifest_contract_consistent", "manifest.schema_invalid")
    if manifest.get("proofcase_id") != PROOFCASE:
        fail("manifest_contract_consistent", "manifest.proofcase_invalid")
    manifest_producer = manifest.get("producer")
    if not isinstance(manifest_producer, dict):
        manifest_producer = {}
        fail("manifest_contract_consistent", "manifest.producer_missing")
    if manifest_producer.get("repository") != PRODUCER_REPOSITORY:
        fail("manifest_contract_consistent", "manifest.producer_repository_mismatch")
    if manifest_producer.get("revision") != producer_revision:
        fail("manifest_contract_consistent", "manifest.producer_revision_mismatch")
    if manifest_producer.get("object_store_implementation") != "acquisition.fs_store.FilesystemObjectStore":
        fail("manifest_contract_consistent", "manifest.object_store_implementation_mismatch")
    if manifest.get("layout") != "<root>/<sha256_hex[:2]>/<sha256_hex[2:]>":
        fail("manifest_contract_consistent", "manifest.layout_mismatch")
    if manifest.get("independent_verification") is not False:
        fail("authority_boundary_valid", "manifest.independent_verification_overclaim")

    # ------------------------------------------------------------------
    # Authority negative space.
    # ------------------------------------------------------------------
    if producer.get("authority_movement") != 0:
        fail("authority_boundary_valid", "authority.producer_nonzero")
    if manifest_producer.get("authority_movement") != 0:
        fail("authority_boundary_valid", "authority.manifest_nonzero")
    summary = facts.get("summary")
    if not isinstance(summary, dict):
        summary = {}
        fail("receipt_object_bindings_valid", "facts.summary_missing")
    if summary.get("claim_admission_decisions") != 0:
        fail("authority_boundary_valid", "authority.claim_admission_present")

    # ------------------------------------------------------------------
    # Producer Artifact grouping and manifest objects.
    # ------------------------------------------------------------------
    raw_artifacts = facts.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raw_artifacts = []
        fail("receipt_object_bindings_valid", "facts.artifacts_invalid")
    artifact_map: dict[str, dict[str, Any]] = {}
    for row in raw_artifacts:
        if not isinstance(row, dict):
            fail("receipt_object_bindings_valid", "facts.artifact_row_invalid")
            continue
        address = row.get("artifact_ref")
        if not isinstance(address, str) or SHA256_ADDRESS_RE.fullmatch(address) is None:
            fail("receipt_object_bindings_valid", "facts.artifact_address_invalid")
            continue
        if address in artifact_map:
            fail("receipt_object_bindings_valid", "facts.artifact_duplicate")
            continue
        if not isinstance(row.get("byte_count"), int) or row["byte_count"] < 0:
            fail("receipt_object_bindings_valid", "facts.artifact_byte_count_invalid")
        artifact_map[address] = row

    raw_manifest_objects = manifest.get("objects")
    if not isinstance(raw_manifest_objects, list):
        raw_manifest_objects = []
        fail("manifest_contract_consistent", "manifest.objects_invalid")
    manifest_map: dict[str, dict[str, Any]] = {}
    manifest_paths: set[str] = set()
    for row in raw_manifest_objects:
        if not isinstance(row, dict):
            fail("manifest_contract_consistent", "manifest.object_row_invalid")
            continue
        address = row.get("artifact_ref")
        relative_path = row.get("relative_path")
        if not isinstance(address, str) or SHA256_ADDRESS_RE.fullmatch(address) is None:
            fail("manifest_contract_consistent", "manifest.object_address_invalid")
            continue
        if address in manifest_map:
            fail("manifest_contract_consistent", "manifest.object_duplicate")
            continue
        if not isinstance(relative_path, str):
            fail("manifest_contract_consistent", "manifest.object_path_invalid")
            continue
        expected_path = _expected_relative_path(address)
        if relative_path != expected_path:
            fail("manifest_contract_consistent", "manifest.object_path_mismatch")
        if relative_path in manifest_paths:
            fail("manifest_contract_consistent", "manifest.path_duplicate")
        manifest_paths.add(relative_path)
        if not isinstance(row.get("byte_count"), int) or row["byte_count"] < 0:
            fail("manifest_contract_consistent", "manifest.object_byte_count_invalid")
        manifest_map[address] = row

    if set(manifest_map) != set(artifact_map):
        fail("manifest_contract_consistent", "manifest.artifact_set_mismatch")
    if manifest.get("object_count") != len(manifest_map):
        fail("manifest_contract_consistent", "manifest.object_count_mismatch")

    # ------------------------------------------------------------------
    # Recompute bytes independently from serialized files.
    # ------------------------------------------------------------------
    total_unique_bytes = 0
    actual_manifest_paths: set[str] = set()
    if not object_store_root.is_dir():
        fail("object_bytes_integrity_valid", "object_store.missing")
    else:
        for address, row in manifest_map.items():
            relative_path = row.get("relative_path")
            if not isinstance(relative_path, str):
                continue
            object_path = _safe_object_path(object_store_root, relative_path)
            if object_path is None:
                fail("object_bytes_integrity_valid", "object.path_unsafe")
                continue
            actual_manifest_paths.add(relative_path)
            try:
                data = object_path.read_bytes()
            except OSError:
                fail("object_bytes_integrity_valid", "object.missing")
                continue
            actual_address = _sha256_address(data)
            if actual_address != address:
                fail("object_bytes_integrity_valid", "object.digest_mismatch")
            if len(data) != row.get("byte_count"):
                fail("object_bytes_integrity_valid", "object.manifest_byte_count_mismatch")
            producer_artifact = artifact_map.get(address)
            if producer_artifact is not None and len(data) != producer_artifact.get("byte_count"):
                fail("object_bytes_integrity_valid", "object.producer_byte_count_mismatch")
            total_unique_bytes += len(data)

        actual_files = {
            path.relative_to(object_store_root).as_posix()
            for path in object_store_root.rglob("*")
            if path.is_file()
        }
        if actual_files != actual_manifest_paths:
            fail("object_bytes_integrity_valid", "object_store.file_set_mismatch")

    if manifest.get("total_unique_bytes") != total_unique_bytes:
        fail("manifest_contract_consistent", "manifest.total_unique_bytes_mismatch")
    max_bundle_bytes = manifest.get("max_bundle_bytes")
    if not isinstance(max_bundle_bytes, int) or max_bundle_bytes < 0:
        fail("manifest_contract_consistent", "manifest.max_bundle_bytes_invalid")
    elif total_unique_bytes > max_bundle_bytes:
        fail("object_bytes_integrity_valid", "object_store.bundle_ceiling_exceeded")

    # ------------------------------------------------------------------
    # Receipt ↔ artifact bindings and producer grouping.
    # ------------------------------------------------------------------
    raw_attempts = facts.get("attempts")
    if not isinstance(raw_attempts, list):
        raw_attempts = []
        fail("receipt_object_bindings_valid", "facts.attempts_invalid")

    captured_rows: list[dict[str, Any]] = []
    capture_ids: set[str] = set()
    derived_groups: dict[str, dict[str, set[str]]] = {}
    by_label: dict[str, dict[str, Any]] = {}

    for row in raw_attempts:
        if not isinstance(row, dict):
            fail("receipt_object_bindings_valid", "facts.attempt_row_invalid")
            continue
        label = row.get("attempt_label")
        if isinstance(label, str):
            if label in by_label:
                fail("capture_topology_valid", "topology.attempt_label_duplicate")
            by_label[label] = row
        status = row.get("capture_status")
        if status == "capture_failed":
            if row.get("capture_receipt") is not None or row.get("captured_object_address") is not None:
                fail("receipt_object_bindings_valid", "receipt.failed_attempt_carries_artifact")
            continue
        if status != "captured":
            fail("receipt_object_bindings_valid", "receipt.capture_status_invalid")
            continue

        captured_rows.append(row)
        receipt = row.get("capture_receipt")
        if not isinstance(receipt, dict):
            fail("receipt_object_bindings_valid", "receipt.missing")
            continue

        capture_id = row.get("capture_id")
        source_id = row.get("source_id")
        source_locator = row.get("source_locator")
        address = row.get("captured_object_address")
        byte_count = row.get("byte_count")

        if not isinstance(capture_id, str) or not capture_id:
            fail("receipt_object_bindings_valid", "receipt.capture_id_invalid")
        elif capture_id in capture_ids:
            fail("receipt_object_bindings_valid", "receipt.capture_id_duplicate")
        else:
            capture_ids.add(capture_id)

        for field, top_value in (
            ("capture_id", capture_id),
            ("source_id", source_id),
            ("source_locator", source_locator),
            ("exact_bytes_sha256", address),
            ("byte_count", byte_count),
        ):
            if receipt.get(field) != top_value:
                fail("receipt_object_bindings_valid", f"receipt.{field}_mismatch")

        if not isinstance(address, str) or address not in artifact_map:
            fail("receipt_object_bindings_valid", "receipt.unknown_artifact")
            continue
        if not isinstance(capture_id, str) or not isinstance(source_locator, str):
            continue
        group = derived_groups.setdefault(
            address,
            {"observation_refs": set(), "source_locators": set()},
        )
        group["observation_refs"].add(capture_id)
        group["source_locators"].add(source_locator)

    if set(derived_groups) != set(artifact_map):
        fail("receipt_object_bindings_valid", "facts.artifact_group_set_mismatch")
    for address, producer_artifact in artifact_map.items():
        group = derived_groups.get(address)
        if group is None:
            continue
        producer_observations = producer_artifact.get("observation_refs")
        producer_locators = producer_artifact.get("source_locators")
        if not isinstance(producer_observations, list) or set(producer_observations) != group["observation_refs"]:
            fail("receipt_object_bindings_valid", "facts.artifact_observation_group_mismatch")
        if not isinstance(producer_locators, list) or set(producer_locators) != group["source_locators"]:
            fail("receipt_object_bindings_valid", "facts.artifact_locator_group_mismatch")

    if summary.get("captured_count") != len(captured_rows):
        fail("receipt_object_bindings_valid", "facts.summary_captured_count_mismatch")
    if summary.get("distinct_artifact_count") != len(artifact_map):
        fail("receipt_object_bindings_valid", "facts.summary_artifact_count_mismatch")

    # ------------------------------------------------------------------
    # Mona Lisa CAPTURE1 topology assertions.
    # ------------------------------------------------------------------
    required_labels = ("commons-original-a", "commons-original-b", "commons-960")
    if any(label not in by_label for label in required_labels):
        fail("capture_topology_valid", "topology.required_attempt_missing")
    else:
        a = by_label["commons-original-a"]
        b = by_label["commons-original-b"]
        rendition = by_label["commons-960"]
        if any(row.get("capture_status") != "captured" for row in (a, b, rendition)):
            fail("capture_topology_valid", "topology.required_attempt_failed")
        if a.get("capture_id") == b.get("capture_id"):
            fail("capture_topology_valid", "topology.repeat_capture_identity_collapsed")
        if a.get("captured_object_address") != b.get("captured_object_address"):
            fail("capture_topology_valid", "topology.repeat_bytes_not_equal")
        if a.get("captured_object_address") == rendition.get("captured_object_address"):
            fail("capture_topology_valid", "topology.rendition_not_distinct")

    for key in (
        "repeat_observation_preserved",
        "repeat_exact_bytes_reused",
        "distinct_rendition_separated",
    ):
        if summary.get(key) is not True:
            fail("capture_topology_valid", f"topology.summary_{key}_invalid")

    passed = all(conclusions[field] is True for field in GATING_FIELDS)
    return {
        "schema_version": REPORT_SCHEMA,
        "verifier": {
            "repository": VERIFIER_REPOSITORY,
            "revision": verifier_revision,
            "imports_producer_implementation": False,
        },
        "input": {
            "proofcase_id": facts.get("proofcase_id"),
            "producer_revision": producer_revision,
            "facts_schema": facts.get("schema_version"),
            "manifest_schema": manifest.get("schema_version"),
        },
        "conclusions": conclusions,
        "failure_codes": sorted(failures),
        "passed": passed,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independently verify a serialized MONA0-CAPTURE1 object bundle."
    )
    parser.add_argument("facts", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("object_store", type=Path)
    parser.add_argument("--verifier-revision", required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        facts = _load_json(args.facts)
        manifest = _load_json(args.manifest)
        report = verify_bundle(
            facts,
            manifest,
            args.object_store,
            verifier_revision=args.verifier_revision.strip().lower(),
        )
    except SourceError as exc:
        print(f"MONA0-VERIFY3 SOURCE ERROR: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for field in GATING_FIELDS:
            value = report["conclusions"][field]
            print(f"{field}: {'PASS' if value else 'FAIL'}")
        for field in (
            "authenticity_verified",
            "claim_truth_verified",
            "source_independence_verified",
            "signature_verified",
        ):
            print(f"{field}: {report['conclusions'][field]}")
        if report["failure_codes"]:
            print("failure_codes: " + ", ".join(report["failure_codes"]))
        print(f"passed: {str(report['passed']).lower()}")

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
