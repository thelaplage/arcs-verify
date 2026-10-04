"""Portable, offline ARCS/SRS receipt verification packages.

The package never chooses its own trust root. A verifier must supply an
independently selected trust context plus the exact external keyring bytes that
context pins. Package bytes contain receipt + envelope schema + manifest only.

Offline verification is honest about freshness: it can evaluate the selected
trust material and local clock, but it cannot learn revocation/compromise facts
published after the trust context's issued_at timestamp.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .verifier import verify_receipt


PACKAGE_SCHEMA = "arcs.verify.portable-package/v0.1"
TRUST_CONTEXT_SCHEMA = "arcs.verify.portable-trust-context/v0.1"
MANIFEST_DIGEST_SENTINEL = "sha256:pending"
PACKAGE_ENTRY_NAMES = ("manifest.json", "receipt.json", "schema.json")
LIMITATIONS = (
    "package_integrity != receipt_verification",
    "receipt_verification != current_standing",
    "receipt_verification != continued_validity",
    "receipt_verification != real_world_truth",
    "valid_signature != proof_governed_action_actually_occurred",
    "offline_verification != post_context_revocation_check",
)


class PortablePackError(ValueError):
    """Source-integrity or package-contract error, never a verification FAIL."""


@dataclass(frozen=True)
class PortableVerificationResult:
    report: dict[str, Any]

    @property
    def passed(self) -> bool:
        return bool(self.report["passed"])


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PortablePackError(f"{label}_unreadable: {path}: {exc}") from exc


def _load_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise PortablePackError(f"{label}_not_utf8") from exc
    except json.JSONDecodeError as exc:
        raise PortablePackError(f"{label}_malformed_json: {exc}") from exc
    if not isinstance(value, dict):
        raise PortablePackError(f"{label}_not_object")
    return value


def _parse_time(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise PortablePackError(f"{label}_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise PortablePackError(f"{label}_invalid") from exc
    if parsed.tzinfo is None:
        raise PortablePackError(f"{label}_must_include_timezone")
    return value


def _manifest_body(*, selected_profile: str, receipt_bytes: bytes, schema_bytes: bytes) -> dict[str, Any]:
    if not isinstance(selected_profile, str) or not selected_profile or selected_profile.strip() != selected_profile:
        raise PortablePackError("selected_profile_invalid")
    return {
        "schema": PACKAGE_SCHEMA,
        "selected_profile": selected_profile,
        "entries": {
            "receipt.json": {
                "sha256": _sha256_bytes(receipt_bytes),
                "size_bytes": len(receipt_bytes),
            },
            "schema.json": {
                "sha256": _sha256_bytes(schema_bytes),
                "size_bytes": len(schema_bytes),
            },
        },
        "limitations": list(LIMITATIONS),
        "manifest_digest": MANIFEST_DIGEST_SENTINEL,
    }


def _finish_manifest(body: dict[str, Any]) -> dict[str, Any]:
    manifest = json.loads(json.dumps(body))
    if manifest.get("manifest_digest") != MANIFEST_DIGEST_SENTINEL:
        raise PortablePackError("manifest_digest_sentinel_missing")
    digest = _sha256_bytes(_canonical_bytes(manifest))
    manifest["manifest_digest"] = digest
    return manifest


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100600 << 16
    return info


def create_portable_package(
    *,
    receipt_path: Path,
    schema_path: Path,
    selected_profile: str,
    output_path: Path,
) -> dict[str, Any]:
    """Create deterministic ZIP bytes without embedding trust material."""
    receipt_bytes = _read_bytes(receipt_path, "receipt")
    schema_bytes = _read_bytes(schema_path, "schema")
    _load_json_bytes(receipt_bytes, "receipt")
    _load_json_bytes(schema_bytes, "schema")

    manifest = _finish_manifest(
        _manifest_body(
            selected_profile=selected_profile,
            receipt_bytes=receipt_bytes,
            schema_bytes=schema_bytes,
        )
    )
    manifest_bytes = _canonical_bytes(manifest)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(output_path, "w") as archive:
            for name, data in (
                ("manifest.json", manifest_bytes),
                ("receipt.json", receipt_bytes),
                ("schema.json", schema_bytes),
            ):
                archive.writestr(_zip_info(name), data)
    except OSError as exc:
        raise PortablePackError(f"package_write_failed: {output_path}: {exc}") from exc
    return {
        "schema": PACKAGE_SCHEMA,
        "output": str(output_path),
        "manifest_digest": manifest["manifest_digest"],
        "package_file_sha256": _sha256_bytes(_read_bytes(output_path, "package")),
        "trust_material_embedded": False,
    }


def _read_package(path: Path) -> tuple[dict[str, Any], bytes, bytes]:
    raw = _read_bytes(path, "package")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise PortablePackError("package_duplicate_entry")
            if tuple(names) != PACKAGE_ENTRY_NAMES:
                raise PortablePackError(
                    f"package_entry_set_or_order_mismatch: expected={PACKAGE_ENTRY_NAMES!r}, got={tuple(names)!r}"
                )
            manifest_bytes = archive.read("manifest.json")
            receipt_bytes = archive.read("receipt.json")
            schema_bytes = archive.read("schema.json")
    except zipfile.BadZipFile as exc:
        raise PortablePackError("package_bad_zip") from exc

    manifest = _load_json_bytes(manifest_bytes, "manifest")
    expected_top = {"schema", "selected_profile", "entries", "limitations", "manifest_digest"}
    if set(manifest) != expected_top:
        raise PortablePackError("manifest_field_set_mismatch")
    if manifest.get("schema") != PACKAGE_SCHEMA:
        raise PortablePackError("manifest_schema_mismatch")
    if manifest.get("limitations") != list(LIMITATIONS):
        raise PortablePackError("manifest_limitations_mismatch")
    selected_profile = manifest.get("selected_profile")
    if not isinstance(selected_profile, str) or not selected_profile:
        raise PortablePackError("manifest_selected_profile_invalid")

    supplied_manifest_digest = manifest.get("manifest_digest")
    body = json.loads(json.dumps(manifest))
    body["manifest_digest"] = MANIFEST_DIGEST_SENTINEL
    expected_manifest_digest = _sha256_bytes(_canonical_bytes(body))
    if supplied_manifest_digest != expected_manifest_digest:
        raise PortablePackError("manifest_digest_mismatch")

    entries = manifest.get("entries")
    if not isinstance(entries, dict) or set(entries) != {"receipt.json", "schema.json"}:
        raise PortablePackError("manifest_entries_mismatch")
    for name, data in (("receipt.json", receipt_bytes), ("schema.json", schema_bytes)):
        meta = entries.get(name)
        if not isinstance(meta, dict) or set(meta) != {"sha256", "size_bytes"}:
            raise PortablePackError(f"manifest_entry_metadata_mismatch:{name}")
        if meta["sha256"] != _sha256_bytes(data):
            raise PortablePackError(f"package_entry_digest_mismatch:{name}")
        if meta["size_bytes"] != len(data):
            raise PortablePackError(f"package_entry_size_mismatch:{name}")

    # Parse before verification so malformed sources are source-integrity errors.
    _load_json_bytes(receipt_bytes, "receipt")
    _load_json_bytes(schema_bytes, "schema")
    return manifest, receipt_bytes, schema_bytes


def _load_trust_context(path: Path, keyring_bytes: bytes) -> dict[str, str]:
    context = _load_json_bytes(_read_bytes(path, "trust_context"), "trust_context")
    expected = {"schema", "context_id", "issued_at", "keyring_sha256"}
    if set(context) != expected:
        raise PortablePackError("trust_context_field_set_mismatch")
    if context.get("schema") != TRUST_CONTEXT_SCHEMA:
        raise PortablePackError("trust_context_schema_mismatch")
    context_id = context.get("context_id")
    if not isinstance(context_id, str) or not context_id or context_id.strip() != context_id:
        raise PortablePackError("trust_context_id_invalid")
    issued_at = _parse_time(context.get("issued_at"), "trust_context.issued_at")
    keyring_digest = _sha256_bytes(keyring_bytes)
    if context.get("keyring_sha256") != keyring_digest:
        raise PortablePackError("trust_context_keyring_digest_mismatch")
    return {
        "context_id": context_id,
        "issued_at": issued_at,
        "keyring_sha256": keyring_digest,
    }


def verify_portable_package(
    *,
    package_path: Path,
    keyring_path: Path,
    trust_context_path: Path,
) -> PortableVerificationResult:
    """Verify package integrity, then verify its receipt using external trust."""
    manifest, receipt_bytes, schema_bytes = _read_package(package_path)
    keyring_bytes = _read_bytes(keyring_path, "keyring")
    keyring = _load_json_bytes(keyring_bytes, "keyring")
    trust_context = _load_trust_context(trust_context_path, keyring_bytes)
    receipt = _load_json_bytes(receipt_bytes, "receipt")

    with tempfile.TemporaryDirectory(prefix="arcs-portable-pack-") as tmp:
        schema_path = Path(tmp) / "schema.json"
        schema_path.write_bytes(schema_bytes)
        verification = verify_receipt(
            receipt,
            keyring,
            schema_path=schema_path,
            selected_profile=manifest["selected_profile"],
        )
    receipt_report = verification.to_dict()
    report = {
        "schema": "arcs.verify.portable-verification-report/v0.1",
        "passed": bool(verification.passed),
        "package_integrity": "pass",
        "manifest_digest": manifest["manifest_digest"],
        "selected_profile": manifest["selected_profile"],
        "trust_context": trust_context,
        "freshness_limitations": {
            "key_status_after_context_issued_at": "not_evaluated",
            "post_context_revocation_or_compromise": "not_evaluated",
            "current_standing": "not_evaluated",
            "continued_validity": "not_evaluated",
            "real_world_truth": "not_evaluated",
        },
        "receipt_verification": receipt_report,
        "limitations": list(LIMITATIONS),
    }
    return PortableVerificationResult(report=report)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or verify a portable offline ARCS/SRS receipt package."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="create a deterministic package; trust material is never embedded")
    create.add_argument("receipt", type=Path)
    create.add_argument("--schema", required=True, type=Path)
    create.add_argument("--profile", required=True)
    create.add_argument("--out", required=True, type=Path)
    create.add_argument("--json", action="store_true", dest="as_json")

    verify = sub.add_parser("verify", help="verify offline using an independently selected external trust context")
    verify.add_argument("package", type=Path)
    verify.add_argument("--keyring", required=True, type=Path)
    verify.add_argument("--trust-context", required=True, type=Path)
    verify.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "create":
            result = create_portable_package(
                receipt_path=args.receipt,
                schema_path=args.schema,
                selected_profile=args.profile,
                output_path=args.out,
            )
            if args.as_json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"manifest_digest: {result['manifest_digest']}")
                print(f"package_file_sha256: {result['package_file_sha256']}")
                print("trust_material_embedded: false")
            return 0

        result = verify_portable_package(
            package_path=args.package,
            keyring_path=args.keyring,
            trust_context_path=args.trust_context,
        )
        if args.as_json:
            print(json.dumps(result.report, indent=2, sort_keys=True))
        else:
            print(f"package_integrity: {result.report['package_integrity'].upper()}")
            print(f"receipt_verification: {'PASS' if result.passed else 'FAIL'}")
            tc = result.report["trust_context"]
            print(f"trust_context_id: {tc['context_id']}")
            print(f"trust_context_issued_at: {tc['issued_at']}")
            print(f"trust_context_keyring_sha256: {tc['keyring_sha256']}")
            print("post_context_revocation_or_compromise: NOT_EVALUATED")
            print("current_standing: NOT_EVALUATED")
            print("continued_validity: NOT_EVALUATED")
            print("real_world_truth: NOT_EVALUATED")
        return 0 if result.passed else 1
    except PortablePackError as exc:
        # Source/package integrity failures are usage/source errors, not receipt
        # verification verdicts. Keep the existing arcs-verify exit discipline.
        if getattr(args, "as_json", False):
            print(json.dumps({"source_integrity_error": "portable_package", "detail": str(exc)}, indent=2, sort_keys=True))
        else:
            print(f"source_integrity_error: portable_package: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
