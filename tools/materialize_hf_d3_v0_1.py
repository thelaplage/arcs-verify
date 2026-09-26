#!/usr/bin/env python3
"""Materialize HF-PUBLIC-SURFACE0 D3 v0.1 from exact pinned ARCS Verify bytes.

This is packaging only. It does not publish to Hugging Face, run Hugging Face
Jobs, create an HF namespace, mint a governed record, or move authority.

The source fixture bytes are always read from the ratified historical Git commit
recorded in input-spec.json, never from the working tree. That prevents later
changes on arcs-verify/main from silently changing the D3 fixture set.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any


SPEC_REL = Path("public_artifacts/hf-public-surface/d3-v0.1/input-spec.json")
OUTPUT_SCHEMA = "arcs.hf_public_surface.d3_dataset.v0.1"


class MaterializationError(RuntimeError):
    """Raised when the candidate cannot be reconstructed exactly."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _git(repo_root: Path, *args: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise MaterializationError(
            f"git {' '.join(args)} failed with exit {proc.returncode}: {detail}"
        )
    return proc.stdout


def _git_show(repo_root: Path, commit: str, source_path: str) -> bytes:
    return _git(repo_root, "show", f"{commit}:{source_path}")


def _load_json(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MaterializationError(f"{label} is not valid UTF-8 JSON: {exc}") from exc


def _write_exact(root: Path, relative: str, raw: bytes) -> dict[str, Any]:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise MaterializationError(f"unsafe output path: {relative!r}")
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {
        "path": rel.as_posix(),
        "sha256": _sha256(raw),
        "byte_length": len(raw),
    }


def _expect_sha(raw: bytes, expected: str, *, label: str) -> None:
    actual = _sha256(raw)
    if actual != expected:
        raise MaterializationError(
            f"{label} sha256 mismatch: expected {expected}, got {actual}"
        )


def materialize(*, repo_root: Path, out_dir: Path) -> dict[str, Any]:
    spec_path = repo_root / SPEC_REL
    if not spec_path.is_file():
        raise MaterializationError(f"input spec not found: {spec_path}")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))

    source = spec["source"]
    source_commit = source["commit"]
    pack_root = source["pack_root"]
    doctrine = spec["doctrine"]
    case_set = spec["case_set"]
    authority = spec["authority_inputs"]

    # The historical commit is part of the candidate identity. A shallow clone
    # that does not contain it must fail closed rather than substitute HEAD.
    _git(repo_root, "cat-file", "-e", f"{source_commit}^{{commit}}")

    out_dir = out_dir.resolve()
    if out_dir.exists():
        raise MaterializationError(f"output path already exists: {out_dir}")
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_dir.parent / f".{out_dir.name}.tmp"
    if tmp.exists():
        raise MaterializationError(f"temporary path already exists: {tmp}")

    payload_files: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []

    try:
        tmp.mkdir()

        normative_raw = _git_show(
            repo_root, source_commit, case_set["normative_manifest"]
        )
        expectations_raw = _git_show(
            repo_root, source_commit, case_set["expectations"]
        )
        normative = _load_json(normative_raw, label="normative manifest")
        expectations = _load_json(expectations_raw, label="expectations")

        entries = normative.get("entries")
        if not isinstance(entries, list):
            raise MaterializationError("normative manifest entries must be a list")
        if len(entries) != case_set["total_count"]:
            raise MaterializationError(
                f"expected {case_set['total_count']} cases, found {len(entries)}"
            )

        by_path: dict[str, dict[str, Any]] = {}
        for row in expectations.get("entries", []):
            path = row.get("path")
            if not isinstance(path, str) or path in by_path:
                raise MaterializationError(
                    "expectations must contain unique string paths"
                )
            by_path[path] = row

        entry_paths = {row.get("path") for row in entries}
        if entry_paths != set(by_path):
            raise MaterializationError(
                "normative manifest and expectations enumerate different cases"
            )

        valid_count = sum(
            isinstance(row.get("path"), str) and row["path"].startswith("valid/")
            for row in entries
        )
        mutation_count = sum(
            isinstance(row.get("path"), str)
            and row["path"].startswith("mutations/")
            for row in entries
        )
        if valid_count != case_set["valid_count"]:
            raise MaterializationError(
                f"expected {case_set['valid_count']} valid cases, found {valid_count}"
            )
        if mutation_count != case_set["mutation_count"]:
            raise MaterializationError(
                "expected "
                f"{case_set['mutation_count']} mutation cases, found {mutation_count}"
            )

        for row in sorted(entries, key=lambda item: item["path"]):
            source_rel = row["path"]
            if not (
                source_rel.startswith("valid/")
                or source_rel.startswith("mutations/")
            ):
                raise MaterializationError(
                    f"case outside bounded D3 directories: {source_rel}"
                )

            source_path = f"{pack_root}/normative/{source_rel}"
            raw = _git_show(repo_root, source_commit, source_path)
            _expect_sha(
                raw,
                row["receipt_file_sha256"],
                label=f"case {source_rel}",
            )

            expected = by_path[source_rel]
            if bool(expected["signature_valid"]) != bool(
                row["expected_signature_valid"]
            ):
                raise MaterializationError(
                    f"signature expectation drift for {source_rel}"
                )

            output_rel = f"cases/{source_rel}"
            file_row = _write_exact(tmp, output_rel, raw)
            file_row["source_path"] = source_path
            payload_files.append(file_row)
            cases.append(
                {
                    "path": output_rel,
                    "class": "valid"
                    if source_rel.startswith("valid/")
                    else "mutation",
                    "receipt_file_sha256": row["receipt_file_sha256"],
                    "canonical_preimage_sha256": row[
                        "canonical_preimage_sha256"
                    ],
                    "expected_signature_valid": bool(
                        row["expected_signature_valid"]
                    ),
                    "expected_failure_codes": list(
                        expected.get("expected_failure_codes", [])
                    ),
                }
            )

        # Exact manifests that define the fixture set and expected outcomes.
        row = _write_exact(
            tmp, "manifests/normative-manifest.json", normative_raw
        )
        row["source_path"] = case_set["normative_manifest"]
        payload_files.append(row)

        row = _write_exact(tmp, "expected/expectations.json", expectations_raw)
        row["source_path"] = case_set["expectations"]
        payload_files.append(row)

        # Trust material.
        trust_spec = authority["trust"]
        trust_raw = _git_show(repo_root, source_commit, trust_spec["path"])
        _expect_sha(trust_raw, trust_spec["sha256"], label="trust bundle")
        row = _write_exact(tmp, "trust/issuer-keys.json", trust_raw)
        row["source_path"] = trust_spec["path"]
        payload_files.append(row)

        # Exact envelope schema.
        schema_spec = authority["envelope_schema"]
        schema_raw = _git_show(repo_root, source_commit, schema_spec["path"])
        _expect_sha(
            schema_raw, schema_spec["sha256"], label="SRS envelope schema"
        )
        row = _write_exact(
            tmp, "authority/srs-envelope-v0.2.0.schema.json", schema_raw
        )
        row["source_path"] = schema_spec["path"]
        payload_files.append(row)

        # Exact frozen profile documents, extracted from the pinned source
        # archive and individually digest-checked.
        archive_raw = _git_show(
            repo_root, source_commit, authority["profile_archive"]
        )
        with zipfile.ZipFile(io.BytesIO(archive_raw), "r") as archive:
            for profile in authority["profile_documents"]:
                archive_path = profile["archive_path"]
                try:
                    profile_raw = archive.read(archive_path)
                except KeyError as exc:
                    raise MaterializationError(
                        f"profile missing from frozen archive: {archive_path}"
                    ) from exc
                _expect_sha(
                    profile_raw,
                    profile["sha256"],
                    label=f"profile {archive_path}",
                )
                output_rel = f"authority/profiles/{Path(archive_path).name}"
                row = _write_exact(tmp, output_rel, profile_raw)
                row["source_path"] = (
                    f"{authority['profile_archive']}::{archive_path}"
                )
                payload_files.append(row)

        # Apache-2.0 license travels with the candidate.
        license_spec = spec["license"]
        license_raw = _git_show(repo_root, source_commit, license_spec["path"])
        row = _write_exact(tmp, "LICENSE", license_raw)
        row["source_path"] = license_spec["path"]
        payload_files.append(row)

        payload_files.sort(key=lambda item: item["path"])
        cases.sort(key=lambda item: item["path"])

        sums = "".join(
            f"{row['sha256']}  {row['path']}\n" for row in payload_files
        ).encode("utf-8")
        (tmp / "SHA256SUMS.txt").write_bytes(sums)
        sums_sha256 = _sha256(sums)

        dataset_manifest = {
            "schema": OUTPUT_SCHEMA,
            "status": "release_candidate_not_published",
            "source": {
                "repository": source["repository"],
                "commit": source_commit,
                "pack_root": pack_root,
            },
            "doctrine": doctrine,
            "profile": "srs.mcp.sdk_enforcement.v0.1",
            "counts": {
                "valid": valid_count,
                "mutations": mutation_count,
                "total": len(cases),
            },
            "verifier": {
                "repository": source["repository"],
                "commit": source_commit,
                "command_template": (
                    "arcs-verify <case> --keyring trust/issuer-keys.json "
                    "--profile srs.mcp.sdk_enforcement.v0.1 --json"
                ),
            },
            "cases": cases,
            "files": payload_files,
            "sha256sums_sha256": sums_sha256,
            "bounded_statement": spec["bounded_statement"],
            "non_claims": spec["non_claims"],
            "publication_boundary": spec["publication_boundary"],
        }
        manifest_raw = _canonical_json(dataset_manifest)
        (tmp / "DATASET_MANIFEST.json").write_bytes(manifest_raw)

        tmp.rename(out_dir)
        return {
            "out_dir": str(out_dir),
            "case_count": len(cases),
            "valid_count": valid_count,
            "mutation_count": mutation_count,
            "source_commit": source_commit,
            "dataset_manifest_sha256": _sha256(manifest_raw),
            "sha256sums_sha256": sums_sha256,
        }
    except Exception:
        if tmp.exists():
            shutil.rmtree(tmp)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = materialize(
            repo_root=args.repo_root.resolve(),
            out_dir=args.out,
        )
    except MaterializationError as exc:
        print(f"D3_MATERIALIZATION_REFUSED={exc}", file=sys.stderr)
        return 2

    print("D3_MATERIALIZATION=PASS")
    print(f"D3_SOURCE_COMMIT={result['source_commit']}")
    print(f"D3_CASES={result['case_count']}")
    print(f"D3_VALID={result['valid_count']}")
    print(f"D3_MUTATIONS={result['mutation_count']}")
    print(f"D3_DATASET_MANIFEST_SHA256={result['dataset_manifest_sha256']}")
    print(f"D3_SHA256SUMS_SHA256={result['sha256sums_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
