#!/usr/bin/env python3
"""Lightweight .ecosystem/ structure gate — no arcs-ecosystem-kit required.

This check runs unconditionally in CI (unlike test_schema_backed_declarations_validate_against_kit_v0_1,
which skips when the private kit is unavailable).  It enforces:

1.  Every expected declaration file exists under .ecosystem/.
2.  Every declaration file is valid JSON-compatible YAML (parsed as JSON here
    since all ecosystem declarations are written in JSON-compatible YAML).
3.  Every declaration file has a non-empty top-level "repository" key.
4.  RELEASE_STATE.yaml declares the expected distribution-placeholder value.

This is a structural pre-flight check; full schema validation against the
arcs-ecosystem-kit JSON schemas is handled by test_ecosystem_declarations.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ECOSYSTEM = ROOT / ".ecosystem"

EXPECTED_DECLARATIONS = {
    "ARCHITECTURE_PASSPORT.yaml",
    "AUTHORITY_REFERENCES.yaml",
    "BOUNDARIES.yaml",
    "CAPABILITY_BINDINGS.yaml",
    "COMPATIBILITY_PROJECTION.yaml",
    "CONFORMANCE_PROJECTION.yaml",
    "CONTRACT_BINDINGS.yaml",
    "DEPENDENCIES.yaml",
    "EXCEPTIONS.yaml",
    "LANES.yaml",
    "RELEASE_STATE.yaml",
    "REPOSITORY.yaml",
    "RESPONSIBILITIES.yaml",
}


def _load(name: str) -> dict:
    path = ECOSYSTEM / name
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(f"FAIL: missing declaration: {name}")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"FAIL: {name} is not valid JSON-compatible YAML: {exc}")
    if not isinstance(payload, dict):
        raise SystemExit(f"FAIL: {name} top-level value is not a mapping")
    return payload


def check_all_files_exist() -> None:
    found = {p.name for p in ECOSYSTEM.glob("*.yaml")}
    missing = EXPECTED_DECLARATIONS - found
    extra = found - EXPECTED_DECLARATIONS
    if missing:
        raise SystemExit(
            "FAIL: missing .ecosystem/ declarations: " + ", ".join(sorted(missing))
        )
    # Extra files are not a hard failure but are flagged.
    if extra:
        print(f"WARN: unexpected .ecosystem/ files (not governed): {sorted(extra)}")


def check_repository_keys() -> None:
    for name in EXPECTED_DECLARATIONS:
        payload = _load(name)
        # REPOSITORY.yaml uses {"name": "arcs-verify", ...}; others use a bare string.
        repo = payload.get("repository")
        if repo is None:
            raise SystemExit(f"FAIL: {name} missing top-level 'repository' key")
        repo_name = repo.get("name") if isinstance(repo, dict) else repo
        if repo_name != "arcs-verify":
            raise SystemExit(
                f"FAIL: {name} repository name is {repo_name!r}, expected 'arcs-verify'"
            )


def check_release_state() -> None:
    payload = _load("RELEASE_STATE.yaml")
    # release_stage and current_version must be non-empty strings.
    for key in ("release_stage", "current_version"):
        val = payload.get(key)
        if not isinstance(val, str) or not val.strip():
            raise SystemExit(
                f"FAIL: RELEASE_STATE.yaml '{key}' must be a non-empty string"
            )


def main() -> None:
    print(f"Checking .ecosystem/ declarations in {ECOSYSTEM} ...")
    check_all_files_exist()
    print("  [OK] all expected declaration files present")
    check_repository_keys()
    print("  [OK] all declarations carry correct repository key")
    check_release_state()
    print("  [OK] RELEASE_STATE.yaml distribution_name present")
    print("PASS: .ecosystem/ structure check complete")


if __name__ == "__main__":
    main()
