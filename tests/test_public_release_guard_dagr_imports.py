"""Negative controls: arcs-verify must import no DAGR/producer code."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_GUARD = Path(__file__).resolve().parents[1] / "tools" / "check_public_release.py"
_spec = importlib.util.spec_from_file_location("check_public_release", _GUARD)
guard = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = guard
_spec.loader.exec_module(guard)


def _pr010(tmp_path: Path, source: str) -> list:
    (tmp_path / "module.py").write_text(source, encoding="utf-8")
    return [f for f in guard.check(tmp_path) if f.rule_id == "PR010"]


@pytest.mark.parametrize(
    "module",
    ["dagr_mcp", "dagr_runtime", "dagr_sdk", "dagr_a2a", "dagr_mcp.server", "dagr"],
)
@pytest.mark.parametrize("form", ["import {m}\n", "from {m} import x\n"])
def test_planted_dagr_import_fails(tmp_path: Path, module: str, form: str) -> None:
    findings = _pr010(tmp_path, form.format(m=module))
    assert len(findings) == 1
    assert module.split(".")[0] in findings[0].message


@pytest.mark.parametrize("module", ["countergraph", "arcs_verify.verifier", "json"])
def test_control_existing_and_clean_imports(tmp_path: Path, module: str) -> None:
    findings = _pr010(tmp_path, "import " + module + "\n")
    assert bool(findings) == (module == "countergraph")


def test_lookalike_names_are_not_flagged(tmp_path: Path) -> None:
    assert _pr010(tmp_path, "import dagrfoo\nimport mydagr_mcp\n") == []


def test_real_tree_is_clean() -> None:
    root = Path(__file__).resolve().parents[1]
    assert [f for f in guard.check(root) if f.rule_id == "PR010"] == []
