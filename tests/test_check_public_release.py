"""Tests for tools/check_public_release.py — brand gate and fail-closed policy.

Focuses on the PR013 fail-closed behavior: an empty denylist emits PR013;
a denylist with the acknowledged-empty sentinel passes silently; a populated
denylist enforces brand token matching.
"""

from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

import pytest

# Load check_public_release without making it a package-level import.
_TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
_spec = importlib.util.spec_from_file_location(
    "check_public_release",
    _TOOLS_DIR / "check_public_release.py",
)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules["check_public_release"] = _mod
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

load_brand_denylist = _mod.load_brand_denylist
check = _mod.check
Finding = _mod.Finding


# ---------------------------------------------------------------------------
# load_brand_denylist unit tests
# ---------------------------------------------------------------------------

class TestLoadBrandDenylist:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = load_brand_denylist(tmp_path)
        assert result == []

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "brand_denylist.txt").write_text("", encoding="utf-8")
        assert load_brand_denylist(tmp_path) == []

    def test_comments_only_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "brand_denylist.txt").write_text(
            "# comment\n# another comment\n", encoding="utf-8"
        )
        assert load_brand_denylist(tmp_path) == []

    def test_acknowledged_empty_sentinel_returns_sentinel_list(self, tmp_path: Path) -> None:
        (tmp_path / "brand_denylist.txt").write_text(
            "# BRAND_GATE: acknowledged-empty\n", encoding="utf-8"
        )
        assert load_brand_denylist(tmp_path) == ["__acknowledged_empty__"]

    def test_populated_denylist_returns_tokens(self, tmp_path: Path) -> None:
        (tmp_path / "brand_denylist.txt").write_text(
            "# header\nAcme\nWidgetCo\n", encoding="utf-8"
        )
        result = load_brand_denylist(tmp_path)
        assert result == ["Acme", "WidgetCo"]

    def test_blank_lines_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "brand_denylist.txt").write_text(
            "Acme\n\n  \nWidgetCo\n", encoding="utf-8"
        )
        assert load_brand_denylist(tmp_path) == ["Acme", "WidgetCo"]


# ---------------------------------------------------------------------------
# PR013 fail-closed brand gate
# ---------------------------------------------------------------------------

def _minimal_repo(tmp_path: Path, *, brand_denylist_content: str = "") -> Path:
    """Write the minimum set of files that pass all non-brand checks."""
    (tmp_path / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    readme = (
        "# Receipt protocol and profiles\n\n"
        "Standard (ARCS)\n\n"
        "<!-- layer-map -->\n"
    )
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "brand_denylist.txt").write_text(brand_denylist_content, encoding="utf-8")
    # Minimal git index so tracked_files has something to iterate.
    # check() falls back to os.walk when .git is absent, so we rely on that.
    return tmp_path


class TestBrandGateFailClosed:
    def test_empty_denylist_emits_pr013(self, tmp_path: Path) -> None:
        _minimal_repo(tmp_path, brand_denylist_content="")
        findings = check(tmp_path, script_dir=tmp_path / "tools")
        codes = [f.rule_id for f in findings]
        assert "PR013" in codes, f"Expected PR013 in {codes}"

    def test_comments_only_denylist_emits_pr013(self, tmp_path: Path) -> None:
        _minimal_repo(
            tmp_path,
            brand_denylist_content="# One candidate brand token per line.\n",
        )
        findings = check(tmp_path, script_dir=tmp_path / "tools")
        codes = [f.rule_id for f in findings]
        assert "PR013" in codes

    def test_acknowledged_empty_sentinel_suppresses_pr013(self, tmp_path: Path) -> None:
        _minimal_repo(
            tmp_path,
            brand_denylist_content="# BRAND_GATE: acknowledged-empty\n",
        )
        findings = check(tmp_path, script_dir=tmp_path / "tools")
        codes = [f.rule_id for f in findings]
        assert "PR013" not in codes

    def test_populated_denylist_suppresses_pr013(self, tmp_path: Path) -> None:
        _minimal_repo(
            tmp_path,
            brand_denylist_content="AcmeCorp\n",
        )
        findings = check(tmp_path, script_dir=tmp_path / "tools")
        codes = [f.rule_id for f in findings]
        assert "PR013" not in codes

    def test_populated_denylist_fires_pr012_on_match(self, tmp_path: Path) -> None:
        _minimal_repo(
            tmp_path,
            brand_denylist_content="WidgetCo\n",
        )
        # Write a file containing the forbidden brand.
        (tmp_path / "README.md").write_text(
            "Receipt protocol and profiles\n<!-- layer-map -->\n"
            "This project is powered by WidgetCo technology.\n",
            encoding="utf-8",
        )
        findings = check(tmp_path, script_dir=tmp_path / "tools")
        codes = [f.rule_id for f in findings]
        assert "PR012" in codes
        assert "PR013" not in codes

    def test_pr013_message_explains_escape_hatch(self, tmp_path: Path) -> None:
        _minimal_repo(tmp_path, brand_denylist_content="")
        findings = check(tmp_path, script_dir=tmp_path / "tools")
        pr013 = [f for f in findings if f.rule_id == "PR013"]
        assert len(pr013) == 1
        assert "acknowledged-empty" in pr013[0].message
