"""SCITT-RATCHET0: the known-gaps ledger is shrink-only against a pinned base.

``failure_code_ratchet.py`` documents the mechanism. These tests prove it; every
adversarial case is a NAMED test that drives one branch, and every case that
needs a base commit runs on a THROWAWAY git repository built from a copy of this
tree, so the real checkout is never written (``test_real_tree_is_not_written``
digest-inventories it before and after).

Cases
* growth rejected even though the ledger was expanded in the same change
  (new code in a gap module / new emitting module / new family / count-neutral
  swap / ledger-only widening / stale branch);
* shrinkage permitted;
* a fully documented new code permitted (no false positive);
* baseline-selection integrity (every guarded file, edited and deleted; the
  out-of-band acceptance valve; a neutered candidate checker; base resolution).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import failure_code_ratchet as ratchet

REAL = ratchet.ROOT
LEDGER_PATH = "tests/failure_code_known_gaps.json"
GAP_MODULE = "arcs_verify/c2pa_srs_observed.py"
REGISTERED_MODULE = "arcs_verify/universal.py"
REPLAY = "arcs_verify/amnesiac/replay.py"
TREES = ("arcs_verify", "docs", "tests", "tools")
FILES = ("pyproject.toml",)
GIT = ["git", "-c", "user.name=ratchet", "-c", "user.email=ratchet@example.invalid", "-c", "commit.gpgsign=false"]


# ---------------------------------------------------------------------------
# throwaway repository harness
# ---------------------------------------------------------------------------


def _copy_tree(dst: Path) -> None:
    for rel in FILES:
        shutil.copyfile(REAL / rel, dst / rel)
    for tree in TREES:
        shutil.copytree(REAL / tree, dst / tree, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout.strip()


def _inventory(base: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for tree in (*TREES, "."):
        pattern = "*" if tree != "." else "pyproject.toml"
        for path in sorted((base / tree).rglob(pattern) if tree != "." else [base / pattern]):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                out[path.relative_to(base).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


@pytest.fixture(scope="module")
def base_repo(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """A repository whose single commit is this tree; origin/main points at it."""
    before = _inventory(REAL)
    root = tmp_path_factory.mktemp("ratchet-base")
    _copy_tree(root)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    sha = _git(root, "rev-parse", "HEAD")
    _git(root, "update-ref", "refs/remotes/origin/main", sha)
    return {"dir": root, "sha": sha, "inventory": before}


@pytest.fixture()
def candidate(base_repo: dict, tmp_path: Path) -> Path:
    """A fresh private copy of the base repository (history included)."""
    dst = tmp_path / "cand"
    shutil.copytree(base_repo["dir"], dst)
    return dst


def run_cli(tree: Path, *args: str, script: Path | None = None, env: dict | None = None) -> tuple[int, str]:
    """Run the ratchet CLI against ``tree``. ``script`` selects WHICH copy runs."""
    entry = script or tree / "tests" / "failure_code_ratchet.py"
    clean = {k: v for k, v in os.environ.items() if not k.startswith("ARCS_VERIFY_RATCHET")}
    clean["PYTHONDONTWRITEBYTECODE"] = "1"
    clean.update(env or {})
    done = subprocess.run(
        [sys.executable, str(entry), "--root", str(tree), *args],
        capture_output=True, text=True, env=clean, timeout=300,
    )
    return done.returncode, done.stdout + done.stderr


def violations(output: str) -> list[tuple[str, str]]:
    return [
        (m.group(1), m.group(2))
        for m in re.finditer(r"^VIOLATION ([A-Z_]+): (.*?)(?: -- .*)?$", output, re.M)
    ]


def verdict(output: str) -> str:
    return next((l for l in output.splitlines() if l.startswith("RATCHET=")), "(no verdict line)")


# --- tree edits ------------------------------------------------------------


def append_source(tree: Path, module: str, text: str) -> None:
    path = tree / module
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def emit_snippet(code: str) -> str:
    return f"\n\ndef _zz_ratchet_probe(report):\n    report.append({code!r})\n"


def edit_ledger(tree: Path, edit) -> None:
    path = tree / LEDGER_PATH
    data = json.loads(path.read_text(encoding="utf-8"))
    edit(data["modules"])
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def add_doc_row(tree: Path, code: str) -> None:
    path = tree / "docs" / "FAILURE_CODES.md"
    path.write_text(path.read_text(encoding="utf-8") + f"\n| `{code}` | ratchet test row |\n", encoding="utf-8")


def commit_all(tree: Path, message: str = "candidate") -> str:
    _git(tree, "add", "-A")
    _git(tree, "commit", "-q", "-m", message)
    return _git(tree, "rev-parse", "HEAD")


# ---------------------------------------------------------------------------
# 0. the harness itself is sound (a control, not a case)
# ---------------------------------------------------------------------------


def test_control_unmodified_candidate_passes(base_repo: dict, candidate: Path) -> None:
    code, out = run_cli(candidate)
    assert code == 0 and verdict(out) == "RATCHET=PASS", out
    assert f"base: {base_repo['sha']}" in out
    assert int(re.search(r"modules checked: (\d+)", out).group(1)) >= 50 and violations(out) == []


def test_real_tree_is_not_written(base_repo: dict) -> None:
    """The throwaway repositories never touch the real checkout."""
    assert _inventory(REAL) == base_repo["inventory"]


# ---------------------------------------------------------------------------
# 1. GROWTH IS REJECTED, even when the ledger is expanded in the same change
# ---------------------------------------------------------------------------


def test_growth_new_code_in_gap_module_rejected_when_ledger_expanded_in_same_commit(candidate: Path) -> None:
    """THE reported hole. Add an undocumented code to a gap module AND add it to
    the ledger, in one commit. The pre-existing exact-set check PASSES; the
    ratchet must refuse and name the code."""
    append_source(candidate, GAP_MODULE, emit_snippet("ZZ_CONCEALED_CODE"))
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["codes"].append("ZZ_CONCEALED_CODE") or m[GAP_MODULE]["codes"].sort())
    commit_all(candidate, "conceal an undocumented code")

    legacy = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:warnings",
         "tests/test_failure_code_census.py", "-k", f"test_known_gap_is_exactly_the_undocumented_set and {Path(GAP_MODULE).name}"],
        cwd=candidate, capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert legacy.returncode == 0 and "1 passed" in legacy.stdout, (
        "the P3 exact-set check was expected to be fooled by the same-commit ledger edit:\n" + legacy.stdout
    )

    code, out = run_cli(candidate)
    # GROWTH_CODE: the emission is not permitted by the base. LEDGER_GROWTH: the ledger edit itself.
    assert code == 1 and verdict(out) == "RATCHET=FAIL GROWTH_CODE,LEDGER_GROWTH", out
    assert (ratchet.GROWTH_CODE, f"{GAP_MODULE}: ZZ_CONCEALED_CODE") in violations(out)


def test_growth_rejected_when_the_base_is_a_committed_branch_tip_the_candidate_cannot_move(base_repo: dict, candidate: Path) -> None:
    """The candidate commits on its own branch; origin/main and therefore the
    base do not move, so the base SHA is unchanged by the candidate's history."""
    append_source(candidate, GAP_MODULE, emit_snippet("ZZ_COMMITTED_CONCEALMENT"))
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["codes"].append("ZZ_COMMITTED_CONCEALMENT"))
    head = commit_all(candidate)
    assert head != base_repo["sha"]
    code, out = run_cli(candidate)
    assert code == 1 and f"base: {base_repo['sha']}" in out
    assert (ratchet.GROWTH_CODE, f"{GAP_MODULE}: ZZ_COMMITTED_CONCEALMENT") in violations(out)


def test_growth_new_emitting_module_with_a_ledger_entry_rejected(candidate: Path) -> None:
    (candidate / "arcs_verify" / "zz_ratchet_new_module.py").write_text(
        "def f(report):\n    report.append('ZZ_NEW_MODULE_CODE')\n", encoding="utf-8"
    )
    edit_ledger(candidate, lambda m: m.__setitem__(
        "arcs_verify/zz_ratchet_new_module.py",
        {"codes": ["ZZ_NEW_MODULE_CODE"], "families": [], "reason": "concealed"},
    ))
    code, out = run_cli(candidate)
    assert code == 1
    assert ("GROWTH_NEW_MODULE", "arcs_verify/zz_ratchet_new_module.py") in violations(out), out
    assert ("LEDGER_GROWTH", "arcs_verify/zz_ratchet_new_module.py") in violations(out)


def test_growth_new_undocumented_family_in_gap_module_rejected(candidate: Path) -> None:
    append_source(candidate, GAP_MODULE, "\n\ndef _zz_family_probe(report, x):\n    report.append(f'zz_ratchet_family.{x}')\n")
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["families"].append("zz_ratchet_family."))
    code, out = run_cli(candidate)
    assert code == 1
    assert (ratchet.GROWTH_FAMILY, f"{GAP_MODULE}: zz_ratchet_family.<...>") in violations(out), out


def test_growth_undocumented_code_in_a_registered_module_rejected_even_with_a_fresh_ledger_key(candidate: Path) -> None:
    """A registered module has no allowance at the base: the same-commit trick of
    inventing a ledger key for it is refused."""
    append_source(candidate, REGISTERED_MODULE, emit_snippet("ZZ_REGISTERED_CONCEALMENT"))
    edit_ledger(candidate, lambda m: m.__setitem__(
        REGISTERED_MODULE, {"codes": ["ZZ_REGISTERED_CONCEALMENT"], "families": [], "reason": "concealed"}
    ))
    code, out = run_cli(candidate)
    assert code == 1
    assert ("GROWTH_NEW_MODULE", REGISTERED_MODULE) in violations(out), out


def test_growth_count_neutral_swap_rejected(candidate: Path) -> None:
    """Document one gap code and smuggle in a different one: the ledger gets
    SHORTER-OR-EQUAL, which a size or count comparison would wave through."""
    append_source(candidate, REPLAY, emit_snippet("ZZ_SWAP_IN"))
    add_doc_row(candidate, "render_mismatch")

    def swap(m: dict) -> None:
        m[REPLAY]["codes"].remove("render_mismatch")
        m[REPLAY]["codes"].append("ZZ_SWAP_IN")

    edit_ledger(candidate, swap)
    before = len(json.loads((REAL / LEDGER_PATH).read_text())["modules"][REPLAY]["codes"])
    after = len(json.loads((candidate / LEDGER_PATH).read_text())["modules"][REPLAY]["codes"])
    assert after == before, "the swap must be count-neutral for this case to mean anything"
    code, out = run_cli(candidate)
    assert code == 1
    assert (ratchet.GROWTH_CODE, f"{REPLAY}: ZZ_SWAP_IN") in violations(out), out
    assert {s for _, s in violations(out)} == {f"{REPLAY}: ZZ_SWAP_IN"}, "only the smuggled code is named; the documented swap-out is not"


def test_growth_ledger_only_widening_rejected_without_any_emission(candidate: Path) -> None:
    """Pre-widening the ledger (no emission yet) is refused so a later commit
    cannot lean on headroom this one created."""
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["codes"].append("ZZ_HEADROOM"))
    code, out = run_cli(candidate)
    assert code == 1
    assert (ratchet.LEDGER_GROWTH, f"{GAP_MODULE}: ZZ_HEADROOM") in violations(out), out


def test_growth_ledger_only_family_widening_rejected(candidate: Path) -> None:
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["families"].append("zz_headroom."))
    code, out = run_cli(candidate)
    assert code == 1
    assert (ratchet.LEDGER_GROWTH, f"{GAP_MODULE}: zz_headroom.<...>") in violations(out), out


def test_stale_branch_cannot_buy_a_larger_allowance_than_the_main_tip(base_repo: dict, candidate: Path) -> None:
    """Main shrinks the ledger after the branch was cut. The base is the TIP, not
    the merge-base, so a branch that still carries the closed gap is refused."""
    stale = _git(candidate, "rev-parse", "HEAD")
    add_doc_row(candidate, "render_mismatch")
    edit_ledger(candidate, lambda m: m[REPLAY]["codes"].remove("render_mismatch"))
    tip = commit_all(candidate, "main shrinks the ledger")
    _git(candidate, "update-ref", "refs/remotes/origin/main", tip)
    _git(candidate, "checkout", "-q", "--detach", stale)  # candidate worktree = stale tree
    code, out = run_cli(candidate)
    assert code == 1 and f"base: {tip}" in out
    assert (ratchet.GROWTH_CODE, f"{REPLAY}: render_mismatch") in violations(out), out


# ---------------------------------------------------------------------------
# 2. SHRINKAGE IS PERMITTED
# ---------------------------------------------------------------------------


def test_shrinkage_documenting_a_gap_code_and_removing_it_from_the_ledger_passes(candidate: Path) -> None:
    add_doc_row(candidate, "render_mismatch")
    edit_ledger(candidate, lambda m: m[REPLAY]["codes"].remove("render_mismatch"))
    code, out = run_cli(candidate)
    assert code == 0 and verdict(out) == "RATCHET=PASS" and violations(out) == [], out


def test_shrinkage_closing_a_whole_gap_module_passes(candidate: Path) -> None:
    ledger = json.loads((candidate / LEDGER_PATH).read_text())["modules"][GAP_MODULE]
    for item in ledger["codes"]:
        add_doc_row(candidate, item)
    edit_ledger(candidate, lambda m: m.pop(GAP_MODULE))
    code, out = run_cli(candidate)
    assert code == 0 and verdict(out) == "RATCHET=PASS", out


# ---------------------------------------------------------------------------
# 3. A FULLY DOCUMENTED NEW CODE IS PERMITTED (no false positive)
# ---------------------------------------------------------------------------


def test_fully_documented_new_code_in_a_registered_module_passes(candidate: Path) -> None:
    append_source(candidate, REGISTERED_MODULE, emit_snippet("zz_ratchet_documented_code"))
    add_doc_row(candidate, "zz_ratchet_documented_code")
    code, out = run_cli(candidate)
    assert code == 0 and verdict(out) == "RATCHET=PASS" and violations(out) == [], out


def test_fully_documented_new_code_in_a_gap_module_passes_without_touching_the_ledger(candidate: Path) -> None:
    append_source(candidate, GAP_MODULE, emit_snippet("zz_ratchet_documented_gap_code"))
    add_doc_row(candidate, "zz_ratchet_documented_gap_code")
    code, out = run_cli(candidate)
    assert code == 0 and verdict(out) == "RATCHET=PASS", out


# ---------------------------------------------------------------------------
# 4. BASELINE-SELECTION INTEGRITY
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("guarded", ratchet.GUARDED)
def test_selection_edit_to_each_guarded_file_is_detected_by_name(guarded: str, base_repo: dict, candidate: Path) -> None:
    assert (candidate / guarded).is_file(), f"{guarded} must exist in the base snapshot"
    append_source(candidate, guarded, "\n# repoint the baseline\n")
    code, out = run_cli(candidate, script=base_repo["dir"] / "tests" / "failure_code_ratchet.py")
    assert code == 1
    assert violations(out) == [(ratchet.SELECTION_CHANGED, guarded)], out


@pytest.mark.parametrize("guarded", ratchet.GUARDED)
def test_selection_deletion_of_each_guarded_file_is_detected_by_name(guarded: str, base_repo: dict, candidate: Path) -> None:
    (candidate / guarded).unlink()
    code, out = run_cli(candidate, script=base_repo["dir"] / "tests" / "failure_code_ratchet.py")
    assert code == 1
    assert (ratchet.SELECTION_CHANGED, guarded) in violations(out), out
    # the deletion branch, not the generic "differs" branch, must be the one that fired
    assert f"VIOLATION SELECTION_CHANGED: {guarded} -- guarded file deleted relative to the base" in out, out


def test_selection_repointing_the_default_base_to_a_permissive_commit_is_detected(base_repo: dict, candidate: Path) -> None:
    """The scenario the guard exists for: the candidate repoints the base at an
    OLD commit whose ledger is larger, then adds the code. Run in-tree (the
    candidate's own checker, still doing its comparison) the repoint is flagged
    as a guarded-file change."""
    old = _git(candidate, "rev-parse", "HEAD")
    append_source(candidate, GAP_MODULE, emit_snippet("ZZ_REPOINT"))
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["codes"].append("ZZ_REPOINT"))
    path = candidate / "tests" / "failure_code_ratchet.py"
    text = path.read_text(encoding="utf-8")
    patched = text.replace('DEFAULT_BASE_REF = "refs/remotes/origin/main"', f'DEFAULT_BASE_REF = "{old}"')
    assert patched != text
    path.write_text(patched, encoding="utf-8")
    code, out = run_cli(candidate)
    assert code == 1 and ratchet.SELECTION_CHANGED in {c for c, _ in violations(out)}, out
    assert (ratchet.SELECTION_CHANGED, "tests/failure_code_ratchet.py") in violations(out)


def test_authoritative_base_copy_run_defeats_a_neutered_candidate_checker(base_repo: dict, candidate: Path) -> None:
    """HONEST LIMIT, proven: a candidate may rewrite its own checker to approve
    everything, and that checker then says PASS. The authoritative run executes
    the BASE's copy of the checker against the candidate tree and refuses."""
    append_source(candidate, GAP_MODULE, emit_snippet("ZZ_NEUTERED"))
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["codes"].append("ZZ_NEUTERED"))
    mine = candidate / "tests" / "failure_code_ratchet.py"
    mine.write_text(
        mine.read_text(encoding="utf-8").replace("def main(argv: list[str] | None = None) -> int:",
                                                 "def main(argv: list[str] | None = None) -> int:\n    print('RATCHET=PASS')\n    return 0\n\n\ndef _original(argv=None):"),
        encoding="utf-8",
    )
    code_own, out_own = run_cli(candidate)
    assert code_own == 0 and verdict(out_own) == "RATCHET=PASS", "the neutered candidate checker should self-approve"
    code, out = run_cli(candidate, script=base_repo["dir"] / "tests" / "failure_code_ratchet.py")
    assert code == 1
    assert (ratchet.GROWTH_CODE, f"{GAP_MODULE}: ZZ_NEUTERED") in violations(out)
    assert (ratchet.SELECTION_CHANGED, "tests/failure_code_ratchet.py") in violations(out)


def test_selection_change_accepted_only_by_the_out_of_band_digest(base_repo: dict, candidate: Path) -> None:
    guarded = "tests/failure_code_census.py"
    append_source(candidate, guarded, "\n# reviewed change\n")
    digest = ratchet.selection_digest(ratchet.selection_manifest(candidate))
    entry = base_repo["dir"] / "tests" / "failure_code_ratchet.py"
    code, out = run_cli(candidate, "--accept-selection-change", digest, script=entry)
    assert code == 0 and "selection change ACCEPTED" in out and violations(out) == [], out
    code, out = run_cli(candidate, script=entry, env={ratchet.ENV_ACCEPT: digest})
    assert code == 0 and "selection change ACCEPTED" in out, "the environment form is equivalent"


def test_selection_acceptance_with_a_wrong_digest_is_refused(base_repo: dict, candidate: Path) -> None:
    append_source(candidate, "tests/failure_code_census.py", "\n# reviewed change\n")
    entry = base_repo["dir"] / "tests" / "failure_code_ratchet.py"
    for wrong in ("0" * 64, hashlib.sha256(b"x").hexdigest(), ratchet.selection_digest(ratchet.selection_manifest(base_repo["dir"]))):
        code, out = run_cli(candidate, "--accept-selection-change", wrong, script=entry)
        assert code == 1 and (ratchet.SELECTION_CHANGED, "tests/failure_code_census.py") in violations(out), out


def test_selection_acceptance_cannot_be_granted_from_inside_the_tree(base_repo: dict, candidate: Path) -> None:
    """A digest file, a note, or a config key in the candidate is not an input."""
    append_source(candidate, "tests/failure_code_census.py", "\n# reviewed change\n")
    digest = ratchet.selection_digest(ratchet.selection_manifest(candidate))
    for name in ("tests/ACCEPT_SELECTION", "tests/failure_code_ratchet.accept", ".ratchet-accept"):
        (candidate / name).write_text(digest + "\n", encoding="utf-8")
    edit_ledger(candidate, lambda m: None)
    data = json.loads((candidate / LEDGER_PATH).read_text())
    data["accept_selection_change"] = digest
    (candidate / LEDGER_PATH).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    code, out = run_cli(candidate, script=base_repo["dir"] / "tests" / "failure_code_ratchet.py")
    assert code == 1 and (ratchet.SELECTION_CHANGED, "tests/failure_code_census.py") in violations(out), out


def test_acceptance_of_a_selection_change_does_not_excuse_growth(base_repo: dict, candidate: Path) -> None:
    append_source(candidate, "tests/failure_code_census.py", "\n# reviewed change\n")
    append_source(candidate, GAP_MODULE, emit_snippet("ZZ_STILL_GROWTH"))
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["codes"].append("ZZ_STILL_GROWTH"))
    digest = ratchet.selection_digest(ratchet.selection_manifest(candidate))
    code, out = run_cli(candidate, "--accept-selection-change", digest, script=base_repo["dir"] / "tests" / "failure_code_ratchet.py")
    assert code == 1 and (ratchet.GROWTH_CODE, f"{GAP_MODULE}: ZZ_STILL_GROWTH") in violations(out), out


def test_first_introduction_of_a_guarded_file_is_reported_not_rejected(base_repo: dict, candidate: Path) -> None:
    """A guarded file that is absent at the base is an INTRODUCTION (this very
    change). It is listed for owner review; it is not a violation."""
    # Re-base: origin/main = a commit that lacks the ratchet test file.
    _git(candidate, "rm", "-q", "tests/test_failure_code_ratchet.py")
    older = commit_all(candidate, "base without the ratchet test")
    _git(candidate, "update-ref", "refs/remotes/origin/main", older)
    # candidate worktree re-adds it (file restored from the real tree)
    shutil.copyfile(REAL / "tests" / "test_failure_code_ratchet.py", candidate / "tests" / "test_failure_code_ratchet.py")
    code, out = run_cli(candidate)
    assert code == 0 and "first introduced" in out and "tests/test_failure_code_ratchet.py" in out, out


# --- base resolution -------------------------------------------------------


def test_base_missing_origin_main_is_unresolved_not_a_pass(candidate: Path) -> None:
    _git(candidate, "update-ref", "-d", "refs/remotes/origin/main")
    code, out = run_cli(candidate)
    assert code == 2 and verdict(out) == "RATCHET=FAIL BASE_UNRESOLVED", out


@pytest.mark.parametrize("spec", ["--upload-pack=touch /tmp/x", "main", "HEAD", "origin/main", "6aeb99e", "z" * 40, "0" * 40])
def test_base_explicit_pin_must_be_a_full_resolvable_sha(spec: str, candidate: Path) -> None:
    code, out = run_cli(candidate, "--base", spec)
    assert code == 2 and (ratchet.BASE_UNRESOLVED, spec) in violations(out), out


def test_base_explicit_pin_not_on_main_is_refused(base_repo: dict, candidate: Path) -> None:
    """A permissive side commit that is not an ancestor of origin/main cannot be
    pinned, even by a well-formed SHA."""
    _git(candidate, "checkout", "-q", "-b", "side")
    edit_ledger(candidate, lambda m: m[GAP_MODULE]["codes"].append("ZZ_SIDE_ALLOWANCE"))
    side = commit_all(candidate, "permissive side commit")
    code, out = run_cli(candidate, "--base", side)
    assert code == 2 and (ratchet.BASE_NOT_ON_MAIN, side) in violations(out), out


def test_base_explicit_pin_on_main_is_honoured(base_repo: dict, candidate: Path) -> None:
    code, out = run_cli(candidate, "--base", base_repo["sha"])
    assert code == 0 and f"base: {base_repo['sha']}" in out, out
    code, out = run_cli(candidate, env={ratchet.ENV_BASE: base_repo["sha"]})
    assert code == 0 and f"base: {base_repo['sha']}" in out, out


def test_base_without_a_readable_ledger_is_refused(candidate: Path) -> None:
    _git(candidate, "rm", "-q", LEDGER_PATH)
    tip = commit_all(candidate, "base without a ledger")
    _git(candidate, "update-ref", "refs/remotes/origin/main", tip)
    shutil.copyfile(REAL / LEDGER_PATH, candidate / LEDGER_PATH)  # the candidate still has one
    code, out = run_cli(candidate)
    assert code == 2 and ratchet.BASE_LEDGER_UNREADABLE in {c for c, _ in violations(out)}, out


# ---------------------------------------------------------------------------
# 5. the pure decision, one branch per test
# ---------------------------------------------------------------------------

_BASE = {"m.py": {"codes": ["a", "b"], "families": ["f:"], "reason": "r"}}


def _codes(found) -> list[str]:
    return [v.code for v in found]


def test_decision_growth_branches() -> None:
    gv = ratchet.growth_violations
    assert gv({}, _BASE, _BASE) == []
    assert gv({"m.py": ({"a"}, {"f:"})}, _BASE, _BASE) == []                      # equal
    assert gv({"m.py": ({"a"}, set())}, _BASE, {"m.py": {"codes": ["a"], "families": []}}) == []  # shrink
    assert _codes(gv({"m.py": ({"a", "c"}, set())}, _BASE, _BASE)) == [ratchet.GROWTH_CODE]
    assert _codes(gv({"m.py": (set(), {"g:"})}, _BASE, _BASE)) == [ratchet.GROWTH_FAMILY]
    assert _codes(gv({"n.py": ({"x"}, set())}, _BASE, _BASE)) == [ratchet.GROWTH_NEW_MODULE]
    # the candidate ledger is IRRELEVANT to the permission decision
    widened = {"m.py": {"codes": ["a", "b", "c"], "families": ["f:"]}}
    assert ratchet.GROWTH_CODE in _codes(gv({"m.py": ({"c"}, set())}, _BASE, widened))
    assert ratchet.LEDGER_GROWTH in _codes(gv({}, _BASE, widened))


def test_decision_ledger_growth_branches() -> None:
    gv = ratchet.growth_violations
    assert _codes(gv({}, _BASE, {"m.py": {"codes": ["a", "z"], "families": ["f:"]}})) == [ratchet.LEDGER_GROWTH]
    assert _codes(gv({}, _BASE, {"m.py": {"codes": ["a"], "families": ["f:", "g:"]}})) == [ratchet.LEDGER_GROWTH]
    assert _codes(gv({}, _BASE, {"n.py": {"codes": [], "families": []}})) == [ratchet.LEDGER_GROWTH]


def test_decision_selection_branches() -> None:
    names = ratchet.GUARDED
    same = {p: "h" for p in names}
    assert ratchet.selection_violations(same, dict(same)) == ([], [])
    changed = dict(same, **{names[0]: "other"})
    found, _ = ratchet.selection_violations(changed, same)
    assert [(v.code, v.subject) for v in found] == [(ratchet.SELECTION_CHANGED, names[0])]
    gone = dict(same, **{names[1]: "ABSENT"})
    found, _ = ratchet.selection_violations(gone, same)
    assert [(v.code, v.subject) for v in found] == [(ratchet.SELECTION_CHANGED, names[1])]
    found, introduced = ratchet.selection_violations(same, dict(same, **{names[2]: None}))
    assert found == [] and introduced == [names[2]]
    assert ratchet.selection_violations(dict(same, **{names[3]: "ABSENT"}), dict(same, **{names[3]: None})) == ([], [])


def test_selection_digest_binds_every_guarded_file_and_its_name() -> None:
    manifest = {p: "h" for p in ratchet.GUARDED}
    base = ratchet.selection_digest(manifest)
    for path in ratchet.GUARDED:
        assert ratchet.selection_digest(dict(manifest, **{path: "x"})) != base, path
    swapped = dict(manifest, **{ratchet.GUARDED[0]: "a", ratchet.GUARDED[1]: "b"})
    reverse = dict(manifest, **{ratchet.GUARDED[0]: "b", ratchet.GUARDED[1]: "a"})
    assert ratchet.selection_digest(swapped) != ratchet.selection_digest(reverse)


# ---------------------------------------------------------------------------
# 6. the real tree, against the real pinned base
# ---------------------------------------------------------------------------


def test_real_tree_does_not_grow_against_the_pinned_base() -> None:
    import test_failure_code_census as gate

    sha, problems = ratchet.resolve_base(REAL, None)
    if sha is None:
        if ratchet.required():
            pytest.fail(f"NOT_EXERCISED is not acceptable here: {problems}")
        pytest.skip(f"NOT_EXERCISED: no pinned base is resolvable ({problems[0]})")
    result = ratchet.evaluate(REAL, gate)
    assert result.ok, "\n".join(str(v) for v in result.violations)
    assert result.base == sha and result.modules_checked >= 50
