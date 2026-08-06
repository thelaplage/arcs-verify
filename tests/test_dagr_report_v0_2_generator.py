"""Generator and golden-provenance gate for the v0.2 report contract.

    python -m pytest tests/test_dagr_report_v0_2_generator.py -q

A verification report carries a ``verifier_commit``: a concrete claim about
which implementation produced it. Closure has landed, so that claim is now
made, exactly once, against the implementation squash-merge commit. That is
enforced here rather than merely documented.

Six proofs:

1. the generator refuses to run without ``--verifier-commit``;
2. it rejects a value that is not a full 40-hex lowercase commit SHA;
3. every generated report carries the supplied commit exactly;
4. two temporary generations are byte-identical;
5. the authoritative v0.2 report goldens are committed, and only under
   ``golden/``;
6. the v0.2 README records completed closure and the merge commit.

Byte-level agreement between the committed goldens and a fresh generation is
proven in ``tests/test_dagr_report_v0_2_golden_closure.py``.

Every generation performed *here* writes into ``tmp_path`` with an explicitly
synthetic commit. Such output is scratch and is never an authoritative golden.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from arcs_verify import dagr_report_v0_2 as dr2
from arcs_verify import subject_ref_origin as sro

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "tools" / "generate_dagr_report_v0_2_goldens.py"

V0_2_ROOT = dr2._CONTRACT_ROOT
V0_2_GOLDEN = V0_2_ROOT / "golden"
V0_2_INPUTS = V0_2_ROOT / "input-fixtures"
V0_2_README = V0_2_ROOT / "README.md"
V0_2_STATUS = V0_2_ROOT / "contract-status.json"
V0_2_MANIFEST = V0_2_ROOT / "golden-digest-manifest.json"

#: The implementation squash-merge commit closure generated the goldens
#: against. Supplied to the generator as an input; never inferred from git.
IMPLEMENTATION_MERGE_COMMIT = "c26af32fcb638489217f4cb43845eca7b2824516"

# Explicitly synthetic. Not a commit of this repository, and deliberately not
# derivable from one: temporary generations must never look authoritative.
SYNTHETIC_COMMIT = "a" * 40
OTHER_SYNTHETIC_COMMIT = "b" * 40

MALFORMED_COMMITS = [
    pytest.param("", id="empty"),
    pytest.param("HEAD", id="mutable_ref"),
    pytest.param("main", id="branch_name"),
    pytest.param("fb35ed6", id="abbreviated_sha"),
    pytest.param("a" * 39, id="thirty_nine_hex"),
    pytest.param("a" * 41, id="forty_one_hex"),
    pytest.param("A" * 40, id="uppercase_hex"),
    pytest.param("g" * 40, id="non_hex_characters"),
    pytest.param(" " + "a" * 40, id="leading_space"),
    pytest.param("a" * 40 + "\n", id="trailing_newline"),
]


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_dagr_report_v0_2_goldens", GENERATOR_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _load_generator()

STATES = list(sro.DECLARED_ORIGINS) + [sro.NOT_DECLARED]
SLUGS = [state.replace("_", "-") for state in STATES]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digest(directory: Path) -> dict[str, str]:
    return {
        path.name: _sha256(path) for path in sorted(directory.rglob("*")) if path.is_file()
    }


def _tracked_files(relative_to: Path) -> list[str] | None:
    """Tracked paths under ``relative_to``, or None outside a git checkout."""

    if not (ROOT / ".git").exists():
        return None
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--", str(relative_to)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return [item.decode("utf-8") for item in proc.stdout.split(b"\0") if item]


# ---------------------------------------------------------------------------
# Proof 1: execution identity is mandatory
# ---------------------------------------------------------------------------


def test_generator_refuses_to_run_without_verifier_commit(tmp_path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        GEN.main(["--output-dir", str(tmp_path / "out")])
    assert exc_info.value.code == 2
    assert not (tmp_path / "out").exists()


def test_generator_refuses_to_run_without_output_dir() -> None:
    with pytest.raises(SystemExit) as exc_info:
        GEN.main(["--verifier-commit", SYNTHETIC_COMMIT])
    assert exc_info.value.code == 2


def test_generator_refuses_to_run_with_no_arguments_at_all() -> None:
    with pytest.raises(SystemExit) as exc_info:
        GEN.main([])
    assert exc_info.value.code == 2


def test_generator_has_no_default_for_either_required_argument() -> None:
    actions = {
        action.dest: action
        for action in GEN.build_parser()._actions
        if action.dest != "help"
    }
    assert set(actions) == {"verifier_commit", "output_dir"}
    for action in actions.values():
        assert action.required is True, action.dest
        assert action.default is None, action.dest


def test_generator_never_consults_repository_state() -> None:
    """No branch-base constant, no implicit HEAD, no git invocation."""

    source = GENERATOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".", 1)[0])
    assert "subprocess" not in imported
    assert "os" not in imported

    assert "rev-parse" not in source

    # No 40-hex literal anywhere: a hard-coded commit is exactly the defect
    # this correction removes.
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert not GEN.VERIFIER_COMMIT_RE.fullmatch(node.value), node.value


# ---------------------------------------------------------------------------
# Proof 2: malformed commit values fail
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", MALFORMED_COMMITS)
def test_generator_rejects_a_non_40_hex_commit(value: str, tmp_path) -> None:
    out = tmp_path / "out"
    with pytest.raises(GEN.InvalidVerifierCommit):
        GEN.generate(verifier_commit=value, output_dir=out)
    assert not out.exists()


@pytest.mark.parametrize("value", MALFORMED_COMMITS)
def test_generator_cli_exits_2_on_a_malformed_commit(
    value: str, tmp_path, capsys
) -> None:
    out = tmp_path / "out"
    assert GEN.main(["--verifier-commit", value, "--output-dir", str(out)]) == 2
    assert "40-hex" in capsys.readouterr().err
    assert not out.exists()


def test_generator_accepts_only_the_contract_commit_pattern() -> None:
    schema = json.loads(
        (V0_2_ROOT / "verification-report.schema.json").read_text(encoding="utf-8")
    )
    assert (
        GEN.VERIFIER_COMMIT_RE.pattern
        == schema["properties"]["verifier_commit"]["pattern"]
    )
    assert GEN.normalized_verifier_commit(SYNTHETIC_COMMIT) == SYNTHETIC_COMMIT


# ---------------------------------------------------------------------------
# Proof 3: the supplied commit is carried exactly
# ---------------------------------------------------------------------------


def test_every_generated_report_carries_the_supplied_commit(tmp_path) -> None:
    out = tmp_path / "out"
    GEN.generate(verifier_commit=SYNTHETIC_COMMIT, output_dir=out)

    reports = sorted(out.glob("*-report.json"))
    assert [path.name for path in reports] == sorted(
        f"origin-{slug}-report.json" for slug in SLUGS
    )
    for path in reports:
        report = json.loads(path.read_text(encoding="utf-8"))
        assert report["verifier_commit"] == SYNTHETIC_COMMIT, path.name
        assert dr2.validate_verification_report(report) == [], path.name

    expectations = json.loads((out / "expectations.json").read_text(encoding="utf-8"))
    assert expectations["verifier_commit"] == SYNTHETIC_COMMIT


def test_a_different_commit_changes_only_the_commit(tmp_path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    GEN.generate(verifier_commit=SYNTHETIC_COMMIT, output_dir=first)
    GEN.generate(verifier_commit=OTHER_SYNTHETIC_COMMIT, output_dir=second)

    for slug in SLUGS:
        a = json.loads(
            (first / f"origin-{slug}-report.json").read_text(encoding="utf-8")
        )
        b = json.loads(
            (second / f"origin-{slug}-report.json").read_text(encoding="utf-8")
        )
        assert a["verifier_commit"] == SYNTHETIC_COMMIT
        assert b["verifier_commit"] == OTHER_SYNTHETIC_COMMIT
        assert {
            key for key in set(a) | set(b) if a.get(key) != b.get(key)
        } == {"verifier_commit"}

    # The inputs do not depend on execution identity at all.
    for name in [f"origin-{slug}-receipt.json" for slug in SLUGS] + [
        "trust-bundle.json"
    ]:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


# ---------------------------------------------------------------------------
# Proof 4: generation is deterministic
# ---------------------------------------------------------------------------


def test_two_temporary_generations_are_byte_identical(tmp_path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    GEN.generate(verifier_commit=SYNTHETIC_COMMIT, output_dir=first)
    GEN.generate(verifier_commit=SYNTHETIC_COMMIT, output_dir=second)

    digests = _tree_digest(first)
    assert digests == _tree_digest(second)
    # 6 receipts + 6 reports + trust bundle + expectations.
    assert len(digests) == 14


def test_regenerating_into_the_same_directory_is_stable(tmp_path) -> None:
    out = tmp_path / "out"
    GEN.generate(verifier_commit=SYNTHETIC_COMMIT, output_dir=out)
    before = _tree_digest(out)
    GEN.generate(verifier_commit=SYNTHETIC_COMMIT, output_dir=out)
    assert _tree_digest(out) == before


def test_committed_input_fixtures_are_exactly_what_the_generator_emits(
    tmp_path,
) -> None:
    """The input fixtures are the generator's own deterministic output."""

    out = tmp_path / "out"
    GEN.generate(verifier_commit=SYNTHETIC_COMMIT, output_dir=out)

    for name in [f"origin-{slug}-receipt.json" for slug in SLUGS] + [
        "trust-bundle.json"
    ]:
        assert (V0_2_INPUTS / name).read_bytes() == (out / name).read_bytes(), name


# ---------------------------------------------------------------------------
# Proof 5: authoritative v0.2 report goldens are committed, and only there
# ---------------------------------------------------------------------------


def test_report_goldens_are_committed_only_under_golden() -> None:
    tracked = _tracked_files(V0_2_ROOT.relative_to(ROOT))
    if tracked is None:
        pytest.skip("requires a git checkout; tracked-file closure cannot be evaluated from an export")
    generated = sorted(
        path
        for path in tracked
        if path.endswith("-report.json") or path.endswith("expectations.json")
    )
    assert generated, "closure commits the authoritative goldens"
    golden_prefix = V0_2_GOLDEN.relative_to(ROOT).as_posix() + "/"
    for path in generated:
        assert path.startswith(golden_prefix), path


def test_the_v0_2_golden_directory_holds_the_full_generated_surface() -> None:
    tracked = _tracked_files(V0_2_GOLDEN.relative_to(ROOT))
    if tracked is None:
        pytest.skip("requires a git checkout; tracked-file closure cannot be evaluated from an export")
    prefix = V0_2_GOLDEN.relative_to(ROOT).as_posix() + "/"
    assert sorted(tracked) == sorted(
        prefix + name
        for name in [f"origin-{slug}-receipt.json" for slug in SLUGS]
        + [f"origin-{slug}-report.json" for slug in SLUGS]
        + ["trust-bundle.json", "expectations.json"]
    )


def test_only_generated_v0_2_artifacts_claim_a_verifier_commit() -> None:
    """The commit claim lives in generated output and the closure metadata."""

    tracked = _tracked_files(V0_2_ROOT.relative_to(ROOT))
    if tracked is None:
        pytest.skip("requires a git checkout; tracked-file closure cannot be evaluated from an export")
    golden_prefix = V0_2_GOLDEN.relative_to(ROOT).as_posix() + "/"
    manifest_path = (V0_2_MANIFEST.relative_to(ROOT)).as_posix()
    status_path = (V0_2_STATUS.relative_to(ROOT)).as_posix()

    for relative in tracked:
        path = ROOT / relative
        if path.suffix != ".json":
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        may_claim = (
            relative.startswith(golden_prefix)
            or relative == manifest_path
            or relative == status_path
        )
        if isinstance(payload, dict) and not may_claim:
            assert "verifier_commit" not in payload, relative

        text = path.read_text(encoding="utf-8")
        # Never the branch base, and never the implementation branch HEAD: a
        # squash merge made both stale, which is why closure supplies the
        # squash-merge commit instead.
        assert "67b4b071980c64b152d574c9b18af536fbe890ef" not in text, relative


def test_input_fixtures_are_not_presented_as_goldens() -> None:
    readme = (V0_2_INPUTS / "README.md").read_text(encoding="utf-8")
    assert "not goldens" in readme.lower()
    assert "not authoritative" in readme.lower()

    names = {path.name for path in V0_2_INPUTS.iterdir()}
    assert not any(name.endswith("-report.json") for name in names)
    assert "expectations.json" not in names


# ---------------------------------------------------------------------------
# Proof 6: completed closure is recorded
# ---------------------------------------------------------------------------


def test_readme_records_completed_closure() -> None:
    readme = V0_2_README.read_text(encoding="utf-8")
    lowered = readme.lower()

    assert "release-closed" in lowered
    assert "closure is complete" in lowered
    assert "merged-authoritative report goldens" in lowered
    assert "squash-merge commit" in lowered
    assert "closure pr" in lowered

    assert "do not yet exist" not in lowered
    assert "not release-closed" not in lowered

    assert "python tools/generate_dagr_report_v0_2_goldens.py" in readme
    assert f"--verifier-commit {IMPLEMENTATION_MERGE_COMMIT}" in readme
    assert "<IMPLEMENTATION_MERGE_COMMIT>" not in readme
    assert (
        "--output-dir arcs_verify/contracts/dagr-srs-verification-report-v0-2/golden"
        in readme
    )


def test_readme_identifies_the_implementation_merge_commit() -> None:
    readme = V0_2_README.read_text(encoding="utf-8")
    assert IMPLEMENTATION_MERGE_COMMIT in readme
    assert "implementation merge commit" in readme.lower()


def test_readme_keeps_the_input_fixture_and_golden_distinction() -> None:
    readme = V0_2_README.read_text(encoding="utf-8")
    lowered = readme.lower()
    assert "generator **inputs**, not goldens, not authoritative" in readme
    assert "authoritative" in lowered
    assert "input-fixtures/" in readme
    assert "golden/" in readme


def test_contract_status_metadata_matches_the_readme() -> None:
    status = json.loads(V0_2_STATUS.read_text(encoding="utf-8"))
    assert status["status"] == "release_closed"
    assert status["release_closed"] is True
    assert status["deterministic_golden_generation_available"] is True
    assert status["merged_authoritative_report_goldens_exist"] is True
    assert status["implementation_merge_commit"] == IMPLEMENTATION_MERGE_COMMIT
    assert status["golden_digest_manifest"] == V0_2_MANIFEST.name
    assert status["verifier_commit_pattern"] == GEN.VERIFIER_COMMIT_RE.pattern
    assert GEN.VERIFIER_COMMIT_RE.fullmatch(status["implementation_merge_commit"])
    assert set(status["generator_required_arguments"]) == {
        "--verifier-commit",
        "--output-dir",
    }

    closure = status["closure"]
    assert closure["required"] is True
    assert closure["completed"] is True
    assert closure["verifier_commit_source"] == (
        "exact implementation squash-merge commit"
    )
    assert closure["verifier_commit"] == IMPLEMENTATION_MERGE_COMMIT
    assert f"--verifier-commit {IMPLEMENTATION_MERGE_COMMIT}" in closure["command"]
    assert closure["command"].endswith(
        "--output-dir arcs_verify/contracts/dagr-srs-verification-report-v0-2/golden"
    )
