"""Generator and golden-provenance gate for the v0.2 report contract.

    python -m pytest tests/test_dagr_report_v0_2_generator.py -q

A verification report carries a ``verifier_commit``: a concrete claim about
which implementation produced it. This branch is the implementation candidate,
so no such claim can be made truthfully yet, and none is committed. That is
enforced here rather than merely documented.

Six proofs:

1. the generator refuses to run without ``--verifier-commit``;
2. it rejects a value that is not a full 40-hex lowercase commit SHA;
3. every generated report carries the supplied commit exactly;
4. two temporary generations are byte-identical;
5. this branch contains no authoritative v0.2 report goldens;
6. the v0.2 README records the post-merge closure requirement.

Every generation performed here writes into ``tmp_path`` with an explicitly
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
# Proof 5: no authoritative v0.2 report goldens exist on this branch
# ---------------------------------------------------------------------------


def test_no_v0_2_report_goldens_are_committed() -> None:
    tracked = _tracked_files(V0_2_ROOT.relative_to(ROOT))
    assert tracked is not None, "expected a git checkout"
    offenders = [
        path
        for path in tracked
        if path.endswith("-report.json") or path.endswith("expectations.json")
    ]
    assert offenders == []


def test_the_v0_2_golden_directory_holds_no_committed_files() -> None:
    tracked = _tracked_files(V0_2_GOLDEN.relative_to(ROOT))
    assert tracked is not None, "expected a git checkout"
    assert tracked == []


def test_no_committed_v0_2_artifact_claims_a_verifier_commit() -> None:
    tracked = _tracked_files(V0_2_ROOT.relative_to(ROOT))
    assert tracked is not None, "expected a git checkout"
    for relative in tracked:
        path = ROOT / relative
        if path.suffix != ".json":
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            assert "verifier_commit" not in payload, relative

        # And not the branch-base commit this correction removed.
        text = path.read_text(encoding="utf-8")
        assert "67b4b071980c64b152d574c9b18af536fbe890ef" not in text, relative


def test_input_fixtures_are_not_presented_as_goldens() -> None:
    readme = (V0_2_INPUTS / "README.md").read_text(encoding="utf-8")
    assert "not goldens" in readme.lower()
    assert "not authoritative" in readme.lower()

    names = {path.name for path in V0_2_INPUTS.iterdir()}
    assert not any(name.endswith("-report.json") for name in names)
    assert "expectations.json" not in names


# ---------------------------------------------------------------------------
# Proof 6: the closure requirement is recorded
# ---------------------------------------------------------------------------


def test_readme_records_the_post_merge_closure_requirement() -> None:
    readme = V0_2_README.read_text(encoding="utf-8")
    lowered = readme.lower()

    assert "implementation candidate" in lowered
    assert "not release-closed" in lowered
    assert "merged-authoritative report goldens" in lowered
    assert "do not yet exist" in lowered
    assert "squash-merge commit" in lowered
    assert "closure pr" in lowered

    assert "python tools/generate_dagr_report_v0_2_goldens.py" in readme
    assert "--verifier-commit <IMPLEMENTATION_MERGE_COMMIT>" in readme
    assert (
        "--output-dir arcs_verify/contracts/dagr-srs-verification-report-v0-2/golden"
        in readme
    )


def test_readme_does_not_claim_authoritative_v0_2_reports() -> None:
    readme = V0_2_README.read_text(encoding="utf-8")
    assert "golden/origin-" not in readme
    assert "golden/expectations.json" not in readme


def test_contract_status_metadata_matches_the_readme() -> None:
    status = json.loads(V0_2_STATUS.read_text(encoding="utf-8"))
    assert status["status"] == "implementation_candidate"
    assert status["release_closed"] is False
    assert status["deterministic_golden_generation_available"] is True
    assert status["merged_authoritative_report_goldens_exist"] is False
    assert status["verifier_commit_pattern"] == GEN.VERIFIER_COMMIT_RE.pattern
    assert set(status["generator_required_arguments"]) == {
        "--verifier-commit",
        "--output-dir",
    }

    closure = status["closure"]
    assert closure["required"] is True
    assert closure["verifier_commit_source"] == (
        "exact implementation squash-merge commit"
    )
    assert "--verifier-commit <IMPLEMENTATION_MERGE_COMMIT>" in closure["command"]
    assert closure["command"].endswith(
        "--output-dir arcs_verify/contracts/dagr-srs-verification-report-v0-2/golden"
    )
