"""The receiver process must need no producer software and no network.

Each detector is paired with a positive control, so that a clean result cannot
come from a detector that is unable to fire.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from stranger0_support import DEFAULT, NEUTRAL_ENV, PV, REPO, S0, load_script, run_receiver

receiver = load_script("stranger0_receiver_under_test", S0 / "receiver.py")
orchestrator = load_script("stranger0_orchestrator_under_test", S0 / "run_stranger0.py")
guard = load_script("check_public_release_for_stranger0", REPO / "tools" / "check_public_release.py")


@pytest.fixture(scope="module")
def clean_run(tmp_path_factory):
    result = run_receiver([PV("admission-admitted"), PV("outcome-result-returned")], DEFAULT, tmp_path_factory.mktemp("indep"))
    assert result.proc.returncode == 0, result.proc.stderr
    return result


# ------------------------------------------------------------- the real receiver process
# ------------------------------------------------------------- interpreter-owned site hooks
# An interpreter may import a site hook of its own accord at startup: Homebrew's
# python@3.13 and python@3.14 ship sitecustomize.py inside the standard library
# directory, so the receiver honestly reports it as a loaded non-stdlib module.
# It is not a declared dependency and must not be added to the allowlist, which
# would excuse the name wherever it came from -- including a pip-installed
# sitecustomize in site-packages, which is exactly the user-controlled case this
# control exists to catch. Ownership is therefore decided by WHERE the module
# resolved, never by its name alone.
SITE_HOOK_NAMES = frozenset({"sitecustomize", "usercustomize"})

DECLARED_VERIFIER_DEPENDENCIES = frozenset({
    "attr", "attrs", "cffi", "cryptography", "jsonschema", "jsonschema_specifications", "referencing",
    "rfc3339_validator", "rfc8785", "rpds", "six", "typing_extensions", "pycparser", "_cffi_backend", "rpds_py",
})


def is_interpreter_owned_site_hook(name: str, origin: str | None, paths: dict[str, str | None]) -> bool:
    """True only for a site hook the interpreter itself owns.

    Pure, so the failure path is testable without planting a module anywhere.
    The hook must (a) carry one of the two reserved names, (b) resolve to a real
    file, (c) live inside this interpreter's stdlib directory, and (d) NOT live
    in any installable location. (d) is load-bearing: site-packages is normally
    a child of the stdlib directory, so a prefix test alone would admit a
    pip-installed hook.
    """
    if name not in SITE_HOOK_NAMES or not origin:
        return False
    try:
        resolved = Path(origin).resolve()
        stdlib = paths.get("stdlib")
        if not stdlib or not resolved.is_relative_to(Path(stdlib).resolve()):
            return False
        for key in ("purelib", "platlib", "usersite"):
            location = paths.get(key)
            if location and resolved.is_relative_to(Path(location).resolve()):
                return False
    except (OSError, ValueError):
        return False
    return True


def probe_site_hooks() -> dict:
    """Ask a process started exactly as the receiver is where its hooks came from."""
    code = textwrap.dedent(
        """
        import json, sys, sysconfig
        try:
            import site
            usersite = site.getusersitepackages()
        except Exception:
            usersite = None
        origins = {}
        for name in ("sitecustomize", "usercustomize"):
            module = sys.modules.get(name)
            origins[name] = getattr(module, "__file__", None) if module is not None else None
        print(json.dumps({"origins": origins, "paths": {
            "stdlib": sysconfig.get_paths().get("stdlib"),
            "purelib": sysconfig.get_paths().get("purelib"),
            "platlib": sysconfig.get_paths().get("platlib"),
            "usersite": usersite if isinstance(usersite, str) else None,
        }}))
        """
    )
    proc = subprocess.run([sys.executable, "-I", "-c", code], env=NEUTRAL_ENV, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_receiver_process_loaded_no_producer_module(clean_run):
    facts = clean_run.facts
    assert facts["producer_modules_loaded"] == []
    assert facts["python_isolated_flag"] is True
    assert any(m == "arcs_verify.verifier" for m in facts["arcs_verify_modules_loaded"])
    # Everything non-stdlib that was loaded is a declared dependency of the
    # verifier, or a site hook this interpreter owns. Nothing else is excused.
    loaded = set(facts["third_party_top_level_modules_loaded"])
    unexpected = loaded - DECLARED_VERIFIER_DEPENDENCIES
    if unexpected:
        probe = probe_site_hooks()
        for name in sorted(unexpected):
            assert is_interpreter_owned_site_hook(name, probe["origins"].get(name), probe["paths"]), (name, probe)


def test_receiver_process_made_no_network_attempt(clean_run):
    tripwire = clean_run.facts["network_tripwire"]
    assert tripwire["blocked_attempts"] == 0
    assert tripwire["is_a_sandbox"] is False        # the record does not overstate the control


def test_receiver_runs_with_no_inherited_python_path(clean_run):
    names = set(clean_run.facts["environment_variable_names"])
    assert not names & {"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "VIRTUAL_ENV"}
    assert names <= set(NEUTRAL_ENV) | {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"}


def test_verifier_identity_matches_the_files_in_this_tree(clean_run):
    import hashlib
    for rel, digest in clean_run.facts["verifier_inputs_sha256"].items():
        assert digest == "sha256:" + hashlib.sha256((REPO / rel).read_bytes()).hexdigest()


# ------------------------------------------------------------- detectors have teeth (positive controls)
def _paths(root: Path, *, venv: bool = False) -> dict[str, str | None]:
    """stdlib plus the installable locations, laid out as CPython really does."""
    stdlib = root / "lib" / "python3.x"
    purelib = (root / "venv" / "lib" / "python3.x" / "site-packages") if venv else (stdlib / "site-packages")
    return {"stdlib": str(stdlib), "purelib": str(purelib), "platlib": str(purelib), "usersite": str(root / "usersite")}


def test_interpreter_owned_site_hook_accepts_only_the_interpreters_own_file(tmp_path):
    paths = _paths(tmp_path)
    own = Path(paths["stdlib"]) / "sitecustomize.py"
    assert is_interpreter_owned_site_hook("sitecustomize", str(own), paths) is True
    assert is_interpreter_owned_site_hook("usercustomize", str(Path(paths["stdlib"]) / "usercustomize.py"), paths) is True


@pytest.mark.parametrize("name", ["requests", "dagr_mcp", "arcs_verify", "cryptography", "sitecustomize_evil"])
def test_ownership_never_excuses_a_name_outside_the_two_reserved_hooks(tmp_path, name):
    paths = _paths(tmp_path)
    planted = Path(paths["stdlib"]) / f"{name}.py"
    assert is_interpreter_owned_site_hook(name, str(planted), paths) is False


def test_an_installable_site_hook_is_never_interpreter_owned(tmp_path):
    # site-packages is a child of the stdlib directory, so a prefix test alone
    # would admit this. A pip-installed sitecustomize is user-controlled.
    paths = _paths(tmp_path)
    installed = Path(paths["purelib"]) / "sitecustomize.py"
    assert str(installed).startswith(paths["stdlib"])        # the trap this guards
    assert is_interpreter_owned_site_hook("sitecustomize", str(installed), paths) is False


def test_a_venv_site_hook_is_never_interpreter_owned(tmp_path):
    paths = _paths(tmp_path, venv=True)
    assert is_interpreter_owned_site_hook("sitecustomize", str(Path(paths["purelib"]) / "sitecustomize.py"), paths) is False
    assert is_interpreter_owned_site_hook("sitecustomize", str(Path(paths["usersite"]) / "sitecustomize.py"), paths) is False


@pytest.mark.parametrize("origin", [None, "", "/tmp/sitecustomize.py"])
def test_a_site_hook_with_no_or_foreign_origin_is_never_interpreter_owned(tmp_path, origin):
    assert is_interpreter_owned_site_hook("sitecustomize", origin, _paths(tmp_path)) is False


def test_ownership_fails_closed_when_the_interpreter_reports_no_stdlib(tmp_path):
    paths = _paths(tmp_path)
    paths["stdlib"] = None
    assert is_interpreter_owned_site_hook("sitecustomize", str(tmp_path / "sitecustomize.py"), paths) is False


def test_probe_reports_this_interpreters_real_layout():
    probe = probe_site_hooks()
    assert set(probe["origins"]) == set(SITE_HOOK_NAMES)
    assert probe["paths"]["stdlib"] and Path(probe["paths"]["stdlib"]).is_dir()
    for name, origin in probe["origins"].items():
        if origin is None:
            continue
        # whatever this interpreter actually loaded must classify the same way
        # the receiver's report is judged by
        assert is_interpreter_owned_site_hook(name, origin, probe["paths"]) == (
            Path(origin).resolve().is_relative_to(Path(probe["paths"]["stdlib"]).resolve())
            and not any(
                probe["paths"].get(k) and Path(origin).resolve().is_relative_to(Path(probe["paths"][k]).resolve())
                for k in ("purelib", "platlib", "usersite")
            )
        )


def test_selfcheck_positive_controls_all_fire():
    proc = subprocess.run([sys.executable, "-I", str(S0 / "receiver.py"), "--selfcheck"], env=NEUTRAL_ENV, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout
    result = json.loads(proc.stdout)
    assert result["ok"] is True
    assert set(result["checks"]) == {
        "network_tripwire_refuses_and_counts",
        "producer_predicate_flags_producer_names",
        "producer_predicate_ignores_benign_names",
        "module_inventory_detects_a_really_imported_producer_module",
        "module_inventory_clean_after_removal",
    }
    assert all(result["checks"].values())


def test_planted_producer_module_is_detected_in_a_fresh_process(tmp_path):
    planted = tmp_path / "dagr_planted_producer.py"
    planted.write_text("VALUE = 1\n")
    code = textwrap.dedent(
        """
        import importlib, json, sys
        sys.path.insert(0, sys.argv[1])
        sys.path.insert(0, sys.argv[2])
        import importlib.util
        spec = importlib.util.spec_from_file_location("rcv", sys.argv[2] + "/stranger0/receiver.py")
        rcv = importlib.util.module_from_spec(spec); spec.loader.exec_module(rcv)
        before = rcv.producer_modules_in(list(sys.modules))
        importlib.import_module("dagr_planted_producer")
        after = rcv.producer_modules_in(list(sys.modules))
        print(json.dumps({"before": before, "after": after}))
        """
    )
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(tmp_path), str(REPO)], capture_output=True, text=True, env=NEUTRAL_ENV)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"before": [], "after": ["dagr_planted_producer"]}


def test_receiver_predicate_covers_every_root_the_release_guard_forbids():
    names = list(guard.PRIVATE_IMPORT_ROOTS) + list(guard.PRIVATE_IMPORT_EXACT) + ["dagr_mcp", "dagr_runtime", "dagr_sdk", "dagr_a2a"]
    assert names
    for name in names:
        assert guard.is_private_import_root(name) is True
        assert receiver.is_producer_module(name) is True, name
    for name in ("json", "arcs_verify", "cryptography", "dagrfoo", "mydagr_mcp"):
        assert guard.is_private_import_root(name) is False
        assert receiver.is_producer_module(name) is False, name


# ------------------------------------------------------------- source-level import allowlist (+ positive controls)
def test_receiver_source_imports_only_stdlib_and_the_verifier():
    result = orchestrator.receiver_import_allowlist()
    assert result["ok"] is True, result
    assert "arcs_verify" in result["imported_top_level"]


@pytest.mark.parametrize("line, offender", [
    ("import dagr_mcp", "dagr_mcp"),
    ("from dagr_runtime import x", "dagr_runtime"),
    ("import countergraph", "countergraph"),
    ("import requests", "requests"),
    ("from counterpedia.client import fetch", "counterpedia"),
])
def test_allowlist_scan_rejects_planted_imports(tmp_path, line, offender):
    source = tmp_path / "planted.py"
    source.write_text("import json\n" + line + "\n")
    result = orchestrator.receiver_import_allowlist(source)
    assert result["ok"] is False
    assert offender in result["outside_stdlib_and_arcs_verify"]


def test_allowlist_scan_accepts_a_clean_control(tmp_path):
    source = tmp_path / "clean.py"
    source.write_text("import json\nfrom arcs_verify.verifier import verify_receipt\n")
    assert orchestrator.receiver_import_allowlist(source)["ok"] is True


# ------------------------------------------------------------- the receiver cannot produce receipts
FORBIDDEN_SIGNING_TOKENS = ("PrivateKey", ".sign(", "private_bytes", "from_private_bytes")


def _signing_tokens(text: str) -> list[str]:
    return [t for t in FORBIDDEN_SIGNING_TOKENS if t in text]


def test_receiver_contains_no_signing_capability():
    assert _signing_tokens((S0 / "receiver.py").read_text()) == []
    assert _signing_tokens((S0 / "run_stranger0.py").read_text()) == []


def test_signing_scan_positive_control():
    assert _signing_tokens("key = Ed25519PrivateKey.generate(); sig = key.sign(b'x')") == ["PrivateKey", ".sign("]


def test_no_signing_code_or_private_key_material_is_committed_in_the_package():
    for path in S0.rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix in {".py", ".json", ".md"}:
            assert _signing_tokens(path.read_text()) == [], path


# ------------------------------------------------------------- the public release guard covers the new tree
def test_release_guard_is_clean_on_the_whole_tree():
    assert guard.check(REPO) == []


def test_release_guard_actually_scans_the_stranger0_tree(tmp_path):
    import shutil
    clean = tmp_path / "clean"
    shutil.copytree(REPO / "stranger0", clean / "stranger0", ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("LICENSE", "SECURITY.md", "README.md"):
        shutil.copy(REPO / name, clean / name)
    shutil.copytree(REPO / "tools", clean / "tools")
    assert guard.check(clean, script_dir=clean / "tools") == []
    marker = "/" + "Users" + "/someone/private"
    (clean / "stranger0" / "receiver.py").write_text((clean / "stranger0" / "receiver.py").read_text() + f"\n# {marker}\n")
    findings = guard.check(clean, script_dir=clean / "tools")
    assert [(f.rule_id, f.path) for f in findings] == [("PR003", "stranger0/receiver.py")]
    (clean / "stranger0" / "receiver.py").write_text("import dagr_planted\n")
    findings = guard.check(clean, script_dir=clean / "tools")
    assert ("PR010", "stranger0/receiver.py") in [(f.rule_id, f.path) for f in findings]
