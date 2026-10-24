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
def test_receiver_process_loaded_no_producer_module(clean_run):
    facts = clean_run.facts
    assert facts["producer_modules_loaded"] == []
    assert facts["python_isolated_flag"] is True
    assert any(m == "arcs_verify.verifier" for m in facts["arcs_verify_modules_loaded"])
    # everything non-stdlib that was loaded is a declared dependency of the verifier
    allowed = {"attr", "attrs", "cffi", "cryptography", "jsonschema", "jsonschema_specifications", "referencing",
               "rfc3339_validator", "rfc8785", "rpds", "six", "typing_extensions", "pycparser", "_cffi_backend", "rpds_py"}
    assert set(facts["third_party_top_level_modules_loaded"]) <= allowed, facts["third_party_top_level_modules_loaded"]


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
