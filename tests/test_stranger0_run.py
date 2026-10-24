"""End-to-end: the one documented command, plus negative controls on the orchestrator itself."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from stranger0_support import NEUTRAL_ENV, REPO, S0, load_script

orchestrator = load_script("stranger0_orchestrator_for_run_tests", S0 / "run_stranger0.py")


def run_orchestrator(root: Path, out: Path, *extra: str, check_sums: bool = False):
    args = [sys.executable, str(root / "stranger0" / "run_stranger0.py"), "--out", str(out)]
    if not check_sums:
        args.append("--skip-package-sums-check")
    return subprocess.run(args + list(extra), capture_output=True, text=True, cwd=out.parent, timeout=900)


@pytest.fixture(scope="module")
def full_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("s0full") / "out"
    proc = run_orchestrator(REPO, out)
    return proc, json.loads((out / "stranger0-result.json").read_text()), out


# ------------------------------------------------------------------------ the documented command
def test_documented_command_passes_and_reports_a_pass(full_run):
    proc, transcript, _ = full_run
    assert proc.returncode == 0, proc.stdout[-3000:]
    assert transcript["result"] == "PASS"
    assert "STRANGER0 RESULT: PASS" in proc.stdout


def test_transcript_covers_every_case_and_every_family(full_run):
    _, transcript, _ = full_run
    catalog = json.loads((S0 / "cases" / "cases.json").read_text())
    assert [c["case_id"] for c in transcript["cases"]] == [c["case_id"] for c in catalog["cases"]]
    assert transcript["totals"]["cases"] == transcript["totals"]["cases_ok"] == len(catalog["cases"])
    assert all(row["ok"] for row in transcript["families"])
    assert transcript["isolation_problems"] == []


def test_transcript_shows_the_separation_between_verifier_pass_and_reliance(full_run):
    _, transcript, _ = full_run
    matrix = transcript["separation_matrix"]
    assert matrix["verifier_failed_and_rely"] == 0
    assert matrix["no_verifier_findings_and_rely"] == 0
    assert matrix["verifier_passed_and_rely"] > 0
    assert matrix["verifier_passed_and_not_rely"] > 0       # pass is necessary, not sufficient
    assert matrix["verifier_failed_and_not_rely"] > 0


def test_each_hostile_case_reports_the_reason_token_and_the_failing_check(full_run):
    _, transcript, _ = full_run
    by_case = {c["case_id"]: c for c in transcript["cases"]}
    tamper = by_case["n-tamper-refused-to-admitted"]["receipts"][0]
    assert tamper["verifier"]["failure_codes"] == ["signature_invalid"]
    assert tamper["verifier"]["failed_checks"] == ["signature_valid"]
    assert tamper["receiver_decision"]["reason_tokens"] == ["verifier.not_passed"]
    selfclaim = by_case["n-embedded-key-not-in-receiver-trust"]["receipts"][0]
    assert selfclaim["verifier"]["failure_codes"] == ["key_id_unresolved"]
    assert selfclaim["receiver_decision"]["decision"] == "do_not_rely"
    declined = by_case["n-declined-boundary-not-accepted"]["receipts"][0]
    assert declined["verifier"]["passed"] is True
    assert declined["receiver_decision"]["reason_tokens"] == ["policy.boundary_not_accepted"]
    missing = by_case["n-chain-missing-admission"]["receipts"][0]
    assert missing["receiver_decision"]["decision"] == "insufficient_evidence"


def test_falsifier_is_not_triggered_and_its_detectors_were_exercised(full_run):
    _, transcript, _ = full_run
    f = transcript["falsifier"]
    assert f["overall"] == "NOT_FALSIFIED_IN_THIS_RUN"
    a = f["verification_requires_producer_or_counterpedia"]["evidence"]
    assert a["processes_with_producer_modules_loaded"] == 0
    assert a["processes_with_network_attempts"] == 0
    assert a["receiver_processes_inspected"] == transcript["totals"]["cases"]
    assert a["detector_selfcheck_positive_controls"]["ok"] is True
    b = f["signature_promoted_to_truth_or_admission"]["evidence"]
    assert b["decisions_rely_without_verifier_pass"] == []
    assert b["receipts_with_valid_signature_that_were_not_relied_upon"]


def test_every_recorded_findings_report_equals_the_existing_cli_output(full_run):
    _, transcript, _ = full_run
    checked = 0
    for case in transcript["cases"]:
        for rec in case["receipts"]:
            if rec["cli_crosscheck"] is not None:
                assert rec["cli_crosscheck"]["cli_json_equals_receiver_recorded_report"] is True, (case["case_id"], rec["index"])
                checked += 1
    assert checked >= 40


def test_transcript_names_what_was_not_exercised_and_leaks_no_local_path(full_run):
    _, transcript, out = full_run
    assert any("sandbox" in item for item in transcript["not_exercised"])
    assert any("independent" in item for item in transcript["not_exercised"])
    text = (out / "stranger0-result.json").read_text()
    for marker in ("/" + "Users" + "/", "/" + "private" + "/", "/" + "var" + "/folders", str(out)):
        assert marker not in text


def test_documented_command_is_independent_of_the_working_directory(tmp_path):
    out = tmp_path / "elsewhere" / "out"
    out.parent.mkdir()
    proc = run_orchestrator(REPO, out, "--only", "pc-admitted-pinned", "--only", "n-tamper-pinned-semantic-field-change")
    assert proc.returncode == 0, proc.stdout


# ------------------------------------------------------------------------ negative controls on the orchestrator
@pytest.fixture
def tree(tmp_path):
    """A private copy of just what the orchestrator needs."""
    root = tmp_path / "repo"
    for name in ("arcs_verify", "packs", "stranger0"):
        shutil.copytree(REPO / name, root / name, ignore=shutil.ignore_patterns("__pycache__"))
    return root


def load_catalog(root: Path):
    return json.loads((root / "stranger0" / "cases" / "cases.json").read_text())


def save_catalog(root: Path, doc) -> None:
    (root / "stranger0" / "cases" / "cases.json").write_text(json.dumps(doc, indent=2) + "\n")


def case_of(doc, case_id):
    return next(c for c in doc["cases"] if c["case_id"] == case_id)


def test_copied_tree_passes_unmodified(tree, tmp_path):                                # control for the three below
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "n-no-trust-anchors", "--only", "pc-admitted-pinned")
    assert proc.returncode == 0, proc.stdout


def test_orchestrator_fails_when_a_stated_expectation_is_wrong(tree, tmp_path):
    doc = load_catalog(tree)
    case_of(doc, "n-tamper-refused-to-admitted")["expect"][0]["verifier_failure_codes"] = ["key_id_unresolved"]   # wrong stated reason
    save_catalog(tree, doc)
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "n-tamper-refused-to-admitted", "--only", "pc-refused-pinned")
    assert proc.returncode == 1
    assert "FAIL" in proc.stdout and "verifier_failure_codes" in proc.stdout


def test_orchestrator_fails_when_the_expected_decision_is_wrong(tree, tmp_path):
    doc = load_catalog(tree)
    case_of(doc, "n-declined-boundary-not-accepted")["expect"][0]["decision"] = "rely"
    save_catalog(tree, doc)
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "n-declined-boundary-not-accepted", "--only", "pc-admitted-pinned")
    assert proc.returncode == 1


def test_orchestrator_fails_a_negative_without_a_positive_control(tree, tmp_path):
    doc = load_catalog(tree)
    case_of(doc, "n-no-trust-anchors")["controls"] = []
    save_catalog(tree, doc)
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "n-no-trust-anchors")
    assert proc.returncode == 1
    assert "without a positive control" in json.dumps(json.loads((tmp_path / "o" / "stranger0-result.json").read_text())["isolation_problems"])


def test_orchestrator_fails_a_false_isolation_claim(tree, tmp_path):
    doc = load_catalog(tree)
    case_of(doc, "n-no-trust-anchors")["isolation"][0]["same_trust_input"] = True        # it is not the same trust input
    save_catalog(tree, doc)
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "n-no-trust-anchors")
    assert proc.returncode == 1


def test_orchestrator_refuses_a_control_that_does_not_rely(tree, tmp_path):
    doc = load_catalog(tree)
    case_of(doc, "pc-admitted-pinned")["expect"][0]["decision"] = "do_not_rely"
    save_catalog(tree, doc)
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "n-no-trust-anchors", "--only", "pc-admitted-pinned")
    assert proc.returncode == 1


def test_orchestrator_stops_on_a_modified_pinned_fixture(tree, tmp_path):
    path = tree / "packs" / "srs.mcp.sdk_enforcement" / "v0.1" / "normative" / "valid" / "admission-admitted.json"
    path.write_text(path.read_text().replace("records.lookup", "records.lookuq"))
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "pc-admitted-pinned")
    assert proc.returncode == 2
    assert "pinned fixture differs" in proc.stderr


def test_orchestrator_stops_on_a_modified_derived_artifact(tree, tmp_path):
    path = tree / "stranger0" / "cases" / "receipts" / "s0-admitted-issuer-a.json"
    path.write_text(path.read_text().replace("records.lookup", "records.lookuq"))
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "pc-synthetic-issuer-a")
    assert proc.returncode == 2
    assert "artifact digest mismatch" in proc.stderr


def test_package_sums_check_fails_closed_on_any_change(tree, tmp_path):
    subprocess.run([sys.executable, str(tree / "stranger0" / "run_stranger0.py"), "--out", str(tmp_path / "x"), "--write-package-sums"], check=True, capture_output=True)
    ok = run_orchestrator(tree, tmp_path / "o1", "--only", "pc-admitted-pinned", check_sums=True)
    assert ok.returncode == 0, ok.stderr
    receiver = tree / "stranger0" / "receiver.py"
    receiver.write_text(receiver.read_text() + "\n# touched\n")
    bad = run_orchestrator(tree, tmp_path / "o2", "--only", "pc-admitted-pinned", check_sums=True)
    assert bad.returncode == 2
    assert "changed: receiver.py" in bad.stderr


def patch_receiver(root: Path, old: str, new: str) -> None:
    path = root / "stranger0" / "receiver.py"
    text = path.read_text()
    assert text.count(old) == 1, old
    path.write_text(text.replace(old, new))


def test_orchestrator_rejects_a_control_whose_catalog_expectation_is_not_rely(tree, tmp_path):
    # The control is made to decline in reality AND in its stated expectation, so its own
    # case matches; only the control-must-rely check can still object.
    doc = load_catalog(tree)
    control = case_of(doc, "pc-admitted-pinned")
    control["trust_input"] = "case:trust/receiver-strict-boundary.json"
    control["expect"] = [{"decision": "do_not_rely", "verifier_passed": True, "failed_checks": [],
                          "verifier_failure_codes": [], "reason_tokens": ["policy.boundary_not_accepted"]}]
    save_catalog(tree, doc)
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "n-no-trust-anchors", "--only", "pc-admitted-pinned")
    assert proc.returncode == 1
    result = json.loads((tmp_path / "o" / "stranger0-result.json").read_text())
    assert all(c["case_ok"] for c in result["cases"])
    assert any("does not rely on every receipt" in p for p in result["isolation_problems"])


def test_orchestrator_detects_an_altered_findings_record(tree, tmp_path):
    # The receiver tampers with a field no expectation looks at; only the CLI cross-check can notice.
    patch_receiver(tree, "            item.report = report.to_dict()\n",
                   "            item.report = dict(report.to_dict(), selected_profile_release_stage=\"stable\")\n")
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "pc-admitted-pinned")
    assert proc.returncode == 1
    assert "findings_unaltered_vs_cli" in proc.stdout


def test_orchestrator_reports_falsified_when_a_receiver_process_loads_a_producer_module(tree, tmp_path):
    planted = tree / "planted"
    planted.mkdir()
    (planted / ("dagr_" + "planted_producer.py")).write_text("VALUE = 1\n")
    patch_receiver(tree, "    data_dir = root / \"arcs_verify\" / \"data\"\n",
                   "    data_dir = root / \"arcs_verify\" / \"data\"\n"
                   f"    sys.path.insert(0, {str(planted)!r})\n"
                   "    importlib.import_module(\"dagr_\" + \"planted_producer\")\n")
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "pc-admitted-pinned")
    assert proc.returncode == 1
    result = json.loads((tmp_path / "o" / "stranger0-result.json").read_text())
    assert result["falsifier"]["overall"] == "FALSIFIED"
    evidence = result["falsifier"]["verification_requires_producer_or_counterpedia"]["evidence"]
    assert evidence["processes_with_producer_modules_loaded"] == 1


def test_orchestrator_reports_falsified_when_a_receiver_process_attempts_network_use(tree, tmp_path):
    patch_receiver(tree, "    data_dir = root / \"arcs_verify\" / \"data\"\n",
                   "    data_dir = root / \"arcs_verify\" / \"data\"\n"
                   "    try:\n        socket.getaddrinfo(\"localhost\", 80)\n    except OSError:\n        pass\n")
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "pc-admitted-pinned")
    assert proc.returncode == 1
    result = json.loads((tmp_path / "o" / "stranger0-result.json").read_text())
    assert result["falsifier"]["overall"] == "FALSIFIED"
    assert result["falsifier"]["verification_requires_producer_or_counterpedia"]["evidence"]["processes_with_network_attempts"] == 1


def test_orchestrator_reports_falsified_when_a_valid_signature_is_promoted_to_reliance(tree, tmp_path):
    patch_receiver(tree, "        elif item.report.get(\"passed\") is not True:\n",
                   "        elif item.report.get(\"signature_valid\") is not True:\n")
    proc = run_orchestrator(tree, tmp_path / "o", "--only", "n-key-marked-untrusted-by-receiver", "--only", "pc-admitted-pinned")
    assert proc.returncode == 1
    result = json.loads((tmp_path / "o" / "stranger0-result.json").read_text())
    assert result["falsifier"]["signature_promoted_to_truth_or_admission"]["falsified"] is True
    assert result["falsifier"]["signature_promoted_to_truth_or_admission"]["evidence"]["decisions_rely_without_verifier_pass"] == ["n-key-marked-untrusted-by-receiver#0"]


# ------------------------------------------------------------------------ the committed transcript is not stale
def test_committed_transcript_matches_the_current_package():
    path = S0 / "results" / "stranger0-result.json"
    assert path.is_file()
    committed = json.loads(path.read_text())
    assert committed["result"] == "PASS"
    assert committed["scope"] == "full"
    sha = lambda p: "sha256:" + __import__("hashlib").sha256(p.read_bytes()).hexdigest()  # noqa: E731
    assert committed["package"] == {
        "catalog_sha256": sha(S0 / "cases" / "cases.json"),
        "artifacts_sha256": sha(S0 / "cases" / "artifacts.json"),
        "receiver_sha256": sha(S0 / "receiver.py"),
        "orchestrator_sha256": sha(S0 / "run_stranger0.py"),
    }
    catalog = json.loads((S0 / "cases" / "cases.json").read_text())
    assert [c["case_id"] for c in committed["cases"]] == [c["case_id"] for c in catalog["cases"]]
