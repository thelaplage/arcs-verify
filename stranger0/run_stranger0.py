#!/usr/bin/env python3
"""stranger0 orchestrator: run the offline receiver acceptance package.

One command, no network, no producer or Counterpedia code:

    python3 stranger0/run_stranger0.py --out /tmp/stranger0-out

For every case in stranger0/cases/cases.json this launches a SEPARATE receiver
process (stranger0/receiver.py, run with ``python -I`` and a minimal
environment) and hands it only the receipt bytes and a receiver-controlled
trust-input file. It then reads the two distinct records the receiver wrote
(the verifier's findings and the receiver's own reliance decision), compares
them with the case's stated expectation, cross-checks the findings against the
existing ``arcs-verify`` CLI, evaluates the falsifier checks, and writes a JSON
result transcript.

This orchestrator imports only the Python standard library. Exit code 0 means
every case matched its expectation and no falsifier check fired; 1 means a
mismatch; 2 is a usage or package-integrity error.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
TRANSCRIPT_SCHEMA = "arcs.verify.stranger0.result_transcript.v0.1"
BOOLEAN_CHECKS = (
    "schema_digest", "envelope", "profile", "raw_content_exclusion",
    "signature_valid", "issuer_key_resolved", "issuer_key_trusted", "attestation_limits_present",
)
FORBIDDEN_CONCLUSION_KEYS = frozenset(
    {"authenticity_verified", "signature_verified", "truth_verified", "event_verified", "admission_granted", "admitted_by_receiver"}
)
_CLI_BOOT = "import sys; sys.path.insert(0, sys.argv[1]); from arcs_verify.cli import main; raise SystemExit(main(sys.argv[2:]))"
_NEUTRAL_ENV = {"PATH": "/usr/bin:/bin"}

NOT_EXERCISED = [
    "OS-level network sandbox: only an in-process socket tripwire was used, and it is not a sandbox",
    "independent cross-implementation verification: the existing verifier was run in another process, which is the same code, not independent code",
    "real producer-emitted receipts: every receipt is a pinned test vector or a synthetic derivation of one",
    "time-based reliance: no trusted clock input; key validity is evaluated by the existing verifier against the receipt's own issued_at only",
    "revocation, key rotation and trust-anchor governance beyond a static receiver-supplied keyring",
    "SCITT or any transparency-service evidence (a separate lane)",
    "live network federation, external publication, production activation",
]


def sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve(catalog: dict[str, Any], ref: str) -> Path:
    for prefix, target in catalog["path_prefixes"].items():
        if ref.startswith(prefix):
            return REPO / (target + ref[len(prefix):])
    raise ValueError(f"unprefixed path in catalog: {ref}")


def rel(path: Path) -> str:
    return path.resolve().relative_to(REPO.resolve()).as_posix()


# --------------------------------------------------------------------------
# Package integrity
# --------------------------------------------------------------------------
def package_files() -> list[Path]:
    out = []
    for path in sorted((HERE).rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        parts = path.relative_to(HERE).parts
        if "__pycache__" in parts:
            continue
        out.append(path)
    return out


def package_sums() -> str:
    return "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(HERE).as_posix()}\n" for p in package_files()
    )


def check_package_sums() -> list[str]:
    sums = HERE / "SHA256SUMS"
    if not sums.is_file():
        return ["stranger0/SHA256SUMS is missing"]
    expected = sums.read_text(encoding="utf-8")
    actual = package_sums()
    if expected == actual:
        return []
    exp = dict(line.split("  ", 1)[::-1] for line in expected.splitlines())
    act = dict(line.split("  ", 1)[::-1] for line in actual.splitlines())
    problems = [f"changed: {name}" for name in sorted(exp.keys() & act.keys()) if exp[name] != act[name]]
    problems += [f"missing from disk: {name}" for name in sorted(exp.keys() - act.keys())]
    problems += [f"not listed: {name}" for name in sorted(act.keys() - exp.keys())]
    return problems


def check_artifacts(catalog: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    artifacts = read_json(HERE / "cases" / "artifacts.json")
    for name, meta in artifacts["artifacts"].items():
        path = HERE / name
        if not path.is_file():
            problems.append(f"artifact missing: {name}")
        elif sha256_ref(path.read_bytes()) != "sha256:" + meta["sha256"]:
            problems.append(f"artifact digest mismatch: {name}")
    pinned_root = REPO / catalog["path_prefixes"]["pinned:"]
    manifest = read_json(pinned_root / "manifest.json")
    for entry in manifest["entries"]:
        path = pinned_root / entry["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["receipt_file_sha256"]:
            problems.append(f"pinned fixture differs from its manifest digest: {entry['path']}")
    return problems


# --------------------------------------------------------------------------
# One case
# --------------------------------------------------------------------------
def failed_checks_of(report: dict[str, Any]) -> list[str]:
    failed = [name for name in BOOLEAN_CHECKS if report.get(name) is not True]
    if report.get("chain_status") != "not_applicable":
        failed.append("chain_status")
    if report.get("principal_binding_digest") == "fail":
        failed.append("principal_binding_digest")
    return sorted(failed)


def run_receiver(python: str, receipts: list[Path], trust: Path, out_dir: Path) -> subprocess.CompletedProcess[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [python, "-I", str(HERE / "receiver.py"), "--verifier-root", str(REPO), "--trust-input", str(trust), "--out-dir", str(out_dir)]
    for receipt in receipts:
        cmd += ["--receipt", str(receipt)]
    return subprocess.run(cmd, cwd=out_dir, env=_NEUTRAL_ENV, capture_output=True, text=True, timeout=180)


_CLI_CACHE: dict[tuple[str, str, str], dict[str, Any] | None] = {}
_CLI_LOCK = threading.Lock()


def cli_crosscheck(python: str, receipt: Path, keyring: dict[str, Any], slug: str, work: Path) -> dict[str, Any] | None:
    """Run the existing arcs-verify CLI on the same inputs. Identical (receipt bytes,
    keyring, profile) triples are run once; the CLI is deterministic."""
    key = (sha256_ref(receipt.read_bytes()), sha256_ref(json.dumps(keyring, sort_keys=True).encode()), slug)
    with _CLI_LOCK:
        if key in _CLI_CACHE:
            return _CLI_CACHE[key]
    result = _cli_run(python, receipt, keyring, slug, work)
    with _CLI_LOCK:
        _CLI_CACHE[key] = result
    return result


def _cli_run(python: str, receipt: Path, keyring: dict[str, Any], slug: str, work: Path) -> dict[str, Any] | None:
    work.mkdir(parents=True, exist_ok=True)
    keyring_path = work / "keyring.json"
    keyring_path.write_text(json.dumps(keyring, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    proc = subprocess.run(
        [python, "-I", "-c", _CLI_BOOT, str(REPO), str(receipt), "--keyring", str(keyring_path), "--profile", slug, "--json"],
        cwd=work, env=_NEUTRAL_ENV, capture_output=True, text=True, timeout=180,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def evaluate_case(python: str, catalog: dict[str, Any], case: dict[str, Any], out_root: Path) -> dict[str, Any]:
    case_dir = out_root / "cases" / case["case_id"]
    receipts = [resolve(catalog, ref) for ref in case["receipts"]]
    trust_path = resolve(catalog, case["trust_input"])
    proc = run_receiver(python, receipts, trust_path, case_dir)
    result: dict[str, Any] = {
        "case_id": case["case_id"],
        "family": case["family"],
        "role": case["role"],
        "description": case["description"],
        "receipt_inputs": [{"path": rel(p), "sha256": sha256_ref(p.read_bytes())} for p in receipts],
        "trust_input": {"path": rel(trust_path), "sha256": sha256_ref(trust_path.read_bytes())},
        "receiver_exit_code": proc.returncode,
        "receiver_stderr": proc.stderr.strip(),
        "problems": [],
        "receipts": [],
    }
    if proc.returncode != 0:
        result["problems"].append(f"receiver exited {proc.returncode}")
        result["case_ok"] = False
        return result
    findings_bytes = (case_dir / "verifier-findings.json").read_bytes()
    decision_bytes = (case_dir / "reliance-decision.json").read_bytes()
    facts = read_json(case_dir / "receiver-process-facts.json")
    findings, decision = json.loads(findings_bytes), json.loads(decision_bytes)
    result["records"] = {
        "verifier_findings_sha256": sha256_ref(findings_bytes),
        "reliance_decision_sha256": sha256_ref(decision_bytes),
        "findings_and_decision_are_distinct_files": True,
    }
    result["process_facts"] = {
        "python_isolated_flag": facts["python_isolated_flag"],
        "producer_modules_loaded": facts["producer_modules_loaded"],
        "network_blocked_attempts": facts["network_tripwire"]["blocked_attempts"],
        "third_party_top_level_modules_loaded": facts["third_party_top_level_modules_loaded"],
    }
    result["verifier_inputs_sha256"] = facts["verifier_inputs_sha256"]
    if decision["findings_record_sha256"] != sha256_ref(findings_bytes):
        result["problems"].append("decision record does not cite the findings record it was written beside")
    if not (len(findings["receipts"]) == len(decision["decisions"]) == len(receipts)):
        result["problems"].append("a receipt was dropped between input, findings and decision")
    if decision["summary"]["receipts_in"] != len(receipts) or not decision["summary"]["no_receipt_dropped"]:
        result["problems"].append("decision summary disagrees with the input count")

    expected = case["expect"]
    if len(expected) != len(receipts):
        result["problems"].append("catalog expectation count differs from receipt count")
    trust_doc = read_json(trust_path)
    for idx, (finding, dec) in enumerate(zip(findings["receipts"], decision["decisions"])):
        report = finding["verifier_report"]
        actual = {
            "decision": dec["decision"],
            "verifier_passed": report["passed"] if report else None,
            "failed_checks": failed_checks_of(report) if report else None,
            "verifier_failure_codes": sorted(report["failure_codes"]) if report else None,
            "reason_tokens": sorted(r["token"] for r in dec["reasons"]),
        }
        want = expected[idx] if idx < len(expected) else {}
        mismatches = []
        for key in ("decision", "verifier_passed", "failed_checks", "verifier_failure_codes", "reason_tokens"):
            if actual[key] != want.get(key, "<unset>"):
                mismatches.append({"field": key, "expected": want.get(key, "<unset>"), "actual": actual[key]})
        if "reliance_claim" in want and dec.get("reliance_claim") != want["reliance_claim"]:
            mismatches.append({"field": "reliance_claim", "expected": want["reliance_claim"], "actual": dec.get("reliance_claim")})
        if dec["decision"] == "rely" and ("reliance_claim" not in dec or not dec.get("not_relied_upon")):
            mismatches.append({"field": "rely_without_scope", "expected": "claim + not_relied_upon", "actual": "missing"})

        crosscheck = None
        if report is not None:
            cli_report = cli_crosscheck(python, receipts[idx], trust_doc["keyring"], finding["selected_profile"], case_dir / "cli-crosscheck" / f"r{idx:03d}")
            crosscheck = {"cli_json_equals_receiver_recorded_report": cli_report == report}
            if cli_report != report:
                mismatches.append({"field": "findings_unaltered_vs_cli", "expected": "equal", "actual": "differs"})
        result["receipts"].append({
            "index": idx,
            "receipt_id": dec["receipt_id"],
            "receipt_bytes_sha256": dec["receipt_bytes_sha256"],
            "declared_disposition": dec["receipt_declared_disposition"],
            "selected_profile": finding["selected_profile"],
            "verifier": {
                "passed": actual["verifier_passed"],
                "failed_checks": actual["failed_checks"],
                "failure_codes": actual["verifier_failure_codes"],
                "chain_status": report["chain_status"] if report else None,
                "signature_valid": report["signature_valid"] if report else None,
            },
            "receiver_decision": {
                "decision": actual["decision"],
                "reason_tokens": actual["reason_tokens"],
                "reliance_claim": dec.get("reliance_claim"),
                "not_relied_upon": dec.get("not_relied_upon"),
            },
            "cli_crosscheck": crosscheck,
            "expected": want,
            "mismatches": mismatches,
        })
        result["problems"] += [f"receipt {idx}: {m['field']}: expected {m['expected']!r}, got {m['actual']!r}" for m in mismatches]
    result["case_ok"] = not result["problems"]
    return result


# --------------------------------------------------------------------------
# Whole-run checks
# --------------------------------------------------------------------------
def receiver_import_allowlist(source: Path | None = None) -> dict[str, Any]:
    tree = ast.parse((source or HERE / "receiver.py").read_text(encoding="utf-8"))
    stdlib = set(sys.stdlib_module_names)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".", 1)[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".", 1)[0])
    outside = sorted(i for i in imported if i not in stdlib and i != "arcs_verify")
    return {"imported_top_level": sorted(imported), "outside_stdlib_and_arcs_verify": outside, "ok": not outside}


def selfcheck(python: str) -> dict[str, Any]:
    proc = subprocess.run([python, "-I", str(HERE / "receiver.py"), "--selfcheck"], env=_NEUTRAL_ENV, capture_output=True, text=True, timeout=120)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        data = {"ok": False, "error": "selfcheck produced no JSON", "stderr": proc.stderr.strip()}
    data["exit_code"] = proc.returncode
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", required=True, type=Path, help="directory for per-case records and the transcript (created)")
    parser.add_argument("--results", type=Path, default=None, help="also write the transcript to this path")
    parser.add_argument("--python", default=sys.executable, help="interpreter for the receiver (needs the verifier dependencies)")
    parser.add_argument("--only", action="append", default=None, help="run only this case_id (repeatable)")
    parser.add_argument("--jobs", type=int, default=4, help="receiver processes run at once (default 4)")
    parser.add_argument("--write-package-sums", action="store_true", help="(re)write stranger0/SHA256SUMS and exit")
    parser.add_argument("--skip-package-sums-check", action="store_true")
    args = parser.parse_args(argv)

    if args.write_package_sums:
        (HERE / "SHA256SUMS").write_text(package_sums(), encoding="utf-8")
        print("wrote stranger0/SHA256SUMS")
        return 0

    catalog = read_json(HERE / "cases" / "cases.json")
    problems = check_artifacts(catalog)
    if not args.skip_package_sums_check:
        problems += check_package_sums()
    if problems:
        for p in problems:
            print(f"package_integrity_error: {p}", file=sys.stderr)
        return 2

    out_root = args.out
    out_root.mkdir(parents=True, exist_ok=True)
    wanted = set(args.only) if args.only else None
    cases = [c for c in catalog["cases"] if wanted is None or c["case_id"] in wanted]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda c: evaluate_case(args.python, catalog, c, out_root), cases))
    for res in results:
        print(f"{'ok  ' if res['case_ok'] else 'FAIL'} {res['family']:<28} {res['case_id']}")
        for p in res["problems"]:
            print(f"       - {p}")
    by_id = {r["case_id"]: r for r in results}

    # families: every negative fails for the stated reason, with at least one control that relies
    family_rows = []
    isolation_problems: list[str] = []
    for family in catalog["families"]:
        negs = [c for c in cases if c["family"] == family and c["role"] == "negative"]
        ctrls = [c for c in cases if c["family"] == family and c["role"] != "negative"]
        row = {"family": family, "claim": catalog["families"][family], "negatives": [c["case_id"] for c in negs],
               "controls_in_family": [c["case_id"] for c in ctrls]}
        ok = all(by_id[c["case_id"]]["case_ok"] for c in negs + ctrls if c["case_id"] in by_id)
        for neg in negs:
            if not neg.get("controls"):
                isolation_problems.append(f"{neg['case_id']}: negative without a positive control")
                ok = False
                continue
            for control_id in neg["controls"]:
                ctrl = next((c for c in catalog["cases"] if c["case_id"] == control_id), None)
                if ctrl is None or ctrl["role"] == "negative":
                    isolation_problems.append(f"{neg['case_id']}: control {control_id} missing or not a control")
                    ok = False
                    continue
                if not all(e["decision"] == "rely" for e in ctrl["expect"]):
                    isolation_problems.append(f"{neg['case_id']}: control {control_id} does not rely on every receipt")
                    ok = False
            for claim in neg.get("isolation", []):
                ctrl = next(c for c in catalog["cases"] if c["case_id"] == claim["control"])
                same_bytes = [sha256_ref(resolve(catalog, r).read_bytes()) for r in neg["receipts"]] == [
                    sha256_ref(resolve(catalog, r).read_bytes()) for r in ctrl["receipts"]
                ]
                same_trust = sha256_ref(resolve(catalog, neg["trust_input"]).read_bytes()) == sha256_ref(resolve(catalog, ctrl["trust_input"]).read_bytes())
                if same_bytes != claim["same_receipt_bytes"] or same_trust != claim["same_trust_input"]:
                    isolation_problems.append(f"{neg['case_id']}: isolation claim vs {claim['control']} does not match the actual inputs")
                    ok = False
        row["ok"] = ok
        family_rows.append(row)

    # separation matrix and promotion checks
    matrix = {"verifier_passed_and_rely": 0, "verifier_passed_and_not_rely": 0, "verifier_failed_and_not_rely": 0,
              "verifier_failed_and_rely": 0, "no_verifier_findings_and_rely": 0, "no_verifier_findings_and_not_rely": 0}
    signature_valid_not_relied: list[str] = []
    rely_without_pass: list[str] = []
    forbidden_keys_seen: list[str] = []
    for res in results:
        for rec in res["receipts"]:
            passed, dec = rec["verifier"]["passed"], rec["receiver_decision"]["decision"]
            if passed is None:
                matrix["no_verifier_findings_and_rely" if dec == "rely" else "no_verifier_findings_and_not_rely"] += 1
            elif passed:
                matrix["verifier_passed_and_rely" if dec == "rely" else "verifier_passed_and_not_rely"] += 1
            else:
                matrix["verifier_failed_and_rely" if dec == "rely" else "verifier_failed_and_not_rely"] += 1
            if dec == "rely" and passed is not True:
                rely_without_pass.append(f"{res['case_id']}#{rec['index']}")
            if rec["verifier"]["signature_valid"] is True and dec != "rely":
                signature_valid_not_relied.append(f"{res['case_id']}#{rec['index']}")
        case_dir = out_root / "cases" / res["case_id"]
        for record in ("verifier-findings.json", "reliance-decision.json"):
            f = case_dir / record
            if f.is_file() and FORBIDDEN_CONCLUSION_KEYS & set(_all_keys(json.loads(f.read_text(encoding="utf-8")))):
                forbidden_keys_seen.append(f"{res['case_id']}/{record}")

    process_rows = [r.get("process_facts") for r in results if r.get("process_facts")]
    allowlist = receiver_import_allowlist()
    detectors = selfcheck(args.python)
    fals_a = {
        "statement": "verification requires producer software or Counterpedia infrastructure",
        "evidence": {
            "receiver_processes_inspected": len(process_rows),
            "processes_with_producer_modules_loaded": sum(1 for r in process_rows if r["producer_modules_loaded"]),
            "processes_with_network_attempts": sum(1 for r in process_rows if r["network_blocked_attempts"]),
            "processes_not_python_isolated": sum(1 for r in process_rows if not r["python_isolated_flag"]),
            "receiver_source_imports": allowlist,
            "detector_selfcheck_positive_controls": detectors,
        },
    }
    # "falsified" means a violation was observed. "evidence_sufficient" means the check
    # had working detectors and something to look at, so a clean result is not vacuous.
    fals_a["falsified"] = bool(
        fals_a["evidence"]["processes_with_producer_modules_loaded"]
        or fals_a["evidence"]["processes_with_network_attempts"]
        or fals_a["evidence"]["processes_not_python_isolated"]
        or not allowlist["ok"]
    )
    fals_a["evidence_sufficient"] = bool(detectors.get("ok")) and bool(process_rows)
    fals_b = {
        "statement": "a passing signature is silently promoted to event truth or to receiver admission",
        "evidence": {
            "decisions_rely_without_verifier_pass": rely_without_pass,
            "receipts_with_valid_signature_that_were_not_relied_upon": signature_valid_not_relied,
            "records_containing_reserved_or_truth_conclusion_keys": forbidden_keys_seen,
            "every_rely_decision_names_what_is_not_relied_upon": all(
                rec["receiver_decision"]["not_relied_upon"] for res in results for rec in res["receipts"]
                if rec["receiver_decision"]["decision"] == "rely"
            ),
        },
    }
    fals_b["falsified"] = bool(
        rely_without_pass or forbidden_keys_seen
        or not fals_b["evidence"]["every_rely_decision_names_what_is_not_relied_upon"]
    )
    fals_b["evidence_sufficient"] = bool(signature_valid_not_relied)

    all_cases_ok = all(r["case_ok"] for r in results)
    full = wanted is None
    ok = all_cases_ok and not isolation_problems and not fals_a["falsified"] and not fals_b["falsified"] \
        and fals_a["evidence_sufficient"] and (fals_b["evidence_sufficient"] or not full) \
        and all(r["ok"] for r in family_rows) and matrix["verifier_failed_and_rely"] == 0
    transcript = {
        "schema": TRANSCRIPT_SCHEMA,
        "result": "PASS" if ok else "FAIL",
        "scope": "full" if full else "subset (--only): the whole-catalog evidence checks were not applied",
        "claim_discipline": [
            "A verifier finding is not a reliance decision.",
            "A valid signature is not event truth and is not receiver admission.",
            "not_evaluated is not PASS; not_applicable is not PASS; envelope-valid is not profile-pass.",
            "A receiver decision is the receiver's own, under its own trust input; it grants no authority to the issuer.",
        ],
        "package": {
            "catalog_sha256": sha256_ref((HERE / "cases" / "cases.json").read_bytes()),
            "artifacts_sha256": sha256_ref((HERE / "cases" / "artifacts.json").read_bytes()),
            "receiver_sha256": sha256_ref((HERE / "receiver.py").read_bytes()),
            "orchestrator_sha256": sha256_ref(Path(__file__).resolve().read_bytes()),
        },
        "environment": {
            "orchestrator_python": sys.version.split()[0],
            "receiver_python": _python_version(args.python),
        },
        "verifier_identity": results[0].get("verifier_inputs_sha256") if results else None,
        "totals": {
            "cases": len(results),
            "cases_ok": sum(1 for r in results if r["case_ok"]),
            "receipts_evaluated": sum(len(r["receipts"]) for r in results),
            "negative_cases": sum(1 for r in results if r["role"] == "negative"),
            "control_cases": sum(1 for r in results if r["role"] != "negative"),
        },
        "separation_matrix": matrix,
        "families": family_rows,
        "isolation_problems": isolation_problems,
        "falsifier": {"verification_requires_producer_or_counterpedia": fals_a, "signature_promoted_to_truth_or_admission": fals_b,
                      "overall": "FALSIFIED" if (fals_a["falsified"] or fals_b["falsified"]) else "NOT_FALSIFIED_IN_THIS_RUN"},
        "not_exercised": NOT_EXERCISED,
        "cases": results,
    }
    text = json.dumps(transcript, indent=2, sort_keys=True) + "\n"
    (out_root / "stranger0-result.json").write_text(text, encoding="utf-8")
    if args.results:
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(text, encoding="utf-8")
    t = transcript["totals"]
    print(f"\nseparation matrix: {matrix}")
    print(f"falsifier: {transcript['falsifier']['overall']}")
    print(f"STRANGER0 RESULT: {transcript['result']}  ({t['cases_ok']}/{t['cases']} cases, {t['receipts_evaluated']} receipts)")
    return 0 if ok else 1


def _python_version(python: str) -> str:
    proc = subprocess.run([python, "-I", "-c", "import sys; print(sys.version.split()[0])"], env=_NEUTRAL_ENV, capture_output=True, text=True)
    return proc.stdout.strip()


def _all_keys(value: Any):
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _all_keys(v)
    elif isinstance(value, list):
        for v in value:
            yield from _all_keys(v)


if __name__ == "__main__":
    raise SystemExit(main())
