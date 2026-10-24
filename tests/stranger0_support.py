"""Shared helpers for the stranger0 acceptance tests (not itself a test module)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

REPO = Path(__file__).resolve().parents[1]
S0 = REPO / "stranger0"
CASES = S0 / "cases"
PINNED = REPO / "packs" / "srs.mcp.sdk_enforcement" / "v0.1" / "normative"
NEUTRAL_ENV = {"PATH": "/usr/bin:/bin"}

# Deliberately written out here instead of read from cases.json, so the tests
# do not just echo the catalog they are meant to check.
PV = lambda name: PINNED / "valid" / f"{name}.json"  # noqa: E731
PM = lambda name: PINNED / "mutations" / f"{name}.json"  # noqa: E731
CR = lambda name: CASES / "receipts" / f"{name}.json"  # noqa: E731
TRUST = lambda name: CASES / "trust" / f"{name}.json"  # noqa: E731
DEFAULT = TRUST("receiver-default")


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@dataclass
class Run:
    proc: subprocess.CompletedProcess
    out_dir: Path
    findings: dict[str, Any] | None
    decision: dict[str, Any] | None
    facts: dict[str, Any] | None

    @property
    def decisions(self) -> list[dict[str, Any]]:
        return self.decision["decisions"]

    def report(self, index: int = 0) -> dict[str, Any] | None:
        return self.findings["receipts"][index]["verifier_report"]

    def tokens(self, index: int = 0) -> list[str]:
        return sorted(r["token"] for r in self.decisions[index]["reasons"])

    def failed_checks(self, index: int = 0) -> list[str]:
        report = self.report(index)
        names = ("schema_digest", "envelope", "profile", "raw_content_exclusion", "signature_valid",
                 "issuer_key_resolved", "issuer_key_trusted", "attestation_limits_present")
        return sorted(n for n in names if report[n] is not True)


def run_receiver(receipts: list[Path], trust: Path, out_dir: Path, *, script: Path | None = None) -> Run:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-I", str(script or S0 / "receiver.py"), "--verifier-root", str(REPO),
           "--trust-input", str(trust), "--out-dir", str(out_dir)]
    for receipt in receipts:
        cmd += ["--receipt", str(receipt)]
    proc = subprocess.run(cmd, cwd=out_dir, env=NEUTRAL_ENV, capture_output=True, text=True, timeout=180)

    def load(name: str) -> dict[str, Any] | None:
        path = out_dir / name
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    return Run(proc, out_dir, load("verifier-findings.json"), load("reliance-decision.json"), load("receiver-process-facts.json"))
