#!/usr/bin/env python3
"""stranger0 receiver: verify SRS receipts, then record a SEPARATE reliance decision.

This program plays the stranger. It is launched as its own process by
``run_stranger0.py`` and is given only:

  * the receipt bytes it is asked to consider, and
  * a receiver-controlled trust-input file (keys, accepted profiles and
    versions, acceptance policy, prior-reliance ledger) supplied out of band.

It calls the existing ARCS Verify verifier unchanged, then writes two distinct
records into ``--out-dir``:

  verifier-findings.json   the verifier's own output, unaltered
  reliance-decision.json   this receiver's own decision under its own policy

plus ``receiver-process-facts.json`` (what this process actually loaded).

Boundaries kept on purpose: a verifier finding is not a reliance decision; a
valid signature is not event truth and is not receiver admission; keys that a
receipt carries or claims for itself are never trust input. Exit code 0 means
the records were written, never "the receipts are fine": inspect the records.
Exit code 2 means usage or input error; no records are written.

Imports: the Python standard library and ``arcs_verify`` only. No producer,
runtime, or Counterpedia code, and no network (a tripwire records any attempt).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any

RECEIVER_ID = "stranger0.receiver.v0.2"
TRUST_INPUT_SCHEMA = "arcs.verify.stranger0.receiver_trust_input.v0.2"
FINDINGS_SCHEMA = "arcs.verify.stranger0.verifier_findings.v0.1"
DECISION_SCHEMA = "arcs.verify.stranger0.reliance_decision.v0.1"
FACTS_SCHEMA = "arcs.verify.stranger0.receiver_process_facts.v0.1"

BOOLEAN_CHECKS = (
    "schema_digest",
    "envelope",
    "profile",
    "raw_content_exclusion",
    "signature_valid",
    "issuer_key_resolved",
    "issuer_key_trusted",
    "attestation_limits_present",
)

# Producer / runtime module roots that a receiver process must never load.
# Mirrors tools/check_public_release.py (checked for consistency by the tests)
# and adds the producer-side packages named in the repository README.
_PRODUCER_EXACT = frozenset(
    {
        "dagr",
        "countergraph",
        "counterpedia",
        "arcs_amnesiac",
        "garp" + "_sdk",
        "garp" + "_core",
        "garp" + "_local",
    }
)
_PRODUCER_PREFIXES = ("dagr" + "_",)


def is_producer_module(top_level_name: str) -> bool:
    return top_level_name in _PRODUCER_EXACT or top_level_name.startswith(
        _PRODUCER_PREFIXES
    )


def producer_modules_in(module_names: Any) -> list[str]:
    """Top-level producer module names present in an iterable of module names."""
    tops = {name.split(".", 1)[0] for name in module_names if name}
    return sorted(top for top in tops if is_producer_module(top))


# --------------------------------------------------------------------------
# Network tripwire. A tripwire records and refuses attempts made through the
# Python socket module in this process. It is NOT a sandbox: it does not stop a
# determined native-code caller. The transcript says so.
# --------------------------------------------------------------------------
_TRIPWIRE_EVENTS: list[str] = []


def install_network_tripwire() -> None:
    def blocked(kind: str):
        def _refuse(*_args: Any, **_kwargs: Any) -> Any:
            _TRIPWIRE_EVENTS.append(kind)
            raise OSError(f"stranger0 network tripwire: {kind} refused")

        return _refuse

    socket.socket.connect = blocked("socket.connect")  # type: ignore[method-assign]
    socket.socket.connect_ex = blocked("socket.connect_ex")  # type: ignore[method-assign]
    socket.create_connection = blocked("socket.create_connection")  # type: ignore[assignment]
    socket.getaddrinfo = blocked("socket.getaddrinfo")  # type: ignore[assignment]
    socket.gethostbyname = blocked("socket.gethostbyname")  # type: ignore[assignment]
    socket.gethostbyname_ex = blocked("socket.gethostbyname_ex")  # type: ignore[assignment]


def sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class UsageError(Exception):
    pass


# --------------------------------------------------------------------------
# Receiver-controlled trust input
# --------------------------------------------------------------------------
_TRUST_TOP_KEYS = {
    "schema",
    "receiver_id",
    "policy_id",
    "keyring",
    "accepted_receipt_versions",
    "accepted_profiles",
    "default_profile",
    "policy",
    "relied_receipt_ledger",
}
_POLICY_KEYS = {
    "accepted_issuer_ids",
    "accepted_boundary_ids",
    "accepted_policy_pack_ids",
    "require_admission_link_for_outcome",
    "require_relied_admission_for_outcome",
}


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise UsageError(f"trust input: {where} must be a list of strings")
    return list(value)


def load_trust_input(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"trust input unreadable: {exc}") from exc
    if not isinstance(data, dict) or set(data) != _TRUST_TOP_KEYS:
        raise UsageError("trust input: top-level keys must be exactly " + ", ".join(sorted(_TRUST_TOP_KEYS)))
    if data["schema"] != TRUST_INPUT_SCHEMA:
        raise UsageError("trust input: unsupported schema")
    for key in ("receiver_id", "policy_id", "default_profile"):
        if not isinstance(data[key], str) or not data[key]:
            raise UsageError(f"trust input: {key} must be a non-empty string")
    keyring = data["keyring"]
    if not isinstance(keyring, dict) or not isinstance(keyring.get("issuers"), list):
        raise UsageError("trust input: keyring must be an object with an issuers list")
    _str_list(data["accepted_receipt_versions"], "accepted_receipt_versions")
    _str_list(data["accepted_profiles"], "accepted_profiles")
    policy = data["policy"]
    if not isinstance(policy, dict) or set(policy) != _POLICY_KEYS:
        raise UsageError("trust input: policy keys must be exactly " + ", ".join(sorted(_POLICY_KEYS)))
    for key in ("accepted_issuer_ids", "accepted_boundary_ids", "accepted_policy_pack_ids"):
        _str_list(policy[key], f"policy.{key}")
    if not isinstance(policy["require_admission_link_for_outcome"], bool):
        raise UsageError("trust input: policy.require_admission_link_for_outcome must be a boolean")
    if not isinstance(policy["require_relied_admission_for_outcome"], bool):
        raise UsageError("trust input: policy.require_relied_admission_for_outcome must be a boolean")
    if policy["require_relied_admission_for_outcome"] and not policy["require_admission_link_for_outcome"]:
        # Requiring reliance on an admission that is not even required to arrive has no
        # reading. Refuse the combination rather than invent one.
        raise UsageError(
            "trust input: policy.require_relied_admission_for_outcome requires "
            "policy.require_admission_link_for_outcome"
        )
    ledger = data["relied_receipt_ledger"]
    if not isinstance(ledger, list):
        raise UsageError("trust input: relied_receipt_ledger must be a list")
    for entry in ledger:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"receipt_id", "canonical_json_sha256"}
            or not all(isinstance(v, str) for v in entry.values())
        ):
            raise UsageError("trust input: ledger entries need exactly receipt_id and canonical_json_sha256")
    return data, sha256_ref(raw)


# --------------------------------------------------------------------------
# Per-receipt handling
# --------------------------------------------------------------------------
class Item:
    def __init__(self, index: int, path: Path, raw: bytes) -> None:
        self.index = index
        self.file_name = path.name
        self.raw = raw
        self.bytes_sha256 = sha256_ref(raw)
        self.parsed: dict[str, Any] | None = None
        self.input_token: str | None = None
        self.input_detail: str | None = None
        self.selected_profile: str | None = None
        self.schema_name: str | None = None
        self.report: dict[str, Any] | None = None
        self.verifier_exception: str | None = None

    @property
    def receipt_id(self) -> str | None:
        value = self.parsed.get("receipt_id") if self.parsed else None
        return value if isinstance(value, str) and value else None

    @property
    def canonical_sha256(self) -> str | None:
        if self.report is not None:
            value = self.report.get("verified_receipt_canonical_json_sha256")
            if isinstance(value, str):
                return value
        return None

    @property
    def replay_digest(self) -> str:
        # Prefer the verifier's canonical-JSON digest; fall back to the raw bytes.
        return self.canonical_sha256 or self.bytes_sha256


def parse_receipt_bytes(item: Item) -> None:
    try:
        text = item.raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        item.input_token, item.input_detail = "input.not_utf8", str(exc)
        return
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        item.input_token, item.input_detail = "input.malformed_json", str(exc)
        return
    if not isinstance(value, dict):
        item.input_token = "input.not_an_object"
        item.input_detail = f"top-level JSON value is {type(value).__name__}"
        return
    item.parsed = value


def claimed_profile_slug(receipt: dict[str, Any], default_profile: str) -> str:
    pid, pver = receipt.get("profile_id"), receipt.get("profile_version")
    if isinstance(pid, str) and isinstance(pver, str) and pid and pver:
        return f"{pid}.{pver}"
    return default_profile


def failed_checks(report: dict[str, Any]) -> list[str]:
    failed = [name for name in BOOLEAN_CHECKS if report.get(name) is not True]
    if report.get("chain_status") != "not_applicable":
        failed.append("chain_status")
    if report.get("principal_binding_digest") == "fail":
        failed.append("principal_binding_digest")
    return failed


def reason(token: str, source: str, **detail: Any) -> dict[str, Any]:
    return {"token": token, "source": source, "detail": detail}


INSUFFICIENT_TOKENS = frozenset({"chain.admission_receipt_unresolved"})
# E-A-LINK. Receiver-origin, and deliberately outside INSUFFICIENT_TOKENS: an admission that
# arrived and was not relied upon is a decision this receiver made, not evidence it lacks.
STRICT_ADMISSION_TOKEN = "chain.admission_not_relied_upon"


def decide_from(reasons: list[dict[str, Any]]) -> str:
    """The receiver's decision for one receipt, given its reasons. Used twice: once
    provisionally, so a dependent decision can read it, and once for the record."""
    if not reasons:
        return "rely"
    if all(r["token"] in INSUFFICIENT_TOKENS for r in reasons):
        return "insufficient_evidence"
    return "do_not_rely"
CHAIN_CODES = ("admission_receipt_unresolved", "admission_outcome_linkage_mismatch")


def attribute_chain_findings(
    outcome_ids: list[str], findings: list[dict[str, str]]
) -> tuple[dict[str, set[str]], bool]:
    """Map existing receipt-set linkage findings onto outcome receipt ids.

    Returns (codes per outcome id, whether any linkage finding could not be
    attributed to an outcome id). The detail templates are the existing
    verifier's own; an unattributable finding is treated conservatively.
    """
    per: dict[str, set[str]] = {rid: set() for rid in outcome_ids}
    unattributed = False
    for finding in findings:
        code, detail = finding.get("code"), finding.get("detail", "")
        if code not in CHAIN_CODES:
            continue
        matched = False
        for rid in outcome_ids:
            if code == "admission_receipt_unresolved" and detail.startswith(f"outcome {rid!r} references "):
                per[rid].add(code)
                matched = True
            elif code == "admission_outcome_linkage_mismatch" and detail == f"logical_call_id differs for outcome {rid!r}":
                per[rid].add(code)
                matched = True
        if not matched:
            unattributed = True
    return per, unattributed


def claim_for(receipt: dict[str, Any]) -> tuple[str, list[str]]:
    base_not_relied = [
        "occurrence_of_the_real_world_event",
        "truth_of_the_issuers_assertions",
        "receiver_admission_of_the_underlying_action",
    ]
    kind = receipt.get("receipt_kind")
    if kind == "admission":
        disposition = receipt.get("disposition")
        claim = f"issuer_attests_admission_disposition_{disposition}"
        extra = {
            "admitted": ["tool_body_execution", "completion_or_approval_of_the_underlying_action"],
            "refused": ["absence_of_execution_outside_the_named_boundary"],
            "deferred_for_review": ["approval_of_the_deferred_call", "tool_body_execution"],
        }.get(disposition, [])
        return claim, base_not_relied + extra
    if kind == "outcome":
        return (
            f"issuer_attests_outcome_{receipt.get('outcome')}",
            base_not_relied + ["tool_body_execution"],
        )
    return f"issuer_attests_receipt_kind_{kind}", base_not_relied


def selfcheck() -> dict[str, Any]:
    """Positive controls for this process's own independence detectors.

    Each check must come out True: the tripwire must refuse and count a
    resolver call (offline: it is refused before any lookup), and the module
    inventory must actually flag a producer-named module that is really
    imported. A detector that cannot fire would make every clean run vacuous.
    """
    try:
        socket.getaddrinfo("localhost", 80)
        refused = False
    except OSError:
        refused = True
    checks: dict[str, bool] = {
        "network_tripwire_refuses_and_counts": refused and "socket.getaddrinfo" in _TRIPWIRE_EVENTS,
        "producer_predicate_flags_producer_names": all(
            is_producer_module(n) for n in ("dagr", "dagr_" + "mcp", "countergraph", "counterpedia")
        ),
        "producer_predicate_ignores_benign_names": not any(
            is_producer_module(n) for n in ("json", "arcs_verify", "dagrfoo", "mydagr_mcp")
        ),
    }
    planted = "dagr_" + "selfcheck_planted"
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / f"{planted}.py").write_text("MARK = 1\n", encoding="utf-8")
        sys.path.insert(0, tmp)
        try:
            importlib.import_module(planted)
            flagged = producer_modules_in(list(sys.modules))
        finally:
            sys.path.remove(tmp)
            sys.modules.pop(planted, None)
    checks["module_inventory_detects_a_really_imported_producer_module"] = flagged == [planted]
    checks["module_inventory_clean_after_removal"] = producer_modules_in(list(sys.modules)) == []
    return {"ok": all(checks.values()), "checks": checks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--selfcheck", action="store_true", help="run the detector positive controls and print JSON")
    parser.add_argument("--verifier-root", type=Path)
    parser.add_argument("--trust-input", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--receipt", action="append", type=Path, dest="receipts")
    args = parser.parse_args(argv)

    install_network_tripwire()
    if args.selfcheck:
        result = selfcheck()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 1
    if not (args.verifier_root and args.trust_input and args.out_dir and args.receipts):
        parser.error("--verifier-root, --trust-input, --out-dir and at least one --receipt are required")
    try:
        return _run(args)
    except UsageError as exc:
        print(f"usage_error: {exc}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    # Records left by an earlier run in this directory must never be mistaken for this run's.
    for stale in ("verifier-findings.json", "reliance-decision.json", "receiver-process-facts.json"):
        (args.out_dir / stale).unlink(missing_ok=True)
    trust, trust_sha = load_trust_input(args.trust_input)

    items: list[Item] = []
    for index, path in enumerate(args.receipts):
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise UsageError(f"receipt unreadable: {path.name}: {exc}") from exc
        item = Item(index, path, raw)
        parse_receipt_bytes(item)
        items.append(item)

    root = args.verifier_root.resolve()
    if not (root / "arcs_verify" / "verifier.py").is_file():
        raise UsageError("--verifier-root does not contain arcs_verify/verifier.py")
    sys.path.insert(0, str(root))
    try:
        from arcs_verify.receipt_set import WORKFLOW_SCHEMAS, verify_receipt_set
        from arcs_verify.verifier import PUBLIC_PUBLICATION_PROFILE, verify_receipt
    except ImportError as exc:
        raise UsageError(f"verifier import failed: {exc}") from exc

    data_dir = root / "arcs_verify" / "data"
    keyring = trust["keyring"]
    default_profile = trust["default_profile"]

    # ---- 1. existing verifier, once per parsed receipt, output kept unaltered
    for item in items:
        if item.parsed is None:
            continue
        item.selected_profile = claimed_profile_slug(item.parsed, default_profile)
        item.schema_name = (
            "srs-envelope-v0.2.1.schema.json"
            if item.selected_profile == PUBLIC_PUBLICATION_PROFILE
            else "srs-envelope-v0.2.0.schema.json"
        )
        try:
            report = verify_receipt(
                item.parsed,
                keyring,
                schema_path=data_dir / item.schema_name,
                selected_profile=item.selected_profile,
            )
            item.report = report.to_dict()
        except Exception as exc:  # a crash is not a verdict
            item.verifier_exception = type(exc).__name__

    # ---- 2. existing receipt-set verifier for admission/outcome linkage
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    chain_report: dict[str, Any] | None = None
    chain_inputs = [i for i in items if i.parsed is not None]
    if chain_inputs:
        workdir = out_dir / "chain-workdir"
        if workdir.exists():
            shutil.rmtree(workdir)
        workdir.mkdir()
        trust_bundle_bytes = (json.dumps(keyring, indent=2, sort_keys=True) + "\n").encode("utf-8")
        (workdir / "trust-bundle.json").write_bytes(trust_bundle_bytes)
        entries = []
        for item in chain_inputs:
            name = f"r{item.index:03d}.json"
            (workdir / name).write_bytes(item.raw)
            entries.append({"path": name, "sha256": hashlib.sha256(item.raw).hexdigest()})
        index = {
            "schema": sorted(WORKFLOW_SCHEMAS)[0],
            "service_mode": "stranger0-receiver-constructed-index",
            "profile": default_profile,
            "trust_bundle": {"path": "trust-bundle.json", "sha256": hashlib.sha256(trust_bundle_bytes).hexdigest()},
            "receipt_set": entries,
        }
        (workdir / "workflow.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        previous_cwd = Path.cwd()
        os.chdir(out_dir)
        try:
            chain_report = verify_receipt_set(Path("chain-workdir") / "workflow.json").to_dict()
        finally:
            os.chdir(previous_cwd)

    # ---- 3. record 1: verifier findings, unaltered
    findings_record = {
        "schema": FINDINGS_SCHEMA,
        "record_kind": "verifier_findings",
        "statement": (
            "Output of the existing ARCS Verify verifier, recorded unaltered. This record "
            "is not a reliance decision and does not say whether anyone should rely on "
            "these receipts."
        ),
        "trust_input_sha256": trust_sha,
        "receipts": [
            {
                "index": item.index,
                "file_name": item.file_name,
                "receipt_bytes_sha256": item.bytes_sha256,
                "input_status": "parsed" if item.parsed is not None else item.input_token,
                "selected_profile": item.selected_profile,
                "envelope_schema_file": item.schema_name,
                "verifier_exception": item.verifier_exception,
                "verifier_report": item.report,
            }
            for item in items
        ],
        "chain_findings": chain_report,
    }
    findings_bytes = (json.dumps(findings_record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (out_dir / "verifier-findings.json").write_bytes(findings_bytes)

    # ---- 4. record 2: this receiver's own reliance decision
    policy = trust["policy"]
    accepted_versions = set(trust["accepted_receipt_versions"])
    accepted_profiles = set(trust["accepted_profiles"])
    ledger = {(e["receipt_id"]): e["canonical_json_sha256"] for e in trust["relied_receipt_ledger"]}

    outcome_ids = [
        i.receipt_id
        for i in items
        if i.parsed is not None and i.receipt_id and i.parsed.get("receipt_kind") == "outcome"
    ]
    chain_by_outcome, chain_unattributed = attribute_chain_findings(
        [rid for rid in outcome_ids if rid], (chain_report or {}).get("findings", [])
    )

    reasons_by_index: dict[int, list[dict[str, Any]]] = {i.index: [] for i in items}
    for item in items:
        rs = reasons_by_index[item.index]
        if item.parsed is None:
            rs.append(reason(item.input_token or "input.unreadable", "receiver_input", detail=item.input_detail))
            continue
        receipt = item.parsed
        if item.report is None:
            rs.append(reason("verifier.no_findings_produced", "receiver_input", exception=item.verifier_exception))
        elif item.report.get("passed") is not True:
            rs.append(
                reason(
                    "verifier.not_passed",
                    "verifier_finding",
                    failed_checks=failed_checks(item.report),
                    failure_codes=list(item.report.get("failure_codes", [])),
                )
            )
        if receipt.get("receipt_version") not in accepted_versions:
            rs.append(reason("policy.receipt_version_not_accepted", "receiver_policy", presented=receipt.get("receipt_version")))
        if item.selected_profile not in accepted_profiles:
            rs.append(reason("policy.profile_not_accepted", "receiver_policy", presented=item.selected_profile))
        if receipt.get("issuer_id") not in policy["accepted_issuer_ids"]:
            rs.append(reason("policy.issuer_not_accepted", "receiver_policy", presented=receipt.get("issuer_id")))
        if receipt.get("boundary_id") not in policy["accepted_boundary_ids"]:
            rs.append(reason("policy.boundary_not_accepted", "receiver_policy", presented=receipt.get("boundary_id")))
        if receipt.get("policy_pack_id") not in policy["accepted_policy_pack_ids"]:
            rs.append(reason("policy.policy_pack_not_accepted", "receiver_policy", presented=receipt.get("policy_pack_id")))

        # chain: only outcome receipts carry an admission link
        if receipt.get("receipt_kind") == "outcome" and item.receipt_id:
            codes = chain_by_outcome.get(item.receipt_id, set())
            if "admission_outcome_linkage_mismatch" in codes:
                rs.append(reason("chain.admission_outcome_linkage_mismatch", "verifier_finding", receipt_set_finding="admission_outcome_linkage_mismatch"))
            if "admission_receipt_unresolved" in codes and policy["require_admission_link_for_outcome"]:
                rs.append(reason("chain.admission_receipt_unresolved", "verifier_finding", receipt_set_finding="admission_receipt_unresolved"))
            if chain_unattributed and not codes and policy["require_admission_link_for_outcome"]:
                rs.append(reason("chain.admission_receipt_unresolved", "receiver_policy", note="unattributed receipt-set linkage finding, treated conservatively"))

    # replay / duplicate / conflict: receiver-owned state (ledger + this submission)
    by_id: dict[str, list[Item]] = {}
    for item in items:
        if item.receipt_id:
            by_id.setdefault(item.receipt_id, []).append(item)
    for rid, group in by_id.items():
        digests = {i.replay_digest for i in group}
        ledger_digest = ledger.get(rid)
        conflict = len(digests) > 1 or (ledger_digest is not None and ledger_digest not in digests)
        for position, item in enumerate(group):
            rs = reasons_by_index[item.index]
            if conflict:
                rs.append(reason("replay.receipt_id_conflict", "receiver_state", receipt_id=rid, distinct_digests_in_submission=len(digests), ledger_has_entry=ledger_digest is not None))
            elif ledger_digest is not None:
                rs.append(reason("replay.already_relied_in_ledger", "receiver_state", receipt_id=rid))
            elif position > 0:
                rs.append(reason("replay.duplicate_in_submission", "receiver_state", receipt_id=rid, first_index=group[0].index))

    # ---- E-A-LINK: strict dependent reliance, under this receiver's own policy only.
    # An admission's decision never depends on an outcome, so one provisional pass over every
    # receipt settles the dependency and the result cannot depend on the order they arrived in.
    # A matching receipt id alone is not enough, and neither is the receipt-set linker's
    # arrival finding: the referenced admission must be the one this receiver relied upon.
    if policy["require_relied_admission_for_outcome"]:
        provisional = {i.index: decide_from(reasons_by_index[i.index]) for i in items}
        by_receipt_id: dict[str, list[Item]] = {}
        for i in items:
            if i.receipt_id:
                by_receipt_id.setdefault(i.receipt_id, []).append(i)
        for item in items:
            if item.parsed is None or item.parsed.get("receipt_kind") != "outcome":
                continue
            ref = item.parsed.get("admission_receipt_ref")
            if not isinstance(ref, str) or not ref:
                continue  # nothing referenced; the arrival requirement owns that case
            group = by_receipt_id.get(ref, [])
            if not group:
                continue  # absent: chain.admission_receipt_unresolved already owns this case
            if len(group) > 1:
                state = "duplicate_receipt_id_in_submission"
            else:
                admission = group[0]
                parsed = admission.parsed or {}
                if parsed.get("receipt_kind") != "admission":
                    # Not an admission, so the reference is unresolved rather than refused:
                    # chain.admission_receipt_unresolved already owns it, and saying both
                    # would assert that the same receipt did and did not arrive.
                    continue
                if parsed.get("logical_call_id") != item.parsed.get("logical_call_id"):
                    state = "logical_call_id_differs"
                elif provisional[admission.index] != "rely":
                    state = provisional[admission.index]
                else:
                    continue
            reasons_by_index[item.index].append(
                reason(
                    STRICT_ADMISSION_TOKEN,
                    "receiver_policy",
                    admission_receipt_id=ref,
                    admission_state=state,
                    matching_receipts_in_submission=len(group),
                )
            )

    decisions = []
    ledger_additions = []
    for item in items:
        rs = sorted(reasons_by_index[item.index], key=lambda r: (r["token"], r["source"]))
        decision = decide_from(rs)
        entry: dict[str, Any] = {
            "index": item.index,
            "file_name": item.file_name,
            "receipt_id": item.receipt_id,
            "receipt_bytes_sha256": item.bytes_sha256,
            "canonical_json_sha256": item.canonical_sha256,
            "receipt_declared_disposition": (item.parsed or {}).get("disposition"),
            "receipt_declared_kind": (item.parsed or {}).get("receipt_kind"),
            "decision": decision,
            "reasons": rs,
            "verifier_passed": (item.report or {}).get("passed") if item.report else None,
        }
        if decision == "rely":
            claim, not_relied = claim_for(item.parsed or {})
            entry["reliance_claim"] = claim
            entry["not_relied_upon"] = not_relied
            if item.receipt_id:
                ledger_additions.append({"receipt_id": item.receipt_id, "canonical_json_sha256": item.replay_digest})
        decisions.append(entry)

    counts: dict[str, int] = {}
    dispositions: dict[str, int] = {}
    for d in decisions:
        counts[d["decision"]] = counts.get(d["decision"], 0) + 1
        label = d["receipt_declared_disposition"] or f"(kind:{d['receipt_declared_kind']})"
        dispositions[label] = dispositions.get(label, 0) + 1

    decision_record = {
        "schema": DECISION_SCHEMA,
        "record_kind": "receiver_reliance_decision",
        "statement": (
            "This receiver's own decision under its own trust input and policy. It is "
            "separate from the verifier findings it cites. A passing verifier result is "
            "necessary for 'rely' but never sufficient; a valid signature is not event "
            "truth and is not receiver admission of the underlying action."
        ),
        "receiver_id": trust["receiver_id"],
        "receiver_version": RECEIVER_ID,
        "policy_id": trust["policy_id"],
        "effective_linkage_policy": {
            "require_admission_link_for_outcome": policy["require_admission_link_for_outcome"],
            "require_relied_admission_for_outcome": policy["require_relied_admission_for_outcome"],
            "note": (
                "The first requires the referenced admission to ARRIVE. The second "
                "additionally requires that this receiver relied on it. With the second "
                "false, a separately verified outcome may be relied upon while its linked "
                "admission was not: that is the narrower, arrival-only reading."
            ),
        },
        "trust_input_sha256": trust_sha,
        "findings_record_sha256": sha256_ref(findings_bytes),
        "decisions": decisions,
        "summary": {
            "receipts_in": len(items),
            "decisions_out": len(decisions),
            "no_receipt_dropped": len(items) == len(decisions),
            "counts_by_decision": dict(sorted(counts.items())),
            "counts_by_receipt_declared_disposition": dict(sorted(dispositions.items())),
        },
        "ledger_additions": ledger_additions,
    }
    (out_dir / "reliance-decision.json").write_text(
        json.dumps(decision_record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # ---- 5. what this process actually loaded
    stdlib = set(sys.stdlib_module_names)
    tops = sorted({name.split(".", 1)[0] for name in sys.modules})
    third_party = sorted(t for t in tops if t not in stdlib and t != "arcs_verify" and not t.startswith("_") and t != "__main__")
    facts = {
        "schema": FACTS_SCHEMA,
        "record_kind": "receiver_process_facts",
        "receiver_version": RECEIVER_ID,
        "python_version": sys.version.split()[0],
        "python_isolated_flag": bool(sys.flags.isolated),
        "environment_variable_names": sorted(os.environ),
        "arcs_verify_modules_loaded": sorted(m for m in sys.modules if m.split(".", 1)[0] == "arcs_verify"),
        "third_party_top_level_modules_loaded": third_party,
        "producer_modules_loaded": producer_modules_in(list(sys.modules)),
        "network_tripwire": {
            "installed": True,
            "blocked_attempts": len(_TRIPWIRE_EVENTS),
            "blocked_attempt_kinds": sorted(set(_TRIPWIRE_EVENTS)),
            "is_a_sandbox": False,
        },
        "verifier_inputs_sha256": {
            "arcs_verify/verifier.py": sha256_ref((root / "arcs_verify" / "verifier.py").read_bytes()),
            "arcs_verify/receipt_set.py": sha256_ref((root / "arcs_verify" / "receipt_set.py").read_bytes()),
            "arcs_verify/data/srs-envelope-v0.2.0.schema.json": sha256_ref((data_dir / "srs-envelope-v0.2.0.schema.json").read_bytes()),
        },
    }
    (out_dir / "receiver-process-facts.json").write_text(
        json.dumps(facts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
