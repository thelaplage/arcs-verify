"""Independent verifier for DAGR Analytics C1 snapshots.

arcs-verify recomputes findings from serialized bytes only. This module imports
ZERO dagr-analytics / Counterpedia producer code and no reference oracle; it
canonicalizes independently via arcs-verify's own RFC8785 machinery, which over
C1's narrowed v0.1 domain (ASCII keys, integer-only scalar context) is byte-
equivalent to dagr.canonical-json.v0.1 (proven by the equivalence vectors).

Upstream C1 (#2) and RET1 (#5) contracts are PROVISIONAL / unmerged: this lane
may consume their exact bytes but must not be readied/merged until they land.

Two facts are kept separate and never conflated:
  - what the verifier independently recomputed from supplied bytes;
  - what the caller DECLARED about a source store the verifier cannot observe.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Optional

import rfc8785

_VENDOR = Path(__file__).resolve().parent.parent / "vendor" / "dagr-analytics"
CANON_PROFILE = "dagr.canonical-json.v0.1"
REPORT_SCHEMA = "arcs_verify.analytics_snapshot_report.v0_1"
VERIFICATION_PROFILE = "arcs_verify.dagr_analytics.c1_snapshot.v0_1"

# Provisional pins of the corrected C1 candidate definitions and the RET1 schedule
# (recomputed from the vendored bytes; see VENDORED_FROM). A self-consistent but
# unpinned definition/schedule is not C1 conformance.
DEF_PINS = {
    "http_request_count": "sha256:0dbf4c9019201ae0139cb5668606722cc0a6c6fcb8d9c824228ce19daf9e9f0f",
    "page_render_count": "sha256:ff12b79611a37062efd2e4b40445b306111837ba5133ff147a329bd635a8862e",
    "page_view_count": "sha256:a83de57baa3acdd820aecfafb55ea1fae54389bc2aaa13818cee22d2db112595",
    "api_object_read_count": "sha256:e8b41b16f46f755c0c51985a29ee23c80b30729aba0a506600fddb44bdba8161",
    "mcp_resource_read_count": "sha256:07b7a142396beba2907ce002885a7036ec2630758755e8d78e56456b9522343f",
}
RET_SCHED_PIN = "sha256:d4eb1f13b819aaa371cab6a62259dba0d9e4beff1183c931dffd317bd282ff75"

# (action, transport) profile for the four direct-count metrics. page_view_count
# is derived from page_render and handled specially.
_DIRECT = {
    "http_request_count": ("http_request", "web"),
    "page_render_count": ("page_render", "web"),
    "api_object_read_count": ("api_object_read", "api"),
    "mcp_resource_read_count": ("mcp_resource_read", "mcp"),
}
SUPPORTED = set(_DIRECT) | {"page_view_count"}

SOURCE_STATUSES = {"supplied", "absent-expired", "absent-withdrawn", "absent-unexplained", "not-supplied"}


class SourceIntegrityError(Exception):
    """Usage / unreadable-input: exit 2 (never a verification verdict)."""


# --------------------------------------------------------------------------- #
# independent canonicalization over the C1 domain
# --------------------------------------------------------------------------- #
def _guard_domain(value: Any) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")) or not value.is_integer():
            raise _Canon("non-integer/non-finite number outside C1 v0.1 domain")
        return
    if isinstance(value, str):
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not all(0x21 <= ord(c) <= 0x7E for c in k):
                raise _Canon(f"non-ASCII/invalid key outside C1 domain: {k!r}")
            _guard_domain(v)
        return
    if isinstance(value, list):
        for v in value:
            _guard_domain(v)
        return
    raise _Canon(f"unserializable value {type(value).__name__}")


class _Canon(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    _guard_domain(value)
    return rfc8785.dumps(value)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


# --------------------------------------------------------------------------- #
# recount
# --------------------------------------------------------------------------- #
def recount(metric_id: str, observations: list[dict]) -> int:
    if metric_id in _DIRECT:
        act, tr = _DIRECT[metric_id]
        return sum(1 for o in observations if o.get("action") == act and o.get("transport") == tr)
    if metric_id == "page_view_count":
        renders = [o for o in observations if o.get("action") == "page_render" and o.get("transport") == "web"]
        distinct = {(o.get("session_ref"), o.get("object_ref")) for o in renders if o.get("session_ref") is not None}
        nulls = sum(1 for o in renders if o.get("session_ref") is None)
        return len(distinct) + nulls  # never infers a session/person identity
    raise ValueError(metric_id)


# --------------------------------------------------------------------------- #
# retention (declared-posture aware)
# --------------------------------------------------------------------------- #
def _parse_rfc3339(s: str) -> _dt.datetime:
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception as e:
        raise SourceIntegrityError(f"bad RFC3339 timestamp {s!r}: {e}")


def _anon_retention_seconds(schedule: dict) -> Optional[int]:
    r = schedule["classes"]["ANONYMOUS_AGGREGATE"]["raw_source_retention"]
    if isinstance(r, dict) and "max_days_after_window_end" in r:
        return int(r["max_days_after_window_end"]) * 86400
    return None


def evaluate_retention(schedule: dict, window_end: str, source_status: str, as_of: str) -> dict:
    """RET1 states are classifications of the DECLARED posture (basis=DECLARED),
    except 'supplied' where the verifier holds the bytes (basis=SUPPLIED_BYTES)."""
    deadline_dt = _parse_rfc3339(window_end) + _dt.timedelta(seconds=_anon_retention_seconds(schedule) or 0)
    as_of_dt = _parse_rfc3339(as_of)
    past_deadline = as_of_dt > deadline_dt
    out = {
        "declared_source_status": source_status,
        "retention_deadline": deadline_dt.isoformat(),
        "evaluated_as_of": as_of,
    }
    if source_status == "supplied":
        out.update(source_status_basis="SUPPLIED_BYTES",
                   source_recomputability_state="FULL_RECOMPUTATION_AVAILABLE",
                   retention_conformance="NONCONFORMING" if past_deadline else "CONFORMING")
    elif source_status == "not-supplied":
        out.update(source_status_basis="DECLARED",
                   source_recomputability_state="NOT_EVALUATED",
                   retention_conformance="NOT_EVALUATED")
    elif source_status == "absent-expired":
        if not past_deadline:
            raise _Contradiction("declared absent-expired but as_of is before the retention deadline")
        out.update(source_status_basis="DECLARED",
                   source_recomputability_state="PROVENANCE_BOUND_SOURCE_EXPIRED",
                   retention_conformance="CONFORMING")
    elif source_status == "absent-withdrawn":
        out.update(source_status_basis="DECLARED",
                   source_recomputability_state="SOURCE_WITHDRAWN",
                   retention_conformance="CONFORMING")
    elif source_status == "absent-unexplained":
        out.update(source_status_basis="DECLARED",
                   source_recomputability_state="SOURCE_UNAVAILABLE_UNEXPLAINED",
                   retention_conformance="NOT_EVALUATED")
    return out


class _Contradiction(ValueError):
    pass


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #
_SNAP_BODY_KEYS = ["derivation_version", "input_partition_digest", "metric_definition_digest",
                   "metric_id", "metric_version", "value", "window_end", "window_start"]


def verify(snapshot: dict, definition: dict, partition: Optional[dict],
           schedule: dict, source_status: str, as_of: str) -> dict:
    findings: list[str] = []
    concl: dict[str, str] = {}
    rec: dict[str, Any] = {"metric_definition_digest": None, "input_partition_digest": None,
                           "value": None, "snapshot_digest": None}

    def C(name, ok):
        concl[name] = "PASS" if ok else "FAIL"
        return ok

    mid = snapshot.get("metric_id")
    mver = snapshot.get("metric_version")

    # snapshot shape
    shape_ok = all(k in snapshot for k in _SNAP_BODY_KEYS + ["privacy_class", "snapshot_digest"])
    if not C("snapshot_shape", shape_ok):
        findings.append("analytics_snapshot.snapshot_shape_invalid")

    # metric profile binding
    if not C("metric_profile_binding", mid in SUPPORTED and mver == "0.1"):
        findings.append("analytics_snapshot.unsupported_metric_profile")

    # metric identity agreement (definition vs snapshot). The definition object
    # names its version field "version"; the snapshot names it "metric_version".
    idmatch = definition.get("metric_id") == mid and definition.get("version") == mver
    if not C("metric_identity", idmatch):
        findings.append("analytics_snapshot.metric_identity_mismatch")

    # metric_definition_digest: recompute + snapshot-match + pin-match
    mdd = digest(definition)
    rec["metric_definition_digest"] = mdd
    dd_ok = mdd == snapshot.get("metric_definition_digest")
    if not C("metric_definition_digest", dd_ok):
        findings.append("analytics_snapshot.metric_definition_digest_mismatch")
    pin_ok = mid in DEF_PINS and mdd == DEF_PINS[mid]
    if not pin_ok:
        findings.append("analytics_snapshot.metric_definition_pin_mismatch")
        concl["metric_definition_pin"] = "FAIL"
    else:
        concl["metric_definition_pin"] = "PASS"

    # partition-dependent conclusions
    if partition is not None:
        obs = partition.get("observations")
        pshape = isinstance(obs, list) and "window_start" in partition and "window_end" in partition
        if not C("partition_shape", pshape):
            findings.append("analytics_snapshot.partition_shape_invalid")
            obs = obs if isinstance(obs, list) else []
        ids = [o.get("event_id") for o in obs]
        uniq = len(ids) == len(set(ids))
        if not C("event_id_uniqueness", uniq):
            findings.append("analytics_snapshot.duplicate_event_id")
        wbind = partition.get("window_start") == snapshot.get("window_start") and \
            partition.get("window_end") == snapshot.get("window_end")
        if not C("window_binding", wbind):
            findings.append("analytics_snapshot.window_mismatch")
        if uniq and pshape:
            ipd = digest({"observations": sorted(obs, key=lambda o: o["event_id"]),
                          "window_end": partition["window_end"], "window_start": partition["window_start"]})
            rec["input_partition_digest"] = ipd
            if not C("input_partition_digest", ipd == snapshot.get("input_partition_digest")):
                findings.append("analytics_snapshot.input_partition_digest_mismatch")
            val = recount(mid, obs) if mid in SUPPORTED else None
            rec["value"] = val
            if not C("value_recomputation", val == snapshot.get("value")):
                findings.append("analytics_snapshot.value_mismatch")
        else:
            concl["input_partition_digest"] = "NOT_EVALUATED"
            concl["value_recomputation"] = "NOT_EVALUATED"
    else:
        concl["partition_shape"] = "NOT_EVALUATED"
        concl["event_id_uniqueness"] = "NOT_EVALUATED"
        concl["window_binding"] = "NOT_EVALUATED"
        concl["input_partition_digest"] = "NOT_EVALUATED"
        concl["value_recomputation"] = "NOT_EVALUATED"

    # snapshot_digest recompute (from retained fields; input_partition_digest from
    # the snapshot itself when partition absent)
    ipd_for_body = rec["input_partition_digest"] or snapshot.get("input_partition_digest")
    body = {k: (ipd_for_body if k == "input_partition_digest" else snapshot.get(k)) for k in _SNAP_BODY_KEYS}
    try:
        sd = digest(body)
        rec["snapshot_digest"] = sd
        if not C("snapshot_digest", sd == snapshot.get("snapshot_digest")):
            findings.append("analytics_snapshot.snapshot_digest_mismatch")
    except _Canon:
        C("snapshot_digest", False)
        findings.append("analytics_snapshot.canonicalization_failed")

    # privacy class binding
    if not C("privacy_class_binding", snapshot.get("privacy_class") == "ANONYMOUS_AGGREGATE"):
        findings.append("analytics_snapshot.privacy_class_mismatch")

    # retention (independent axis)
    retention = evaluate_retention(schedule, snapshot.get("window_end", ""), source_status, as_of)
    if retention["retention_conformance"] == "NONCONFORMING":
        findings.append("analytics_snapshot.retention_nonconforming")

    metric_integrity = "PASS" if all(v == "PASS" for k, v in concl.items()) else \
        ("FAIL" if any(v == "FAIL" for v in concl.values()) else "PARTIAL")

    return {
        "schema": REPORT_SCHEMA,
        "verification_profile": VERIFICATION_PROFILE,
        "upstream_contract_posture": "PROVISIONAL",
        "canonicalization_profile": CANON_PROFILE,
        "conclusions": concl,
        "metric_integrity": metric_integrity,
        "recomputed": rec,
        "retention": {"schedule_digest": digest(schedule), "retention_schedule_pin": RET_SCHED_PIN, **retention},
        "failure_codes": sorted(set(findings)),
        "limitations": _limitations(source_status, partition),
    }


def _limitations(source_status: str, partition: Optional[dict]) -> list[str]:
    lim = []
    if partition is None:
        lim.append("input_partition_digest and value_recomputation are NOT_EVALUATED: no partition was supplied; this is limited verification, not a full recount.")
    if source_status != "supplied":
        lim.append(f"source storage fact was DECLARED by the caller (--source-status {source_status}) and was NOT independently observed by the verifier.")
    return lim


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except Exception as e:
        raise SourceIntegrityError(f"cannot read {path}: {e}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arcs-verify analytics-snapshot")
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--metric-definition", required=True)
    ap.add_argument("--partition")
    ap.add_argument("--retention-schedule", required=True)
    ap.add_argument("--source-status", required=True, choices=sorted(SOURCE_STATUSES))
    ap.add_argument("--as-of", required=True, help="explicit RFC3339; no implicit wall clock")
    ap.add_argument("--json", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2

    # source-status <-> partition contract (argument-combination = usage, exit 2)
    if args.source_status == "supplied" and not args.partition:
        print("usage: --source-status supplied requires --partition", file=sys.stderr)
        return 2
    if args.partition and args.source_status != "supplied":
        print("usage: --partition requires --source-status supplied", file=sys.stderr)
        return 2

    try:
        snapshot = _load(args.snapshot)
        definition = _load(args.metric_definition)
        schedule = _load(args.retention_schedule)
        partition = _load(args.partition) if args.partition else None

        # retention schedule pin (shape + exact pinned digest)
        if not all(k in schedule for k in ("schedule", "classes", "recomputability_states")):
            print("retention schedule shape invalid", file=sys.stderr)
            return _emit_fail("analytics_snapshot.retention_schedule_invalid", args)
        if digest(schedule) != RET_SCHED_PIN:
            return _emit_fail("analytics_snapshot.retention_schedule_pin_mismatch", args)

        report = verify(snapshot, definition, partition, schedule, args.source_status, args.as_of)
    except _Contradiction as e:
        return _emit_fail("analytics_snapshot.source_status_contradiction", args, str(e))
    except SourceIntegrityError as e:
        print(f"source-integrity error: {e}", file=sys.stderr)
        return 2
    except _Canon as e:
        return _emit_fail("analytics_snapshot.canonicalization_failed", args, str(e))

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _human(report)

    failed = any(v == "FAIL" for v in report["conclusions"].values())
    nonconforming = report["retention"]["retention_conformance"] == "NONCONFORMING"
    return 1 if (failed or nonconforming) else 0


def _emit_fail(code: str, args, detail: str = "") -> int:
    report = {"schema": REPORT_SCHEMA, "verification_profile": VERIFICATION_PROFILE,
              "upstream_contract_posture": "PROVISIONAL", "failure_codes": [code],
              "detail": detail, "conclusions": {}, "retention": {"retention_conformance": "NOT_EVALUATED"}}
    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"FAIL: {code} {detail}".rstrip(), file=sys.stderr)
    return 1


def _human(r: dict) -> None:
    print(f"canonicalization_profile: {r['canonicalization_profile']}")
    print(f"upstream_contract_posture: {r['upstream_contract_posture']}")
    print(f"metric_integrity: {r['metric_integrity']}")
    ret = r["retention"]
    print(f"source_status_basis: {ret['source_status_basis']}")
    print(f"source_recomputability_state: {ret['source_recomputability_state']}")
    print(f"retention_conformance: {ret['retention_conformance']}")
    print("conclusions:")
    for k, v in r["conclusions"].items():
        print(f"  {k}: {v}")
    for lim in r["limitations"]:
        print(f"limitation: {lim}")


if __name__ == "__main__":
    sys.exit(main())
