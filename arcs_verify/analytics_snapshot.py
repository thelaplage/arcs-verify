"""Independent verifier for DAGR Analytics C1 snapshots.

arcs-verify recomputes findings from serialized bytes only. This module imports
ZERO dagr-analytics / Counterpedia producer code and no reference oracle; it
canonicalizes independently via arcs-verify's own RFC8785 machinery, which over
C1's narrowed v0.1 domain (ASCII keys, integer-only scalar context) is byte-
equivalent to dagr.canonical-json.v0.1 (proven by the equivalence vectors).

Upstream C1 (#2, merge b8444c13) and RET1 (#5, merge dcc74df0) have LANDED as
CANDIDATE contracts on dagr-analytics main; their exact landed bytes are vendored
and pinned (see VENDORED_FROM). They are NOT ratified, so the report keeps
upstream_contract_posture=PROVISIONAL and this verifier remains draft pending its
own readiness assessment.

Contract is enforced in verify() (the core), so CLI and library cannot drift.
Two facts are kept separate: what the verifier independently recomputed from
supplied bytes, and what the caller DECLARED about a store it cannot observe.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Optional

import jsonschema
import rfc8785
from referencing import Registry, Resource

_VENDOR = Path(__file__).resolve().parent.parent / "vendor" / "dagr-analytics"
CANON_PROFILE = "dagr.canonical-json.v0.1"
REPORT_SCHEMA = "arcs_verify.analytics_snapshot_report.v0_1"
VERIFICATION_PROFILE = "arcs_verify.dagr_analytics.c1_snapshot.v0_1"
EXPECTED_DERIVATION_VERSION = "0.1.0"

DEF_PINS = {
    "http_request_count": "sha256:53a1b6d219b931c5de3b6a20b039daa8ae1e291b74b3ec2ddfdc614da405227a",
    "page_render_count": "sha256:168e50cc048fd4d6df02ac63c86fa02146f0a140a4f405084d66cc3dea96a48d",
    "page_view_count": "sha256:152f236f1026f9bf494078418bed262e1c1dfdc1083c60ba595e26488130ce34",
    "api_object_read_count": "sha256:95c7a9a07a4adc686c9053193e5e415acaaf90c1e185e9bcd5bf471cafc83ec1",
    "mcp_resource_read_count": "sha256:4c953612fd71bf877c7e6246514a3a3595a5538f9d5206612c717a6814bdfd75",
}
RET_SCHED_PIN = "sha256:5cad76410af1cd74b94ae8e478d0cb7611a09cd26da6854f2103a97596cd15dc"

_DIRECT = {
    "http_request_count": ("http_request", "web"),
    "page_render_count": ("page_render", "web"),
    "api_object_read_count": ("api_object_read", "api"),
    "mcp_resource_read_count": ("mcp_resource_read", "mcp"),
}
SUPPORTED = set(_DIRECT) | {"page_view_count"}
SOURCE_STATUSES = {"supplied", "absent-expired", "absent-withdrawn", "absent-unexplained", "not-supplied"}


# --------------------------------------------------------------------------- #
# vendored schemas — enforced locally, no network resolution
# --------------------------------------------------------------------------- #
def _vload(rel: str) -> dict:
    return json.loads((_VENDOR / rel).read_text())


_OBS_SCHEMA = _vload("c1/contracts/dagr.analytics.observation.v0_1.schema.json")
_PROFILE = _vload("c1/contracts/C1_transport_read.v0_1.schema.json")
_SNAP_SCHEMA = _vload("c1/contracts/metric_snapshot.v0_1.schema.json")
_RET_SCHEMA = _vload("ret1/retention_schedule.v0_1.schema.json")

_REGISTRY = Registry().with_resources([(_OBS_SCHEMA["$id"], Resource.from_contents(_OBS_SCHEMA))])
_V_PROFILE = jsonschema.Draft202012Validator(_PROFILE, registry=_REGISTRY)
_V_SNAP = jsonschema.Draft202012Validator(_SNAP_SCHEMA)
_V_RET = jsonschema.Draft202012Validator(_RET_SCHEMA)


def _valid(validator: jsonschema.Draft202012Validator, instance: Any) -> bool:
    try:
        validator.validate(instance)
        return True
    except jsonschema.ValidationError:
        return False


class SourceIntegrityError(Exception):
    """Usage / unreadable-input / invocation-shape contradiction: exit 2."""


class _Contradiction(ValueError):
    """Semantic declared-posture contradiction: exit 1, source_status_contradiction."""


class _Canon(ValueError):
    pass


class _ArtifactTime(ValueError):
    """A producer artifact timestamp is malformed: verification failure, not exit 2."""


# --------------------------------------------------------------------------- #
# canonicalization over the C1 domain
# --------------------------------------------------------------------------- #
def _guard_domain(value: Any) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, int):
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
        return len(distinct) + nulls
    raise ValueError(metric_id)


# --------------------------------------------------------------------------- #
# time
# --------------------------------------------------------------------------- #
def _parse_caller_time(s: str) -> _dt.datetime:
    """--as-of: strict timezone-aware RFC3339; malformed => usage/source-integrity."""
    try:
        d = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception as e:
        raise SourceIntegrityError(f"malformed --as-of {s!r}: {e}")
    if d.tzinfo is None:
        raise SourceIntegrityError(f"--as-of must be timezone-aware: {s!r}")
    return d


def _parse_artifact_time(s: Any) -> _dt.datetime:
    """window_start/window_end: producer artifact; malformed => verification failure."""
    if not isinstance(s, str):
        raise _ArtifactTime(f"artifact timestamp not a string: {s!r}")
    try:
        d = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception as e:
        raise _ArtifactTime(f"malformed artifact timestamp {s!r}: {e}")
    if d.tzinfo is None:
        raise _ArtifactTime(f"artifact timestamp must be timezone-aware: {s!r}")
    return d


def _anon_retention_seconds(schedule: dict) -> Optional[int]:
    r = schedule["classes"]["ANONYMOUS_AGGREGATE"]["raw_source_retention"]
    if isinstance(r, dict) and "max_days_after_window_end" in r:
        return int(r["max_days_after_window_end"]) * 86400
    return None


# --------------------------------------------------------------------------- #
# invocation-shape contract (usage) — enforced in the core, not just the CLI
# --------------------------------------------------------------------------- #
def _enforce_invocation_shape(partition: Optional[dict], source_status: str) -> None:
    if source_status not in SOURCE_STATUSES:
        raise SourceIntegrityError(f"unknown --source-status {source_status!r}")
    if source_status == "supplied" and partition is None:
        raise SourceIntegrityError("source_status=supplied requires partition bytes")
    if source_status != "supplied" and partition is not None:
        raise SourceIntegrityError(f"source_status={source_status} must not be given partition bytes")


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #
_SNAP_BODY_KEYS = ["derivation_version", "input_partition_digest", "metric_definition_digest",
                   "metric_id", "metric_version", "value", "window_end", "window_start"]


def verify(snapshot: dict, definition: dict, partition: Optional[dict],
           schedule: dict, source_status: str, as_of: str) -> dict:
    _enforce_invocation_shape(partition, source_status)      # usage: raises SourceIntegrityError
    as_of_dt = _parse_caller_time(as_of)                     # usage: raises SourceIntegrityError

    findings: list[str] = []
    concl: dict[str, str] = {}
    rec: dict[str, Any] = {"metric_definition_digest": None, "input_partition_digest": None,
                           "value": None, "snapshot_digest": None}

    def C(name: str, ok: bool) -> bool:
        concl[name] = "PASS" if ok else "FAIL"
        return ok

    def NE(name: str) -> None:
        concl[name] = "NOT_EVALUATED"

    # --- retention schedule: schema + exact pin (verification findings) ---
    schedule_ok = True
    if not _valid(_V_RET, schedule):
        findings.append("analytics_snapshot.retention_schedule_invalid")
        C("retention_schedule", False)
        schedule_ok = False
    elif digest(schedule) != RET_SCHED_PIN:
        findings.append("analytics_snapshot.retention_schedule_pin_mismatch")
        C("retention_schedule", False)
        schedule_ok = False
    else:
        C("retention_schedule", True)

    # --- snapshot shape: full schema validation (additionalProperties=false etc.) ---
    if not C("snapshot_shape", _valid(_V_SNAP, snapshot)):
        findings.append("analytics_snapshot.snapshot_shape_invalid")

    mid = snapshot.get("metric_id")
    mver = snapshot.get("metric_version")
    if not C("metric_profile_binding", mid in SUPPORTED and mver == "0.1"):
        findings.append("analytics_snapshot.unsupported_metric_profile")

    if not C("metric_identity", definition.get("metric_id") == mid and definition.get("version") == mver):
        findings.append("analytics_snapshot.metric_identity_mismatch")

    # --- derivation_version binding: snapshot == definition == pinned ---
    dv_ok = (snapshot.get("derivation_version") == EXPECTED_DERIVATION_VERSION
             and definition.get("derivation_version") == EXPECTED_DERIVATION_VERSION)
    if not C("derivation_version", dv_ok):
        findings.append("analytics_snapshot.derivation_version_mismatch")

    # --- definition digest: recompute + snapshot-match + pin ---
    mdd = digest(definition)
    rec["metric_definition_digest"] = mdd
    if not C("metric_definition_digest", mdd == snapshot.get("metric_definition_digest")):
        findings.append("analytics_snapshot.metric_definition_digest_mismatch")
    if C("metric_definition_pin", mid in DEF_PINS and mdd == DEF_PINS[mid]) is False:
        findings.append("analytics_snapshot.metric_definition_pin_mismatch")

    # --- artifact window timestamps (verification failure if malformed) ---
    window_ok = True
    try:
        _parse_artifact_time(snapshot.get("window_start"))
        _parse_artifact_time(snapshot.get("window_end"))
    except _ArtifactTime:
        window_ok = False
        findings.append("analytics_snapshot.window_mismatch")
        C("window_timestamps", False)
    else:
        C("window_timestamps", True)

    # --- partition-dependent conclusions ---
    if partition is not None:
        pshape = isinstance(partition, dict) and isinstance(partition.get("observations"), list) \
            and "window_start" in partition and "window_end" in partition
        obs = partition.get("observations") if pshape else []
        if not C("partition_shape", pshape):
            findings.append("analytics_snapshot.partition_shape_invalid")

        # every observation must validate the C1 profile (fail before recount)
        obs_profile_ok = pshape and all(isinstance(o, dict) and _valid(_V_PROFILE, o) for o in obs)
        if not C("observation_profile", obs_profile_ok):
            findings.append("analytics_snapshot.observation_profile_invalid")

        ids = [o.get("event_id") for o in obs if isinstance(o, dict)]
        uniq = pshape and len(ids) == len(set(ids)) and len(ids) == len(obs)
        if not C("event_id_uniqueness", uniq):
            findings.append("analytics_snapshot.duplicate_event_id")

        wbind = pshape and partition.get("window_start") == snapshot.get("window_start") \
            and partition.get("window_end") == snapshot.get("window_end")
        if not C("window_binding", wbind):
            findings.append("analytics_snapshot.window_mismatch")

        if pshape and obs_profile_ok and uniq:
            ipd = digest({"observations": sorted(obs, key=lambda o: o["event_id"]),
                          "window_end": partition["window_end"], "window_start": partition["window_start"]})
            rec["input_partition_digest"] = ipd
            if not C("input_partition_digest", ipd == snapshot.get("input_partition_digest")):
                findings.append("analytics_snapshot.input_partition_digest_mismatch")
            if mid in SUPPORTED:
                val = recount(mid, obs)
                rec["value"] = val
                if not C("value_recomputation", val == snapshot.get("value")):
                    findings.append("analytics_snapshot.value_mismatch")
            else:
                NE("value_recomputation")
        else:
            NE("input_partition_digest")
            NE("value_recomputation")
    else:
        for k in ("partition_shape", "observation_profile", "event_id_uniqueness",
                  "window_binding", "input_partition_digest", "value_recomputation"):
            NE(k)

    # --- snapshot_digest recompute ---
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

    if not C("privacy_class_binding", snapshot.get("privacy_class") == "ANONYMOUS_AGGREGATE"):
        findings.append("analytics_snapshot.privacy_class_mismatch")

    # --- retention (independent axis) ---
    if schedule_ok and window_ok:
        retention = _evaluate_retention(schedule, snapshot["window_end"], source_status, as_of_dt, as_of)
    else:
        retention = {"declared_source_status": source_status, "source_status_basis":
                     "SUPPLIED_BYTES" if source_status == "supplied" else "DECLARED",
                     "source_recomputability_state": "NOT_EVALUATED",
                     "retention_conformance": "NOT_EVALUATED", "evaluated_as_of": as_of}
    if retention["retention_conformance"] == "NONCONFORMING":
        findings.append("analytics_snapshot.retention_nonconforming")

    metric_integrity = "PASS" if all(v == "PASS" for v in concl.values()) else \
        ("FAIL" if any(v == "FAIL" for v in concl.values()) else "PARTIAL")

    return {
        "schema": REPORT_SCHEMA,
        "verification_profile": VERIFICATION_PROFILE,
        "upstream_contract_posture": "PROVISIONAL",
        "canonicalization_profile": CANON_PROFILE,
        "conclusions": concl,
        "metric_integrity": metric_integrity,
        "recomputed": rec,
        "retention": {"retention_schedule_pin": RET_SCHED_PIN,
                      "schedule_digest": (digest(schedule) if schedule_ok else None), **retention},
        "failure_codes": sorted(set(findings)),
        "limitations": _limitations(source_status, partition),
    }


def _evaluate_retention(schedule, window_end, source_status, as_of_dt, as_of_raw):
    deadline_dt = _parse_artifact_time(window_end) + _dt.timedelta(seconds=_anon_retention_seconds(schedule) or 0)
    past = as_of_dt > deadline_dt
    out = {"declared_source_status": source_status, "retention_deadline": deadline_dt.isoformat(),
           "evaluated_as_of": as_of_raw}
    if source_status == "supplied":
        out.update(source_status_basis="SUPPLIED_BYTES", source_recomputability_state="FULL_RECOMPUTATION_AVAILABLE",
                   retention_conformance="NONCONFORMING" if past else "CONFORMING")
    elif source_status == "not-supplied":
        out.update(source_status_basis="DECLARED", source_recomputability_state="NOT_EVALUATED",
                   retention_conformance="NOT_EVALUATED")
    elif source_status == "absent-expired":
        if not past:
            raise _Contradiction("declared absent-expired but as_of is before the retention deadline")
        out.update(source_status_basis="DECLARED", source_recomputability_state="PROVENANCE_BOUND_SOURCE_EXPIRED",
                   retention_conformance="CONFORMING")
    elif source_status == "absent-withdrawn":
        out.update(source_status_basis="DECLARED", source_recomputability_state="SOURCE_WITHDRAWN",
                   retention_conformance="CONFORMING")
    elif source_status == "absent-unexplained":
        out.update(source_status_basis="DECLARED", source_recomputability_state="SOURCE_UNAVAILABLE_UNEXPLAINED",
                   retention_conformance="NOT_EVALUATED")
    return out


def _limitations(source_status, partition):
    lim = []
    if partition is None:
        lim.append("input_partition_digest and value_recomputation are NOT_EVALUATED: no partition supplied; limited verification, not a full recount.")
    if source_status != "supplied":
        lim.append(f"source storage fact was DECLARED by the caller (--source-status {source_status}) and was NOT independently observed.")
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
    ap.add_argument("--as-of", required=True, help="explicit tz-aware RFC3339; no implicit wall clock")
    ap.add_argument("--json", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2

    try:
        snapshot = _load(args.snapshot)
        definition = _load(args.metric_definition)
        schedule = _load(args.retention_schedule)
        partition = _load(args.partition) if args.partition else None
        report = verify(snapshot, definition, partition, schedule, args.source_status, args.as_of)
    except _Contradiction as e:
        return _emit_fail("analytics_snapshot.source_status_contradiction", args, str(e))
    except SourceIntegrityError as e:
        print(f"source-integrity/usage error: {e}", file=sys.stderr)
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
              "upstream_contract_posture": "PROVISIONAL", "failure_codes": [code], "detail": detail,
              "conclusions": {}, "retention": {"retention_conformance": "NOT_EVALUATED"}}
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
    print(f"source_status_basis: {ret.get('source_status_basis')}")
    print(f"source_recomputability_state: {ret.get('source_recomputability_state')}")
    print(f"retention_conformance: {ret.get('retention_conformance')}")
    print("conclusions:")
    for k, v in r["conclusions"].items():
        print(f"  {k}: {v}")
    for lim in r["limitations"]:
        print(f"limitation: {lim}")


if __name__ == "__main__":
    sys.exit(main())
