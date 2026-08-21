"""
arcs_verify/cg_replay.py — CG-REPLAY0: independent digest-binding verifier
for countergraph.execution-packet/v0.1 (flat schema).

INDEPENDENCE CONTRACT
  This module imports NOTHING from countergraph, dagr-mcp, dagr-spec,
  counterpedia, or any other producer.  It derives all findings from the
  byte-level contract and profile specification only.

PACKET SCHEMA (countergraph.execution-packet/v0.1 — flat form)
  {
    "schema":                   "countergraph.execution-packet/v0.1",
    "packet_id":                "...",
    "query":                    { ... },
    "query_digest":             "sha256:<hex>",
    "projection_digest":        "sha256:<hex>",
    "result":                   { "nodes": [...], "edges": [...], "posture": "..." },
    "result_digest":            "sha256:<hex>",
    "execution_digest":         "sha256:<hex>",
    "execution_packet_digest":  "sha256:<hex>",
    "authority_effect":         "none"
  }

DIGEST RECOMPUTATION RULES
  query_digest            = sha256_canonical(packet["query"])
  result_digest           = sha256_canonical(packet["result"])
  execution_digest        = sha256_canonical({
                                "query_digest":      <declared>,
                                "result_digest":     <declared>,
                                "projection_digest": <declared>
                            })
  execution_packet_digest = sha256_canonical(packet_without_execution_packet_digest)

CANONICALIZATION PROFILE: canonical-json/v0.1
  key ordering:  Python str sort (Unicode code point)
  separators:    compact ("," / ":")
  unicode:       ensure_ascii=False
  encoding:      UTF-8 before hashing
  digest format: "sha256:<64 lowercase hex>"

PERMANENT NON-FINDINGS (hard constants, not posture)
  truth_verified     = "not_evaluated"  — digest match ≠ real-world event occurred
  authority_conferred = False           — this verifier confers no authority

NON-EQUIVALENCES (always included in every finding)
  "digest_match != real-world event occurred"
  "execution_reproduced != result is true"
  "query_binding_valid != admission or evidence"
  "authority_conferred:false is a hard constant, not a posture"
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

# ── contract constants ────────────────────────────────────────────────────────

EXECUTION_PACKET_SCHEMA = "countergraph.execution-packet/v0.1"

_SHA256_PREFIX = "sha256:"
_SHA256_TOTAL_LEN = 71  # len("sha256:") + 64

# These non-equivalences are always present regardless of digest outcomes.
_PERMANENT_NON_EQUIVALENCES: tuple[str, ...] = (
    "digest_match != real-world event occurred",
    "execution_reproduced != result is true",
    "query_binding_valid != admission or evidence",
    "authority_conferred:false is a hard constant, not a posture",
)


# ── result dataclass ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CGReplayFinding:
    """Structured findings from one CG execution-packet digest-binding verification.

    All Boolean findings reflect digest-binding recomputation only.

    truth_verified is always "not_evaluated".
    authority_conferred is always False.
    non_equivalences always contains the four permanent epistemic guards.
    """

    projection_integrity_valid: bool | None
    """None when projection bytes are not provided (presence-only check performed)."""

    query_binding_valid: bool
    """Recomputed query_digest matches the declared value in packet."""

    result_digest_valid: bool
    """Recomputed result_digest matches the declared value in packet."""

    execution_digest_valid: bool
    """Recomputed execution_digest matches the declared value in packet."""

    execution_reproduced: bool
    """True only when all four digest fields are individually valid."""

    execution_packet_digest_valid: bool
    """Recomputed execution_packet_digest matches the declared value in packet."""

    truth_verified: Literal["not_evaluated"]
    """Hard constant. Digest match does NOT prove the real-world event occurred."""

    authority_conferred: Literal[False]
    """Hard constant. This verifier confers no authority."""

    non_equivalences: tuple[str, ...]
    """Epistemic guards. Always contains the four permanent non-equivalences."""

    failure_code: str | None = None
    failure_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "projection_integrity_valid": self.projection_integrity_valid,
            "query_binding_valid": self.query_binding_valid,
            "result_digest_valid": self.result_digest_valid,
            "execution_digest_valid": self.execution_digest_valid,
            "execution_reproduced": self.execution_reproduced,
            "execution_packet_digest_valid": self.execution_packet_digest_valid,
            "truth_verified": self.truth_verified,
            "authority_conferred": self.authority_conferred,
            "non_equivalences": list(self.non_equivalences),
            "failure_code": self.failure_code,
            "failure_detail": self.failure_detail,
        }


def _fail(code: str, detail: str) -> CGReplayFinding:
    """Return a fully-failed finding with the given error code/detail."""
    return CGReplayFinding(
        projection_integrity_valid=False,
        query_binding_valid=False,
        result_digest_valid=False,
        execution_digest_valid=False,
        execution_reproduced=False,
        execution_packet_digest_valid=False,
        truth_verified="not_evaluated",
        authority_conferred=False,
        non_equivalences=_PERMANENT_NON_EQUIVALENCES,
        failure_code=code,
        failure_detail=detail,
    )


# ── canonicalization (profile: canonical-json/v0.1) ──────────────────────────

_MAX_DEPTH = 64


def _canon_walk(value: Any, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("structure exceeds maximum canonicalization depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        import math
        if not math.isfinite(value):
            raise ValueError("non-finite float has no JSON representation")
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [_canon_walk(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {key: _canon_walk(value[key], depth + 1) for key in sorted(value.keys())}
    raise TypeError(f"type {type(value).__name__!r} cannot be canonicalized")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _canon_walk(value, 0),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _sha256_digest(value: Any) -> str:
    raw = _canonical_json(value).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


# ── format helpers ────────────────────────────────────────────────────────────

def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != _SHA256_TOTAL_LEN:
        return False
    if not value.startswith(_SHA256_PREFIX):
        return False
    body = value[len(_SHA256_PREFIX):]
    if body != body.lower():
        return False
    try:
        int(body, 16)
    except ValueError:
        return False
    return True


# ── digest recomputation ──────────────────────────────────────────────────────

def _recompute_query_digest(query: dict[str, Any]) -> str:
    """sha256_canonical(packet["query"])"""
    return _sha256_digest(query)


def _recompute_result_digest(result: dict[str, Any]) -> str:
    """sha256_canonical(packet["result"])"""
    return _sha256_digest(result)


def _recompute_execution_digest(
    query_digest: str,
    result_digest: str,
    projection_digest: str,
) -> str:
    """sha256_canonical({"query_digest":…, "result_digest":…, "projection_digest":…})"""
    return _sha256_digest(
        {
            "projection_digest": projection_digest,
            "query_digest": query_digest,
            "result_digest": result_digest,
        }
    )


def _recompute_execution_packet_digest(packet: dict[str, Any]) -> str:
    """sha256_canonical(packet minus execution_packet_digest field)"""
    carried = copy.deepcopy(packet)
    carried.pop("execution_packet_digest", None)
    return _sha256_digest(carried)


# ── public entry point ────────────────────────────────────────────────────────

def verify_execution_packet(packet: dict[str, Any]) -> CGReplayFinding:
    """Independently verify digest bindings in a countergraph.execution-packet/v0.1.

    Args:
        packet: The execution packet dict (flat schema form).

    Returns:
        CGReplayFinding with seven digest-binding findings plus permanent
        non-findings (truth_verified=not_evaluated, authority_conferred=False)
        and the four permanent non-equivalence assertions.
    """
    if not isinstance(packet, dict):
        return _fail("invalid_packet", "packet must be a dict")

    schema = packet.get("schema")
    if schema != EXECUTION_PACKET_SCHEMA:
        return _fail(
            "wrong_packet_schema",
            f"expected {EXECUTION_PACKET_SCHEMA!r}, got {schema!r}",
        )

    # ── query_digest ──────────────────────────────────────────────────────────
    query = packet.get("query")
    if not isinstance(query, dict):
        return _fail("missing_query", "packet[\"query\"] must be a dict")

    declared_query_digest = packet.get("query_digest")
    if not _is_sha256(declared_query_digest):
        return _fail("invalid_query_digest", "query_digest is absent or malformed")

    try:
        recomputed_query_digest = _recompute_query_digest(query)
    except Exception as exc:
        return _fail("query_digest_error", f"query digest recomputation failed: {exc}")

    query_binding_valid = recomputed_query_digest == declared_query_digest

    # ── result_digest ─────────────────────────────────────────────────────────
    result = packet.get("result")
    if not isinstance(result, dict):
        return _fail("missing_result", "packet[\"result\"] must be a dict")

    declared_result_digest = packet.get("result_digest")
    if not _is_sha256(declared_result_digest):
        return _fail("invalid_result_digest", "result_digest is absent or malformed")

    try:
        recomputed_result_digest = _recompute_result_digest(result)
    except Exception as exc:
        return _fail("result_digest_error", f"result digest recomputation failed: {exc}")

    result_digest_valid = recomputed_result_digest == declared_result_digest

    # ── projection_digest (presence/format only — no projection bytes) ────────
    declared_projection_digest = packet.get("projection_digest")
    if declared_projection_digest is None:
        projection_integrity_valid: bool | None = None
    elif _is_sha256(declared_projection_digest):
        projection_integrity_valid = True
    else:
        projection_integrity_valid = False

    # ── execution_digest ──────────────────────────────────────────────────────
    declared_execution_digest = packet.get("execution_digest")
    if not _is_sha256(declared_execution_digest):
        return _fail("invalid_execution_digest", "execution_digest is absent or malformed")

    # projection_digest must be present for execution_digest recomputation
    if not _is_sha256(declared_projection_digest):
        execution_digest_valid = False
    else:
        try:
            recomputed_execution_digest = _recompute_execution_digest(
                declared_query_digest,
                declared_result_digest,
                declared_projection_digest,
            )
        except Exception as exc:
            return _fail(
                "execution_digest_error",
                f"execution digest recomputation failed: {exc}",
            )
        execution_digest_valid = recomputed_execution_digest == declared_execution_digest

    # ── execution_packet_digest ───────────────────────────────────────────────
    declared_packet_digest = packet.get("execution_packet_digest")
    if not _is_sha256(declared_packet_digest):
        return _fail(
            "invalid_execution_packet_digest",
            "execution_packet_digest is absent or malformed",
        )

    try:
        recomputed_packet_digest = _recompute_execution_packet_digest(packet)
    except Exception as exc:
        return _fail(
            "execution_packet_digest_error",
            f"packet digest recomputation failed: {exc}",
        )

    execution_packet_digest_valid = recomputed_packet_digest == declared_packet_digest

    # ── execution_reproduced ──────────────────────────────────────────────────
    execution_reproduced = (
        query_binding_valid
        and result_digest_valid
        and execution_digest_valid
        and execution_packet_digest_valid
        and projection_integrity_valid is True
    )

    return CGReplayFinding(
        projection_integrity_valid=projection_integrity_valid,
        query_binding_valid=query_binding_valid,
        result_digest_valid=result_digest_valid,
        execution_digest_valid=execution_digest_valid,
        execution_reproduced=execution_reproduced,
        execution_packet_digest_valid=execution_packet_digest_valid,
        truth_verified="not_evaluated",
        authority_conferred=False,
        non_equivalences=_PERMANENT_NON_EQUIVALENCES,
    )
