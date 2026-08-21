"""
CG-REPLAY0 — independent digest-binding verifier for countergraph.execution-packet/v0.1.

INDEPENDENCE CONTRACT: this module imports nothing from countergraph, dagr-mcp,
dagr-spec, counterpedia, or any other producer. It works from the byte-level
contract and profile specification only.

Seven findings are returned. truth_verified is always not_evaluated.
authority_conferred is always false.

What this verifier checks (digest-binding only):
  - packet_digest_valid     recomputed packet_digest matches declared
  - packet_id_valid         packet_id encodes packet_digest correctly
  - projection_integrity_valid  projection_digest field is present and well-formed sha256
  - query_binding_valid     recomputed query_digest matches declared (in root_execution.query)
  - result_digest_valid     recomputed read_result digest matches declared
  - execution_digest_valid  recomputed execution_digest matches declared
  - execution_reproduced    all six digest bindings passed (structural full-binding check)

What this verifier does NOT check:
  - Whether the embedded traversal result was actually produced from the named
    projection. Full replay requires the exact projection bytes — that is the
    stronger property the packet LIMITATIONS acknowledge.
  - Whether the projection named by projection_digest is admitted or correct.
  - Whether any claim in the result is true.

Verification vocabulary:
  digest binding ≠ replay
  replay ≠ truth
  projection presence ≠ support
  authority_effect is always "none" — this verifier confers no authority

Canonicalization profile: countergraph.canonical-json/v0.1
  Key ordering:  Python str sort order (Unicode code point, not UTF-16)
  Separators:    compact ("," / ":")
  Unicode:       ensure_ascii=False
  Encoding:      UTF-8 before hashing
  Digest format: "sha256:<64 lowercase hex>"
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any

# ── contract constants ─────────────────────────────────────────────────────────

EXECUTION_PACKET_SCHEMA = "countergraph.execution-packet/v0.1"
QUERY_EXECUTION_SCHEMA = "countergraph.query-execution/v0.1"

_DIGEST_SENTINEL = "sha256:pending"
_PACKET_ID_SENTINEL = "cg:execution-packet:sha256:pending"
_SHA256_PREFIX = "sha256:"
_SHA256_TOTAL_LEN = 71  # len("sha256:") + 64
_PACKET_ID_PREFIX = "cg:execution-packet:sha256:"


# ── result dataclass ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CGExecutionReplayReport:
    """Structured findings from one CG execution-packet digest-binding verification.

    All Boolean findings reflect digest-binding recomputation only.
    truth_verified is always "not_evaluated".
    authority_conferred is always False.
    """

    packet_digest_valid: bool
    packet_id_valid: bool
    projection_integrity_valid: bool
    query_binding_valid: bool
    result_digest_valid: bool
    execution_digest_valid: bool
    execution_reproduced: bool
    truth_verified: str  # always "not_evaluated"
    authority_conferred: bool  # always False
    failure_code: str | None
    failure_detail: str | None

    @property
    def all_digest_bindings_valid(self) -> bool:
        return (
            self.packet_digest_valid
            and self.packet_id_valid
            and self.projection_integrity_valid
            and self.query_binding_valid
            and self.result_digest_valid
            and self.execution_digest_valid
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_digest_valid": self.packet_digest_valid,
            "packet_id_valid": self.packet_id_valid,
            "projection_integrity_valid": self.projection_integrity_valid,
            "query_binding_valid": self.query_binding_valid,
            "result_digest_valid": self.result_digest_valid,
            "execution_digest_valid": self.execution_digest_valid,
            "execution_reproduced": self.execution_reproduced,
            "truth_verified": self.truth_verified,
            "authority_conferred": self.authority_conferred,
            "failure_code": self.failure_code,
            "failure_detail": self.failure_detail,
        }


def _fail(code: str, detail: str) -> CGExecutionReplayReport:
    return CGExecutionReplayReport(
        packet_digest_valid=False,
        packet_id_valid=False,
        projection_integrity_valid=False,
        query_binding_valid=False,
        result_digest_valid=False,
        execution_digest_valid=False,
        execution_reproduced=False,
        truth_verified="not_evaluated",
        authority_conferred=False,
        failure_code=code,
        failure_detail=detail,
    )


# ── canonicalization (profile: countergraph.canonical-json/v0.1) ──────────────

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
    raise ValueError(f"type {type(value).__name__!r} cannot be canonicalized")


def _canonical_json(value: Any) -> str:
    return json.dumps(_canon_walk(value, 0), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_digest(value: Any) -> str:
    raw = _canonical_json(value).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


# ── digest format helpers ─────────────────────────────────────────────────────

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


def _is_packet_id(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith(_PACKET_ID_PREFIX):
        return False
    body = value[len(_PACKET_ID_PREFIX):]
    if len(body) != 64 or body != body.lower():
        return False
    try:
        int(body, 16)
    except ValueError:
        return False
    return True


def _packet_id_from_digest(digest: str) -> str:
    return _PACKET_ID_PREFIX + digest[len(_SHA256_PREFIX):]


# ── digest recomputation ──────────────────────────────────────────────────────

def _recompute_packet_digest(packet: dict[str, Any]) -> str:
    """Recompute packet_digest per the CG sentinel procedure.

    The packet is canonicalized with:
      packet_digest  → DIGEST_SENTINEL
      packet_id      → PACKET_ID_SENTINEL
    """
    carried = copy.deepcopy(packet)
    carried["packet_digest"] = _DIGEST_SENTINEL
    carried["packet_id"] = _PACKET_ID_SENTINEL
    return _sha256_digest(carried)


def _recompute_query_digest(query_doc: dict[str, Any]) -> str:
    """Recompute query_digest per the CG sentinel procedure.

    The query sub-document is canonicalized with:
      query_digest → DIGEST_SENTINEL
    """
    carried = copy.deepcopy(query_doc)
    carried["query_digest"] = _DIGEST_SENTINEL
    return _sha256_digest(carried)


def _recompute_read_result_digest(read_result: dict[str, Any]) -> str:
    """Recompute the read-result digest per the CG sentinel procedure.

    The read_result sub-document is canonicalized with:
      result_digest → DIGEST_SENTINEL
    (Note: the field name in the read_result is result_digest, not read_result_digest.)
    """
    carried = copy.deepcopy(read_result)
    carried["result_digest"] = _DIGEST_SENTINEL
    return _sha256_digest(carried)


def _recompute_execution_digest(execution: dict[str, Any]) -> str:
    """Recompute execution_digest per the CG sentinel procedure.

    The execution document is canonicalized with:
      execution_digest → DIGEST_SENTINEL
    """
    carried = copy.deepcopy(execution)
    carried["execution_digest"] = _DIGEST_SENTINEL
    return _sha256_digest(carried)


# ── public entry point ────────────────────────────────────────────────────────

def verify_cg_execution_packet(packet: dict[str, Any]) -> CGExecutionReplayReport:
    """Independently verify digest bindings in a countergraph.execution-packet/v0.1.

    Input: the execution packet document dict (e.g. the "packet" field from a
    POST /v0/query/packet response, or from a packet transport artifact).

    Returns a CGExecutionReplayReport with seven digest-binding findings plus
    the permanent non-findings (truth_verified=not_evaluated, authority_conferred=false).

    This verifier handles only query_execution packets. join_execution packets
    return a failure_code of "unsupported_packet_kind".
    """
    if not isinstance(packet, dict):
        return _fail("invalid_packet", "packet must be a dict")

    schema = packet.get("schema")
    if schema != EXECUTION_PACKET_SCHEMA:
        return _fail(
            "wrong_packet_schema",
            f"expected {EXECUTION_PACKET_SCHEMA!r}, got {schema!r}",
        )

    packet_kind = packet.get("packet_kind")
    if packet_kind != "query_execution":
        return _fail(
            "unsupported_packet_kind",
            f"CG-REPLAY0 handles query_execution only; got {packet_kind!r}",
        )

    # ── packet digest ──────────────────────────────────────────────────────────
    declared_packet_digest = packet.get("packet_digest")
    if not _is_sha256(declared_packet_digest):
        return _fail("invalid_packet_digest", "packet_digest is absent or malformed")

    try:
        recomputed_packet_digest = _recompute_packet_digest(packet)
    except Exception as exc:
        return _fail("packet_digest_error", f"digest recomputation failed: {exc}")

    packet_digest_valid = recomputed_packet_digest == declared_packet_digest

    # ── packet id ─────────────────────────────────────────────────────────────
    declared_packet_id = packet.get("packet_id")
    packet_id_valid = (
        _is_packet_id(declared_packet_id)
        and declared_packet_id == _packet_id_from_digest(declared_packet_digest)
    )

    # ── root execution ─────────────────────────────────────────────────────────
    root_execution = packet.get("root_execution")
    if not isinstance(root_execution, dict):
        return _fail("missing_root_execution", "root_execution must be a dict")

    exec_schema = root_execution.get("schema")
    if exec_schema != QUERY_EXECUTION_SCHEMA:
        return _fail(
            "wrong_execution_schema",
            f"expected {QUERY_EXECUTION_SCHEMA!r} in root_execution.schema, got {exec_schema!r}",
        )

    # ── projection_integrity_valid ─────────────────────────────────────────────
    # Check that projection_digest is present and well-formed in source_requirement.
    # We cannot verify it IS the right projection without the actual projection bytes.
    query_doc = root_execution.get("query")
    projection_integrity_valid = False
    if isinstance(query_doc, dict):
        source_req = query_doc.get("source_requirement")
        if isinstance(source_req, dict):
            projection_integrity_valid = _is_sha256(source_req.get("projection_digest"))

    # ── query digest ──────────────────────────────────────────────────────────
    query_binding_valid = False
    if isinstance(query_doc, dict):
        declared_query_digest = query_doc.get("query_digest")
        if _is_sha256(declared_query_digest):
            try:
                recomputed = _recompute_query_digest(query_doc)
                query_binding_valid = recomputed == declared_query_digest
            except Exception:
                pass

    # ── read-result digest ────────────────────────────────────────────────────
    result_digest_valid = False
    read_result = root_execution.get("read_result")
    if isinstance(read_result, dict):
        declared_result_digest = read_result.get("result_digest")
        # execution also carries read_result_digest — must match
        exec_read_result_digest = root_execution.get("read_result_digest")
        if (
            _is_sha256(declared_result_digest)
            and declared_result_digest == exec_read_result_digest
        ):
            try:
                recomputed = _recompute_read_result_digest(read_result)
                result_digest_valid = recomputed == declared_result_digest
            except Exception:
                pass

    # ── execution digest ──────────────────────────────────────────────────────
    execution_digest_valid = False
    declared_exec_digest = root_execution.get("execution_digest")
    if _is_sha256(declared_exec_digest):
        try:
            recomputed = _recompute_execution_digest(root_execution)
            execution_digest_valid = recomputed == declared_exec_digest
        except Exception:
            pass

    execution_reproduced = (
        packet_digest_valid
        and packet_id_valid
        and projection_integrity_valid
        and query_binding_valid
        and result_digest_valid
        and execution_digest_valid
    )

    return CGExecutionReplayReport(
        packet_digest_valid=packet_digest_valid,
        packet_id_valid=packet_id_valid,
        projection_integrity_valid=projection_integrity_valid,
        query_binding_valid=query_binding_valid,
        result_digest_valid=result_digest_valid,
        execution_digest_valid=execution_digest_valid,
        execution_reproduced=execution_reproduced,
        truth_verified="not_evaluated",
        authority_conferred=False,
        failure_code=None,
        failure_detail=None,
    )
