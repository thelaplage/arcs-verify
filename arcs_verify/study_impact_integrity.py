"""Independent Countergraph MEMORY-IMPACT0 digest recomputation.

Reproduces the frozen ``countergraph.canonical-json/v0.1`` profile locally;
does not import Countergraph. This profile is intentionally *not* RFC 8785.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping

CANONICAL_PROFILE = "countergraph.canonical-json/v0.1"
DIGEST_SENTINEL = "sha256:pending"
MEMORY_IMPACT_SCHEMA = "countergraph.study-memory-impact/v0.1"
_MAX_DEPTH = 64


class StudyImpactIntegrityError(ValueError):
    pass


def _walk(value: Any, path: str, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        raise StudyImpactIntegrityError(f"{path}: canonicalization depth exceeded")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StudyImpactIntegrityError(f"{path}: non-finite float")
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [_walk(item, f"{path}[{index}]", depth + 1) for index, item in enumerate(value)]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise StudyImpactIntegrityError(f"{path}: non-string object key")
        return {
            key: _walk(value[key], f"{path}.{key}", depth + 1)
            for key in sorted(value)
        }
    raise StudyImpactIntegrityError(f"{path}: unsupported type {type(value).__name__}")


def canonical_serialize(value: Any) -> bytes:
    normalized = _walk(value, "$", 0)
    return json.dumps(
        normalized,
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def recompute_memory_impact_digest(impact: Mapping[str, Any]) -> str:
    if not isinstance(impact, Mapping):
        raise StudyImpactIntegrityError("impact must be an object")
    if impact.get("schema") != MEMORY_IMPACT_SCHEMA:
        raise StudyImpactIntegrityError("impact schema mismatch")
    if impact.get("authority_effect") != "none":
        raise StudyImpactIntegrityError("impact authority_effect must be none")
    if "impact_digest" not in impact:
        raise StudyImpactIntegrityError("impact_digest missing")
    body = dict(impact)
    body["impact_digest"] = DIGEST_SENTINEL
    return "sha256:" + hashlib.sha256(canonical_serialize(body)).hexdigest()


def verify_memory_impact_digest(impact: Mapping[str, Any]) -> bool:
    declared = impact.get("impact_digest") if isinstance(impact, Mapping) else None
    return isinstance(declared, str) and declared == recompute_memory_impact_digest(impact)


__all__ = [
    "CANONICAL_PROFILE",
    "DIGEST_SENTINEL",
    "MEMORY_IMPACT_SCHEMA",
    "StudyImpactIntegrityError",
    "canonical_serialize",
    "recompute_memory_impact_digest",
    "verify_memory_impact_digest",
]
