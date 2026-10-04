"""Independent canonical hashing for candidate EBC artifacts.

NON-NORMATIVE / PROVISIONAL. This reimplements a candidate canonicalization
and domain-separation scheme -- ``sha256(ascii(domain_prefix) +
canonical_json(payload))`` -- for the still-unratified doctrine candidate
``dagr.candidates.epistemic-boundary-commitment.v0.1``. It imports no
producer code; digests are recomputed independently from supplied bytes and
compared against declared values.

The canonical-JSON step follows this repository's existing convention (see
``arcs_verify/amnesiac/canonical.py``): ``json.dumps(payload, sort_keys=True,
separators=(",", ":"), ensure_ascii=False)``. Sorting object keys makes the
scheme insensitive to the field order a fixture author happens to write on
disk -- this module's test suite proves that discipline holds rather than
assuming it.

Domain prefixes are provisional labels chosen for this prototype to keep each
artifact kind's hash space separate from the others (so a boundary digest can
never collide with, or be mistaken for, a horizon digest computed over
similar bytes). ``DAGR-BOUNDARY-V0.1:`` is the one prefix pinned by this
task's instructions; the remaining prefixes below extend the same naming
convention for the other EBC artifact kinds and are equally provisional --
nothing here ratifies them as a doctrine-level naming scheme.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

DOMAIN_PREFIX_HORIZON = "DAGR-HORIZON-V0.1:"
DOMAIN_PREFIX_CONTEXT = "DAGR-CONTEXT-V0.1:"
DOMAIN_PREFIX_OMISSION = "DAGR-OMISSION-V0.1:"
DOMAIN_PREFIX_DOCTRINE_MANIFEST = "DAGR-DOCTRINE-MANIFEST-V0.1:"
DOMAIN_PREFIX_BOUNDARY = "DAGR-BOUNDARY-V0.1:"
DOMAIN_PREFIX_COMMITMENT = "DAGR-COMMITMENT-V0.1:"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def is_well_formed_digest(value: Any) -> bool:
    """Structural check only: ``sha256:`` + 64 lowercase hex chars.

    This does not check that the digest was computed correctly, only that it
    is shaped like one of this scheme's digests at all.
    """
    return isinstance(value, str) and bool(_DIGEST_RE.match(value))


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def domain_hash(domain_prefix: str, payload: dict[str, Any]) -> str:
    """``sha256(ascii(domain_prefix) + canonical_json(payload))``, prefixed ``sha256:``."""
    preimage = domain_prefix.encode("ascii") + canonical_json(payload).encode("utf-8")
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def horizon_hash(horizon: dict[str, Any]) -> str:
    payload = {k: v for k, v in horizon.items() if k != "digest"}
    return domain_hash(DOMAIN_PREFIX_HORIZON, payload)


def context_hash(context: dict[str, Any]) -> str:
    payload = {k: v for k, v in context.items() if k != "digest"}
    return domain_hash(DOMAIN_PREFIX_CONTEXT, payload)


def omission_hash(omission: dict[str, Any]) -> str:
    payload = {k: v for k, v in omission.items() if k != "digest"}
    return domain_hash(DOMAIN_PREFIX_OMISSION, payload)


def doctrine_manifest_hash(manifest: dict[str, Any]) -> str:
    payload = {k: v for k, v in manifest.items() if k != "digest"}
    return domain_hash(DOMAIN_PREFIX_DOCTRINE_MANIFEST, payload)


def boundary_hash(boundary: dict[str, Any]) -> str:
    payload = {k: v for k, v in boundary.items() if k != "digest"}
    return domain_hash(DOMAIN_PREFIX_BOUNDARY, payload)


def commitment_hash(commitment: dict[str, Any]) -> str:
    payload = {k: v for k, v in commitment.items() if k != "digest"}
    return domain_hash(DOMAIN_PREFIX_COMMITMENT, payload)
