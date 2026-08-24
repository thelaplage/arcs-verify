"""
arcs_verify/market_audit_packet.py — MARKET-AUDIT-PACKET0: portable native-ref
audit packet for independent market-transaction replay.

INDEPENDENCE CONTRACT
  This module imports NOTHING from any market/commerce producer, DAGR
  runtime, or other issuer implementation. It assembles and digest-binds
  native artifact references only, and recomputes packet-level digests
  from bytes the caller supplies. It confers no authority, truth, or
  admission verdict.

WHAT THIS MODULE IS
  A market audit packet is a portable, immutable bundle of native artifact
  references (content-addressed "sha256:<hex>" refs) spanning the lifecycle
  categories of one governed market transaction: offer, discovery,
  selection, quote, quote_acceptance, authorization, execution, receipt,
  witness, verification, sla, settlement, history. It exists so an
  independent party can later replay/recompute against the referenced
  bytes without trusting the assembler's claims.

WHAT THIS MODULE IS NOT
  - Not a verifier of the referenced artifacts' contents. It records refs
    and digests, not payloads, and never fetches or validates the bytes a
    ref points to.
  - Not a signer, issuer, or authority. `authority_effect`, `truth_effect`,
    and `admission_effect` are hard-pinned to "none" and cannot be
    promoted; construction raises ValueError if any is set otherwise.
  - `audit_completeness` reports which categories are present as native
    refs. Completeness is a structural finding: assembling a packet !=
    verifying it, and a passing packet-digest recomputation is not proof
    that any real-world event occurred.

NON-EQUIVALENCES (always included in findings)
  "audit_complete != authorized"
  "audit_complete != admitted"
  "packet_digest_valid != real-world transaction occurred"
  "native_ref_present != referenced content verified"
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

# ── contract constants ────────────────────────────────────────────────────────

REQUIRED: tuple[str, ...] = (
    "offer",
    "discovery",
    "selection",
    "quote",
    "quote_acceptance",
    "authorization",
    "execution",
    "receipt",
    "witness",
    "verification",
    "sla",
    "settlement",
    "history",
)

_SHA256_PREFIX = "sha256:"
_SHA256_TOTAL_LEN = 71  # len("sha256:") + 64

# These non-equivalences are always present regardless of packet outcomes.
_PERMANENT_NON_EQUIVALENCES: tuple[str, ...] = (
    "audit_complete != authorized",
    "audit_complete != admitted",
    "packet_digest_valid != real-world transaction occurred",
    "native_ref_present != referenced content verified",
)


# ── native-ref format ──────────────────────────────────────────────────────────

def is_native_ref(value: Any) -> bool:
    """True iff `value` is a well-formed content-addressed native ref:
    "sha256:" followed by exactly 64 lowercase hex characters.

    An audit packet is "native-ref" precisely because its entries are
    content-addressed pointers, not opaque labels or inline payloads — this
    is the check that distinguishes the two.
    """
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


# ── canonicalization / digest recomputation ───────────────────────────────────

def recompute_packet_digest(body: dict[str, Any]) -> str:
    """Independently recompute a packet digest from a plain dict body (e.g.
    one loaded from serialized JSON bytes). This is the recomputation an
    independent third party performs; it requires no `MarketAuditPacket`
    instance and no producer code.

    Canonicalization profile: sort_keys, compact separators, UTF-8.
    """
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{sha256(canonical).hexdigest()}"


def verify_packet_digest(serialized: dict[str, Any]) -> dict[str, Any]:
    """Independently verify a serialized packet's self-declared
    `packet_digest` by recomputing over the remaining body bytes. Never
    raises on malformed input — malformed input is reported as a finding.

    `digest_valid` is `None` (not `False`) when the serialized packet
    carries no `packet_digest` field to check against: absence of a claim
    is not the same as a failed claim.
    """
    if not isinstance(serialized, dict):
        return {
            "digest_valid": False,
            "recomputed_digest": None,
            "declared_digest": None,
            "non_equivalences": _PERMANENT_NON_EQUIVALENCES,
        }
    declared = serialized.get("packet_digest")
    body = {key: value for key, value in serialized.items() if key != "packet_digest"}
    recomputed = recompute_packet_digest(body)
    digest_valid = None if declared is None else recomputed == declared
    return {
        "digest_valid": digest_valid,
        "recomputed_digest": recomputed,
        "declared_digest": declared,
        "non_equivalences": _PERMANENT_NON_EQUIVALENCES,
    }


# ── packet ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MarketAuditPacket:
    """A portable, immutable bundle of native artifact refs for one governed
    market transaction.

    Confers no authority, truth, or admission effect: those three fields
    are hard-pinned to "none". Construction rejects any attempt to promote
    them (`ValueError`) — the dataclass is frozen, so no later mutation can
    promote them either.
    """

    packet_id: str
    artifact_refs: dict[str, str]
    created_at: str
    authority_effect: str = "none"
    truth_effect: str = "none"
    admission_effect: str = "none"

    def __post_init__(self) -> None:
        if any(getattr(self, k) != "none" for k in ("authority_effect", "truth_effect", "admission_effect")):
            raise ValueError("audit packet cannot promote authority/truth/admission semantics")

    def body(self) -> dict[str, Any]:
        """The canonical, portable body used for digesting. Effect fields
        are always the hard "none" constants regardless of instance state
        (belt-and-suspenders; the constructor already forbids any other
        value)."""
        return {
            "packet_id": self.packet_id,
            "artifact_refs": dict(sorted(self.artifact_refs.items())),
            "created_at": self.created_at,
            "authority_effect": "none",
            "truth_effect": "none",
            "admission_effect": "none",
        }

    def digest(self) -> str:
        """Content-addressed digest of the packet body. Independently
        recomputable by any party holding the serialized body — see
        `recompute_packet_digest`."""
        return recompute_packet_digest(self.body())

    def to_dict(self) -> dict[str, Any]:
        """Portable serialized form, self-describing with its own digest so
        an independent recipient can recompute and compare without this
        class (see `verify_packet_digest`)."""
        out = self.body()
        out["packet_digest"] = self.digest()
        return out


def ref_format_findings(packet: MarketAuditPacket) -> dict[str, bool]:
    """Per-category native-ref format validity for every artifact ref the
    packet currently carries. Presence in `artifact_refs` does not by
    itself mean the value is a well-formed native reference — a packet
    intended for real independent replay should pass this check on every
    required category too (see `audit_completeness`'s `malformed_refs`)."""
    return {key: is_native_ref(value) for key, value in packet.artifact_refs.items()}


def audit_completeness(packet: MarketAuditPacket) -> dict[str, Any]:
    """Structural completeness of a market audit packet: which of the 13
    required lifecycle categories are present, and — separately — which
    present values are well-formed native refs.

    `complete` reflects category PRESENCE only. A packet can be `complete`
    while still carrying malformed refs (surfaced in `malformed_refs`);
    callers that require both presence and well-formedness should check
    `complete and not malformed_refs`.

    This is a structural finding, not an authority, truth, or admission
    verdict — those effects are permanently "none" (see module docstring).
    """
    missing = [key for key in REQUIRED if key not in packet.artifact_refs]
    malformed = sorted(
        key
        for key in REQUIRED
        if key in packet.artifact_refs and not is_native_ref(packet.artifact_refs[key])
    )
    return {
        "complete": not missing,
        "missing": missing,
        "malformed_refs": malformed,
        "packet_digest": packet.digest(),
        "authority_effect": "none",
        "truth_effect": "none",
        "admission_effect": "none",
        "non_equivalences": _PERMANENT_NON_EQUIVALENCES,
    }
