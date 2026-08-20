"""Universal receipt verification entry points.

These three typed entry points route raw receipt bytes to the appropriate
internal verifier and always return the SRS ``VerificationReport`` shape:
8 separate Booleans + ``chain_status``.

    verify_claim_receipt(receipt: bytes)  -> VerificationReport
    verify_memory_receipt(receipt: bytes) -> VerificationReport
    verify_action_receipt(receipt: bytes) -> VerificationReport

Receipt classification
----------------------
Each function accepts the raw serialized bytes of one SRS receipt envelope.
The profile is auto-detected from the ``profile_id`` / ``profile_version``
fields embedded in the receipt; callers do not need to pass a separate profile
selector.

Authority boundary
------------------
These wrappers perform NO additional policy evaluation beyond what the profile
verifier already enforces.  They do not decide truth, admission, or standing.
``not_evaluated`` is never collapsed into pass or fail.

Producer/verifier independence
-------------------------------
These functions import only from ``arcs_verify`` itself — never from any dagr,
producer, or host-adapter package.  The producer/verifier firewall enforced by
``tools/check_public_release.py`` applies here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .verifier import (
    ACTIVITY_GOVERNED_READ_PROFILE,
    BROADCAST_CONTROL_PROFILE,
    CONNECTION_PROFILE,
    DEFERRED_OPERATION_PROFILE,
    EDITORIAL_CITATION_PACK_PROFILE,
    EDITORIAL_PUBLICATION_INGEST_PROFILE,
    EDITORIAL_SOURCE_CAPTURE_PROFILE,
    EDITORIAL_SOURCE_CAPTURE_PROFILE_V011,
    EDITORIAL_SOURCE_CAPTURE_PROFILE_V02,
    EDITORIAL_SOURCE_INGEST_PROFILE,
    MCP_PROFILE,
    VerificationReport,
    verify_receipt,
)
from .schema import ACCEPTED_SCHEMA_SHA256

# ---------------------------------------------------------------------------
# Profile classification sets
# ---------------------------------------------------------------------------

#: Profiles associated with claim / editorial receipts (Counterpedia surface).
CLAIM_PROFILES: frozenset[str] = frozenset({
    EDITORIAL_PUBLICATION_INGEST_PROFILE,
    EDITORIAL_SOURCE_CAPTURE_PROFILE,
    EDITORIAL_SOURCE_CAPTURE_PROFILE_V011,
    EDITORIAL_SOURCE_CAPTURE_PROFILE_V02,
    EDITORIAL_SOURCE_INGEST_PROFILE,
    EDITORIAL_CITATION_PACK_PROFILE,
})

#: Profiles associated with governed-action receipts (Countervail / MCP surface).
ACTION_PROFILES: frozenset[str] = frozenset({
    MCP_PROFILE,
    CONNECTION_PROFILE,
    BROADCAST_CONTROL_PROFILE,
    DEFERRED_OPERATION_PROFILE,
    ACTIVITY_GOVERNED_READ_PROFILE,
})

#: Profile IDs associated with memory receipts (Amnesiac surface).
#: These are SRS envelopes whose ``profile_id`` prefix is ``srs.memory``.
#: The first concrete profile is declared here as a stub; it will be
#: populated when arcs-srs ratifies the memory-receipt profile.
MEMORY_PROFILE_ID_PREFIX = "srs.memory"

# Path to the bundled SRS envelope schema (runtime copy shipped as package
# data, byte-verified against ACCEPTED_SCHEMA_SHA256 by verify_receipt).
# v0.2.1 is the current accepted schema; verify_receipt accepts both v0.2.0
# and v0.2.1 pins (ACCEPTED_SCHEMA_SHA256 contains both digests).
_SCHEMA_PATH = Path(__file__).resolve().parent / "data" / "srs-envelope-v0.2.1.schema.json"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _decode_receipt(receipt: bytes) -> dict[str, Any]:
    """Decode raw receipt bytes to a dict.

    Raises ``ValueError`` on decode failure so callers can surface
    ``parse_error`` in a failure report without catching bare exceptions.
    """
    try:
        return json.loads(receipt)
    except Exception as exc:
        raise ValueError(f"receipt_decode_failed: {exc}") from exc


def _reject(code: str) -> VerificationReport:
    """Return a hard-fail VerificationReport with a single failure code."""
    report = VerificationReport()
    report.failure_codes.append(code)
    return report


def _detect_profile(receipt: dict[str, Any]) -> str | None:
    """Return the composite profile key (profile_id.profile_version) or None."""
    pid = receipt.get("profile_id")
    pver = receipt.get("profile_version")
    if not isinstance(pid, str) or not isinstance(pver, str):
        return None
    return f"{pid}.{pver}"


def _is_memory_profile(pid: str | None) -> bool:
    if not isinstance(pid, str):
        return False
    return pid.startswith(MEMORY_PROFILE_ID_PREFIX)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_claim_receipt(receipt: bytes) -> VerificationReport:
    """Verify one serialized SRS claim receipt (Counterpedia surface).

    Routes through the editorial / counterpedia-relevant profiles
    (``srs.editorial.*``).  A receipt whose ``profile_id`` belongs to a
    non-claim profile family is rejected with ``profile.wrong_domain``.

    Returns
    -------
    VerificationReport
        The standard 8-Boolean + ``chain_status`` report shape.  Never raises;
        parse or routing failures are reported as ``failure_codes`` entries.
    """
    try:
        parsed = _decode_receipt(receipt)
    except ValueError as exc:
        return _reject(str(exc))

    composite = _detect_profile(parsed)
    if composite is None:
        return _reject("profile.missing_or_non_string")

    # Route to the correct editorial profile constant.
    selected: str | None = None
    for candidate in CLAIM_PROFILES:
        if composite == candidate:
            selected = candidate
            break

    if selected is None:
        report = _reject("profile.wrong_domain")
        report.details.append(
            f"verify_claim_receipt received a non-claim profile: {composite!r}. "
            "Use verify_action_receipt for action profiles or "
            "verify_memory_receipt for memory profiles."
        )
        return report

    return verify_receipt(parsed, {}, schema_path=_SCHEMA_PATH, selected_profile=selected)


def verify_action_receipt(receipt: bytes) -> VerificationReport:
    """Verify one serialized SRS action receipt (Countervail / MCP surface).

    Routes through governed-action profiles (``srs.mcp.*``,
    ``srs.connection.*``, ``srs.broadcast_control.*``,
    ``srs.deferred_operation.*``, ``srs.activity.*``).  A receipt whose
    ``profile_id`` belongs to a non-action profile family is rejected with
    ``profile.wrong_domain``.

    Returns
    -------
    VerificationReport
        The standard 8-Boolean + ``chain_status`` report shape.
    """
    try:
        parsed = _decode_receipt(receipt)
    except ValueError as exc:
        return _reject(str(exc))

    composite = _detect_profile(parsed)
    if composite is None:
        return _reject("profile.missing_or_non_string")

    selected: str | None = None
    for candidate in ACTION_PROFILES:
        if composite == candidate:
            selected = candidate
            break

    if selected is None:
        report = _reject("profile.wrong_domain")
        report.details.append(
            f"verify_action_receipt received a non-action profile: {composite!r}. "
            "Use verify_claim_receipt for editorial profiles or "
            "verify_memory_receipt for memory profiles."
        )
        return report

    return verify_receipt(parsed, {}, schema_path=_SCHEMA_PATH, selected_profile=selected)


def verify_memory_receipt(receipt: bytes) -> VerificationReport:
    """Verify one serialized SRS memory receipt (Amnesiac surface).

    **Stub — memory profile not yet ratified by arcs-srs.**

    This function accepts any SRS receipt whose ``profile_id`` starts with
    ``srs.memory``.  The arcs-srs memory-receipt profile is not yet ratified;
    when it is, this stub will be replaced by a real routing call to
    ``verify_receipt`` with the ratified profile constant.

    Until then the function returns a ``VerificationReport`` with:
    - ``profile = False``
    - ``failure_codes = ["profile.memory_not_yet_ratified"]``
    - All other Booleans ``False``

    The ``not_evaluated`` discipline is preserved: no field is forced to
    ``True`` and ``authenticity_verified`` / ``signature_verified`` remain
    governed by the signature path, not asserted here.

    Returns
    -------
    VerificationReport
        The standard 8-Boolean + ``chain_status`` report shape.  Never raises.
    """
    try:
        parsed = _decode_receipt(receipt)
    except ValueError as exc:
        return _reject(str(exc))

    pid = parsed.get("profile_id")

    # If the caller passes a non-memory profile, route them to the right function.
    if not _is_memory_profile(pid):
        composite = _detect_profile(parsed)
        report = _reject("profile.wrong_domain")
        report.details.append(
            f"verify_memory_receipt received a non-memory profile: {composite!r}. "
            "Use verify_claim_receipt for editorial profiles or "
            "verify_action_receipt for action profiles."
        )
        return report

    # Memory profile is not yet ratified — stub response.
    report = VerificationReport()
    report.profile = False
    report.failure_codes.append("profile.memory_not_yet_ratified")
    report.details.append(
        "The srs.memory profile family is not yet ratified by arcs-srs. "
        "This stub will be replaced with a real routing call once the "
        "profile is published and pinned."
    )
    return report


__all__ = [
    "verify_claim_receipt",
    "verify_action_receipt",
    "verify_memory_receipt",
    "CLAIM_PROFILES",
    "ACTION_PROFILES",
    "MEMORY_PROFILE_ID_PREFIX",
]
