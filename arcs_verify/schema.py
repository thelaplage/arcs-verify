"""Stable schema-pin exports for downstream consumers.

Worktrees 02, 04, and 05 (and other downstream repos) import from this module
to get the frozen SRS envelope schema pins without reaching into verifier.py
internals.  These constants are byte-pinned: a downstream consumer that imports
ENVELOPE_SCHEMA_PINS and asserts the expected digest in its own test suite will
break loudly if the schema drifts, not silently.

Usage::

    from arcs_verify.schema import ENVELOPE_SCHEMA_PINS, CURRENT_SCHEMA_VERSION

Authority note: arcs-srs owns the SRS serialization spec; arcs-verify owns the
ACCEPTANCE of those bytes (which schemas are accepted, and at which pins).  The
pins here reflect the acceptance set at the time this module was frozen.
"""
from __future__ import annotations

# SRS envelope schema v0.2.0 pin — byte-identical to the original FROZEN_SCHEMA_SHA256.
# Verifies all historical v0.2.0-era receipts.
SCHEMA_PIN_V0_2_0 = (
    "d03aad1d5517e2acb65d5c866905aed7219bcbbfadd1a4a97eac546dd23f0333"
)

# SRS envelope schema v0.2.1 pin (additive: adds optional subject_ref_origin).
# Vendored from arcs-srs merge ccc4e4bb.
SCHEMA_PIN_V0_2_1 = (
    "2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"
)

# Ordered map: published_version -> sha256 hex (without "sha256:" prefix).
# Add new pins here when arcs-srs introduces a new schema version; never remove
# existing entries — doing so would break verification of all receipts signed
# under the removed schema.
ENVELOPE_SCHEMA_PINS: dict[str, str] = {
    "v0.2.0": SCHEMA_PIN_V0_2_0,
    "v0.2.1": SCHEMA_PIN_V0_2_1,
}

# The current recommended schema version for NEW receipt emission.
# Downstream producers should reference this constant rather than hard-coding
# a version string.
CURRENT_SCHEMA_VERSION = "v0.2.1"

# The set of all accepted sha256 hex values — useful for membership tests
# without iterating the dict.
ACCEPTED_SCHEMA_SHA256: frozenset[str] = frozenset(ENVELOPE_SCHEMA_PINS.values())

# Discriminator value expected in every SRS v5.1 envelope.
RECEIPT_VERSION = "srs.core.v5.1"

__all__ = [
    "SCHEMA_PIN_V0_2_0",
    "SCHEMA_PIN_V0_2_1",
    "ENVELOPE_SCHEMA_PINS",
    "CURRENT_SCHEMA_VERSION",
    "ACCEPTED_SCHEMA_SHA256",
    "RECEIPT_VERSION",
]
