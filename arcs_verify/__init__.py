"""ARCS/SRS receipt verification."""

from .verifier import VerificationReport, verify_receipt
from .universal import (
    verify_action_receipt,
    verify_claim_receipt,
    verify_memory_receipt,
)
from .schema import (
    ACCEPTED_SCHEMA_SHA256,
    CURRENT_SCHEMA_VERSION,
    ENVELOPE_SCHEMA_PINS,
    RECEIPT_VERSION,
    SCHEMA_PIN_V0_2_0,
    SCHEMA_PIN_V0_2_1,
)
from .cg_execution_replay import (
    CGExecutionReplayReport,
    verify_cg_execution_packet,
)

__all__ = [
    # Core verifier
    "VerificationReport",
    "verify_receipt",
    # Universal typed entry points
    "verify_action_receipt",
    "verify_claim_receipt",
    "verify_memory_receipt",
    # Schema pins (stable import path for downstream consumers)
    "ACCEPTED_SCHEMA_SHA256",
    "CURRENT_SCHEMA_VERSION",
    "ENVELOPE_SCHEMA_PINS",
    "RECEIPT_VERSION",
    "SCHEMA_PIN_V0_2_0",
    "SCHEMA_PIN_V0_2_1",
    # CG-REPLAY0 (EXECUTION-BINDING0 Lane 4)
    "CGExecutionReplayReport",
    "verify_cg_execution_packet",
]
__version__ = "0.1.1"
