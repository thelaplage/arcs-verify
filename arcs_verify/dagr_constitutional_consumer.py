"""arcs-verify constitutional alignment — DAGR-MIGRATION-WAVE-0 L11.

Declares arcs-verify's role as the independent verifier under the DAGR
Constitutional Contract v0.1. arcs-verify re-derives conformance from
artifact bytes alone; it never imports producer code.

verification != truth
valid_signature != trusted_issuer
profile_valid != runtime_authorized
verifier_reference != recomputed_finding

Exports:
  - DAGR_CONSTITUTIONAL_CONTRACT_ID / _STATUS
  - VERIFIER_ROLE, VERIFIER_DOMAIN
  - DOMAIN_NEQ_ASSERTIONS  (domain-qualified; constitutional form per L00 NEQ-09 pattern)
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Constitutional contract reference
# ---------------------------------------------------------------------------

DAGR_CONSTITUTIONAL_CONTRACT_ID = "dagr.constitutional-contract.v0.1"
DAGR_CONSTITUTIONAL_CONTRACT_STATUS = "DRAFT R1 (Lane 00 / DAGR-MIGRATION-WAVE-0)"

# ---------------------------------------------------------------------------
# Verifier role declaration
# ---------------------------------------------------------------------------

VERIFIER_ROLE = "independent_verifier"
VERIFIER_DOMAIN = "arcs_verify"

# ---------------------------------------------------------------------------
# Domain-qualified NEQ assertions (constitutional form, per L00 NEQ-09 pattern)
# ---------------------------------------------------------------------------

DOMAIN_NEQ_ASSERTIONS: tuple[str, ...] = (
    # Verification != truth — core invariant
    "arcs_verify:verification != arcs:truth",
    # Valid signature != trusted issuer
    "arcs_verify:valid_signature != arcs:trusted_issuer",
    # Profile-valid != runtime-authorized
    "arcs_verify:profile_valid != action:runtime_authorized",
    # not_evaluated is not false
    "arcs_verify:not_evaluated != arcs:false",
    # not_evaluated is not pass
    "arcs_verify:not_evaluated != arcs:pass",
    # not_applicable is not pass
    "arcs_verify:not_applicable != arcs:pass",
    # Emitter assertion != independently recomputed finding
    "arcs_verify:emitter_assertion != arcs_verify:independently_recomputed_finding",
    # Disclosure != verdict
    "arcs_verify:disclosure != arcs_verify:verdict",
    # Verifier reference in receipt != recomputed finding
    "arcs_verify:verifier_reference_in_receipt != arcs_verify:independently_recomputed_finding",
    # Independent verifier != producer/emitter
    "arcs_verify:independent_verifier != dagr:emitter",
    # Verification pass != action permitted
    "arcs_verify:verification_pass != action:permitted",
    # chain_status != individual finding
    "arcs_verify:chain_status != arcs_verify:individual_finding",
)
