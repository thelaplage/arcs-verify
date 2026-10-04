"""DAGR Constitutional Contract — Non-Equivalence (NEQ) Assertions.

This module documents the 11 NEQ assertions ratified in DAGR-MIGRATION-WAVE-0
Lane 00 (L00), which defines the DAGR constitutional contract including the
state graph, transition vocabulary, and mandatory receipt fields.

The verifier MUST NOT conflate these pairs. Each constant names one side of an
NEQ pair so tests can assert distinctness and import sites can reference the
canonical authority string rather than embedding bare string literals.

Authority: garp-doctrine DAGR constitutional contract (L00), ratified 2026-08-20.
This module is documentation and assertion targets only. It contains no
runtime enforcement logic and imports no producer code.

Issuer/verifier separation is inviolate: arcs-verify never imports from
dagr-mcp, dagr-ingest, or any other producer.
"""

# ---------------------------------------------------------------------------
# NEQ-01: not_evaluated is not false
# A field whose verdict is "not_evaluated" has not been assessed. It is not a
# negative finding. Collapsing not_evaluated into false is a category error.
# ---------------------------------------------------------------------------
NOT_EVALUATED = "not_evaluated"
NEQ_01_NOT_EVALUATED_IS_NOT_FALSE_A = NOT_EVALUATED
NEQ_01_NOT_EVALUATED_IS_NOT_FALSE_B = "false"

# ---------------------------------------------------------------------------
# NEQ-02: not_evaluated is not pass
# A field whose verdict is "not_evaluated" has not been assessed. It is not a
# positive finding. Collapsing not_evaluated into pass is a category error and
# the most dangerous direction of conflation.
# ---------------------------------------------------------------------------
NEQ_02_NOT_EVALUATED_IS_NOT_PASS_A = NOT_EVALUATED
NEQ_02_NOT_EVALUATED_IS_NOT_PASS_B = "pass"

# ---------------------------------------------------------------------------
# NEQ-03: emitter_assertion is not independently_recomputed_finding
# A claim recorded by the emitter in a receipt field is an assertion by the
# issuer. It is not a finding independently recomputed by arcs-verify from
# serialized bytes. The verifier trusts no issuer claim.
# ---------------------------------------------------------------------------
EMITTER_ASSERTION = "emitter_assertion"
INDEPENDENTLY_RECOMPUTED_FINDING = "independently_recomputed_finding"
NEQ_03_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_A = EMITTER_ASSERTION
NEQ_03_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_B = INDEPENDENTLY_RECOMPUTED_FINDING

# ---------------------------------------------------------------------------
# NEQ-04: disclosure is not verdict
# Reporting or surfacing a finding (disclosure) is not the same as issuing a
# pass/fail verdict. A verifier that discloses without adjudicating is not a
# verifier in the DAGR sense.
# ---------------------------------------------------------------------------
DISCLOSURE = "disclosure"
VERDICT = "verdict"
NEQ_04_DISCLOSURE_IS_NOT_VERDICT_A = DISCLOSURE
NEQ_04_DISCLOSURE_IS_NOT_VERDICT_B = VERDICT

# ---------------------------------------------------------------------------
# NEQ-05: not_applicable is not pass
# A check that does not apply to a given receipt has not been passed. The
# absence of applicability is not evidence of conformance.
# ---------------------------------------------------------------------------
NOT_APPLICABLE = "not_applicable"
NEQ_05_NOT_APPLICABLE_IS_NOT_PASS_A = NOT_APPLICABLE
NEQ_05_NOT_APPLICABLE_IS_NOT_PASS_B = "pass"

# ---------------------------------------------------------------------------
# NEQ-06: envelope_valid is not profile_pass
# A receipt that satisfies the SRS envelope schema (structural envelope
# validity) has not necessarily passed any profile-specific verification.
# Profile conformance is a separate, additional gate.
# ---------------------------------------------------------------------------
ENVELOPE_VALID = "envelope_valid"
PROFILE_PASS = "profile_pass"
NEQ_06_ENVELOPE_VALID_IS_NOT_PROFILE_PASS_A = ENVELOPE_VALID
NEQ_06_ENVELOPE_VALID_IS_NOT_PROFILE_PASS_B = PROFILE_PASS

# ---------------------------------------------------------------------------
# NEQ-07: registration is not ratification
# A receipt, profile, or schema that is registered in a registry has not
# necessarily been ratified as an authority. Registration is an administrative
# act; ratification is a governance act.
# ---------------------------------------------------------------------------
REGISTRATION = "registration"
RATIFICATION = "ratification"
NEQ_07_REGISTRATION_IS_NOT_RATIFICATION_A = REGISTRATION
NEQ_07_REGISTRATION_IS_NOT_RATIFICATION_B = RATIFICATION

# ---------------------------------------------------------------------------
# NEQ-08: historical_colocation is not current_authority
# The fact that two artifacts or definitions resided in the same repository at
# some point in history does not establish that one is the current authority
# for the other. Authority is explicit and delegated, not inferred from
# co-location.
# ---------------------------------------------------------------------------
HISTORICAL_COLOCATION = "historical_colocation"
CURRENT_AUTHORITY = "current_authority"
NEQ_08_HISTORICAL_COLOCATION_IS_NOT_AUTHORITY_A = HISTORICAL_COLOCATION
NEQ_08_HISTORICAL_COLOCATION_IS_NOT_AUTHORITY_B = CURRENT_AUTHORITY

# ---------------------------------------------------------------------------
# NEQ-09: action domain token is not memory domain token
# Vocabulary terms are domain-qualified under the L01 enum-freeze doctrine.
# An "ADMITTED" verdict in the action: domain is a distinct token from
# "ADMITTED" in the memory: domain. Cross-domain conflation is a vocabulary
# error regardless of token spelling equality.
# ---------------------------------------------------------------------------
ACTION_DOMAIN_PREFIX = "action:"
MEMORY_DOMAIN_PREFIX = "memory:"
NEQ_09_ACTION_DOMAIN_IS_NOT_MEMORY_DOMAIN_A = ACTION_DOMAIN_PREFIX
NEQ_09_ACTION_DOMAIN_IS_NOT_MEMORY_DOMAIN_B = MEMORY_DOMAIN_PREFIX

# ---------------------------------------------------------------------------
# NEQ-10: action domain token is not evidence domain token
# Vocabulary terms in the action: domain and the evidence: domain are distinct
# even when their unqualified spelling coincides.
# ---------------------------------------------------------------------------
EVIDENCE_DOMAIN_PREFIX = "evidence:"
NEQ_10_ACTION_DOMAIN_IS_NOT_EVIDENCE_DOMAIN_A = ACTION_DOMAIN_PREFIX
NEQ_10_ACTION_DOMAIN_IS_NOT_EVIDENCE_DOMAIN_B = EVIDENCE_DOMAIN_PREFIX

# ---------------------------------------------------------------------------
# NEQ-11: signed_receipt is not verified_receipt
# A receipt that carries a cryptographic signature has not been independently
# verified. Signing establishes issuer identity (when the key is trusted) and
# integrity; it does not establish that the receipt satisfies a profile
# contract or that the signing key is trusted by an independent verifier.
# ---------------------------------------------------------------------------
SIGNED_RECEIPT = "signed_receipt"
VERIFIED_RECEIPT = "verified_receipt"
NEQ_11_SIGNED_RECEIPT_IS_NOT_VERIFIED_A = SIGNED_RECEIPT
NEQ_11_SIGNED_RECEIPT_IS_NOT_VERIFIED_B = VERIFIED_RECEIPT

# ---------------------------------------------------------------------------
# Convenience collection: all 11 NEQ pair names for iteration in tests.
# Each entry is (label, left_value, right_value). Both values are non-empty
# distinct strings by construction.
# ---------------------------------------------------------------------------
ALL_NEQ_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("NEQ-01", NEQ_01_NOT_EVALUATED_IS_NOT_FALSE_A, NEQ_01_NOT_EVALUATED_IS_NOT_FALSE_B),
    ("NEQ-02", NEQ_02_NOT_EVALUATED_IS_NOT_PASS_A, NEQ_02_NOT_EVALUATED_IS_NOT_PASS_B),
    ("NEQ-03", NEQ_03_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_A, NEQ_03_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_B),
    ("NEQ-04", NEQ_04_DISCLOSURE_IS_NOT_VERDICT_A, NEQ_04_DISCLOSURE_IS_NOT_VERDICT_B),
    ("NEQ-05", NEQ_05_NOT_APPLICABLE_IS_NOT_PASS_A, NEQ_05_NOT_APPLICABLE_IS_NOT_PASS_B),
    ("NEQ-06", NEQ_06_ENVELOPE_VALID_IS_NOT_PROFILE_PASS_A, NEQ_06_ENVELOPE_VALID_IS_NOT_PROFILE_PASS_B),
    ("NEQ-07", NEQ_07_REGISTRATION_IS_NOT_RATIFICATION_A, NEQ_07_REGISTRATION_IS_NOT_RATIFICATION_B),
    ("NEQ-08", NEQ_08_HISTORICAL_COLOCATION_IS_NOT_AUTHORITY_A, NEQ_08_HISTORICAL_COLOCATION_IS_NOT_AUTHORITY_B),
    ("NEQ-09", NEQ_09_ACTION_DOMAIN_IS_NOT_MEMORY_DOMAIN_A, NEQ_09_ACTION_DOMAIN_IS_NOT_MEMORY_DOMAIN_B),
    ("NEQ-10", NEQ_10_ACTION_DOMAIN_IS_NOT_EVIDENCE_DOMAIN_A, NEQ_10_ACTION_DOMAIN_IS_NOT_EVIDENCE_DOMAIN_B),
    ("NEQ-11", NEQ_11_SIGNED_RECEIPT_IS_NOT_VERIFIED_A, NEQ_11_SIGNED_RECEIPT_IS_NOT_VERIFIED_B),
)
