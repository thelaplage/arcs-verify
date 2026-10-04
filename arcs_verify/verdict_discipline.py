"""DAGR Constitutional Contract — Verdict Discipline Constants.

This module makes the verdict discipline rules from the DAGR constitutional
contract (L00) importable by tests and downstream consumers. The constants
here are documentation targets and importable markers only — they carry no
runtime enforcement logic.

The discipline rules documented here correspond to NEQ-02, NEQ-03, NEQ-04,
and NEQ-05 from arcs_verify.neq, applied specifically to the verification
verdict surface.

Authority: garp-doctrine DAGR constitutional contract (L00) and DAGR
MIGRATION WAVE 0 Lane 03 (L03), ratified 2026-08-20.

Issuer/verifier separation is inviolate: this module imports no producer code.
"""

# ---------------------------------------------------------------------------
# Verdict tokens — canonical string values used in VerificationReport fields.
# Never use bare string literals in tests: import from here so the string is
# single-sourced and any rename is caught at import time.
# ---------------------------------------------------------------------------

VERDICT_NOT_EVALUATED: str = "not_evaluated"
"""A check that was not run. NOT equivalent to pass, fail, or not_applicable.

Per NEQ-02: not_evaluated != pass.
Per NEQ-01: not_evaluated != false (i.e. not a negative finding).

The 'authenticity_verified' and 'signature_verified' conclusions in
arcs-verify are hard-coded to 'not_evaluated' by design (reserved, not yet
implemented); they are NOT passes.
"""

VERDICT_NOT_APPLICABLE: str = "not_applicable"
"""A check that does not apply to this receipt type or profile.

Per NEQ-05: not_applicable != pass.

Example: chain_status is 'not_applicable' for a single-receipt verification
where no chain is presented. This is not evidence of chain conformance.
"""

VERDICT_PASS: str = "pass"
"""A check that was run and satisfied the contract.

A pass is only meaningful if the check was actually run against the artifact's
bytes using the pinned profile authority. An emitter assertion is not a pass.
"""

VERDICT_FAIL: str = "fail"
"""A check that was run and found a violation of the contract.

Failure codes (failure_codes) carry the specific named finding.
"""

# ---------------------------------------------------------------------------
# Discipline rules — importable assertion targets for tests.
# Each is a plain string describing the invariant; tests assert inequality of
# the pair they guard.
# ---------------------------------------------------------------------------

RULE_NOT_EVALUATED_IS_NOT_PASS: str = (
    "not_evaluated != pass — a verdict of not_evaluated means the check was "
    "not run; it is not a positive finding and must never be treated as pass."
)
"""NEQ-02: not_evaluated is not pass."""

RULE_NOT_EVALUATED_IS_NOT_FAIL: str = (
    "not_evaluated != fail — a verdict of not_evaluated means the check was "
    "not run; it is not a negative finding and must never be treated as fail."
)
"""NEQ-01 (fail direction): not_evaluated is not a negative finding."""

RULE_NOT_APPLICABLE_IS_NOT_PASS: str = (
    "not_applicable != pass — a check that does not apply to this receipt "
    "has not been passed; absence of applicability is not conformance."
)
"""NEQ-05: not_applicable is not pass."""

RULE_ENVELOPE_VALID_IS_NOT_PROFILE_PASS: str = (
    "envelope_valid != profile_pass — satisfying the SRS envelope schema is "
    "a necessary but not sufficient condition for profile conformance; a "
    "receipt may be envelope-valid and profile-failing simultaneously."
)
"""NEQ-06: envelope_valid is not profile_pass."""

RULE_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_FINDING: str = (
    "emitter_assertion != independently_recomputed_finding — a value recorded "
    "by the emitter in a receipt field is an issuer claim, not a finding "
    "derived by arcs-verify from serialized bytes under the pinned profile "
    "authority. The verifier trusts no issuer claim."
)
"""NEQ-03: emitter_assertion is not independently_recomputed_finding."""

RULE_DISCLOSURE_IS_NOT_VERDICT: str = (
    "disclosure != verdict — reporting or surfacing a finding is not the same "
    "as issuing a pass/fail verdict; a verifier that discloses without "
    "adjudicating is not a verifier in the DAGR sense."
)
"""NEQ-04: disclosure is not verdict."""

RULE_SIGNED_IS_NOT_VERIFIED: str = (
    "signed_receipt != verified_receipt — a cryptographic signature establishes "
    "issuer identity (when the key is trusted) and integrity; it does not "
    "establish profile conformance or independent key trust. A signed receipt "
    "has not been independently verified."
)
"""NEQ-11: signed_receipt is not verified_receipt."""

# ---------------------------------------------------------------------------
# All rules as a mapping for iteration in tests.
# ---------------------------------------------------------------------------
ALL_DISCIPLINE_RULES: dict[str, str] = {
    "NEQ-01-fail": RULE_NOT_EVALUATED_IS_NOT_FAIL,
    "NEQ-02": RULE_NOT_EVALUATED_IS_NOT_PASS,
    "NEQ-03": RULE_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_FINDING,
    "NEQ-04": RULE_DISCLOSURE_IS_NOT_VERDICT,
    "NEQ-05": RULE_NOT_APPLICABLE_IS_NOT_PASS,
    "NEQ-06": RULE_ENVELOPE_VALID_IS_NOT_PROFILE_PASS,
    "NEQ-11": RULE_SIGNED_IS_NOT_VERIFIED,
}
