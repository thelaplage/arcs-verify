# EXIT-O Origin-Authentication Verification Report Contract v0.1

Report contract `arcs.verify.exit-o-origin-authentication-report/v0.1`, emitted by
`arcs_verify/exit_o_origin_authentication.py` (ARCS-VERIFY-EXIT-O0).

This is a **new, independent** report contract. It does **not** extend, reuse, or
touch `arcs_verify.verifier.VerificationReport` or its `chain_status` field —
`chain_status` already means `not_applicable` for the standalone-SRS path and
participates in that path's pass semantics, and must not move.

## What it verifies

The `srs.activity.semantic_issuer_origin_authentication.v0.1` proof artifact
(arcs-srs, pinned below), recomputed from the receipt bytes and the pinned profile
authority alone. No producer code is imported; no producer posture is accepted as
a finding.

## Pins

| Pin | Value |
|---|---|
| profile | `srs.activity.semantic_issuer_origin_authentication.v0.1` |
| source head (arcs-srs) | `11db54bbb3143c13b0db148efece68b5a2f3766b` |
| schema git-blob-sha1 | `236643eb4cc229d38266c6e7a5bcfa8291b0aec7` |
| schema raw sha256 | `c03733f92e5bb05f4087c8fcc944528f013bf3043940478f6ea7a087da0c5531` |
| profile document sha256 | `85dd6a9b3ae0fb084a6a932f880adb5bbbce3c5924a78954548281e597ad82ea` |

## Findings

**Structural (boolean, recomputed):** `profile_schema_pinned`,
`proof_receipt_conformance`, `exact_semantic_disposition_binding`.

**Substantive (`pass` / `fail` / `not_evaluated` / `unavailable`):**
`proof_receipt_signature`, `key_authentication_finding`, `act_principal_finding`,
`semantic_authority_finding`, `semantic_act_finding`,
`historical_scope_authorization_finding`, `temporal_consistency_finding`.

The controlling rule: **`artifact bytes present != digest matches != semantic
layer verified`.** A layer whose evidence bytes are absent is `unavailable`; a
layer whose evidence digest matches (integrity) but for which no governed
verifier contract exists is `not_evaluated`. Neither is a pass, and a producer
posture is never promoted to a finding.

## Fail-closed aggregation

`exit_o_chain_satisfied` is `true` only when **every** required substantive finding
is `pass`. `fail` / `not_evaluated` / `unavailable` fail closed. In the current
estate — no governed upstream evidence verifiers, no provisioned signing key — a
well-formed, correctly-bound, honestly-partial proof therefore yields
`exit_o_chain_satisfied = false`. See `golden/partial-honest-report.json`: the
literal producer proof binds and is temporally consistent, yet the chain is
correctly **not** satisfied. This verifier refuses correctly before a real
producer or signing key exists.
