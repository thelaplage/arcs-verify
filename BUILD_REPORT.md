# BUILD REPORT — W2-04

Lane: W2-04
Repository: arcs-verify
Branch: feat/deferred-sequence-verification-v0-1
Base commit: f26df3fe38b6c41d0045e6c73fdc46a85a854423
Head SHA: [not yet committed — stop before commit per lane discipline]
Base tree: 95a37220119d5b2d7122ecd28f8210d9245992a7

Dependency gate: W2-02 (arcs-srs — deferred-operation sequence schema/fixtures)
Status: SATISFIED (arcs-srs W2-02 PR open at thelaplage/arcs-srs#30;
fixtures consumed from worktree at ../arcs-srs__w2-02/conformance/profiles/srs.deferred_operation.v0.1/)

---

## Pre-flight state

Repository was clean except for two untracked lane files (LANE_COORDINATES_W2-04.txt,
LANE_PROMPT_W2-04.md). No modified tracked files. No destructive operations performed.

Baseline test run:
```
python3 -m pytest tests/ -x --tb=short -q
513 passed, 1 skipped in 1.18s
```

Producer package absence confirmed:
```
python3 -c "import dagr_mcp"  → ModuleNotFoundError
python3 -c "import arcs_srs"  → ModuleNotFoundError
```

---

## Changed paths

Modified tracked files:
- `arcs_verify/verifier.py` — added DEFERRED_OPERATION_PROFILE constant,
  PROFILE_IDENTITIES entry, DEFERRED_OPERATION_BASE_LIMIT, receipt kind/outcome/
  exclusion frozensets, and _deferred_operation_profile_errors() function,
  dispatched from _profile_errors().
- `arcs_verify/cli.py` — added "deferred-sequence" subcommand dispatch to
  deferred_sequence.main().

New untracked files:
- `arcs_verify/deferred_sequence.py` — sequence-level independent verifier module
  with DeferredSequenceReport, verify_deferred_sequence(), CLI main().
- `tests/test_deferred_operation_profile.py` — 20 single-receipt profile
  conformance tests.
- `tests/test_deferred_sequence_verifier.py` — 31 sequence-level tests including
  mutation corpus and non-equivalence gates.
- `tests/fixtures/deferred_sequence/` — fixture directory:
  - issuer-keys.json (test trust bundle with real Ed25519 key)
  - defer-signed.json (signed defer_request)
  - condition-response-signed.json (signed condition_response, approved)
  - terminal-admitted-signed.json (signed terminal_admission, admitted)
  - execution-outcome-signed.json (signed execution_outcome)
  - valid-full-sequence.json (array: all four above in order)
  - valid-refused-sequence.json (defer → condition(rejected) → terminal(refused))
  - mutation-wrong-sequence-id.json
  - mutation-wrong-predecessor-ref.json
  - mutation-wrong-defer-receipt-ref.json
  - mutation-wrong-condition-receipt-ref.json
  - mutation-duplicate-receipt-id.json
  - mutation-missing-operation-digest.json
  - mutation-terminal-deferred-disposition.json
  - mutation-outcome-after-refused.json
  - mutation-expired-followed-by-reevaluation.json

---

## Commands and results

### Fixture generation (signed, with real Ed25519 key)

```
python3 -c "..."  # key generation + receipt signing
# All signed fixtures written with valid 64-char sha256 digests
```

Verified: `issuer-keys.json` contains a real Ed25519 public key. Signed fixtures
verified end-to-end (signature_valid=True, issuer_key_trusted=True) in tests.

### Full validation suite

```
python3 -m pytest tests/ -x --tb=short -q
564 passed, 1 skipped in 1.26s
```

New tests only:
```
python3 -m pytest tests/test_deferred_operation_profile.py tests/test_deferred_sequence_verifier.py -v
51 passed in 0.46s
```

### Public release check

```
python3 tools/check_public_release.py .
PASS: 0 finding(s)
```

### Ecosystem declarations

```
python3 -m pytest tests/test_ecosystem_declarations.py -v
14 passed, 1 skipped
```

---

## Acceptance gate results

| Gate | Result |
|------|--------|
| Producer packages absent from verifier environment | PASS (dagr_mcp, arcs_srs: ModuleNotFoundError) |
| Every mutation rejected or yields correct finding | PASS (9 mutation fixtures, 9/9 tests pass) |
| No one master verification status replaces findings | PASS (test_no_master_status_replaces_conclusions) |
| NOT_EVALUATED preserved | PASS (test_not_evaluated_is_not_promoted_to_pass) |
| Existing verifier profiles unchanged | PASS (513 pre-existing tests pass, regression: 0) |

---

## Findings produced by verify_deferred_sequence()

The sequence verifier produces 14 named conclusions (no single master status):

| Conclusion | What it independently recomputes |
|---|---|
| event_presence | At least one defer_request is present |
| sequence_id_continuity | All receipts share the same sequence_id |
| predecessor_linkage | Each non-defer_request receipt's predecessor_receipt_ref matches preceding receipt_id |
| defer_receipt_linkage | terminal_admission/execution_outcome defer_receipt_ref matches the defer_request receipt_id |
| condition_receipt_linkage | reevaluation/terminal_admission condition_receipt_ref resolves to the condition_response |
| operation_digest_continuity | All operation_digest-bearing receipts carry a non-empty sha256: digest |
| response_expiry_honoured | An expired condition_response is not followed by a reevaluation |
| terminal_state_present | At least one terminal_admission is present |
| terminal_disposition_valid | terminal_admission disposition is admitted or refused (not deferred_for_review) |
| refused_has_no_execution_outcome | A refused terminal_admission has no linked execution_outcome |
| outcome_links_admitted_terminal | execution_outcome terminal_admission_ref resolves to an admitted terminal |
| replay_clean | No receipt_id appears more than once |
| individual_receipts_valid | Each receipt passes srs.deferred_operation.v0.1 profile conformance |
| receipt_gap_disclosed (informational) | Any receipt_gap present; does NOT gate passed |

Signature findings (key_resolved, key_trusted, signature_valid) are reported
per-receipt via individual_receipt_reports, not as sequence-level conclusions.

---

## Limitations (explicit, in report output)

1. Sequence integrity ≠ policy correctness.
2. Sequence integrity ≠ human intent.
3. Sequence integrity ≠ side-effect reality.
4. operation_digest match ≠ same real-world operation.
5. condition_response approved ≠ operation admissible.
6. receipt_gap present ≠ sequence valid.
7. key_resolved/key_trusted require explicit trust bundle; sequence findings do not substitute.
8. NOT_EVALUATED is not PASS. not_applicable is not PASS.

These appear verbatim in every DeferredSequenceReport.to_dict()["limitations"] list.

---

## Non-equivalences enforced

All seven non-equivalences from profile spec §7 are tested:
- test_approved_condition_response_not_admission_verdict
- test_approved_condition_not_admissibility_verdict
- test_terminal_admission_present_not_sequence_complete
- test_receipt_gap_present_not_sequence_valid
- test_operation_digest_match_not_same_real_world_operation
- test_not_evaluated_not_promoted_on_bad_signature
- test_not_evaluated_is_not_promoted_to_pass

---

## Remaining work / known gaps

- The single-receipt profile check does NOT verify cross-receipt digest chaining
  (condition_digest incorporation into subsequent operation_digest). This is an
  emitter-side construction; the verifier can only check presence and format.
  Documented in _deferred_operation_profile_errors() docstring.
- Signature findings at the sequence level are informational (per-receipt only).
  A fully adversarial sequence where individual receipts have valid signatures but
  cross-receipt linkage is broken is the primary attack surface — this is exactly
  what the sequence-level findings catch.
- The BASE_LIMIT string in verifier.py uses a slightly different normalization
  than the arcs-srs fixtures (extra spaces/line breaks in the arcs-srs doc).
  Fixtures in this repo use the verifier's normalized form. A canonical
  normalization agreement between arcs-srs and arcs-verify is an open item.
- No pyproject.toml changes needed: deferred_sequence.py is auto-included by
  the existing `include = ["arcs_verify*"]` find rule.

---

## Stop point

Stopped here per lane discipline. No commit, push, PR creation, or merge performed.
