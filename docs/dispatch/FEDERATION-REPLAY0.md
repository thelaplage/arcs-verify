# FEDERATION-REPLAY0

PROGRAM: COUNTERPEDIA-FEDERATION-WAVE2
LANE: L02
REPO: thelaplage/arcs-verify
BASE: main
STATUS: DRAFT
AUTHORITY_MOVEMENT: 0

## Goal
Independently replay and verify a complete federation run from saved artifacts and native receipts without importing Counterpedia authority semantics into ARCS Verify.

## Required invariant
`replayable != valid != authorized != true != admitted`.
Replay proves deterministic custody/consistency within the supplied artifact set; it does not create authority or epistemic standing.

## Required work
1. Accept a `FederationRunEnvelope` or equivalent manifest plus resolvable native artifact refs.
2. Verify envelope digest and exact referenced artifact digests before domain-specific checks.
3. Reuse existing ARCS/SRS verification surfaces for receipts rather than reimplementing them.
4. Verify REG1 application proof against supplied pinned before-state bytes read-only.
5. Verify memory-handoff package digest/currentness signal integrity without claiming memory admission.
6. Verify MCP read receipts/trust-bundle bindings without promoting issuer trust from discovery alone.
7. Verify federated Counterpaths query/result/coverage digests and detect incomplete coverage.
8. Emit a deterministic replay report with per-artifact PASS/FAIL/NOT_EVALUATED and explicit authority_effect:none.
9. Support disconnected/offline replay from a complete local artifact bundle.

## Negative tests
- missing referenced bytes;
- digest substitution;
- valid receipt attached to wrong run;
- wrong REG1 before-state;
- memory package tamper;
- trust bundle discovered but not independently trusted;
- path result with absent peer silently represented as complete;
- replay PASS interpreted as admission.

## Non-goals
No network calls required for core replay. No consensus. No DAGR transition. No registrar application. No publication. No truth score.
