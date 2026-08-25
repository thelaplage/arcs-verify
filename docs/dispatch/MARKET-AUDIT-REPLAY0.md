# MARKET-AUDIT-REPLAY0

PROGRAM: COUNTERPEDIA-RECON-LIVE0
LANE: L06
REPO: thelaplage/arcs-verify
BASE: main
STATUS: DRAFT
AUTHORITY_MOVEMENT: 0

## Goal
Independently replay the complete LIVE-MARKET0 transaction offline from its portable audit artifacts, without access to the running marketplace or authority services.

## Prerequisite
Consume the exact MarketAuditPacket / FederationRunEnvelope and native referenced artifacts emitted by LIVE-MARKET0. Do not import Counterpedia-agent orchestration logic as the verifier oracle.

## Required invariant
`replayable != valid != authorized != true != admitted`
`audit_complete != market_correct`
`receipt_valid != provider_trusted`

## Verification surface
Independently check, where applicable:
- audit/run envelope digest identity;
- provider/onboarding identity-binding refs;
- active offer + lifecycle refs;
- discovery/availability/selection refs;
- quote and quote-acceptance binding;
- task/provider/offer/policy authorization binding;
- capture/artifact digests;
- SRS receipt integrity/profile/signature using supplied trust material;
- witness observation integrity;
- SLA reconstruction from observable facts;
- deterministic test-settlement linkage;
- provider-history linkage;
- dispute refs if present;
- REG1 registration proof and external authorization-provenance refs;
- federated path/coverage artifacts if present.

## Result vocabulary
Each check must report exactly one bounded posture such as:
- PASS
- FAIL
- NOT_EVALUATED
Do not turn missing artifacts into falsehood, lack of evidence into authorization failure, or successful replay into truth/admission.

## Offline requirement
The authoritative replay path must work from a supplied directory/bundle with network disabled. Any optional network enrichment must be clearly non-authoritative and disabled in the core conformance test.

## Tamper tests
Mutate independently:
- quote digest;
- authorization policy ref;
- capture bytes;
- SRS receipt;
- witness ref;
- SLA observation;
- settlement ref;
- REG1 provenance anchor;
- audit manifest.
Each must fail in the correct layer without promoting unrelated layers to FAIL.

## Outputs
- deterministic `market-audit-replay-report.v0.1.json`;
- human-readable replay summary;
- exact artifact-by-artifact status table;
- coverage of NOT_EVALUATED cases;
- no domain authority movement.

## Acceptance
A fresh verifier process with no marketplace connectivity can reproduce the integrity/provenance/authorization-binding conclusions of the live transaction from native bytes alone, while explicitly leaving truth and Counterpedia admission to their owning domains.