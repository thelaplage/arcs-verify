# C2PA-SIGVERIFY0 — independent signed-observation test lane

STATUS: DRAFT; IMPLEMENTATION NOT YET QUALIFIED OR MERGE AUTHORIZED.
Owner authorized bounded, offline, test-only verification of signed SRS
C2PA observations, using arcs-verify as an independent receiver. Signing is
implemented by separate dagr-ingest C2PA-SIGN0. No production issuer, key,
operational signing, publication, deployment, SCITT registration, trust-list
membership or profile ratification is authorized. AUTHORITY_MOVEMENT = 0.

## Contracts

Consume the existing provisional srs.c2pa.validation_observation.v0.1
profile and SRS Signed Receipt Profile v0.1. Ed25519 verifies the RFC8785-JCS
preimage of all receipt fields except receipt_signature.signature. Profile
version, key id, unknown extensions and all semantic fields remain signed.

Verifier code imports NO producer implementation. The caller supplies a
specific TEST-only public key and an explicit trust decision, in memory.
The issuer-namespaced key_id must bind SHA-256 of exactly that selected raw
public key; key-id reuse or substitution is a typed refusal.
There is no default trust bundle, key fetching, network egress or file-based
key lookup.

Three distinct findings: signature_valid, issuer_key_resolved, and
issuer_key_trusted. Crypto verification and key trust are not native C2PA
manifest validation, signer trust, TSA trust, content truth or operational
issuer standing. Each remains separately not_evaluated unless a distinct
receiver-owned proof is run.

## Genuine frozen source observations

Only test-sign derivatives from these unsigned EMIT0 output SHA-256 values:

- sha256:32a0ebd9cb47edd093f15eba1db1eb43c3130bb32bda645016ee2f7a337cbb22
- sha256:6b9f1219499da201c341cb45974ea2e3f0807a922c532967e297615a90c6a3da
- sha256:d4818c21c319b417110b067c423ca8ecfddf7f367591111f9a1fc2527ff26982

Existing real specimens, assets, native reports and manifest store bytes are
retained in tests/c2pa_srs/produced from arcs-verify#18. The test-only
cross-repository harness may import the separately installed SIGN0 in the
test process, but no verifier runtime module imports it.

## Required acceptance

The two independent tests are:

    python -m pytest -q tests/c2pa_srs/test_test_signature0.py
    python -m pytest -q tests/c2pa_srs/test_signed_integrated_replay0.py

Set C2PA_SIGN0_REQUIRED=1 for the integrated qualification, so a missing
SIGN0 installation is a test failure rather than a skip.
Set ARCS_VERIFY_C2PATOOL to the exact pinned local c2patool 0.27.15 executable
before the genuine native recomputation pass. Missing signer install or
validator is NOT_EXERCISED; never count that as an integrated proof PASS.

Negative matrix: valid signature with key untrusted; missing key; wrong key;
wrong issuer binding; altered receipt id, profile/version, signature, unknown
extension; producer native Invalid with exit 0; Manifest Store unavailable;
TSA trust material absent; no receipt-wide trust promotion. A signed test
receipt is NOT a SCITT registration or an operational issuer receipt.

### One-command macOS offline execution

Use prepared, clean checkouts of both qualified PR heads and preinstalled test
dependencies. Create an empty evidence directory OUTSIDE both repositories.
No installer or provider request runs inside the acceptance gate.

    export C2PA_SIGN0_REPO=/absolute/path/to/prepared/dagr-ingest-sign0
    export C2PA_SIGN0_EXPECTED_HEAD=$(git -C "$C2PA_SIGN0_REPO" rev-parse HEAD)
    export C2PA_SIGVERIFY_EXPECTED_HEAD=$(git rev-parse HEAD)
    export ARCS_VERIFY_C2PATOOL=/absolute/path/to/pinned/c2patool
    export C2PA_SIGNED_TEST_EVIDENCE_DIR=/absolute/path/to/empty/evidence
    bash tools/run_c2pa_signed0_offline.sh

The runner checks both exact heads and clean worktrees, refuses a missing
OS network-deny sandbox, sets C2PA_SIGN0_REQUIRED=1 and runs all affected
signature and real-producer replay tests with the pinned validator. The
live test additionally checks SHA-256 of that validator executable against
the frozen real-producer provenance, not just version 0.27.15.

Only after all asserted tests complete, each of the three genuine specimens
writes its TEST-ONLY signed receipt, 32-byte public test key, and a separate
JSON report containing signature findings and native recomputation. These
nine evidence files belong to the test packet; no private signing key is
retained. A missing, skipped or overwritten proof file is an acceptance
failure. Never publish this local evidence directory without a separate
disclosure/rights decision.

Preserve the exact signed bytes, ephemeral public test key, input digests,
separate cryptographic and native reports, executed test identifiers and
independent final-head review. A fresh production signing/profile gate is a
SEPARATE future owner decision. No PR merge without the required code-only
owner disposition. AUTHORITY_MOVEMENT = 0.
