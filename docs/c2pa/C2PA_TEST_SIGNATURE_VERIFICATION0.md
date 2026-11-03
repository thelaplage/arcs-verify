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

Set ARCS_VERIFY_C2PATOOL to the exact pinned local c2patool 0.27.15 executable
before the genuine native recomputation pass. Missing signer install or
validator is NOT_EXERCISED; never count that as an integrated proof PASS.

Negative matrix: valid signature with key untrusted; missing key; wrong key;
wrong issuer binding; altered receipt id, profile/version, signature, unknown
extension; producer native Invalid with exit 0; Manifest Store unavailable;
TSA trust material absent; no receipt-wide trust promotion. A signed test
receipt is NOT a SCITT registration or an operational issuer receipt.

Preserve the exact signed bytes, ephemeral public test key, input digests,
separate cryptographic and native reports, executed test identifiers and
independent final-head review. A fresh production signing/profile gate is a
SEPARATE future owner decision. No PR merge without the required code-only
owner disposition. AUTHORITY_MOVEMENT = 0.
