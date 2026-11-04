# C2PA-SIGVERIFY0 — independent signed-observation test lane

STATUS: HARDEN0-P1 IMPLEMENTATION; NOT YET QUALIFIED OR MERGE AUTHORIZED.
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

Five distinct findings: signature_valid, issuer_key_resolved,
issuer_key_trusted, source_integrity and receipt_identity. Crypto verification
and key trust are not native C2PA manifest validation, signer trust, TSA trust,
content truth or operational issuer standing. Each remains separately
not_evaluated unless a distinct receiver-owned proof is run.

## Receiver-side source binding and receipt identity (HARDEN0-P1)

A declared digest is not evidence. The receiver passes the unsigned observation
bytes it holds as `source_bytes` — `bytes` only, at most 8 MiB. `bytearray`,
`memoryview`, `str` and oversized input raise `TypeError` instead of being
coerced or truncated; empty `bytes` are hashed normally and fail the comparison.
The verifier hashes them locally and compares that digest with the signed source
reference and the frozen admission allowlist.

- `source_integrity` is `pass` only when supplied bytes hash to the carried
  reference **and** that reference is one of the frozen admitted digests. Missing
  bytes give `not_evaluated` with `source_bytes_missing`; altered or substituted
  bytes give `fail` with `source_digest_mismatch`; bytes that match a reference
  outside the allowlist give `fail` with `source_not_admitted`.
- Source integrity is byte consistency plus admission of the reference. It is
  independent of whether the receipt itself is admitted (`test_provenance_not_admitted`)
  and of whether its signature verifies (`signature_invalid`); it never implies who
  produced the bytes.
- `receipt_identity` recomputes
  `dagr-ingest-c2pa-TEST-SIGNED-<source_digest[-16:]>-<key_fingerprint[:16]>`
  from the *verified* source digest and the fingerprint of the receiver-selected
  key. It is `fail` for a malformed, missing or substituted id
  (`receipt_id_malformed`, `receipt_id_mismatch`) and `not_evaluated` while the
  source or key is unverified (`receipt_identity_unverified`).
- The identity is a consistency label, not authentication: anyone who signs a
  receipt can write any id into it. It binds a receipt to a source and key for
  this test lane; it does not prove who produced either.
- A valid signature never promotes a failed source or identity finding, and a
  passing source or identity never implies a valid signature. The fields are
  reported side by side and no aggregate result is produced.
- The retained proof report names the digest of the bytes the receiver actually
  supplied as `supplied_source_sha256`; on a refusal that field can hold the digest
  of rejected bytes, which is why it is not called *verified*.

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
    python -m pytest -q tests/c2pa_srs/test_receiver_binding0.py
    python -m pytest -q tests/c2pa_srs/test_signed_integrated_replay0.py

Set C2PA_SIGN0_REQUIRED=1 for the integrated qualification, so a missing
SIGN0 installation is a test failure rather than a skip.
Set ARCS_VERIFY_C2PATOOL to the exact pinned local c2patool 0.27.15 executable
before the genuine native recomputation pass. Missing signer install or
validator is NOT_EXERCISED; never count that as an integrated proof PASS.

Negative matrix: valid signature with key untrusted; missing key; wrong key;
wrong issuer binding; altered receipt id, profile/version, signature, unknown
extension; producer native Invalid with exit 0; Manifest Store unavailable;
TSA trust material absent; no receipt-wide trust promotion. HARDEN0-P1 adds:
missing source bytes; substituted source bytes; a single modified source byte;
malformed, empty and missing receipt ids; and a validly re-signed receipt whose
identity is bound to the wrong key or source. A signed test receipt is NOT a
SCITT registration or an operational issuer receipt.

### One-command macOS offline execution

Use prepared, clean checkouts of both qualified PR heads and preinstalled test
dependencies. Create an empty evidence directory OUTSIDE both repositories.
No installer or provider request runs inside the acceptance gate.

    export C2PA_SIGN0_REPO=/absolute/path/to/prepared/dagr-ingest-sign0
    export C2PA_SIGN0_EXPECTED_HEAD=<literal full SIGN0 commit SHA under review>
    export C2PA_SIGVERIFY_EXPECTED_HEAD=<literal full SIGVERIFY0 commit SHA under review>
    export ARCS_VERIFY_C2PATOOL=/absolute/path/to/pinned/c2patool
    export C2PA_SIGNED_TEST_EVIDENCE_DIR=/absolute/path/to/empty/evidence
    bash tools/run_c2pa_signed0_offline.sh

Never derive either expected head from the checkout being tested: a head
compared with itself verifies nothing. Record the literal commit SHAs under
review in the qualification receipt.

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
