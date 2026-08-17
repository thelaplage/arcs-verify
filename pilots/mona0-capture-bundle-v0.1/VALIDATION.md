# MONA0-VERIFY3 validation record

Validation scope: verifier mechanics over synthetic serialized capture bundles only. The fixture is **not Mona Lisa evidence**.

Pinned `arcs-verify` base: `236f61b114a67cc56d5ec0b21ccba9ecb0034aad`.

The local hostile matrix exercised the verifier without importing `counterpedia-acquisition` code.

Observed result:

```text
MONA0-VERIFY3 LOCAL TEST: PASS
valid_bundle=PASS
tampered_bytes=REJECTED
coherent_rewrite=PASS_WITH_AUTHENTICITY_NOT_EVALUATED
producer_independence_overclaim=REJECTED
claim_admission_smuggle=REJECTED
unmanifested_object=REJECTED
forged_source_id=REJECTED
moving_verifier_revision=REJECTED_AS_SOURCE_ERROR
```

## Interpretation

The clean fixture establishes that the verifier can independently recompute and cross-check:

- exact object SHA-256 addresses from preserved bytes;
- manifest paths and byte counts;
- producer receipt ↔ top-level capture bindings;
- acquisition-local URL-derived source identity without importing producer code;
- producer Artifact groupings;
- the MONA0 repeat-capture / distinct-rendition topology;
- the authority firewall (`claim_admission_decisions == 0`).

The tamper fixture establishes that changing preserved bytes without changing the serialized digests fails the independent object-integrity conclusion.

The coherent-rewrite fixture is intentionally different: it rewrites the bytes and all matching serialized digests consistently. That bundle can pass structural/content-address verification. The report still returns:

```text
authenticity_verified        = not_evaluated
claim_truth_verified         = not_evaluated
source_independence_verified = not_evaluated
signature_verified           = not_evaluated
```

This is a required limitation, not a missing test. The pilot has no external historical/authenticity anchor and no signed SRS receipt in scope.

The synthetic fixture and validation record do not move admission, standing, publication, registry identity, or memory state.

**Authority movement = 0.**
