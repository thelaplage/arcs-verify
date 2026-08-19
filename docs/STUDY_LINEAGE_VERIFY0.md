# STUDY-LINEAGE-VERIFY0

Independent integrity verification for provider-neutral study/memory lineage.

## Inputs

Serialized artifacts only:

- `counterpedia.study_manifest/v0.1`
- optional `counterpedia.study_artifact/v0.1`
- optional `countergraph.study-memory-impact/v0.1`
- exact producer repo/commit pins

The verifier imports neither producer implementation.

## Independently recomputed

- StudyManifest structural shape and canonical digest.
- StudyArtifact -> StudyManifest digest linkage.
- Artifact addressability posture (`content_addressed` requires digest; `provider_addressed` must not invent one).
- Countergraph MEMORY-IMPACT0 -> StudyManifest and StudyArtifact linkage.
- Exact producer repo/commit pins.
- Countergraph `countergraph.canonical-json/v0.1` impact digest via an independent local reproduction of the frozen canonicalization profile.

Countergraph's profile is deliberately preserved as **not RFC 8785**.

## Not verified

```text
integrity != source truth
manifest inputs != study completeness
artifact linkage != proof provider learned the inputs
provider deletion != forgetting
impact binding != semantic correctness of impact state
recall != causal reliance
authorization != this verifier's authority
```

Unknown/omitted optional artifacts remain `NOT_EVALUATED`, not silently converted to PASS or FAIL.

## Dependency posture

This branch currently pins draft producer heads for STUDY-CONTRACTS0 and MEMORY-IMPACT0. It must remain draft until both producers merge, then be repinned and re-executed against literal final producer fixtures.