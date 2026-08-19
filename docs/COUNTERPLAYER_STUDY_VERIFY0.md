# COUNTERPLAYER-STUDY-VERIFY0

Independent integrity verifier for Counterplayer's landed persistent-study stack.

Pinned producer snapshot:

- repository `thelaplage/counterplayer`
- commit `13bfb93da886c209799da1610a4905729453888a`

That merge contains the complete landed sequence through the stale-memory benchmark:

- `counterplayer.study-artifact-manifest/v0.1`
- RECALL0 / `research-events0.v0.1` recall events
- `counterplayer.study-impact/v0.1`

## Independent checks

The verifier imports no Counterplayer code. It locally reproduces Counterplayer's frozen canonical subset: recursive NFC, sorted-key compact JSON, UTF-8, no floats.

It independently checks:

- exact producer pin;
- StudyArtifactManifest field set, artifact identity, and manifest digest;
- StudyImpact field set, digest, classification vocabulary, and artifact linkage;
- RecallEvent field set, recall digest, and StudyArtifact linkage.

Optional impact/recall artifacts remain `NOT_EVALUATED` if absent.

## Boundary

```text
integrity != source truth
manifest != proof provider learned inputs
impact integrity != semantic correctness of impact classification
recall integrity != evidence
recall integrity != causal reliance
artifact replacement != forgetting
verification != authorization
```

This profile does not replace Countergraph verification of its replay/diff/attribution producer artifacts. It verifies the Counterplayer consumer-side persistent-study records only.