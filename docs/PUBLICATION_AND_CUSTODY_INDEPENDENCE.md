# Publication and Custody Independence

ARCS Verify evaluates supported serialized receipt/artifact bytes under a pinned verifier context. It does not use publication membership or custody location as a verification signal.

## Boundary

```text
verification input = serialized bytes + pinned verifier context
verification result != Counterpedia inclusion
verification result != local custody
publication presence/absence != trust signal
```

For the signed-SRS path, changing the filesystem path, store, host, or publication that supplied byte-identical receipt material MUST NOT change the verifier's findings. The selected profile, schema bytes, receipt bytes, and trust inputs are the load-bearing inputs.

Counterpedia, Counterpose, Amnesiac, or SRS Store metadata MUST NOT repair an invalid signature, malformed envelope, profile violation, unresolved key, or untrusted key.

Conversely, a valid receipt is not invalidated merely because no Counterpedia page or local custody relation exists.

## Source errors remain separate

An unreadable or malformed source file is a source-integrity/usage problem, not a publication verdict. This boundary does not change the existing exit-code distinction.

## Non-claims

```text
hosted_by_counterpedia != verified
stored_in_srs_store != trusted
external_custody != invalid
published != signature_valid
```

This note sharpens existing verifier architecture. It does not add remote receipt discovery, a trust bundle, publication eligibility, or artifact-retention policy, and it does not claim canonical conformance to proposed `thelaplage/garp-doctrine#184` while that candidate remains unratified.
