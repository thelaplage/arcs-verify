# Portable Offline Verification v0.1

**Status:** implementation candidate; not a public-release authorization

`arcs-verify portable-pack` packages a serialized SRS receipt and the exact envelope schema used to verify it so the artifact can be copied, mirrored, emailed, archived, and checked without Counterpedia custody or network access.

## Package contents

v0.1 has an exact three-entry ZIP contract:

```text
manifest.json
receipt.json
schema.json
```

Trust material is deliberately absent.

A package cannot choose the keyring under which it will be trusted. Verification requires two separately supplied inputs:

1. the external keyring bytes; and
2. an operator-selected trust-context pin containing `context_id`, `issued_at`, and the SHA-256 of those exact keyring bytes.

The trust context is not evidence merely because it exists. It is the verifier/operator's selected context. Package bytes never supply or override it.

## Offline verification

`portable-pack verify` performs only local file reads, package/digest validation, and the existing independent `verify_receipt` path. It requires no Counterpedia account, API credential, custody lookup, callback, or network request.

The test suite runs verification with `socket.socket.connect` replaced by a hard failure to guard accidental outbound access.

## Revocation honesty — VFY-08

An offline verifier can evaluate the selected trust/keyring material and its local clock. It cannot discover revocation or compromise facts published after the selected trust context was issued.

Every portable verification report therefore carries:

```text
key_status_after_context_issued_at: not_evaluated
post_context_revocation_or_compromise: not_evaluated
current_standing: not_evaluated
continued_validity: not_evaluated
real_world_truth: not_evaluated
```

Those fields are never forced to PASS by a successful receipt verification.

## Exit discipline

- `0`: package integrity passed and the existing receipt verifier passed;
- `1`: package integrity passed but receipt verification failed;
- `2`: source/package integrity or usage error. A malformed or mutated package is not mislabeled as a receipt-verification verdict.

## Public release remains blocked

This lane does not create `VERIFY-PUBLIC0`. The repository's checked-in brand denylist is still under the explicit acknowledged-empty waiver. A public verifier release requires real approved deny tokens and a passing `tools/check_public_release.py --require-denylist` run with brand checking actually performed.
