# Anatomy of a Signed SRS Receipt

This walkthrough annotates the committed sample receipt the quickstart
verifies:

```
packs/srs.mcp.sdk_enforcement/v0.1/normative/valid/admission-admitted.json
```

It is an **admission receipt**: evidence that an MCP tool call was evaluated
at an SDK enforcement boundary and admitted under a named policy pack. Read it
alongside the sample once; after that, every conformant receipt in this
profile reads the same way. The normative field definitions live in the
vendored SRS profile documents under `vendor/arcs-srs/`; this page is a
reader's guide, not a second normative source.

## The one design rule that explains everything else

The receipt contains **references and digests, never raw content**. There is
no prompt, no tool output, no argument payload anywhere in it. What the tool
call actually said is represented by `argument_digest`; who acted is
represented by `actor_ref`. The `raw_content_exclusion` result enforces this
at verification time, and `artifact_classes_excluded` declares it explicitly.
A receipt can therefore travel to an auditor, a counterparty, or a public
proof pack without carrying governed content with it.

## Identity and versioning

| Field | Sample value | What it tells you |
|---|---|---|
| `receipt_id` | `urn:srs:receipt:admission:0001` | Stable identifier for this receipt. |
| `receipt_version` | `srs.core.v5.1` | The envelope discriminator. The verifier requires exactly this value. |
| `profile_id` / `profile_version` | `srs.mcp.sdk_enforcement` / `v0.1` | The named profile the receipt claims conformance to. Verification is always against an explicitly selected profile; a mismatch is a profile failure, not a fallback. |
| `receipt_type` | `sdk_enforcement` | The receipt family within the profile. |
| `receipt_kind` | `admission` | What kind of event this receipt attests. Admission receipts pair with outcome receipts, which reference them. |

## The event

| Field | Sample value | What it tells you |
|---|---|---|
| `boundary_id` | `boundary:test:fastmcp` | The enforcement boundary that evaluated the call. |
| `boundary_type` | `mcp_tool_call` | The class of boundary. |
| `protocol_binding` | `mcp` | The protocol this receipt family binds. MCP is the first supported binding. |
| `logical_call_id` | `call-0001` | The logical call the receipt is about, usable to correlate admission and outcome receipts. |
| `subject_ref` | `tool-call:call-0001` | Reference to the governed subject of the receipt. A reference, not the call content. |
| `requested_tool_name` | `records.lookup` | The tool the caller asked for, by name only. |
| `tool_resolution_status` | `not_observed` | Whether the boundary observed tool resolution. `not_observed` is a disclosure, and the profile forbids a resolution reference when this is the value. |
| `disposition` | `admitted` | The boundary's decision. The profile constrains the allowed set; `profile.invalid_disposition` fires on anything else. |

## Who attests, under what policy

| Field | Sample value | What it tells you |
|---|---|---|
| `issuer_id` | `issuer:vcp:test` | The attesting issuer. Must match the issuer bound to the signing key in the trust bundle, or `issuer_key_trusted` fails. |
| `runtime_instance_id` | `runtime:test:001` | The runtime instance that emitted the receipt. |
| `policy_pack_id` / `policy_pack_version` | `policy:test:mcp` / `2026.07.11` | The policy pack in force at the boundary when the decision was made. |
| `issued_at` | `2026-07-11T20:00:00Z` | Issuance time. Must fall inside the signing key's validity window. |

## References and digests instead of content

| Field | Sample value | What it tells you |
|---|---|---|
| `actor_ref` | `actor:sha256:...` | Reference to the acting principal. |
| `argument_digest` | `sha256:...` | Digest of the call arguments. The arguments themselves are absent by design. |
| `artifact_classes_covered` | `["tool_call_admission"]` | What the receipt attests. |
| `artifact_classes_excluded` | `["raw_prompt", "raw_output", "raw_tool_arguments", "raw_tool_result"]` | What the receipt deliberately does not carry. The profile requires these exclusions to be declared. |
| `retention_class_applied` | `hash_only` | The retention posture applied to the governed content: here, only hashes were retained. |

## Honesty markers

| Field | Sample value | What it tells you |
|---|---|---|
| `attestation_limits` | one sentence | What this receipt does **not** claim. The verifier fails `attestation_limits_present` if this is absent or empty: a receipt that states no limits is nonconformant, by design. |
| `extensions` | `{"mcp": {...}}` | Namespaced extension data (here, the concrete SDK binding version). Must be a JSON object. |

## The signature

```json
"receipt_signature": {
  "algorithm": "Ed25519",
  "canonicalization": "RFC8785-JCS",
  "key_id": "issuer.vcp.test/receipt-signing/2026-01",
  "signature": "..."
}
```

The preimage is the receipt with only the `signature` member removed,
serialized under RFC 8785 (JCS) canonicalization. `key_id` resolves against
the supplied trust bundle (`issuer_key_resolved`), the resolved key must be
trusted for this issuer with `issued_at` inside its validity window
(`issuer_key_trusted`), and the signature must verify over the preimage
(`signature_valid`). Verifying proves the receipt was not modified after
issuance under that key. It does not prove the described event occurred, and
the verifier never claims that it does.

## What to try next

Copy the sample, change any field value, and rerun the quickstart command
against your copy. Watch which results fail and which failure codes name
your edit (see [FAILURE_CODES.md](FAILURE_CODES.md)). Then reformat the file
without changing any value and watch verification still pass: the signature
covers RFC 8785 canonical content, not file formatting. The two experiments
together teach the verification model faster than any further prose.
