Vendor-Neutral MCP Audit-Trail Pack (v0.1)
==========================================

Status: first vendor-neutral, receipt-bearing conformance pack in this repo.
This is the **neutral** pack that proves the shape before any vendor-specific
(e.g. Bedrock) pack is built. See "Bedrock pack remains deferred" below.

What this pack is
-----------------

It takes one **explicit, public-safe** MCP (Model Context Protocol)
custody-gateway **audit-trail input file** and builds one ARCS SRS **envelope**
receipt from it with a minimal, deterministic adapter. The receipt carries the
audit evidence as a GARP body under `extensions.garp.body`, and the pack proves
that the receipt validates against the canonical SRS envelope schema already
vendored/reconciled in this repo.

```
input/mcp_audit_trail.input.json          explicit public-safe MCP audit-trail input
tools/build_receipt.py                    minimal deterministic input -> receipt adapter
fixtures/valid/mcp_audit_trail.envelope.json   generated/expected valid SRS envelope receipt
fixtures/invalid/top_level_status_verdict.json forbidden-drift fixture (rejected)
expected/valid/   expected/invalid/       byte-for-byte expected validator output
PROVENANCE.json                           authorship + public-safety + Option A record
check.sh                                  the pack conformance check
```

Run it from the repository root:

```
bash packs/mcp-audit-trail/v0.1/check.sh
```

The check regenerates the receipt from the input (deterministic, byte-identical),
verifies the receipt cryptographically binds the input bytes, validates the
receipt against the canonical SRS envelope schema (exit 0, output matches
`expected/valid/`), and confirms the forbidden-drift fixture is rejected by that
same canonical validator (exit 1, output matches `expected/invalid/`).

What it proves — and what it does not
-------------------------------------

The verifier/conformance check validates **structural and cryptographic
integrity only**:

- **structural**: the receipt is a well-formed ARCS SRS envelope under the
  canonical schema (`schemas/srs-envelope/v0.1.0/`, pinned digest
  `e866eabf…d6b61`), with all GARP body content under `extensions.garp.body`.
- **cryptographic**: the receipt binds the exact input bytes — the sha256 in
  `extensions.garp.body.artifact_hashes` equals the sha256 of the input file —
  and regenerates byte-identically from that input.

It does **not** prove truth. It does not assert that any recorded audit event is
true, that any tool call was authorized, that any custody claim is correct, or
that any external system behaved as the trail describes. The receipt attests
envelope form and input-byte integrity; nothing more. The body's
`attestation_limits` say the same thing inside the receipt.

Why this is vendor-neutral
--------------------------

- The input is generic MCP custody-gateway evidence: generic tool names
  (`fs.read`, `kv.get`), generic server refs (`mcp-server:filesystem`), a
  generic gateway. There is **no AWS / OpenAI / Microsoft / Bedrock** identifier,
  no vendor profile, no account, ARN, region, or product name.
- It is **explicit-file input only**: no scanner, no live credentials, no
  network calls, no mutation of any external system, no private corpus. The
  adapter reads one file and writes one file.
- The audit trail is **digest-only**: tool arguments and results appear as
  sha256 digests, never as raw payloads. That is what makes the sample
  public-safe, and it is a property of the evidence shape, not of any vendor.

Envelope shape (required invariants)
------------------------------------

- **No top-level `receipt_class`.** The envelope carries none.
- **`receipt_type` remains the family axis** and is in the closed enum; this
  pack uses `provenance` (an audit trail is provenance over tool custody).
- **`boundary_type` remains the top-level routing axis.** This pack uses
  `audit_trail_boundary`, a **pack-local descriptive routing label**. It is
  **not** a newly-minted canonical `boundary_type`: the canonical `boundary_type`
  lane remains `arcs-srs`'s to define. The value only names how this receipt
  routes. The canonical schema treats `boundary_type` as an **open string** (no
  enum, no registry), so this value is **accepted** by the conformance pack
  precisely because the field is open — it mints nothing canonical. `check.sh`
  carries a posture guard that fails loudly if that open-string posture ever
  changes. See `docs/BOUNDARY_TYPE_POSTURE.md` for the full ratification.
- **GARP body content lives under `extensions.garp.body`**, named by `body_kind`
  (`mcp_audit_trail`). Hoisting any of it to the top level is rejected by the
  canonical validator (see `docs/BODY_KIND_EXTENSION_RULES.md`).

Option A / `decision_ref` (preserved)
-------------------------------------

This pack preserves **Option A** as recorded in **garp-ops PR #87** (R0/R1
Option A) and **garp-sdk PR #78** (admission receipt contract conformed to
Option A / `decision_ref`):

- Any decision/verdict semantics are carried as a **reference** —
  `extensions.garp.body.decision_ref` — and **never** as a body-level or
  top-level `verdict` / `status` / `disposition` / `decision` /
  `governance_state`.
- The valid receipt demonstrates the correct shape (a `decision_ref` in the
  body, no verdict anywhere).
- The forbidden-drift fixture (`fixtures/invalid/top_level_status_verdict.json`)
  hoists the gateway decision onto the envelope as a top-level `status` verdict.
  The canonical validator rejects it with `TOP_LEVEL_BODY_VERDICT` — proving the
  drift away from `decision_ref` is structurally refused.

Bedrock pack remains deferred
-----------------------------

A Bedrock-specific (and any other vendor-specific) pack is **deferred until this
neutral pack proves the shape**. No Bedrock, AWS, OpenAI, or Microsoft vendor
profile is introduced here. Once this vendor-neutral pack is accepted, a
vendor-specific pack can reuse the same canonical schema, the same envelope
invariants, and the same `decision_ref` discipline, differing only in its
explicit, vendor-shaped input — never by weakening any invariant above.
