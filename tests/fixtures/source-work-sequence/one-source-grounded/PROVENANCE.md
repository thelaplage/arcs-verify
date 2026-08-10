# one-source-grounded (OSG-01) — provenance

The **end-to-end single-source witness** for ARCSV-SOURCESEQ0. One governed source
threads capture → grounded proposal → declaration binding → `source_capture.v0.2`,
so on the SAME source both `capture_linkage=PASS` (the raw captured bytes are
vendored and recompute) and `proposal_grounding=PASS` (a same-lineage grounded
proposal whose grounding recomputes). Contrast TIT-S02, whose captured object is an
out-of-evidence PDF (`capture_linkage=PARTIAL`) and which bound no proposal
(`proposal_grounding=NOT_EVALUATED`) — both honest states that stay unchanged.

These files are **literal producer bytes**, generated once and copied verbatim
(`cp`, then hashed immediately — never re-serialized or pretty-printed here). The
digests below are pinned in `tests/test_source_work_sequence.py`
(`ONE_SOURCE_FIXTURE_DIGESTS`); any silent regeneration fails that pin.

## Producer pins

| lane | repo @ commit | role |
|---|---|---|
| A | `counterpedia-acquisition` @ `d4b1127d` | capture + grounded proposal + session export (ACQ-SESSION0 / ACQ-DECL0) |
| B | `dagr-ingest` @ `dbe880dc` | DAGR-ACQ-SRS0 adapter emits `srs.editorial.source_capture.v0.2` |
| — | `arcs-srs` @ `4d90b9c` | `srs.editorial.source_capture.v0.2` profile authority |

## Generation recipe

Snapshot reproducibility ≠ identity reproducibility. Draw the boundary precisely:

- **Deterministic identity outputs — reproduce exactly.** `declaration.OSG_01_MANIFEST.json`
  and `captured_source.html` are byte-deterministic, and from them the *identity
  outputs* recompute identically on every run: `declaring_artifact_ref`, the R1a
  `source_reference_id`/`subject_ref`, and the captured-object digest. These are the
  only outputs the verifier consumes.
- **Execution-instance artifacts — do NOT reproduce byte-for-byte.**
  `capture_receipt.json`, `session.manifest.json`, `grounded_content_proposal.json`,
  and the `source_capture.v0_2.receipt.json` derived from them embed values the
  producers mint fresh each execution (`capture_id`, `captured_at`, `envelope_id`,
  `observed_at`, `issued_at`). Their exact bytes differ across runs.

So the vendored files here are **one historical producer execution**, made durable by
the digest pins below — not a byte-reproducible build. The verifier reads none of the
per-run fields (it recomputes only the identity/linkage above), so a re-run yields a
different-bytes but identity-identical session. To refresh the fixture you must
re-vendor and re-pin the new snapshot's digests (mirroring how TIT-S02 is frozen).
This is deliberate: the incidental execution UUIDs/timestamps are intentionally not
normalized, rather than modifying the producers so a test fixture could pretend a
historical execution is reproducible.

**Lane A — `counterpedia-acquisition @ d4b1127d`.** The committed generator
`scripts/gen_osg01_sourceseq_fixture.py`
(`sha256:2639643a1a8ad2f5374e156e7ed255238a0270272ce07f27c0dd6d53a7c69ced`; landed
in `counterpedia-acquisition` via PR #19, squash-merge `412c6bbb`) runs the
real ACQ-SESSION0 pipeline over a small self-hosted HTML source and exports the
literal session wire bytes:

```
PYTHONPATH=src python3 scripts/gen_osg01_sourceseq_fixture.py <out_dir>
```

Pinned generation inputs (these ARE the fixture identity):

- host `127.0.0.1`, **fixed** port `8973` — a bind failure is a hard STOP (never a
  fallback port; a different locator would change the binding → R1a).
- locator `http://127.0.0.1:8973`
- inventory key `OSG-01`
- source HTML `sha256:5b7fa4b9559750e1b5dd0aa9fd396d3291569054f6cbb0a441b9aebf1785eb33`
- grounded proposal: 1 extractive field (`headline`, anchored to the first
  visible-text line) + 1 abstractive field (`summary`, no anchor); 0 dropped.

The generator recomputes and asserts, before exit, that
`sha256(raw html)` = capture receipt exact-bytes = manifest captured-object address
= manifest `captured_bytes` artifact digest = grounded proposal `artifact_digest`,
and that `declaration_digest` + R1a match the binding.

**Lane B — `dagr-ingest @ dbe880dc`.** The untouched export is consumed by
`emit_source_capture_from_session(<out_dir>, acknowledge_provisional=True, …)`
(`dagr_ingest/adapters/acquisition_source_capture.py`) with issuer identity:

- `issuer_id = issuer.counterpedia/demo-corpus/wave1`
- `runtime_instance_id = runtime-counterpedia-capture-0001`
- `boundary_id = boundary-editorial-corpus-0001`
- `capturer_identity = counterpedia-capture-pipeline/wave1@v0.1`

The returned receipt dict is serialized once (2-space indent, emitter-natural key
order, trailing newline) to `source_capture.v0_2.receipt.json`. Verified:
`declaring_artifact_ref + OSG-01 → source_reference_id == subject_ref` and
`captured_bytes_ref == sha256(raw html)`.

**Lane C — `arcs-verify`.** Copy bytes only into this directory; the verifier
recomputes every axis from these serialized bytes and imports no producer code.

## Vendored artifacts (sha256)

| file | source (Lane) | sha256 |
|---|---|---|
| `declaration.OSG_01_MANIFEST.json` | A `declaration/<hex>.bin` | `bfc8d023c092468d359c6a515599fb3b6c3c94504e1bcb535ce44bd167d272d6` |
| `source_declaration_binding.json` | A | `48570a29b59f8151d6bfabbe149e3a9cae31fe5b3012c1a22223fc71f2035d20` |
| `session.manifest.json` | A | `39d85aefd36d1ff4e099f5828cb5c190c8dfbc21a2368ec5886b1b54a378a8ae` |
| `capture_receipt.json` | A | `7855ec9d7eaa32885031f2a7fb45dea276a1346251390790faf391a827bd548f` |
| `grounded_content_proposal.json` | A | `81e33407e2d736b18f68b429ddffb8455a85ddd761ddf2141f656e851bc69a6e` |
| `captured_source.html` | A `captured/<hex>.bin` (raw source; proposal source == captured bytes) | `5b7fa4b9559750e1b5dd0aa9fd396d3291569054f6cbb0a441b9aebf1785eb33` |
| `source_capture.v0_2.receipt.json` | B | `1296ea1bbd6e1608ea919c6b20b5f72020ae5bf15d32490729f9f027c5ce435f` |

## Recomputed identity

- `declaring_artifact_ref` = `sha256:bfc8d023c092468d359c6a515599fb3b6c3c94504e1bcb535ce44bd167d272d6`
- R1a `source_reference_id` = `subject_ref` =
  `urn:counterpedia.source-reference:sha256:bfc8d023c092468d359c6a515599fb3b6c3c94504e1bcb535ce44bd167d272d6:OSG-01`
- captured-object digest = `sha256:5b7fa4b9559750e1b5dd0aa9fd396d3291569054f6cbb0a441b9aebf1785eb33`
