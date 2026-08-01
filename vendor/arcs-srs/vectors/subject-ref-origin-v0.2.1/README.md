# `subject_ref_origin` vectors — SRS envelope v0.2.1

Four unsigned envelope vectors for the optional `subject_ref_origin` field
introduced in SRS Envelope v0.2.1.

These are **envelope** vectors. They carry no `receipt_signature` and prove
nothing about signing; the signed vector sets (`signed-receipt-v0.1`,
`connection-lifecycle-v0.1`) remain the authority for that. Each vector's
bytes are pinned by `receipt_file_sha256` in `manifest.json` under the same
hashing discipline as the sibling sets.

Validated against:

```
srs-envelope@0.2.1+sha256:2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1
```

| vector | declares | reads as |
| ------ | -------- | -------- |
| `valid/supplied-subject.json` | `supplied_subject` | `supplied_subject` |
| `valid/derived-from-supplied-correlation.json` | `derived_from_supplied_correlation` | `derived_from_supplied_correlation` |
| `valid/binding-minted.json` | `binding_minted` | `binding_minted` |
| `valid/v0-2-0-era-not-declared.json` | *(absent)* | `not_declared` |

One vector per supplied/derived class is deliberately not provided; the set
covers the supplied class, one derived class, the minted class, and absence.

The fourth vector is a v0.2.0-era receipt: it predates the field and does not
carry it. Under v0.2.1 tooling it validates cleanly and its origin reports as
`not_declared`. That is the whole of what absence means — it supports no
inference about emitter vintage, and no consumer may collapse it into any
supplied class. `not_declared` is a rendering, never an emittable value, and
is not a member of the closed enum.
