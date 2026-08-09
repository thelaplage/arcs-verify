# `srs.editorial.source_ingest.v0.1` authority — vendored pin

Byte-identical copy of the arcs-srs authority for the provisional
`srs.editorial.source_ingest.v0.1` profile. arcs-verify is a consumer of this
authority: it does not redefine the profile, it pins these bytes and derives its
verifier expectations from them.

Pinned arcs-srs commit:

```
1f8768d68fa46c61a6b0b20c9caad8ae7de9f683
```

| file | sha256 |
| ---- | ------ |
| `profile.manifest.json` | `f71ab3238599abf86838ed2987a94e00323be2fc2389d11b6062a5445efee25f` |

The manifest's `document_sha256` (the profile prose it governs,
`docs/profiles/SRS_EDITORIAL_SOURCE_INGEST_PROFILE_v0_1.md`) is:

```
0454e96ea67c5f415c57ea9b7ca624165366ea0b80914bdb6be77448bdf56b98
```

`tests/test_editorial_source_capture_v02_ingest_pins.py` recomputes the manifest
digest against the pin above and asserts the verifier's expectation constants
(`SOURCE_INGEST_V01_*` in `arcs_verify/verifier.py`) equal the values declared in
these bytes.

`fixtures/valid/` are literal Titan specimen ingests (source_artifact_id
`sha256:ffdbd3df…`, parser `dagr-ingest.pdf`, historical `pdo_module_identity`
`garp-ingest/0.1.0`, derivation output `sha256:c95bf3ff…`). `fixtures/invalid/`
are the authority's structural negatives; each carries its own `_expected_code`.
These are envelope-unsigned vectors and prove nothing about signing
(`requires_signing: false`).
