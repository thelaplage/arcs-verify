# `srs.editorial.source_capture.v0.2` authority — vendored pin

Byte-identical copy of the arcs-srs authority for the provisional
`srs.editorial.source_capture.v0.2` profile. arcs-verify is a consumer of this
authority: it does not redefine the profile, it pins these bytes and derives its
verifier expectations from them.

Pinned arcs-srs commit:

```
1f8768d68fa46c61a6b0b20c9caad8ae7de9f683
```

| file | sha256 |
| ---- | ------ |
| `profile.manifest.json` | `d08730e9c9e568eccc265d7b560226d10aacd67abeca9e55fd6c101af4c5c6e9` |

The manifest's `document_sha256` (the profile prose it governs,
`docs/profiles/SRS_EDITORIAL_SOURCE_CAPTURE_PROFILE_v0_2.md`) is:

```
d621fa989350c010221ed91bd78017458ed73fc419f7d0c9fbecd5471167bc86
```

`tests/test_editorial_source_capture_v02_ingest_pins.py` recomputes the manifest
digest against the pin above and asserts the verifier's expectation constants
(`SOURCE_CAPTURE_V02_*` in `arcs_verify/verifier.py`) equal the values declared
in these bytes, so the verifier can never drift into a fresh local dialect.

`fixtures/valid/` are literal Titan specimen captures (declaring_artifact_ref
`sha256:a272eb55…`, inventory key `TIT-S02`/`TIT-S05`). `fixtures/invalid/` are
the authority's structural negatives; each carries its own `_expected_code`.
These are envelope-unsigned vectors and prove nothing about signing
(`requires_signing: false`).
