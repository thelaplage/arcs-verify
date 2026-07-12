# SRS Signed Receipt v0.1 vectors

These vectors are deterministically generated from `tools/generate_signed_vectors.py`. The fixed private seed exists only for public conformance vectors and MUST NOT be used outside tests.

The valid set covers admitted, refused, deferred-for-review, linked result outcome, and task-submission receipts. The mutation set distinguishes semantic changes from non-semantic JSON reserialization. `trust/issuer-keys.json` is an explicit verifier-selected test trust bundle.

Regenerate with the pinned dependencies in `tools/vector-requirements.txt`, then run:

```sh
python3 tools/generate_signed_vectors.py
python3 -m pytest -q tests/test_signed_vectors.py
```
