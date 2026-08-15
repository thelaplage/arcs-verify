# SEM-H2-SHACL0

Base SHA: `4c7e21822e99b998fcf302320b832db499e59c68`

AUTHORITY MOVEMENT = 0.

Adds an independent semantic-projection conformance check. PASS means only that a supplied projection conforms to the bounded semantic projection constraints checked here; it is explicitly not evidence verification, admission, publication, standing, or truth.

The v0.1 implementation uses deterministic local shape checks instead of adding a SHACL engine. It rejects unknown schemas, malformed refs, blank-node governed subject identity, non-projection posture, and injected authority assertions. It performs no remote context/ontology resolution.

Changed implementation:
- `arcs_verify/semantic_projection.py`
- `tests/test_semantic_projection.py`
- HARVEST2 boundary + acceptance docs

Connector-native build note: this environment had no local `gh` binary, so the branch was built through the connected GitHub API. CI/full repository validation remains the review gate.

DRAFT ONLY. DO NOT MERGE. DO NOT MARK READY.
