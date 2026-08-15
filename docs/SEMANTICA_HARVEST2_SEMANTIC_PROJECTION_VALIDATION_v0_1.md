# Semantica HARVEST2 — Semantic Projection Validation v0.1

**Status:** IMPLEMENTATION CANDIDATE / DRAFT PR
**AUTHORITY MOVEMENT = 0**

This check validates the structural conformance of a supplied Counterpedia semantic projection. A PASS means only that the supplied projection conforms to the declared semantic projection constraints checked by this verifier.

It does not mean the projection is true, admitted, published, evidentially verified, or granted standing. The verifier performs no network resolution and does not fetch remote JSON-LD contexts or ontologies.

The v0.1 implementation uses direct deterministic shape checks rather than adding a SHACL dependency. This keeps the authority and network boundary small while preserving a future path to a local, version-pinned SHACL engine if the projection contract grows.

## Non-goals

- evidence verifier replacement
- admission or publication
- ontology inference as truth
- auto-fixing projections
- remote context/ontology resolution
- graph database integration
- Semantica code import
