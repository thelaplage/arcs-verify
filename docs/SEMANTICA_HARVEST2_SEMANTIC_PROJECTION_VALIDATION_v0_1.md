# Semantica HARVEST2 — Semantic Projection Validation v0.1

**Status:** IMPLEMENTATION CANDIDATE / DRAFT PR
**AUTHORITY MOVEMENT = 0**

This check validates the structural conformance of a supplied Counterpedia semantic projection against the projection contract that projection declares.

A PASS means only that the supplied bytes are shaped as the contract requires. It says nothing about what they assert.

```
semantic validation != evidence verification
semantic validation != admission
semantic validation != publication
semantic validation != standing
semantic validation != truth
```

A conforming projection may describe a record that is unadmitted, unpublished, unverified, or simply wrong.

## Validated contract

The verifier targets the `counterpedia.semantic_projection.v0.1` contract emitted by the Counterpedia JSON-LD exporter over `GarpediaRenderedRecord`. It pins `@context`, `@type`, `schema`, and `source_schema_family`/`source_schema_version` **by value**, not merely by presence, and requires `@id` to be a stable non-blank governed identifier.

`authority_posture` is deliberately *not* pinned by value: NE-11 requires that a non-authority projection carry no authority-shaped field at all, so the verifier requires the key to be structurally absent. A projection that carries `authority_posture` with any value -- including a value that once looked "safe", like `projection_only` -- fails conformance.

Its forbidden-authority-key set is deliberately aligned with the producer's own guard, including `authority`. A projection the exporter would refuse to emit must not return PASS here.

## Report shape

The report follows this repo's existing conventions rather than introducing a parallel verifier framework: a `Conclusion` enum (`true` / `false` / `not_evaluated`), a frozen finding dataclass, and a `to_dict()` carrying `schema`, `verification_profile`, `findings`, and a `conclusions` map.

**Nine independent conclusions**, not one master Boolean. `passed` requires every gated conclusion to be TRUE. A defect fails its own conclusion and leaves the others standing, so a report distinguishes *what* failed.

`verification_reports_status` is a **distinct status string** (`valid` / `absent` / `invalid`) held outside the Boolean set, in the same spirit as `chain_status` in `verifier.py`. The collection is optional on the owning contract, so its absence is neither a pass nor a failure, and a malformed optional collection raises a finding without flipping the structural conclusions.

`verification_reports[].passed` is the upstream verifier's own assertion as carried by the projection. This module neither recomputes it nor gates on it: **an emitter assertion is not a recomputed finding.** A projection carrying `passed: false` is still structurally conformant.

## Limits

- `NOT_EVALUATED` is not PASS. `not_applicable` is not PASS. A default-constructed report passes nothing.
- Conformance of a projection is not conformance of the record it projects.
- The producer's declarations are checked as declared bytes; they are not corroborated against the record.
- No producer code is imported, and no remote context, ontology, or schema is resolved. The primary test fixture is real exporter output captured as bytes.

## Non-goals

- evidence verifier replacement
- admission or publication
- ontology inference as truth
- auto-fixing projections
- remote context/ontology resolution
- graph database integration
- Semantica code import

The v0.1 implementation uses direct deterministic shape checks rather than adding a SHACL dependency. This keeps the authority and network boundary small while preserving a future path to a local, version-pinned SHACL engine if the projection contract grows.
