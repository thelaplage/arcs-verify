# WAVE B — VERIFICATION-FINDINGS0

**Repo:** `thelaplage/arcs-verify`  
**Exact base:** `main@9a6bae99bfdba89eb700bd064ac485f2ac184d7d`  
**Branch:** `waveb/verification-findings0`  
**Posture:** DRAFT / DO NOT MERGE / `AUTHORITY_MOVEMENT=0`

## Mission

Add a deterministic, machine-readable **verification findings projection** over results ARCS Verify already computes. This is a projection of verifier observations/failure codes — not a second verifier and not a new verdict authority.

A verification finding answers "what check ran / what structural or cryptographic condition was observed?" It does **not** answer truth, source quality, authenticity of the underlying real-world claim, authorization, admission, standing, publication eligibility, or certification.

## Current neighbors / non-overlap

- Main already owns `READMISSION-CONTENT-DIVERGENCE0`; preserve its tri-state disclosure separate from `passed`.
- `#74 SRS-VNEXT-VERIFY0` is an open DRAFT independent verifier for external-profile receipts. Do not copy its candidate logic into this lane or make this projection depend on unmerged producer/runtime code.
- Existing stable failure-code registries remain the semantic source of failure identities. Do not invent synonymous codes for presentation.

## Core job

Inventory the result shapes emitted by current verifier families on this exact base. Design one compact closed projection that can represent their **already-computed** findings without importing producer code or re-running verification logic inside the projector.

Prefer a shape along these semantic lines, adapted to existing repo vocabulary rather than forcing new names:

- verifier family/profile;
- check/failure-code identity;
- observed status (`PASS`, `FAIL`, `NOT_EVALUATED` only if current result semantics genuinely support it);
- bounded human-readable explanation derived from registered code metadata, not free-form reinterpretation;
- exact artifact/field scope already named by the verifier result, when present;
- technical details sufficient to trace the finding back to the verifier result without embedding raw secret/input content;
- explicit `nonclaims`/boundary posture only if the repo already uses such structural metadata; otherwise keep it in docs/types, not duplicated into every row.

The projection must be deterministic and order-stable.

## Critical law

- `overall verifier PASS` does not erase individual checks/findings.
- one failure code may produce a finding; it must not be relabeled into a truth/quality score.
- `content_digest_comparison=DIVERGED` remains a disclosure/observation, not a verifier failure unless the existing verifier says so.
- absence of a check/result != PASS.
- unknown future failure/check codes fail closed or remain typed-unprojectable; never map to a generic reassuring label.

## Hostile tests

At minimum prove:

- exact same verifier result -> byte/deterministic finding projection;
- result ordering does not change canonical projected ordering;
- PASS findings and FAIL findings remain distinct without green=truth/red=false semantics;
- unknown/unregistered code is refused or typed unprojectable;
- missing/not-run check never becomes PASS;
- content divergence remains outside overall `passed` semantics;
- projection imports no DAGR/Counterpedia/producer runtime;
- secrets/raw receipt content are not newly surfaced by the projection;
- registered failure-code documentation remains in sync with any code identity exposed publicly.

## Public surface

A small library API and optional CLI/JSON projection are in scope. Do not add network transport unless this repo already exposes an equivalent verifier-result read service. Keep it independently consumable by a future Counterforum/Counterpedia presentation layer.

## Validation

Run focused tests plus the repository-wide failure-code registry tests and adjacent verifier-family tests touched by the projector. Run normal lint/type/static checks. Report exact commands/counts and distinguish exact-head local execution from hosted CI.

## Stop conditions

STOP rather than inventing cross-family semantic normalization if current verifier outputs do not share enough owned structure. It is acceptable to support only the verifier families whose outputs can be projected losslessly and return typed unsupported for the rest.

## Output contract

Implement on this same branch. Keep DRAFT. Prefer one bounded implementation commit after this dispatch commit. Update PR body with exact supported verifier families, files, head SHA, executed tests, and nonclaims. No ready flip. No merge.
