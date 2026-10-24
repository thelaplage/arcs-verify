# stranger0: an offline receiver acceptance package

A stranger receives signed SRS receipts. It holds its own keys and its own
policy, supplied out of band. It runs the **existing** ARCS Verify verifier on
the receipt bytes, and then records **its own** reliance decision as a separate
record. This package makes that sequence executable, offline, for valid and
hostile receipts.

The point being shown: evidence that another party can verify without
surrendering the receiver's own authority. A verifier finding says what the
bytes are. Whether anyone should rely on them is a different record, written by
a different party, under that party's own trust input.

Nothing here changes verifier behaviour, schema pins, or the reserved
conclusions. The verifier is called through its existing entry points
(`arcs_verify.verifier.verify_receipt` and `arcs_verify.receipt_set.verify_receipt_set`),
and the receiver's recorded findings are checked against the existing
`arcs-verify` CLI output for equality.

## Run it

Python 3.11+ with the verifier's declared dependencies (`pip install -e .` from
the repository root). No network is used, and none is needed.

```bash
python3 stranger0/run_stranger0.py --out /tmp/stranger0-out
```

Exit code `0`: every case matched its stated expectation and no falsifier check
fired. `1`: a mismatch. `2`: a usage or package-integrity error (a pinned
fixture, a committed artifact, or `SHA256SUMS` does not match its bytes).
`--only CASE_ID` (repeatable) runs a subset; a subset run is labelled as such in
the transcript and does not apply the whole-catalog evidence checks.

The run writes `stranger0-out/stranger0-result.json` (the JSON result
transcript) and, per case, the receiver's three output files under
`stranger0-out/cases/<case_id>/`.

## What runs

```text
orchestrator (run_stranger0.py, stdlib only)
   |  for each case:  python -I receiver.py --verifier-root . \
   |                    --trust-input <receiver-controlled file> --receipt <bytes> [...]
   v
receiver process (receiver.py: stdlib + arcs_verify only; minimal environment)
   |  calls the existing verifier, unchanged
   |  writes, into its own out dir:
   |    verifier-findings.json      the verifier's output, unaltered
   |    reliance-decision.json      the receiver's decision, citing the findings by digest
   |    receiver-process-facts.json what this process actually loaded
   v
orchestrator reads the records, compares them with the case's stated expectation,
cross-checks the findings with the existing CLI, evaluates the falsifier checks.
```

The receiver is given exactly two kinds of input: receipt bytes and one trust-input
file. The trust input holds the receiver's keyring, the receipt versions and
profiles it accepts, its acceptance policy (issuers, boundaries, policy packs,
and the two linkage settings below), and a ledger of receipts it has already
relied on. Keys or key claims that travel inside a
receipt are never trust input.

### The two linkage settings

Both are required in the trust input; neither has a default, so no receiver
silently gets one reading or the other.

| Setting | What it requires |
|---|---|
| `require_admission_link_for_outcome` | the referenced admission must **arrive** in the submission |
| `require_relied_admission_for_outcome` | additionally, **this receiver must have relied on it** |

These are different questions, and the second is the stricter one. With it
`false`, a separately verified outcome may be relied upon while the admission it
references was refused: that is the narrower, arrival-only reading, and
`cases/trust/receiver-arrival-only-linkage.json` keeps it reachable. Every run
states which reading it applied, under `effective_linkage_policy` in
`reliance-decision.json`.

Under the strict setting an outcome is relied upon only if the admission it
references is present, carries the same `logical_call_id`, is the only receipt in
the submission with that receipt id, and was itself relied upon. A matching
receipt id is not enough, and neither is the receipt-set linker's own arrival
finding: the requirement establishes the dependency itself rather than waiting for
a sibling check to fire. The dependency is resolved from the whole submission
after every receipt has a provisional decision, so the result does not depend on
the order the receipts arrived in.

A referenced admission that never arrived stays `insufficient_evidence` under
`chain.admission_receipt_unresolved` — missing evidence, not a refusal. One that
arrived and was not relied upon is `do_not_rely` under
`chain.admission_not_relied_upon`, which names the admission's receipt id and the
state that disqualified it. Requiring reliance without requiring arrival has no
reading, so the trust input refuses that combination instead of guessing.

Declining to rely on an outcome says nothing about whether the underlying action
occurred. It is this receiver's decision about this evidence, under its own policy.

One detail worth knowing: the existing receipt-set verifier accepts exactly one
workflow-index schema identifier, and that identifier names a demo workflow. The
receiver builds the index itself, from the bytes it was given plus its own
keyring, and uses it only to obtain the existing admission/outcome linkage
findings. The identifier is a wire string that verifier requires; it is not a
claim that the receipts came from that workflow, and the index is never an
authenticity claim.

### The two records

| Record | Written by | Says |
|---|---|---|
| `verifier-findings.json` | the receiver, quoting the verifier | the eight Booleans, the distinct `chain_status`, failure codes, exactly as the verifier produced them; plus the existing receipt-set linkage findings |
| `reliance-decision.json` | the receiver, under its own policy | per receipt: `rely`, `do_not_rely` or `insufficient_evidence`, with reason tokens, and for `rely` a stated claim plus what is *not* relied upon |

A `rely` needs the verifier's own `passed` to be true and no receiver reason
against it. It never means the real-world event occurred, that the underlying
action was approved or completed, or that the issuer's assertions are true; each
`rely` record says so in `not_relied_upon`.

Reason tokens that originate with the receiver: `verifier.not_passed`,
`verifier.no_findings_produced`, `input.malformed_json` (and `input.not_utf8`,
`input.not_an_object`), `policy.receipt_version_not_accepted`,
`policy.profile_not_accepted`, `policy.issuer_not_accepted`,
`policy.boundary_not_accepted`, `policy.policy_pack_not_accepted`,
`replay.duplicate_in_submission`, `replay.already_relied_in_ledger`,
`replay.receipt_id_conflict`, `chain.admission_receipt_unresolved`,
`chain.admission_outcome_linkage_mismatch`. Verifier failure codes
(`signature_invalid`, `key_id_unresolved`, `key_untrusted`,
`raw_content.forbidden_key:<key>`, ...) are carried through unchanged in the findings.

## Cases

44 cases, 61 receipts. Every negative family has at least one positive control,
and each negative states which single variable it changes relative to its
control (`isolation` in `cases/cases.json`). The orchestrator checks those
isolation claims against the actual input bytes.

| Family | Hostile input | Why it must fail (stated, then checked exactly) |
|---|---|---|
| `body_tamper_after_signing` | a pinned refused receipt edited to `admitted` after signing; three pinned tamper vectors | only `signature_valid` fails; code `signature_invalid` |
| `wrong_key` | signed by a rogue key under a trusted `key_id`; an unknown `key_id` | `signature_invalid`; `key_id_unresolved` |
| `self_trust_embedded_key` | validly signed under a public key the receipt carries for itself, naming an accepted issuer | `key_id_unresolved`: the key is not in the receiver's trust input. A counterfactual control adds that key to the receiver's trust input and the same bytes are then relied upon, which isolates trust-input membership as the only variable |
| `trust_input_variants` | same pinned bytes under a receiver with no keys; under a receiver that marked the key untrusted | `key_id_unresolved`; `key_untrusted` with `signature_valid` still true |
| `unknown_version_profile` | unknown `receipt_version`; unregistered profile id; pinned version-binding vector | `profile.invalid_receipt_version`, `profile.unsupported_selection`, plus the receiver's own policy tokens |
| `chain_link` | outcome without its admission; outcome whose `logical_call_id` disagrees | `insufficient_evidence` (every single-receipt check passes); `chain.admission_outcome_linkage_mismatch` |
| `dependent_admission_reliance` | the referenced admission arrived but its signature fails; the same pair outcome-first; the admission declined from the receiver's own ledger with every verifier check passing; two receipts carrying the referenced id; a valid but unrelated admission | `chain.admission_not_relied_upon`, while the outcome's own verifier finding stays passing and is not converted to a failure. The unrelated-admission case keeps `chain.admission_receipt_unresolved`. A counterfactual control applies the arrival-only reading to the same bytes and relies on the outcome, which isolates the policy as the only variable |
| `duplicate_replay` | same bytes twice; a receipt already in the receiver's ledger; two validly signed receipts with one id | `replay.*` tokens; verifier passes in all three |
| `refused_deferred_honesty` | refused and deferred beside an admitted receipt and beside a forgery | none dropped; refusal is never described as admission; deferral is never described as approval |
| `metadata_only_violation` | validly signed receipts carrying `tool_arguments`, `result_body`, `access_token` | only `raw_content_exclusion` fails, `signature_valid` stays true |
| `valid_but_declined` | every verifier check passes; receiver policy declines the boundary, or the issuer | `policy.boundary_not_accepted`, `policy.issuer_not_accepted`; same bytes are relied upon under the default receiver |
| `input_integrity` | truncated, non-JSON bytes | `input.malformed_json`; no verifier findings exist, which is not a pass |

The transcript's `separation_matrix` counts every receipt by (verifier passed?)
x (relied upon?). The cell "verifier failed and relied upon" must be 0, and the
cell "verifier passed and not relied upon" is non-empty by construction.

## Falsifier

The package is falsified if either of these is observed in the run:

1. verification requires producer software or Counterpedia infrastructure; or
2. a passing signature is silently promoted to event truth or to receiver admission.

Check (1) inspects every receiver process: producer-named modules loaded (none
allowed), network attempts recorded by an in-process socket tripwire (none
allowed), `python -I` isolation, and a source scan that the receiver imports only
the standard library and `arcs_verify`. The detectors have positive controls:
`receiver.py --selfcheck` plants and imports a producer-named module, resolves a
name through the tripwire, and requires both to be detected. A tripwire is not a
sandbox, and the transcript records `is_a_sandbox: false`.

Check (2) requires that no `rely` exists without the verifier's pass, that every
`rely` names what it does not rely on, that no record carries a reserved or
truth-style conclusion key, and that there is evidence the check had something
to catch (valid signatures that were nonetheless not relied upon).

A clean result is reported as `NOT_FALSIFIED_IN_THIS_RUN`, not as proof.

## Fixtures and provenance

* **Pinned originals** are used in place from
  `packs/srs.mcp.sdk_enforcement/v0.1/normative/` (signed valid receipts, pinned
  mutation vectors, and the pinned trust bundle). Their digests are checked
  against that pack's own `manifest.json` on every run.
* **Synthetic derivations** (`cases/receipts/s0-*.json`, `n-*.json`) are pinned
  receipts plus a recorded list of edits, re-signed where the case needs a valid
  signature. `cases/artifacts.json` records, per file, the pinned source, its
  digest, the exact edit list, and the public key of the synthetic signer.
  `tests/test_stranger0_package.py` replays every derivation without any signer:
  apply the edits to the pinned source and compare everything except the
  signature value. The tamper case is checked to carry the source's own
  signature untouched.
* **Synthetic signing keys** are derived from public labels, are public by
  construction, and authenticate nothing. The signer that produced the re-signed
  receipts is deliberately **not** in this repository, because
  `docs/PRODUCING_RECEIPTS.md` states that this repository ships no emitter. Only
  its output and the provenance records are committed.
* **Trust inputs** (`cases/trust/`) are receiver-controlled files; the default
  one embeds the pinned issuer entry verbatim.

## Tests and mutation check

```bash
python3 -m pytest tests/test_stranger0_package.py tests/test_stranger0_receiver.py \
    tests/test_stranger0_independence.py tests/test_stranger0_run.py
python3 stranger0/mutation_check.py --out /tmp/stranger0-mutation.json
```

`mutation_check.py` applies each mutant to a scratch copy of the tree, asserts
the edited text occurs exactly once, shows the diff, runs the target tests on the
unmutated copy (must be green) and on the mutant (must be red), and reports any
survivor. Run heavy suites one at a time.

`stranger0/SHA256SUMS` lists every file in this directory except itself.
`python3 stranger0/run_stranger0.py --out DIR --write-package-sums` rewrites it,
and every run refuses to proceed if it no longer matches.

## What this does not show

* An OS-level network sandbox (only the in-process tripwire was used).
* Independent verification: the verifier ran in another process, which is the
  same code, not independent code.
* Real producer-emitted receipts: every receipt is a pinned test vector or a
  synthetic derivation of one.
* A trusted clock, revocation, key rotation, or trust-anchor governance beyond a
  static receiver-supplied keyring.
* Parser-differential inputs (duplicate JSON keys, non-standard constants).
* SCITT or any transparency-service evidence.
* Live federation, external publication, production activation.

`not_evaluated` is not a pass and `not_applicable` is not a pass: the
`chain_status` of a standalone receipt is reported as the verifier reports it
(`not_applicable`), and the receipt-set linkage result is a separate finding.
This package is test evidence, not a legal opinion or a regulatory certification.
