# Experimental offline SCITT verifier candidate

This opt-in ARCS Verify draft implements the native verification path for the
landed SRS SCITT binding. It emits the proposed seven separate findings. It does
not establish owner acceptance, standards ratification, production readiness,
or a real registration. The copied handoff remains `CANDIDATE_NOT_ACCEPTED`;
its historical execution note describes the SRS delivery, before this experiment.

## Reproduce offline

Prepare dependencies before disabling the network, using Python 3.11 or later:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r docs/scitt-offline/qualification-requirements.txt
.venv/bin/python -m pip install --no-deps -e .
```

The qualification run used Python 3.14 on macOS, with all dependency versions in
[qualification-requirements.txt](qualification-requirements.txt). Other Python/OS
combinations are not qualified by this run. The optional `scitt` group also pins
the three direct verification dependencies and the native backend commit.
Installing plain ARCS Verify does not install that optional backend.

On macOS, these commands execute under an OS network denial policy (dependencies
must already be present):

```sh
sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  .venv/bin/python -m pytest tests -q --basetemp=/tmp/arcs-scitt-replay-tests
sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  .venv/bin/arcs-verify scitt-registration \
  docs/scitt-offline/constructed/forward-sidecar.json \
  --artifact docs/scitt-offline/constructed/artifact.json \
  --selection docs/scitt-offline/constructed/selection.json
sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  .venv/bin/python tools/scitt_constructed_replay.py /tmp/scitt-constructed-replay
```

Use an equivalent OS/container network denial on another platform. A socket
connection attempt was separately confirmed to fail with `EPERM` under the macOS
policy. Adapter tests additionally fail on socket creation, name resolution, or
connection attempts. There is no retrieval, submission, key discovery, Check
wrapping, or capture-witness wiring in this entry point.

The retained [constructed fixture](constructed/) contains an artifact, two
independently signed statements, a native Receipt including only S1, role-specific
public keys and named local policy decisions, exact forward/reverse reports,
and SHA-256 checksums. The generator and tests use a separate COSE producer and
recursive Merkle implementation in `tests/scitt/material.py`, without importing
any native backend producer or adapter helpers. Cryptography and CBOR primitives
are shared dependencies; this is not a second implementation of Ed25519 itself.
All test keys/material are constructed, and the artifact is deliberately not a
claim of a valid SRS receipt. Separate regression tests use the existing valid
SRS golden fixtures. Nothing populates the reserved real-service T01 fixture.

## Findings and process exit status

Select `arcs-verify scitt-registration` or the Python API
`arcs_verify.scitt_registration.verify_registration` explicitly. The existing SRS
CLI route and SRS verifier are unchanged. An absent sidecar through the API
produces seven `not_evaluated` findings. No registration result gates SRS validity.

The experimental CLI exits **0 when it produces a report**, including reports
containing failures or unevaluated findings; it exits **2 on input/invocation
errors**. It does not use exit 0 to mean verified registration. Consumers must
inspect the named findings. No aggregate success field or source count is emitted.

Findings distinguish artifact binding, statement profile, statement signature,
receipt inclusion, registration time, issuer trust, and service trust. A valid
signature does not repair a profile violation, an artifact mismatch, or SRS
invalidity. Inclusion does not establish event truth, custody, time, consistency,
or authorization to disclose or submit anything.

## Minimal local selection input

[local-selection.schema.json](../../arcs_verify/contracts/scitt-registration/v0.1/local-selection.schema.json)
defines an experimental local input, not an extension to the SRS trust bundle or
a portable ecosystem contract. The `default` selection is used unless an entry
has a complete replacement selection under its zero-based index in `entries`.
Entry selections do not partially inherit defaults. Reordering entries requires
reordering their explicit selections. Carrier hints never select a key or policy.

Each role, `statement_issuer` or `transparency_service`, has an `identity` and a
PEM **public** key. An optional `policy` object contains a nonempty `id` and an
explicit `decision` of `accept` or `reject`. This records a caller's local policy
appraisal of that identity/key in that role; the adapter does not discover an
institutional policy or infer trust from possession of a key. Missing policy
means the trust finding is `not_evaluated`. A service key under a reject policy
can still establish inclusion, while service trust fails. Statement selection
must match protected `iss`; service identity is the explicit local identity
associated with the key that verified the Receipt, never the sidecar hint.

`proof_index` selects one proof from the Receipt's unprotected `396 / -1` array.
All proof shapes are validated, including unselected proofs. There is no fallback
to another proof or service key. JSON input rejects duplicate object keys and
unknown properties. The Python API uses `SelectedKey` and `Selection` with the
same roles and policies.

Complete result reuse is confined to one invocation and requires all three
actual byte digests plus the complete evaluation context to match. Context binds
selected proof, fixed profile, verifier version, backend commit, dependency
versions, both role keys (SPKI digests), identities and policy objects, explicit
absence of a time policy, and the SRS semantic pin. Results without target bytes
are never reused. Per-entry hints remain separate observations. Exact duplicate
JSON entries remain a carrier schema error. Relationship output is sorted by its
evaluation key; entry indexes and observations naturally reflect input order.

## Native path and qualification

The implementation reuses `scitt-cose` **0.4.0 at
`3d32059474b468f9cd851199a319d022aa38aef0`**, with `cbor2==6.1.4`,
`cryptography==46.0.7`, and `jsonschema==4.26.0`. Runtime guards verify these
versions and the hashes of every pinned backend Python source file. The SRS
contract files are hash-checked before interpretation. See
[source-pin.json](../../arcs_verify/contracts/scitt-registration/v0.1/source-pin.json).

SRS source is candidate `36338d3e80f3ea8d9e70294abd97ed27f20b6ecf`, landed as
`c91ee0e719fe7ccfd918ab16b4192e4bdeb216b6`; semantic digest is
`sha256:2b969c9e588f653c71088d24bb324ad4b2691a21922d5133e97ae0da981915f7`.
The three copied SRS files retain exact bytes and original labels.
ARCS Verify base is `9e6daefca6e77306691fd288880448194bd28f75`.

For RFC9162_SHA256, the leaf input is the **exact Signed Statement bytes**, not
the SHA-256 digest of those bytes. The adapter passes the explicitly selected
proof to the pinned native implementation, which reconstructs the root and
verifies its COSE signature. It also checks that an attached payload equals that
reconstructed root. This realizes the binding's inclusion requirement and the
[verification sequence in RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html#section-5.2.1).
It is not a claim of full SCITT service/profile conformance.

Source inspection and executed regressions identified two backend integration
hazards. The pinned backend can accept a signature over an attached payload even
when the selected statement reconstructs a different root. The adapter's explicit
root equality check prevents that false inclusion. Malformed nested `crit` labels
can raise `TypeError` in the backend; the adapter validates their shape before
invocation. Both are retained executable regressions. A subsequent technical
review also reproduced inclusion PASS for malformed Receipt CWT Claims and for
critical CWT semantics this adapter does not implement. Experimental verifier
version 2 validates the claim-map structure in both header buckets and refuses
critical CWT Claims. Well-formed noncritical claims remain uninterpreted metadata;
this does not introduce a time policy. See the [technical review](TECHNICAL_REVIEW.md).
No upstream issue or message was sent as part of this work.

The backend's own builder is not used by the adapter or its constructed producer.
Its generic published SCITT examples use statement-digest leaves; those examples
must not be mistaken for this binding's raw-statement leaves. Separately, **163
selected upstream tests passed with networking denied**, including the native
COSE, Merkle, Receipt, negative-conformance, hardening, envelope, published-vector,
RFC9162 vector, and COSE WG reference-vector modules. These qualify specific
primitives; they neither qualify the entire library nor close the attached-root
gap without the adapter guard. The complete upstream suite was not run.

To repeat that qualification, clone the backend before disabling networking,
check out the exact commit above, then run the nine modules listed in
[validation.json](evidence/validation.json) with this environment's Python.
The published COSE example is independently attributed to
[RFC 9052 Appendix C.2.1](https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C.2.1).
The constructed adapter probes complement those external known-answer tests.

## Executed evidence and remaining scope

[CASE_MATRIX.md](CASE_MATRIX.md) retains all 35 proposed handoff case identifiers,
links each to executed tests, and explicitly marks partial/unexecuted cases.
[evidence/](evidence/) contains the actual test logs, JUnit cases, native subset
results, package build log, and installed-wheel smoke results. The installed
smoke runs outside the source checkout, reproduces both retained reports exactly,
and exercises existing SRS verification and the DAGR CLI/contract goldens.

Supported cryptographic selections are Ed25519, P-256/ES256 and P-384/ES384 with
empty external AAD, tagged COSE_Sign1 and RFC9162_SHA256. Unsupported cases remain
explicit: CCF and other data structures, certificate reference/profile validation
or chain discovery, critical Receipt CWT semantics, other algorithms/curves, untagged COSE, and backend-rejected
non-minimal/indefinite encodings. Unsupported data structures and valid encodings
outside backend support do not become cryptographic passes. This bounded adapter
accepts at most 128 registrations, 16 proofs per Receipt, and 10 MiB per COSE
object; it is not a general hostile-service resource qualification.

There is **no registration-time policy implementation**. Unsigned CWT `iat` in
the Receipt and sidecar time hints are labelled unauthenticated observations;
even a protected `iat` does not establish an accepted registration-time bound.
Time findings remain `not_evaluated`. B03's alternate proof-profile/time-policy
contexts and T13's trustworthy registration-time premise are not fully exercised;
the partial status prevents claiming all 35 acceptance cases passed.

The existing owner decisions remain open: relation-mode reuse, ARCS Verify's
acceptance of the handoff, and portable trust inputs. The narrow vocabulary
question is recorded in the existing [SRS #94 decision record](https://github.com/thelaplage/arcs-srs/pull/94):
can `external_anchor` be reused for this relationship? Nothing here adopts
`transparency_registration` as a new mode or authorized synonym. The landed
labels stay unchanged. This draft adds executable evidence for owner review;
it does not decide those questions or address #93's G01–G08 capture-witness gaps.
