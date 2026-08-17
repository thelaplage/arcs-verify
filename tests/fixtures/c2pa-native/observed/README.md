# Observed-side fixtures

Every file in this directory is a **constructed producer observation**, not a
captured one, and each carries `"x_fixture_provenance": "constructed"` so the
label travels with the bytes.

## Why constructed

The `observed` side of this contract carries what a producer or third party
*asserts* about a C2PA subject. No such feed exists yet: the SRS native
observation receipt that will carry these assertions is a sibling lane that has
not landed. Until it does, there is no real producer observation to capture.

Constructing the observed side is legitimate in a way that constructing the
recomputed side would not be. The observed side is a **supplied input** whose
entire contractual status is "somebody asserted this, and the assertion carries
no independent weight." Fabricating a *native validator report* and presenting
it as a tool's output would be manufacturing evidence; supplying an assertion
that is explicitly typed as an assertion is what the input slot is for.

## The invariant these fixtures must not violate

The **recomputed** side of every test is always a genuine run of the pinned
native validator over the real specimen bytes — either live, or replayed from
`../frozen-native-reports/`, which are recorded outputs of that same pinned
validator. No recomputed side anywhere in this bundle is constructed.

So in every comparison test:

| side | origin |
|---|---|
| `observed` | constructed here, labelled `constructed` |
| `recomputed` | genuine pinned-validator output over real bytes |

## What these fixtures do NOT prove — a deferred obligation on PROV-PACK0

Constructed observations legitimately prove three things: that the optional
`observed` input slot works, that the comparison machinery produces the right
axis states and postures, and that comparability is recomputed rather than
asserted. Those are real proofs and they are not weakened by the fixtures being
constructed.

They do **not** prove **end-to-end producer→verifier interoperability**. No
producer has ever emitted an observation that this verifier then consumed. The
field names, the serialization, and the trust-basis and validator-identity
declarations on the `observed` side are this lane's own construction, so a real
producer could emit something this comparison mishandles and nothing here would
catch it.

That proof is **deferred to PROV-PACK0**, and it is owed once `SRS-C2PA-BIND0`
emits a real native observation artifact: take that producer's bytes unmodified,
feed them into this comparison, and show the axes resolve without adaptation. It
is recorded here so the gap is visible rather than assumed closed. Until then,
producer→verifier interoperability is **not evaluated**, and not evaluated is
not a pass.

## What each fixture exists to exercise

| File | Exercises |
|---|---|
| `CA-observed-matching.json` | all axes agree on a comparable basis |
| `CA-observed-trust-basis-delta.json` | identical bytes, different trust material — trust comparison must be `not_comparable`, never a divergence claim |
| `expired-observed-before-expiry.json` | a producer that observed the certificate while it was still inside its validity window, before the recomputation's wall clock passed the expiry — must not produce an integrity accusation |
| `XCA-observed-claims-binding-satisfied.json` | a producer asserting an asset binding that the recomputation finds failed, on identical bytes and an identical validator — the one case that reaches `possible_substantive_divergence` |
