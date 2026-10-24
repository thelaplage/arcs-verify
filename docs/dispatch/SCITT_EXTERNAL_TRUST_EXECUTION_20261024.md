# ARCS Verify — SCITT external trust and public verifier acceptance plan

**Owner:** ARCS Verify, main snapshot `144a6954c0f4d35e5e00426a1be0ad435b32377b`. **Consumers:** ARCS SRS #92/#93/#94, [ARCS Verify #6](https://github.com/thelaplage/arcs-verify/pull/6) (landed experimental opt-in SCITT verifier), #5 public-release guard (code landed, publication still held). This is a test/owner-decision plan, **not a portable external trust standard**.

## Non-equivalences

Signed statement bytes ≠ accepted issuer. Native inclusion proof ≠ transparency service trusted. A present receipt ≠ verification success. Verifier finding ≠ proposition/event truth. A passing experimental local policy ≠ current external authoritative policy. SRS receipt publication ≠ ARCS-standard registration authority.

## Work package AV-S1 — Current exact local verifier compatibility

1. Pin exact public/private ARCS Verify main, SRS producer pin and `scitt-cose`/`cbor2`/`cryptography` versions before replay; verify no historical private source files or markers are included in a proposed public artifact.
2. Run the actual #6 `scitt-registration` adapter on known-answer Signed Statement, artifact and native Receipt bytes; separately test seven findings. Exercise the retained S1/P PASS and S2/P FAIL in both entry orders and repeated order; one good proof must never mask a bad one.
3. Mutate native CWT claims, critical header/payload semantics, unexpected proof/root/leaf, policy key identity, canonical artifact digest, qualified service/issuer identity and cache context. Unsupported semantics must refuse or remain `not_evaluated` without a global fake PASS.
4. Check CLI output contracts: exit 0 denotes a report (including failed findings), exit 2 denotes invalid invocation/input. Assert automation must inspect findings individually, not regard exit 0 as verification success.
5. Run executable test suites, independent raw bytes/source hashes and explicit mutation kills. Preserve default verifier/CLI behavior with no unannounced experimental path activation.

## Work package AV-S2 — External issuer and transparency-service authority decisions

6. Specify exact issuer and transparency **separate roles**, their public key custody, trust registry/pin source, valid date/time rules, revocation, service receipt profile, policy location and procedure for no policy. Do not auto-trust any public key merely because supplied.
7. Where real service requires CCF/certificate path validation or a different proof profile, model it as an explicit `NOT_SUPPORTED / NOT_EVALUATED` versioned gap; do not coerce it into RFC9162-only verification.
8. Do not infer trusted time from unsigned timestamps. A time requirement may remain `not_evaluated` until an independently governed clock/time attestation exists.
9. Add versioned producer/consumer conformance vectors only after ratified policy; ensure same exact signed bytes and native receipt digest and bounded verifier context survive independent process re-execution.

## Work package AV-S3 — External-service pilot/release (authority-gated)

10. Freeze one exact external registration/transparency endpoint, issuer keys, format/policy, operation cap, timeout/bytes/cost, expiry and non-secret evidence destination. Obtain explicit owner authority before network interaction.
11. Independently validate one real issued receipt, key/policy trust, inclusion and failure controls, alongside a revoked/wrong issuer failure. Verify cross-implementation output with separate verifier where actual independence can be achieved; same implementation run in another process is **not** independent code.
12. Execute the public-release guard on actual tagged artifact and package content. #5's merged guard does not authorize publishing: no new tag, PyPI/package upload, CDN promotion or transparency registration without owner approval.
13. Obtain external receiver-controlled acceptance before positioning the verifier as authoritative. Keep original local experimental diagnostics intact for comparison.

## Ownership and evidence

Use independent issuer/service policy owners, SRS producer maintainers, ARCS Verify cryptography author and separate receiver evaluator. Existing SCITT profile/standard and BAGR runtime are **not** silently extended. Exact tree, package dependency pins, executed suite counts/skips, intentional false-pass mutations, verified key/policy source, actual network request counts and each of the seven findings required in the final receipt.

**Holds:** operational keys and trust anchors, real registration, signed issuance, packaging/release and deployment. Local cryptographic conformance may merge through normal protected review independently.
