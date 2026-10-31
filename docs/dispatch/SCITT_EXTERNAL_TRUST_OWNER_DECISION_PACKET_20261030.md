# ARCS Verify — SCITT external trust: owner decision packet (AV-S2)

**Status:** PREPARED FOR OWNER DECISION · NON-OPERATIVE · DECIDES NOTHING · NOT A RATIFICATION · NOT FILED AS CANONICAL
**Lane:** AV-S2 (items 6–8) of [SCITT_EXTERNAL_TRUST_EXECUTION_20261024.md](SCITT_EXTERNAL_TRUST_EXECUTION_20261024.md). Item 9 waits for ratified policy and is not started.
**Prepared:** 2026-10-30, against the exact revisions in §1.
**Owner fields:** every decision below ends in an owner field marked **UNFILLED**. Nothing here takes effect until the owner records a separately filed decision; merging this document records a packet, not the decisions.

```text
AUTHORITY_MOVEMENT = 0 · RATIFICATION = NONE · TRUST_GRANT = NONE · KEY_USE = 0
SERVICE_SELECTION = 0 · ENDPOINT_APPROVAL = 0 · EGRESS = 0 · EXTERNAL_REGISTRATION = 0
SCHEMA_OR_VERIFIER_CHANGE = 0 · SUITES_OR_BUILDS_RUN = 0
```

## 0. How to read this packet

Seven decisions. T1–T5 narrow the open portable-trust question (D3 in the SCITT-DOCTRINE-RECON0 packet, R0 below). D4 and D4b keep that packet's egress numbering.

| ID | Decision | Section |
|---|---|---|
| T1 | Issuer and transparency-service roles | §3 |
| T2 | Public-key custody and the pin source for each key | §4 |
| T3 | Policy ownership: who may accept or reject an issuer or a service | §5 |
| T4 | Revocation and time treatment | §6 |
| T5 | Supported receipt profile (and statement-construction scope) | §7 |
| D4 | Egress classification of a registration submission | §8 |
| D4b | Definition of `no_derived_fingerprint_present` for hash-bearing payloads | §9 |

Each decision gives the question, the current state with cited authority, the concrete options, a recommendation, what adopting it would and would not authorize, and an owner field. Citations are `ref Lnn`, with refs pinned in §1. Every line number was printed from `git show <commit>:<path>` at the pinned commit. None was carried over from an earlier draft without being re-printed.

## 1. Exact sources

Most rows name private repositories. A public reader cannot resolve them; they are recorded so that the owner can.

| Ref | Repository @ commit | Path | Git blob | Status at that commit |
|---|---|---|---|---|
| P0 | `arcs-verify@ce9e0ffe8da6986dc1580bad912a2f84b190d890` (public `main`, re-read 2026-10-30) | `docs/dispatch/SCITT_EXTERNAL_TRUST_EXECUTION_20261024.md` | `90ec1caa` | Plan; this lane's mandate |
| V1 | same | `docs/scitt-offline/README.md` | `77389e25` | EXPERIMENTAL (#6) |
| V2 | same | `arcs_verify/scitt_registration.py` | `109242ac` | EXPERIMENTAL (#6) |
| V3 | same | `arcs_verify/contracts/scitt-registration/v0.1/local-selection.schema.json` | `d61407e0` | EXPERIMENTAL local input |
| V4 | same | `stranger0/README.md` | `d6a561fd` | STRANGER0 receiver package (#8) |
| E4 | `garp-doctrine@1ff268684600b5f4ca81f1f61d5858e796c5bb3a` (`main`, 2026-10-30) | `docs/garp/ARCS_-_IN___GARP_Governed_Egress_Doctrine_v0_4_MAY16.md` | `69a61c56` | `canonical` in registry. Blob identical at `85e2f419` and at #449's merge `40740cb1` |
| G2 | same | `docs/internal/ARCS_-_IN___SRS_External_Standards_Interoperability_And_Extension_Governance_v0_1_2_JUL18.md` | `03050132` | `ratified`; sha256 equals registry `ratified_digest` `6b206181…6349` |
| G4 | same | `docs/garp/ARCS_-_IN___GARP_Compartmentalization_Egress_Resolution_v1_1_MAY16.md` | `83c6fb5c` | `canonical` |
| G6A | same | `docs/internal/IN___PRODUCTION_SIGNER_BINDING0_Design_Ratification_Record_v0_1_OCT02.md` | `8741d76e` | `ratified`; sha256 equals registry `d5fe8952…5c55d` |
| G6B | same | `docs/internal/IN___PRODUCTION_KEY_PROVISION0_PREP_Design_Ratification_Record_v0_1_OCT03.md` | `19aa8de2` | `ratified`; sha256 equals registry `0bcae033…ac68` |
| ACT0 | same | `docs/internal/IN___PUBLIC_PUBLICATION_ACT0_Ratification_Record_v0_1_OCT01.md` | `81319051` | `ratified`; sha256 equals registry `f853ec0e…1470` |
| BTE | same | `docs/internal/IN___DAGR_Browser_Trace_Evidence_Doctrine_v0_1_JUL19.md` | `ddd98763` | `ratified` 2026-07-20 in registry; sha256 equals `ratified_digest` `adb11cda…c1d4`. Its frontmatter still says Draft; the registry governs |
| R0 | same | `docs/internal/IN___SCITT_DOCTRINE_RECON0_DECISION_PACKET_2026_10_23.md` | `26cacc14` | Landed as #449 (`40740cb1`); RECONCILIATION ONLY / NON-OPERATIVE |
| S1 | `arcs-srs@cded2ca533f62d4d7672aa30ecad2ecf9a17784f` (`main`) | `conformance/bindings/srs.scitt.registration.v0.1/binding-rules.json` | `e2ebb804` | LANDED / PROVISIONAL; blob identical at `c91ee0e7` |
| S2 | same | `conformance/bindings/srs.scitt.registration.v0.1/verifier-handoff.json` | `cc38372c` | `CANDIDATE_NOT_ACCEPTED`; blob identical at `c91ee0e7` |
| S3 | same | `schemas/trust-bundles/v0.2/trust-bundle.schema.json` | `37a3d27b` | Landed schema |
| S4 | same | `docs/integrations/SRS_SCITT_REGISTRATION_ACCEPTANCE_GAPS_2026_10_13.md` | `c92094cc` | Gap record G01–G08 |
| B1 | `dagr-mcp@b251a1c4cd4b0cb11020101bd78490f4649ecac9` (`main`, #179) | `docs/CAPTURE_WITNESS_PUBLISHER.md` | `24952c88` | BAGR publisher documentation |
| B2 | same | `dagr_mcp/capture_witness_publisher.py` | `a5e9d83c` | BAGR publisher |
| B3 | same | `tests/fixtures/capture-witness/signed_statement_kat.scitt_cose_0_5_0.json` | `346c3cdf` | TEST-ONLY known-answer vector |
| B4 | same | `tests/fixtures/capture-witness/acquisition_binding_digest_only.v0_1.json` | `9198d826` | Literal Acquisition producer output |
| C1 | `counterpedia-acquisition@3881ccb04575c0900917e5d98489065bae945c7e` (`main`, #457) | `src/acquisition/capture_witness.py` | `c98f3e04` | Capture-transparency binding |
| C2 | same | `src/acquisition/capture.py` | `36c00cfb` | `CaptureReceipt` |
| C3 | same | `src/acquisition/ids.py` | `fb48f0da` | Identifier rules |
| C4 | same | `docs/CAPTURE_WITNESS.md` | `e135992c` | Acquisition documentation |

**Earlier drafts consumed.** The 2026-10-23 decision-prep drafts are held outside any repository and were never filed. Their bytes matched their own `SHA256SUMS` on 2026-10-30:
- D4 draft: sha256 `51cca65b4eaf6ccff925d2c6894cd94c8639160adf644c824aea1adf23acb358`. This packet supersedes it for D4 and D4b; §10 lists the corrections.
- D3 draft: sha256 `4edcca2c0d1434fbb4498f8321876913ed7b4bef8f19e0344d40a9b461ad5171`. Its sub-decision D3-0 is a dependency in §11. Its line citations into ARCS Verify modules were **not** re-verified here.

## 2. Keep separate

- **Code defect "D4" ≠ egress decision D4.** The hostile `int`-subclass status defect fixed by dagr-mcp #179 (`b251a1c4`) and counterpedia-acquisition #457 (`3881ccb0`) shares the label only. Closing it resolves no egress authority, no classification and no fingerprint question.
- **External trust (this lane) ≠ local cryptographic acceptance (lane AV-S1).** This packet decides nothing about whether a signature or proof verifies. Where it reports a fact about bytes (the decoded header in §4, the subject value in §7), that is an input to a decision. It is not an executed compatibility result.
- **Local policy pass ≠ external authoritative policy** (P0 L7). Under V2 L357–358 and L407–408, a trust finding of `pass` means only that the caller's local selection said `accept`.
- **Registration ≠ ratification. Landed ≠ effective. Emitter assertion ≠ independently recomputed finding.** BAGR's `registered` state is transport-grade, never verified inclusion (B1 L123–126).

## 3. T1 — Issuer and transparency-service roles

**Question.** What are the two trust roles, what may each be, and how is each identified?

**Current state.**
- The SRS binding defines the statement issuer as the party that signed the Signed Statement, named by protected CWT `iss`. It is not necessarily the SRS receipt's issuer or key, and not the submitting client; the binding records no submitter (S1 L217–224).
- Service identity comes from the authenticated Receipt, matched against verifier-selected trust material, never from carrier hints (S1 L230).
- The handoff requires two separate findings, `statement_issuer_trusted` and `transparency_service_trusted`. Both default to `not_evaluated` and are evaluated only with verifier-selected trust input (S2 L110–117).
- ARCS Verify's experimental input already separates the roles `statement_issuer` and `transparency_service`, each with an identity and a public key (V1 L84–92). It is explicitly not a portable contract (V1 L77–79; V2 L68–75).
- The plan requires separate roles and forbids auto-trusting a supplied key (P0 L19).
- A native attestation keeps its own issuer, trust policy and verification path (G2 L236). An SRS issuer must not restate it as original authority (G2 L303).
- BAGR has no issuer of record. The signer sits in dagr-mcp under owner ruling ACQ-CAPTURE-WITNESS-AUTHORITY0 (B1 L3–6; C4 L82–97), but the `issuer` string is a caller-supplied constructor argument (B2 L487–509). The only concrete value in the estate is the test identifier `did:web:dagr.example` in the known-answer vector (B3).

**Options.**
- **T1-a.** Two separate functional roles: `statement_issuer` (signs Signed Statements) and `transparency_service` (signs native Receipts). Each role has its own keys, trust entries and policy decision. No key may hold both roles.
- **T1-b.** One combined "SCITT trust" role and key list. This collapses the two findings S2 requires, and lets any consumer that does not branch on role read a service key as an issuer key.
- **T1-c.** Service trust derived from issuer trust ("trusted because our issuer chose it"). This is self-authorized trust.

Sub-decision **T1.1, issuer identity form:**
- (i) A stable institutional identifier, pinned with its key in a trust input (G6A L73–77 is the precedent: distinct from every test issuer, and denoting only which signer attests).
- (ii) A `did:web` identifier resolved over the network. Resolution is key discovery, which V2 L203 does not support, and the resolution request is itself an outbound act.
- (iii) X.509 `x5chain` / `x5t`. Certificate validation and chain discovery are unsupported (V1 L172–173), so this is a NOT_SUPPORTED gap under T5.

Sub-decision **T1.2, BAGR issuer of record:**
- (i) A dedicated capture-witness issuer identity, distinct from every SRS `issuer_id` and from the production `public_publication` issuer.
- (ii) Reuse an existing issuer identity. B1 L203 and L206–210 forbid wiring this plane to the `public_publication` signer without a separate act, and G6A L45–46 limits G6A to that profile's signer.

Sub-decision **T1.3, service-operator independence.** A registration does not establish external witnessing (G2 L655) or service custody (R0 L122).
- (i) Record the service operator's relationship to the issuer as a declared attribute of the trust entry, and label a same-operator service non-independent.
- (ii) Ignore operator identity.

**Recommendation.** T1-a; T1.1 (i); T1.2 (i); T1.3 (i). Accept a `did:web` string only as a name: trust comes from the pinned key, never from resolution.

**Would authorize:**
- arcs-srs to specify role-typed trust entries, once T3 assigns that seat;
- ARCS Verify to keep two separate trust findings;
- the BAGR producer owner to plan a dedicated issuer identity.

**Would not authorize:** any identity value, key, service, trust grant, endpoint or registration. It does not change the binding or the verifier.

| T1 owner field | Value |
|---|---|
| Decision (T1-a / T1-b / T1-c / amend / hold; T1.1, T1.2, T1.3) | **UNFILLED** |
| Owner identity and authority | **UNFILLED** |
| Effective from | **UNFILLED** |
| Carrier (record path, PR) | **UNFILLED** |

## 4. T2 — Public-key custody and the pin source for each key

**Question.** Who holds each key, and where does a verifier or receiver obtain the public key it pins?

**Current state.**
- The BAGR publisher generates no key, reads no environment and persists nothing; the private key is caller-injected (B1 L199–206; B2 L480–485).
- Bundling a public key does not establish trust in it (S4 L120–121). A key a caller supplies does not establish trust (R0 L119).
- The ratified precedent for the `public_publication` signer is as follows. G6A §3.3 requires a single, named, separate custody role (G6A L85–90) and a governed, versioned, retentive trust-material path (G6A L119–126). G6B-PREP0 sets storage requirements: the key stays outside the repository and outside artifacts, access is role-restricted, and there is an audit trail (G6B L85–96). A functional custody role is named at G6B L75–83. **Both records govern only the `public_publication` signer (G6A L45–46): precedent, not delegated authority.**
- **Decoded fact (input, not an AV-S1 result).** The known-answer statement's 54-byte protected header (B3 `expected.statement_hex`, decoded by hand) is `{3: "application/json", 15: {1: iss, 2: sub}, 1: -8}`, and its unprotected header is empty. It carries no `kid` (4), `x5chain` (33) or `x5t` (34).
  - The statement therefore carries no in-statement key reference. It does not satisfy the SRS binding's key-reference requirement: `kid`, unless `x5t` or `x5chain` is present (S1 L131–150).
  - Explicit, versioned, out-of-band public-key selection remains possible. ARCS Verify's adapter accepts an explicitly selected public key and binds that key's SPKI digest into the evaluation context (V2 L92–98, L116–119). It has no time policy (V2 L120), so it does no validity-window selection either.
  - The narrower result: nothing in the statement names its key, so key choice and rotation rest entirely on the out-of-band selection and its versioning. G6A L79–83 (a rotation-addressable `key_id`) is precedent.

**Keys and options.**

| Key | Options | Recommendation |
|---|---|---|
| **K1** statement-issuer private key (the BAGR signing key) | (a) A new functional custody role dedicated to capture-witness / SCITT signing, separate from G6B §4's role, with G6B L85–96's storage requirements applied by analogy. (b) Assign it to G6B §4's role with a distinct key; key reuse stays forbidden (B1 L203), and G6A's scope means a new act is needed anyway. (c) Leave it held by whoever deploys, with no governed custody (today's state). | **(a)** |
| **K2** statement-issuer public key (verifier / receiver pin) | (a) A versioned, retained trust input in a sibling external-attestation contract under G2 §5.5 (G2 L325–327). arcs-srs owns its shape (R0 L189); the K1 custody role authors its content updates, on the G6A L119–126 precedent. (b) Receiver-controlled trust input only: each receiver pins through its own channel (V4 L57–62). (c) Discovery from the issuer identity (DID document, key set or certificate chain). | **(a) as the published candidate source, with (b) deciding reliance.** Never (c): unsupported (V2 L203; V1 L172–173) and forbidden as trust (P0 L19). |
| **K3** transparency-service Receipt-signing key | (a) Obtained out of band from the operator and recorded in the versioned trust input with source, date and SPKI digest before any registration. (b) Fetched from the service's key endpoint at verification time. (c) Certificate / CCF identity. | **(a).** (b) is a network act needing its own owner authority (P0 L26) and is discovery. (c) is a T5 NOT_SUPPORTED gap. |
| **K4** test keys (B3's label-derived Ed25519 seed; V1 L53 constructed material) | Must never be a trust anchor or used to register. | Restate as a standing rule. G6A L136 forbids test-key substitution on the precedent path. |
| **K5** SRS emitter keys and the `public_publication` production signer | Out of scope for SCITT. | No reuse (B1 L203, L206–210; R0 L190). |

Sub-decision **T2.1, key identifier in a registered statement:**
- (i) Require `kid` (or a certificate reference, under T5) in any statement profile accepted for registration. That is a producer change, a separate act not authorized here.
- (ii) Permit statements without `kid`, relying solely on explicit, versioned out-of-band key selection. Such statements stay outside the SRS binding's key-reference requirement.

**Recommendation.** K1 (a); K2 (a)+(b); K3 (a); K4 and K5 as stated; T2.1 (i).

**Would authorize:**
- designing the custody role and the trust-input content procedure;
- arcs-srs to draft the sibling contract (after D3-0, §11);
- the BAGR owner to plan the `kid` change.

**Would not authorize:** generating, storing, moving or using any key; selecting a secret backend; publishing or updating any trust input; naming a role holder; retrieving any service key.

| T2 owner field | Value |
|---|---|
| Decision (K1–K5 options; T2.1) | **UNFILLED** |
| Owner identity and authority | **UNFILLED** |
| Effective from | **UNFILLED** |
| Carrier (record path, PR) | **UNFILLED** |

## 5. T3 — Policy ownership: who may accept or reject an issuer or a service

**Question.** Who decides that an issuer or service is accepted or rejected in its role, where that decision lives, and what happens when there is none?

**Current state.**
- The binding leaves submission, disclosure, choice of service, retry on another service and key use to "whoever governs the deployment", and that party is unnamed (S1 L317–318).
- R0 asks for normative trust semantics to be separated from concrete verifier selection and deployment policy (R0 L92). It places the trust-bundle wire shape with arcs-srs, after D1 (R0 L189).
- STRANGER0 states the reliance model: whether anyone should rely on a finding is a different record, by a different party, under that party's own trust input (V4 L9–12, L57–62).
- ARCS Verify records a caller's local `accept` / `reject` per role and does not discover or infer policy (V1 L84–92; V2 L83–88). A service key under `reject` can still establish inclusion while service trust fails (V1 L89–90).
- The plan asks for independent issuer/service policy owners (P0 L33).
- Egress sign-off is destination-bound, and cross-destination promotion requires a new proposal (E4 L98). Delegations are typed; high-stakes classes stay per-event (E4 L100).

**Options.** These are three separable seats; one owner may hold more than one, but each is recorded separately.

| Seat | Options | Recommendation |
|---|---|---|
| **3.1** Normative trust semantics and the trust-input wire shape | (a) arcs-srs, under G2 §5.5. (b) garp-doctrine directly. (c) ARCS Verify. | **(a).** Not (c), keeping syntax apart from authority. ARCS Verify may define a local selection format and compute findings from it. It must not silently turn that format into portable policy authority, or auto-select trusted principals. R0 recognizes the local selection without ratifying it or granting service trust (R0 L77, L92). |
| **3.2** Submission side: may a BAGR deployment register to this service? | (a) The governed egress / runtime owner, through per-event, destination-bound sign-off (E4 L98, L100; R0 L135). (b) The deployment operator alone (today's unnamed default). (c) ARCS Verify. | **(a)** |
| **3.3** Reliance side: does a receiver accept this issuer or service in its role? | (a) Each receiver, under its own trust input (V4 L57–62; G2 L236). (b) An estate-published accepted list, offered as candidate input that binds no receiver. (c) ARCS Verify defaults. | **(a), optionally fed by (b).** Never (c): the experimental input is explicitly not a portable contract (V2 L68–75). |

**Procedure when no policy exists (recommended rule).**
- On the reliance side, the trust finding stays `not_evaluated` (S2 L110–117; V1 L88–89). There is no default `accept`, and possession of a key never becomes a pass (P0 L19).
- On the submission side, no policy means refusal before transmission (R0 L121; S4 L142–146).
- A policy change is a governed, attributable, versioned update with prior states retained (G6A L119–126 precedent).
- Policy values are three-state: `accept`, `reject`, or absent (→ `not_evaluated`).

**Would authorize:** naming the owner of each seat and adopting the no-policy rule.

**Would not authorize:** any accepted issuer or service, any policy content, any change to verifier defaults, any delegation.

| T3 owner field | Value |
|---|---|
| Decision (seats 3.1, 3.2, 3.3; no-policy rule) | **UNFILLED** |
| Owner identity and authority | **UNFILLED** |
| Effective from | **UNFILLED** |
| Carrier (record path, PR) | **UNFILLED** |

## 6. T4 — Revocation and time treatment

**Question.** How are time and revocation evaluated, given that authenticated registration time is currently `not_evaluated`?

**Current state: time.**
- The binding requires an authenticated time assertion: one covered by the Receipt's verified signature, defined by the selected proof profile and accepted by a selected time policy. It assumes no Receipt carries one (S1 L287–291).
- Unauthenticated times never support a bound (S1 L294). A registration time does not equal `issued_at`, is not independently witnessed, and does not establish issuance or capture time (S1 L296–298).
- The handoff makes the time finding `not_evaluated` when no profile defines an authenticated time or no time policy is selected (S2 L96–107). A time seen only outside the signature is reported as unauthenticated (S2 L180–182).
- ARCS Verify has no time policy: `time_policy` is `None` (V2 L120), findings start `not_evaluated` (V2 L215–216), and the file never assigns `registration_time_authenticated` (0 occurrences in V2). Even a protected `iat` does not establish a bound (V1 L179–184).
- The plan forbids inferring trusted time from unsigned timestamps (P0 L21). No timestamp authority or new proof family is authorized (S4 L178–181).

**Current state: revocation.**
- On the G6A precedent, revocation withdraws current trust in a versioned, retained trust state and never rewrites the past. Historical verifiability is never claimed from `issued_at` alone (G6A L103–117; G6B L108–117).
- Trust bundle v0.2 carries a per-key `revocation` object: a revoked key is untrusted even when the cryptography verifies (S3 L148–168).
- The ARCS Verify local input has no revocation field (V1 L84–92). STRANGER0 excludes revocation and a trusted clock (V4 L257–258).

**Options: time.**
- **T4-t-a.** Keep `registration_time_authenticated` = `not_evaluated`. Prohibit time claims from CWT `iat`, sidecar hints, HTTP `Date`, transport timing or SRS `issued_at`.
- **T4-t-b.** Adopt a proof profile that defines an authenticated registration time, with a named time-policy owner and policy (S1 L290–291). This needs a service whose Receipt profile defines one; none is identified.
- **T4-t-c.** Independent time attestation under a separately governed clock. This would be new authority (S4 L178–181).

**Options: revocation.**
- **T4-r-a.** Current-state trust withdrawal in the versioned, retained trust input (T2 K2/K3), on the G6A L103–117 model and with S3's revocation semantics.
- **T4-r-b.** Online status checking (a revocation list or status endpoint). This is a network act and discovery; unsupported.
- **T4-r-c.** No revocation (a static keyring), acceptable only as a labelled limitation of offline fixtures (V4 L257–258).

**The interaction the decision must state.**
- While time is `not_evaluated`, there is no authenticated registration time to compare with a revocation instant.
- A trust finding can therefore be evaluated only against a named trust-input version.
- A claim that a statement was "registered before revocation" or "valid at registration" stays `not_evaluated`.
- After a compromise revocation, every statement under that key fails trust in the current state, and no historical-validity claim is available.

**Recommendation.** T4-t-a, until T4-t-b is separately decided for a named profile. T4-r-a. Adopt the interaction statement as written.

**Would authorize:**
- ARCS Verify to keep time `not_evaluated`;
- version-scoped trust evaluation after T2/T3;
- the interaction statement as the reading of any trust finding.

**Would not authorize:** any time source, clock, timestamp authority, online status check, or claim of witnessed or anti-backdated time.

| T4 owner field | Value |
|---|---|
| Decision (time option; revocation option; interaction statement) | **UNFILLED** |
| Owner identity and authority | **UNFILLED** |
| Effective from | **UNFILLED** |
| Carrier (record path, PR) | **UNFILLED** |

## 7. T5 — Supported receipt profile (and statement-construction scope)

**Question.** Which native Receipt structures, and which statement constructions, are in the supported profile, and how is everything else reported?

**Current state.**
- The binding relies on inclusion proofs only; consistency is an auditor concern outside it (S1 L232–243).
- `RFC9162_SHA256` is specified, but no verifier has replayed a real Receipt of that kind (S1 L245–251).
- `CCF_LEDGER_SHA256` (draft-ietf-scitt-receipts-ccf-profile-05) has no assigned registry value and is `candidate_unpinned` (S1 L254–259). An unsupported structure yields `not_evaluated` (S1 L262). A Transparent Statement is not carried (S1 L263).
- ARCS Verify supports tagged COSE_Sign1 with Ed25519, ES256 or ES384 and `RFC9162_SHA256` only. CCF, other structures, certificate validation, critical Receipt CWT semantics and untagged COSE stay explicit gaps (V1 L170–177; V2 L113, L203).
- The plan says to model CCF or certificate-path requirements as an explicit, versioned NOT_SUPPORTED / NOT_EVALUATED gap, never coerced into RFC 9162 (P0 L20).
- **Two statement constructions exist, and only one is bound.**
  - The SRS exact-receipt construction (S1) requires `sub` to be the RFC 6920 `ni` URI of the exact artifact digest (S1 L164–165). ARCS Verify #6 implements this construction.
  - The Acquisition capture-witness construction that BAGR signs has a different shape. It attaches the whole binding JSON as payload (C1 L314–315; B2 L545–553), and sets `sub` to the `capture_id`: `"cap_one"` in B3's decoded header.
  - The binding states that the capture-witness construction is neither an RFC 9995 hash envelope nor an SRS receipt, and is unchanged and unwired (S1 L17). R0 keeps the two constructions non-interchangeable (R0 L125).
  - This is an observation from bytes. AV-S1 owns any executed comparison.

**Options.**
- **T5-a.** RFC 9942 inclusion over `RFC9162_SHA256` only, with the algorithms and encodings above; consistency not relied on; no Transparent Statement.
- **T5-b.** T5-a, plus `CCF_LEDGER_SHA256` recorded as a versioned NOT_SUPPORTED gap (findings `not_evaluated`, structure and draft named) until a verifier implements and names it.
- **T5-c.** Accept whatever a chosen service emits, coerced into the RFC 9162 path.

Sub-decision **T5.1, statement-construction scope:**
- (i) The profile covers the SRS construction only. Capture-witness registration stays out of scope until it has its own binding and profile (the G04 gap: S4 L123 onward).
- (ii) Extend the profile to the capture-witness construction now. That first needs an owner-made binding for it.
- (iii) Treat the two constructions as interchangeable.

**Recommendation.** T5-b (which contains T5-a), and T5.1 (i). Reject T5-c and T5.1 (iii).

**Consequence to record.** Under T5.1 (i), no BAGR capture-witness statement can reach a supported verification path, so lane AV-S3 has nothing to register for that construction until T5.1 is revisited.

**Would authorize:** ARCS Verify to declare its supported profile and its versioned gaps; arcs-srs or Acquisition to scope a capture-witness binding as separate work.

**Would not authorize:** any service selection, any CCF implementation, any change to a binding or producer, any registration.

| T5 owner field | Value |
|---|---|
| Decision (T5-a / T5-b / T5-c; T5.1) | **UNFILLED** |
| Owner identity and authority | **UNFILLED** |
| Effective from | **UNFILLED** |
| Carrier (record path, PR) | **UNFILLED** |

## 8. D4 — Egress classification of a registration submission

**Question.** Under Governed Egress v0.4, which canonical class does a submission of a Signed Statement to a transparency service fall in?

**Authority (re-verified at E4, blob `69a61c56`).**
- Twelve canonical classes, each with its own checklist, TTL and sign-off mode (E4 L108–125). `public_publication` is at L115; `digest_export` is at L119, described as a bundle export to an authorized recipient set.
- High-stakes classes default to interactive sign-off (E4 L127).
- Every outbound surface routes through an egress decision (E4 L94). Sign-off is payload-bound (E4 L96) and destination-bound (E4 L98).
- Every egress event emits an SRS receipt (E4 L106, L154).
- `public_publication`: five locked affirmations (E4 L139–144), including `no_derived_fingerprint_present` at L142. Interactive sign-off, TTL 24 h, payload retained (E4 L209).
- `digest_export`: four affirmations covering the recipient set and bundle composition; TTL 1 h; payload retained (E4 L213).
- Editorial drift, noted only: L175 says "one of the eleven canonical classes".
- ACT0 defines a public-publication act as one exact artifact made publicly available at one declared destination (ACT0 L35–36). Its six seats — actor, proposal, authority, decision, execution, outcome — must not collapse (ACT0 L41–49). ACT0 does not define who may hold publication authority (ACT0 L73–75).
- Registration on a public service publishes the disclosed values and is permanent (S1 L316). Conformance never authorizes submission, disclosure, choice of service, retry or key use (S1 L317–318).

**What actually leaves.** A classification applies to the whole disclosure, not to its digest label (R0 L94; S1 L315):
- the statement payload. For capture-witness this is every binding field verbatim (C1 L214–229, L294–307), including a literal locator in `literal` mode;
- the protected header (`iss`, `sub`, and `kid` if present);
- request metadata: caller-supplied request headers (B2 L497, L570), plus network address and timing, which the binding does not constrain (S1 L309–313);
- the destination itself.

No production transport or egress path is composed in either producer repository (B1 L185–195; C4 L77–80).

**Options.**
1. **Publicly readable service** (anyone can read entries) → `public_publication`. The five locked affirmations, the six ACT0 seats and per-event sign-off apply, and the submission is treated as permanent.
2. **Service with an enumerated, authorized recipient set and no public read** → `digest_export` (E4 L119, L213). The operator is always a recipient, so this option requires evidence of the operator's read policy. Also requiring evidence that the operator can never widen readership later is a **PROPOSED stronger condition**: the cited recipient-set rule (E4 L119, L213) does not establish it. Without the evidence the owner requires, option 3 applies.
3. **Unknown or changeable readership** → classified as `public_publication`, the stricter case. *No doctrine line states this rule.* The nearest analogue is RE1 strictest-wins (G4 L60–68), which orders compartment and egress dispositions, not readership. Adopting option 3 is new doctrine, not a reading of existing doctrine.
4. **No thirteenth class.** The egress SRS receipt records the submission act and its sign-off. It is not native inclusion, and not the registration-event SRS receipt that the binding declines to define.
5. **Same statement, second service** → a new egress act with its own sign-off (E4 L98; S1 L318).

**Recommendation.** Adopt 1, 2 (with its evidence condition), 3, 4 and 5 together. For this hash-bearing SCITT submission, resolve the fingerprint classification before recording an affirmative answer to `no_derived_fingerprint_present`. This adds no restriction on unrelated publication work.

**Would authorize:** a classification rule that future egress proposals for SCITT registration must apply.

**Would not authorize:** any sign-off, destination, payload, service, key use or registration. It does not answer any affirmation, does not satisfy any ACT0 seat, and creates no delegation.

| D4 owner field | Value |
|---|---|
| Decision (options 1–5: accept / amend / refuse each) | **UNFILLED** |
| Owner identity and authority | **UNFILLED** |
| Effective from | **UNFILLED** |
| Carrier (record path, PR) | **UNFILLED** |

## 9. D4b — Defining `no_derived_fingerprint_present` for hash-bearing payloads

**Question.** When is a digest, or an identifier derived from one, a "derived fingerprint" under E4 L142?

**Facts.**
- **The term is undefined.** `git grep` over all of `garp-doctrine@1ff26868` finds it only as a list item: v0.3 L125 and v0.4 L142.
- **Capture-witness payload fields** (C1 L214–229, L294–307):

  | Field | How it is made | Locator oracle? |
  |---|---|---|
  | `source_locator_sha256` | Plain, unsalted SHA-256 of the locator (C1 L298) | **Yes.** Anyone who can guess the URL confirms it offline. |
  | `source_id` | `"src_"` + the first 32 hex characters of SHA-256 over canonical JSON `{"url": <locator>}` (C3 L78–105). `CaptureReceipt` refuses any `source_id` not so derived; "derived from source_locator only" (C2 L139–147). Recomputed for B4's fixture locator: equal to B4's `source_id`. `source_locator_sha256` hashes the locator's UTF-8 bytes directly (C1 L298); `source_id` instead hashes canonical JSON that contains the locator. | **Yes.** A second, independent oracle for the same locator. |
  | `capture_id` | By default the factory mints `cap_` + random UUID4 (C3 L52–54), as the field's default (C2 L100). That is a default, not an invariant: a caller may supply any value (C2 L100), the binding checks only length (C1 L256–263), and B4's own fixture uses `cap_one`. | Default-generated UUID4 values: no; they are random correlation handles (S1 L314). Caller-supplied values need field-level assessment, unless a provenance rule is explicitly enforced. Randomness is not a guarantee of the current contract. |
  | `binding_id` | `acq:transparency:sha256:` + SHA-256 over the canonical body, which includes `source_id` and `source_locator_sha256` (C1 L294–311) | **Yes, when kept beside a redacted body.** Anyone holding the remaining body fields and the original `binding_id` can rebuild the body for each candidate URL and compare digests. Reproduced with stdlib hashing: with both locator-derived fields withheld, B4's provenance locator reproduces B4's `binding_id` (`acq:transparency:sha256:5f1af280…2425b`); the same URL with a different query value does not. |
  | `capture_receipt_sha256` | SHA-256 of the canonical `CaptureReceipt` (C1 L306), whose preimage includes the locator and capture metadata | Depends on preimage entropy. Assess per field. |
  | `exact_bytes_sha256` | Digest of the captured bytes | Confirms content to anyone who already holds it. Assess per source. |
  | `source_locator` | Literal in `literal` mode; `null` in `digest_only`, the default (C1 L289; C4 L19–22) | Literal disclosure. |

  Today's schema requires both locator-derived fields: `source_id` and `source_locator_sha256` have no default (C1 L224–225), and extra fields are forbidden (C1 L217). The `binding_id` finding therefore concerns the proposed remedy. It does not show that the current implementation accepts a binding with those fields deleted.

- **SRS construction.** The payload is the SHA-256 of the exact receipt bytes, plus `iss` and key reference (S1 L304–306).
- **Ratified precedent in another domain.** BTE rules that a bare, unsalted hash of a low-entropy or identifying value is not sufficient redaction (BTE L169). It permits only a keyed, domain-separated HMAC or an opaque reference (BTE L171). It adds that a public-safe derivative needs a separate egress or publication determination, and that the keyed path governs retention, not disclosure (BTE L178). BTE governs browser-trace evidence: **precedent, not delegated egress authority.**

**Options.**
- **(i)** Any digest of protected material is a derived fingerprint. Public registration is then impossible without blinding, which changes the statement's subject construction.
- **(ii)** A digest, truncated digest, or identifier deterministically derived from one is a derived fingerprint when its preimage is low-entropy, guessable or enumerable by a plausible adversary.
- **(iii)** Field-level disclosure review per destination, recorded with evidence in the checklist answer.
- **(iv)** A remedy, not a rule.
  - The named precedent is BTE L171: a keyed, domain-separated HMAC over the value, or an opaque external reference resolvable only through a separately governed system. BTE L178 limits that exception to retention; it does not by itself establish safe publication.
  - Salted hashing is not established as equivalent: a disclosed salt still lets an observer hash candidate URLs.
  - Secret random blinding, or any other hiding commitment, is a separate proposal. It would have to specify its secrecy, entropy, custody and verification consequences.
  - Any of these changes Acquisition's binding and BAGR's statement, each by its own owner's separate act.

**Recommendation.** Adopt (ii) as the rule, (iii) as the procedure, and record (iv) as the available remedy. Concretely:
- every identifier deterministically derived from a non-public locator — today **both** `source_locator_sha256` **and** `source_id` — is a derived fingerprint;
- `binding_id` goes through the same preimage and disclosure analysis. Any separately versioned redacted or blinded construction must define its identifier over that construction, and must assess whether keeping an original-body identifier reintroduces the guessing oracle. The reproduction above shows that it does;
- a `digest_only` capture binding over a non-public locator cannot satisfy E4 L142 until the locator-derived fields are removed or replaced under (iv), with the identifier redefined over the new construction;
- the assessment covers the COMPLETE disclosed representation, including retained identifiers and digests: `capture_receipt_sha256` and `exact_bytes_sha256` go to the (iii) review per destination;
- default-generated `capture_id` values are random correlation handles, reviewed under (iii). A caller-supplied `capture_id` needs field-level assessment.

This is a doctrine decision, not an engineering detail.

**Would authorize:** a definition that egress checklists can apply.

**Would not authorize:** marking any payload as passing, changing any binding or statement (those are the producer owners' separate acts), or any registration.

| D4b owner field | Value |
|---|---|
| Decision ((i) / (ii) / (iii) / (iv) / combination / other) | **UNFILLED** |
| Owner identity and authority | **UNFILLED** |
| Effective from | **UNFILLED** |
| Carrier (record path, PR) | **UNFILLED** |

## 10. Corrections to the 2026-10-23 D4 draft

1. **Citations re-verified; none moved.** E4 L108–125, L115, L119, L139–144, L142, L154, L175, L209 and L213, and ACT0 L41–49, are unchanged. E4's blob is identical at `85e2f419`, `40740cb1` and `1ff26868`. The citations are now pinned to `1ff26868`.
2. **The locator has a second fingerprint.** The draft named `source_locator_sha256` as the field that fails, and its remedy removes or blinds that one field. `source_id` is an independent unsalted-hash oracle for the same locator (C2 L139–147; C3 L78–105; recomputed against B4). Under the draft's own recommended rule its remedy was insufficient, and §9 corrects it. A remedy must also account for `binding_id`, which commits to both locator-derived fields (C1 L294–311): keeping the original `binding_id` beside a redacted body reintroduces the oracle.
3. **The payload is the whole binding.** The draft described the capture-witness statement as carrying three digests. The BAGR statement attaches the entire binding JSON (B2 L545–553; C1 L314–315), so every binding field is disclosed verbatim.
4. **Metadata outside the statement.** The draft did not address request headers, network address and timing (B2 L497, L570; S1 L309–313). §8 does.
5. **"Unknown → public" is new doctrine.** No line states it, and RE1 (G4 L60–68) is an analogue only. §8 option 3 says so.

## 11. Dependencies and order (not an authorization)

1. **D3-0** (from the 2026-10-23 D3 draft) rules on the existing two-shape trust-material divergence. T2 K2/K3 and T3 seat 3.1 build on it.
2. **D1** (R0 L88) settles the relation mode for the SRS construction before an arcs-srs binding revision. T5.1 depends on the binding's scope.
3. **D4b before an affirmative L142 answer.** For this hash-bearing SCITT submission, resolve the fingerprint classification before recording an affirmative answer to `no_derived_fingerprint_present`. Unrelated publication work is not affected.
4. **T1–T5, then plan item 9.** Conformance vectors follow ratified policy only (P0 L22).
5. **AV-S3 stays held** until every row here is decided and the plan's own preconditions are met: one frozen endpoint, keys, policy, caps, expiry and evidence destination, plus explicit owner authority before network interaction (P0 L26). R0's order (R0 L241–247) also applies.

## 12. What this packet would and would not authorize, in total

**If every recommendation were adopted,** the owners of arcs-srs, ARCS Verify, BAGR (dagr-mcp) and Acquisition could design and propose the follow-on work, each in their own repository and under their own review:
- role-typed trust inputs;
- version-scoped trust evaluation;
- a declared receipt profile with named gaps;
- an issuer identity with `kid`;
- a separately versioned redacted or blinded capture binding, with its identifier defined over that construction;
- a classification rule for egress proposals.

**It would still not authorize:**
- selecting a service or approving an endpoint;
- generating, provisioning or using any key;
- publishing any trust input;
- any egress sign-off;
- any registration, network contact, retrieval of a service key, or production activation;
- any ratification or registry change in garp-doctrine.

Each of those remains its own deliberate act.

## 13. Method and limits

- **How sources were read.** Every source was read from Git objects at the pinned commit. Line numbers were printed from those exact bytes. Registry status and digests were recomputed from `registry/doctrine_registry.json` at `1ff26868`. PR states for #449, ARCS Verify #5–#8, dagr-mcp #179 and counterpedia-acquisition #457 were read from GitHub.
- **Three local recomputations.**
  - B4's `source_id` was recomputed from B4's provenance locator by the C3 rule, using Python `hashlib`.
  - B4's `binding_id` was rebuilt from B4's other body fields plus the provenance locator, using C1's canonical JSON form (sorted keys, compact separators, ASCII). It matched; a negative control with a different query value did not.
  - B3's protected header was decoded by hand from `expected.statement_hex`.
- **Not done.** No test suite, build, cryptographic verification, network-denied replay or service contact was performed for this document. AV-S1 owns local cryptographic compatibility.

## 14. Owner disposition summary

| Decision | Disposition | Owner / authority | Effective from | Carrier |
|---|---|---|---|---|
| T1 roles | **UNFILLED** | **UNFILLED** | **UNFILLED** | **UNFILLED** |
| T2 custody and pins | **UNFILLED** | **UNFILLED** | **UNFILLED** | **UNFILLED** |
| T3 policy ownership | **UNFILLED** | **UNFILLED** | **UNFILLED** | **UNFILLED** |
| T4 revocation and time | **UNFILLED** | **UNFILLED** | **UNFILLED** | **UNFILLED** |
| T5 receipt profile | **UNFILLED** | **UNFILLED** | **UNFILLED** | **UNFILLED** |
| D4 egress class | **UNFILLED** | **UNFILLED** | **UNFILLED** | **UNFILLED** |
| D4b derived fingerprint | **UNFILLED** | **UNFILLED** | **UNFILLED** | **UNFILLED** |
