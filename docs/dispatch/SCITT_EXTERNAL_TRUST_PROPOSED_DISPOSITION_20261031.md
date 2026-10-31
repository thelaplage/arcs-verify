# ARCS Verify — SCITT external trust: PROPOSED disposition (reviewer recommendation)

**Status:** PROPOSED DISPOSITION · REVIEWER RECOMMENDATION · **NOT AN OWNER DECISION** · NO EFFECTIVE DATE · NO RATIFICATION · AUTHORIZES NOTHING
**Companion to:** [SCITT_EXTERNAL_TRUST_OWNER_DECISION_PACKET_20261030.md](SCITT_EXTERNAL_TRUST_OWNER_DECISION_PACKET_20261030.md) at `070ac9d53579114d47ce34c86b6de25e318de1a9`, packet blob `a341032dfced1a6cd5e0b29b5a9ff1074780f90d`. Every option label and line number (`Lnn`) below refers to that exact revision of the packet.
**Owner fields:** every owner field in the packet remains **UNFILLED**. This file fills none of them and does not stand in for them.
**Recorded:** 2026-10-30 (US Eastern). The filename date was set by the instruction.

```text
DISPOSITION_STATUS = PROPOSED · SOURCE = REVIEWER_RECOMMENDATION · OWNER_DECISION = NONE
EFFECTIVE_FROM = NONE · RATIFICATION = NONE · AUTHORIZATION = NONE · OWNER_FIELDS_FILLED = 0
PACKET_EDITED = NO
```

## 1. Provenance

The owner instructed, in their words: "Record the reviewer's seven recommended selections on #17 as a clearly labelled PROPOSED disposition (reviewer recommendation, not an owner decision), leaving every owner field UNFILLED and the PR in draft."

The selections, their meanings, the D4 amendment wording and the two clarifications are the **reviewer's**, recorded as stated. The coordinating session relayed them. Each option label was checked against the packet at `070ac9d5` before recording. §5 lists every place where the reviewer's stated meaning differs from, or adds to, the packet's text. Those places are flagged, not reinterpreted.

## 2. Reviewer's recommended selections

| Decision | Reviewer's selection | Packet labels at `070ac9d5` | Reviewer's stated meaning |
|---|---|---|---|
| **T1** Roles | T1-a; T1.1(i); T1.2(i); T1.3(i) | T1-a L87; T1.1(i) L92; T1.2(i) L97; T1.3(i) L101 | Statement issuer and transparency service are separate roles, with separate keys and trust decisions. Plan a dedicated capture-witness issuer identity. Record whether the service operator is independent of the issuer. Treat an identity string as a name whose key is explicitly selected. |
| **T2** Custody and pins | K1(a); K2(a)+(b); K3(a); K4/K5 retained; T2.1(i) | K1 L137; K2 L138; K3 L139; K4 L140; K5 L141; T2.1(i) L144 | Explicit functional custody responsibility. A versioned, retained candidate pin source, with each receiver selecting its own trust inputs and reliance policy. Service-key material through an explicitly governed channel. A key reference required in any future supported registration profile. Test keys confined to labelled fixtures, separate from operational trust anchors. |
| **T3** Policy ownership | 3.1(a), scoped as stated; 3.2(a); 3.3(a), optionally informed by 3.3(b) | 3.1 L179; 3.2 L180; 3.3 L181; no-policy procedure L183–187 | arcs-srs proposes the portable trust-input contract; the doctrine owner keeps normative ratification; the egress/runtime owner controls submission; each receiver controls reliance. ARCS Verify computes findings from explicit inputs. Missing trust policy stays `not_evaluated`; absent submission authority prevents transmission. |
| **T4** Revocation and time | T4-t-a and T4-r-a | T4-t-a L217; T4-r-a L222; interaction statement L226–230 | Authenticated registration time stays `not_evaluated`. Trust is evaluated against a named, retained trust-input version. Revocation changes trust under that version, while the signature finding is still reported separately. Do not infer historical "valid at registration" without the required time evidence. |
| **T5** Receipt profile and construction | T5-b and T5.1(i), with separate capture-witness scoping | T5-b L266; T5.1(i) L270; "Would authorize" L278 | Preserve the existing SRS profile and its declared gaps. Keep CCF explicitly unsupported in this path. Scope a separately versioned capture-witness profile as offline design work. Keep the current capture statement's rejection by the SRS adapter as a negative control. |
| **D4** Egress classification | Adopt 1, 2, 4 and 5; amend 3 | Options 1–5 at L313–317 | Publicly readable service → `public_publication`. Established authorized recipient set, including the operator → `digest_export`. Insufficient destination or audience evidence keeps the proposed submission unadmitted until resolved. Use the actual readership policy; do not require an absolute guarantee that readership can never change. |
| **D4b** Derived fingerprints | Rule (ii) plus procedure (iii); remedy (iv) stays separately specified | (ii) L357; (iii) L358; (iv) L359–363 | Assess the complete disclosure for guessability and linkage, including original-body identifiers, caller-supplied IDs, content digests, receipt digests and metadata. Specify any remedy as a separately versioned construction with its own identifier derivation and disclosure assessment. |

## 3. Reviewer's D4 amendment (proposed replacement for packet option 3, L315)

Proposed replacement text for option 3, as the reviewer worded it:

> Classify against an established destination and audience. Where the evidence is insufficient to establish the applicable audience, the proposed submission remains unadmitted until that evidence is sufficient.

The reviewer's accompanying notes:
- The amendment keeps the existing class list intact.
- For a restricted service, record the operator, the recipient set and the actual read policy.
- A governed change to the destination or audience requires a new proposal.
- The stronger "can never widen readership" condition (labelled PROPOSED in packet option 2, L314) is **not** recommended.

## 4. Reviewer's clarifications

1. Functional responsibilities can be assigned to existing personnel, with separate keys and records where required.
2. The candidate pin source does not bind receivers. Each receiver still chooses which material to select and what reliance follows.

## 5. Label check and flags

**All labels exist.** Every label in §2 exists in the packet at `070ac9d5`, at the line given. None was renamed or reinterpreted.

**Flags.** Each item below is recorded as stated. Where the reviewer's meaning differs from or adds to the packet text, the difference is named for the owner.

- **F1 · T3 seat 3.1(a), "scoped".** Packet L179 assigns seat 3.1 — normative trust semantics *and* the trust-input wire shape — to arcs-srs under option (a). The reviewer's scoping keeps normative ratification with the doctrine owner, with arcs-srs proposing the portable contract. That is narrower than option (a) as written at L179. If adopted, it is option (a) amended, not option (a) as written.
- **F2 · T4-r-a, "revocation changes trust under that version".** Packet L222, on the G6A precedent, expresses revocation as a withdrawal in the *current* trust state. Prior versions are retained unchanged, and evaluation is against a named version (L228). The reviewer's phrase can be read as altering a named, retained version. On the packet's reading, a revocation yields a new named version and does not modify a retained one. The reviewer's statement that the signature finding is still reported separately adds to the packet text and does not conflict with it.
- **F3 · T5, "the current capture statement's rejection by the SRS adapter".** The packet does not record an executed rejection. Packet L262 states that its construction comparison is an observation from bytes and that AV-S1 owns any executed comparison. AV-S1's hand-over note reports `registration_subject_binding` and `registration_statement_profile` failing by construction for its constructed case W1, with test keys only. That is a written finding held outside any repository, and it was not re-verified for this file. The proposed negative control therefore rests on AV-S1's evidence, not on the packet.
- **F4 · D4 option 2, adopted without the stronger condition.** Packet L314 frames the "never widen readership" requirement as a separate, PROPOSED stronger condition, so adopting option 2 without it is consistent with the packet text. L314's closing sentence sends cases lacking the required evidence to option 3. Under the §3 amendment, that would mean "unadmitted until resolved" rather than classification as `public_publication`.
- **F5 · T2 K1(a) and clarification 1.** Packet L137 option (a) specifies a new functional custody role, separate from G6B-PREP0 §4's role. The reviewer's meaning ("explicit functional custody responsibility") does not restate that separation, and clarification 1 allows existing personnel to hold functional responsibilities. The packet treats the role's holder as an operational assignment (packet L127, citing G6B L75–83). Assigning existing personnel therefore does not conflict with option (a). Whether the role must be separate from G6B-PREP0 §4's role is left as the packet states it.

**No further differences.** The remaining stated meanings match the packet text at the cited lines:
- T1's meanings match L87–104.
- T3's no-policy behaviour matches L183–187.
- T4's time treatment matches L217 and L229.
- T5's separate scoping matches L278.
- D4b matches L357–363.

## 6. What this file does and does not do

**This file:**
- records a reviewer's recommendation, so the owner can see it beside the packet.

**This file does not:**
- edit the packet, whose blob stays `a341032d…`;
- fill, pre-fill or imply any owner field;
- take effect, set an effective date, ratify, or change any registry;
- select a service, approve an endpoint, use or provision a key, grant trust, sign off egress, or register anything.

An owner decision, if one is made, is a separately filed record that fills the packet's owner fields (packet §14, L430–440). Such a record may cite this file. It is not created by this file.
