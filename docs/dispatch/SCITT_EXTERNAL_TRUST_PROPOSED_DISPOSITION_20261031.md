# ARCS Verify — SCITT external trust: PROPOSED disposition (reviewer recommendation)

**Status:** PROPOSED DISPOSITION · REVIEWER RECOMMENDATION · **NOT AN OWNER DECISION** · NO EFFECTIVE DATE · NO RATIFICATION · AUTHORIZES NOTHING
**Companion to:** [SCITT_EXTERNAL_TRUST_OWNER_DECISION_PACKET_20261030.md](SCITT_EXTERNAL_TRUST_OWNER_DECISION_PACKET_20261030.md) at `070ac9d53579114d47ce34c86b6de25e318de1a9`, packet blob `a341032dfced1a6cd5e0b29b5a9ff1074780f90d`. Every option label and line number (`Lnn`) below refers to that exact revision of the packet.
**Owner fields:** every owner field in the packet remains **UNFILLED**: 36 lines of the packet contain `UNFILLED`, with 57 literal occurrences, both unchanged. This file fills none of them and does not stand in for them.
**Recorded:** 2026-10-30 (US Eastern). The filename date was set by the instruction.
**Revised:** after the reviewer's check of `a3be4cdb`, which resolved flags F1–F5 (§5). The selections are unchanged; the wording of F1–F5 follows the reviewer's resolutions.

```text
DISPOSITION_STATUS = PROPOSED · SOURCE = REVIEWER_RECOMMENDATION · OWNER_DECISION = NONE
EFFECTIVE_FROM = NONE · RATIFICATION = NONE · AUTHORIZATION = NONE · OWNER_FIELDS_FILLED = 0
PACKET_EDITED = NO
```

## 1. Provenance

The owner instructed, in their words: "Record the reviewer's seven recommended selections on #17 as a clearly labelled PROPOSED disposition (reviewer recommendation, not an owner decision), leaving every owner field UNFILLED and the PR in draft."

The selections, their meanings, the D4 amendment wording and the two clarifications are the **reviewer's**, recorded as stated. The coordinating session relayed them. Each option label was checked against the packet at `070ac9d5` before recording. §5 lists every place where the reviewer's stated meaning differed from, or added to, the packet's text, together with the reviewer's own resolution of each. None was reinterpreted by the recorder.

## 2. Reviewer's recommended selections

| Decision | Reviewer's selection | Packet labels at `070ac9d5` | Reviewer's stated meaning |
|---|---|---|---|
| **T1** Roles | T1-a; T1.1(i); T1.2(i); T1.3(i) | T1-a L87; T1.1(i) L92; T1.2(i) L97; T1.3(i) L101 | Statement issuer and transparency service are separate roles, with separate keys and trust decisions. Plan a dedicated capture-witness issuer identity. Record whether the service operator is independent of the issuer. Treat an identity string as a name whose key is explicitly selected. |
| **T2** Custody and pins | K1(a); K2(a)+(b); K3(a); K4/K5 retained; T2.1(i) | K1 L137; K2 L138; K3 L139; K4 L140; K5 L141; T2.1(i) L144 | K1(a) remains selected: a distinct capture-witness/SCITT custody role, separate in remit from the G6B-PREP0 §4 role, with separate keys and records. Existing personnel may hold the separately recorded responsibilities; this recommendation does not require a different person. A versioned, retained candidate pin source, with each receiver selecting its own trust inputs and reliance policy. Service-key material through an explicitly governed channel. A key reference required in any future supported registration profile. Test keys confined to labelled fixtures, separate from operational trust anchors. |
| **T3** Policy ownership | 3.1(a), amended; 3.2(a); 3.3(a), optionally informed by 3.3(b) | 3.1 L179; 3.2 L180; 3.3 L181; no-policy procedure L183–187 | *Proposed allocation for the owner to consider:* Recommend 3.1(a), amended: arcs-srs authors and proposes the portable trust-input contract; the doctrine owner retains normative ratification. The submission owner controls transmission, and each receiver retains its trust and reliance decisions. ARCS Verify computes findings from explicit inputs. Missing trust policy stays `not_evaluated`; absent submission authority prevents transmission. |
| **T4** Revocation and time | T4-t-a and T4-r-a | T4-t-a L217; T4-r-a L222; interaction statement L226–230 | Authenticated registration time stays `not_evaluated`. Trust is evaluated against a named, retained trust-input version. Revocation is recorded in a new named trust-input version; previously retained versions remain unchanged. Each trust finding identifies the version evaluated. Signature findings remain separate. Authenticated registration time and historical "valid at registration" claims remain `not_evaluated` without the required time evidence. A report evaluated against an older version describes that selected state; it does not establish current trust or authenticated historical validity. |
| **T5** Receipt profile and construction | T5-b and T5.1(i), with separate capture-witness scoping | T5-b L266; T5.1(i) L270; "Would authorize" L278 | Preserve the existing SRS profile and its declared gaps. Keep CCF explicitly unsupported in this path. Scope a separately versioned capture-witness profile as offline design work. Keep the retained capture-witness statement as an expected-failure vector for `registration_subject_binding` and `registration_statement_profile` under the existing SRS profile. AV-S1's written hand-over reports those failures for case W1; this disposition does not independently verify that execution. |
| **D4** Egress classification | Adopt 1, 2, 4 and 5; amend 3 | Options 1–5 at L313–317 | Publicly readable service → `public_publication`. Established authorized recipient set, including the operator → `digest_export`. Insufficient destination or audience evidence keeps the proposed submission unadmitted until resolved. Use the actual readership policy; do not require an absolute guarantee that readership can never change. |
| **D4b** Derived fingerprints | Rule (ii) plus procedure (iii); remedy (iv) stays separately specified | (ii) L357; (iii) L358; (iv) L359–363 | Assess the complete disclosure for guessability and linkage, including original-body identifiers, caller-supplied IDs, content digests, receipt digests and metadata. Specify any remedy as a separately versioned construction with its own identifier derivation and disclosure assessment. |

## 3. Reviewer's D4 amendment (proposed replacement for packet option 3, L315)

Proposed replacement text for option 3, as the reviewer worded it:

> Classify against an established destination and audience. Where the evidence is insufficient to establish the applicable audience, the proposed submission remains unadmitted until that evidence is sufficient.

The reviewer's accompanying notes:
- The amendment keeps the existing class list intact. It remains a proposed admission rule within that list.
- For a restricted service, the evidence must establish the operator, the authorized recipients and the actual read policy.
- The "can never widen readership" requirement (labelled PROPOSED in packet option 2, L314) is **not** part of the selection.
- Insufficient destination or audience evidence keeps the submission unadmitted, pending sufficient evidence.
- A governed change to the destination or audience requires a new proposal.

## 4. Reviewer's clarifications

1. Functional responsibilities can be assigned to existing personnel, with separate keys and records where required.
2. The candidate pin source does not bind receivers. Each receiver still chooses which material to select and what reliance follows.

## 5. Label check, flags and the reviewer's resolutions

**All labels exist.** Every label in §2 exists in the packet at `070ac9d5`, at the line given. None was renamed or reinterpreted.

**Flags and resolutions.** The first recording (`a3be4cdb`) flagged five places where the reviewer's stated meaning differed from or added to the packet text. The reviewer resolved each one, and §2–§3 now carry the resolved wording. All five remain a reviewer recommendation, not an owner decision.

- **F1 · T3 seat 3.1.**
  - *Flagged:* the selection was labelled "scoped".
  - *Resolved:* relabelled "3.1(a), amended", a proposed allocation for the owner to consider.
  - *Reason recorded:* the packet combines normative trust semantics and the trust-input wire shape in seat 3.1 (packet L175–181). The recommendation separates contract authorship (arcs-srs) from normative ratification (the doctrine owner).
- **F2 · T4-r-a.**
  - *Flagged:* "revocation changes trust under that version" could be read as altering a retained version.
  - *Resolved:* revocation is recorded in a new named trust-input version, and previously retained versions remain unchanged. Each trust finding identifies the version evaluated, and signature findings stay separate. A report against an older version describes that selected state only.
  - *Source:* packet model L211–230.
- **F3 · T5.**
  - *Flagged:* "rejection by the SRS adapter" implied an executed result the packet does not record.
  - *Resolved:* narrowed to an expected-failure vector for exactly two findings, `registration_subject_binding` and `registration_statement_profile`, under the existing SRS profile. It implies no aggregate adapter verdict, no process-exit failure and no signature failure. AV-S1's written hand-over reports those two failures for case W1, with test keys only; this disposition does not independently verify that execution.
  - *Sources:* packet L258–262. In the adapter at `arcs-verify@ce9e0ffe`, `arcs_verify/scitt_registration.py` L303–337: the profile finding requires protected labels 1, 15, 258 and 259 plus a key reference (L315–316), and subject binding is computed against the `ni` URI of the target digest (L334–337).
- **F4 · D4.**
  - *Confirmed as recorded.* The replacement for option 3 stays; §3 makes the evidence conditions explicit. It remains a proposed admission rule within the existing class list.
- **F5 · T2 K1(a).**
  - *Flagged:* the earlier wording did not restate that the custody role is separate from G6B-PREP0 §4's role.
  - *Resolved:* K1(a) remains selected: a distinct capture-witness/SCITT custody role, separate in remit from the G6B-PREP0 §4 role, with separate keys and records. Existing personnel may hold the separately recorded responsibilities; a different person is not required.
  - *Source:* packet K1, L133–147.

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
