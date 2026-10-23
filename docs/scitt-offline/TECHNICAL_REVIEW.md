# Technical review follow-up — 2026-10-13

The review of draft #6 at `311b0eda49188670c016e7b6c3a9d4a38fbaeee9`
found one concrete Receipt-header acceptance defect. A correctly signed Receipt
with CWT Claims (label 15) set to a string, array or integer could produce an
inclusion PASS. Invalid claim-label types also passed. Marking label 15 critical
did not prevent acceptance because the adapter declared all CWT semantics
understood while implementing no corresponding Receipt application policy.

[RFC 9597 section 2](https://www.rfc-editor.org/rfc/rfc9597.html#section-2)
defines the header as a map with integer or text claim labels. Shape validation
alone does not implement application-specific critical claim processing.

The correction validates CWT map shape and label types in both Receipt header
buckets and removes CWT Claims from this candidate's understood critical-header
set. Such Receipts now fail inclusion under R08 and cannot report an authenticated
service identity. Independent statement signature and subject-binding findings
remain intact. Well-formed noncritical Receipt claims and supported critical
algorithm/data-structure headers still verify. Registration time stays
`not_evaluated`; no new time or trust policy was introduced.

The added regression group produced **13 failures and three passing controls**
against the previous implementation. After correction, all **16 new tests pass**.
The complete repository run passes **110 tests, zero skips**, with networking
denied: 107 SCITT tests plus the three existing tests. The previously executed
163-test upstream qualification remains evidence for the unchanged backend;
it was not rerun or represented as a new upstream run during this correction.

The verifier context is now `arcs-verify.scitt-registration/experimental-2`, so
results from the previous behavior cannot share its evaluation identity. The
retained reports/checksums were regenerated. Exact constructed artifact,
Signed Statements, Receipt, sidecars and key/policy inputs are unchanged. Both
pairing orders still yield S1/P inclusion PASS and S2/P inclusion FAIL.

The wheel/sdist and installed replay are rebuilt for this correction; see
[evidence/validation.json](evidence/validation.json) and the installed smoke log.
This is a technical review and correction of the draft, not independent owner
acceptance or ratification. The 35-case matrix still has 32 cases with constructed
coverage, two partial cases (B03/T13), and unexecuted real-service case T01.
