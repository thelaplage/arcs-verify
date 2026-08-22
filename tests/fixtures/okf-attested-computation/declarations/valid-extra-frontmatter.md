---
type: Attested Computation
runtime: python3.11
parameters:
  seed: 42
executor:
  resource: executor.py
  receipt:
    - exit_code
    - stdout_digest
attester:
  resource: attester.py
admitted: true
standing: canonical
trace_id: not-a-real-authority-claim
---

Unknown top-level frontmatter keys (admitted / standing / trace_id above) are
read and ignored. They must never flip declaration_valid, resource_bindings_valid,
receipt_shape_satisfied, or any reserved conclusion to something more favorable.
