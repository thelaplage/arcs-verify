---
type: Attested Computation
runtime: python3.11
executor:
  resource: a-directory
  receipt:
    - exit_code
attester:
  resource: attester.py
---

Negative fixture: `executor.resource` resolves to a directory, not a file.
