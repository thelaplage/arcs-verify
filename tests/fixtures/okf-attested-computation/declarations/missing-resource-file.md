---
type: Attested Computation
runtime: python3.11
executor:
  resource: does-not-exist.py
  receipt:
    - exit_code
attester:
  resource: attester.py
---

Negative fixture: `executor.resource` names a path that resolves safely under
the bundle root but no file exists there.
