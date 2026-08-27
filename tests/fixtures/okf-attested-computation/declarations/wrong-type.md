---
type: Something Else
runtime: python3.11
executor:
  resource: executor.py
  receipt:
    - exit_code
attester:
  resource: attester.py
---

Negative fixture: `type` is not "Attested Computation".
