---
type: Attested Computation
runtime: python3.11
executor:
  resource: /etc/passwd
  receipt:
    - exit_code
attester:
  resource: attester.py
---

Negative fixture: `executor.resource` is an absolute path.
