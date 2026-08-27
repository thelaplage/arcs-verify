---
type: Attested Computation
runtime: python3.11
parameters:
  seed: 42
  mode: batch
executor:
  resource: executor.py
  receipt:
    - exit_code
    - stdout_digest
attester:
  resource: attester.py
---

# Example OKF Attested Computation

This body is prose. Bridge0 does not read the Markdown body — only the
frontmatter fields above are consulted, and only the executor/attester
resource bytes referenced from it.
