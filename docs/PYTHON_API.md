# Python API

Embedding verification in a service does not require shelling out to the CLI.
The CLI is a thin wrapper over one function, and that function is the
supported programmatic entry point.

## The entry point

```python
from pathlib import Path
import json

from arcs_verify.verifier import verify_receipt

receipt = json.loads(Path("receipt.json").read_text(encoding="utf-8"))
keyring = json.loads(Path("issuer-keys.json").read_text(encoding="utf-8"))

report = verify_receipt(
    receipt,
    keyring,
    schema_path=Path("arcs_verify/data/srs-envelope-v0.2.0.schema.json"),
    selected_profile="srs.mcp.sdk_enforcement.v0.1",
)

if not report.passed:
    for code in report.failure_codes:
        alert(code)          # exact-string match; see docs/FAILURE_CODES.md
```

Signature:

```python
def verify_receipt(
    receipt: dict,
    keyring: dict,
    *,
    schema_path: Path,
    selected_profile: str | None = None,   # default: srs.mcp.sdk_enforcement.v0.1
) -> VerificationReport
```

The default schema path used by the CLI is the pinned envelope schema shipped
inside the package:

```python
from pathlib import Path
import arcs_verify

schema_path = Path(arcs_verify.__file__).parent / "data" / "srs-envelope-v0.2.0.schema.json"
```

The `schema_digest` result applies regardless of which path you pass: a schema
file that does not hash to the frozen SHA-256 fails that result.

## The report object

`VerificationReport` is a dataclass with the eight Boolean results
(`schema_digest`, `envelope`, `profile`, `raw_content_exclusion`,
`signature_valid`, `issuer_key_resolved`, `issuer_key_trusted`,
`attestation_limits_present`), the separate `chain_status` string,
`failure_codes: list[str]`, and `details: list[str]` (human-readable schema
validator messages; not stable strings, do not match on them).

- `report.passed` is a property: all eight Booleans true **and**
  `chain_status == "not_applicable"`.
- `report.to_dict()` returns the same shape the CLI prints under `--json`,
  including a computed `passed` key. The shape is documented in
  [REPORT_SCHEMAS.md](REPORT_SCHEMAS.md).

## Inputs are your responsibility

`verify_receipt` takes parsed dictionaries, not paths, so the caller decides
how receipt and trust-bundle bytes are obtained and whether they came from a
source you trust for that purpose. The function never fetches anything: no
network, no environment lookup, no producer import. Malformed JSON should be
caught at your parse site; the CLI maps unreadable input to exit 2, and a
library caller should treat parse failures the same way, as usage errors
rather than verification verdicts.

## Stability

`arcs_verify.verifier.verify_receipt` and the `VerificationReport` field set
above are the supported surface for the signed-SRS path. Fields are
append-only in intent: existing names keep their meaning and new results
arrive as new fields, so read fields by name and tolerate additions. Modules
other than `verifier` (the chain, receipt-set, and report generators) are
reachable but their Python interfaces are not yet declared stable; drive them
through the CLI subcommands until they are.
