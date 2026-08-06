# Machine-Readable Report Shapes

The two report shapes documented in this release are described by committed
JSON Schemas so CI consumers can pin what they parse. The CLI has further
JSON-producing surfaces (`receipt-set --json`, `deferred-sequence --json`,
and the DAGR report generators) whose shapes are not yet schema-documented;
treat them as undocumented until schemas land here:

| Subcommand | Schema file |
|---|---|
| signed-SRS (default, `--json`) | [schemas/signed-srs-report-v0.1.schema.json](schemas/signed-srs-report-v0.1.schema.json) |
| `amnesiac-chain` | [schemas/amnesiac-chain-report-v0.1.1.schema.json](schemas/amnesiac-chain-report-v0.1.1.schema.json) |

`tests/test_report_schemas.py` generates both reports from the committed
fixtures and validates them against these schemas, so drift between the code
and the schemas fails in CI.

Two rules for consumers:

1. **The schemas are descriptive, not normative.** The verifier code is the
   source of truth; the schemas document the shape the current bytes emit and
   are updated when the code changes. A disagreement is a documentation
   defect worth reporting.
2. **Tolerate additions.** Fields are append-only in intent: existing names
   keep their meaning and new results arrive as new fields. Parse by name,
   ignore what you do not recognize, and match `failure_codes` entries as
   exact strings ([FAILURE_CODES.md](FAILURE_CODES.md)). The `details` array
   is human-readable text and is not a stable interface.

The chain report additionally carries `report_hash`, the digest of the report
content itself, so a stored report can be checked for post-hoc modification
by anyone holding the report bytes.
