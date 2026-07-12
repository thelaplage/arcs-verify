#!/usr/bin/env bash
#
# check.sh — conformance check for the vendor-neutral MCP audit-trail pack.
#
# This is the first vendor-neutral, receipt-bearing pack in this repo. It takes
# an explicit, public-safe MCP (Model Context Protocol) custody-gateway
# audit-trail input file, builds an ARCS SRS *envelope* receipt from it with the
# pack's minimal adapter, and proves:
#
#   1. the receipt regenerates byte-identically from the input (deterministic
#      adapter, no wall clock, no randomness),
#   2. the receipt cryptographically binds the exact input bytes (the sha256 in
#      extensions.garp.body.artifact_hashes matches the input file),
#   3. the receipt validates against the canonical SRS envelope schema already
#      vendored in this repo (envelope form only), and
#   4. a forbidden-drift fixture is rejected by that same canonical validator.
#
# It validates STRUCTURAL and CRYPTOGRAPHIC integrity only. It does NOT assert
# that any recorded audit event is true, that any tool call was authorized, or
# that any custody claim is correct. See README.md.
#
# No network, no live credentials, no scanner, no private corpus, no vendor
# profile. Python 3 standard library and stock POSIX tooling only.
#
# Usage (from the repository root):
#   bash packs/mcp-audit-trail/v0.1/check.sh
#
# Exit status: 0 all checks passed; non-zero the first failing check aborted.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)

if [ "$(pwd -P)" != "$REPO_ROOT" ]; then
    printf 'ERROR: run this script from the repository root: %s\n' "$REPO_ROOT" >&2
    exit 2
fi

PACK="packs/mcp-audit-trail/v0.1"
VALIDATOR="tools/validate_srs_envelope.py"
INPUT="$PACK/input/mcp_audit_trail.input.json"
ADAPTER="$PACK/tools/build_receipt.py"
VALID="$PACK/fixtures/valid/mcp_audit_trail.envelope.json"
INVALID="$PACK/fixtures/invalid/top_level_status_verdict.json"
EXPECTED_VALID="$PACK/expected/valid/mcp_audit_trail.envelope.txt"
EXPECTED_INVALID="$PACK/expected/invalid/top_level_status_verdict.txt"

TMPDIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/check_mcp_audit.XXXXXX")
cleanup() {
    rm -rf "$TMPDIR_WORK"
}
trap cleanup EXIT INT TERM

step=0
pass() {
    step=$((step + 1))
    printf 'ok %d - %s\n' "$step" "$1"
}

# --- 1. no unstaged whitespace/conflict damage -----------------------------

git diff --check
pass "git diff --check (no whitespace/conflict damage)"

# --- 2. all pack JSON artifacts parse --------------------------------------

for artifact in "$INPUT" "$VALID" "$INVALID" "$PACK/PROVENANCE.json"; do
    python3 -m json.tool "$artifact" >/dev/null
done
pass "input, fixtures, and provenance parse as JSON"

# --- 3. receipt regenerates byte-identically from the input ----------------

REGEN="$TMPDIR_WORK/regenerated.envelope.json"
python3 "$ADAPTER" "$INPUT" --out "$REGEN"
diff -u "$VALID" "$REGEN"
pass "adapter regenerates the valid receipt byte-identically from the input"

# --- 4. receipt cryptographically binds the exact input bytes --------------

python3 - "$INPUT" "$VALID" <<'PY'
import hashlib, json, sys
input_path, receipt_path = sys.argv[1], sys.argv[2]
actual = "sha256:" + hashlib.sha256(open(input_path, "rb").read()).hexdigest()
receipt = json.load(open(receipt_path))
recorded = receipt["extensions"]["garp"]["body"]["artifact_hashes"][
    "input/mcp_audit_trail.input.json"
]
if actual != recorded:
    sys.stderr.write(f"input digest {actual} != recorded {recorded}\n")
    sys.exit(1)
PY
pass "receipt artifact_hashes matches the sha256 of the input bytes"

# --- 5. valid receipt: validator passes (exit 0) and output matches --------

out="$TMPDIR_WORK/valid.out"
set +e
python3 "$VALIDATOR" "$VALID" >"$out"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    printf 'ERROR: validator exit %d on valid fixture (expected 0)\n' "$rc" >&2
    exit 1
fi
diff -u "$EXPECTED_VALID" "$out"
pass "valid receipt: exit 0 and output matches $EXPECTED_VALID"

# --- 6. invalid drift fixture: validator fails (exit 1) and output matches --

out="$TMPDIR_WORK/invalid.out"
set +e
python3 "$VALIDATOR" "$INVALID" >"$out"
rc=$?
set -e
if [ "$rc" -ne 1 ]; then
    printf 'ERROR: validator exit %d on invalid fixture (expected 1)\n' "$rc" >&2
    exit 1
fi
diff -u "$EXPECTED_INVALID" "$out"
pass "invalid drift fixture: exit 1 and output matches $EXPECTED_INVALID"

# --- 7. boundary_type posture guard ----------------------------------------
#
# Ratifies the boundary_type posture (see docs/BOUNDARY_TYPE_POSTURE.md): the
# canonical schema treats boundary_type as an OPEN STRING (no enum, no
# registry), so audit_trail_boundary is accepted as a *pack-local descriptive*
# routing label and is NOT a minted canonical value. This guard fails loudly if
# the open-string posture ever changes (e.g. arcs-srs closes boundary_type into
# an enum), forcing a conscious decision instead of silent drift.

SCHEMA="schemas/srs-envelope/v0.1.0/srs-envelope.schema.json"
python3 - "$SCHEMA" "$VALID" <<'PY'
import json, sys
schema_path, receipt_path = sys.argv[1], sys.argv[2]
schema = json.load(open(schema_path))
bt = schema.get("properties", {}).get("boundary_type", {})
# Posture holds only while boundary_type is an open string with no enum.
if bt.get("type") != "string" or "enum" in bt:
    sys.stderr.write(
        "boundary_type posture changed: canonical schema no longer treats "
        f"boundary_type as an open string (got {bt!r}). audit_trail_boundary "
        "must now be ratified upstream into the enum or replaced with an "
        "already-governed value. See docs/BOUNDARY_TYPE_POSTURE.md.\n"
    )
    sys.exit(1)
# This pack does NOT mint a canonical value; it carries the pack-local label.
receipt = json.load(open(receipt_path))
if receipt.get("boundary_type") != "audit_trail_boundary":
    sys.stderr.write(
        "expected pack-local descriptive boundary_type 'audit_trail_boundary', "
        f"got {receipt.get('boundary_type')!r}\n"
    )
    sys.exit(1)
PY
pass "boundary_type posture: open-string schema; audit_trail_boundary is pack-local descriptive, not canonical"

# --- summary ---------------------------------------------------------------

printf 'PASS: vendor-neutral MCP audit-trail pack v0.1 (%d checks)\n' "$step"
