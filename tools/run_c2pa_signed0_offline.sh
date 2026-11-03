#!/usr/bin/env bash
# C2PA-SIGVERIFY0: local macOS offline acceptance gate, NOT an issuer/deployment.
# No dependency download occurs here. Use prepared clean checkouts. Refuse if the
# operating system's network-deny sandbox cannot be invoked.
set -euo pipefail

fail() { printf '%s\n' "C2PA_SIGNED0_BLOCKED: $*" >&2; exit 3; }
[[ "$(uname -s)" == "Darwin" ]] || fail "macOS sandbox-exec required; no unsandboxed fallback"
command -v sandbox-exec >/dev/null || fail "sandbox-exec not installed"
: "$C2PA_SIGN0_REPO"
: "$C2PA_SIGN0_EXPECTED_HEAD"
: "$C2PA_SIGVERIFY_EXPECTED_HEAD"
: "$ARCS_VERIFY_C2PATOOL"
: "$C2PA_SIGNED_TEST_EVIDENCE_DIR"

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
sign_repo="$(cd "$C2PA_SIGN0_REPO" && pwd -P)"
[[ -f "$sign_repo/dagr_ingest/srs/c2pa_test_signing0.py" ]] || fail "SIGN0 source missing"
[[ -f "$repo/arcs_verify/c2pa_test_signature0.py" ]] || fail "SIGVERIFY0 source missing"

actual_sign="$(git -C "$sign_repo" rev-parse HEAD)"
actual_verify="$(git -C "$repo" rev-parse HEAD)"
[[ "$actual_sign" == "$C2PA_SIGN0_EXPECTED_HEAD" ]] || fail "SIGN0 exact commit mismatch"
[[ "$actual_verify" == "$C2PA_SIGVERIFY_EXPECTED_HEAD" ]] || fail "SIGVERIFY0 exact commit mismatch"
[[ -z "$(git -C "$sign_repo" status --porcelain)" ]] || fail "SIGN0 checkout dirty"
[[ -z "$(git -C "$repo" status --porcelain)" ]] || fail "SIGVERIFY0 checkout dirty"
[[ -f "$ARCS_VERIFY_C2PATOOL" ]] || fail "pinned validator path not a file"
[[ -d "$C2PA_SIGNED_TEST_EVIDENCE_DIR" ]] || fail "create an empty evidence directory first"
[[ -z "$(find "$C2PA_SIGNED_TEST_EVIDENCE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] || fail "evidence directory is not empty"

# OS-level deny network applies to the Python/pytest process and its child c2patool.
# Never weaken/remove this profile to obtain a green result.
profile='(version 1)(allow default)(deny network*)'
cd "$repo"
export C2PA_SIGN0_REQUIRED=1
export PYTHONPATH="$sign_repo:$repo"
sandbox-exec -p "$profile" \
  python -m pytest -q \
    tests/c2pa_srs/test_test_signature0.py \
    tests/c2pa_srs/test_signed_integrated_replay0.py

# Three genuine specimens, three public artifacts each. Private keys never retained.
for name in positive negative_native_invalid_exit0 negative_remote_manifest_missing; do
  for ext in signed-observation.json test-public-key.bin proof.json; do
    [[ -s "$C2PA_SIGNED_TEST_EVIDENCE_DIR/$name.$ext" ]] ||
      fail "missing test-only proof artifact: $name.$ext"
  done
done

printf '%s\n' \
  'C2PA_SIGNED0_LOCAL_TEST_PASS' \
  "SIGN0_HEAD=$actual_sign" \
  "SIGVERIFY0_HEAD=$actual_verify" \
  "EVIDENCE_DIR=$C2PA_SIGNED_TEST_EVIDENCE_DIR" \
  'NOTE: TEST-only cryptography; no operational issuer or reliance authorized'
