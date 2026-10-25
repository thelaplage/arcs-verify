#!/bin/sh
# Negative controls for tests/test_failure_code_registry.py.
#
# The registry gate is a completeness check, and a completeness check that
# cannot fail is worth nothing. Each control below introduces one real omission
# or invention and requires THE SPECIFIC TEST that protects that property to
# fail. "Some test failed" is not accepted: a control that trips a sibling gate
# proves nothing about its own.
#
# Every mutation is reverted, including on interrupt, and every tracked file
# this script touches is digest-compared before and after. The closing green
# rerun is asserted, not merely printed.
#
# Offline: no network, nothing installed, no commit, no push.
# Needs a python env with pytest and the package (`pip install -e .`).
# Override the interpreter with PY=/path/to/python.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
PY=${PY:-./.venv-q/bin/python}
[ -x "$PY" ] || PY=python3

T=tests/test_failure_code_registry.py
REG=docs/FAILURE_CODES.md
VERIFIER=arcs_verify/verifier.py
FINDINGS=arcs_verify/findings.py
PROBE=arcs_verify/_control_probe_emitting_module.py
TRACKED="$REG $VERIFIER $FINDINGS"
# --- preflight, BEFORE any cleanup handler exists --------------------------
# Nothing in this script may move or delete a path it did not create. The
# cleanup handler is therefore installed only after these checks pass.
for f in $TRACKED $T; do
  if [ ! -f "$f" ]; then
    printf 'qualify: BLOCKED -- %s not found; run this from the repository (ROOT=%s)\n' "$f" "$ROOT" >&2
    exit 2
  fi
done

collisions=''
for f in $TRACKED; do
  [ -e "$f.control-backup" ] && collisions="$collisions $f.control-backup"
done
[ -e "$PROBE" ] && collisions="$collisions $PROBE"
if [ -n "$collisions" ]; then
  printf 'qualify: BLOCKED -- these paths already exist and do not belong to this run:\n' >&2
  for c in $collisions; do printf '    %s\n' "$c" >&2; done
  printf '  A previous run may have been killed, or they belong to another process.\n' >&2
  printf '  Inspect and move them aside yourself: this script will neither delete\n' >&2
  printf '  them nor restore them over a tracked file.\n' >&2
  exit 2
fi

# --- custody: only this run's own artifacts are ever cleaned up -----------
OWNED=''
OWN_PROBE=no
WORK=''
cleanup() {
  for f in $OWNED; do
    [ -f "$f.control-backup" ] && mv -f "$f.control-backup" "$f"
  done
  [ "$OWN_PROBE" = yes ] && rm -f "$PROBE"
  [ -n "$WORK" ] && rm -rf "$WORK"
  return 0
}
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

WORK=$(mktemp -d /tmp/registry-controls.XXXXXX)
fail=0

digest() {
  if [ ! -f "$1" ]; then printf 'MISSING:%s\n' "$1"; return 0; fi
  shasum -a 256 "$1" | cut -d' ' -f1
}
for f in $TRACKED; do
  eval "BEFORE_$(printf '%s' "$f" | tr './-' '___')=$(digest "$f")"
done

perturb() {  # take custody of a file before mutating it
  if [ -e "$1.control-backup" ]; then
    printf '  !! backup collision for %s; refusing to mutate it\n' "$1"
    fail=1
    return 1
  fi
  cp "$1" "$1.control-backup" || { fail=1; return 1; }
  OWNED="$OWNED $1"
}
restore() {
  mv -f "$1.control-backup" "$1"
}

# A control passes only when ITS OWN test fails. Any other failing test means
# the control does not isolate the property it claims to exercise, which is a
# harness defect, not a detail.
expect_fail() {
  label=$1
  wanted=$2
  out=$($PY -m pytest -q -p no:warnings "$T" 2>&1)
  if printf '%s\n' "$out" | grep -qE "FAILED [^ ]*::${wanted}( |$)"; then
    printf '  [detected] %-30s %s\n' "$label" "$wanted"
  else
    printf '  [VACUOUS]  %-30s expected %s to fail; it did not\n' "$label" "$wanted"
    fail=1
  fi
  others=$(printf '%s\n' "$out" | grep -oE 'FAILED [^ ]*::[a-z_]+' | sed 's/.*:://' | grep -v "^${wanted}$" | sort -u | tr '\n' ' ')
  if [ -n "$others" ]; then
    printf '  !! %-30s also tripped: %s(a control must isolate its property)\n' "$label" "$others"
    fail=1
  fi
  return 0
}

assert_changed() {  # a substitution that silently stops matching must be loud
  if [ "$(digest "$1")" = "$(digest "$1.control-backup")" ]; then
    printf '  [INVALID]  %-30s mutation did not apply to %s\n' "$2" "$1"
    fail=1
  fi
}

printf 'negative controls for the failure-code registry gate\n'
printf 'interpreter: %s\n\n' "$($PY --version 2>&1)"

# --- C1: a code the modules emit stops being documented.
CODE=$(grep -ohE '`[a-z_]+\.[a-z_]+`' "$REG" | head -1 | tr -d '`')
perturb "$REG"
perl -0pi -e "s/\`\Q$CODE\E\`/\`REDACTED_BY_CONTROL\`/g" "$REG"
assert_changed "$REG" "omitted static code"
expect_fail "omitted static code" test_every_emitted_code_is_in_the_registry
restore "$REG"

# --- C2: a new emitting module escapes the fixed MODULES list. This is the
#         property that once let governed_memory_sequence.py through unnoticed.
OWN_PROBE=yes
cat > "$PROBE" <<'PYEOF'
"""Transient control fixture; removed by tools/qualify_failure_code_registry.sh."""


def _fail(report, code, detail):
    return report


def check(report):
    return _fail(report, "control_probe.unregistered_code", "probe")
PYEOF
expect_fail "unregistered emitting module" test_no_emitting_module_is_unregistered
rm -f "$PROBE"

# --- C3: the registry invents a code nothing emits. Scoped deliberately: the
#         gate reads the receipt-set..amnesiac-chain section and matches dotless
#         identifiers, so a control placed elsewhere, or written family.code,
#         would prove nothing. Widening that check is separate work.
perturb "$REG"
$PY - "$REG" <<'PYEOF'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
index = text.index("## `amnesiac-chain` subcommand")
row = "| `zz_phantom_code` | Never emitted by receipt_set or deferred_sequence. |\n\n"
open(path, "w", encoding="utf-8").write(text[:index] + row + text[index:])
PYEOF
assert_changed "$REG" "phantom documented code"
expect_fail "phantom documented code" test_registry_lists_no_phantom_static_codes
restore "$REG"

# --- C4: a module starts emitting a NEW dynamic family that nobody documented.
#         Mutating the code rather than the registry is deliberate: it exercises
#         the property in its real direction, and an f-string emission harvests
#         as a template only, so the static-code gate stays quiet and the signal
#         is isolated to the dynamic-family gate.
perturb "$FINDINGS"
cat >> "$FINDINGS" <<'PYEOF'


def _control_probe_dynamic_family(report, value):  # transient control fixture
    return _fail(report, f"zz_dynamic_control.{value}", "probe")
PYEOF
assert_changed "$FINDINGS" "undocumented dynamic family"
expect_fail "undocumented dynamic family" test_every_dynamic_family_prefix_is_in_the_registry
restore "$FINDINGS"

# --- C5: the verifier declares a NEW signature failure code that nobody
#         documented. Added to the set literal, which the structural sweep does
#         not harvest, so only the signature-registry gate can see it.
perturb "$VERIFIER"
$PY - "$VERIFIER" <<'PYEOF'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
anchor = "SIGNATURE_FAILURE_CODES = {\n"
index = text.index(anchor) + len(anchor)
open(path, "w", encoding="utf-8").write(
    text[:index] + '    "zz_signature_control_code",\n' + text[index:]
)
PYEOF
assert_changed "$VERIFIER" "undocumented signature code"
expect_fail "undocumented signature code" test_every_signature_failure_code_is_in_the_registry
restore "$VERIFIER"

# --- post-conditions -------------------------------------------------------
printf '\npost-conditions\n'
for f in $TRACKED; do
  key=BEFORE_$(printf '%s' "$f" | tr './-' '___')
  eval "was=\$$key"
  now=$(digest "$f")
  if [ "$was" = "$now" ] && [ "${now#MISSING:}" = "$now" ]; then
    printf '  restored byte-identical: %s\n' "$f"
  else
    printf '  !! NOT RESTORED: %s\n' "$f"
    fail=1
  fi
done
if [ -e "$PROBE" ]; then
  printf '  !! control probe left behind: %s\n' "$PROBE"
  fail=1
else
  printf '  control probe removed\n'
fi

# The closing rerun is ASSERTED. A control run that leaves the gate red must not
# be able to report success.
if $PY -m pytest -q -p no:warnings "$T" >"$WORK/final" 2>&1; then
  printf '  gate green again: %s\n' "$(grep -E 'passed|failed' "$WORK/final" | tail -1)"
else
  printf '  !! gate NOT green after restore:\n'
  grep -E '^FAILED|passed|failed' "$WORK/final" | sed 's/^/     /'
  fail=1
fi

if [ $fail -eq 0 ]; then printf '\nREGISTRY_CONTROLS=ALL_FIRE\n'; exit 0; fi
printf '\nREGISTRY_CONTROLS=PROBLEM\n'
exit 1
