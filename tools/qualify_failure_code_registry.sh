#!/bin/sh
# Negative controls for tests/test_failure_code_registry.py.
#
# The registry gate is a completeness check, and a completeness check that
# cannot fail is worth nothing. Each control below introduces one real omission
# or invention and requires the gate to fail on it. Every mutation is reverted,
# and the registry's digest is compared before and after.
#
# Offline: no network, nothing installed, no commit. Needs an installed
# node-free python env with pytest and the package (`pip install -e .`).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
PY=${PY:-./.venv-q/bin/python}
command -v "$PY" >/dev/null 2>&1 || [ -x "$PY" ] || PY=python3
T=tests/test_failure_code_registry.py
REG=docs/FAILURE_CODES.md
BEFORE=$(shasum -a 256 "$REG" | cut -d' ' -f1)
fail=0

expect_failure() {
  out=$($PY -m pytest -q -p no:warnings "$T" 2>&1 | tail -4)
  if printf '%s' "$out" | grep -q failed; then
    printf '  [detected] %-34s %s\n' "$1" "$(printf '%s' "$out" | grep -oE 'FAILED [^ ]+' | head -1 | sed 's/FAILED //')"
  else
    printf '  [VACUOUS]  %-34s the gate still passes\n' "$1"
    fail=1
  fi
}

printf 'negative controls for the failure-code registry gate\n\n'

# C1 -- a code the modules emit stops being documented.
CODE=$(grep -ohE '`[a-z_]+\.[a-z_]+`' "$REG" | head -1 | tr -d '`')
cp "$REG" "$REG.control-backup"
perl -0pi -e "s/\`\Q$CODE\E\`/\`REDACTED_BY_CONTROL\`/g" "$REG"
expect_failure "omitted code ($CODE)"
mv "$REG.control-backup" "$REG"

# C2 -- a new emitting module escapes the fixed MODULES list. This is the
# property that once let governed_memory_sequence.py through unnoticed.
PROBE=arcs_verify/_control_probe_emitting_module.py
cat > "$PROBE" <<'PYEOF'
"""Transient control fixture; removed by tools/qualify_failure_code_registry.sh."""


def _fail(report, code, detail):
    return report


def check(report):
    return _fail(report, "control_probe.unregistered_code", "probe")
PYEOF
expect_failure "unregistered emitting module"
rm -f "$PROBE"

# C3 -- the registry invents a code nothing emits. Scoped deliberately: the gate
# reads the receipt-set..amnesiac-chain section and matches dotless identifiers,
# so the control must be placed there to be meaningful.
cp "$REG" "$REG.control-backup"
$PY - "$REG" <<'PYEOF'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
anchor = "## `amnesiac-chain` subcommand"
index = text.index(anchor)
row = "| `zz_phantom_code` | Never emitted by receipt_set or deferred_sequence. |\n\n"
open(path, "w", encoding="utf-8").write(text[:index] + row + text[index:])
PYEOF
expect_failure "phantom documented code"
mv "$REG.control-backup" "$REG"

printf '\npost-conditions\n'
AFTER=$(shasum -a 256 "$REG" | cut -d' ' -f1)
[ "$BEFORE" = "$AFTER" ] && printf '  registry restored byte-identical\n' || { printf '  !! registry NOT restored\n'; fail=1; }
[ -e "$PROBE" ] && { printf '  !! control probe left behind\n'; fail=1; } || printf '  control probe removed\n'
$PY -m pytest -q -p no:warnings "$T" 2>&1 | grep -E 'passed|failed' | tail -1 | sed 's/^/  gate green again: /'

if [ $fail -eq 0 ]; then printf '\nREGISTRY_CONTROLS=ALL_FIRE\n'; exit 0; fi
printf '\nREGISTRY_CONTROLS=PROBLEM\n'; exit 1
