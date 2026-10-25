#!/bin/sh
# Self-test for tools/qualify_failure_code_registry.sh.
#
# That script mutates tracked files, so its REFUSAL paths matter as much as its
# detections: a harness that corrupts the tree while reporting failure is worse
# than one that simply misses a defect. Each case below injects one fault and
# requires the runner to stop AND to leave every tracked file and every foreign
# artifact exactly as it found them.
#
# Case 3 and case 4 exist because `test -e` follows symbolic links, so a
# DANGLING link is invisible to it. Before that was fixed, a dangling backup
# symlink passed preflight and was then moved over docs/FAILURE_CODES.md,
# replacing a tracked file with a broken link and destroying its contents.
#
# Offline, and custody-safe in the same way: it refuses to start if any artifact
# it would create already exists, and removes only what it made.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
PY=${PY:-./.venv-q/bin/python}
[ -x "$PY" ] || PY=python3
export PY

# Overridable so this self-test can be aimed at a previous revision of the
# runner, which is how its own non-vacuity is demonstrated.
RUNNER=${RUNNER:-tools/qualify_failure_code_registry.sh}
REG=docs/FAILURE_CODES.md
PROBE=arcs_verify/_control_probe_emitting_module.py
BACKUP="$REG.control-backup"
GHOST="$ROOT/.selftest_ghost_target"
COPY=tools/.selftest_runner_copy.sh
fail=0

exists_any() { [ -e "$1" ] || [ -L "$1" ]; }

for p in "$BACKUP" "$PROBE" "$GHOST" "$COPY"; do
  if exists_any "$p"; then
    printf 'selftest: BLOCKED -- %s already exists; move it aside first\n' "$p" >&2
    exit 2
  fi
done
[ -f "$RUNNER" ] || { printf 'selftest: BLOCKED -- %s not found\n' "$RUNNER" >&2; exit 2; }

cleanup() { rm -f "$BACKUP" "$PROBE" "$GHOST" "$COPY"; }
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

PRISTINE=$(shasum -a 256 "$REG" | cut -d' ' -f1)

check() {  # label, observed exit, expected exit
  if [ "$2" = "$3" ]; then
    printf '  [ok]   %-38s exit %s\n' "$1" "$2"
  else
    printf '  [FAIL] %-38s exit %s, expected %s\n' "$1" "$2" "$3"
    fail=1
  fi
}
assert_registry_intact() {
  if [ -L "$REG" ]; then
    printf '         %-38s !! tracked registry is now a SYMLINK\n' "$1"; fail=1
  elif [ "$(shasum -a 256 "$REG" 2>/dev/null | cut -d' ' -f1)" != "$PRISTINE" ]; then
    printf '         %-38s !! tracked registry was modified\n' "$1"; fail=1
  fi
}
assert_preserved() {  # the foreign artifact must survive untouched
  if [ "$2" = symlink ]; then
    [ -L "$1" ] || { printf '         %-38s !! foreign symlink %s was consumed\n' "$3" "$1"; fail=1; }
  else
    [ -f "$1" ] || { printf '         %-38s !! foreign file %s was consumed\n' "$3" "$1"; fail=1; }
  fi
}
assert_absent() {
  exists_any "$1" && { printf '         %-38s !! %s was created\n' "$2" "$1"; fail=1; }
  return 0
}

printf 'self-test for %s\n\n' "$RUNNER"

# 1 -- an ordinary leftover backup must not be adopted
printf 'leftover-backup\n' > "$BACKUP"
sh "$RUNNER" >/dev/null 2>&1; check "plain pre-existing backup" "$?" 2
assert_registry_intact "plain pre-existing backup"
assert_preserved "$BACKUP" file "plain pre-existing backup"
rm -f "$BACKUP"

# 2 -- an ordinary leftover probe must not be deleted
printf '# someone elses module\n' > "$PROBE"
sh "$RUNNER" >/dev/null 2>&1; check "plain pre-existing probe" "$?" 2
assert_preserved "$PROBE" file "plain pre-existing probe"
rm -f "$PROBE"

# 3 -- a DANGLING backup symlink: invisible to `test -e`
ln -s "$GHOST" "$BACKUP"
sh "$RUNNER" >/dev/null 2>&1; check "dangling backup symlink" "$?" 2
assert_registry_intact "dangling backup symlink"
assert_preserved "$BACKUP" symlink "dangling backup symlink"
assert_absent "$GHOST" "dangling backup symlink"
rm -f "$BACKUP"

# 4 -- a DANGLING probe symlink
ln -s "$GHOST" "$PROBE"
sh "$RUNNER" >/dev/null 2>&1; check "dangling probe symlink" "$?" 2
assert_preserved "$PROBE" symlink "dangling probe symlink"
assert_absent "$GHOST" "dangling probe symlink"
rm -f "$PROBE"

# 5 -- a control aimed at a sibling gate proves nothing about its own
cp "$RUNNER" "$COPY"
perl -0pi -e 's/expect_fail "omitted static code" test_every_emitted_code_is_in_the_registry/expect_fail "omitted static code" test_no_emitting_module_is_unregistered/' "$COPY"
out=$(sh "$COPY" 2>&1); status=$?
check "control aimed at a sibling test" "$status" 1
printf '%s\n' "$out" | grep -q 'VACUOUS' || { printf '         %-38s !! no VACUOUS report\n' "sibling"; fail=1; }
assert_registry_intact "control aimed at a sibling test"
rm -f "$COPY"

# 6 -- a skipped restore must be caught, and must not leave the tree dirty
cp "$RUNNER" "$COPY"
perl -0pi -e 's/^restore "\$REG" \|\| exit 1\n\n# --- C2/\n# --- C2/m' "$COPY"
sh "$COPY" >/dev/null 2>&1; check "a restore removed" "$?" 1
assert_registry_intact "a restore removed"
rm -f "$COPY"

printf '\npost-conditions\n'
assert_registry_intact "final"
for p in "$BACKUP" "$PROBE" "$GHOST" "$COPY"; do
  exists_any "$p" && { printf '  !! leftover: %s\n' "$p"; fail=1; }
done
printf '  tracked registry byte-identical: %s\n' "$([ "$(shasum -a 256 "$REG" | cut -d' ' -f1)" = "$PRISTINE" ] && echo yes || echo NO)"

if [ $fail -eq 0 ]; then printf '\nRUNNER_SELFTEST=ALL_REFUSALS_HOLD\n'; exit 0; fi
printf '\nRUNNER_SELFTEST=PROBLEM\n'
exit 1
