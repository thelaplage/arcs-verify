#!/bin/sh
# Self-test for tools/qualify_failure_code_registry.sh.
#
# The runner is a harness, and a harness fails in two directions: it can miss a
# defect (a vacuous "all fire"), and it can damage what it is guarding. Each case
# below injects ONE fault and requires the runner to refuse or to report the
# right failure -- and, in every case, to leave the tree exactly as found.
#
#   refusals      stray backup / probe files, DANGLING symlinks (invisible to
#                 `test -e`), a missing or explicit-but-absent interpreter, an
#                 interpreter without pytest
#   non-vacuity   a harness that collects zero tests, a package that resolves
#                 to somewhere other than the snapshot, a gate whose assertion
#                 was removed, a gate that is already red, a control aimed at a
#                 sibling test, a control whose token the failure never names, a
#                 mutation that does not apply
#   safety        a full run leaves the tree byte-identical; SIGKILL and SIGTERM
#                 mid-mutation leave it byte-identical; a tree altered DURING the
#                 run is reported
#
# Every case runs against a throwaway COPY of the tree in a private temp
# directory, never the checkout, so a runner under test -- including the earlier
# in-place revision this one is aimed at in order to prove the self-test bites --
# can only damage the copy. The checkout is digest-inventoried before and after
# and must be byte-identical.
#
# Offline. Needs the same python env as the runner. RUNNER and PY are overridable.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
PY=${PY:-./.venv-q/bin/python}
[ -x "$PY" ] || PY=python3
case "$PY" in /*) ;; */*) PY=$ROOT/$PY ;; *) PY=$(command -v "$PY") ;; esac
[ -x "$PY" ] || { printf 'selftest: BLOCKED -- no usable python (PY=%s)\n' "$PY" >&2; exit 2; }
RUNNER=${RUNNER:-tools/qualify_failure_code_registry.sh}
[ -f "$RUNNER" ] || { printf 'selftest: BLOCKED -- %s not found\n' "$RUNNER" >&2; exit 2; }
case "$RUNNER" in /*) RUNNER_ABS=$RUNNER ;; *) RUNNER_ABS=$ROOT/$RUNNER ;; esac

SELFTMP=$(mktemp -d "${TMPDIR:-/tmp}/registry-selftest.XXXXXX") || exit 2
FIX=$SELFTMP/fixture          # throwaway copy of the tree the runner is aimed at
RUNTMP=$SELFTMP/runner-tmp    # the runner's private $TMPDIR, so leaks are visible
STATE=$SELFTMP/state          # shim state
SHIM=$SELFTMP/shim.sh
mkdir -p "$RUNTMP" "$STATE"
LIVE_PIDS=''
fail=0

cleanup() {
  for p in $LIVE_PIDS; do kill -9 "$p" 2>/dev/null; done
  case "$SELFTMP" in */registry-selftest.*) rm -rf "$SELFTMP" ;; esac
  return 0
}
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

treesum() {  # one digest over every gated file name + content under $1
  ( cd "$1" && find arcs_verify docs tests tools pyproject.toml \
      \( -type f -o -type l \) ! -path '*/__pycache__/*' ! -name '*.pyc' -print 2>/dev/null \
    | LC_ALL=C sort | while IFS= read -r f; do
        if [ -L "$f" ]; then printf 'L %s %s\n' "$f" "$(readlink "$f")"
        else printf 'F %s %s\n' "$f" "$(shasum -a 256 "$f" | cut -d' ' -f1)"; fi
      done | shasum -a 256 | cut -d' ' -f1 )
}
CHECKOUT_BEFORE=$(treesum "$ROOT")

ok()   { printf '  [ok]   %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=1; }
check_exit() {  # label observed expected
  if [ "$2" = "$3" ]; then ok "$1 -> exit $2"; else bad "$1 -> exit $2, expected $3"; fi
}
expect_text() {  # label file pattern
  if grep -qE "$3" "$2"; then ok "$1 reports /$3/"; else bad "$1 did not report /$3/"; fi
}
refute_text() {
  if grep -qE "$3" "$2"; then bad "$1 reported /$3/ and must not have"; else ok "$1 did not report /$3/"; fi
}

fresh_fixture() {
  rm -rf "$FIX"
  mkdir -p "$FIX/tools"
  for d in arcs_verify docs tests; do cp -R "$ROOT/$d" "$FIX/$d"; done
  cp "$ROOT/pyproject.toml" "$FIX/pyproject.toml"
  cp "$RUNNER_ABS" "$FIX/tools/qualify_failure_code_registry.sh"
  find "$FIX" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null
  rm -rf "$RUNTMP"; mkdir -p "$RUNTMP"; rm -rf "$STATE"; mkdir -p "$STATE"
  MODE=plain; AT=0; TOUCH=/dev/null
  FIX_SUM=$(treesum "$FIX")
}

# A python shim: passes through to the real interpreter, injecting one fault.
cat > "$SHIM" <<'SHIMEOF'
#!/bin/sh
# SHIM_MODE: nopytest | zero | safepath | stall | touch | plain
real=$SHIM_REAL
is_pytest=no
[ "${1:-}" = "-m" ] && [ "${2:-}" = "pytest" ] && is_pytest=yes
case "$SHIM_MODE" in
  nopytest) [ "${1:-}" = "-c" ] && case "${2:-}" in *"import pytest"*) exit 1 ;; esac ;;
  zero)     [ $is_pytest = yes ] && exec "$real" "$@" -k __no_such_test_selected__ ;;
  safepath) exec env PYTHONSAFEPATH=1 "$real" "$@" ;;
  stall|touch)
    if [ $is_pytest = yes ]; then
      n=$(cat "$SHIM_STATE/n" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$SHIM_STATE/n"
      if [ "$n" -eq "$SHIM_AT" ]; then
        if [ "$SHIM_MODE" = stall ]; then
          echo $$ > "$SHIM_STATE/pid"; echo $PPID > "$SHIM_STATE/ppid"; : > "$SHIM_STATE/stalled"
          exec sleep 120
        else
          printf '\n' >> "$SHIM_TOUCH"
        fi
      fi
    fi ;;
esac
exec "$real" "$@"
SHIMEOF
chmod +x "$SHIM"

# run_runner OUTFILE PYVALUE [args...]  -- inside the fixture. The shim fault is
# chosen with the globals MODE / AT / TOUCH, which fresh_fixture resets.
run_runner() {
  out=$1; pyv=$2; shift 2
  ( cd "$FIX" && env TMPDIR="$RUNTMP" PY="$pyv" SHIM_REAL="$PY" SHIM_STATE="$STATE" \
      SHIM_MODE="$MODE" SHIM_AT="$AT" SHIM_TOUCH="$TOUCH" \
      sh tools/qualify_failure_code_registry.sh "$@" ) >"$out" 2>&1
}
leaks() { find "$RUNTMP" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' '; }
sum_unchanged() {  # label
  if [ "$(treesum "$FIX")" = "$FIX_SUM" ]; then ok "$1: tree byte-identical"; else bad "$1: TREE WAS MODIFIED"; fi
}
edit_runner() {  # perl-expr label  -- edit the fixture's copy of the runner; the edit must take
  cp "$FIX/tools/qualify_failure_code_registry.sh" "$SELFTMP/before.sh"
  perl -0pi -e "$1" "$FIX/tools/qualify_failure_code_registry.sh"
  if cmp -s "$SELFTMP/before.sh" "$FIX/tools/qualify_failure_code_registry.sh"; then
    bad "$2: the self-test's own edit did not apply"; return 1
  fi
  FIX_SUM=$(treesum "$FIX"); return 0
}

printf 'self-test for %s\n' "$RUNNER"
printf 'python: %s\n\n' "$("$PY" --version 2>&1)"
OUT=$SELFTMP/out

# ---- A. refusals: the runner must stop and leave foreign artifacts alone -----
printf 'refusals\n'
GHOST=$FIX/.selftest_ghost_target
BACKUP=docs/FAILURE_CODES.md.control-backup
PROBE=arcs_verify/_control_probe_emitting_module.py

fresh_fixture; printf 'leftover\n' > "$FIX/$BACKUP"; FIX_SUM=$(treesum "$FIX")
run_runner "$OUT" "$PY"; check_exit "stray backup file" "$?" 2
[ -f "$FIX/$BACKUP" ] && ok "stray backup file: preserved" || bad "stray backup file was consumed"
sum_unchanged "stray backup file"

fresh_fixture; printf '# someone elses module\n' > "$FIX/$PROBE"; FIX_SUM=$(treesum "$FIX")
run_runner "$OUT" "$PY"; check_exit "stray probe file" "$?" 2
[ -f "$FIX/$PROBE" ] && ok "stray probe file: preserved" || bad "stray probe file was consumed"
sum_unchanged "stray probe file"

fresh_fixture; ln -s "$GHOST" "$FIX/$BACKUP"; FIX_SUM=$(treesum "$FIX")
run_runner "$OUT" "$PY"; check_exit "dangling backup symlink" "$?" 2
[ -L "$FIX/$BACKUP" ] && ok "dangling backup symlink: preserved" || bad "dangling backup symlink was consumed"
[ -e "$GHOST" ] || [ -L "$GHOST" ] && bad "dangling backup symlink: target was created" || ok "dangling backup symlink: target never created"
[ -L "$FIX/docs/FAILURE_CODES.md" ] && bad "tracked registry became a symlink" || ok "dangling backup symlink: tracked registry still a regular file"
sum_unchanged "dangling backup symlink"

fresh_fixture; ln -s "$GHOST" "$FIX/$PROBE"; FIX_SUM=$(treesum "$FIX")
run_runner "$OUT" "$PY"; check_exit "dangling probe symlink" "$?" 2
[ -L "$FIX/$PROBE" ] && ok "dangling probe symlink: preserved" || bad "dangling probe symlink was consumed"
[ -e "$GHOST" ] || [ -L "$GHOST" ] && bad "dangling probe symlink: target was created" || ok "dangling probe symlink: target never created"

fresh_fixture
run_runner "$OUT" /nonexistent/python; check_exit "explicit PY that does not exist (no silent fallback)" "$?" 2
[ "$(leaks)" = 0 ] && ok "no temp tree created" || bad "temp tree created for a refused run"

fresh_fixture
MODE=nopytest; run_runner "$OUT" "$SHIM"; check_exit "interpreter without pytest" "$?" 2
sum_unchanged "interpreter without pytest"

# ---- B. non-vacuity: every way a harness can read "killed" without killing ---
printf '\nnon-vacuity (C1 only; each must fail closed)\n'
fresh_fixture
MODE=zero; run_runner "$OUT" "$SHIM" C1; st=$?
check_exit "harness that collects zero tests" "$st" 1
expect_text "zero-test harness" "$OUT" 'BASELINE_RED'
refute_text "zero-test harness" "$OUT" '\[killed'
sum_unchanged "zero-test harness"

fresh_fixture
MODE=safepath; run_runner "$OUT" "$SHIM" C1; check_exit "package resolving outside the snapshot" "$?" 2
expect_text "unresolvable package" "$OUT" 'BLOCKED: arcs_verify resolves to'

fresh_fixture; perl -0pi -e 's/assert not missing, \(\n        "codes emitted but absent/assert True, (\n        "codes emitted but absent/' "$FIX/tests/test_failure_code_registry.py"
if grep -q 'assert True, (' "$FIX/tests/test_failure_code_registry.py"; then FIX_SUM=$(treesum "$FIX")
  run_runner "$OUT" "$PY" C1; check_exit "gate with its assertion removed" "$?" 1
  expect_text "defanged gate" "$OUT" 'SURVIVED'
  refute_text "defanged gate" "$OUT" '\[killed'
else bad "defanged gate: the self-test's own edit did not apply"; fi

# One extractor branch removed from the gate (the `code=` keyword harvest). Only the
# per-shape controls for that branch can see it; they must survive-report it.
fresh_fixture; perl -0pi -e 's/if keyword\.arg == "code":/if False:/' "$FIX/tests/test_failure_code_registry.py"
if grep -q 'if False:' "$FIX/tests/test_failure_code_registry.py"; then FIX_SUM=$(treesum "$FIX")
  run_runner "$OUT" "$PY" S05 S10; check_exit "gate with one extractor branch removed" "$?" 1
  expect_text "removed extractor branch" "$OUT" 'SURVIVED .*S05 +code_keyword '
  expect_text "removed extractor branch" "$OUT" 'SURVIVED .*S10 +code_keyword_f'
  refute_text "removed extractor branch" "$OUT" '\[killed'
else bad "removed extractor branch: the self-test's own edit did not apply"; fi

fresh_fixture; perl -0pi -e 's/`schema\.digest_mismatch`/`schema.digest_mismatch_REMOVED`/g' "$FIX/docs/FAILURE_CODES.md"
FIX_SUM=$(treesum "$FIX")
run_runner "$OUT" "$PY" C1; check_exit "gate already red before any mutation" "$?" 1
expect_text "red baseline" "$OUT" 'BASELINE_RED'
refute_text "red baseline" "$OUT" '\[killed'

fresh_fixture
if edit_runner 's/("omitted static code", "wanted": )T_STATIC/${1}T_MODULE/' "control aimed at a sibling test"; then
  run_runner "$OUT" "$PY" C1; check_exit "control aimed at a sibling test" "$?" 1
  expect_text "sibling-aimed control" "$OUT" 'SURVIVED'
fi

fresh_fixture
if edit_runner 's/"token": f": \{first_code\}"/"token": "no_such_token_in_any_failure"/' "kill that never names its mutation"; then
  run_runner "$OUT" "$PY" C1; check_exit "kill that never names its mutation" "$?" 1
  expect_text "unattributed kill" "$OUT" 'MISATTRIBUTED'
fi

fresh_fixture
if edit_runner 's/## `amnesiac-chain` subcommand"\)\n        row/## `no-such-heading` subcommand")\n        row/' "mutation that does not apply"; then
  run_runner "$OUT" "$PY" C3; check_exit "mutation that does not apply" "$?" 1
  expect_text "inapplicable mutation" "$OUT" 'INVALID'
  refute_text "inapplicable mutation" "$OUT" '\[killed'
fi

# ---- C. safety: the tree under test is never what gets mutated ---------------
printf '\nsafety\n'
fresh_fixture
MODE=touch; AT=3; TOUCH="$FIX/docs/FAILURE_CODES.md"; run_runner "$OUT" "$SHIM"; st=$?
check_exit "tree altered by someone else DURING the run" "$st" 1
expect_text "mid-run alteration" "$OUT" 'REAL TREE CHANGED'

for sig in KILL TERM; do
  fresh_fixture
  # exec: $! must be the runner's OWN pid, not that of a wrapper subshell
  ( cd "$FIX" && exec env TMPDIR="$RUNTMP" PY="$SHIM" SHIM_REAL="$PY" SHIM_STATE="$STATE" \
      SHIM_MODE=stall SHIM_AT=3 sh tools/qualify_failure_code_registry.sh ) >"$OUT" 2>&1 &
  rpid=$!; LIVE_PIDS="$LIVE_PIDS $rpid"
  i=0; while [ ! -e "$STATE/stalled" ] && [ $i -lt 400 ]; do sleep 0.2; i=$((i + 1)); done
  if [ ! -e "$STATE/stalled" ]; then bad "SIG$sig: the run never reached a live mutation (cannot test)"; kill -9 "$rpid" 2>/dev/null; continue; fi
  spid=$(cat "$STATE/pid"); epid=$(cat "$STATE/ppid")
  ok "SIG$sig: run stalled with a mutation live (runner $rpid, interpreter parent $epid, pytest stand-in $spid)"
  kill -$sig "$rpid" 2>/dev/null
  { wait "$rpid"; } 2>/dev/null; st=$?
  kill -0 "$rpid" 2>/dev/null && bad "SIG$sig: the runner process survived" || ok "SIG$sig: the runner process is gone"
  if [ "$sig" = TERM ]; then
    check_exit "SIGTERM mid-mutation (the runner's own trap)" "$st" 143
    kill -0 "$epid" 2>/dev/null && bad "SIGTERM: the control engine outlived the runner" || ok "SIGTERM: the control engine was stopped"
    kill -0 "$spid" 2>/dev/null && bad "SIGTERM: the pytest stand-in outlived the runner" || ok "SIGTERM: the pytest stand-in was stopped"
    [ "$(leaks)" = 0 ] && ok "SIGTERM: temp tree removed" || bad "SIGTERM: temp tree left behind"
  else
    # a SIGKILL cannot be trapped: the engine and its child run on, orphaned
    kill -0 "$epid" 2>/dev/null && ok "SIGKILL: the engine was orphaned, as a handler-less kill implies" || ok "SIGKILL: the engine had already exited"
    n=$(leaks)
    [ "$n" -le 1 ] && ok "SIGKILL: $n orphaned temp dir under the runner's TMPDIR; none under the checkout" || bad "SIGKILL: $n temp dirs"
  fi
  for q in "$epid" "$spid"; do kill -9 "$q" 2>/dev/null; done
  sleep 0.3
  sum_unchanged "SIG$sig mid-mutation"
done

fresh_fixture
run_runner "$OUT" "$PY"; st=$?
check_exit "complete run" "$st" 0
expect_text "complete run" "$OUT" 'REGISTRY_CONTROLS=ALL_FIRE'
expect_text "complete run" "$OUT" 'baseline: unmutated gate GREEN, [0-9]+/[0-9]+ tests ran and passed'
sum_unchanged "complete run"
[ "$(leaks)" = 0 ] && ok "complete run: temp tree removed" || bad "complete run: temp tree left behind"

# ---- the checkout itself ---------------------------------------------------------
printf '\npost-conditions\n'
if [ "$(treesum "$ROOT")" = "$CHECKOUT_BEFORE" ]; then ok "checkout byte-identical before and after the self-test"
else bad "CHECKOUT WAS MODIFIED"; fi

if [ $fail -eq 0 ]; then printf '\nRUNNER_SELFTEST=ALL_HOLD\n'; exit 0; fi
printf '\nRUNNER_SELFTEST=PROBLEM\n'
exit 1
