#!/bin/sh
# Negative controls for tests/test_failure_code_registry.py.
#
# The registry gate is a completeness check, and a completeness check that
# cannot fail is worth nothing. Every control below introduces one real omission
# or invention and requires THE SPECIFIC TEST that protects that property to
# fail, for the right reason:
#
#   * the unmutated gate is run first and must be green with its FULL test count,
#     so a harness that collects nothing cannot read as "every mutant killed";
#   * a mutant is KILLED only if the whole suite ran, the NAMED test failed,
#     nothing else failed, and the failure text names the mutated token --
#     "some test failed" and "pytest exited non-zero" are both rejected;
#   * each of the gate's sites is mutated separately: all five properties, every
#     module in the gate's MODULES list, and every emission shape its extractor
#     claims to recognise (each shape also run with its registered twin, which
#     must be green, so the kill is the registry's absence and nothing else);
#   * modules that contribute nothing to the gate are reported, not skipped.
#
# SAFETY: nothing here writes to the repository. The tree is snapshotted into a
# private temp directory and every mutant is applied to its own fresh copy of
# that snapshot, so there is nothing to "restore" and nothing a SIGKILL, crash or
# concurrent reader of the checkout can see. The real tree is digest-inventoried
# before and after and must be byte-identical; the temp tree is removed on exit,
# INT, TERM and HUP. (A SIGKILL cannot run a handler: it can orphan the temp
# directory under $TMPDIR, never touch the checkout.)
#
# Offline: no network, nothing installed, no commit, no push.
# Needs a python env with pytest (`pip install -e .[dev]`). The package is read
# from the snapshot, never from an installed copy; the run is refused if it
# would not resolve there. Override the interpreter with PY=/path/to/python.
#
# usage: sh tools/qualify_failure_code_registry.sh [CONTROL_ID_PREFIX ...]
#   no argument  every control; exit 0 only for REGISTRY_CONTROLS=ALL_FIRE
#   C1 M S       a subset; can never report ALL_FIRE (exit 3 = PARTIAL)
# exit: 0 all fire / 1 problem / 2 blocked before any mutation / 3 partial
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

T=tests/test_failure_code_registry.py
REG=docs/FAILURE_CODES.md
REG2=docs/FAILURE_CODES_EXTERNAL_PROFILE.md
VERIFIER=arcs_verify/verifier.py
FINDINGS=arcs_verify/findings.py
PROBE=arcs_verify/_control_probe_emitting_module.py
TRACKED="$REG $REG2 $VERIFIER $FINDINGS"

# `test -e` FOLLOWS symbolic links, so a dangling link is invisible to it.
exists_any() { [ -e "$1" ] || [ -L "$1" ]; }
blocked() { printf 'qualify: BLOCKED -- %s\n' "$1" >&2; exit 2; }

# --- interpreter -----------------------------------------------------------
if [ -n "${PY:-}" ]; then
  PYREQ=explicit
else
  PYREQ=default
  PY=./.venv-q/bin/python
  [ -x "$PY" ] || PY=python3
fi
case "$PY" in
  /*) ;;
  */*) PY=$ROOT/$PY ;;
  *) PY=$(command -v "$PY" 2>/dev/null || true) ;;
esac
[ -n "$PY" ] && [ -x "$PY" ] || blocked "interpreter not executable (PY is $PYREQ); refusing to fall back silently"
"$PY" -c 'import pytest' >/dev/null 2>&1 || blocked "$PY cannot import pytest"

# --- preflight: nothing below may start on a tree it cannot trust ------------
for f in $TRACKED $T; do
  [ -f "$f" ] || blocked "$f not found; run this from the repository (ROOT=$ROOT)"
  [ -L "$f" ] && blocked "$f is a symbolic link; refusing to snapshot it"
done
# An earlier in-place version of this runner left these behind when it was
# killed, together with a MUTATED tracked file. The tree is then not pristine.
collisions=''
for f in $TRACKED; do
  exists_any "$f.control-backup" && collisions="$collisions $f.control-backup"
done
exists_any "$PROBE" && collisions="$collisions $PROBE"
if [ -n "$collisions" ]; then
  printf 'qualify: BLOCKED -- these paths already exist and do not belong to this run:\n' >&2
  for c in $collisions; do printf '    %s\n' "$c" >&2; done
  printf '  A previous run may have been killed, or they belong to another process.\n' >&2
  printf '  Inspect and move them aside yourself: this script will neither delete\n' >&2
  printf '  them nor treat the tree as pristine while they exist.\n' >&2
  exit 2
fi

# --- custody: the only thing this script ever removes is its own temp tree ----
WORK=''
ENGINE_PID=''
cleanup() {
  if [ -n "$ENGINE_PID" ]; then
    kill "$ENGINE_PID" 2>/dev/null
    wait "$ENGINE_PID" 2>/dev/null
    ENGINE_PID=''
  fi
  case "$WORK" in
    */registry-controls.*) [ -d "$WORK" ] && rm -rf "$WORK" ;;
  esac
  return 0
}
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

TMPBASE=${TMPDIR:-/tmp}
WORK=$(mktemp -d "${TMPBASE%/}/registry-controls.XXXXXX") || blocked "cannot create a temp directory"
WORKPATH=$WORK

printf 'negative controls for the failure-code registry gate\n'
printf 'interpreter: %s (PY %s)\n' "$("$PY" --version 2>&1)" "$PYREQ"
printf 'tree:        %s\n' "$ROOT"
printf 'temp tree:   %s (private; removed on exit)\n\n' "$WORKPATH"

cat > "$WORK/engine.py" <<'PYEOF'
"""Control engine for tools/qualify_failure_code_registry.sh (embedded there).

Nothing here ever writes to the repository.  The tree under test is snapshotted
once into a pristine copy; every mutant is applied to its OWN fresh copy of that
snapshot, run, and discarded.  "Restore" is therefore "throw the copy away", and
the proof of it is a digest inventory taken of the real tree before and after.
"""

import ast
import hashlib
import importlib.util
import os
import re
import shutil
import signal
import subprocess
import sys
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(sys.argv[1])
WORK = Path(sys.argv[2])
PYEXE = sys.argv[3]
ONLY = tuple(sys.argv[4:])

TEST = "tests/test_failure_code_registry.py"
REGS = ("docs/FAILURE_CODES.md", "docs/FAILURE_CODES_EXTERNAL_PROFILE.md")
PROBE = "arcs_verify/_control_probe_emitting_module.py"
SHAPE_HOST = "arcs_verify/universal.py"
SNAP_FILES = (TEST, "pyproject.toml") + REGS
SNAP_TREES = ("arcs_verify",)
PROOF_FILES = ("pyproject.toml",)
PROOF_TREES = ("arcs_verify", "docs", "tests", "tools")

T_STATIC = "test_every_emitted_code_is_in_the_registry"
T_FAMILY = "test_every_dynamic_family_prefix_is_in_the_registry"
T_PHANTOM = "test_registry_lists_no_phantom_static_codes"
T_PHANTOM_WIDE = "test_registry_documents_no_code_unknown_to_the_verifier"
T_MODULE = "test_no_emitting_module_is_unregistered"
T_SIGNATURE = "test_every_signature_failure_code_is_in_the_registry"

# Modules that are in the gate's MODULES list yet contribute NOTHING to its
# failure domain at the pristine bytes: a new code emitted there would not be
# seen.  That is a property of the gate (it is a byte-identical port), reported
# here instead of being hidden behind a green line.  The table is two-sided: a
# blind module that is not listed, or a listed module that is no longer blind,
# is a PROBLEM, so the list can neither grow nor go stale silently.
KNOWN_BLIND = {
    "arcs_verify/c2pa_native.py":
        "codes go through a self.fail(...) method the sweep does not recognise",
    "arcs_verify/findings.py":
        "owned codes sit in frozenset({...}) literals and are copied by "
        "failure_codes.append(code); no emitting call site carries a literal",
    "arcs_verify/cg_execution_replay.py":
        "failure_code= keyword is not harvested; the only harvest is the "
        "digest prefix 'sha256:', which is not a code family",
    "arcs_verify/cg_replay.py":
        "failure_code= keyword is not harvested; the only harvest is the "
        "digest prefix 'sha256:', which is not a code family",
}


def log(line=""):
    print(line, flush=True)


def _term(_signum, _frame):
    raise SystemExit(143)


signal.signal(signal.SIGTERM, _term)
signal.signal(signal.SIGHUP, _term)


# --- inventories ------------------------------------------------------------
def _walk(base, trees, files):
    seen = []
    for rel in files:
        if (base / rel).exists() or (base / rel).is_symlink():
            seen.append(rel)
    for tree in trees:
        top = base / tree
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for name in sorted(filenames):
                if name.endswith(".pyc"):
                    continue
                seen.append((Path(dirpath) / name).relative_to(base).as_posix())
    return seen


def inventory(base, trees, files):
    out = {}
    for rel in _walk(base, trees, files):
        path = base / rel
        if path.is_symlink():
            out[rel] = "SYMLINK->" + os.readlink(path)
        else:
            out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def differing(a, b):
    return {k for k in set(a) | set(b) if a.get(k) != b.get(k)}


# --- one gate run ------------------------------------------------------------
class Run:
    def __init__(self, rc, cases, tail):
        self.rc = rc
        self.cases = cases  # name -> (state, text)
        self.tail = tail

    @property
    def ran(self):
        return len(self.cases)

    @property
    def failed(self):
        return {n for n, (s, _) in self.cases.items() if s in ("fail", "error")}


def run_gate(sandbox, tag):
    report = WORK / f"{tag}.junit.xml"
    cmd = [PYEXE, "-m", "pytest", "-q", "-p", "no:warnings", "-p", "no:cacheprovider",
           "--junitxml", str(report), TEST]
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        cp = subprocess.run(cmd, cwd=sandbox, env=env, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return Run(None, {}, "timeout")
    tail = (cp.stdout or cp.stderr or "").strip().splitlines()[-3:]
    if not report.is_file():
        return Run(cp.returncode, {}, " | ".join(tail))
    cases = {}
    for tc in ET.parse(report).getroot().iter("testcase"):
        state, text = "pass", ""
        for child in tc:
            if child.tag in ("failure", "error"):
                state = "fail" if child.tag == "failure" else "error"
                text = (child.get("message") or "") + "\n" + (child.text or "")
            elif child.tag == "skipped":
                state = "skip"
        cases[tc.get("name")] = (state, text)
    return Run(cp.returncode, cases, " | ".join(tail))


# --- state -------------------------------------------------------------------
problems = []
counts = {"killed": 0, "controls": 0, "paired": 0, "pairs": 0}


def problem(message):
    problems.append(message)


def selected(control_id):
    return not ONLY or any(control_id.startswith(prefix) for prefix in ONLY)


def read(sb, rel):
    return (sb / rel).read_text(encoding="utf-8")


def write(sb, rel, text):
    (sb / rel).write_text(text, encoding="utf-8", newline="\n")


def main():
    # 1. snapshot the real tree into a pristine copy, faithfully
    real_before = inventory(ROOT, PROOF_TREES, PROOF_FILES)
    pristine = WORK / "pristine"
    for rel in SNAP_FILES:
        if not (ROOT / rel).is_file() or (ROOT / rel).is_symlink():
            log(f"BLOCKED: {rel} is not a regular file")
            return 2
    snap_before = inventory(ROOT, SNAP_TREES, SNAP_FILES)
    if any(v.startswith("SYMLINK->") for v in snap_before.values()):
        log("BLOCKED: a symbolic link sits inside the snapshot set; refusing to copy it")
        return 2
    for rel in snap_before:
        dst = pristine / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dst)
    inv_pristine = inventory(pristine, SNAP_TREES, SNAP_FILES)
    if inv_pristine != snap_before:
        log("BLOCKED: pristine snapshot differs from the real tree")
        return 2
    log(f"snapshot: {len(inv_pristine)} files copied; pristine == real tree (digest inventory)")

    sandboxes = WORK / "sandboxes"
    sandboxes.mkdir()

    def sandbox(name):
        sb = sandboxes / name
        shutil.copytree(pristine, sb)
        if differing(inv_pristine, inventory(sb, SNAP_TREES, SNAP_FILES)):
            raise RuntimeError(f"sandbox {name} is not a faithful copy of the pristine tree")
        return sb

    # 2. the gate's own extraction, read from the pristine copy
    spec = importlib.util.spec_from_file_location("registry_gate_under_test", pristine / TEST)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    expected_tests = {
        n.name for n in ast.parse((pristine / TEST).read_text(encoding="utf-8")).body
        if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
    }

    # 3. package resolution: a sandbox that imports the REAL tree would make the
    #    signature control vacuous (an editable install elsewhere is common here)
    probe_sb = sandbox("resolve")
    cp = subprocess.run([PYEXE, "-c", "import arcs_verify,sys; sys.stdout.write(arcs_verify.__file__)"],
                        cwd=probe_sb, capture_output=True, text=True)
    resolved = os.path.realpath(cp.stdout.strip()) if cp.returncode == 0 else ""
    sb_real = os.path.realpath(probe_sb)
    shutil.rmtree(probe_sb, ignore_errors=True)
    if not resolved.startswith(sb_real + os.sep):
        log(f"BLOCKED: arcs_verify resolves to {resolved or 'nothing'}, not to the sandbox")
        return 2
    log("package resolution: arcs_verify imports from the sandbox copy, not an installed one")

    # 4. baseline: the UNMUTATED gate must be green, with the full test count
    base = run_gate(sandbox("baseline"), "baseline")
    shutil.rmtree(sandboxes / "baseline", ignore_errors=True)
    base_ok = (
        base.rc == 0
        and set(base.cases) == expected_tests
        and len(expected_tests) > 0
        and all(s == "pass" for s, _ in base.cases.values())
    )
    if not base_ok:
        log(f"BASELINE_RED: rc={base.rc} ran={base.ran}/{len(expected_tests)} "
            f"failed={sorted(base.failed)} {base.tail}")
        log("  no mutant was run: a kill measured against a red or empty baseline proves nothing")
        return 1
    n_base = base.ran
    log(f"baseline: unmutated gate GREEN, {n_base}/{len(expected_tests)} tests ran and passed")
    log()

    def judge_kill(control, run):
        """Return (verdict, detail).  A kill needs ALL of: the whole suite ran,
        the NAMED test failed, nothing else failed, and the failure text names
        the mutated token."""
        if run.rc not in (0, 1) or run.ran != n_base:
            return "HARNESS", f"ran {run.ran}/{n_base}, rc={run.rc}, {run.tail}"
        if control["wanted"] not in run.cases:
            return "HARNESS", f"{control['wanted']} did not run"
        state, text = run.cases[control["wanted"]]
        # Two gates can genuinely overlap: a dotless phantom inside the
        # receipt-set slice is a phantom by both the narrow and the
        # whole-registry definition. Such an overlap must be DECLARED on the
        # control; an undeclared one is still NOT-ISOLATED.
        others = sorted(run.failed - {control["wanted"]} - set(control.get("also", ())))
        if state == "pass":
            return "SURVIVED", f"{control['wanted']} stayed green"
        if control["token"] not in text:
            return "MISATTRIBUTED", f"{control['wanted']} failed but never names {control['token']!r}"
        if others:
            return "NOT-ISOLATED", "also failed: " + ", ".join(others)
        return "killed", f"{run.ran} ran, 1 failed, names {control['token']!r}"

    def evaluate(control):
        cid = control["id"]
        sb = sandbox(cid)
        try:
            changed = set(control["apply"](sb))
            actual = differing(inv_pristine, inventory(sb, SNAP_TREES, SNAP_FILES))
            if not actual or actual != changed:
                return "INVALID", f"mutation changed {sorted(actual)}, intended {sorted(changed)}"
            run = run_gate(sb, cid)
        except Exception as exc:  # a substitution that stops matching must be loud
            return "INVALID", f"{type(exc).__name__}: {exc}"
        finally:
            shutil.rmtree(sb, ignore_errors=True)
            if sb.exists():
                problem(f"sandbox {cid} was not removed")
        if control.get("green"):
            if run.rc == 0 and run.ran == n_base and not run.failed:
                return "paired-green", f"{run.ran}/{n_base} ran, all passed"
            return "PAIR-RED", f"rc={run.rc} ran={run.ran}/{n_base} failed={sorted(run.failed)}"
        return judge_kill(control, run)

    def report(control, verdict, detail):
        ok = verdict in ("killed", "paired-green")
        log(f"  [{verdict:<12}] {control['id']:<4} {control['label']:<44} {detail}")
        if control.get("green"):
            counts["pairs"] += 1
            counts["paired"] += ok
        else:
            counts["controls"] += 1
            counts["killed"] += ok
        if not ok:
            problem(f"{control['id']} {control['label']}: {verdict}")

    def go(control):
        if selected(control["id"]):
            verdict, detail = evaluate(control)
            report(control, verdict, detail)

    # --- apply functions ---------------------------------------------------
    def a_remove_code(code):
        def apply(sb):
            changed = []
            for rel in REGS:
                text = read(sb, rel)
                new = text.replace(f"`{code}`", "`REDACTED_BY_CONTROL`")
                if new != text:
                    write(sb, rel, new)
                    changed.append(rel)
            return changed
        return apply

    def a_remove_prefix(prefix):
        def apply(sb):
            changed = []
            for rel in REGS:
                text = read(sb, rel)
                new = text.replace(prefix, "REDACTED_PREFIX_BY_CONTROL")
                if new != text:
                    write(sb, rel, new)
                    changed.append(rel)
            return changed
        return apply

    def a_probe_module(sb):
        write(sb, PROBE,
              '"""Transient control fixture."""\n\n\n'
              "def _fail(report, code, detail):\n    return report\n\n\n"
              "def check(report):\n"
              '    return _fail(report, "control_probe.unregistered_code", "probe")\n')
        return [PROBE]

    def a_phantom(sb):
        text = read(sb, REGS[0])
        index = text.index("## `amnesiac-chain` subcommand")
        row = "| `zz_phantom_code` | Never emitted by receipt_set or deferred_sequence. |\n\n"
        write(sb, REGS[0], text[:index] + row + text[index:])
        return [REGS[0]]

    def a_append(rel, snippet):
        def apply(sb):
            write(sb, rel, read(sb, rel) + snippet)
            return [rel]
        return apply

    def a_signature(sb):
        text = read(sb, "arcs_verify/verifier.py")
        anchor = "SIGNATURE_FAILURE_CODES = {\n"
        index = text.index(anchor) + len(anchor)
        write(sb, "arcs_verify/verifier.py",
              text[:index] + '    "zz_signature_control_code",\n' + text[index:])
        return ["arcs_verify/verifier.py"]

    def a_probe_and_register(snippet, entry):
        def apply(sb):
            write(sb, SHAPE_HOST, read(sb, SHAPE_HOST) + snippet)
            write(sb, REGS[0], read(sb, REGS[0]) + "\n" + entry + "\n")
            return [SHAPE_HOST, REGS[0]]
        return apply

    # --- C1-C5: the five properties, one control each --------------------------
    first_code = next(
        iter(re.findall(r"`([a-z_]+\.[a-z_]+)`", (pristine / REGS[0]).read_text("utf-8"))),
        None)
    log("property controls (one mutant each; the named test must fail and name the mutation)")
    if first_code is None:
        problem("C1: no dotted code found in the registry to omit")
    else:
        go({"id": "C1", "label": "omitted static code", "wanted": T_STATIC,
            "token": f": {first_code}", "apply": a_remove_code(first_code)})
    go({"id": "C2", "label": "unregistered emitting module", "wanted": T_MODULE,
        "token": PROBE, "apply": a_probe_module})
    go({"id": "C3", "label": "phantom documented code", "wanted": T_PHANTOM,
        "token": "zz_phantom_code", "apply": a_phantom, "also": (T_PHANTOM_WIDE,)})

    # C6 and C7 reach the two cases the narrow gate cannot see by construction:
    # it reads only receipt-set..amnesiac-chain and matches bare identifiers.
    def a_phantom_outside(sb):
        write(sb, REGS[0], read(sb, REGS[0]) +
              "\n| `zz_phantom_outside_section` | Documented nowhere near receipt-set. |\n")
        return [REGS[0]]

    def a_phantom_dotted(sb):
        text = read(sb, REGS[0])
        index = text.index("## `amnesiac-chain` subcommand")
        row = "| `zz_family.invented_code` | Emitted by nothing in the verifier. |\n\n"
        write(sb, REGS[0], text[:index] + row + text[index:])
        return [REGS[0]]

    go({"id": "C6", "label": "phantom outside the narrow section", "wanted": T_PHANTOM_WIDE,
        "token": "zz_phantom_outside_section", "apply": a_phantom_outside})

    go({"id": "C7", "label": "dotted phantom code", "wanted": T_PHANTOM_WIDE,
        "token": "zz_family.invented_code", "apply": a_phantom_dotted})
    go({"id": "C4", "label": "undocumented dynamic family", "wanted": T_FAMILY,
        "token": "zz_dynamic_control.",
        "apply": a_append("arcs_verify/findings.py",
                          "\n\ndef _control_probe_dynamic_family(report, value):  # transient control fixture\n"
                          '    return _fail(report, f"zz_dynamic_control.{value}", "probe")\n')})
    go({"id": "C5", "label": "undocumented signature code", "wanted": T_SIGNATURE,
        "token": "zz_signature_control_code", "apply": a_signature})

    # --- M: every module in the gate's list, mutated separately -----------------
    log()
    log("per-module controls (a registry omission for a code each module emits)")
    harvest = {m: gate._extract(m) for m in gate.MODULES}
    emitters = {}
    for module, (static, _templates) in harvest.items():
        for code in static:
            emitters.setdefault(code, set()).add(module)
    blind = sum(1 for m in gate.MODULES
                if not harvest[m][0] and not any("." in p for p in harvest[m][1]))
    live = len(gate.MODULES) - blind
    for number, module in enumerate(gate.MODULES, 1):
        static, templates = harvest[module]
        families = sorted(p for p in templates if "." in p)
        cid = f"M{number:02d}"
        if not selected(cid):
            continue
        if static:
            code = min(static, key=lambda c: (len(emitters[c]), c))
            go({"id": cid, "label": module.removeprefix("arcs_verify/"), "wanted": T_STATIC,
                "token": f"{module}: {code}", "apply": a_remove_code(code)})
        elif families:
            prefix = families[0]
            go({"id": cid, "label": module.removeprefix("arcs_verify/") + " (family)", "wanted": T_FAMILY,
                "token": f"{module}: {prefix}<...>", "apply": a_remove_prefix(prefix)})
        else:
            reason = KNOWN_BLIND.get(module)
            if reason:
                log(f"  [blind       ] {cid:<4} {module.removeprefix('arcs_verify/'):<44} contributes nothing to the gate (known: {reason})")
            else:
                log(f"  [BLIND       ] {cid:<4} {module.removeprefix('arcs_verify/'):<44} contributes nothing to the gate and is NOT in KNOWN_BLIND")
                problem(f"{cid} {module}: new blind module")
    for module in KNOWN_BLIND if selected("M") or not ONLY else ():
        static, templates = harvest.get(module, (set(), set()))
        if module not in harvest or static or any("." in p for p in templates):
            log(f"  [STALE       ] {module} is listed in KNOWN_BLIND but is no longer blind")
            problem(f"{module}: stale KNOWN_BLIND entry")

    # --- S: every emission shape the sweep claims to recognise ------------------
    log()
    log("per-shape controls (probe appended to a gated module; each shape paired with its registered twin)")
    static_shapes = [
        ("helper_fail",    'def _probe(report):\n    return _fail(report, "{T}", "d")\n'),
        ("helper_finding", 'def _probe(report):\n    return _finding(report, "{T}", "d")\n'),
        ("append_code",    'def _probe(report):\n    report.failure_codes.append("{T}")\n'),
        ("value_error",    'def _probe():\n    raise ValueError("{T}")\n'),
        ("code_keyword",   'def _probe():\n    return Thing(code="{T}")\n'),
        ("return_list",    'def _probe():\n    return ["{T}"]\n'),
        ("return_bare",    'def _probe():\n    return "{T}"\n'),
    ]
    family_shapes = [
        ("append_f",       'def _probe(report, v):\n    report.failure_codes.append(f"{T}{{v}}")\n'),
        ("value_error_f",  'def _probe(v):\n    raise ValueError(f"{T}{{v}}")\n'),
        ("code_keyword_f", 'def _probe(v):\n    return Thing(code=f"{T}{{v}}")\n'),
        ("return_f",       'def _probe(v):\n    return f"{T}{{v}}"\n'),
        ("return_list_f",  'def _probe(v):\n    return [f"{T}{{v}}"]\n'),
    ]
    number = 0
    for kind, shapes, wanted in (("static", static_shapes, T_STATIC), ("family", family_shapes, T_FAMILY)):
        for name, template in shapes:
            number += 1
            if kind == "static":
                token = f"zz_shape_{name}_code"
                entry = f"| `{token}` | control |"
                shown = f"{SHAPE_HOST}: {token}"
            else:
                token = f"zz_shape_{name}."
                entry = f"| `{token}<suffix>` | control |"
                shown = f"{SHAPE_HOST}: {token}<...>"
            snippet = "\n\n" + template.replace("{T}", token).replace("{{v}}", "{v}")
            go({"id": f"S{number:02d}", "label": f"{name}", "wanted": wanted,
                "token": shown, "apply": a_append(SHAPE_HOST, snippet)})
            go({"id": f"S{number:02d}p", "label": f"{name} + registered twin", "green": True,
                "apply": a_probe_and_register(snippet, entry)})

    # --- closing proofs -----------------------------------------------------------
    log()
    log("post-conditions")
    real_after = inventory(ROOT, PROOF_TREES, PROOF_FILES)
    delta = differing(real_before, real_after)
    if delta:
        log(f"  !! REAL TREE CHANGED: {sorted(delta)}")
        problem("real tree changed during the run")
    else:
        log(f"  real tree byte-identical before and after: {len(real_after)} files in {', '.join(PROOF_TREES)}")
    if differing(inv_pristine, inventory(pristine, SNAP_TREES, SNAP_FILES)):
        log("  !! the pristine snapshot itself was altered")
        problem("pristine snapshot altered")
    else:
        log("  pristine snapshot never altered")
    leftovers = sorted(p.name for p in sandboxes.iterdir())
    if leftovers:
        log(f"  !! sandboxes left behind: {leftovers}")
        problem("sandboxes left behind")
    else:
        log("  every mutant sandbox removed")

    log()
    log(f"domain: {sum(len(s) for s, _ in harvest.values())} static codes and "
        f"{sum(len(t) for _, t in harvest.values())} dynamic prefixes harvested across "
        f"{live} live of {len(gate.MODULES)} gated modules; {blind} contribute nothing")
    log(f"controls: {counts['killed']}/{counts['controls']} killed by their named test; "
        f"{counts['paired']}/{counts['pairs']} registered twins green")
    if problems:
        log("problems:")
        for p in problems:
            log(f"  - {p}")
        return 1
    return 3 if ONLY else 0


if __name__ == "__main__":
    try:
        status = main()
    except SystemExit:
        raise
    except BaseException:
        traceback.print_exc()
        log("ENGINE_ERROR")
        status = 1
    sys.exit(status)
PYEOF

"$PY" -I "$WORK/engine.py" "$ROOT" "$WORK" "$PY" "$@" &
ENGINE_PID=$!
wait "$ENGINE_PID"
status=$?
ENGINE_PID=''

cleanup
if exists_any "$WORKPATH"; then
  printf '  !! temp tree left behind: %s\n' "$WORKPATH"
  case $status in 2) ;; *) status=1 ;; esac
else
  printf '  temp tree removed\n'
fi

case $status in
  0) printf '\nREGISTRY_CONTROLS=ALL_FIRE\n' ;;
  2) printf '\nREGISTRY_CONTROLS=BLOCKED\n' ;;
  3) printf '\nREGISTRY_CONTROLS=PARTIAL (subset run; not a pass)\n' ;;
  *) printf '\nREGISTRY_CONTROLS=PROBLEM\n'; status=1 ;;
esac
exit $status
