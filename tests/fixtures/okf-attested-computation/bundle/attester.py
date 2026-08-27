# Stand-in OKF attester resource fixture.
#
# This file is never executed by arcs-verify. Bridge0 treats it as opaque
# bytes and only ever recomputes its sha256 digest for resource-binding
# checks. Its content is deliberately inert.
def attest(run_result):
    return {"verdict": "unknown"}
