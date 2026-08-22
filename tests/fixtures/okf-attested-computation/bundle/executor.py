# Stand-in OKF executor resource fixture.
#
# This file is never executed by arcs-verify. Bridge0 treats it as opaque
# bytes and only ever recomputes its sha256 digest for resource-binding
# checks. Its content is deliberately inert.
def run():
    return {"exit_code": 0, "stdout_digest": "sha256:not-a-real-digest"}
