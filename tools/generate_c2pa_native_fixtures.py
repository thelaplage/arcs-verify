#!/usr/bin/env python3
"""Regenerate the frozen native C2PA reports used by the hermetic test suite.

The committed frozen reports under
``tests/fixtures/c2pa-native/frozen-native-reports/`` are recorded outputs of
the pinned native validator, produced by running this script. The test suite
replays them so it can execute with no network, no credentials, and no Rust
toolchain present.

A replayed frozen report is NOT a fresh independent recomputation and is never
presented as one: every canonical finding built from one carries
``evidence_class: replayed_frozen_native_report``. Tests that require a genuine
live invocation are gated on the pinned validator actually being present.

Usage::

    cargo install c2patool --version 0.27.15 --locked
    python tools/generate_c2pa_native_fixtures.py --c2patool "$(command -v c2patool)"

Regenerating with the same pinned validator over the same specimen bytes
reproduces these reports; a digest that no longer matches is drift, not an
update. Note that time-dependent axes can legitimately drift as wall-clock
passes — see FROZEN_MANIFEST.json ``time_dependent_specimens``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "c2pa-native"
SPECIMENS = FIXTURES / "specimens"
TRUST = FIXTURES / "trust"
FROZEN = FIXTURES / "frozen-native-reports"

sys.path.insert(0, str(REPO_ROOT))
from arcs_verify.c2pa_native import (  # noqa: E402
    HERMETIC_SETTINGS_TOML,
    PINNED_VALIDATOR,
    _classify_invocation,
    native_validator_version,
)

# Each case names the specimen, the manifest acquisition mode, and the trust
# posture the frozen run was produced under.
CASES: list[dict[str, object]] = [
    {"name": "CA-default-trust", "asset": "CA.jpg", "mode": "embedded", "trust": "default"},
    {"name": "CA-allowed-list-trust", "asset": "CA.jpg", "mode": "embedded", "trust": "allowed_list"},
    {"name": "C-default-trust", "asset": "C.jpg", "mode": "embedded", "trust": "default"},
    {"name": "CACA-default-trust", "asset": "CACA.jpg", "mode": "embedded", "trust": "default"},
    {"name": "XCA-asset-binding-mismatch", "asset": "XCA.jpg", "mode": "embedded", "trust": "default"},
    {"name": "E-sig-CA-claim-signature-mismatch", "asset": "E-sig-CA.jpg", "mode": "embedded", "trust": "default"},
    {
        "name": "cloud-sealed-replay",
        "asset": "cloud.jpg",
        "mode": "remote_reference",
        "trust": "default",
        "external_manifest": "cloud_remote_manifest.c2pa",
    },
    {
        "name": "cloud-manifest-not-captured",
        "asset": "cloud.jpg",
        "mode": "remote_reference",
        "trust": "default",
        "expect_unavailable": True,
    },
]


# Specimens whose media bytes are NOT vendored into this repository, because
# their licensing was not established. Only the native report over them is
# committed, together with the asset digest and an upstream commit pin, so the
# run can be reproduced by re-acquiring the asset by digest. Supply the
# directory holding them with --external-specimen-dir.
EXTERNAL_CASES: list[dict[str, object]] = [
    {
        "name": "expired-signing-certificate",
        "asset": "ChatGPT_Image.png",
        "mode": "embedded",
        "trust": "default",
        "asset_not_vendored": True,
        "asset_source": "contentauth/example-assets",
        "asset_source_pin": "c37f93e115289ac1ef00f899a860e6e08ab9886f",
        "note": (
            "The signing certificate's validity window closed on 2026-04-15. The identical "
            "bytes validated differently before that date. This specimen is the empirical "
            "basis for treating signer_validity as time_dependent and for refusing to derive "
            "an integrity accusation from a divergence on it."
        ),
    },
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def settings_for(trust: str, workdir: Path) -> Path:
    path = workdir / f"settings-{trust}.toml"
    text = HERMETIC_SETTINGS_TOML
    if trust == "allowed_list":
        pem = (TRUST / "ca-signer-ee.pem").read_text(encoding="utf-8").strip()
        text = text + f'[trust]\nallowed_list = """{pem}"""\n'
    path.write_text(text, encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c2patool", required=True)
    parser.add_argument(
        "--external-specimen-dir",
        type=Path,
        default=None,
        help="directory holding the non-vendored specimens listed in EXTERNAL_CASES",
    )
    args = parser.parse_args(argv)

    version = native_validator_version(args.c2patool)
    if version != PINNED_VALIDATOR["version"]:
        print(
            f"refusing to generate: validator reports version {version!r}, contract pins "
            f"{PINNED_VALIDATOR['version']!r}. A validator version change is a verdict input.",
            file=sys.stderr,
        )
        return 2

    FROZEN.mkdir(parents=True, exist_ok=True)
    import tempfile

    manifest: dict[str, object] = {
        "generator": "tools/generate_c2pa_native_fixtures.py",
        "validator": dict(PINNED_VALIDATOR),
        "hermetic_settings_digest": "sha256:"
        + hashlib.sha256(HERMETIC_SETTINGS_TOML.encode("utf-8")).hexdigest(),
        "cases": {},
    }

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        cases = list(CASES)
        if args.external_specimen_dir is not None:
            cases += EXTERNAL_CASES
        else:
            print(
                "note: --external-specimen-dir not supplied; leaving the non-vendored "
                "specimen reports untouched",
                file=sys.stderr,
            )
        for case in cases:
            name = str(case["name"])
            asset = (
                Path(args.external_specimen_dir) / str(case["asset"])
                if case.get("asset_not_vendored")
                else SPECIMENS / str(case["asset"])
            )
            settings = settings_for(str(case["trust"]), workdir)
            argv_list = [args.c2patool, "--settings", str(settings)]
            external = case.get("external_manifest")
            if external:
                argv_list += ["--external-manifest", str(SPECIMENS / str(external))]
            argv_list.append(str(asset))

            proc = subprocess.run(argv_list, capture_output=True, text=True, check=False)
            outcome = _classify_invocation(proc.stdout, proc.stderr, proc.returncode)

            record = {
                "case": name,
                "asset": str(case["asset"]),
                "asset_digest": "sha256:" + sha256_file(asset),
                "manifest_acquisition_mode": case["mode"],
                "trust_posture": case["trust"],
                "external_manifest": external,
                "external_manifest_digest": (
                    "sha256:" + sha256_file(SPECIMENS / str(external)) if external else None
                ),
                "settings_digest": "sha256:" + sha256_file(settings),
                "process_exit_status": proc.returncode,
                "evaluation_status": outcome.evaluation_status,
                "evaluation_status_detail": outcome.detail,
                "native_report": outcome.report,
                "native_stderr_excerpt": (proc.stderr or "").strip()[:400] or None,
                "asset_not_vendored": bool(case.get("asset_not_vendored")),
                "asset_source": case.get("asset_source"),
                "asset_source_pin": case.get("asset_source_pin"),
                "note": case.get("note"),
            }
            out = FROZEN / f"{name}.json"
            out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            manifest["cases"][name] = {  # type: ignore[index]
                "file": f"{name}.json",
                "sha256": sha256_file(out),
                "process_exit_status": proc.returncode,
                "evaluation_status": outcome.evaluation_status,
                "native_validation_state": (outcome.report or {}).get("validation_state"),
            }
            print(
                f"{name}: exit={proc.returncode} status={outcome.evaluation_status} "
                f"state={(outcome.report or {}).get('validation_state')}"
            )

    (FROZEN / "FROZEN_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
