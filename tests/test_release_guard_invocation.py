from pathlib import Path


def test_public_release_workflow_requires_real_brand_denylist() -> None:
    """Public/demo release CI must not accept the acknowledged-empty waiver.

    Population of tools/brand_denylist.txt remains a separate naming task, but
    every release-facing invocation must opt into the fail-closed real-token
    mode so an empty/waived denylist cannot produce a false green.
    """

    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / "test.yml"
    ).read_text(encoding="utf-8")

    required = "python3 tools/check_public_release.py --require-denylist ."
    bare = "python3 tools/check_public_release.py ."

    assert required in workflow
    assert bare not in workflow
