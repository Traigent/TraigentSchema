"""Static security invariants for release-critical GitHub workflows."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FULL_SHA_ACTION = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _workflow(name: str) -> dict:
    data = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_publish_is_bound_to_the_verified_exact_main_sha() -> None:
    workflow = _workflow("publish.yml")
    jobs = workflow["jobs"]
    gate = jobs["verify-release-ref"]
    publish = jobs["publish"]

    gate_script = gate["steps"][1]["run"]
    assert '"refs/heads/main"' in gate_script
    assert "refs/remotes/origin/main" in gate_script
    assert '"$CURRENT_MAIN_SHA" != "$DISPATCH_SHA"' in gate_script
    assert gate["outputs"]["verified_sha"] == "${{ steps.verify.outputs.verified_sha }}"

    checkout = publish["steps"][0]
    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["ref"] == "${{ needs.verify-release-ref.outputs.verified_sha }}"

    recheck = next(step for step in publish["steps"] if step["name"].startswith("Re-verify main"))
    assert '"$CURRENT_MAIN_SHA" != "$VERIFIED_SHA"' in recheck["run"]
    assert publish["permissions"] == {"id-token": "write", "contents": "read"}

    for job in jobs.values():
        for step in job.get("steps", []):
            if "uses" in step:
                assert FULL_SHA_ACTION.fullmatch(step["uses"]), step["uses"]


def test_codeql_posts_the_two_main_ruleset_contexts() -> None:
    workflow = _workflow("codeql.yml")
    analyze = workflow["jobs"]["analyze"]

    assert analyze["name"] == "Analyze (${{ matrix.language }})"
    assert analyze["strategy"]["matrix"]["language"] == ["actions", "python"]
    assert workflow["permissions"]["security-events"] == "write"

    checkout = analyze["steps"][0]
    assert checkout["with"]["persist-credentials"] is False
    assert any("github/codeql-action/init@" in step.get("uses", "") for step in analyze["steps"])
    assert any("github/codeql-action/analyze@" in step.get("uses", "") for step in analyze["steps"])
    for step in analyze["steps"]:
        if "uses" in step:
            assert FULL_SHA_ACTION.fullmatch(step["uses"]), step["uses"]
