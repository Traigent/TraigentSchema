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


def _checkout_steps(job: dict) -> list[dict]:
    return [
        step
        for step in job.get("steps", [])
        if str(step.get("uses", "")).split("@", 1)[0] == "actions/checkout"
    ]


def test_read_only_workflow_checkouts_do_not_persist_credentials() -> None:
    read_only_jobs = {
        "auth-taxonomy-parity.yml": ("auth-taxonomy-parity",),
        "parity-check.yml": ("parity-check",),
        "schema-orphan-check.yml": ("schema-orphan-check",),
        "validation-spine-pr.yml": ("spine-pr-scan",),
        "ci.yml": ("changes", "lint-type", "test", "package", "ci-required"),
    }

    for workflow_name, job_names in read_only_jobs.items():
        workflow = _workflow(workflow_name)
        for job_name in job_names:
            checkouts = _checkout_steps(workflow["jobs"][job_name])
            assert checkouts, f"{workflow_name}:{job_name} must check out source"
            for checkout in checkouts:
                assert checkout["with"]["persist-credentials"] is False, (
                    f"{workflow_name}:{job_name} must not leave checkout credentials in git config"
                )


def test_breaking_schema_checkout_retains_credentials_for_its_later_fetch() -> None:
    workflow = _workflow("ci.yml")
    job = workflow["jobs"]["breaking-schema-check"]
    checkout = _checkout_steps(job)

    assert len(checkout) == 1
    assert "persist-credentials" not in checkout[0].get("with", {})
    ref_resolution = next(
        step["run"]
        for step in job["steps"]
        if step.get("name") == "Resolve base/head refs for this event"
    )
    assert "git fetch origin" in ref_resolution
