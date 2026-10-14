"""Keep security and quality scanning active on both supported languages."""

from pathlib import Path

import pytest
import yaml


@pytest.mark.parametrize("language", ["actions", "python"])
def test_codeql_runs_security_and_quality_for_each_language(language: str) -> None:
    workflow_path = Path(__file__).resolve().parents[1] / ".github/workflows/codeql.yml"
    # BaseLoader retains the GitHub Actions ``on`` key instead of YAML 1.1's bool.
    workflow = yaml.load(
        workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    assert {"pull_request", "merge_group", "push", "schedule"} <= workflow["on"].keys()
    job = workflow["jobs"]["analyze"]
    assert language in job["strategy"]["matrix"]["language"]
    assert "if" not in job
    assert job.get("continue-on-error", "false") == "false"
    init_steps = [
        step
        for step in job["steps"]
        if step.get("uses", "").startswith("github/codeql-action/init@")
    ]
    assert len(init_steps) == 1
    init = init_steps[0]
    assert init["with"]["languages"] == "${{ matrix.language }}"
    assert init["with"].get("queries") == "security-and-quality"
    assert "if" not in init
    assert init.get("continue-on-error", "false") == "false"
    analyze_steps = [
        step
        for step in job["steps"]
        if step.get("uses", "").startswith("github/codeql-action/analyze@")
    ]
    assert len(analyze_steps) == 1
    assert "if" not in analyze_steps[0]
    assert analyze_steps[0].get("continue-on-error", "false") == "false"
