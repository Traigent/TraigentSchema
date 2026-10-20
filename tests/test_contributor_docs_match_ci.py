"""Contributor-facing docs must name real CI jobs and runnable commands.

On a clean tree the README's Development block told contributors to run
`ruff check .` and `mypy traigent_schema`, which exit 1 with errors CI does not
gate, and `docs/LOCAL_CI_GATE.md` attributed the lint and type steps to the
`test` job rather than `lint-type` (#571). Nothing executed either document, so
nothing caught the drift. These checks pin both to the workflows and the
Makefile.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_README = _REPO_ROOT / "README.md"
_LOCAL_GATE_DOC = _REPO_ROOT / "docs" / "LOCAL_CI_GATE.md"
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_MAKEFILE = _REPO_ROOT / "Makefile"

# A "What it runs" row: | `<command>` | `CI / <job>` -> *<step name>* (`ci.yml`) | ... |
_GATE_ROW = re.compile(
    r"^\|\s*`(?P<command>[^`]+)`\s*\|\s*`CI / (?P<job>[A-Za-z0-9_-]+)`\s*"
    r"\u2192\s*\*(?P<step>[^*]+)\*\s*\(`ci\.yml`\)\s*\|",
    re.MULTILINE,
)
# "make local-gate" -> "local-gate"
_MAKE_INVOCATION = re.compile(r"^make\s+([A-Za-z0-9_-]+)\s*(?:#.*)?$")
# "lint: ## ruff check ..." -> "lint"
_MAKE_TARGET = re.compile(r"^([A-Za-z0-9_-]+):")


def _ci_jobs() -> dict[str, list[dict]]:
    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    return {name: job.get("steps") or [] for name, job in workflow["jobs"].items()}


def _make_targets() -> set[str]:
    return {
        match.group(1)
        for line in _MAKEFILE.read_text(encoding="utf-8").splitlines()
        if (match := _MAKE_TARGET.match(line)) and match.group(1) != ".PHONY"
    }


def _development_block() -> list[str]:
    """The commands inside the README's `## Development` bash fence."""
    lines = _README.read_text(encoding="utf-8").splitlines()
    start = lines.index("## Development")
    fence = lines.index("```bash", start)
    end = lines.index("```", fence + 1)
    block = (line.strip() for line in lines[fence + 1 : end])
    return [line for line in block if line and not line.startswith("#")]


def test_local_ci_gate_doc_attributes_each_step_to_the_job_that_runs_it() -> None:
    """A reader hunting a red check must land in the job that actually ran it."""
    jobs = _ci_jobs()
    rows = _GATE_ROW.findall(_LOCAL_GATE_DOC.read_text(encoding="utf-8"))
    assert rows, "the local-gate doc no longer attributes any step to a CI job"

    for command, claimed_job, claimed_step in rows:
        running_jobs = {
            name: step.get("name")
            for name, steps in jobs.items()
            for step in steps
            if command in (step.get("run") or "")
        }
        assert running_jobs, f"no ci.yml step runs {command!r}, but the doc says {claimed_job} does"
        assert claimed_job in running_jobs, (
            f"docs/LOCAL_CI_GATE.md attributes {command!r} to job {claimed_job!r}, "
            f"but ci.yml runs it in {sorted(running_jobs)}"
        )
        assert running_jobs[claimed_job] == claimed_step.strip(), (
            f"docs/LOCAL_CI_GATE.md calls the {command!r} step {claimed_step.strip()!r}; "
            f"ci.yml calls it {running_jobs[claimed_job]!r}"
        )


def test_local_ci_gate_doc_does_not_claim_a_sonarqube_pr_check() -> None:
    # `sonarqube-local.yml` runs only on push-to-main and workflow_dispatch, so
    # no `SonarQube Quality Gate` check is ever reported on a pull request;
    # `SonarCloud Code Analysis` is the required static-analysis check.
    doc = _LOCAL_GATE_DOC.read_text(encoding="utf-8")
    sonar_workflow = _CI_WORKFLOW.parent / "sonarqube-local.yml"
    workflow = yaml.safe_load(sonar_workflow.read_text(encoding="utf-8"))
    # `on:` parses to the boolean True under the YAML 1.1 rules PyYAML follows.
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"push", "workflow_dispatch"}, (
        "sonarqube-local.yml gained a pull_request trigger — re-check what the doc should say"
    )
    assert "`SonarQube Quality Gate` required check" not in doc


def test_readme_development_block_only_runs_mirrored_commands() -> None:
    targets = _make_targets()
    commands = _development_block()

    assert commands, "the README Development block has no commands"
    for command in commands:
        if command.startswith("pip install"):
            continue
        match = _MAKE_INVOCATION.match(command)
        assert match is not None, (
            f"README Development block runs {command!r}, which is not a `make` target. "
            "Raw tool invocations drift from what CI runs — add a Makefile target instead."
        )
        assert match.group(1) in targets, (
            f"README Development block runs `make {match.group(1)}`, "
            f"which the Makefile does not define. Targets: {sorted(targets)}"
        )
