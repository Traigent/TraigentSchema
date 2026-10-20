"""Contributor-facing docs must name real CI jobs and runnable commands.

On a clean tree the README's Development block told contributors to run
`ruff check .` and `mypy traigent_schema`, which exit 1 with errors CI does not
gate, and `docs/LOCAL_CI_GATE.md` attributed the lint and type steps to the
`test` job rather than `lint-type` (#571). Nothing executed either document, so
nothing caught the drift.

The README's claim is a three-link chain - README names a `make` target, the
target's recipe is what CI runs, and the local-gate doc attributes each command
to the job that runs it. All three links are checked here; checking only the
ends would leave the middle free to drift, which is #571's own defect class.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_README = _REPO_ROOT / "README.md"
_LOCAL_GATE_DOC = _REPO_ROOT / "docs" / "LOCAL_CI_GATE.md"
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_CI_WORKFLOW = _WORKFLOWS / "ci.yml"
_MAKEFILE = _REPO_ROOT / "Makefile"

_DEVELOPMENT_HEADING = "## Development"

# A "What it runs" row: | `<command>` | `CI / <job>` -> *<step name>* (`ci.yml`) | ... |
_GATE_ROW = re.compile(
    r"^\|\s*`(?P<command>[^`]+)`\s*\|\s*`CI / (?P<job>[A-Za-z0-9_-]+)`\s*"
    r"→\s*\*(?P<step>[^*]+)\*\s*\(`ci\.yml`\)\s*\|",
    re.MULTILINE,
)
# Rows attributed to ci.yml are the ones the regex above must keep matching.
# Reformatting one row used to drop it silently while the others kept the test
# green, so the count is pinned: raise it when a row is added, never lower it
# to make a reformatted row go away.
_EXPECTED_GATE_ROWS = 3

# "make local-gate" / "make install" anywhere on a line, including in a comment
# such as `pip install -e ".[dev]"   # or: make install`.
_MAKE_INVOCATION = re.compile(r"\bmake\s+([A-Za-z0-9_-]+)")
# A command line in the README block that is not a `make` call.
_BARE_COMMAND = re.compile(r"^(?P<tool>[A-Za-z0-9_.-]+)\b")
# "lint: ## ruff check ..." -> "lint"
_MAKE_TARGET = re.compile(r"^([A-Za-z0-9_-]+):")

# `make <target>` -> the ci.yml step whose `run` must contain the same command.
# This is the middle link: the README promises "each one runs exactly the form
# CI runs", and only this mapping can keep that promise true.
_TARGETS_MIRRORING_CI = {
    "lint": "ruff check traigent_schema/",
    "typecheck": "mypy traigent_schema/ --ignore-missing-imports",
}

# Commands in the README block that are legitimately not `make` calls.
_ALLOWED_BARE_TOOLS = {"pip"}


def _ci_jobs() -> dict[str, list[dict]]:
    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    return {name: job.get("steps") or [] for name, job in workflow["jobs"].items()}


def _workflow_triggers(name: str) -> set[str]:
    """The `on:` keys of a workflow.

    PyYAML follows YAML 1.1, where the bare key `on` is the boolean `True`, so
    the mapping has to be looked up under both spellings.
    """
    workflow = yaml.safe_load((_WORKFLOWS / name).read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict), f"{name}: could not read the `on:` mapping"
    return set(triggers)


def _make_recipes() -> dict[str, list[str]]:
    """target -> its recipe lines, with the leading tab stripped."""
    recipes: dict[str, list[str]] = {}
    current: str | None = None
    for line in _MAKEFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("\t"):
            if current is not None:
                recipes[current].append(line.lstrip("\t").lstrip("@").strip())
            continue
        match = _MAKE_TARGET.match(line)
        current = match.group(1) if match and match.group(1) != ".PHONY" else None
        if current is not None:
            recipes.setdefault(current, [])
    return recipes


def _development_block() -> list[str]:
    """The commands inside the README's `## Development` bash fence."""
    lines = _README.read_text(encoding="utf-8").splitlines()
    if _DEVELOPMENT_HEADING not in lines:
        pytest.fail(
            f"README.md has no {_DEVELOPMENT_HEADING!r} heading; "
            "if it was renamed, update _DEVELOPMENT_HEADING here too"
        )
    start = lines.index(_DEVELOPMENT_HEADING)
    fence = lines.index("```bash", start)
    end = lines.index("```", fence + 1)
    block = (line.strip() for line in lines[fence + 1 : end])
    return [line for line in block if line and not line.startswith("#")]


def test_local_ci_gate_doc_attributes_each_step_to_the_job_that_runs_it() -> None:
    """A reader hunting a red check must land in the job that actually ran it."""
    jobs = _ci_jobs()
    rows = _GATE_ROW.findall(_LOCAL_GATE_DOC.read_text(encoding="utf-8"))
    assert len(rows) == _EXPECTED_GATE_ROWS, (
        f"matched {len(rows)} ci.yml rows in the local-gate doc's table, expected "
        f"{_EXPECTED_GATE_ROWS}. A reformatted row stops being checked silently, so "
        "either restore its format or update _EXPECTED_GATE_ROWS deliberately."
    )

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


def test_make_targets_run_exactly_what_ci_runs() -> None:
    """The middle link of the README's claim.

    Without this, `make lint` could be narrowed or widened and both the README
    ("each one runs exactly the form CI runs") and the local-gate doc would
    still pass while the promise was false.
    """
    recipes = _make_recipes()
    jobs = _ci_jobs()
    ci_commands = [
        (name, step.get("run") or "") for name, steps in jobs.items() for step in steps
    ]

    for target, command in _TARGETS_MIRRORING_CI.items():
        assert target in recipes, f"the Makefile no longer defines `{target}`"
        assert recipes[target] == [command], (
            f"`make {target}` runs {recipes[target]}, but the README promises it runs exactly "
            f"what CI runs, which is {command!r}. Change both or neither."
        )
        assert any(command in run for _, run in ci_commands), (
            f"no ci.yml step runs {command!r} any more, so `make {target}` no longer mirrors CI"
        )


def test_local_ci_gate_doc_does_not_claim_a_sonarqube_pr_check() -> None:
    """`sonarqube-local.yml` reports no check on a pull request.

    It runs only on push-to-main and workflow_dispatch, so a doc that tells a
    contributor to expect a `SonarQube Quality Gate` check on their PR sends
    them looking for something that never appears. `SonarCloud Code Analysis`
    is the required static-analysis check, and only on `main`.
    """
    assert _workflow_triggers("sonarqube-local.yml") == {"push", "workflow_dispatch"}, (
        "sonarqube-local.yml gained or lost a trigger - re-check what the doc should say"
    )

    doc = _LOCAL_GATE_DOC.read_text(encoding="utf-8")

    # Positive half: the denial must be present, so deleting it is also a
    # failure. A purely negative string assertion can be walked around by
    # rewording; this cannot be satisfied by saying nothing.
    assert "no `SonarQube Quality Gate` check on a pull request" in doc, (
        "docs/LOCAL_CI_GATE.md no longer states that there is no "
        "`SonarQube Quality Gate` check on a pull request"
    )
    assert "SonarCloud Code Analysis" in doc, (
        "docs/LOCAL_CI_GATE.md no longer names the check that IS required"
    )

    # Negative half: match the claim, not one spelling of it. Any line putting
    # "SonarQube Quality Gate" next to "check" asserts such a check exists,
    # unless the line is itself a denial.
    negated = re.compile(r"\b(no|not|never|cannot|without)\b", re.IGNORECASE)
    offending = [
        line
        for line in doc.splitlines()
        if "SonarQube Quality Gate" in line
        and re.search(r"\bcheck\b", line)
        and not negated.search(line)
    ]
    assert not offending, (
        "docs/LOCAL_CI_GATE.md describes a `SonarQube Quality Gate` check as if it exists; "
        "no workflow produces one. Offending line(s):\n  " + "\n  ".join(offending)
    )


def test_readme_development_block_only_runs_mirrored_commands() -> None:
    recipes = _make_recipes()
    commands = _development_block()

    assert commands, "the README Development block has no commands"
    for command in commands:
        # Every `make <target>` on the line must exist, including one named in
        # a trailing comment (`pip install -e ".[dev]"   # or: make install`).
        invoked = _MAKE_INVOCATION.findall(command)
        for target in invoked:
            assert target in recipes, (
                f"README Development block names `make {target}`, "
                f"which the Makefile does not define. Targets: {sorted(recipes)}"
            )
        if invoked:
            continue

        tool = _BARE_COMMAND.match(command)
        assert tool is not None and tool.group("tool") in _ALLOWED_BARE_TOOLS, (
            f"README Development block runs {command!r}, which is not a `make` target. "
            "Raw tool invocations drift from what CI runs - add a Makefile target instead."
        )
