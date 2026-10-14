"""Characterization tests for ``verify_breaking_schema_check_skip`` and ``evaluate``.

Pins, for scripts/check_required_gate.py, the exact ``(ok, message)`` returned for every
shape of the ``changes`` job outputs, and the full ``GateResult`` (problems and
justifications, in order) for every combination of dependency results ``evaluate``
distinguishes. The expected values in tests/data/check_required_gate_characterization.json
were recorded from the implementation before both functions were split into smaller
helpers. The cases reach every branch of both functions.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from tests._characterization import REPO_ROOT, Case, load_golden, load_script, observe

GOLDEN_FILE = "check_required_gate_characterization.json"
TARGET = load_script(
    "check_required_gate_characterization_target",
    REPO_ROOT / "scripts" / "check_required_gate.py",
)


def _changes(result: Any = "success", **outputs: Any) -> dict[str, Any]:
    return {"result": result, "outputs": outputs}


def _verify(needs: Any) -> Case:
    return lambda m: m.verify_breaking_schema_check_skip(needs)


VERIFY_CASES: dict[str, Case] = {
    "changes_absent": _verify({}),
    "changes_not_dict": _verify({"changes": "success"}),
    "changes_failed": _verify({"changes": _changes("failure")}),
    "changes_result_missing": _verify({"changes": {"outputs": {}}}),
    "outputs_missing": _verify({"changes": {"result": "success"}}),
    "outputs_not_dict": _verify({"changes": {"result": "success", "outputs": ["x"]}}),
    "event_not_applicable": _verify({"changes": _changes(event_applicable="false")}),
    "event_not_applicable_ignores_rest": _verify(
        {"changes": _changes(event_applicable="false", schema_relevant="true")}
    ),
    "event_applicable_bool": _verify({"changes": _changes(event_applicable=True)}),
    "event_applicable_other": _verify({"changes": _changes(event_applicable="yes")}),
    "schema_relevant_missing": _verify({"changes": _changes(event_applicable="true")}),
    "schema_relevant_true": _verify(
        {"changes": _changes(event_applicable="true", schema_relevant="true")}
    ),
    "schema_relevant_empty": _verify(
        {"changes": _changes(event_applicable="true", schema_relevant="")}
    ),
    "file_count_missing": _verify(
        {"changes": _changes(event_applicable="true", schema_relevant="false")}
    ),
}

for _label, _count in {
    "int": 3,
    "str": "3",
    "str_padded": " 4 ",
    "float_str": "1.5",
    "word": "many",
    "list": [1],
    "negative": "-2",
    "zero": "0",
    "zero_int": 0,
    "bool": True,
}.items():
    for _ancestry_label, _ancestry in {
        "absent": None,
        "true": "true",
        "false": "false",
        "other": "yes",
    }.items():
        _outputs: dict[str, Any] = {
            "event_applicable": "true",
            "schema_relevant": "false",
            "changed_file_count": _count,
        }
        if _ancestry is not None:
            _outputs["ancestry_only"] = _ancestry
        VERIFY_CASES[f"count_{_label}_ancestry_{_ancestry_label}"] = _verify(
            {"changes": _changes(**_outputs)}
        )


def _evaluate(needs: Any) -> Case:
    return lambda m: m.evaluate(needs)


SAFE_SKIP = _changes(event_applicable="false")
UNSAFE_SKIP = _changes(event_applicable="true", schema_relevant="true")


def _needs(**results: Any) -> dict[str, Any]:
    needs: dict[str, Any] = {}
    for job, value in results.items():
        job = job.replace("_", "-")
        needs[job] = value if isinstance(value, dict) else {"result": value}
    return needs


EVALUATE_CASES: dict[str, Case] = {
    "empty_needs": _evaluate({}),
    "all_success": _evaluate(
        _needs(
            changes="success",
            lint_type="success",
            test="success",
            package="success",
            breaking_schema_check="success",
        )
    ),
    "allowlisted_jobs_missing": _evaluate(
        _needs(changes="success", lint_type="success", breaking_schema_check="success")
    ),
    "breaking_job_missing": _evaluate(
        _needs(lint_type="success", test="success", package="success")
    ),
    "only_unrelated_job": _evaluate(_needs(other="failure")),
    "info_not_dict": _evaluate({"test": "success", "package": None, "breaking-schema-check": []}),
    "result_missing": _evaluate(
        {"test": {}, "package": {"result": ""}, "breaking-schema-check": {}}
    ),
}
for _combo in itertools.product(
    ["success", "skipped", "failure", "cancelled"],
    ["success", "skipped", "failure"],
    ["success", "skipped", "failure"],
    [SAFE_SKIP, UNSAFE_SKIP, _changes("failure")],
):
    _lint, _test, _breaking, _changes_entry = _combo
    _changes_label = {id(SAFE_SKIP): "safe", id(UNSAFE_SKIP): "unsafe"}.get(
        id(_changes_entry), "failed"
    )
    EVALUATE_CASES[f"lint_{_lint}_test_{_test}_breaking_{_breaking}_changes_{_changes_label}"] = (
        _evaluate(
            {
                "changes": _changes_entry,
                "lint-type": {"result": _lint},
                "test": {"result": _test},
                "package": {"result": "skipped"},
                "breaking-schema-check": {"result": _breaking},
            }
        )
    )

ALL_CASES: dict[str, Case] = {
    **{f"verify_skip/{k}": v for k, v in VERIFY_CASES.items()},
    **{f"evaluate/{k}": v for k, v in EVALUATE_CASES.items()},
}


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], TARGET) == _golden()[case_id]
