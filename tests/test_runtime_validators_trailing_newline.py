"""Python runtime validators must refuse a trailing newline (``$`` would accept ``"\\n"``)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from traigent_schema import fleet_observe_digest as fod
from traigent_schema.analytics_validators import AnalyticsValidator

_V = AnalyticsValidator()


def _accepts(fn: Callable[[str], Any]) -> Callable[[str], bool]:
    def run(value: str) -> bool:
        try:
            return bool(fn(value))
        except ValueError:
            return False

    return run


_CASES = {
    "example_id": (_accepts(_V.validate_example_id_format), "ex_abc12345_0"),
    "job_id": (_accepts(_V.validate_job_id_format), "score_job-1_17"),
    "algorithm_version": (_accepts(_V.validate_algorithm_version), "1.2.3"),
    "observed_at": (_accepts(fod.canonical_observed_at), "2026-01-02T03:04:05Z"),
    "digest": (_accepts(lambda v: fod._digest(v, "d")), "sha256:" + "a" * 64),
    "scp_remote": (_accepts(lambda v: fod._split_remote(v)[0] is None), "git@host.example:org/repo"),
    "host_port": (_accepts(lambda v: fod._host_and_port(v, None)), "host.example:8080"),
}


@pytest.mark.parametrize("name", sorted(_CASES))
def test_valid_value_is_accepted(name: str) -> None:
    check, value = _CASES[name]
    assert check(value) is True


@pytest.mark.parametrize("suffix", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("name", sorted(_CASES))
def test_trailing_newline_is_refused(name: str, suffix: str) -> None:
    check, value = _CASES[name]
    assert check(value + suffix) is False
