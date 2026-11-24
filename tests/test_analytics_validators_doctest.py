"""Doctest gate for traigent_schema.analytics_validators (issue #713).

The ``>>>`` examples in the docstrings are executable documentation. This
test runs them so they cannot rot: a NameError or a wrong documented output
fails the suite.
"""

from __future__ import annotations

import doctest

import traigent_schema.analytics_validators as analytics_validators

# validate_example_metrics, validate_example_id_format, validate_job_id_format
# and validate_algorithm_version each carry one or more examples.
MIN_EXAMPLES = 7


def test_analytics_validators_docstring_examples_pass() -> None:
    result = doctest.testmod(analytics_validators, verbose=False, report=True)
    assert result.attempted >= MIN_EXAMPLES, (
        f"expected at least {MIN_EXAMPLES} doctest examples, ran {result.attempted}"
    )
    assert result.failed == 0
