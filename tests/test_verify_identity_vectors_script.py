"""The production identity-vector verifier must fail when it checks nothing (#709)."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "verify_identity_vectors_against_production.py"
)


def _load_script():
    spec = importlib.util.spec_from_file_location("verify_identity_vectors", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def script():
    return _load_script()


@pytest.fixture
def stub_traigent(monkeypatch):
    # The SDK import is the only thing check_sdk needs from the checkout.
    monkeypatch.setitem(sys.modules, "traigent", types.ModuleType("traigent"))


@pytest.fixture
def stub_traigent_with_optimize(monkeypatch):
    # Passes the entry-point guard, so an empty vector list reaches the
    # `checked == 0` guard that these tests exercise.
    stub = types.ModuleType("traigent")
    stub.optimize = lambda **_kwargs: (lambda fn: fn)
    monkeypatch.setitem(sys.modules, "traigent", stub)


def test_check_sdk_reports_a_problem_when_zero_python_vectors_are_checked(
    script, stub_traigent_with_optimize, monkeypatch
):
    monkeypatch.setattr(script, "_py_vectors", lambda: [])
    problems = script.check_sdk()
    assert problems, "checked 0 python vectors must be reported as a problem"


def test_main_exits_nonzero_when_zero_python_vectors_are_checked(
    script, stub_traigent_with_optimize, monkeypatch, tmp_path
):
    monkeypatch.setattr(script, "_py_vectors", lambda: [])
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "argv", ["verify", "--component", "sdk", "--checkout", str(tmp_path)])
    monkeypatch.chdir(tmp_path)
    assert script.main() != 0


UNSUPPORTED_VECTOR = {
    "id": "unsupported-vector",
    "input": {"sdk": "python", "function_name": "f", "objectives": ["accuracy"]},
    "expected": {"outcome": "unsupported"},
}

SUPPORTED_VECTOR = {
    "id": "supported-vector",
    "input": {"sdk": "python", "function_name": "probe_fn", "objectives": ["accuracy"]},
    "expected": {"registration_identity": "probe_fn"},
}


def _run_main(script, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "argv", ["verify", "--component", "sdk", "--checkout", str(tmp_path)])
    monkeypatch.chdir(tmp_path)
    return script.main()


def test_main_fails_when_stub_sdk_lacks_optimize_and_only_unsupported_vectors(
    script, stub_traigent, monkeypatch, tmp_path
):
    # A stub/old SDK with no `optimize` makes the unsupported vector raise
    # AttributeError for the wrong reason; that must not count as verified.
    monkeypatch.setattr(script, "_py_vectors", lambda: [UNSUPPORTED_VECTOR])
    assert _run_main(script, tmp_path, monkeypatch) != 0


def test_main_exits_zero_when_supported_vector_checks_out(
    script, monkeypatch, tmp_path
):
    # Control: a working optimize decorator plus a supported vector passes.
    stub = types.ModuleType("traigent")

    def optimize(**_kwargs):
        def deco(fn):
            fn.experiment_name = fn.__name__
            return fn

        return deco

    stub.optimize = optimize
    monkeypatch.setitem(sys.modules, "traigent", stub)
    monkeypatch.setattr(script, "_py_vectors", lambda: [UNSUPPORTED_VECTOR, SUPPORTED_VECTOR])
    assert _run_main(script, tmp_path, monkeypatch) == 0
