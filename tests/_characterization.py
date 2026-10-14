"""Shared harness for the recorded-output characterization tests.

A characterization case is a callable taking the module under test and returning whatever
the code under test returns. ``observe`` runs it and reduces everything a caller can see --
the return value, a raised exception (type and message), anything printed to stdout or
stderr, and any warning emitted -- to plain JSON data, so it can be compared with output
recorded from an earlier implementation in a ``tests/data/*_characterization.json`` file.

The recorded files are expected output, not a snapshot to refresh: a mismatch is a
behaviour change and must be justified on its own rather than regenerated away.
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import json
import sys
import warnings
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "tests" / "data"

Case = Callable[[ModuleType], Any]


def load_script(name: str, path: Path) -> ModuleType:
    """Import a file under ``scripts/`` as a module without touching ``sys.path``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def to_plain(value: Any) -> Any:
    """Reduce a return value to JSON data, keeping the type name of structured values."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            "__type__": type(value).__name__,
            **{f.name: to_plain(getattr(value, f.name)) for f in dataclasses.fields(value)},
        }
    if isinstance(value, dict):
        return {"__dict__": [[to_plain(k), to_plain(v)] for k, v in value.items()]}
    if isinstance(value, (list, tuple)):
        return {"__" + type(value).__name__ + "__": [to_plain(v) for v in value]}
    if isinstance(value, (set, frozenset)):
        return {"__set__": sorted(repr(to_plain(v)) for v in value)}
    if isinstance(value, Path):
        return {"__path__": value.as_posix()}
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return {"__repr__": repr(value)}


def observe(case: Case, module: ModuleType) -> dict[str, Any]:
    """Run one case against ``module`` and return everything observable about it."""
    stdout, stderr = io.StringIO(), io.StringIO()
    observed: dict[str, Any] = {}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                observed["return"] = to_plain(case(module))
            except Exception as exc:  # noqa: BLE001 - the exception is the observation
                observed["raises"] = [type(exc).__name__, str(exc)]
    observed["stdout"] = stdout.getvalue()
    observed["stderr"] = stderr.getvalue()
    observed["warnings"] = [[w.category.__name__, str(w.message)] for w in caught]
    # Round-trip so recorded and live observations compare as the same JSON data.
    return json.loads(json.dumps(observed))


def observe_all(cases: dict[str, Case], module: ModuleType) -> dict[str, Any]:
    return {case_id: observe(cases[case_id], module) for case_id in sorted(cases)}


def load_golden(filename: str) -> dict[str, Any]:
    return json.loads((DATA_DIR / filename).read_text(encoding="utf-8"))
