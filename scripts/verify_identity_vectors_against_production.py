#!/usr/bin/env python3
"""One-off check: run REAL production functions against identity_vectors_v1.json.

Run it with the Python SDK checkout's own interpreter:

  <Traigent>/.venv/bin/python scripts/verify_identity_vectors_against_production.py \
      --component sdk --checkout <Traigent checkout>

sdk: decorates a probe function with the real ``traigent.optimize`` and compares
``experiment_name`` (registration identity) and the real
``_build_default_experiment_name``.
Exits non-zero on any mismatch or import failure. Read-only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

VECTORS = (
    Path(__file__).resolve().parents[1] / "traigent_schema/data/identity/identity_vectors_v1.json"
)


def _py_vectors():
    doc = json.loads(VECTORS.read_text("utf-8"))
    return [v for v in doc["provenance"] if v["input"]["sdk"] == "python"]


def check_sdk() -> list[str]:
    os.environ.pop("TRAIGENT_EXPERIMENT_NAME", None)
    import traigent  # noqa: PLC0415

    problems, checked = [], 0
    for v in _py_vectors():
        inp, exp = v["input"], v["expected"]
        if exp.get("outcome") == "unsupported":
            import functools  # noqa: PLC0415

            try:
                traigent.optimize(objectives=inp["objectives"])(functools.partial(print))
                problems.append(f"{v['id']}: decoration unexpectedly succeeded")
            except AttributeError:
                checked += 1
            except Exception as exc:  # noqa: BLE001
                problems.append(f"{v['id']}: expected AttributeError, got {exc!r}")
            continue
        fn_name = inp["function_name"]

        def probe(*a, **k):  # noqa: ANN002, ANN003
            return None

        probe.__name__ = fn_name
        probe.__qualname__ = inp.get("qualname") or fn_name
        kwargs = {}
        if inp.get("objectives"):
            kwargs["objectives"] = inp["objectives"]
        if inp.get("knobs"):
            kwargs["configuration_space"] = {k: [1, 2] for k in inp["knobs"]}
        if inp.get("agent_name"):
            kwargs["agent_name"] = inp["agent_name"]
        if inp.get("experiment_name_env"):
            os.environ["TRAIGENT_EXPERIMENT_NAME"] = inp["experiment_name_env"]
        try:
            got = traigent.optimize(**kwargs)(probe).experiment_name
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{v['id']}: decoration raised {exc!r}")
            continue
        finally:
            os.environ.pop("TRAIGENT_EXPERIMENT_NAME", None)
        checked += 1
        if got != exp["registration_identity"]:
            problems.append(
                f"{v['id']}: experiment_name {got!r} != {exp['registration_identity']!r}"
            )
    print(f"sdk: checked {checked} python vectors, {len(problems)} problems")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", choices=["sdk"], required=True)
    parser.add_argument("--checkout", required=True)
    args = parser.parse_args()
    root = Path(args.checkout).resolve()
    os.chdir(root)
    sys.path.insert(0, str(root))
    try:
        problems = check_sdk()
    except Exception as exc:  # noqa: BLE001
        print(f"IMPORT/RUN FAILURE: {type(exc).__name__}: {exc}")
        return 2
    for p in problems:
        print("MISMATCH", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
