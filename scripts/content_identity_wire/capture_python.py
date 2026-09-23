"""Capture the Python SDK's content-identity WIRE payloads as test fixtures.

Runs the SDK's own builders (traigent.identity.run.prepare_content_identity_run,
ContentIdentityRun.session_wire / trial_wire, provider_versions.observations_payload)
-- nothing here assembles a wire object by hand -- and writes
tests/data/content_identity_wire/python_sdk.json.

Usage (a Traigent SDK checkout that has traigent/identity/run.py):

    PYTHONPATH=<Traigent checkout> <venv>/bin/python \
        scripts/content_identity_wire/capture_python.py <Traigent checkout>

Keys are the PUBLIC TEST purpose keys of vector tenant_a
(traigent_schema/data/content_identity_v1_vectors.json key_derivation), installed
through the SDK's production grant entry point.
"""

from __future__ import annotations

import json
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tests" / "data" / "content_identity_wire" / "python_sdk.json"


def _provenance(sdk_root: Path) -> dict[str, Any]:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(sdk_root), *args], capture_output=True, text=True, check=True
        ).stdout.strip()

    return {
        "sdk": "traigent (Python)",
        "commit": git("rev-parse", "HEAD"),
        "dirty_paths": sorted(
            line[3:] for line in git("status", "--porcelain").splitlines() if line
        ),
    }


def main() -> None:
    sdk_root = Path(sys.argv[1]).resolve()
    from traigent.evaluators.base import Dataset, EvaluationExample
    from traigent.evaluators.local import LocalEvaluator
    from traigent.identity import run as run_module
    from traigent.identity.evaluator_version import declare_evaluator
    from traigent.identity.examples import result_identity_fields
    from traigent.identity.keys import (
        ContentIdentityKeys,
        clear_content_identity_keys,
        set_content_identity_keys,
    )
    from traigent.identity.provider_versions import observations_payload

    vectors = json.loads(
        (ROOT / "traigent_schema" / "data" / "content_identity_v1_vectors.json").read_text(
            encoding="utf-8"
        )
    )
    row = next(k for k in vectors["key_derivation"] if k["tenant"] == "tenant_a")
    grant = {
        "tenant_id": row["tenant_id"],
        "kid": row["key_id"],
        "example_id_key": row["example_id_key_hex"],
        "example_version_key": row["example_version_key_hex"],
        "encoding": "hex",
    }
    set_content_identity_keys(ContentIdentityKeys.from_grant(grant))

    def dataset(rows: list[tuple[Any, Any]]) -> Dataset:
        return Dataset(
            examples=[EvaluationExample(input_data=i, expected_output=e) for i, e in rows],
            name="d",
        )

    class Objective:
        def __init__(self, name: str) -> None:
            self.name, self.orientation, self.weight = name, "maximize", 1.0

    def agent(q: str) -> str:
        return q

    def exact(output: Any, expected: Any, **_: Any) -> float:
        return float(output == expected)

    def run(ds: Dataset, **overrides: Any) -> Any:
        kwargs: dict[str, Any] = {
            "agent_key": "agent_1",
            "evaluator": LocalEvaluator(metrics=["accuracy"]),
            "objectives": [Objective("accuracy")],
            "evaluator_id": None,
        }
        kwargs.update(overrides)
        return run_module.prepare_content_identity_run(agent, ds, **kwargs)

    def results(ds: Dataset) -> list[dict[str, Any]]:
        return [result_identity_fields(e, "legacy") for e in ds.examples]

    # A duplicate row (count 2) and a conflicting label (same input, two versions).
    rows = [({"q": "a"}, "1"), ({"q": "b"}, "2"), ({"q": "a"}, "1"), ({"q": "c"}, "3"),
            ({"q": "c"}, "4")]
    base = dataset(rows)
    session: dict[str, Any] = {}
    trial: dict[str, Any] = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        full = run(base)
        session["all_slots_builtin_evaluator"] = full.session_wire({})

        declared = LocalEvaluator(metric_functions={"accuracy": exact})
        declare_evaluator(
            declared,
            evaluator_id="ev_exact",
            judge={"provider": "openai", "model": "gpt-4o-mini", "config": {"t": 0}},
            config_digest="sha256:" + "a" * 64,
            helper_digests={},
            dependency_versions={"ragas": "0.2.1"},
        )
        session["declared_evaluator_with_judge"] = run(base, evaluator=declared).session_wire(
            {"temperature": 0.2}
        )
        session["fallback_agent_id"] = run(base, agent_key=None).session_wire({})
        session["withheld_agent_evaluator_dataset"] = run(
            dataset([({"q": f"row {n}"}, str(n)) for n in range(run_module.MAX_INLINE_MEMBERS + 1)]),
            agent_key="not a key!",
            evaluator=LocalEvaluator(metric_functions={"accuracy": exact}),
        ).session_wire({})
        session["unidentifiable_dataset_bad_evaluator_id"] = run(
            dataset([({"q": "a"}, "1"), ({"n": 2**53}, "x")]), evaluator_id="bad id!"
        ).session_wire({})
        session["no_evaluator"] = run(base, evaluator=None).session_wire({})

        observed = observations_payload(
            {
                ("openai", "gpt-4o", "gpt-4o-2024-08-06", "fp_44709d6fcb"): 3,
                ("anthropic", "claude-sonnet-4-5", None, None): 1,
            }
        )
        trial["full_dataset_with_observations"] = full.trial_wire(
            "trial_1", {"temperature": 0.2}, results(base), observed
        )
        trial["subset_no_observations"] = full.trial_wire(
            "trial_2", {"temperature": 0.7}, results(base)[:2], []
        )
        trial["results_unavailable_config_not_canonicalizable"] = full.trial_wire(
            "trial_3", {"a": object()}, None, []
        )
        trial["row_outside_dataset"] = full.trial_wire(
            "trial_4", {}, [*results(base), {"example_id": "example_3"}], []
        )
        unidentifiable = run(dataset([({"n": 2**53}, "x")]), agent_key="not a key!")
        trial["unidentifiable_dataset_no_agent"] = unidentifiable.trial_wire(
            "trial_5", {}, [], []
        )
    clear_content_identity_keys()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "note": "Generated by scripts/content_identity_wire/capture_python.py from the SDK's own "
        "builders. Do not hand-edit; regenerate.",
        "generated_by": _provenance(sdk_root),
        # The SDK's own declared reason vocabulary (traigent.identity.run.UNAVAILABLE_REASONS).
        "declared_reasons": sorted(run_module.UNAVAILABLE_REASONS),
        "purpose_key_grant": grant,
        "session": session,
        "trial": trial,
    }
    OUT.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(session)} session, {len(trial)} trial payloads)")


if __name__ == "__main__":
    main()
