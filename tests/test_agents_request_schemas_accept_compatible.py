"""Additive-only guard: every request body the schema bound to an agents route at the
develop base (beca446) accepted must still validate at HEAD.

The branch gave several routes new request schemas. Where the old schema was open
(additionalProperties true), a property added with a type or bound would reject bodies that
used to pass, so added properties carry a description only. The old schemas are read with
``git show`` from the base commit.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from traigent_schema.utils import get_schemas_dir

BASE = "beca446"
REPO = Path(__file__).resolve().parent.parent
NEW_DIR = get_schemas_dir() / "agents"
REL = "traigent_schema/schemas/agents/"

# (old schema bound at BASE, new schema bound at HEAD)
PAIRS = [
    ("agent_create_request_schema.json", "agent_import_request_schema.json"),
    ("agent_schema.json", "agent_update_request_schema.json"),
    ("retriever_create_request_schema.json", "project_retriever_create_request_schema.json"),
    ("model_parameters_create_request_schema.json", "project_model_parameters_create_request_schema.json"),
    ("model_parameters_schema.json", "model_parameters_update_request_schema.json"),
]

WRONG = ["hot", 12345, True, None, ["x"], {"x": 1}, -5, 99999.5]


def _git_show(name: str) -> dict:
    out = subprocess.run(
        ["git", "show", f"{BASE}:{REL}{name}"], cwd=REPO, capture_output=True, text=True
    )
    if out.returncode != 0:
        pytest.skip(f"base commit {BASE} not available: {out.stderr.strip()}")
    return json.loads(out.stdout)


def _validator(schema: dict, folder: str) -> Draft7Validator:
    """Validator that resolves the schema's relative refs inside ``folder`` (HEAD tree)."""
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    registry = Registry()
    for path in get_schemas_dir().rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            registry = registry.with_resource(
                doc["$id"], Resource.from_contents(doc, default_specification=DRAFT7)
            )
    return Draft7Validator(schema, registry=registry)


def _old_valid(old: dict, new: dict) -> list[dict]:
    """Bodies the old schema accepts: the two reported examples plus one wrong-typed body per
    property the new schema added."""
    bodies: list[dict] = [
        {"name": "a", "agent_type_id": "qa", "schema_version": 1},
        {"name": "a", "agent_type_id": "qa", "agent": 5},
        {"temperature": "hot"},
        {"model_id": 7, "temperature": "hot", "stop_sequences": "x"},
        {"name": "r", "vector_store": {}, "k": 1, "retrieval_k": 1, "chunk_size": 1, "overlap": 0},
        # minimal bodies of the closed base schemas (agent_schema, model_parameters_schema)
        {"id": "i", "name": "a", "agent_type": "qa"},
        {"id": "i", "model_id": "m"},
    ]
    added = set(new.get("properties", {})) - set(old.get("properties", {}))
    for prop in sorted(added):
        for wrong in WRONG:
            bodies.append({"name": "a", "agent_type_id": "qa", prop: wrong})
            bodies.append({prop: wrong})
            bodies.append({"id": "i", "name": "a", "agent_type": "qa", prop: wrong})
            bodies.append({"id": "i", "model_id": "m", prop: wrong})
    return bodies


@pytest.mark.parametrize("old_name,new_name", PAIRS)
def test_bodies_valid_at_base_stay_valid_at_head(old_name: str, new_name: str) -> None:
    old = _git_show(old_name)
    new = json.loads((NEW_DIR / new_name).read_text(encoding="utf-8"))
    old_v = _validator(old, "agents")
    new_v = _validator(new, "agents")
    checked = 0
    for body in _old_valid(old, new):
        if old_v.is_valid(body):
            checked += 1
            errs = [e.message for e in new_v.iter_errors(body)]
            assert not errs, f"{new_name} rejects a body {old_name} accepted: {body!r}: {errs}"
    assert checked, f"no old-valid body generated for {old_name}"


def test_reported_examples() -> None:
    imp = _validator(json.loads((NEW_DIR / "agent_import_request_schema.json").read_text()), "agents")
    assert imp.is_valid({"name": "a", "agent_type_id": "qa", "schema_version": 1})
    mp = _validator(
        json.loads((NEW_DIR / "project_model_parameters_create_request_schema.json").read_text()),
        "agents",
    )
    assert mp.is_valid({"temperature": "hot"})
