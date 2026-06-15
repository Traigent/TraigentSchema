"""#148: list/dashboard response schemas that duplicate the same rows under two
top-level arrays now mark one array deprecated (behavior-preserving — both still
emitted; consumers migrate to the canonical key)."""
import json

from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()

# (schema, deprecated alias, canonical key)
CASES = [
    ("observability/review_score_list_response_schema.json", "scores", "items"),
    ("audit/security_incidents_response_schema.json", "incidents", "data"),
    ("audit/alerts_response_schema.json", "data", "alerts"),
]


def _load(rel):
    with open(S / rel, encoding="utf-8") as fh:
        return json.load(fh)


def test_duplicate_array_alias_is_deprecated_and_points_to_canonical():
    for rel, alias, canonical in CASES:
        props = _load(rel)["properties"]
        assert alias in props and canonical in props, rel
        assert props[alias].get("deprecated") is True, f"{rel}:{alias} not deprecated"
        assert canonical in props[alias]["description"], f"{rel}:{alias} desc must point to {canonical}"
        # the canonical key is NOT deprecated
        assert props[canonical].get("deprecated") is not True, f"{rel}:{canonical} wrongly deprecated"


def test_alias_and_canonical_describe_the_same_rows():
    # the duplication is only safe to deprecate because both arrays carry identical items
    for rel, alias, canonical in CASES:
        props = _load(rel)["properties"]
        assert props[alias].get("items") == props[canonical].get("items"), rel
