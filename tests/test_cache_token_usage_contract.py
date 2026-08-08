"""Contract tests for the canonical cached-token usage vocabulary.

Traigent/Traigent#2068, Traigent/traigent-js#290 and TraigentBackend#2511 all need
one thing from Schema: a usage shape that can carry cached-token counts AND express
"the provider did not report this", so that a silent provider is never rounded to a
confident zero.

These tests pin the two properties the downstream fixes actually depend on:

1. the fields exist on the usage surfaces (ingest, read, cost aggregate), and
2. ``null`` is a legal value distinct from ``0`` — because defaulting a silent
   provider to ``0`` is what makes the cost wrong in the first place.
"""

import json

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

CANONICAL_DEFINITIONS = (
    "CacheReadTokens",
    "CacheCreationTokens",
    "UnreportedUsageFields",
)

CACHE_FIELDS = ("cache_read_tokens", "cache_creation_tokens")


def _schema(*parts):
    path = get_schemas_dir()
    for part in parts:
        path = path / part
    with open(path) as handle:
        return json.load(handle)


def test_canonical_cache_definitions_live_in_common_types():
    """The vocabulary has exactly one home, so surfaces cannot drift apart."""
    definitions = _schema("common_types_schema.json")["definitions"]

    for name in CANONICAL_DEFINITIONS:
        assert name in definitions, f"{name} missing from common_types_schema.json"


@pytest.mark.parametrize("name", ["CacheReadTokens", "CacheCreationTokens"])
def test_cache_counts_are_nullable_by_design(name):
    """null (provider silent) must remain distinguishable from 0 (no cache used).

    This is the whole point of the contract change. If someone "tidies" these to a
    plain integer, every downstream cost path silently regains the confidently-wrong
    zero that #2068/#2511 were filed about — so pin it here rather than in prose.
    """
    definition = _schema("common_types_schema.json")["definitions"][name]

    assert definition["type"] == ["integer", "null"]
    assert definition["minimum"] == 0


def test_cache_fields_reference_the_canonical_definitions_not_a_local_copy():
    """Each surface $refs the shared definition instead of re-spelling the type."""
    surfaces = {
        "observation_schema": _schema(
            "observability", "observation_schema.json"
        )["properties"],
        "cost_user_usage_item_schema": _schema(
            "costs", "cost_user_usage_item_schema.json"
        )["properties"],
    }

    for surface, properties in surfaces.items():
        for field in CACHE_FIELDS:
            assert field in properties, f"{field} missing from {surface}"
            ref = properties[field].get("$ref", "")
            assert "common_types_schema.json#/definitions/" in ref, (
                f"{surface}.{field} inlines its own type instead of referencing "
                f"the canonical definition (got {ref!r})"
            )


def test_every_ingest_depth_level_carries_the_cache_fields():
    """observation_ingest repeats its shape per nesting depth; none may lag.

    The file hand-duplicates Observation_d1..d6. A cache field added to only the
    top level would silently drop cached tokens from any nested generation.
    """
    definitions = _schema("observability", "observation_ingest_schema.json")[
        "definitions"
    ]
    depth_levels = [name for name in definitions if name.startswith("Observation_d")]

    assert len(depth_levels) >= 6, "expected the 6 hand-duplicated depth levels"

    for level in depth_levels:
        properties = definitions[level]["properties"]
        for field in (*CACHE_FIELDS, "unreported_usage_fields"):
            assert field in properties, f"{field} missing from {level}"


def test_ingest_accepts_a_provider_that_reported_cache_tokens():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "id": "obs_cached",
            "type": "generation",
            "name": "anthropic.messages.create",
            "input_tokens": 6,
            "output_tokens": 120,
            "cache_read_tokens": 4609,
            "cache_creation_tokens": 0,
        },
        "observation_ingest_schema",
    )

    assert errors == [], errors


def test_ingest_accepts_a_silent_provider_as_null_with_an_attribution():
    """Amazon Nova omits the cache keys entirely rather than reporting 0.

    The producer must be able to say "unknown", and say *why* it is unknown, without
    inventing a number.
    """
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "id": "obs_silent",
            "type": "generation",
            "name": "bedrock.converse",
            "input_tokens": 4615,
            "output_tokens": 120,
            "cache_read_tokens": None,
            "cache_creation_tokens": None,
            "unreported_usage_fields": [
                "cache_read_tokens",
                "cache_creation_tokens",
            ],
        },
        "observation_ingest_schema",
    )

    assert errors == [], errors


def test_ingest_still_accepts_a_payload_with_no_cache_dimension_at_all():
    """Pre-existing producers must keep validating unchanged (pure widening)."""
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "id": "obs_legacy",
            "type": "generation",
            "name": "openai.chat.completions.create",
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 150,
        },
        "observation_ingest_schema",
    )

    assert errors == [], errors


def test_ingest_rejects_a_negative_cache_count():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "id": "obs_bad",
            "type": "generation",
            "name": "openai.chat.completions.create",
            "cache_read_tokens": -1,
        },
        "observation_ingest_schema",
    )

    assert errors != [], "a negative cached-token count must not validate"


def test_cost_user_usage_item_carries_cache_tokens_without_requiring_them():
    """The aggregate gains the dimension; existing backends keep validating."""
    item_schema = _schema("costs", "cost_user_usage_item_schema.json")

    for field in CACHE_FIELDS:
        assert field in item_schema["properties"]
        assert field not in item_schema["required"], (
            f"{field} must stay optional so the current backend response, which "
            f"does not yet emit it, keeps validating"
        )


# --------------------------------------------------------------------------
# Cache-write TTL tiers (#383). A cache write is priced per tier -- 1.25x base
# input at 5 minutes, 2x at 1 hour -- so an untiered total is 60% wrong whenever
# the assumed tier is not the one that ran. The contract has to be able to say
# which tier, and to say "unknown".
# --------------------------------------------------------------------------


def test_ttl_breakdown_definition_exists_and_is_nullable_per_tier():
    definitions = _schema("common_types_schema.json")["definitions"]

    assert "CacheCreationTokensByTtl" in definitions
    props = definitions["CacheCreationTokensByTtl"]["properties"]
    for tier in ("ephemeral_5m", "ephemeral_1h"):
        assert props[tier]["type"] == ["integer", "null"], (
            f"{tier} must stay nullable: absent means the provider did not report "
            f"that tier, which is not the same as zero tokens on it"
        )


def test_ttl_breakdown_rejects_an_unknown_tier_name():
    """A typo'd or newly-invented tier must not slip through as opaque data."""
    definitions = _schema("common_types_schema.json")["definitions"]

    assert definitions["CacheCreationTokensByTtl"]["additionalProperties"] is False


def test_every_ingest_depth_level_carries_the_ttl_breakdown():
    definitions = _schema("observability", "observation_ingest_schema.json")[
        "definitions"
    ]
    depth_levels = [n for n in definitions if n.startswith("Observation_d")]

    assert len(depth_levels) >= 6
    for level in depth_levels:
        assert "cache_creation_tokens_by_ttl" in definitions[level]["properties"], (
            f"{level} lags the top level; a nested generation would silently lose "
            f"its cache-write tier"
        )


def test_ingest_accepts_a_request_that_used_both_tiers():
    """Anthropic can report both tiers on one request."""
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "id": "obs_both",
            "type": "generation",
            "name": "anthropic.messages.create",
            "cache_creation_tokens": 1500,
            "cache_creation_tokens_by_ttl": {
                "ephemeral_5m": 1000,
                "ephemeral_1h": 500,
            },
        },
        "observation_ingest_schema",
    )

    assert errors == [], errors


def test_ingest_accepts_an_untiered_total_as_tier_unknown():
    """Bedrock Converse reports only an aggregate cacheWriteInputTokens."""
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "id": "obs_untiered",
            "type": "generation",
            "name": "bedrock.converse",
            "cache_creation_tokens": 1500,
            "unreported_usage_fields": ["cache_creation_tokens_by_ttl"],
        },
        "observation_ingest_schema",
    )

    assert errors == [], errors


def test_ingest_rejects_a_misspelled_tier():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "id": "obs_bad_tier",
            "type": "generation",
            "name": "anthropic.messages.create",
            "cache_creation_tokens_by_ttl": {"ephemeral_10m": 100},
        },
        "observation_ingest_schema",
    )

    assert errors != [], "an unrecognised TTL tier must not validate"


def test_the_cost_aggregate_can_express_the_ttl_tier_it_prices_by():
    """`cost_user_usage_item` is the one surface here that multiplies a count by a rate.

    It carried `cache_creation_tokens` but not the TTL breakdown, while declaring
    `additionalProperties: false` — so a producer that knew the tier could not send
    it. That is not a silent gap: it is a HARD REJECT of the only payload able to
    price a cache write correctly, on the only surface that prices one.
    """
    item_schema = _schema("costs", "cost_user_usage_item_schema.json")

    assert item_schema.get("additionalProperties") is False, (
        "this test's premise is that undeclared fields are rejected here"
    )
    assert "cache_creation_tokens_by_ttl" in item_schema["properties"], (
        "an untiered cache-write count cannot be priced: the 5-minute and 1-hour "
        "tiers differ by 60%, so the surface that applies a rate must be able to "
        "carry the tier"
    )
    assert "cache_creation_tokens_by_ttl" not in item_schema.get("required", []), (
        "must stay optional — the current backend response does not emit it yet"
    )


def test_input_tokens_states_the_disjointness_convention_it_now_assumes():
    """The contract redefines `input_tokens`; it has to say so ON `input_tokens`.

    Producers are told to normalize to the disjoint convention (input excludes
    cache reads), but that instruction lived only on `CacheReadTokens`. A consumer
    reading `input_tokens` alone — which is exactly what an `input_tokens × rate`
    query does — had no way to learn the convention changed, and old and new
    records are not distinguishable by the field itself.
    """
    for args in (
        ("costs", "cost_user_usage_item_schema.json"),
        ("observability", "observation_schema.json"),
    ):
        schema = _schema(*args)
        description = schema["properties"]["input_tokens"].get("description", "")
        assert "cache_read_tokens" in description, (
            f"{args[-1]}: input_tokens must name the convention it now assumes"
        )
        assert "5.7.0" in description, (
            f"{args[-1]}: input_tokens must say which records predate the convention, "
            f"since the field alone cannot distinguish them"
        )
