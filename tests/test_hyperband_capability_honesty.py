import json
from pathlib import Path

from traigent_schema import SchemaValidator


def test_hyperband_is_advertised_as_planned_without_breaking_wire_acceptance() -> None:
    """#277: accepted vocabulary must not claim a nonexistent executor exists."""
    path = (
        Path(__file__).parents[1]
        / "traigent_schema/schemas/optimization/optimization_strategy_schema.json"
    )
    schema = json.loads(path.read_text())
    capability = schema["x-traigent-optimization-capabilities"]["hyperband"]
    assert capability["implementation_status"] == "planned"
    assert "not currently executable" in capability["description"]
    assert capability["canonical_algorithm"] == "hyperband"
    assert capability["execution_mode"] == "cloud"

    # This metadata correction deliberately leaves the stable wire vocabulary
    # accepted; runtime dispatch remains responsible for rejecting unsupported use.
    validator = SchemaValidator()
    assert validator.validate_json("hyperband", "optimization_strategy_schema") == []
    assert (
        validator.validate_json(
            {"algorithm": "hyperband"}, "optimization_strategy_schema"
        )
        == []
    )


def test_frontier_scout_is_advertised_as_planned_without_breaking_wire_acceptance() -> None:
    """#277: frontier_scout is not selectable on the classic algorithm path."""
    path = (
        Path(__file__).parents[1]
        / "traigent_schema/schemas/optimization/optimization_strategy_schema.json"
    )
    schema = json.loads(path.read_text())
    capability = schema["x-traigent-optimization-capabilities"]["frontier_scout"]
    assert capability["implementation_status"] == "planned"
    assert "not currently available" in capability["description"]
    assert capability["canonical_algorithm"] == "frontier_scout"

    validator = SchemaValidator()
    assert validator.validate_json("frontier_scout", "optimization_strategy_schema") == []


def test_every_advertised_capability_validates_against_its_own_definition() -> None:
    """#277: advertised metadata must satisfy the schema's capability definition."""
    from jsonschema import Draft7Validator

    path = (
        Path(__file__).parents[1]
        / "traigent_schema/schemas/optimization/optimization_strategy_schema.json"
    )
    schema = json.loads(path.read_text())
    capability_schema = {
        "$ref": "#/definitions/OptimizationCapability",
        "definitions": schema["definitions"],
    }
    validator = Draft7Validator(capability_schema)
    advertised = schema["x-traigent-optimization-capabilities"]
    for name, capability in advertised.items():
        errors = [e.message for e in validator.iter_errors(capability)]
        assert errors == [], f"{name}: {errors}"
    assert "scheduler" not in json.dumps(advertised).lower()
