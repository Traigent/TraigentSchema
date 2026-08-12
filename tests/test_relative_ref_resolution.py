"""Relative ``$ref``s must actually resolve.

169 schema files in this library reference their siblings with relative paths
(``./x.json``, ``../x.json``), and ``planned_projects_endpoints.json`` alone carries
60 such refs inside inline request schemas.

Before this fix every one of them was dead: ``Draft7Validator(schema, registry=...)``
leaves the resolver with an empty base URI, so the reference target was looked up
under ``""`` and raised ``Unresolvable``. The broad handler in ``_run_validator``
then rendered that as ``"Validation error: Unresolvable: ../status_schema.json#/..."``
-- which reads like the *payload* was rejected. That is why the defect survived: every
affected schema produced a plausible per-payload error instead of an obvious wiring
failure.

These tests pin both halves: refs resolve, and a genuinely dangling ref is reported
as a contract defect rather than laundered into a payload complaint.
"""

import copy

from referencing.jsonschema import DRAFT7

from traigent_schema import SchemaValidator


def _errors(validator, payload, schema_name):
    return validator.validate_json(payload, schema_name)


def _reference_failures(errors):
    """Dead-reference errors under either spelling.

    Matching only this fix's wording would let these tests pass vacuously against
    the old code, which reported the same condition as
    ``"Validation error: Unresolvable: ..."``.
    """
    return [e for e in errors if "Schema reference error" in e or "Unresolvable" in e]


def test_parent_directory_ref_resolves():
    """``observability/observation_schema.json`` -> ``../status_schema.json``."""
    validator = SchemaValidator()

    errors = _errors(
        validator,
        {"id": "obs_1", "type": "generation", "name": "call", "status": "completed"},
        "observation_ingest_schema",
    )

    assert errors == [], errors


def test_parent_directory_ref_still_enforces_the_referenced_constraint():
    """Resolution must import the *constraint*, not merely stop erroring.

    ``success`` is not a member of ObservabilityTraceStatus. If this passes, the ref
    is resolving to something empty and the enum is not being enforced.
    """
    validator = SchemaValidator()

    errors = _errors(
        validator,
        {"id": "obs_1", "type": "generation", "name": "call", "status": "success"},
        "observation_ingest_schema",
    )

    assert errors != [], "the referenced status enum is not being enforced"
    assert any("is not one of" in e for e in errors), errors


def test_same_directory_ref_resolves():
    """``observation_ingest_schema.json`` -> ``./correlation_ids_schema.json``."""
    validator = SchemaValidator()

    errors = _errors(
        validator,
        {
            "id": "obs_1",
            "type": "generation",
            "name": "call",
            "correlation_ids": {},
        },
        "observation_ingest_schema",
    )

    assert errors == [], errors


def _walk_refs(node, out):
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            out.append(ref)
        for value in node.values():
            _walk_refs(value, out)
    elif isinstance(node, list):
        for value in node:
            _walk_refs(value, out)


def test_every_relative_ref_in_the_library_resolves():
    """Statically resolve every ``$ref`` in every schema.

    Payload-driven checks only exercise the refs a given payload happens to reach,
    so they cannot prove the library is free of dead references. This walks the
    contracts themselves: each ``$ref`` is resolved against its own schema's base
    URI, exactly as the validator now does.
    """
    validator = SchemaValidator()
    registry = validator._registry
    broken = {}

    for name, schema in validator._schemas.items():
        schema_id = schema.get("$id")
        if not schema_id:
            continue

        refs = []
        _walk_refs(schema, refs)
        resolver = registry.resolver(base_uri=schema_id)

        for ref in refs:
            try:
                resolver.lookup(ref)
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                broken.setdefault(name, []).append(f"{ref} -> {type(exc).__name__}")

    assert broken == {}, f"schemas with dangling references: {broken}"


def test_every_relative_ref_in_inline_catalog_schemas_resolves_from_its_catalog():
    """Inline refs resolve from the declaring endpoint catalog's directory."""
    validator = SchemaValidator()
    broken = {}

    for key, schema in validator._inline_request_schemas.items():
        base_uri = validator._inline_request_schema_base_ids[key]
        resource = DRAFT7.create_resource(schema)
        registry = validator._registry.with_resource(base_uri, resource)
        resolver = registry.resolver(base_uri=base_uri)

        refs = []
        _walk_refs(schema, refs)
        for ref in refs:
            try:
                resolver.lookup(ref)
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                broken.setdefault(key, []).append(f"{ref} -> {type(exc).__name__}")

    assert broken == {}, f"inline schemas with dangling references: {broken}"


def test_dangling_reference_is_reported_as_a_contract_defect():
    """A missing target must not read as "your payload is invalid"."""
    validator = SchemaValidator()

    errors = validator._run_validator(
        {"anything": 1},
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {"anything": {"$ref": "./does_not_exist_schema.json"}},
        },
    )

    assert len(errors) == 1, errors
    assert errors[0].startswith("Schema reference error (contract defect, not payload)")


def test_inline_catalog_schema_resolves_its_relative_refs():
    """Inline request schemas have no ``$id`` and must still resolve siblings.

    ``planned_projects_endpoints.json`` embeds request schemas that reference
    ``./error_envelope_schema.json`` and ``./projects/*.json`` directly.
    """
    validator = SchemaValidator()

    errors = validator._run_validator(
        {"envelope": {"success": False, "error": {"code": "X", "message": "y"}}},
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {"envelope": {"$ref": "./error_envelope_schema.json"}},
        },
    )

    assert _reference_failures(errors) == [], errors


def test_real_subdirectory_inline_catalog_schema_resolves_its_relative_ref():
    """The annotation-queue completion request resolves from ``observability/``."""
    validator = SchemaValidator()

    errors = validator.validate_request(
        "/api/v1beta/annotation-queues/items/{item_id}/complete",
        "POST",
        {
            "scores": [
                {
                    "measure_id": "measure_1",
                    "target_type": "observability_trace",
                    "target_id": "trace_1",
                    "numeric_value": 1.0,
                }
            ]
        },
    )

    assert errors == [], errors


def test_relative_schema_id_uses_the_fallback_base_for_sibling_refs():
    """A caller-supplied relative ``$id`` must not become an empty-base ref."""
    validator = SchemaValidator()

    errors = validator._run_validator(
        "not-an-integer",
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "relative-schema.json",
            "$ref": "./common_types_schema.json#/definitions/CacheReadTokens",
        },
    )

    assert _reference_failures(errors) == [], errors
    assert any("is not of type" in error for error in errors), errors


def test_anchored_validation_uses_the_supplied_schema_not_the_registry_copy():
    """Anchoring establishes a base without discarding caller mutations."""
    validator = SchemaValidator()
    schema = copy.deepcopy(validator._schemas["agent_schema"])
    schema["properties"]["mutation_probe"] = {"type": "string"}
    schema.setdefault("required", []).append("mutation_probe")

    errors = validator._run_validator({}, schema)

    assert any("mutation_probe" in error for error in errors)
