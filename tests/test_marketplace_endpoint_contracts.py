"""Contracts for TraigentBackend PR #3169's AWS Marketplace routes (register,
complete, events), authored against src/routes/marketplace_routes.py as
implemented -- see billing/marketplace_endpoints.json and the sibling
marketplace_*_schema.json files."""
from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

B = get_schemas_dir() / "billing"
CATALOG_NAME = "marketplace_endpoints.json"
CATALOG_PATH = B / CATALOG_NAME

EXPECTED_PATHS = {
    "/api/v1/billing/marketplace/register",
    "/api/v1/billing/marketplace/complete",
    "/api/v1/billing/marketplace/events",
}


def _load_catalog() -> dict:
    with open(CATALOG_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def test_catalog_lists_exactly_the_three_marketplace_paths_with_post():
    spec = _load_catalog()
    paths = spec["paths"]
    assert set(paths.keys()) == EXPECTED_PATHS
    for path, methods in paths.items():
        assert "post" in methods, f"{path} is missing a post operation"
        assert set(methods.keys()) == {"post"}, (
            f"{path} declares unexpected methods {methods.keys()}"
        )



def test_marketplace_operations_are_contract_first_until_the_backend_routes_land():
    """The three routes are implemented by TraigentBackend #3169, which is not merged.

    Until it is, each operation must say ``x-asserted-against-backend: false`` so the
    Backend's documented-routes conformance canary lists them as contract-first
    instead of failing every Backend traigent-schema pin bump. Flip to ``true`` in
    the same change that pins the Backend to a commit containing its routes.
    """
    spec = _load_catalog()
    flags = {
        (path, method): op.get("x-asserted-against-backend")
        for path, ops in spec["paths"].items()
        for method, op in ops.items()
        if isinstance(op, dict)
    }
    assert len(flags) == 3
    assert all(flag is False for flag in flags.values()), flags

def test_catalog_wired_into_mep_master_module_list():
    with open(get_schemas_dir() / "mep_endpoints.json", encoding="utf-8") as fh:
        mep = json.load(fh)
    modules = mep["x-endpoint-modules"]
    matching = [
        m for m in modules if m.get("paths_file") == "./billing/marketplace_endpoints.json"
    ]
    assert len(matching) == 1, (
        "marketplace_endpoints.json must be listed exactly once in mep_endpoints.json"
    )
    assert matching[0]["name"]
    assert matching[0]["description"]


def test_no_orphan_marketplace_catalog():
    """Mirrors test_endpoint_catalog_completeness.py's own check, scoped to this
    catalog: it must be reachable from mep_endpoints.json's module list, or
    SchemaValidator never loads it and every marketplace route fails open."""
    schemas = get_schemas_dir()

    def collect(rel_path: str, seen: set[str]) -> None:
        path = schemas / rel_path
        if not path.exists() or rel_path in seen:
            return
        seen.add(rel_path)
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)
        for module in spec.get("x-endpoint-modules", []):
            paths_file = module.get("paths_file")
            if not paths_file:
                continue
            from pathlib import Path

            target = (Path(rel_path).parent / paths_file).as_posix().lstrip("./")
            target = target.replace("../", "")
            collect(target, seen)

    reachable: set[str] = set()
    collect("mep_endpoints.json", reachable)
    assert f"billing/{CATALOG_NAME}" in reachable


def _iter_refs(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _iter_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_refs(item)


def test_every_ref_in_catalog_resolves_to_an_existing_file():
    spec = _load_catalog()
    refs = list(_iter_refs(spec["paths"]))
    assert refs, "expected at least one $ref in the marketplace catalog"
    for ref in refs:
        assert not ref.startswith("http"), f"unexpected absolute $ref {ref}"
        target = (B / ref).resolve()
        assert target.exists(), f"$ref {ref} does not resolve to an existing file"


def test_new_marketplace_schema_files_are_valid_and_load_through_validator():
    validator = SchemaValidator()
    schema_stems = [
        "marketplace_register_request_schema",
        "marketplace_register_error_response_schema",
        "marketplace_complete_request_schema",
        "marketplace_complete_response_schema",
        "marketplace_complete_error_response_schema",
        "marketplace_events_request_schema",
        "marketplace_events_response_schema",
        "marketplace_events_error_response_schema",
    ]
    for stem in schema_stems:
        assert stem in validator.available_schemas, f"{stem} did not load into SchemaValidator"


def test_register_request_schema_accepts_valid_and_rejects_violations():
    validator = SchemaValidator()

    assert (
        validator.validate_json(
            {"x-amzn-marketplace-token": "tok_abc123"},
            "marketplace_register_request_schema",
        )
        == []
    )

    # missing required field
    assert validator.validate_json({}, "marketplace_register_request_schema")
    # additionalProperties: false
    assert validator.validate_json(
        {"x-amzn-marketplace-token": "tok_abc123", "extra": "nope"},
        "marketplace_register_request_schema",
    )


def test_complete_request_schema_accepts_valid_and_rejects_violations():
    validator = SchemaValidator()

    assert (
        validator.validate_json(
            {"registration_id": "mpr_abc123"},
            "marketplace_complete_request_schema",
        )
        == []
    )
    assert (
        validator.validate_json(
            {"registration_id": "mpr_abc123", "tenant_id": "tenant_42"},
            "marketplace_complete_request_schema",
        )
        == []
    )

    # missing required field
    assert validator.validate_json({}, "marketplace_complete_request_schema")
    # additionalProperties: false
    assert validator.validate_json(
        {"registration_id": "mpr_abc123", "unexpected": True},
        "marketplace_complete_request_schema",
    )


def test_complete_response_schema_accepts_valid_and_rejects_violations():
    validator = SchemaValidator()

    valid = {
        "tenant_id": "tenant_42",
        "plan_tier": "team",
        "status": "active",
        "current_period_end": "2026-07-04T12:00:00+00:00",
    }
    assert validator.validate_json(valid, "marketplace_complete_response_schema") == []

    valid_null_period_end = {**valid, "current_period_end": None}
    assert (
        validator.validate_json(valid_null_period_end, "marketplace_complete_response_schema")
        == []
    )

    # plan_tier outside the enum
    invalid_plan_tier = {**valid, "plan_tier": "ultra"}
    assert validator.validate_json(invalid_plan_tier, "marketplace_complete_response_schema")

    # missing required field
    missing_status = {k: v for k, v in valid.items() if k != "status"}
    assert validator.validate_json(missing_status, "marketplace_complete_response_schema")


def test_events_request_schema_accepts_valid_and_rejects_violations():
    validator = SchemaValidator()

    valid = {
        "id": "evt-123",
        "detail-type": "License Updated",
        "detail": {"CustomerAWSAccountId": "111122223333"},
        "source": "aws.partnersubscription",
        "account": "123456789012",
    }
    assert validator.validate_json(valid, "marketplace_events_request_schema") == []

    # missing required `id`
    assert validator.validate_json(
        {"detail-type": "License Updated"}, "marketplace_events_request_schema"
    )
    # empty id violates minLength
    assert validator.validate_json({"id": ""}, "marketplace_events_request_schema")


def test_events_response_schema_accepts_each_real_result_and_rejects_unknown_value():
    validator = SchemaValidator()

    results = ("duplicate", "ignored", "unknown_customer", "orphaned_purchase", "processed")
    for result in results:
        errors = validator.validate_json({"result": result}, "marketplace_events_response_schema")
        assert errors == []

    assert validator.validate_json({"result": "success"}, "marketplace_events_response_schema")
    assert validator.validate_json({}, "marketplace_events_response_schema")


def test_error_schemas_accept_their_own_literals_and_reject_foreign_or_unstructured_bodies():
    validator = SchemaValidator()

    register_errors = [
        "marketplace integration is not enabled",
        "missing x-amzn-marketplace-token",
        "AWS could not resolve this purchase; please retry from AWS Marketplace",
    ]
    for message in register_errors:
        assert (
            validator.validate_json(
                {"error": message}, "marketplace_register_error_response_schema"
            )
            == []
        )
    # a message that belongs to a different route's vocabulary is rejected
    assert validator.validate_json(
        {"error": "unauthorized"}, "marketplace_register_error_response_schema"
    )
    # the generic envelope shape (success/message/error) is not this route's shape
    assert validator.validate_json(
        {"success": False, "message": "x", "error": register_errors[0]},
        "marketplace_register_error_response_schema",
    )

    complete_errors = [
        "marketplace integration is not enabled",
        "registration_id is required",
        (
            "tenant_id does not match the authenticated session's tenant; "
            "a purchase can only be claimed into a tenant you belong to"
        ),
        "registration not found",
        "registration already claimed",
        "registration expired; start again from AWS Marketplace",
        (
            "this tenant already has an entitling Paddle subscription; "
            "cancel it before linking an AWS Marketplace purchase"
        ),
        "this AWS Marketplace purchase is already linked to another tenant",
    ]
    for message in complete_errors:
        assert (
            validator.validate_json(
                {"error": message}, "marketplace_complete_error_response_schema"
            )
            == []
        )
    assert validator.validate_json(
        {"error": "malformed event"}, "marketplace_complete_error_response_schema"
    )

    events_errors = ["marketplace integration is not enabled", "unauthorized", "malformed event"]
    for message in events_errors:
        assert (
            validator.validate_json({"error": message}, "marketplace_events_error_response_schema")
            == []
        )
    assert validator.validate_json(
        {"error": "registration not found"}, "marketplace_events_error_response_schema"
    )
