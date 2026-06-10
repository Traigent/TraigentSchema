"""Contract tests for the canonical API-key auth vocabulary.

The vocabulary prevents BE/FE token drift by making the shared Schema package
own scope tokens, permission tokens, and the scope-to-permission bridge. These
tests intentionally assert metadata and refs, not backend/frontend runtime code.
"""

from __future__ import annotations

import json

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator, load_schema
from traigent_schema.utils import get_schemas_dir

VOCABULARY_SCHEMA = "api_key_authorization_vocabulary_schema"
DEVICE_AUTH_REQUEST = "device_authorization_request_schema"
AUDIT_LOG_ENTRY_RESPONSE = "audit_log_entry_response_schema"
PROJECT_MEMBER_LOOKUP_ERROR = "project_member_lookup_error_schema"

EXPECTED_SCOPES = [
    "agents:read",
    "agents:write",
    "admin:all",
    "benchmarks:read",
    "benchmarks:write",
    "datasets:read",
    "datasets:write",
    "experiments:read",
    "experiments:write",
    "measures:read",
    "measures:write",
    "traces:read",
    "traces:write",
]

EXPECTED_USER_REQUESTABLE_SCOPES = [
    "agents:read",
    "agents:write",
    "benchmarks:read",
    "benchmarks:write",
    "datasets:read",
    "datasets:write",
    "experiments:read",
    "experiments:write",
    "measures:read",
    "measures:write",
    "traces:read",
    "traces:write",
]

EXPECTED_PERMISSIONS = [
    "admin",
    "agent.read",
    "agent.write",
    "audit.export",
    "audit.read",
    "benchmark.read",
    "benchmark.write",
    "dataset.read",
    "dataset.write",
    "delete",
    "experiment.read",
    "experiment.write",
    "measure.read",
    "measure.write",
    "project.membership.manage",
    "read",
    "system.read",
    "trace.read",
    "trace.write",
    "write",
]

EXPECTED_SCOPE_PERMISSION_MAP = {
    "agents:read": ["agent.read"],
    "agents:write": ["agent.write", "agent.read"],
    "admin:all": ["admin"],
    "benchmarks:read": ["benchmark.read"],
    "benchmarks:write": ["benchmark.write", "benchmark.read"],
    "datasets:read": ["dataset.read"],
    "datasets:write": ["dataset.write", "dataset.read"],
    "experiments:read": ["experiment.read"],
    "experiments:write": ["experiment.write", "experiment.read"],
    "measures:read": ["measure.read"],
    "measures:write": ["measure.write", "measure.read"],
    "traces:read": ["trace.read"],
    "traces:write": ["trace.write", "trace.read"],
}


def _audit_log_entry(permission: str | None) -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "id": 42,
            "event_type": "access_granted",
            "timestamp": "2026-05-24T09:31:12+00:00",
            "user_id": "user_123",
            "api_key_id": None,
            "resource": "audit_log/log_42",
            "permission": permission,
            "action": "read",
            "outcome": "success",
            "reason": "Audit log access granted",
            "is_admin_action": True,
            "ip_address": "203.0.113.10",
            "event_data": {"scope_mode": "global", "scope_tenant_id": None},
            "checksum": "0" * 64,
        },
    }


def test_api_key_authorization_vocabulary_is_valid_draft7() -> None:
    Draft7Validator.check_schema(load_schema(VOCABULARY_SCHEMA))


def test_canonical_scope_and_permission_enums_are_pinned() -> None:
    schema = load_schema(VOCABULARY_SCHEMA)
    definitions = schema["definitions"]

    assert definitions["ApiKeyScopeToken"]["enum"] == EXPECTED_SCOPES
    assert (
        definitions["UserRequestableApiKeyScopeToken"]["enum"]
        == EXPECTED_USER_REQUESTABLE_SCOPES
    )
    assert definitions["ApiKeyPermissionToken"]["enum"] == EXPECTED_PERMISSIONS
    assert schema["x-user-requestable-scopes"] == EXPECTED_USER_REQUESTABLE_SCOPES
    assert schema["x-privileged-scopes"] == ["admin:all"]
    assert "admin:all" not in definitions["UserRequestableApiKeyScopeToken"]["enum"]


def test_scope_permission_map_covers_every_scope_once() -> None:
    schema = load_schema(VOCABULARY_SCHEMA)
    scope_enum = schema["definitions"]["ApiKeyScopeToken"]["enum"]
    permission_enum = set(schema["definitions"]["ApiKeyPermissionToken"]["enum"])
    scope_map = schema["x-scope-permission-map"]

    assert sorted(scope_map) == sorted(scope_enum)
    assert {
        scope: metadata["permissions"] for scope, metadata in scope_map.items()
    } == EXPECTED_SCOPE_PERMISSION_MAP

    for scope, metadata in scope_map.items():
        assert set(metadata["permissions"]) <= permission_enum, scope
        if scope.endswith(":write"):
            read_permission = metadata["permissions"][0].replace(".write", ".read")
            assert read_permission in metadata["permissions"], scope

    assert scope_map["admin:all"]["privileged"] is True


def test_scope_and_permission_conventions_are_documented_and_enforced() -> None:
    schema = load_schema(VOCABULARY_SCHEMA)

    scope_pattern = schema["definitions"]["ApiKeyScopeToken"]["pattern"]
    permission_pattern = schema["definitions"]["ApiKeyPermissionToken"]["pattern"]
    assert scope_pattern == schema["x-scope-convention"]["pattern"]
    assert permission_pattern == schema["x-permission-convention"]["pattern"]
    assert schema["x-scope-convention"]["delimiter"] == ":"
    assert schema["x-permission-convention"]["delimiter"] == "."


def test_device_authorization_scope_refs_user_requestable_scope_list() -> None:
    request_schema = load_schema(DEVICE_AUTH_REQUEST)
    scope_schema = request_schema["properties"]["scope"]

    assert (
        scope_schema["$ref"]
        == "./api_key_authorization_vocabulary_schema.json#/definitions/UserRequestableApiKeyScopeList"
    )


def test_device_authorization_scope_accepts_only_canonical_tokens() -> None:
    validator = SchemaValidator()
    assert (
        validator.validate_json(
            {
                "client_id": "traigent-python-cli",
                "scope": "experiments:read traces:write",
            },
            DEVICE_AUTH_REQUEST,
        )
        == []
    )

    for invalid_scope in (
        "api:project",
        "dataset:write",
        "experiments.write",
        "admin:all",
        "experiments:read admin:all",
    ):
        errors = validator.validate_json(
            {"client_id": "traigent-python-cli", "scope": invalid_scope},
            DEVICE_AUTH_REQUEST,
        )
        assert errors, invalid_scope


def test_audit_permission_refs_canonical_permission_value() -> None:
    schema = load_schema(AUDIT_LOG_ENTRY_RESPONSE)
    permission_schema = schema["definitions"]["AuditLogEntry"]["properties"][
        "permission"
    ]

    assert (
        permission_schema["$ref"]
        == "../auth/api_key_authorization_vocabulary_schema.json#/definitions/AuditPermissionValue"
    )


def test_audit_permission_accepts_canonical_tokens_and_rejects_scope_tokens() -> None:
    validator = SchemaValidator()

    for permission in ("audit.read", "read,write", None):
        assert (
            validator.validate_json(
                _audit_log_entry(permission),
                AUDIT_LOG_ENTRY_RESPONSE,
            )
            == []
        )

    errors = validator.validate_json(
        _audit_log_entry("experiments:read"),
        AUDIT_LOG_ENTRY_RESPONSE,
    )
    assert errors


def test_project_permission_required_refs_canonical_project_permission() -> None:
    schema = load_schema(PROJECT_MEMBER_LOOKUP_ERROR)
    permission_schema = schema["properties"]["permission_required"]

    expected_ref = (
        "../auth/api_key_authorization_vocabulary_schema.json"
        "#/definitions/ProjectPermissionValue"
    )
    assert permission_schema["$ref"] == expected_ref


def test_project_permission_required_rejects_unknown_permission() -> None:
    validator = SchemaValidator(contract="planned_projects")
    valid_payload = {
        "error_code": "INSUFFICIENT_PERMISSIONS",
        "message": "denied",
        "permission_required": "project:membership:manage",
    }
    assert validator.validate_json(valid_payload, PROJECT_MEMBER_LOOKUP_ERROR) == []

    invalid_payload = {
        **valid_payload,
        "permission_required": "project:memberships:manage",
    }
    errors = validator.validate_json(invalid_payload, PROJECT_MEMBER_LOOKUP_ERROR)
    assert errors


def test_required_permission_annotations_point_to_project_permission_vocab() -> None:
    schemas_dir = get_schemas_dir()
    with open(
        schemas_dir / "projects" / "project_member_candidate_schema.json",
        encoding="utf-8",
    ) as handle:
        candidate = json.load(handle)
    with open(
        schemas_dir / "planned_projects_endpoints.json", encoding="utf-8"
    ) as handle:
        planned = json.load(handle)

    operation = planned["paths"][
        "/api/v1beta/projects/{project_id}/membership-candidates"
    ]["get"]

    assert candidate["x-required-permission"] == "project:membership:manage"
    assert operation["x-required-permission"] == "project:membership:manage"
    assert candidate["x-required-permission-vocabulary"].endswith(
        "#/definitions/ProjectPermissionToken"
    )
    assert operation["x-required-permission-vocabulary"].endswith(
        "#/definitions/ProjectPermissionToken"
    )
