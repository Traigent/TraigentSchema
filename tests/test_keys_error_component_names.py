"""API-key error response components use unique, API-key-scoped names.

Generic names (BadRequest, Conflict, ...) collided with the differently
defined components of certification_endpoints_v0.json when contracts are
composed.  The rename is wire-preserving: only component names and local
$refs change.
"""

from __future__ import annotations

import json

from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
KEYS = json.loads((SCHEMAS / "auth" / "keys_endpoints.json").read_text())
CERT = json.loads(
    (SCHEMAS / "certification" / "certification_endpoints_v0.json").read_text()
)

RENAMES = {
    "BadRequest": ("ApiKeyBadRequest", "Invalid request."),
    "Unauthorized": ("ApiKeyUnauthorized", "Authentication is required."),
    "Forbidden": ("ApiKeyForbidden", "The action is not permitted."),
    "NotFound": ("ApiKeyNotFound", "API key was not found."),
    "Conflict": (
        "ApiKeyConflict",
        "The requested lifecycle action conflicts with the current API key state.",
    ),
    "InternalError": ("ApiKeyInternalError", "The request could not be completed."),
}
PREFIX = "#/components/responses/"


def test_old_generic_names_are_gone_and_new_names_do_not_collide():
    keys_responses = KEYS["components"]["responses"]
    cert_names = set(CERT["components"]["responses"])
    assert set(keys_responses) == {new for new, _ in RENAMES.values()}
    assert not set(keys_responses) & cert_names


def test_response_bodies_unchanged_by_rename():
    for new, description in RENAMES.values():
        body = KEYS["components"]["responses"][new]
        assert body == {
            "description": description,
            "content": {
                "application/json": {
                    "schema": {"$ref": "../error_envelope_schema.json"}
                }
            },
        }


def test_every_local_response_ref_resolves_to_renamed_component():
    refs = []

    def walk(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith(PREFIX):
                refs.append(ref[len(PREFIX):])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(KEYS["paths"])
    assert refs
    assert set(refs) <= set(KEYS["components"]["responses"])
