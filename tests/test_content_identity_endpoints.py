"""Content-identity ENDPOINT contracts (datasets/content_identity_endpoints.json).

Four Backend routes (M3; declared ahead of the Backend merge):

* POST /api/v1/content-identity/purpose-keys -> bare PurposeKeyGrantV1, no-store;
* GET  /api/v1/datasets/{dataset_id}/versions/{version_id}/content-identity;
* GET  /api/v1/datasets/versions/by-root/{dataset_root};
* PUT  /api/v1/datasets/{dataset_id}/public-benchmark (ruling D3).

The valid bodies below mirror the Backend's own serializers
(HostedDatasetIdentityView.to_wire / unavailable_wire, DatasetVersion.to_dict,
response_handler.success_response / error_response) and their identifiers are
REAL: minted with the reference implementation from a fixed tenant master, so a
stated root must recompute from the examples map. Negative cases pin what the
contract refuses.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import SchemaValidator
from traigent_schema import example_identity as ei

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
DATASETS = SCHEMAS / "datasets"
CATALOG_PATH = DATASETS / "content_identity_endpoints.json"
CATALOG_BASE = "https://schemas.traigent.ai/datasets/content_identity_endpoints.json"
NEW_SCHEMA_FILES = [
    DATASETS / "dataset_version_content_identity_response_schema.json",
    DATASETS / "dataset_versions_by_root_response_schema.json",
    DATASETS / "dataset_public_benchmark_request_schema.json",
    DATASETS / "dataset_public_benchmark_response_schema.json",
]

PURPOSE_KEYS = "/api/v1/content-identity/purpose-keys"
IDENTITY = "/api/v1/datasets/{dataset_id}/versions/{version_id}/content-identity"
BY_ROOT = "/api/v1/datasets/versions/by-root/{dataset_root}"
PUBLIC_BENCHMARK = "/api/v1/datasets/{dataset_id}/public-benchmark"


def _registry() -> Registry:
    resources = []
    for path in SCHEMAS.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


_REGISTRY = _registry()
CATALOG = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _response_validator(path: str, method: str, status: str) -> Draft7Validator:
    """The catalog's response schema, resolved relative to the catalog file."""
    schema = CATALOG["paths"][path][method]["responses"][status]["content"]["application/json"][
        "schema"
    ]
    # allOf, not a sibling: draft-07 ignores every keyword beside $ref, $id included.
    return Draft7Validator({"$id": CATALOG_BASE, "allOf": [schema]}, registry=_REGISTRY)


def _errors(validator: Draft7Validator, instance: Any) -> list[str]:
    return [error.message for error in validator.iter_errors(instance)]


# ---------------------------------------------------------------------------
# Real identifiers, minted the way the Backend mints hosted rows (section 4.4:
# input_text -> input, expected_output -> expected, None -> ABSENT).
# ---------------------------------------------------------------------------

TENANT_ID = "tenant_ci_endpoints"
KEYS = ei.derive_tenant_keys(bytes.fromhex("a5" * 16 + "5a" * 16), TENANT_ID)
ROWS = [
    ("ex-row-1", "q1", "a1"),
    ("ex-row-2", "q2", "a2"),
    ("ex-row-3", "q3", None),
    ("ex-row-4", "q1", "a1"),  # duplicate content: counted, not collapsed
]


def _example(uuid: str, input_text: str, expected: str | None) -> dict[str, str]:
    example_id = ei.compute_example_id(KEYS, input_text)
    example_version = ei.compute_example_version(
        KEYS, example_id, expected=ei.ABSENT if expected is None else expected
    )
    return {"example_uuid": uuid, "example_id": example_id, "example_version": example_version}


EXAMPLES = sorted((_example(*row) for row in ROWS), key=lambda e: e["example_uuid"])
MULTISET = ei.compute_multiset_root(
    [
        ei.MultisetMember(eid, ever, n)
        for (eid, ever), n in Counter(
            (e["example_id"], e["example_version"]) for e in EXAMPLES
        ).items()
    ]
)

AVAILABLE = {
    "scheme": "traigent.content_identity.v1",
    "status": "available",
    "key_id": KEYS.key_id,
    "dataset_root": MULTISET.root,
    "distinct_count": MULTISET.distinct_count,
    "total_count": MULTISET.total_count,
    "conflicting_example_ids": list(MULTISET.conflicting_example_ids),
    "members_ref": "ml1:cml_0123456789abcdef0123456789abcdef",
    "members_source": "server_computed",
    "examples": EXAMPLES,
    "dataset_version_id": "7f1c2a9e-0000-4000-8000-000000000001",
    "dataset_id": "dsci0123456789abcdef",
}


def _envelope(data: Any, message: str = "Success") -> dict[str, Any]:
    return {"success": True, "message": message, "data": data}


def _unavailable(reason: str) -> dict[str, Any]:
    return {
        "scheme": "traigent.content_identity.v1",
        "status": "unavailable",
        "reason": reason,
        "dataset_version_id": AVAILABLE["dataset_version_id"],
        "dataset_id": AVAILABLE["dataset_id"],
    }


VERSION = {  # DatasetVersion.to_dict() without the snapshot
    "id": AVAILABLE["dataset_version_id"],
    "dataset_id": AVAILABLE["dataset_id"],
    "version_label": "v1",
    "description": None,
    "example_ids": ["ex-row-1", "ex-row-2", "ex-row-3", "ex-row-4"],
    "example_count": 4,
    "metadata": {},
    "created_by": "ci_owner_1234",
    "content_digest": "sha256:" + "0" * 64,
    "content_digest_domain": "traigent.dataset_version.content.v1",
    "created_at": "2026-09-23T10:00:00+00:00",
}

GRANT = {
    "tenant_id": TENANT_ID,
    "kid": KEYS.key_id,
    "example_id_key": KEYS.example_id_key.hex(),
    "example_version_key": KEYS.example_version_key.hex(),
    "encoding": "hex",
}

ERROR_ENVELOPE = {
    "success": False,
    "message": "An error occurred",
    "error": "Dataset not found",
}


# ---------------------------------------------------------------------------
# 1. The schemas and the catalog
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", NEW_SCHEMA_FILES, ids=lambda p: p.name)
def test_schema_is_valid_draft7(path: Path) -> None:
    Draft7Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


def test_every_pattern_uses_the_portable_end_anchor() -> None:
    def walk(node: Any) -> list[str]:
        if isinstance(node, dict):
            found = [node["pattern"]] if isinstance(node.get("pattern"), str) else []
            return found + [p for value in node.values() for p in walk(value)]
        if isinstance(node, list):
            return [p for item in node for p in walk(item)]
        return []

    for path in [*NEW_SCHEMA_FILES, CATALOG_PATH]:
        for pattern in walk(json.loads(path.read_text(encoding="utf-8"))):
            assert "(?![\\s\\S])" in pattern and "$" not in pattern, (path.name, pattern)


def test_catalog_is_registered_in_the_backend_contract_root() -> None:
    mep = json.loads((SCHEMAS / "mep_endpoints.json").read_text(encoding="utf-8"))
    files = [module["paths_file"] for module in mep["x-endpoint-modules"]]
    assert "./datasets/content_identity_endpoints.json" in files


def test_catalog_declares_exactly_the_four_routes_ahead_of_the_backend() -> None:
    operations = {
        (path, method): op
        for path, methods in CATALOG["paths"].items()
        for method, op in methods.items()
    }
    assert set(operations) == {
        (PURPOSE_KEYS, "post"),
        (IDENTITY, "get"),
        (BY_ROOT, "get"),
        (PUBLIC_BENCHMARK, "put"),
    }
    for key, op in operations.items():
        assert op["x-asserted-against-backend"] is False, key
        assert op["operationId"], key


def test_every_catalog_ref_resolves() -> None:
    def refs(node: Any) -> list[str]:
        if isinstance(node, dict):
            found = [node["$ref"]] if isinstance(node.get("$ref"), str) else []
            return found + [r for value in node.values() for r in refs(value)]
        if isinstance(node, list):
            return [r for item in node for r in refs(item)]
        return []

    resolver = _REGISTRY.resolver(base_uri=CATALOG_BASE)
    for ref in refs(CATALOG):
        resolver.lookup(ref)  # raises if the target file or pointer is missing


def test_validator_binds_the_routes() -> None:
    validator = SchemaValidator(contract="backend")
    for key in (
        f"POST:{PURPOSE_KEYS}",
        f"GET:{IDENTITY}",
        f"GET:{BY_ROOT}",
        f"PUT:{PUBLIC_BENCHMARK}",
    ):
        assert key in validator._known_endpoints, key
    assert validator._endpoint_schemas.get(f"PUT:{PUBLIC_BENCHMARK}") == (
        "dataset_public_benchmark_request_schema"
    )
    url = "/api/v1/datasets/ds_1/public-benchmark"
    assert validator.validate_request(url, "PUT", {"public_benchmark": True}) == []
    assert validator.validate_request(url, "PUT", {"public_benchmark": "yes"})
    assert validator.validate_request(url, "PUT", {})
    assert validator.validate_request(url, "PUT", {"public_benchmark": True, "name": "x"})


def test_purpose_key_grant_is_now_reachable_through_the_catalog() -> None:
    report = json.loads(
        (ROOT / "reports" / "schema_reachability" / "unreachable_schemas.json").read_text(
            encoding="utf-8"
        )
    )
    unreachable = set(report["unreachableSchemas"])
    for rel in (
        "datasets/purpose_key_grant_v1_schema.json",
        "datasets/content_identity_v1_schema.json",
        "datasets/dataset_version_content_identity_response_schema.json",
        "datasets/dataset_versions_by_root_response_schema.json",
        "datasets/dataset_public_benchmark_request_schema.json",
        "datasets/dataset_public_benchmark_response_schema.json",
    ):
        assert rel not in unreachable, rel


# ---------------------------------------------------------------------------
# 2. POST /api/v1/content-identity/purpose-keys
# ---------------------------------------------------------------------------


def test_purpose_keys_200_is_the_bare_grant_with_no_store() -> None:
    op = CATALOG["paths"][PURPOSE_KEYS]["post"]
    assert "requestBody" not in op
    assert op["x-wrap-status"] == "bare"
    ok = op["responses"]["200"]
    assert (
        ok["content"]["application/json"]["schema"]["$ref"] == "./purpose_key_grant_v1_schema.json"
    )
    cache = Draft7Validator(ok["headers"]["Cache-Control"]["schema"])
    assert cache.is_valid("no-store, max-age=0")
    assert cache.is_valid("no-store")
    assert not cache.is_valid("max-age=0")
    assert not cache.is_valid("no-storex")
    validator = _response_validator(PURPOSE_KEYS, "post", "200")
    assert _errors(validator, GRANT) == []
    assert _errors(validator, _envelope(GRANT))  # never wrapped
    assert _errors(validator, {**GRANT, "tenant_master": "00" * 32})  # never the master


def test_purpose_keys_error_bodies() -> None:
    unavailable = _response_validator(PURPOSE_KEYS, "post", "503")
    body = {
        "error": "content_identity_keys_unavailable",
        "message": "Content identity keys are not available for this tenant.",
    }
    assert _errors(unavailable, body) == []
    masked = {
        "success": False,
        "message": "Internal server error",
        "error": "Internal server error",
        "error_code": "RATE_LIMIT_UNAVAILABLE",
    }
    assert _errors(unavailable, masked) == []
    # the custody reason is log-only: it must never appear on the wire
    assert _errors(unavailable, {**body, "reason": "wrap_scheme_mismatch"})
    assert _errors(unavailable, {**body, "error": "wrap_scheme_mismatch"})

    forbidden = _response_validator(PURPOSE_KEYS, "post", "403")
    assert _errors(forbidden, {"error": "tenant_context_required"}) == []
    assert _errors(forbidden, {**ERROR_ENVELOPE, "error": "Forbidden"}) == []
    assert _errors(forbidden, {"error": "something_else"})

    hidden = _response_validator(PURPOSE_KEYS, "post", "404")
    assert (
        _errors(hidden, {**ERROR_ENVELOPE, "error": "Not found", "error_code": "NOT_FOUND"}) == []
    )


# ---------------------------------------------------------------------------
# 3. GET .../versions/{version_id}/content-identity
# ---------------------------------------------------------------------------

IDENTITY_OK = _response_validator(IDENTITY, "get", "200")


def test_available_identity_validates_and_recomputes() -> None:
    assert _errors(IDENTITY_OK, _envelope(AVAILABLE)) == []
    # the root is real: rebuilding the multiset from the examples map recomputes it
    counts = Counter((e["example_id"], e["example_version"]) for e in AVAILABLE["examples"])
    rebuilt = ei.compute_multiset_root([ei.MultisetMember(i, v, n) for (i, v), n in counts.items()])
    assert rebuilt.root == AVAILABLE["dataset_root"]
    assert (rebuilt.distinct_count, rebuilt.total_count) == (3, 4)
    assert rebuilt.total_count == len(AVAILABLE["examples"])
    for identifier in (AVAILABLE["dataset_root"], *(e["example_id"] for e in EXAMPLES)):
        assert ei.key_id_of(identifier) == AVAILABLE["key_id"]


def test_public_digest_is_accepted_only_as_an_exu1_digest() -> None:
    flagged = copy.deepcopy(AVAILABLE)
    flagged["examples"][0]["public_input_digest"] = ei.compute_public_input_digest("q1")
    assert _errors(IDENTITY_OK, _envelope(flagged)) == []
    flagged["examples"][0]["public_input_digest"] = "exu1:" + "Z" * 64
    assert _errors(IDENTITY_OK, _envelope(flagged))


@pytest.mark.parametrize(
    "reason", ["legacy_version_without_snapshot", "not_yet_computed", "stored_identity_mismatch"]
)
def test_unavailable_identity_validates(reason: str) -> None:
    assert _errors(IDENTITY_OK, _envelope(_unavailable(reason))) == []


def _mutations() -> dict[str, dict[str, Any]]:
    def with_(**changes: Any) -> dict[str, Any]:
        return {**copy.deepcopy(AVAILABLE), **changes}

    def without(key: str) -> dict[str, Any]:
        body = copy.deepcopy(AVAILABLE)
        del body[key]
        return body

    bad_example = copy.deepcopy(AVAILABLE)
    bad_example["examples"][0]["input_text"] = "q1"  # content never leaves the Backend
    other_kid_example = copy.deepcopy(AVAILABLE)
    other_kid_example["examples"][0]["example_id"] = "ex1:k" + "f" * 16 + ":" + "0" * 64
    other_kid_example["examples"][0]["example_version"] = "exv1:k" + "f" * 16
    return {
        "record_state_is_not_part_of_the_hosted_shape": with_(record_state="complete"),
        "inline_members_refused": with_(members=[]),
        "client_submitted_source_refused": with_(members_source="client_submitted"),
        "unknown_status": with_(status="partial"),
        "no_root": without("dataset_root"),
        "no_examples": without("examples"),
        "no_members_ref": without("members_ref"),
        "malformed_members_ref": with_(members_ref="cml_123"),
        "root_with_trailing_newline": with_(dataset_root=AVAILABLE["dataset_root"] + "\n"),
        "uppercase_kid": with_(key_id=AVAILABLE["key_id"].upper()),
        "count_over_safe_integer": with_(total_count=2**53),
        "example_carries_content": bad_example,
        "malformed_example_version": other_kid_example,
    }


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_available_identity_rejections(name: str) -> None:
    assert _errors(IDENTITY_OK, _envelope(_mutations()[name])), name


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            {**_unavailable("not_yet_computed"), "reason": "keys_missing"}, id="unknown_reason"
        ),
        pytest.param(
            {**_unavailable("not_yet_computed"), "dataset_root": AVAILABLE["dataset_root"]},
            id="unavailable_with_a_root",
        ),
        pytest.param(
            {k: v for k, v in _unavailable("not_yet_computed").items() if k != "reason"},
            id="unavailable_without_reason",
        ),
    ],
)
def test_unavailable_identity_rejections(body: dict[str, Any]) -> None:
    assert _errors(IDENTITY_OK, _envelope(body))


def test_identity_is_enveloped() -> None:
    assert _errors(IDENTITY_OK, AVAILABLE)  # bare body refused
    assert _errors(IDENTITY_OK, {"success": True, "data": AVAILABLE})  # message required


# ---------------------------------------------------------------------------
# 4. GET /api/v1/datasets/versions/by-root/{dataset_root}
# ---------------------------------------------------------------------------

BY_ROOT_OK = _response_validator(BY_ROOT, "get", "200")


def test_by_root_response_validates() -> None:
    body = _envelope(
        {
            "dataset_root": MULTISET.root,
            "versions": [VERSION, {**VERSION, "id": "v2", "dataset_id": "ds2"}],
        },
        message="Dataset versions resolved by root",
    )
    assert _errors(BY_ROOT_OK, body) == []


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            {"dataset_root": MULTISET.root, "versions": []}, id="empty_match_is_404_not_200"
        ),
        pytest.param({"dataset_root": "not-a-root", "versions": [VERSION]}, id="malformed_root"),
        pytest.param(
            {
                "dataset_root": MULTISET.root,
                "versions": [{**VERSION, "content_identity": AVAILABLE}],
            },
            id="version_object_stays_closed",
        ),
        pytest.param({"versions": [VERSION]}, id="no_root"),
    ],
)
def test_by_root_rejections(data: dict[str, Any]) -> None:
    assert _errors(BY_ROOT_OK, _envelope(data))


def test_by_root_path_parameter_is_a_multiset_root() -> None:
    (param,) = CATALOG["paths"][BY_ROOT]["get"]["parameters"]
    validator = Draft7Validator(
        {"$id": CATALOG_BASE, "allOf": [param["schema"]]}, registry=_REGISTRY
    )
    assert validator.is_valid(MULTISET.root)
    assert not validator.is_valid("not-a-root")
    assert not validator.is_valid(MULTISET.root + "\n")
    assert set(CATALOG["paths"][BY_ROOT]["get"]["responses"]) == {"200", "400", "401", "403", "404"}


# ---------------------------------------------------------------------------
# 5. PUT /api/v1/datasets/{dataset_id}/public-benchmark
# ---------------------------------------------------------------------------


def test_public_benchmark_request_and_response() -> None:
    request = Draft7Validator(
        json.loads((DATASETS / "dataset_public_benchmark_request_schema.json").read_text("utf-8"))
    )
    assert request.is_valid({"public_benchmark": True})
    assert request.is_valid({"public_benchmark": False})
    for bad in (
        {},
        {"public_benchmark": "yes"},
        {"public_benchmark": 1},
        {"public_benchmark": None},
    ):
        assert not request.is_valid(bad), bad

    ok = _response_validator(PUBLIC_BENCHMARK, "put", "200")
    good = _envelope(
        {"dataset_id": "ds_1", "public_benchmark": True}, message="Dataset public_benchmark updated"
    )
    assert _errors(ok, good) == []
    assert _errors(ok, _envelope({"dataset_id": "ds_1"}))
    assert _errors(
        ok, _envelope({"dataset_id": "ds_1", "public_benchmark": True, "previous": False})
    )

    forbidden = _response_validator(PUBLIC_BENCHMARK, "put", "403")
    assert (
        _errors(
            forbidden,
            {
                "success": False,
                "message": "Only a tenant owner or admin may change public_benchmark",
                "error": "Forbidden",
                "error_code": "FORBIDDEN",
            },
        )
        == []
    )


def test_generic_dataset_writes_cannot_set_the_flag() -> None:
    for write in ("dataset_create_request_schema.json", "dataset_update_request_schema.json"):
        properties = json.loads((DATASETS / write).read_text("utf-8")).get("properties", {})
        assert "public_benchmark" not in properties, write
