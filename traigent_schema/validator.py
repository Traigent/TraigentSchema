# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""
Schema Validator for the Traigent platform.

Provides validation of API requests and JSON data against Traigent schemas.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from jsonschema import Draft7Validator, FormatChecker, ValidationError
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT7

from traigent_schema.utils import ContractName, get_contract_path, get_schemas_dir

logger = logging.getLogger(__name__)
SCHEMA_ID_BASE = "https://schemas.traigent.ai/"
# Fallback base for caller-supplied schemas that have no usable absolute ``$id``.
# Inline endpoint schemas use a catalog-relative variant recorded at load time.
_INLINE_SCHEMA_BASE_ID = f"{SCHEMA_ID_BASE}__inline_request_schema__"

UnknownEndpointPolicy = Literal["strict", "warn", "allow"]
_UNKNOWN_ENDPOINT_POLICIES: tuple[UnknownEndpointPolicy, ...] = ("strict", "warn", "allow")
_DEFAULT_UNKNOWN_ENDPOINT_POLICY: UnknownEndpointPolicy = "warn"
_UNKNOWN_ENDPOINT_POLICY_ENV_VAR = "TRAIGENT_SCHEMA_UNKNOWN_ENDPOINT_POLICY"
# Prefix on the placeholder message returned in "warn" mode so callers can
# tell "not validated" apart from "validated and found zero errors" without
# relying on emptiness alone.
UNVALIDATED_ENDPOINT_MARKER = "UNVALIDATED_ENDPOINT"


class UnvalidatedEndpointError(RuntimeError):
    """Raised by :meth:`SchemaValidator.validate_request` when no schema is
    registered for the requested endpoint/method and the validator's
    ``unknown_endpoint_policy`` is ``"strict"``.

    Production Safety Rule 1 requires policy surfaces to fail closed: a
    request against an endpoint with no registered contract must not
    silently pass validation. Callers that need the historical permissive
    behaviour must opt in explicitly via ``unknown_endpoint_policy="allow"``.
    """


_RFC3339_DATE_TIME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[Tt]"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d+)?"
    r"(?P<tz>[Zz]|[+-]\d{2}:\d{2})$"
)
_FORMAT_CHECKER = FormatChecker()


@_FORMAT_CHECKER.checks("date-time")
def _is_rfc3339_date_time(value: object) -> bool:
    """Enforce Traigent's RFC-3339 subset without optional jsonschema extras."""
    if not isinstance(value, str):
        return True

    match = _RFC3339_DATE_TIME_RE.fullmatch(value)
    if match is None:
        return False

    if match.group("time").endswith(":60"):
        # Leap seconds stay out of contract until we add full RFC-3339 support.
        return False

    fraction = match.group("fraction") or ""
    if fraction:
        # datetime.fromisoformat accepts at most 6 fractional digits.
        fraction = "." + fraction[1:7]

    timezone = match.group("tz")
    if timezone in {"Z", "z"}:
        timezone = "+00:00"
    normalized = f"{match.group('date')}T{match.group('time')}{fraction}{timezone}"
    try:
        datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return True


def _load_canonical_public_key(value: object) -> object | None:
    """Decode a canonical public-key SPKI, without echoing key material."""
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization

    if not isinstance(value, str):
        return None
    try:
        der = base64.b64decode(value, validate=True)
        if base64.b64encode(der).decode("ascii") != value:
            return None
        key = serialization.load_der_public_key(der)
        canonical = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (ValueError, TypeError, IndexError, UnsupportedAlgorithm):
        return None
    if canonical != der:
        return None
    return key


@_FORMAT_CHECKER.checks("canonical-spki-der-base64")
def _is_canonical_spki_der_base64(value: object) -> bool:
    """Reject private-key DER and non-SPKI/non-canonical public material."""
    return _load_canonical_public_key(value) is not None


@_FORMAT_CHECKER.checks("canonical-ed25519-spki-der-base64")
def _is_canonical_ed25519_spki_der_base64(value: object) -> bool:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = _load_canonical_public_key(value)
    return isinstance(key, ed25519.Ed25519PublicKey)


@_FORMAT_CHECKER.checks("canonical-ecdsa-p256-spki-der-base64")
def _is_canonical_ecdsa_p256_spki_der_base64(value: object) -> bool:
    from cryptography.hazmat.primitives.asymmetric import ec

    key = _load_canonical_public_key(value)
    return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)


class SchemaValidator:
    """
    Validates API requests and JSON data against Traigent schemas.

    This class loads all schemas on initialization and provides methods
    for validating requests against the appropriate schema based on
    endpoint and method.

    Example:
        validator = SchemaValidator()
        errors = validator.validate_request('/api/v1/agents', 'POST', data)
        if errors:
            print(f"Validation failed: {errors}")
    """

    _RECURSION_ERROR_MESSAGE = (
        "Validation error: input nesting is too deep to validate "
        "(exceeded the interpreter recursion limit); rejected as malformed. "
        "Bound the nesting depth of recursive structures (e.g. observation children)."
    )

    def __init__(
        self,
        contract: ContractName = "backend",
        unknown_endpoint_policy: UnknownEndpointPolicy | None = None,
    ):
        """Initialize the validator with all available schemas.

        Args:
            contract: Endpoint contract catalog to load.
            unknown_endpoint_policy: What :meth:`validate_request` does when
                the endpoint/method pair has no registered schema (neither a
                ``$ref`` nor an inline request schema):

                - ``"strict"``: raise :class:`UnvalidatedEndpointError`.
                - ``"warn"`` (default): log a warning and return a
                  non-empty, distinguishable placeholder message (prefixed
                  with :data:`UNVALIDATED_ENDPOINT_MARKER`) instead of an
                  empty list, so callers can't mistake "not validated" for
                  "validated and clean".
                - ``"allow"``: return ``[]``, matching the historical
                  fail-open behaviour. Must be opted into explicitly.

                Resolution order: this argument, then the
                ``TRAIGENT_SCHEMA_UNKNOWN_ENDPOINT_POLICY`` environment
                variable, then ``"warn"``.
        """
        self.contract = contract
        self.unknown_endpoint_policy = self._resolve_unknown_endpoint_policy(
            unknown_endpoint_policy
        )
        self._schemas: dict[str, dict[str, Any]] = {}
        self._endpoint_schemas: dict[str, str] = {}
        self._inline_request_schemas: dict[str, dict[str, Any]] = {}
        self._inline_request_schema_base_ids: dict[str, str] = {}
        # Every "{METHOD}:{path}" pair present in the loaded OpenAPI contract,
        # regardless of whether it declares a JSON request body. Lets
        # validate_request tell "this route is known but structurally has no
        # body to validate (e.g. GET)" apart from "this route isn't in the
        # contract at all" -- only the latter is the unknown_endpoint_policy
        # gap; the former has nothing to validate under any policy.
        self._known_endpoints: set[str] = set()
        self._registry: Registry | None = None
        self._load_schemas()
        self._load_endpoint_mappings()

    @staticmethod
    def _resolve_unknown_endpoint_policy(
        explicit: UnknownEndpointPolicy | None,
    ) -> UnknownEndpointPolicy:
        """Resolve the unknown-endpoint policy: argument, then env var, then default."""
        candidate: str | None = explicit
        if candidate is None:
            candidate = os.environ.get(_UNKNOWN_ENDPOINT_POLICY_ENV_VAR)
        if candidate is None:
            return _DEFAULT_UNKNOWN_ENDPOINT_POLICY
        if candidate not in _UNKNOWN_ENDPOINT_POLICIES:
            valid_policies = ", ".join(_UNKNOWN_ENDPOINT_POLICIES)
            raise ValueError(
                f"Unknown unknown_endpoint_policy {candidate!r}; "
                f"expected one of: {valid_policies}"
            )
        return candidate  # type: ignore[return-value]

    @staticmethod
    def _resolve_package_relative_path(base_dir: Path, relative_path: str) -> Path | None:
        """Resolve an OpenAPI module path without allowing directory escape."""
        raw_path = Path(relative_path)
        if raw_path.is_absolute():
            return None

        base_root = base_dir.resolve()
        resolved_path = (base_dir / raw_path).resolve()
        if not resolved_path.is_relative_to(base_root):
            return None

        return resolved_path

    def _load_schemas(self) -> None:
        """Load all schema files into memory."""
        schemas_dir = get_schemas_dir()

        for schema_file in schemas_dir.rglob("*.json"):
            if "_endpoints" in schema_file.name:
                continue  # Skip endpoint definition files

            try:
                with open(schema_file, encoding='utf-8') as f:
                    schema = json.load(f)
                    if "$id" not in schema:
                        relative_path = schema_file.relative_to(schemas_dir).as_posix()
                        schema["$id"] = f"{SCHEMA_ID_BASE}{relative_path}"
                    schema_name = schema_file.stem
                    self._schemas[schema_name] = schema
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to load schema file %s: %s", schema_file, exc)

        self._build_registry()

    def _build_registry(self) -> None:
        """Build a jsonschema Registry for reference resolution."""
        resources: list[tuple[str, Resource[dict[str, Any]]]] = []
        for _name, schema in self._schemas.items():
            if "$id" in schema:
                resource: Resource[dict[str, Any]] = Resource.from_contents(schema)
                resources.append((schema["$id"], resource))

        self._registry = Registry().with_resources(resources)

    def _load_endpoint_mappings(self) -> None:
        """Load endpoint-to-schema mappings from OpenAPI spec."""
        try:
            openapi_path = get_contract_path(self.contract)
            if not openapi_path.exists():
                logger.warning(
                    "OpenAPI contract root %s does not exist for contract %s",
                    openapi_path,
                    self.contract,
                )
                return

            with open(openapi_path, encoding='utf-8') as f:
                openapi = json.load(f)

            self._parse_openapi(openapi, openapi_path)
            self._load_endpoint_modules(openapi, openapi_path.parent)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "Failed to load OpenAPI contract root for %s: %s",
                self.contract,
                exc,
            )

    def _load_endpoint_modules(
        self,
        openapi: dict[str, Any],
        base_dir: Path,
    ) -> None:
        """Load endpoint mappings from module files referenced by the root spec."""
        for module in openapi.get("x-endpoint-modules", []):
            if not isinstance(module, dict):
                continue

            paths_file = module.get("paths_file")
            if not isinstance(paths_file, str):
                continue

            module_path = self._resolve_package_relative_path(base_dir, paths_file)
            if module_path is None:
                logger.warning(
                    "OpenAPI endpoint module %r referenced by contract %s escapes %s",
                    paths_file,
                    self.contract,
                    base_dir,
                )
                continue

            if not module_path.exists():
                logger.warning(
                    "OpenAPI endpoint module %s referenced by contract %s does not exist",
                    module_path,
                    self.contract,
                )
                continue

            try:
                with open(module_path, encoding="utf-8") as f:
                    module_openapi = json.load(f)
                    self._parse_openapi(module_openapi, module_path)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to load endpoint module %s: %s", module_path, exc)
                continue

    def _parse_openapi(
        self,
        openapi: dict[str, Any],
        catalog_path: Path | None = None,
    ) -> None:
        """Parse OpenAPI spec to extract endpoint-schema mappings."""
        catalog_dir = ""
        if catalog_path is not None:
            try:
                relative_parent = catalog_path.parent.relative_to(get_schemas_dir())
                catalog_dir = relative_parent.as_posix()
                if catalog_dir == ".":
                    catalog_dir = ""
            except ValueError:
                logger.warning(
                    "Endpoint catalog %s is outside the schema root; inline refs use root base",
                    catalog_path,
                )
        inline_base_id = (
            f"{SCHEMA_ID_BASE}{catalog_dir}/__inline_request_schema__"
            if catalog_dir
            else _INLINE_SCHEMA_BASE_ID
        )
        paths = openapi.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, spec in methods.items():
                if not isinstance(spec, dict):
                    continue
                request_body = spec.get("requestBody", {})
                content = request_body.get("content", {})
                json_content = content.get("application/json", {})
                json_schema = json_content.get("schema", {})
                schema_ref = json_schema.get("$ref", "")
                key = f"{method.upper()}:{path}"
                self._known_endpoints.add(key)

                if schema_ref:
                    schema_name = schema_ref.split("/")[-1]
                    if schema_name.endswith(".json"):
                        schema_name = schema_name[:-5]
                    self._endpoint_schemas[key] = schema_name
                elif isinstance(json_schema, dict) and json_schema:
                    self._inline_request_schemas[key] = json_schema
                    self._inline_request_schema_base_ids[key] = inline_base_id

    def validate_request(
        self,
        endpoint: str,
        method: str,
        data: dict[str, Any]
    ) -> list[str]:
        """
        Validate a request against the schema for the given endpoint.

        Args:
            endpoint: API endpoint path (e.g., '/api/v1/agents')
            method: HTTP method (e.g., 'POST')
            data: Request body data to validate

        Returns:
            List of validation error messages. Empty if valid.

        Raises:
            UnvalidatedEndpointError: If no schema is registered for this
                endpoint/method and ``unknown_endpoint_policy`` is
                ``"strict"``.
        """
        endpoint = self._normalize_endpoint(method, endpoint)
        key = f"{method.upper()}:{endpoint}"
        schema_name = self._endpoint_schemas.get(key)
        inline_schema = self._inline_request_schemas.get(key)

        if not schema_name and not inline_schema:
            if key in self._known_endpoints:
                # Known route (e.g. a GET with no request body) that
                # structurally has nothing to validate -- not a policy gap.
                return []
            return self._handle_unmapped_endpoint(method, endpoint)

        if inline_schema:
            return self._validate_inline_schema(
                data,
                inline_schema,
                self._inline_request_schema_base_ids.get(key, _INLINE_SCHEMA_BASE_ID),
            )

        if schema_name is None:
            return [f"Schema not found for endpoint: {method.upper()} {endpoint}"]
        return self.validate_json(data, schema_name)

    def _handle_unmapped_endpoint(self, method: str, endpoint: str) -> list[str]:
        """Apply ``unknown_endpoint_policy`` when no schema is registered.

        This is the branch that historically returned ``[]``
        unconditionally, which is indistinguishable from "validated and
        found no errors" -- a fail-open policy surface. Production Safety
        Rule 1 requires policy surfaces to fail closed, so an unregistered
        endpoint must never silently pass without someone explicitly
        choosing that outcome (``unknown_endpoint_policy="allow"``).
        """
        key_desc = f"{method.upper()} {endpoint}"

        if self.unknown_endpoint_policy == "strict":
            raise UnvalidatedEndpointError(
                f"No schema registered for {key_desc}; validate_request() "
                "cannot validate this request under the 'strict' "
                "unknown_endpoint_policy. Register a schema for this "
                "endpoint, or construct SchemaValidator with "
                "unknown_endpoint_policy='warn' or 'allow' if bypassing "
                "validation here is intentional."
            )

        if self.unknown_endpoint_policy == "warn":
            logger.warning(
                "No schema registered for %s; validate_request() did not "
                "validate this request (unknown_endpoint_policy=warn). "
                "Register a schema for this endpoint, or set "
                "unknown_endpoint_policy='allow' to silence this warning.",
                key_desc,
            )
            return [
                f"{UNVALIDATED_ENDPOINT_MARKER}: no schema registered for "
                f"{key_desc}; request was NOT validated "
                "(unknown_endpoint_policy=warn)"
            ]

        # "allow": explicit opt-in to the historical fail-open behaviour.
        return []

    @staticmethod
    def _template_matches_endpoint(template: str, endpoint: str) -> bool:
        """Match OpenAPI path templates without compiling dynamic regexes."""
        template_parts = template.split("/")
        endpoint_parts = endpoint.split("/")
        if len(template_parts) != len(endpoint_parts):
            return False

        for template_part, endpoint_part in zip(
            template_parts, endpoint_parts, strict=True
        ):
            if template_part.startswith("{") and template_part.endswith("}"):
                if not endpoint_part:
                    return False
                continue
            if template_part != endpoint_part:
                return False

        return True

    def _normalize_endpoint(self, method: str, endpoint: str) -> str:
        """Normalize concrete paths to OpenAPI path templates before lookup."""
        direct_key = f"{method.upper()}:{endpoint}"
        if (
            direct_key in self._endpoint_schemas
            or direct_key in self._inline_request_schemas
            or direct_key in self._known_endpoints
        ):
            return endpoint

        candidate_keys: set[str] = (
            set(self._endpoint_schemas)
            | set(self._inline_request_schemas)
            | self._known_endpoints
        )
        for candidate_key in candidate_keys:
            candidate_method, candidate_path = candidate_key.split(":", 1)
            if candidate_method != method.upper():
                continue
            if self._template_matches_endpoint(candidate_path, endpoint):
                return candidate_path

        return endpoint

    def validate_json(
        self,
        data: dict[str, Any],
        schema_name: str
    ) -> list[str]:
        """
        Validate JSON data against a named schema.

        Args:
            data: Data to validate
            schema_name: Name of the schema to validate against

        Returns:
            List of validation error messages. Empty if valid.
        """
        schema = self._schemas.get(schema_name)
        if not schema:
            # Try with _schema suffix
            schema = self._schemas.get(f"{schema_name}_schema")

        if not schema:
            return [f"Schema not found: {schema_name}"]

        return self._run_validator(data, schema)

    def _run_validator(
        self,
        data: dict[str, Any],
        schema: dict[str, Any],
        base_uri: str | None = None,
    ) -> list[str]:
        """Run a Draft7 validator over ``data`` against ``schema``.

        Shared validation body for :meth:`validate_json` and
        :meth:`_validate_inline_schema`: builds the registry/format-checker
        aware validator, collects errors, and maps recursion / unexpected
        failures to stable messages.

        The validator is anchored on the schema's own ``$id`` (see
        :meth:`_anchored_validator`) so that relative ``$ref``s resolve. Passing
        the schema dict straight to ``Draft7Validator`` leaves the resolver with an
        empty base URI, which makes every ``./x.json`` and ``../x.json`` reference
        in the library unresolvable.
        """
        try:
            validator = self._anchored_validator(schema, base_uri=base_uri)
            errors = list(validator.iter_errors(data))
            return [self._format_error(e) for e in errors]
        except RecursionError:
            return [self._RECURSION_ERROR_MESSAGE]
        except Unresolvable as e:
            # A dangling reference is a broken contract, not a property of the
            # payload. Say so, instead of letting it read as "this data is invalid"
            # -- that laundering is what hid the empty-base-URI bug in the first
            # place, because every affected schema reported a plausible-looking
            # per-payload validation error.
            return [f"Schema reference error (contract defect, not payload): {e}"]
        except Exception as e:
            return [f"Validation error: {str(e)}"]

    def _anchored_validator(
        self,
        schema: dict[str, Any],
        base_uri: str | None = None,
    ) -> Draft7Validator:
        """Build a validator whose resolver knows where ``schema`` lives.

        Relative ``$ref``s are resolved against the base URI of the referring
        schema. ``Draft7Validator(schema, registry=...)`` does not derive that base
        from ``$id``, so the reference target is looked up under an empty base and
        raises ``Unresolvable``. Validating through a ``$ref`` to the schema's
        registered ``$id`` instead makes resolution start *inside* that resource,
        which is where the relative refs are written to resolve from.
        """
        schema_id = schema.get("$id")

        if isinstance(schema_id, str) and urlsplit(schema_id).scheme:
            # Register the actual object passed to this call, even when its $id
            # matches a schema loaded during initialization. Tests and callers use
            # _run_validator with deliberately mutated schema copies; resolving the
            # $id only through the original registry would silently validate the
            # pristine copy instead of the supplied contract.
            registry = self._registry or Registry()
            anchored_resource: Resource[dict[str, Any]] = DRAFT7.create_resource(schema)
            return Draft7Validator(
                {"$ref": schema_id},
                registry=registry.with_resource(schema_id, anchored_resource),
                format_checker=_FORMAT_CHECKER,
            )

        # Inline request schemas have no absolute $id of their own. Anchor each
        # endpoint schema at the directory of the catalog that declared it; a
        # caller-supplied schema without catalog provenance falls back to the
        # schemas root. A relative/non-URI $id must not override that usable base.
        anchor_id = base_uri or _INLINE_SCHEMA_BASE_ID
        registry = self._registry or Registry()
        inline_resource: Resource[dict[str, Any]] = DRAFT7.create_resource(schema)
        return Draft7Validator(
            {"$ref": anchor_id},
            registry=registry.with_resource(anchor_id, inline_resource),
            format_checker=_FORMAT_CHECKER,
        )

    def _validate_inline_schema(
        self,
        data: dict[str, Any],
        schema: dict[str, Any],
        base_uri: str,
    ) -> list[str]:
        """Validate JSON data against an inline request schema."""
        return self._run_validator(data, schema, base_uri=base_uri)

    def _format_error(self, error: ValidationError) -> str:
        """Format a validation error into a readable message."""
        path = ".".join(str(p) for p in error.absolute_path) or "root"
        if error.validator == "format" and str(error.validator_value).startswith(
            "canonical-"
        ):
            return f"{path}: invalid public-key encoding"
        return f"{path}: {error.message}"

    @property
    def available_schemas(self) -> list[str]:
        """Get list of available schema names."""
        return list(self._schemas.keys())
