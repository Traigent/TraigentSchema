# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the economics recommendation calculator (WI-C): the closed
characterization submission request and the backend-authoritative recommendation
response.

Like the WI-B telemetry tests, these are mostly ADVERSARIAL: each submits the
payload a motivated agent would send to get an inflated or dishonest
recommendation — a value shipped for a field the sharing policy withheld, an
inferred band with no evidence, a payback claimed on a losing lower bound, a
credit/pricing input smuggled into the request — and asserts the contract
rejects it. The positive cases (and the shipped offline fixtures) prove the
strictness did not also reject an honest submission or recommendation.

Invariants JSON Schema cannot enforce (tenant ownership from context, budget
floor<=recommended<=cap ordering, that the boolean flags reflect the real signs)
are NOT proven here; they are asserted to be DECLARED as backend obligations so
the backend packet inherits a visible list rather than an assumption.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy

from traigent_schema import SchemaValidator, load_schema
from traigent_schema.utils import get_schema_path, get_schemas_dir

ECON = get_schemas_dir() / "economics"
FIXTURES = get_schemas_dir().parent.parent / "tests" / "test_data" / "economics"

REQUEST = "economics_recommendation_request_schema"
RESPONSE = "economics_recommendation_response_schema"
ENDPOINT = "/api/v1/economics/recommendation"


def _v() -> SchemaValidator:
    return SchemaValidator(contract="planned_projects")


def _load(name: str) -> dict:
    with open(ECON / name, encoding="utf-8") as fh:
        return json.load(fh)


def _load_fixture(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as fh:
        return json.load(fh)


def _ok(payload: dict, schema: str) -> bool:
    return _v().validate_json(payload, schema) == []


def _rejected(payload: dict, schema: str) -> bool:
    return _v().validate_json(payload, schema) != []


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
def _report(field: str, **extra) -> dict:
    report = {
        "field": field,
        "provenance": "asked",
        "confidence": 1.0,
        "sharing_outcome": "shared",
    }
    report.update(extra)
    return report


def _request(**extra) -> dict:
    """A minimal, honest submission: two asked bands, both allowlisted and shared."""
    event = {
        "contract": "economics_recommendation",
        "contract_version": "1.0.0",
        "request_id": "econrec-req-1",
        "submitted_at": "2026-07-18T09:00:00Z",
        "source": {"kind": "coding_agent", "name": "coding-agent", "version": "1.4.2"},
        "characterization": {
            "bands": {
                "value_channel": "save_expert_time",
                "error_cost_band": "human_correction_1_to_50_usd",
            },
            "field_reports": [
                _report("value_channel"),
                _report("error_cost_band"),
            ],
            "asked_count": 2,
        },
        "sharing_policy": {
            "policy_version": "sharing-policy-v0",
            "allowlist": ["value_channel", "error_cost_band"],
        },
    }
    event.update(extra)
    return event


def _interval(**extra) -> dict:
    interval = {"estimate": 640.0, "lower": 168.0, "upper": 1120.0, "level": 0.9, "unit": "usd"}
    interval.update(extra)
    return interval


def _response(**extra) -> dict:
    event = {
        "contract": "economics_recommendation",
        "contract_version": "1.0.0",
        "request_id": "econrec-req-1",
        "computed_at": "2026-07-18T09:00:01Z",
        "formula_identity": {
            "formula_version": "econ-formula-v0",
            "assumption_set_version": "econ-assumptions-v0",
            "assumptions_are_starting_assumptions": True,
            "published_reference": "econ-formula-doc-v0",
        },
        "archetype": "solo_coding_builder",
        "dominant_value_channel": "save_expert_time",
        "budget": {
            "recommended_daily_usd": 12.0,
            "floor_usd": 5.0,
            "cap_usd": 50.0,
            "floor_cap_are_starting_assumptions": True,
            "basis": {
                "method": "clamp_floor_cap_fraction_of_conservative_realized_value",
                "uses_conservative_lower_bound": True,
                "value_lower_bound": _interval(),
            },
        },
        "payback": {
            "is_lower_bound_positive": True,
            "payback_days": 4.2,
            "conservative_daily_realized_value_usd": 12.0,
            "explanation": [
                {"component": "avoided_bad_promotion_payback", "usd_value": 100.0,
                 "number_value": 1.2, "unit": "count", "emphasis": "lower_bound"},
            ],
        },
        "stop_rule": {"rule": "continue_while_evsi_plus_lower_bound_exceeds_next_cost"},
        "required_receipt": {"receipt_kind": "winner"},
        "spend_zero_case": {
            "available": True,
            "explanation": [{"component": "spend_zero_always_available"}],
        },
        "why": [
            {"component": "conservative_lower_bound_leads", "emphasis": "lower_bound"},
            {"component": "assumptions_are_starting_not_validated"},
        ],
    }
    event.update(extra)
    return event


# --------------------------------------------------------------------------- #
# wiring / posture
# --------------------------------------------------------------------------- #
def test_route_binds_the_recommendation_request_schema() -> None:
    validator = _v()
    assert validator._endpoint_schemas.get(f"POST:{ENDPOINT}") == REQUEST, (
        "the recommendation route must resolve through SchemaValidator, not fail open"
    )
    assert validator.validate_request(ENDPOINT, "POST", _request()) == []
    assert validator.validate_request(ENDPOINT, "POST", {}) != []


def test_route_is_not_claimed_as_canonical_backend_truth() -> None:
    """Contract-first honesty: no backend serves this yet, so it must not sit in
    the canonical `backend` root (which means 'current backend truth')."""
    assert (
        SchemaValidator(contract="backend")._endpoint_schemas.get(f"POST:{ENDPOINT}") is None
    )
    catalog = _load("economics_endpoints.json")
    assert catalog["x-stability"] == "pre-release"
    assert catalog["x-asserted-against-backend"] is False


def test_endpoint_documents_success_auth_validation_and_unavailable() -> None:
    op = _load("economics_endpoints.json")["paths"][ENDPOINT]["post"]
    responses = set(op["responses"])
    # 200 success, 401/403 auth, 400/422 validation, 503 unavailable
    assert {"200", "400", "401", "403", "422", "503"} <= responses
    assert op["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "economics_recommendation_request_schema.json"
    )
    assert responses_200_ref(op).endswith("economics_recommendation_response_schema.json")


def responses_200_ref(op: dict) -> str:
    return op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]


def test_every_error_status_binds_the_shared_error_envelope() -> None:
    """Every documented non-2xx status carries a body schema, and it is the same
    shared envelope the sibling telemetry route binds (#343, `01f3e2a`). This is a
    contract-first SPECIFICATION, not a verified observation: no backend serves this
    route yet (`x-asserted-against-backend: false`), so this pins what the service
    must return rather than what it does return. A bare description with no schema —
    the gap #343 closed next door — fails here."""
    responses = _load("economics_endpoints.json")["paths"][ENDPOINT]["post"]["responses"]
    for status in ("400", "401", "403", "422", "503"):
        ref = responses[status]["content"]["application/json"]["schema"]["$ref"]
        assert ref == "../error_envelope_schema.json", (
            f"{status} must $ref ../error_envelope_schema.json exactly, got {ref!r}"
        )


def test_the_route_documents_exactly_the_expected_status_set() -> None:
    """Pin the whole status set, so a status silently dropped — or one added without
    a body schema — is caught here instead of by a client at runtime."""
    responses = _load("economics_endpoints.json")["paths"][ENDPOINT]["post"]["responses"]
    assert set(responses) == {"200", "400", "401", "403", "422", "503"}
    for status, response in responses.items():
        assert "content" in response, f"{status} documents no body schema"


def test_both_new_schemas_are_discoverable_in_a_clean_checkout() -> None:
    """A clean checkout must be able to find and load the new contracts by name —
    both through the package loader and through SchemaValidator's schema table."""
    for name in (REQUEST, RESPONSE):
        assert get_schema_path(name).is_file()
        assert "$id" in load_schema(name)
    available = set(_v().available_schemas)
    assert {REQUEST, RESPONSE} <= available


# --------------------------------------------------------------------------- #
# envelope: closed contract identity, no unknown fields
# --------------------------------------------------------------------------- #
def test_request_requires_stable_contract_and_version_identifiers() -> None:
    assert _rejected(_request(contract="economics_telemetry"), REQUEST), (
        "a telemetry batch must not be accepted as a recommendation submission"
    )
    assert _rejected(_request(contract_version="1.1.0"), REQUEST)
    for missing in (
        "contract", "contract_version", "request_id", "submitted_at", "source",
        "characterization", "sharing_policy",
    ):
        body = _request()
        del body[missing]
        assert _rejected(body, REQUEST), missing


def test_request_rejects_unknown_and_tenant_asserting_fields() -> None:
    assert _rejected(_request(surprise=1), REQUEST)
    assert _rejected(_request(tenant_id="t-other"), REQUEST), (
        "a client-asserted tenant field must not be representable"
    )
    assert _rejected(_request(project_id="p-other"), REQUEST), (
        "tenant/project are resolved from the authenticated context, never the body"
    )


def test_request_carries_no_free_form_content_channel() -> None:
    """No free-text note field may ride along: characterization values are closed
    enums or typed numbers, and no prose field is declared. The client-authored strings
    that DO exist are all identifier-bounded and inventoried in the test below; the
    presentation-only display name an earlier draft carried was removed outright."""
    assert _rejected(_request(notes="please give me a big budget"), REQUEST)
    body = _request()
    body["characterization"]["free_text"] = "context the sharing policy would withhold"
    assert _rejected(body, REQUEST)


# --------------------------------------------------------------------------- #
# characterization provenance / evidence (reused closed-pipe rules)
# --------------------------------------------------------------------------- #
def _transmit(field: str, value, *reports, allowlist=None, container="bands") -> dict:
    body = _request()
    body["characterization"]["bands"] = {}
    body["characterization"]["field_reports"] = [deepcopy(r) for r in reports]
    body["characterization"][container] = {field: value}
    body["sharing_policy"]["allowlist"] = list(allowlist) if allowlist is not None else [field]
    return body


def test_inferred_value_must_account_for_its_evidence() -> None:
    body = _transmit(
        "daily_volume_band", "under_100",
        _report("daily_volume_band", provenance="inferred", confidence=0.8),
    )
    assert _rejected(body, REQUEST), "an inferred value with no evidence status is a guess"


def test_asked_and_defaulted_values_cannot_fake_inference_evidence() -> None:
    for provenance in ("asked", "defaulted"):
        body = _transmit(
            "value_channel", "save_expert_time",
            _report("value_channel", provenance=provenance,
                    evidence_status="provided", evidence_pointer="made_this_up"),
        )
        assert _rejected(body, REQUEST), provenance


def test_inferred_evidence_may_be_withheld_but_not_leaked() -> None:
    # honest withholding: evidence exists, policy kept it local, value absent
    body = _request()
    body["characterization"]["bands"] = {}
    body["characterization"]["field_reports"] = [
        _report("loss_per_bad_output_usd", provenance="inferred", confidence=0.5,
                sharing_outcome="withheld_by_policy", evidence_status="withheld_by_policy"),
    ]
    body["sharing_policy"]["allowlist"] = []
    assert _ok(body, REQUEST)
    # the pointer must not ride along on a withheld field
    body["characterization"]["field_reports"][0]["evidence_pointer"] = (
        "incident_ledger_median_escalation"
    )
    assert _rejected(body, REQUEST)


def test_every_report_must_state_its_confidence() -> None:
    body = _transmit("value_channel", "save_expert_time", _report("value_channel"))
    assert _ok(body, REQUEST)
    del body["characterization"]["field_reports"][0]["confidence"]
    assert _rejected(body, REQUEST), "confidence is required on every report"


# --------------------------------------------------------------------------- #
# structural sharing policy: withholding is structural, allowlist gates egress
# --------------------------------------------------------------------------- #
def test_a_withheld_field_cannot_ship_its_value() -> None:
    """The closed-pipe promise: 'withheld_by_policy' must mean the value did not
    leave the machine — declaring a field withheld while shipping its value is
    unrepresentable (reused from the WI-B telemetry rule)."""
    body = _transmit(
        "lifecycle_stage", "full_production_we_pay",
        _report("lifecycle_stage", sharing_outcome="withheld_by_policy"),
        allowlist=["lifecycle_stage"],
    )
    assert _rejected(body, REQUEST)


def test_a_transmitted_value_must_be_on_the_sharing_allowlist() -> None:
    """The NEW structural sharing-policy binding: a value present in the transmitted
    area REQUIRES its field on the allowlist. A value for a non-allowlisted field is
    unrepresentable, not a policy bug caught downstream — that is what makes
    withholding structural rather than advisory."""
    # value transmitted, field NOT on the allowlist -> rejected
    off_allowlist = _transmit(
        "value_channel", "save_expert_time", _report("value_channel"), allowlist=[]
    )
    assert _rejected(off_allowlist, REQUEST), "a value off the sharing allowlist must not egress"
    # ... and adding the field to the allowlist makes the same payload honest
    on_allowlist = _transmit(
        "value_channel", "save_expert_time", _report("value_channel"),
        allowlist=["value_channel"],
    )
    assert _ok(on_allowlist, REQUEST)


def test_the_allowlist_binding_covers_overrides_not_only_bands() -> None:
    off = _transmit(
        "observed_daily_volume", 80,
        _report("observed_daily_volume", provenance="inferred", confidence=0.8,
                evidence_status="provided", evidence_pointer="traces_14d_count"),
        allowlist=[], container="overrides",
    )
    assert _rejected(off, REQUEST), "a transmitted override off the allowlist must be rejected"
    on = _transmit(
        "observed_daily_volume", 80,
        _report("observed_daily_volume", provenance="inferred", confidence=0.8,
                evidence_status="provided", evidence_pointer="traces_14d_count"),
        allowlist=["observed_daily_volume"], container="overrides",
    )
    assert _ok(on, REQUEST)


def test_every_vocabulary_field_is_allowlist_gated_not_just_the_sampled_ones() -> None:
    """The schema writes one allOf gate per characterization field by hand, so a
    missing or mistyped gate is invisible to a spot check of two fields. Drive the
    whole vocabulary from the vocabulary itself: for each of the ten fields, a value
    transmitted with an empty allowlist must be rejected and the same value with the
    field allowlisted must be accepted. Deleting any single gate fails here."""
    vocab = load_schema("economics_characterization_vocabulary_schema")["definitions"]
    bands = vocab["CharacterizationBands"]["properties"]
    overrides = vocab["CharacterizationOverrides"]["properties"]
    all_fields = set(vocab["CharacterizationFieldName"]["enum"])
    assert all_fields == set(bands) | set(overrides), (
        "vocabulary drift: the allowlist names and the transmittable containers "
        "must describe the same ten fields"
    )

    def _first_enum_member(prop: dict) -> str:
        """Resolve a band property's local $ref to its enum and take a member, so the
        test tracks the vocabulary instead of hard-coding values that could drift."""
        target = prop["$ref"].rsplit("/", 1)[-1]
        return vocab[target]["enum"][0]

    for field in sorted(all_fields):
        container = "bands" if field in bands else "overrides"
        value = _first_enum_member(bands[field]) if container == "bands" else 42
        report = _report(field, provenance="asked", confidence=1.0, sharing_outcome="shared")
        off = _transmit(field, value, report, allowlist=[], container=container)
        assert _rejected(off, REQUEST), f"{field}: transmitted off-allowlist was accepted"
        on = _transmit(field, value, report, allowlist=[field], container=container)
        assert _ok(on, REQUEST), f"{field}: honest allowlisted transmission was rejected"


def test_an_empty_allowlist_all_withheld_submission_is_honest() -> None:
    """Withholding everything is representable: the client shares nothing, every
    determined field is reported withheld_by_policy, and the recommendation still
    returns the spend-$0 case. The shipped fixture is the worked example."""
    assert _ok(_load_fixture("recommendation_request_all_withheld.json"), REQUEST)


def test_allowlist_is_bounded_and_drawn_from_the_vocabulary() -> None:
    body = _request()
    body["sharing_policy"]["allowlist"] = ["not_a_real_field"]
    assert _rejected(body, REQUEST), "the allowlist is drawn from the closed field vocabulary"
    body = _request()
    body["sharing_policy"]["allowlist"] = ["value_channel", "value_channel", "error_cost_band"]
    assert _rejected(body, REQUEST), "the allowlist must be unique"


def test_sharing_policy_requires_a_version_and_an_allowlist() -> None:
    for field in ("policy_version", "allowlist"):
        body = _request()
        del body["sharing_policy"][field]
        assert _rejected(body, REQUEST), field


# --------------------------------------------------------------------------- #
# no presentation channel; evidence pointers are opaque
# --------------------------------------------------------------------------- #
def test_the_request_carries_no_presentation_string_at_all() -> None:
    """An earlier draft carried an 80-character `agent_display_name` and claimed a
    bounded, control-character-free string 'cannot become a free-text egress
    channel'. Eighty printable characters carry prose, so the claim was false and the
    field was removed rather than re-worded. Nothing replaced it: the agent renders
    the response from structured tokens on its own machine."""
    schema = _load(f"{REQUEST}.json")
    assert "agent_display_name" not in schema["properties"]
    assert _rejected(_request(agent_display_name="your QA agent"), REQUEST), (
        "additionalProperties:false must make a display name unrepresentable"
    )
    assert _rejected(_request(display_name="anything"), REQUEST)
    obligations = " ".join(schema["x-backend-obligations"])
    assert "NO PRESENTATION CHANNEL" in obligations


# Object/array-shaping keywords: a node carrying one of these is a container to
# descend into, never a string leaf.
_STRUCTURAL_KEYWORDS = (
    "properties", "items", "additionalProperties", "patternProperties",
    "required", "if", "then", "else", "propertyNames", "not", "contains",
    "dependencies", "minItems", "maxItems", "uniqueItems", "minProperties",
    "maxProperties",
)

# The request's COMPLETE content-capable string surface: every path a client both
# authors and bounds only by an identifier grammar, which admits `Alice.Smith.SSN.123`
# as readily as `gpt-4o-mini`. Terra round 5 disproved the tidier story this started
# as ("the only client-authored string is the evidence pointer") — it was simply
# false, and counting exceptions was the wrong frame. This inventory is the honest
# one, and it is what the contract's wording and its redaction obligation must both
# match. A new entry means a new content-capable channel and demands a deliberate
# decision; a removed entry means someone tightened a grammar and should say so.
EXPECTED_CLIENT_AUTHORED_STRING_PATHS = {
    "request_id",                                    # agent-generated join key
    "source.name",                                   # emitting surface name
    "source.version",                                # emitting surface version
    "sharing_policy.policy_version",                 # client policy label
    "characterization.sharing_policy_version",       # the same label inside telemetry
    "characterization.field_reports[].evidence_pointer",  # narrowed by the request overlay
}

def _free_text_paths(schema: dict) -> set[str]:
    """Every path under `schema` at which an arbitrary string can be sent.

    Deliberately structural, not annotation-driven: an earlier version of this guard
    only looked for `x-content: true`, which any new prose field could simply omit —
    it called itself general while catching nothing.

    A node counts as admitting a string when it has no `const`/`enum`, no pattern
    beyond a trivially permissive one, and a type that includes `string` (a type LIST
    containing "string" counts). `allOf` intersects, so one constraining branch is
    enough; `anyOf`/`oneOf` unite, so EVERY branch must constrain. Traversal covers
    `properties`, `items`, `additionalProperties`, and the combinators, at any depth
    and across files.

    Three limits, stated rather than implied, because this test's whole purpose is to
    not overclaim:
    1. It does NOT compose intersections across sibling overlays. A field constrained
       only by an allOf overlay elsewhere in the document is still reported here —
       which is exactly why `EXPECTED_CLIENT_AUTHORED_STRING_PATHS` is an explicit set
       rather than an assertion of emptiness.
    2. Object/array applicator keywords (`required`, `minItems`, …) are treated as
       evidence that a node shapes a container rather than a string. JSON Schema
       technically ignores them for string instances, so this is a heuristic; it
       holds here because every declared object in this contract is closed, which
       the scan itself now checks (an `additionalProperties`-less declared object is
       reported as an open channel).
    3. `$ref` cycles stop at the first repeat and fail CLOSED — an unresolvable ref is
       reported as free text rather than skipped. `format` and `maxLength` are not
       treated as content constraints, because neither bounds which characters may be
       sent.
    """
    # A pattern counts as constraining only if it actually REJECTS prose. Terra
    # bypassed an earlier allowlist-of-trivial-patterns version with
    # `^.{1,80}$` — non-trivial to look at, wide open in practice. So probe it:
    # if any of these representative prose/PII strings satisfies the pattern, the
    # field can carry free text no matter how clever the regex looks.
    prose_probes = (
        "Alice Smith SSN 123-45-6789",
        'he said "we lose $4k a day"',
        "alice@customer.example",
        "traces show ~3.1k runs/day",
        "line one\nline two",
        # Identifier-SHAPED PII. Terra round 5: without these, every field bounded
        # only by the repo's identifier grammar reads as "constrained" while it can
        # still carry a name and a number. A field that accepts these is a
        # content-capable channel and belongs in the inventory below.
        "Alice.Smith.SSN.123-45-6789",
        "Alice_Smith_SSN_123-45-6789",
        # Lowercase prose with spaces and nothing else. A pattern like
        # `^[a-z ]{1,80}$` rejects every probe above while accepting sentences,
        # so without this the scan would call it constrained.
        "we lose about four thousand a day on bad answers",
        "0123456789 0123456789 0123456789",
    )

    def pattern_admits_prose(pattern: str) -> bool:
        try:
            compiled = re.compile(pattern)
        except re.error:
            return True  # unparseable here: assume the worst rather than skip
        return any(compiled.search(probe) for probe in prose_probes)

    def deref(node: dict, doc: dict, seen: frozenset) -> tuple[dict, dict, frozenset] | None:
        """Resolve a $ref against the document it appears IN — a local `#/definitions/X`
        inside a referenced file must resolve in that file, not in the request."""
        ref = node["$ref"]
        file_part, _, frag = ref.partition("#")
        key = (doc.get("$id", ""), ref) if not file_part else ref
        if key in seen:
            return None
        target_doc = doc if not file_part else _load(file_part.lstrip("./"))
        target = target_doc
        for part in [p for p in frag.split("/") if p]:
            target = target[part]
        return target, target_doc, seen | {key}

    def admits_string(node: dict, doc: dict, seen: frozenset) -> bool:
        """True if an arbitrary string can satisfy this node."""
        if "$ref" in node:
            resolved = deref(node, doc, seen)
            return True if resolved is None else admits_string(*resolved)
        if any(k in node for k in ("const", "enum")):
            return False
        pattern = node.get("pattern")
        if pattern is not None and not pattern_admits_prose(pattern):
            return False
        types = node.get("type")
        types = [types] if isinstance(types, str) else types
        if types is not None:
            # A type LIST including "string" still admits a string (the
            # ["string", "null"] case that slipped past the first version).
            if "string" not in types:
                return False
        elif any(k in node for k in _STRUCTURAL_KEYWORDS):
            # An untyped node that shapes an object/array is a container to descend
            # into, not a string leaf. (An untyped node with nothing at all DOES
            # admit a string, and is reported.)
            return False
        # allOf intersects: constrained if ANY branch constrains.
        if any(not admits_string(sub, doc, seen) for sub in node.get("allOf", [])):
            return False
        # anyOf/oneOf unions: one free-text branch is enough to admit free text,
        # so this is only constrained when EVERY branch is.
        for key in ("anyOf", "oneOf"):
            branches = node.get(key)
            if branches and all(not admits_string(sub, doc, seen) for sub in branches):
                return False
        return True

    found: set[str] = set()

    def walk(node: dict, doc: dict, path: str, seen: frozenset) -> None:
        if "$ref" in node:
            resolved = deref(node, doc, seen)
            if resolved is None:
                found.add(path)  # unresolvable cycle: fail closed
                return
            walk(resolved[0], resolved[1], path, resolved[2])
            return
        if admits_string(node, doc, seen):
            found.add(path)
            return
        for sub in (s for key in ("allOf", "anyOf", "oneOf") for s in node.get(key, [])):
            walk(sub, doc, path, seen)
        for name, prop in (node.get("properties") or {}).items():
            walk(prop, doc, f"{path}.{name}" if path else name, seen)
        extra = node.get("additionalProperties")
        if isinstance(extra, dict):
            walk(extra, doc, f"{path}.*", seen)
        elif extra is not False and node.get("type") == "object":
            # A DECLARED object that is absent `additionalProperties` (or sets it
            # true) accepts arbitrary extra members, and a string is one of them.
            # Restricted to declared objects on purpose: an allOf overlay carries
            # `properties` without a type and cannot widen the closed base it
            # intersects, so flagging those would be noise, not a finding.
            found.add(f"{path}.* (open object)")
        for name, sub in (node.get("patternProperties") or {}).items():
            walk(sub, doc, f"{path}.<{name}>", seen)
        for name, sub in (node.get("dependencies") or {}).items():
            if isinstance(sub, dict):
                walk(sub, doc, f"{path}.{name}?", seen)
        if isinstance(node.get("propertyNames"), dict):
            walk(node["propertyNames"], doc, f"{path}.<names>", seen)
        # `if` / `then` / `else` / `not` / `contains` are deliberately NOT traversed.
        # They are predicates and restrictions: against a closed object they can
        # reject payloads but never make a new member acceptable, so they add no
        # string channel. Walking them produced false positives — e.g. the
        # `contains` matcher that detects a withheld report is a declared object
        # without `additionalProperties: false`, and nothing is ever validated
        # against it as a payload shape.
        items = node.get("items")
        if isinstance(items, dict):
            walk(items, doc, f"{path}[]", seen)

    walk(schema, schema, "", frozenset())
    return found


def test_the_redaction_obligation_names_every_content_capable_string() -> None:
    """The inventory and the obligation must not drift apart: a backend implementer
    reads the obligation, not this test file, so every path the scan finds has to be
    named there by the field a reader would recognize."""
    obligations = _load(f"{REQUEST}.json")["x-backend-obligations"]
    # Each path must be named in an obligation that ITSELF requires redaction.
    # Joining every obligation into one string and then looking for "redact"
    # anywhere passed even with redaction removed from five of the six fields,
    # because the separate evidence-pointer obligation still contained the word.
    redacting = [o for o in obligations if "redact" in o.lower()]
    assert redacting, "no obligation requires redaction at all"
    for path in EXPECTED_CLIENT_AUTHORED_STRING_PATHS:
        # Full path, not the leaf: "version" alone appears throughout the text, so
        # leaf matching passed while `source.version` had been deleted.
        assert any(f"`{path}`" in o for o in redacting), (
            f"{path} is not covered by any obligation that requires redaction"
        )


def test_the_content_capable_string_surface_is_exactly_the_documented_inventory() -> None:
    """The set of paths a client can fill with content of its choosing must be
    exactly the documented inventory — nothing else, at any depth.

    Catches a re-added prose field whatever it is named, including every shape that
    slipped past earlier versions of this guard: `["string", "null"]`,
    `pattern: ".*"`, the deceptively-narrow `pattern: "^.{1,80}$"`, an anyOf with one
    free branch, a nested object or array of unconstrained strings, an
    additionalProperties string map, patternProperties, propertyNames, and a declared
    object that forgot `additionalProperties: false`."""
    assert _free_text_paths(_load(f"{REQUEST}.json")) == EXPECTED_CLIENT_AUTHORED_STRING_PATHS


def _pointer_request(pointer: str) -> dict:
    """A minimal valid request whose single inferred field carries `pointer`."""
    req = _request()
    req["characterization"]["field_reports"] = [
        {
            "field": "value_channel",
            "provenance": "inferred",
            "confidence": 0.8,
            "sharing_outcome": "shared",
            "evidence_status": "provided",
            "evidence_pointer": pointer,
        }
    ]
    req["characterization"]["bands"] = {"value_channel": "save_expert_time"}
    req["sharing_policy"]["allowlist"] = ["value_channel"]
    return req


def test_evidence_pointers_cannot_carry_sentence_shaped_text() -> None:
    """The shared WI-B EvidencePointer admits 280 characters of free text. Inside THIS
    request it is intersected with the repo's opaque-identifier grammar, which rejects
    whitespace, quotes, at-signs, non-ASCII, and control characters — so a copied
    sentence or an email address is unrepresentable.

    Scoped deliberately: the assertion is about SENTENCE-shaped text, not about PII in
    general. See the companion residual test for what this does NOT stop."""
    assert _ok(_pointer_request("traces_14d_count_mean"), REQUEST)
    for leak in (
        "traces show ~3.1k runs/day over 14 days",
        "Alice Smith SSN 123-45-6789",
        "alice@customer.example",
        "loss per bad output = $4000",
        'customer said "we lose 4k a day"',
        "runs_per_day_3100\n",
    ):
        assert _rejected(_pointer_request(leak), REQUEST), f"prose accepted: {leak!r}"


def test_the_pointer_narrowing_bounds_the_channel_and_does_not_seal_it() -> None:
    """Honesty check on the fix itself, and the reason the contract must not claim
    'PII is unrepresentable'. The identifier grammar permits `.`, `_`, `:`, `/`, `+`
    and `-` between alphanumerics, so an underscore-joined name or amount is a VALID
    token — including one belonging to a field the client reported withheld. No schema
    can detect that. These payloads are asserted to VALIDATE so the residual stays
    visible: if someone later narrows the grammar, this test fails and they must
    update the contract's wording to match, instead of the wording quietly drifting
    ahead of what is enforced."""
    for still_valid in (
        "loss_per_bad_output_4000",
        "Alice_Smith_SSN_123-45-6789",
    ):
        assert _ok(_pointer_request(still_valid), REQUEST), (
            f"{still_valid!r} SHOULD validate — this documents the residual channel"
        )
    obligations = " ".join(_load(f"{REQUEST}.json")["x-backend-obligations"])
    assert "EVIDENCE POINTERS ARE OPAQUE, NOT SEALED" in obligations
    assert "redact" in obligations.lower()
    assert "does NOT make PII or values unrepresentable" in obligations, (
        "the obligation must state the residual in the same words the test proves"
    )


def test_no_presentation_field_is_a_telemetry_characterization_field() -> None:
    """The WI-B telemetry contract could never carry a display name either: it is not
    an allowlisted CharacterizationFieldName. Kept as a regression guard on the
    vocabulary, now that the request has no such field at all."""
    vocab = load_schema("economics_characterization_vocabulary_schema")
    allowlist = set(vocab["definitions"]["CharacterizationFieldName"]["enum"])
    assert "agent_display_name" not in allowlist
    assert "display_name" not in allowlist


# --------------------------------------------------------------------------- #
# response: formula identity, budget, payback, stop, receipt, spend-$0, why
# --------------------------------------------------------------------------- #
def test_response_requires_the_whole_recommendation_record() -> None:
    for field in (
        "contract", "contract_version", "request_id", "computed_at", "formula_identity",
        "archetype", "dominant_value_channel", "budget", "payback", "stop_rule",
        "required_receipt", "spend_zero_case", "why",
    ):
        body = _response()
        del body[field]
        assert _rejected(body, RESPONSE), f"{field}: an incomplete recommendation is not valid"


def test_response_carries_versioned_formula_and_assumption_identity() -> None:
    for field in (
        "formula_version", "assumption_set_version", "assumptions_are_starting_assumptions",
        "published_reference",
    ):
        body = _response()
        del body["formula_identity"][field]
        assert _rejected(body, RESPONSE), field


def test_assumptions_are_labelled_starting_not_validated() -> None:
    """Every dollar figure is a starting assumption. The label is a required const
    true, so a recommendation cannot drop it or set it false to imply validation."""
    body = _response()
    body["formula_identity"]["assumptions_are_starting_assumptions"] = False
    assert _rejected(body, RESPONSE), "the starting-assumption label cannot be set false"


def test_no_why_component_can_claim_an_assumption_was_validated() -> None:
    components = set(
        _load(f"{RESPONSE}.json")["definitions"]["WhyComponent"]["properties"]["component"]["enum"]
    )
    assert "assumptions_are_starting_not_validated" in components
    assert not any("validated" in c and c != "assumptions_are_starting_not_validated"
                   for c in components), "no render token may claim assumptions are validated"
    body = _response()
    body["why"][0] = {"component": "assumptions_validated"}
    assert _rejected(body, RESPONSE), "a 'validated' render token must be unrepresentable"


def test_budget_leads_with_a_conservative_lower_bound() -> None:
    for field in ("recommended_daily_usd", "floor_usd", "cap_usd",
                  "floor_cap_are_starting_assumptions", "basis"):
        body = _response()
        del body["budget"][field]
        assert _rejected(body, RESPONSE), field
    # the conservative-lower-bound label is a required const true
    body = _response()
    body["budget"]["basis"]["uses_conservative_lower_bound"] = False
    assert _rejected(body, RESPONSE)
    # the value interval must carry its level, so a point estimate cannot pose as a bound
    body = _response()
    del body["budget"]["basis"]["value_lower_bound"]["level"]
    assert _rejected(body, RESPONSE)


def test_budget_floor_and_cap_are_labelled_starting_assumptions_not_funding() -> None:
    body = _response()
    body["budget"]["floor_cap_are_starting_assumptions"] = False
    assert _rejected(body, RESPONSE), "the floor/cap starting-assumption label cannot be set false"


def test_payback_is_only_claimed_on_a_positive_lower_bound() -> None:
    # positive lower bound: payback_days required and allowed
    assert _ok(_response(), RESPONSE)
    body = _response()
    del body["payback"]["payback_days"]
    assert _rejected(body, RESPONSE), "a positive lower bound must state its payback_days"
    # non-positive lower bound: payback_days FORBIDDEN, spend-$0 leads
    body = _response()
    body["payback"] = {
        "is_lower_bound_positive": False,
        "conservative_daily_realized_value_usd": -4.3,
        "explanation": [{"component": "spend_zero_always_available"}],
    }
    assert _ok(body, RESPONSE), "a non-positive lower bound is a valid, honest recommendation"
    body["payback"]["payback_days"] = 4.2
    assert _rejected(body, RESPONSE), "payback must not be claimed on a non-positive lower bound"


def test_payback_daily_value_is_signed() -> None:
    body = _response()
    body["payback"] = {
        "is_lower_bound_positive": False,
        "conservative_daily_realized_value_usd": -12.5,
        "explanation": [{"component": "conservative_lower_bound_leads", "emphasis": "lower_bound"}],
    }
    assert _ok(body, RESPONSE), "the conservative daily value may legitimately be negative"


def test_payback_explanation_is_structured_not_free_form() -> None:
    body = _response()
    body["payback"]["explanation"] = "one avoided bad promotion pays for two weeks"
    assert _rejected(body, RESPONSE), "the payback explanation is structured tokens, not prose"
    body = _response()
    body["payback"]["explanation"][0]["prose"] = "free text"
    assert _rejected(body, RESPONSE), "a render token carries no free-text field"


def test_spend_zero_case_is_always_present_and_available() -> None:
    body = _response()
    del body["spend_zero_case"]
    assert _rejected(body, RESPONSE), "the spend-$0 case is required on every recommendation"
    body = _response()
    body["spend_zero_case"]["available"] = False
    assert _rejected(body, RESPONSE), "the spend-$0 option can never be disabled"


def test_why_is_required_non_empty_and_bounded() -> None:
    body = _response()
    body["why"] = []
    assert _rejected(body, RESPONSE), "the explanation duty means why cannot be empty"
    body = _response()
    body["why"] = [{"component": "conservative_lower_bound_leads"} for _ in range(25)]
    assert _rejected(body, RESPONSE), "why is bounded"


def test_why_components_are_a_closed_vocabulary_referencing_user_fields() -> None:
    body = _response()
    body["why"][0] = {"component": "give_us_your_money"}
    assert _rejected(body, RESPONSE), "the why vocabulary is closed"
    # a render token may reference the user's OWN characterization field (closed enum)
    body = _response()
    body["why"][0] = {
        "component": "daily_volume_drives_scale", "references_field": "daily_volume_band",
    }
    assert _ok(body, RESPONSE)
    body["why"][0]["references_field"] = "internal_revenue_forecast"
    assert _rejected(body, RESPONSE), "references_field is drawn from the closed field allowlist"


def test_stop_rule_and_required_receipt_are_closed() -> None:
    body = _response()
    body["stop_rule"]["rule"] = "keep_spending"
    assert _rejected(body, RESPONSE)
    body = _response()
    body["required_receipt"]["receipt_kind"] = "vibes"
    assert _rejected(body, RESPONSE), "the required receipt kind reuses the closed receipt enum"


def test_required_receipt_reuses_the_receipt_contract_enum() -> None:
    """The recommendation and the receipt it requires must not drift: the kind enum
    is reused by $ref from the receipt contract, not restated."""
    resp = _load(f"{RESPONSE}.json")
    ref = resp["definitions"]["RequiredReceipt"]["properties"]["receipt_kind"]["allOf"][0]["$ref"]
    assert ref == "./economics_receipt_event_schema.json#/properties/receipt_kind"
    receipt = _load("economics_receipt_event_schema.json")
    assert receipt["properties"]["receipt_kind"]["enum"] == ["winner", "defect", "savings"]


def test_response_dominant_channel_reuses_the_vocabulary() -> None:
    body = _response()
    body["dominant_value_channel"] = "make_money_fast"
    assert _rejected(body, RESPONSE), "the value channel is the closed vocabulary enum"


# --------------------------------------------------------------------------- #
# money is finite, bounded, and correctly signed
# --------------------------------------------------------------------------- #
def test_response_money_is_finite_nonnegative_and_bounded() -> None:
    body = _response()
    body["budget"]["recommended_daily_usd"] = -1
    assert _rejected(body, RESPONSE), "a negative recommended budget is not representable"
    body = _response()
    body["budget"]["cap_usd"] = 1e12
    assert _rejected(body, RESPONSE), "an unbounded cap is not representable"
    body = _response()
    body["budget"]["floor_usd"] = "5"
    assert _rejected(body, RESPONSE), "money is a number, not a string"
    body = _response()
    body["payback"]["payback_days"] = 1e9
    assert _rejected(body, RESPONSE), "payback_days is bounded"


# --------------------------------------------------------------------------- #
# WI-D boundary: no credit / incentive / pricing / wallet / dollar-gate surface
# --------------------------------------------------------------------------- #
_FORBIDDEN_TOKENS = (
    "credit", "incentive", "grant", "promo", "wallet", "billing", "coupon",
    "discount", "dollar_gate", "sales", "price", "pricing", "funding", "voucher",
    "balance", "subscription", "invoice", "charge", "quota",
)


def _property_names(schema: dict, *, follow_refs: bool = True) -> set[str]:
    """Property names declared anywhere in `schema`, INCLUDING through `$ref`.

    The ref-following matters: this request imports its whole characterization
    shape by reference, so a scan that stopped at the local document would have
    declared the WI-D boundary clean without ever looking at the imported fields.
    """
    names: set[str] = set()
    seen_refs: set[str] = set()

    def walk(node: object, doc: dict) -> None:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if follow_refs and isinstance(ref, str) and ref not in seen_refs:
                seen_refs.add(ref)
                file_part, _, frag = ref.partition("#")
                try:
                    target_doc = doc if not file_part else _load(file_part.lstrip("./"))
                    target = target_doc
                    for part in [x for x in frag.split("/") if x]:
                        target = target[part]
                except (KeyError, FileNotFoundError):  # pragma: no cover - fails loudly below
                    raise AssertionError(f"unresolvable $ref while scanning: {ref}") from None
                walk(target, target_doc)
            props = node.get("properties")
            if isinstance(props, dict):
                names.update(props)
            for value in node.values():
                walk(value, doc)
        elif isinstance(node, list):
            for value in node:
                walk(value, doc)

    walk(schema, schema)
    return names


def test_no_credit_incentive_or_pricing_field_is_declared_anywhere() -> None:
    """WI-D boundary: credit/incentive/funding and pricing/wallet/billing are OUT of
    scope. Neither contract may declare such a field; the recommendation cannot be a
    function of state it cannot carry."""
    for schema_name in (REQUEST, RESPONSE):
        names = _property_names(_load(f"{schema_name}.json"))
        offenders = {n for n in names if any(tok in n for tok in _FORBIDDEN_TOKENS)}
        assert not offenders, f"{schema_name}: forbidden WI-D/pricing field(s): {offenders}"


def test_credit_and_pricing_inputs_are_unrepresentable_in_the_request() -> None:
    for field in ("credit_backed", "credit_usd", "incentive", "wallet_balance_usd",
                  "pricing_discount", "dollar_gate"):
        assert _rejected(_request(**{field: True}), REQUEST), field
        body = _request()
        body["sharing_policy"][field] = True
        assert _rejected(body, REQUEST), f"sharing_policy.{field}"


def test_credit_and_pricing_fields_are_unrepresentable_in_the_response() -> None:
    for field in ("credit_backed", "credit_usd", "incentive_usd", "wallet_balance_usd",
                  "sales_incentive", "dollar_gate", "promotional_balance_usd"):
        assert _rejected(_response(**{field: 1}), RESPONSE), field
        body = _response()
        body["budget"][field] = 1
        assert _rejected(body, RESPONSE), f"budget.{field}"


def test_no_evidence_gym_or_runtime_field_leaks_into_the_contract() -> None:
    """WI-D also folds dollar gates / adherence arms into the Evidence Gym program.
    None of that runtime vocabulary belongs in this pre-release calculator contract."""
    for name in (REQUEST, RESPONSE):
        blob = json.dumps(_load(f"{name}.json")).lower()
        for token in ("evidence_gym", "dollar_gate", "credit_backed"):
            assert token not in blob, f"{name}: unexpected WI-D token {token!r}"


# --------------------------------------------------------------------------- #
# reuse: vocabulary + common by $ref, no restated enums/bounds
# --------------------------------------------------------------------------- #
def test_request_reuses_vocabulary_and_telemetry_by_ref_not_restatement() -> None:
    """The submission references the closed vocabulary and the WI-B characterization
    machinery rather than restating enums/bounds, so the closed pipe cannot drift."""
    req = _load(f"{REQUEST}.json")
    blob = json.dumps(req)
    assert "economics_characterization_vocabulary_schema.json" in blob
    assert "CharacterizationFieldName" in blob
    assert "economics_run_event_schema.json#/definitions/CharacterizationTelemetry" in blob
    # the band enum members are NOT restated in the request file itself
    assert "save_expert_time" not in blob, "value-channel enum members must not be restated"
    assert "under_100" not in blob, "volume-band enum members must not be restated"


def test_response_reuses_common_and_vocabulary_by_ref() -> None:
    resp = _load(f"{RESPONSE}.json")
    blob = json.dumps(resp)
    assert "economics_common_schema.json#/definitions/ConfidenceInterval" in blob
    assert "economics_common_schema.json#/definitions/UsdAmount" in blob
    assert "economics_characterization_vocabulary_schema.json#/definitions/ValueChannel" in blob
    # archetype enum members are not restated here
    assert "solo_coding_builder" not in blob, "archetype enum members must not be restated"


# --------------------------------------------------------------------------- #
# deterministic offline fixtures: same request/response shapes, no computation
# --------------------------------------------------------------------------- #
def test_offline_fixture_vectors_validate_against_the_contracts() -> None:
    request_fixtures = [
        "recommendation_request_solo_builder.json",
        "recommendation_request_support_automation.json",
        "recommendation_request_all_withheld.json",
    ]
    response_fixtures = [
        "recommendation_response_solo_builder.json",
        "recommendation_response_support_automation.json",
        "recommendation_response_spend_zero.json",
    ]
    for name in request_fixtures:
        payload = _load_fixture(name)
        assert _ok(payload, REQUEST), name
        assert _v().validate_request(ENDPOINT, "POST", payload) == [], name
    for name in response_fixtures:
        assert _ok(_load_fixture(name), RESPONSE), name


def test_offline_fixture_pairs_share_request_ids_without_recomputing() -> None:
    """The fixtures are canonical request/response SHAPES paired by request_id. They
    are schema-valid EXAMPLES, not conformance evidence: no backend and no offline
    path exists yet, so nothing is claimed to agree with them. They embody no
    computation — the pairing is by echoed id, not a recomputed value."""
    pairs = [
        ("recommendation_request_solo_builder.json", "recommendation_response_solo_builder.json"),
        ("recommendation_request_support_automation.json",
         "recommendation_response_support_automation.json"),
        ("recommendation_request_all_withheld.json", "recommendation_response_spend_zero.json"),
    ]
    for req_name, resp_name in pairs:
        req = _load_fixture(req_name)
        resp = _load_fixture(resp_name)
        assert req["request_id"] == resp["request_id"], (req_name, resp_name)
        # every response leads with the spend-$0 case and a starting-assumption label
        assert resp["spend_zero_case"]["available"] is True
        assert resp["formula_identity"]["assumptions_are_starting_assumptions"] is True


def test_the_all_withheld_pair_leads_with_spend_zero_and_no_payback() -> None:
    resp = _load_fixture("recommendation_response_spend_zero.json")
    assert resp["payback"]["is_lower_bound_positive"] is False
    assert "payback_days" not in resp["payback"], "no payback on a non-positive lower bound"
    assert resp["budget"]["basis"]["method"] == "spend_zero_no_positive_lower_bound"


# --------------------------------------------------------------------------- #
# honesty: what the contract does NOT prove
# --------------------------------------------------------------------------- #
def test_the_value_interval_must_be_denominated_in_dollars() -> None:
    """The budget is a dollar amount derived from this interval, but the shared
    ConfidenceInterval also admits `tokens`, `seconds`, and `count`. Without pinning
    the unit, a token-denominated interval is a schema-valid basis for a USD budget.
    Ordering (lower <= estimate <= upper) cannot be expressed in JSON Schema and is
    carried as an obligation instead — asserted as declared, not as enforced."""
    body = _response()
    assert _ok(body, RESPONSE)
    for wrong_unit in ("tokens", "seconds", "count"):
        body = _response()
        body["budget"]["basis"]["value_lower_bound"]["unit"] = wrong_unit
        assert _rejected(body, RESPONSE), f"a {wrong_unit} interval was accepted as a USD basis"
    inverted = _response()
    inverted["budget"]["basis"]["value_lower_bound"].update({"lower": 900.0, "estimate": 100.0})
    assert _ok(inverted, RESPONSE), (
        "ordering is NOT schema-enforceable; this asserts the honest limit so the "
        "obligation below cannot be quietly dropped as redundant"
    )
    obligations = " ".join(_load(f"{RESPONSE}.json")["x-backend-obligations"])
    assert "VALUE INTERVAL ORDERING" in obligations


def test_unenforceable_invariants_are_declared_as_backend_obligations() -> None:
    request_obligations = " ".join(_load(f"{REQUEST}.json")["x-backend-obligations"])
    for marker in ("TENANT/PROJECT FROM CONTEXT", "SHARING POLICY IS CLIENT-ENFORCED",
                   "NO PRESENTATION CHANNEL", "EVIDENCE POINTERS ARE OPAQUE, NOT SEALED",
                   "CLIENT-AUTHORED STRINGS ARE USER CONTENT", "UNIQUE CHARACTERIZATION FIELDS",
                   "NO PRICING/CREDIT INPUT"):
        assert marker in request_obligations, marker
    response_obligations = " ".join(_load(f"{RESPONSE}.json")["x-backend-obligations"])
    for marker in ("BUDGET ORDERING", "LOWER-BOUND LEADS", "NO PRICING/CREDIT/WALLET INPUT",
                   "PAYBACK ONLY ON A POSITIVE LOWER BOUND", "ASSUMPTIONS ARE NOT VALIDATED",
                   "VALUE INTERVAL ORDERING", "REQUEST ID IS AN ECHO, NOT A NEW ID",
                   "PUBLISHED REFERENCE MUST RESOLVE"):
        assert marker in response_obligations, marker


def test_deep_copy_fixtures_are_independent() -> None:
    first = _request()
    first["characterization"]["field_reports"].clear()
    assert _request()["characterization"]["field_reports"], "fixtures must be fresh"
