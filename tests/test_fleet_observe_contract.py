"""Fleet Observe v1 contracts (fleet_observe domain, TRAIG-179).

Contract-only, additive: identity cluster, independent agent-record fields,
evidence class on evidence records, source-to-class table, spawn-tree stub,
import event, coverage ratio and the identity_conflict finding.
"""

import copy
import json
import re

import jsonschema
import pytest

from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
DOMAIN = S / "fleet_observe"
MAP_PATH = S.parent / "data" / "fleet_observe" / "source_evidence_class_map.json"

CLUSTER = "fleet_observe/identity_cluster_schema.json"
AGENT = "fleet_observe/agent_observation_record_schema.json"
EVIDENCE = "fleet_observe/evidence_record_schema.json"
MAPSCHEMA = "fleet_observe/source_evidence_class_map_schema.json"
SPAWN = "fleet_observe/spawn_tree_schema.json"
IMPORT = "fleet_observe/import_event_schema.json"
COVERAGE = "fleet_observe/coverage_ratio_schema.json"
FINDING = "fleet_observe/finding_schema.json"
COMMON = "fleet_observe/fleet_observe_common_schema.json"
IMPORT_REQUEST = "fleet_observe/import_request_schema.json"
RESPONSES = "fleet_observe/fleet_observe_responses_schema.json"
BUNDLE = "fleet_observe/import_bundle_schema.json"
ENDPOINTS = "fleet_observe/fleet_observe_endpoints.json"
ALL = [
    CLUSTER, AGENT, EVIDENCE, MAPSCHEMA, SPAWN, IMPORT, COVERAGE, FINDING,
    IMPORT_REQUEST, RESPONSES, BUNDLE, ENDPOINTS, COMMON,
]

H = "0" * 32
DIGEST = "sha256:" + "a" * 64
TS = "2026-11-10T09:00:00Z"
BOUNDARY = {"boundary_ref": "boundaryref_" + H, "boundary_kind": "cloud_account"}


def _load(rel):
    return json.loads((S / rel).read_text(encoding="utf-8"))


def _validator(rel):
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    registry = Registry()
    for path in S.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = "https://schemas.traigent.ai/" + path.relative_to(S).as_posix()
        registry = registry.with_resource(
            uri, Resource.from_contents(doc, default_specification=DRAFT7)
        )
    return jsonschema.Draft7Validator(
        _load(rel), registry=registry, format_checker=jsonschema.FormatChecker()
    )


def _ok(rel, body):
    errors = list(_validator(rel).iter_errors(body))
    assert not errors, [e.message for e in errors]


def _bad(rel, body):
    assert list(_validator(rel).iter_errors(body)), "expected a validation error"


def _cluster():
    return {
        "cluster_ref": "clusterref_" + H,
        "cluster_state": "candidate",
        "confidence": "medium",
        "members": [
            {"member_kind": "principal", "member_digest": DIGEST},
            {"member_kind": "credential", "member_digest": "sha256:" + "b" * 64},
        ],
        "agent_ref": None,
        "boundary": BOUNDARY,
        "first_observed_at": TS,
        "last_observed_at": TS,
        "revision": 1,
    }


def _evidence(source="cloud_iam_principal", cls="independent_observed", trust="backend_observed"):
    return {
        "evidence_ref": "evidenceref_" + H,
        "source_kind": source,
        "origin_trust_level": trust,
        "evidence_class": cls,
        "observed_at": TS,
        "boundary": BOUNDARY,
        "retention_class": "evidence_standard",
        "payload_digest": DIGEST,
        "import_event_ref": None,
        "cluster_ref": None,
    }


def _coverage():
    return {
        "coverage_state": "unknown",
        "observed_count": 40,
        "unknown_count": 3,
        "denominator": None,
        "denominator_basis": "internal_import",
        "boundary": BOUNDARY,
        "period_start": TS,
        "period_end": "2026-11-11T09:00:00Z",
    }


def test_every_fleet_observe_document_is_present():
    """Literal path references keep the orphan-schema ratchet (tests/test_schemas.py) honest."""
    schemas_dir = get_schemas_dir()
    assert (schemas_dir / "fleet_observe" / "agent_observation_record_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "coverage_ratio_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "evidence_record_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "finding_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "fleet_observe_common_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "identity_cluster_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "import_event_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "source_evidence_class_map_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "spawn_tree_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "import_request_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "fleet_observe_responses_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "import_bundle_schema.json").is_file()
    assert (schemas_dir / "fleet_observe" / "fleet_observe_endpoints.json").is_file()
    assert len(list(DOMAIN.glob("*.json"))) == 13


@pytest.mark.parametrize("rel", ALL)
def test_documents_are_valid_draft7_schemas(rel):
    jsonschema.Draft7Validator.check_schema(_load(rel))


def test_no_free_text_string_fields():
    """Every string node is enum/const/pattern/format bounded: no free text anywhere."""
    offenders = []

    def walk(node, path):
        if isinstance(node, dict):
            if node.get("type") == "string" and not (
                {"enum", "const", "pattern", "format"} & node.keys()
            ):
                offenders.append(path)
            for k, v in node.items():
                walk(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}/{i}")

    for rel in ALL:
        walk(_load(rel), rel)
    assert not offenders, offenders


@pytest.mark.parametrize("rel", ALL[:-1])
def test_every_object_is_closed(rel):
    def walk(node, path):
        if isinstance(node, dict):
            if node.get("type") == "object" and "properties" in node:
                assert node.get("additionalProperties") is False, path
            for k, v in node.items():
                walk(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}/{i}")

    walk(_load(rel), rel)


def test_out_of_scope_entities_are_absent():
    names = {p.name for p in DOMAIN.glob("*.json")}
    forbidden = ("lineage", "birth", "terminal", "charter", "crew")
    assert not [n for n in names if any(f in n for f in forbidden)]
    text = " ".join(p.read_text(encoding="utf-8") for p in DOMAIN.glob("*.json"))
    assert "charter_ref" not in text and "crew_run_id" not in text


# --- identity cluster -------------------------------------------------------
def test_cluster_valid_and_unknown_state():
    _ok(CLUSTER, _cluster())
    unk = _cluster()
    unk.update(cluster_state="unknown", confidence="unknown")
    _ok(CLUSTER, unk)


def test_cluster_unknown_state_requires_unknown_confidence_and_no_agent():
    c = _cluster()
    c.update(cluster_state="unknown", confidence="high")
    _bad(CLUSTER, c)
    c = _cluster()
    c.update(cluster_state="unknown", confidence="unknown", agent_ref="agentref_" + H)
    _bad(CLUSTER, c)


def test_cluster_candidate_needs_explicit_confidence():
    c = _cluster()
    c["confidence"] = "unknown"
    _bad(CLUSTER, c)


def test_cluster_rejects_names_extras_and_empty_members():
    c = _cluster()
    c["members"][0]["member_digest"] = "Alice_has_diabetes"
    _bad(CLUSTER, c)
    c = _cluster()
    c["display_name"] = "x"
    _bad(CLUSTER, c)
    c = _cluster()
    c["members"] = []
    _bad(CLUSTER, c)
    c = _cluster()
    c["members"][0]["member_kind"] = "agent"
    _bad(CLUSTER, c)


# --- agent record: independent fields ---------------------------------------
def test_agent_fields_are_independent():
    base = {"agent_ref": "agentref_" + H, "cluster_ref": None}
    for prov in ("human_created", "autonomously_created", "unknown"):
        for own in ("owned", "unowned", "unknown"):
            for rev in ("reviewed", "unreviewed", "unknown"):
                _ok(AGENT, {**base, "creation_provenance": prov,
                            "ownership_state": own, "review_state": rev})


def test_agent_autonomous_can_be_owned_and_reviewed_and_unknown_is_required():
    _ok(AGENT, {"agent_ref": "agentref_" + H, "creation_provenance": "autonomously_created",
                "ownership_state": "owned", "review_state": "reviewed"})
    _bad(AGENT, {"agent_ref": "agentref_" + H, "creation_provenance": "autonomously_created",
                 "ownership_state": "owned"})
    _bad(AGENT, {"agent_ref": "agentref_" + H, "creation_provenance": "autonomously_created",
                 "ownership_state": "owned_and_reviewed", "review_state": "reviewed"})


def test_agent_schema_has_no_cross_field_constraint():
    doc = _load(AGENT)
    assert not {"allOf", "oneOf", "anyOf", "if", "then"} & doc.keys()


# --- evidence class ---------------------------------------------------------
def test_evidence_class_enum_is_the_six_classes():
    assert _load(COMMON)["definitions"]["EvidenceClass"]["enum"] == [
        "independent_observed", "self_reported", "lineage_internal",
        "inherited_conditional", "vendor_claimed", "constraint_enforced",
    ]


def test_trust_level_enum_matches_existing_lifecycle_trust_level():
    existing = _load("agent_lifecycle_record/agent_lifecycle_common_schema.json")
    assert (_load(COMMON)["definitions"]["TrustLevel"]["enum"]
            == existing["definitions"]["TrustLevel"]["enum"])


def test_evidence_valid_for_each_mapped_source():
    rows = json.loads(MAP_PATH.read_text(encoding="utf-8"))["rows"]
    for r in rows:
        _ok(EVIDENCE, _evidence(r["source_kind"], r["evidence_class"], r["origin_trust_level"]))


def test_evidence_rejects_class_trust_mismatch():
    _bad(EVIDENCE, _evidence("cloud_iam_principal", "independent_observed", "client_attested"))
    _bad(EVIDENCE, _evidence("sdk_declaration", "self_reported", "server_verified"))
    # a self-report can never be upgraded to independent_observed by its source
    _bad(EVIDENCE, _evidence("sdk_declaration", "independent_observed", "backend_observed"))
    # missing the new class field
    e = _evidence()
    del e["evidence_class"]
    _bad(EVIDENCE, e)
    e = _evidence()
    e["evidence_class"] = "trusted"
    _bad(EVIDENCE, e)


# --- source -> class table --------------------------------------------------
def test_source_map_table_validates_and_covers_every_source_once():
    table = json.loads(MAP_PATH.read_text(encoding="utf-8"))
    _ok(MAPSCHEMA, table)
    kinds = _load(COMMON)["definitions"]["ImportSourceKind"]["enum"]
    assert sorted(r["source_kind"] for r in table["rows"]) == sorted(kinds)
    assert {r["evidence_class"] for r in table["rows"]} == set(
        _load(COMMON)["definitions"]["EvidenceClass"]["enum"]
    )


def test_source_map_table_matches_evidence_schema_conditionals():
    table = {r["source_kind"]: (r["evidence_class"], r["origin_trust_level"])
             for r in json.loads(MAP_PATH.read_text(encoding="utf-8"))["rows"]}
    pinned = {}
    for branch in _load(EVIDENCE)["allOf"]:
        src = branch["if"]["properties"].get("source_kind")
        if src:
            props = branch["then"]["properties"]
            pinned[src["const"]] = (props["evidence_class"]["const"],
                                    props["origin_trust_level"]["const"])
    assert pinned == table


def test_constraint_enforced_is_reserved_in_the_table():
    rows = json.loads(MAP_PATH.read_text(encoding="utf-8"))["rows"]
    enforced = [r for r in rows if r["evidence_class"] == "constraint_enforced"]
    assert enforced and all(r["producer_state"] == "reserved" for r in enforced)
    assert all(r["producer_state"] == "observe_v1" for r in rows if r not in enforced)


# --- spawn tree stub --------------------------------------------------------
def test_spawn_tree_stub():
    ok = {"spawn_tree_ref": "spawntreeref_" + H, "root_cluster_ref": "clusterref_" + H,
          "aggregates_state": "not_computed"}
    _ok(SPAWN, ok)
    _bad(SPAWN, {**ok, "aggregates_state": "computed"})
    _bad(SPAWN, {**ok, "descendant_count": 5})
    _bad(SPAWN, {**ok, "root_cluster_ref": "agentref_" + H})


# --- import event -----------------------------------------------------------
def _import():
    return {"import_event_ref": "importref_" + H, "idempotency_key": DIGEST,
            "source_ref": "sourceref_" + H, "source_kind": "kubernetes_workload",
            "observed_at": TS, "boundary": BOUNDARY, "retention_class": "ledger_minimal",
            "member_count": 12}


def test_import_event_shape():
    _ok(IMPORT, _import())
    for field in ("idempotency_key", "source_ref", "observed_at", "boundary", "retention_class"):
        b = _import()
        del b[field]
        _bad(IMPORT, b)
    b = _import()
    b["idempotency_key"] = "replay-1"
    _bad(IMPORT, b)
    b = _import()
    b["retention_class"] = "forever"
    _bad(IMPORT, b)


# --- coverage ratio ---------------------------------------------------------
def test_coverage_unknown_without_external_denominator():
    _ok(COVERAGE, _coverage())
    c = _coverage()
    c["denominator_basis"] = "none"
    _ok(COVERAGE, c)


def test_coverage_measured_needs_independent_denominator():
    c = _coverage()
    c.update(coverage_state="measured", denominator=50, denominator_basis="independent_inventory")
    _ok(COVERAGE, c)
    c["denominator_basis"] = "internal_import"
    _bad(COVERAGE, c)
    c = _coverage()
    c.update(coverage_state="measured", denominator=None, denominator_basis="independent_inventory")
    _bad(COVERAGE, c)


def test_coverage_unknown_cannot_carry_a_denominator_and_has_no_score():
    c = _coverage()
    c["denominator"] = 50
    _bad(COVERAGE, c)
    c = _coverage()
    c["score"] = 0.8
    _bad(COVERAGE, c)
    c = _coverage()
    del c["denominator"]
    _bad(COVERAGE, c)


# --- finding ----------------------------------------------------------------
def _finding():
    return {"finding_ref": "findingref_" + H, "kind": "identity_conflict",
            "conflict_basis": "credential_shared_across_clusters",
            "cluster_refs": ["clusterref_" + H, "clusterref_" + "1" * 32],
            "detected_at": TS, "finding_state": "open"}


def test_finding_kind_is_limited_to_identity_conflict():
    _ok(FINDING, _finding())
    assert _load(FINDING)["properties"]["kind"]["enum"] == ["identity_conflict"]
    for kind in ("unattributed_principal", "assessment_on_another_release"):
        f = _finding()
        f["kind"] = kind
        _bad(FINDING, f)


def test_finding_carries_no_free_text():
    f = _finding()
    f["summary"] = "two agents share a key"
    _bad(FINDING, f)
    f = copy.deepcopy(_finding())
    f["cluster_refs"] = []
    _bad(FINDING, f)


def test_id_patterns_are_kind_specific():
    pats = [v["pattern"] for k, v in _load(COMMON)["definitions"].items() if k.endswith("Ref")]
    assert len(pats) == len(set(pats))
    assert all(re.fullmatch(r"\^[a-z]+ref_\[0-9a-f\]\{32\}\$", p) for p in pats)


# --- review fixes (terra) ---------------------------------------------------
# Finding 1: appended corrections and invalidations
OLD = "evidenceref_" + "1" * 32


def test_evidence_correct_and_invalidate_reference_the_prior_record():
    _ok(EVIDENCE, _evidence())
    e = _evidence()
    e.update(record_operation="assert", supersedes=None, invalidation_reason=None)
    _ok(EVIDENCE, e)
    e = _evidence()
    e.update(record_operation="correct", supersedes=OLD)
    _ok(EVIDENCE, e)
    e = _evidence()
    e.update(record_operation="invalidate", supersedes=OLD,
             invalidation_reason="model_or_template_changed")
    _ok(EVIDENCE, e)


def test_evidence_correction_without_supersedes_or_reason_is_rejected():
    for op in ("correct", "invalidate"):
        e = _evidence()
        e.update(record_operation=op, invalidation_reason="source_changed")
        _bad(EVIDENCE, e)  # no supersedes
        e["supersedes"] = None
        _bad(EVIDENCE, e)
    e = _evidence()
    e.update(record_operation="invalidate", supersedes=OLD)
    _bad(EVIDENCE, e)  # invalidate needs a reason
    e["invalidation_reason"] = None
    _bad(EVIDENCE, e)
    e["invalidation_reason"] = "because I said so"
    _bad(EVIDENCE, e)  # reason is a closed enum
    e = _evidence()
    e.update(record_operation="correct", supersedes=OLD, invalidation_reason="source_changed")
    _bad(EVIDENCE, e)  # reason only with invalidate
    e = _evidence()
    e.update(record_operation="delete", supersedes=OLD)
    _bad(EVIDENCE, e)
    e = _evidence()
    e["supersedes"] = OLD
    _bad(EVIDENCE, e)  # supersedes without an operation
    e["record_operation"] = "assert"
    _bad(EVIDENCE, e)


# Finding 2: coverage ratio impossible values
def check_coverage_counts(record):
    """Consumer-side check for what draft-07 cannot express (coverage_ratio_schema.json).

    A measured record needs denominator >= 1 and observed_count + unknown_count <=
    denominator. Consumers apply this after schema validation and before computing or
    displaying a ratio. Returns a list of problems (empty means consistent).
    """
    if record.get("coverage_state") != "measured":
        return []
    denominator = record.get("denominator")
    if not isinstance(denominator, int) or denominator < 1:
        return ["denominator must be an integer >= 1"]
    if record["observed_count"] + record["unknown_count"] > denominator:
        return ["observed_count + unknown_count exceeds denominator"]
    return []


def _measured(**kw):
    c = _coverage()
    c.update(coverage_state="measured", denominator_basis="independent_inventory",
             observed_count=40, unknown_count=3, denominator=50)
    c.update(kw)
    return c


def test_coverage_measured_denominator_zero_is_rejected():
    c = _measured(denominator=0)
    _bad(COVERAGE, c)
    assert check_coverage_counts(c)


def test_coverage_counts_above_denominator_are_rejected_by_the_helper():
    c = _measured(denominator=10)
    _ok(COVERAGE, c)  # structurally valid: draft-07 cannot compare fields
    assert check_coverage_counts(c) == ["observed_count + unknown_count exceeds denominator"]
    assert check_coverage_counts(_measured()) == []
    assert check_coverage_counts(_measured(denominator=43)) == []
    assert check_coverage_counts(_coverage()) == []


# Finding 3: source map enforces its own contract
def _table():
    return json.loads(MAP_PATH.read_text(encoding="utf-8"))


def test_source_map_schema_rejects_duplicate_source_and_contradictory_row():
    _ok(MAPSCHEMA, _table())
    t = _table()
    t["rows"][5]["source_kind"] = "otel_trace_export"  # duplicate, sdk_declaration missing
    _bad(MAPSCHEMA, t)
    t = _table()
    t["rows"].append(dict(t["rows"][5], evidence_class="independent_observed",
                          origin_trust_level="backend_observed"))
    _bad(MAPSCHEMA, t)  # contradictory second sdk_declaration row (length too)
    t = _table()
    t["rows"][5].update(evidence_class="independent_observed",
                        origin_trust_level="backend_observed")
    _bad(MAPSCHEMA, t)  # in place contradiction
    t = _table()
    t["rows"][9]["producer_state"] = "observe_v1"
    _bad(MAPSCHEMA, t)


# Finding 4: timestamps
@pytest.mark.parametrize("bad", [
    "2026-99-99T99:99:99Z", "2026-13-01T00:00:00Z", "2026-00-10T00:00:00Z",
    "2026-02-30T00:00:00Z", "2026-04-31T00:00:00Z", "2026-11-10T24:00:00Z",
    "2026-11-10T09:60:00Z", "2026-11-10T09:00:61Z",
])
def test_timestamp_rejects_impossible_calendar_values(bad):
    c = _cluster()
    c["first_observed_at"] = bad
    _bad(CLUSTER, c)


def test_timestamp_accepts_valid_and_format_checker_is_enabled():
    c = _cluster()
    c["first_observed_at"] = "2024-02-29T23:59:59.123456Z"
    _ok(CLUSTER, c)
    assert _validator(CLUSTER).format_checker is not None


# Finding 5: cross-cluster findings name at least two clusters
@pytest.mark.parametrize("basis", ["credential_shared_across_clusters",
                                   "member_in_multiple_clusters"])
def test_cross_cluster_finding_needs_two_clusters(basis):
    f = _finding()
    f["conflict_basis"] = basis
    f["cluster_refs"] = ["clusterref_" + H]
    _bad(FINDING, f)
    f["cluster_refs"].append("clusterref_" + "1" * 32)
    _ok(FINDING, f)


# Finding 6: independent literal per-source expectations (not derived from the map)
PINNED = {
    "cloud_iam_principal": ("independent_observed", "backend_observed", "observe_v1"),
    "credential_inventory": ("independent_observed", "backend_observed", "observe_v1"),
    "kubernetes_workload": ("independent_observed", "backend_observed", "observe_v1"),
    "llm_gateway_log": ("independent_observed", "backend_observed", "observe_v1"),
    "otel_trace_export": ("self_reported", "client_attested", "observe_v1"),
    "sdk_declaration": ("self_reported", "client_attested", "observe_v1"),
    "spawn_parent_report": ("lineage_internal", "client_attested", "observe_v1"),
    "parent_evidence_inherit": ("inherited_conditional", "client_attested", "observe_v1"),
    "vendor_platform_registry": ("vendor_claimed", "client_attested", "observe_v1"),
    "mediated_enforcement_connector": ("constraint_enforced", "server_verified", "reserved"),
}


def test_pinned_expectations_cover_every_source_kind():
    assert sorted(PINNED) == sorted(_load(COMMON)["definitions"]["ImportSourceKind"]["enum"])


@pytest.mark.parametrize("source", sorted(PINNED))
def test_every_source_is_pinned_in_table_and_evidence_schema(source):
    cls, trust, state = PINNED[source]
    row = next(r for r in _table()["rows"] if r["source_kind"] == source)
    got = (row["evidence_class"], row["origin_trust_level"], row["producer_state"])
    assert got == PINNED[source]
    _ok(EVIDENCE, _evidence(source, cls, trust))
    for other_cls in _load(COMMON)["definitions"]["EvidenceClass"]["enum"]:
        for other_trust in _load(COMMON)["definitions"]["TrustLevel"]["enum"]:
            if (other_cls, other_trust) != (cls, trust):
                _bad(EVIDENCE, _evidence(source, other_cls, other_trust))


# --- request, responses, bundle (grounded in the API server) ---------------------------------


def _members():
    return [
        {"member_kind": "principal", "member_digest": DIGEST},
        {
            "member_kind": "credential",
            "member_digest": "sha256:" + "c" * 64,
            "parent_member_digest": DIGEST,
        },
    ]


def _request(**over):
    body = {
        "source_kind": "sdk_declaration",
        "boundary": {"boundary_kind": "repository", "boundary_digest": DIGEST},
        "idempotency_key": DIGEST,
        "observed_at": TS,
        "members": _members(),
    }
    body.update(over)
    return body


def test_import_request_accepts_backend_shape_and_optional_retention():
    _ok(IMPORT_REQUEST, _request())
    _ok(IMPORT_REQUEST, _request(retention_class="legal_hold"))


@pytest.mark.parametrize(
    "bad",
    [
        {"source_kind": "mediated_enforcement_connector"},  # reserved, Backend 400
        {"source_kind": "nope"},
        {"retention_class": "forever"},
        {"observed_at": "2026-11-10T09:00:00+00:00"},  # Backend accepts the Z form only
        {"members": []},
        {"members": [{"member_kind": "agent", "member_digest": DIGEST}]},
        {"members": [{"member_kind": "principal", "member_digest": "Alice_has_diabetes"}]},
        {"members": [{"member_kind": "principal", "member_digest": DIGEST, "name": "x"}]},
        {"extra": 1},
        {"boundary": {"boundary_kind": "repository"}},
        {"boundary": {"boundary_kind": "boundary", "boundary_digest": DIGEST}},
    ],
)
def test_import_request_rejects_what_the_backend_rejects(bad):
    _bad(IMPORT_REQUEST, _request(**bad))


def test_import_request_accepts_an_explicit_null_parent():
    members = _members()
    members[0]["parent_member_digest"] = None
    _ok(IMPORT_REQUEST, _request(members=members))
    members[0]["parent_member_digest"] = "not a digest"
    _bad(IMPORT_REQUEST, _request(members=members))


def test_import_request_rejects_missing_required_and_oversize():
    for key in ("source_kind", "boundary", "idempotency_key", "observed_at", "members"):
        body = _request()
        del body[key]
        _bad(IMPORT_REQUEST, body)
    many = [
        {"member_kind": "principal", "member_digest": "sha256:" + f"{i:064x}"}
        for i in range(5001)
    ]
    _bad(IMPORT_REQUEST, _request(members=many))
    _ok(IMPORT_REQUEST, _request(members=many[:5000]))


def test_import_request_source_kinds_are_the_observe_v1_producers():
    producers = sorted(r["source_kind"] for r in _table()["rows"] if r["producer_state"] == "observe_v1")
    got = sorted(_load(IMPORT_REQUEST)["properties"]["source_kind"]["enum"])
    assert got == producers


def _snapshot():
    return {"import_seq": 3, "as_of": TS}


def _import_view(replayed):
    return {
        "import_event": {
            "import_event_ref": "importref_" + H,
            "idempotency_key": DIGEST,
            "source_ref": "sourceref_" + H,
            "source_kind": "sdk_declaration",
            "observed_at": TS,
            "boundary": BOUNDARY,
            "retention_class": "ledger_minimal",
            "member_count": 2,
        },
        "evidence": {"evidence_class": "self_reported", "origin_trust_level": "client_attested"},
        "outcome": {
            "import_seq": 3,
            "new_cluster_count": 1,
            "changed_cluster_count": 0,
            "unknown_member_count": 0,
            "conflict_count": 0,
        },
        "replayed": replayed,
    }


def _resp(definition, body):
    schema = {"$ref": f"https://schemas.traigent.ai/{RESPONSES}#/definitions/{definition}"}
    base = _validator(RESPONSES)
    validator = jsonschema.Draft7Validator(
        schema, registry=base._registry, format_checker=jsonschema.FormatChecker()
    )
    return list(validator.iter_errors(body))


def _env(message, data):
    return {"success": True, "message": message, "data": data}


def test_import_response_is_the_nested_view_plus_replayed():
    assert not _resp("ImportResponse", _env("Import accepted", _import_view(False)))
    assert not _resp("ImportResponse", _env("Import already accepted", _import_view(True)))
    assert _resp("ImportResponse", _env("Import accepted", _import_view(True)))
    assert _resp("ImportResponse", _env("Import already accepted", _import_view(False)))
    flat = {**_import_view(False)["import_event"], "replayed": False}
    assert _resp("ImportResponse", _env("Import accepted", flat))


def _cluster_summary():
    return {
        "cluster_ref": "clusterref_" + H,
        "cluster_state": "candidate",
        "confidence": "high",
        "agent_ref": None,
        "boundary": BOUNDARY,
        "first_observed_at": TS,
        "last_observed_at": TS,
        "revision": 1,
        "member_count": 2,
    }


def test_cluster_page_detail_coverage_diff_findings_shapes():
    page = {"limit": 50, "next_cursor": None, "has_more": False}
    clusters = {
        "snapshot": _snapshot(),
        "clusters": [_cluster_summary()],
        "page": page,
        "aggregates": {
            "clusters_total": 1,
            "members_total": 2,
            "by_state": {"candidate": 1, "unknown": 0},
            "by_confidence": {"high": 1, "medium": 0, "low": 0, "unknown": 0},
            "matching_total": 1,
        },
        "truncation": {
            "ranked": False,
            "ranked_bound": None,
            "truncated": False,
            "returned_through": 1,
        },
    }
    assert not _resp("ListClustersResponse", _env("Clusters retrieved", clusters))
    cursor = "eyJ2IjoxfQ." + "a" * 32
    clusters["page"] = {"limit": 50, "next_cursor": cursor, "has_more": True}
    assert not _resp("ListClustersResponse", _env("Clusters retrieved", clusters))
    clusters["page"]["next_cursor"] = "not a cursor"
    assert _resp("ListClustersResponse", _env("Clusters retrieved", clusters))

    detail = {
        "snapshot": _snapshot(),
        "cluster": _cluster(),
        "member_count": 2,
        "members_truncated": False,
    }
    assert not _resp("GetClusterResponse", _env("Cluster retrieved", detail))

    coverage = {
        "snapshot": _snapshot(),
        "boundaries": [{"coverage": _coverage(), "internal_import_total": 2}],
        "totals": {"boundaries_total": 1, "observed_count": 2, "unknown_count": 0},
        "truncation": {"truncated": False, "boundary_limit": 200},
        "denominator_note": "internal_import: no independent inventory, so no ratio is claimed",
    }
    assert not _resp("CoverageResponse", _env("Coverage retrieved", coverage))
    coverage["denominator_note"] = "a free text note"
    assert _resp("CoverageResponse", _env("Coverage retrieved", coverage))

    listing = {"total": 1, "cluster_refs": ["clusterref_" + H], "truncated": False}
    diff = {
        "snapshot": _snapshot(),
        "from_import_seq": 2,
        "to_import_seq": 3,
        "imports_in_range": 1,
        "new_clusters": listing,
        "changed_clusters": {"total": 0, "cluster_refs": [], "truncated": False},
        "members_added": 2,
        "findings_new": 0,
        "coverage_state": "unknown",
        "denominator_note": "internal_import: no independent inventory, so no ratio is claimed",
    }
    assert not _resp("DiffResponse", _env("Diff retrieved", diff))
    diff["coverage_state"] = "measured"
    assert _resp("DiffResponse", _env("Diff retrieved", diff))

    bases = ["member_in_multiple_clusters", "credential_shared_across_clusters", "workload_digest_mismatch"]
    finding = _finding()
    findings = {
        "snapshot": _snapshot(),
        "findings": [
            {
                "finding": finding,
                "source": {"import_event_ref": "importref_" + H, "source_ref": "sourceref_" + H},
            }
        ],
        "page": page,
        "aggregates": {"findings_total": 1, "by_basis": dict.fromkeys(bases, 0)},
        "rollup": {
            "surface_limit": 20,
            "total": 1,
            "surfaced": 1,
            "folded": 0,
            "groups": [
                {
                    "basis": b,
                    "total": 0,
                    "surfaced": 0,
                    "folded": 0,
                    "representative_finding_refs": [],
                    "suppression_provenance": "none",
                }
                for b in bases
            ],
        },
    }
    assert not _resp("FindingsResponse", _env("Findings retrieved", findings))
    findings["rollup"]["groups"][0]["suppression_provenance"] = "hidden"
    assert _resp("FindingsResponse", _env("Findings retrieved", findings))


ERROR_ROWS = [
    ("fleet_observe_validation_failed", "validation_error", "The request is not valid."),
    ("fleet_observe_not_found", "not_found", "Not found."),
    ("fleet_observe_idempotency_conflict", "conflict",
     "The idempotency key was already used with a different request."),
    ("fleet_observe_project_quota_exceeded", "quota_exceeded", "The project import quota is exhausted."),
    ("fleet_observe_internal_error", "internal_error", "Internal error."),
    ("fleet_observe_unavailable", "unavailable", "The fleet view is unavailable. Retry later."),
]


@pytest.mark.parametrize("code,error,message", ERROR_ROWS)
def test_error_body_is_closed_and_ties_code_to_message(code, error, message):
    body = {"success": False, "message": message, "error": error, "error_code": code}
    assert not _resp("ErrorBody", body)
    assert _resp("ErrorBody", {**body, "message": "Something else"})
    other = "not_found" if error != "not_found" else "conflict"
    assert _resp("ErrorBody", {**body, "error": other})
    assert _resp("ErrorBody", {**body, "details": {}})
    assert _resp("ErrorBody", {**body, "error_code": "fleet_observe_other"})


def test_error_body_published_codes_match_backend_four_plus_two_planned():
    codes = _load(RESPONSES)["definitions"]["ErrorBody"]["properties"]["error_code"]["enum"]
    backend_today = {
        "fleet_observe_validation_failed",
        "fleet_observe_not_found",
        "fleet_observe_unavailable",
        "fleet_observe_internal_error",
    }
    planned = {"fleet_observe_idempotency_conflict", "fleet_observe_project_quota_exceeded"}
    assert set(codes) == backend_today | planned


def _bundle_head():
    return {
        "bundle_version": 1,
        "digest_scheme": "hmac_sha256_v1",
        "digest_key_id": "0123456789abcdef",
        "source_kind": "sdk_declaration",
        "boundary": {"boundary_kind": "repository", "boundary_digest": DIGEST},
        "observed_at": TS,
    }


def _bdef(name, body):
    schema = {"$ref": f"https://schemas.traigent.ai/{BUNDLE}#/definitions/{name}"}
    base = _validator(BUNDLE)
    validator = jsonschema.Draft7Validator(schema, registry=base._registry)
    return list(validator.iter_errors(body))


def test_bundle_and_manifest_shapes():
    batch = {"idempotency_key": DIGEST, "request_digest": DIGEST, "members": _members()}
    assert not _bdef("Bundle", {**_bundle_head(), "batches": [batch]})
    assert _bdef("Bundle", {**_bundle_head(), "batches": []})
    assert _bdef("Bundle", {**_bundle_head(), "digest_scheme": "sha256", "batches": [batch]})
    assert _bdef("Bundle", {**_bundle_head(), "digest_key_id": "ZZ", "batches": [batch]})
    assert _bdef("Bundle", {**_bundle_head(), "label_map": {}, "batches": [batch]})
    manifest = {
        **_bundle_head(),
        "manifest_version": 1,
        "batch_count": 1,
        "member_count_total": 2,
        "batches": [
            {"batch_no": 1, "idempotency_key": DIGEST, "request_digest": DIGEST, "member_count": 2}
        ],
    }
    assert not _bdef("Manifest", manifest)
    assert _bdef("Manifest", {**manifest, "batches": [{"batch_no": 1, "member_count": 2}]})


def test_rate_limited_body_matches_the_limiter_wire_shape():
    long_msg = "Too many requests for this operation. Please retry later."
    body = {
        "success": False,
        "message": long_msg,
        "error": "Too many requests",
        "error_code": "RATE_LIMIT_EXCEEDED",
        "details": {"scope": "expensive_bulk", "retry_after": 30, "limit": 30, "remaining": 0},
    }
    assert not _resp("RateLimitedBody", body)
    plain = {**body, "message": "Rate limit exceeded", "details": {"scope": "global", "retry_after": 3}}
    assert not _resp("RateLimitedBody", plain)
    assert _resp("RateLimitedBody", {**body, "message": "slow down"})
    assert _resp("RateLimitedBody", {**body, "details": {"scope": "expensive_bulk"}})
    assert _resp("RateLimitedBody", {**body, "details": {**body["details"], "note": "x"}})


def test_masked_5xx_and_auth_bodies():
    masked = {
        "success": False,
        "message": "Internal server error",
        "error": "Internal server error",
        "error_code": "RATE_LIMIT_UNAVAILABLE",
    }
    assert not _resp("RateLimitUnavailableBody", masked)
    assert _resp("RateLimitUnavailableBody", {**masked, "details": {"service": "expensive_bulk"}})
    auth = {
        "success": False,
        "message": "Unauthorized",
        "error": "TOKEN_EXPIRED",
        "error_code": "TOKEN_EXPIRED",
    }
    assert not _resp("AuthErrorBody", auth)
    assert _resp("AuthErrorBody", {**auth, "message": "Bad token abc"})


def _named(name, body):
    from traigent_schema import SchemaValidator

    return SchemaValidator(contract="backend").validate_json(body, name)


def test_bundle_document_root_is_constrained_through_the_public_named_validator():
    """validate_json(name) uses the document root: it must not accept arbitrary content."""
    batch = {"idempotency_key": DIGEST, "request_digest": DIGEST, "members": _members()}
    good = {**_bundle_head(), "batches": [batch]}
    assert _named("import_bundle_schema", good) == []
    assert _named("import_bundle_schema", {"anything": "goes"})
    assert _named("import_bundle_schema", {**good, "label_map": {"Alice_has_diabetes": "x"}})
    assert _named("import_bundle_schema", {**good, "agent_name": "Alice_has_diabetes"})
    named = {**batch, "members": [{**_members()[0], "member_name": "Alice_has_diabetes"}]}
    assert _named("import_bundle_schema", {**good, "batches": [named]})
    manifest = {
        **_bundle_head(),
        "manifest_version": 1,
        "batch_count": 1,
        "member_count_total": 2,
        "batches": [
            {"batch_no": 1, "idempotency_key": DIGEST, "request_digest": DIGEST, "member_count": 2}
        ],
    }
    assert _named("import_bundle_schema", manifest) == []


def test_responses_document_root_is_constrained_through_the_public_named_validator():
    ok = _env("Diff retrieved", None)  # wrong data on purpose
    assert _named("fleet_observe_responses_schema", ok)
    assert _named("fleet_observe_responses_schema", {"anything": "goes"})
    err = {
        "success": False,
        "message": "Not found.",
        "error": "not_found",
        "error_code": "fleet_observe_not_found",
    }
    assert _named("fleet_observe_responses_schema", err) == []
    assert _named("fleet_observe_responses_schema", {**err, "echo": "Alice_has_diabetes"})


@pytest.mark.parametrize(
    "code,message",
    [
        ("AUTHENTICATION_REQUIRED", "Authentication required"),  # request middleware, no credential
        ("INVALID_TOKEN", "Authentication required"),  # middleware pre-validation of a bad token
        ("AUTHENTICATION_REQUIRED", "Unauthorized"),  # authentication layer
        ("INVALID_TOKEN", "Unauthorized"),
        ("TOKEN_EXPIRED", "Unauthorized"),
        ("AUTH_TEST_TOKEN_BLOCKED", "Unauthorized"),
        ("TOKEN_REVOKED", "Session has been revoked"),
        ("ACCOUNT_DEACTIVATED", "Account is deactivated"),
    ],
)
def test_auth_error_body_accepts_every_verified_401_variant(code, message):
    body = {"success": False, "message": message, "error": code, "error_code": code}
    assert not _resp("AuthErrorBody", body)


@pytest.mark.parametrize(
    "code,message",
    [
        ("TOKEN_EXPIRED", "Authentication required"),
        ("TOKEN_REVOKED", "Unauthorized"),
        ("ACCOUNT_DEACTIVATED", "Session has been revoked"),
        ("AUTHENTICATION_REQUIRED", "Please log in as alice"),
    ],
)
def test_auth_error_body_rejects_a_mismatched_or_free_message(code, message):
    body = {"success": False, "message": message, "error": code, "error_code": code}
    assert _resp("AuthErrorBody", body)
    assert _resp(
        "AuthErrorBody",
        {"success": False, "message": "Unauthorized", "error": "INVALID_TOKEN", "error_code": "TOKEN_EXPIRED"},
    )
