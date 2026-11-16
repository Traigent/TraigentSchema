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
ALL = [CLUSTER, AGENT, EVIDENCE, MAPSCHEMA, SPAWN, IMPORT, COVERAGE, FINDING, COMMON]

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
    assert len(list(DOMAIN.glob("*.json"))) == 9


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
