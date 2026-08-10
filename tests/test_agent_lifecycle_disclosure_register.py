"""ALR-1102 (Terra review P1-2, 2026-08-10) / ALR-1106 (Route 1/2 packet,
2026-08-10): the client-boundary disclosure register for all nine
property-bearing Part 1 roots named at PART1_CONTRACT_FREEZE_DRAFT.md:406-408.

Authoritative contract: PART1_CONTRACT_FREEZE_DRAFT.md:376-408 ("Versioned
client-boundary disclosure register"). Every property of every Part 1 public
request/response schema must carry an ``x-disclosure {rule, artifact}``
annotation (the closed meta-schema is registered in
``traigent_schema/schemas/x_extensions_meta_schema.json``). This module is
the guard that makes guard-killing mutation row 17
(PART1_CONTRACT_FREEZE_DRAFT.md:1155) executable.

ALR-1102 originally scoped this guard to the four Route 3/Route 4 documents
it owned, because the two new producer routes (agent_lifecycle_agent_
revision_register_*, agent_lifecycle_measurement_contract_register_*) and
agent_lifecycle_record_response_schema.json (Route 5, merged later by
ALR-1105) did not exist yet -- a manifest entry naming a nonexistent document
would have failed the manifest's own literal-resolution requirement, exactly
the poison class row 17 exists to catch. ALR-1106 builds the two missing
producer routes and extends ``_IN_SCOPE_ROOTS`` to the full nine roots,
including ``agent_lifecycle_record_response_schema.json`` -- which ALR-1105
had already annotated but which this guard did not yet walk (its own
docstring said so explicitly). ``tests/data/agent_lifecycle_record/
disclosure_manifest.json`` is extended in lockstep with the new exact
overrides each of the five newly in-scope documents needs.

Known, deliberately out-of-scope limitation (verified, not assumed): this
traversal resolves ``$ref`` only when it appears inside an ``allOf`` branch
(an established codebase convention for reference types that need deep
disclosure walking -- see agent_lifecycle_receipt_submit_response_schema.
json's ``measurement_coverage``). Several already-merged definitions still
use a *bare* ``$ref`` at their use site (record_response_schema.json's
``governance_profile``/``identity_state``/``comparability_verdict``/
``measurement_coverage``/``pending_episode``/``rescorability``/``bindings``
items/``evidence_episodes`` items, and the axis-value oneOf branches inside
``agent_lifecycle_common_schema.json``) and are therefore walked only down to
their own top-level property position, not into their nested fields. This
packet does not retrofit that pre-existing (ALR-1101/ALR-1105) authoring gap
-- see the ALR-1106 story report for the full accounting of what is and is
not covered.

Two things are proved here, matching the contract's own split:
1. Coverage -- every reachable property in every in-scope root carries a
   present, well-formed x-disclosure annotation (nothing silently missing).
2. Non-poison -- every present annotation's `rule` matches either an exact
   manifest override or the deterministic-assignment algorithm
   (PART1_CONTRACT_FREEZE_DRAFT.md:404) for its exact (document, pointer);
   `artifact` matches the containing register version.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from traigent_schema.utils import get_schemas_dir

SCHEMAS_DIR = get_schemas_dir()
MANIFEST_PATH = (
    Path(__file__).parent / "data" / "agent_lifecycle_record" / "disclosure_manifest.json"
)

REGISTER_ARTIFACT = "agent_lifecycle_disclosure_register.v1"

RULE_VOCABULARY = frozenset(
    {
        "wire_contract_version",
        "closed_measurement_source_declaration",
        "content_free_request_discriminator",
        "discovery_issued_backend_resource_handle",
        "request_only_client_attestation",
        "request_only_sensitive_membership_selector",
        "single_consumption_capability",
        "coarse_selection_mode",
        "coarse_universe_provenance",
        "coarse_evaluator_provenance",
        "opaque_lifecycle_record_handle",
        "opaque_lifecycle_reference",
        "backend_snapshot_timestamp",
        "backend_record_timestamp",
        "protocol_accounting_count",
        "in_flight_episode_projection",
        "bounded_reason_vocabulary",
        "closed_interop_vocabulary",
        "closed_public_structure",
    }
)

# The nine exact property-bearing roots named at
# PART1_CONTRACT_FREEZE_DRAFT.md:406-408, relative to traigent_schema/schemas/.
_IN_SCOPE_ROOTS = [
    "agent_lifecycle_record/agent_lifecycle_agent_revision_register_request_schema.json",
    "agent_lifecycle_record/agent_lifecycle_agent_revision_register_response_schema.json",
    "agent_lifecycle_record/agent_lifecycle_measurement_contract_register_request_schema.json",
    "agent_lifecycle_record/agent_lifecycle_measurement_contract_register_response_schema.json",
    "agent_lifecycle_record/agent_lifecycle_run_plan_issue_request_schema.json",
    "agent_lifecycle_record/agent_lifecycle_run_plan_issue_response_schema.json",
    "agent_lifecycle_record/agent_lifecycle_receipt_submit_request_schema.json",
    "agent_lifecycle_record/agent_lifecycle_receipt_submit_response_schema.json",
    "agent_lifecycle_record/agent_lifecycle_record_response_schema.json",
]

# Not a traversal root (PART1_CONTRACT_FREEZE_DRAFT.md:406: "the resolved
# definition target, not a tenth route root"), but a legitimate manifest
# override document -- the contract's own worked table repeatedly overrides
# exact pointers inside it (StableSourceRef, AgentLifecycleRecordRef,
# ClientDeclaredIdentityDescriptor, ClientAttestedArtifactDescriptor).
_COMMON_SCHEMA_RELATIVE_PATH = "agent_lifecycle_record/agent_lifecycle_common_schema.json"

# Timestamps that use backend_record_timestamp. Route 5's `as_of` is the one
# named exception (PART1_CONTRACT_FREEZE_DRAFT.md:404: "except Route 5
# as_of") and is special-cased directly in _deterministic_rule below rather
# than living in this bucket.
_TIMESTAMP_PROPERTY_NAMES = {"issued_at", "expires_at", "sealed_at", "created_at"}

# Counted/index integer properties -> protocol_accounting_count.
_COUNT_PROPERTY_NAMES = {
    "expected_count",
    "index",
    "expected",
    "produced",
    "cached",
    "missing",
    "failed",
    "fallback",
    "excluded",
    "duplicate",
}

# Closed enum/const/discriminator/axis scalar properties -> closed_interop_vocabulary.
# ALR-1106 adds the three record-level axis fields that stay a single
# consistent rule at every use site across the nine in-scope roots
# (governance_profile/identity_state also appear on Route 1's response and
# Route 5's response; comparability_verdict is Route 5 only). Route 5's
# `measurement_coverage` is NOT added here even though it is also an axis
# field: unlike the other three, that exact property name is ALSO used by
# Route 4's response for a structurally different (non-axis) purpose that
# deterministically maps to closed_public_structure via _CONTAINER_PROPERTY_
# NAMES below, so the two contexts would collide on one shared bucket. Route
# 5's occurrence is handled by an exact manifest override instead (see
# tests/data/agent_lifecycle_record/disclosure_manifest.json).
_CLOSED_VOCAB_PROPERTY_NAMES = {
    "state",
    "basis",
    "trust_level",
    "outcome",
    "rescorability_state",
    "authority_effect",
    "kind",
    "governance_profile",
    "identity_state",
    "comparability_verdict",
}

# Reason-code fields (both the array property and its items) -> bounded_reason_vocabulary.
_REASON_PROPERTY_NAMES = {"reason_codes"}

# Named *_ref opaque-reference fields, and the id/version_id components of a
# ref object -> opaque_lifecycle_reference. record_ref is the one named
# exception at every site it appears (opaque_lifecycle_record_handle
# instead) and is handled by an exact manifest override rather than a
# bucket, since the generic *_ref suffix rule must keep applying to every
# other *_ref field.
_REF_SUFFIX = "_ref"
_REF_ID_COMPONENT_NAMES = {"id", "version_id"}

# Closed structural containers whose children each carry their own rule.
# ALR-1106 adds the Route 1/2/5 container-shaped properties that are
# unambiguous (single consistent rule at every use site across the nine
# in-scope roots): identity_declaration (Route 1 request), identity_
# descriptor/artifact_descriptor (the two request-only closed descriptor
# wrappers), item_keys (Route 2 request, both dataset_source and
# slice_definition branches), and evidence_episodes (Route 5 response).
_CONTAINER_PROPERTY_NAMES = {
    "expected_items",
    "receipts",
    "measurement_coverage",
    "rescorability",
    "identity_declaration",
    "identity_descriptor",
    "artifact_descriptor",
    "item_keys",
    "evidence_episodes",
    "bindings",
}


def _load_json(relative_path: str) -> dict[str, Any]:
    with open(SCHEMAS_DIR / relative_path, encoding="utf-8") as handle:
        return json.load(handle)


def _load_manifest() -> dict[str, Any]:
    with open(MANIFEST_PATH, encoding="utf-8") as handle:
        return json.load(handle)


_LITERAL_POINTER_FORBIDDEN_TOKENS = (
    ",",
    " and ",
    " or ",
    "*",
    "{",
    "}",
    "(",
    ")",
    "...",
    "Same document",
    "corresponding",
    "descendant",
    "each",
)


def _pointer_is_literal(pointer: str) -> bool:
    """PART1_CONTRACT_FREEZE_DRAFT.md:410: one literal RFC 6901 pointer
    beginning '#' and containing no comma-separated list, whitespace
    conjunction, wildcard, brace, parenthesis, ellipsis, or the named
    expansion-grammar phrases."""
    if not pointer.startswith("#"):
        return False
    if any(token in pointer for token in _LITERAL_POINTER_FORBIDDEN_TOKENS):
        return False
    # No whitespace at all in a genuine literal RFC 6901 pointer.
    if re.search(r"\s", pointer):
        return False
    return True


def _resolve_document_path(relative_path: str) -> Path:
    return SCHEMAS_DIR / relative_path


def _resolve_pointer(document: dict[str, Any], pointer: str) -> Any:
    """Resolve one literal RFC 6901 pointer (e.g. '#/properties/nonce')
    against an already-loaded document. Raises on any unresolvable segment --
    callers use this to prove resolvability, not to silently return None."""
    assert pointer.startswith("#")
    remainder = pointer[1:]
    node: Any = document
    if remainder == "":
        return node
    for raw_segment in remainder.strip("/").split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            node = node[int(segment)]
        elif isinstance(node, dict):
            node = node[segment]
        else:
            raise KeyError(f"cannot descend into {type(node)} at segment {segment!r}")
    return node


class DisclosureFinding(Exception):
    """Raised by the traversal when a property fails coverage or is poisoned."""


def _deterministic_rule(
    property_name: str,
    in_ref_object: bool,
) -> str | None:
    """PART1_CONTRACT_FREEZE_DRAFT.md:404's deterministic-assignment
    algorithm, scoped to the property-name/shape patterns the nine in-scope
    schemas actually contain. Returns None when a property cannot be
    generically classified -- it must then come from an exact manifest
    override in tests/data/agent_lifecycle_record/disclosure_manifest.json
    (e.g. `nonce`, `record_ref`, `pending_episode`, the Route 1/2 request
    discriminators/selection modes, and the request-only-descriptor scalars
    living in agent_lifecycle_common_schema.json)."""
    if property_name == "schema_version":
        return "wire_contract_version"
    if property_name == "as_of":
        # PART1_CONTRACT_FREEZE_DRAFT.md:404: the one named timestamp
        # exception -- Route 5's own read-snapshot time, not a Backend
        # write/issuance timestamp.
        return "backend_snapshot_timestamp"
    if property_name in _TIMESTAMP_PROPERTY_NAMES:
        return "backend_record_timestamp"
    if property_name in _COUNT_PROPERTY_NAMES:
        return "protocol_accounting_count"
    if property_name in _REASON_PROPERTY_NAMES:
        return "bounded_reason_vocabulary"
    if property_name in _CLOSED_VOCAB_PROPERTY_NAMES:
        return "closed_interop_vocabulary"
    if property_name in _REF_ID_COMPONENT_NAMES and in_ref_object:
        return "opaque_lifecycle_reference"
    if property_name.endswith(_REF_SUFFIX):
        return "opaque_lifecycle_reference"
    if property_name in _CONTAINER_PROPERTY_NAMES:
        return "closed_public_structure"
    return None


def _manifest_override_index(manifest: dict[str, Any]) -> dict[tuple[str, str], str]:
    index: dict[tuple[str, str], str] = {}
    for entry in manifest["disclosure_manifest"]:
        key = (entry["document"], entry["pointer"])
        index[key] = entry["rule"]
    return index


def _expected_rule(
    document: str,
    pointer: str,
    property_name: str,
    in_ref_object: bool,
    overrides: dict[tuple[str, str], str],
) -> str:
    override = overrides.get((document, pointer))
    if override is not None:
        return override
    deterministic = _deterministic_rule(property_name, in_ref_object)
    if deterministic is None:
        raise DisclosureFinding(
            f"{document}{pointer}: property {property_name!r} has no manifest override and "
            "no deterministic rule -- the corpus/manifest is incomplete, not the schema"
        )
    return deterministic


def _is_ref_definition_document_pointer(document: str, pointer: str) -> bool:
    return document == "agent_lifecycle_record/agent_lifecycle_common_schema.json" and (
        pointer.startswith("#/definitions/TypedOpaqueRef")
        or pointer.startswith("#/definitions/StableOpaqueRef")
    )


def _iter_property_positions(
    document: str,
    pointer: str,
    node: Any,
    schemas_cache: dict[str, dict[str, Any]],
    visited: set[tuple[str, str]],
) -> list[tuple[str, str, dict[str, Any], str]]:
    """Yield (document, pointer, node, property_name) for every reachable
    property position under `node`, resolving cross-file $refs and following
    oneOf/anyOf branches and $ref-only/typed allOf branches. Pure narrowing
    allOf branches (no 'type' and no '$ref' -- e.g. {"properties": {"kind":
    {"const": ...}}}) are deliberately NOT walked for coverage purposes: they
    narrow an already-covered position, they do not declare a new one (the
    real annotation for a narrowed sub-field lives at the $ref target)."""
    positions: list[tuple[str, str, dict[str, Any], str]] = []
    if (document, pointer) in visited:
        return positions
    visited.add((document, pointer))

    if not isinstance(node, dict):
        return positions

    if "properties" in node and isinstance(node["properties"], dict):
        for key, subnode in node["properties"].items():
            child_pointer = f"{pointer}/properties/{key}"
            positions.append((document, child_pointer, subnode, key))
            positions.extend(
                _iter_property_positions(document, child_pointer, subnode, schemas_cache, visited)
            )

    if "items" in node and isinstance(node["items"], dict):
        item_pointer = f"{pointer}/items"
        positions.extend(
            _iter_property_positions(document, item_pointer, node["items"], schemas_cache, visited)
        )

    for combiner in ("oneOf", "anyOf"):
        if combiner in node and isinstance(node[combiner], list):
            for index, branch in enumerate(node[combiner]):
                branch_pointer = f"{pointer}/{combiner}/{index}"
                positions.extend(
                    _iter_property_positions(document, branch_pointer, branch, schemas_cache, visited)
                )

    if "allOf" in node and isinstance(node["allOf"], list):
        for branch in node["allOf"]:
            if not isinstance(branch, dict):
                continue
            if "$ref" in branch:
                target_document, target_pointer, target_node = _resolve_ref(
                    document, branch["$ref"], schemas_cache
                )
                positions.extend(
                    _iter_property_positions(
                        target_document, target_pointer, target_node, schemas_cache, visited
                    )
                )
            elif "type" in branch:
                # A genuine (non-narrowing) inline schema fragment.
                positions.extend(
                    _iter_property_positions(document, pointer, branch, schemas_cache, visited)
                )
            # else: a pure narrowing fragment (properties/required only, no
            # type, no $ref) -- deliberately not walked; see docstring.

    return positions


def _resolve_ref(
    current_document: str, ref: str, schemas_cache: dict[str, dict[str, Any]]
) -> tuple[str, str, Any]:
    file_part, _, pointer_part = ref.partition("#")
    pointer = "#" + pointer_part if not pointer_part.startswith("#") else pointer_part
    if file_part:
        target_document = str((Path(current_document).parent / file_part).as_posix())
    else:
        target_document = current_document
    if target_document not in schemas_cache:
        schemas_cache[target_document] = _load_json(target_document)
    node = _resolve_pointer(schemas_cache[target_document], pointer)
    return target_document, pointer, node


def _collect_all_positions() -> list[tuple[str, str, dict[str, Any], str]]:
    schemas_cache: dict[str, dict[str, Any]] = {root: _load_json(root) for root in _IN_SCOPE_ROOTS}
    visited: set[tuple[str, str]] = set()
    all_positions: list[tuple[str, str, dict[str, Any], str]] = []
    for root in _IN_SCOPE_ROOTS:
        all_positions.extend(
            _iter_property_positions(root, "#", schemas_cache[root], schemas_cache, visited)
        )
    return all_positions


# ---------------------------------------------------------------------------
# Manifest literal-grammar / resolution tests
# ---------------------------------------------------------------------------


class TestDisclosureManifestIsLiteralAndResolvable:
    def test_manifest_entries_are_closed_and_use_literal_pointers(self) -> None:
        manifest = _load_manifest()
        entries = manifest["disclosure_manifest"]
        assert entries, "the scoped disclosure manifest must not be empty"

        for entry in entries:
            assert set(entry) == {"document", "pointer", "rule", "artifact"}, entry
            assert _pointer_is_literal(entry["pointer"]), f"non-literal pointer: {entry}"
            assert entry["artifact"] == REGISTER_ARTIFACT
            assert entry["rule"] in RULE_VOCABULARY

    def test_manifest_documents_and_pointers_resolve(self) -> None:
        manifest = _load_manifest()
        for entry in manifest["disclosure_manifest"]:
            document_path = _resolve_document_path(entry["document"])
            assert document_path.is_file(), f"manifest names a document that does not exist: {entry}"
            with open(document_path, encoding="utf-8") as handle:
                data = json.load(handle)
            # Must not raise -- proves the pointer resolves inside the document.
            _resolve_pointer(data, entry["pointer"])

    def test_manifest_has_no_duplicate_document_pointer_pairs(self) -> None:
        manifest = _load_manifest()
        pairs = [(e["document"], e["pointer"]) for e in manifest["disclosure_manifest"]]
        assert len(pairs) == len(set(pairs)), f"duplicate (document, pointer) pairs: {pairs}"

    def test_manifest_only_names_documents_this_story_owns(self) -> None:
        """Guards the scoping decision documented in the manifest's own
        $comment: every entry's document must be either one of the nine
        exact in-scope roots (PART1_CONTRACT_FREEZE_DRAFT.md:406-408) or
        agent_lifecycle_common_schema.json -- the resolved definitions
        target the contract's own worked table (PART1_CONTRACT_FREEZE_DRAFT.
        md:412-487) repeatedly overrides directly (StableSourceRef,
        AgentLifecycleRecordRef, ClientDeclaredIdentityDescriptor,
        ClientAttestedArtifactDescriptor). It is deliberately NOT itself an
        _IN_SCOPE_ROOTS traversal root (PART1_CONTRACT_FREEZE_DRAFT.md:406:
        'the resolved definition target, not a tenth route root'), but a
        manifest override entry naming it is still legitimate: it is
        reached and checked via allOf/$ref resolution from an in-scope root,
        not via its own top-level traversal. A stray reference to any OTHER
        document (a definitions-only or endpoint-catalog file that is
        neither) would itself violate the resolvability test above but is
        worth asserting directly as the intended invariant."""
        manifest = _load_manifest()
        allowed_documents = {*_IN_SCOPE_ROOTS, _COMMON_SCHEMA_RELATIVE_PATH}
        for entry in manifest["disclosure_manifest"]:
            assert entry["document"] in allowed_documents, entry


# ---------------------------------------------------------------------------
# Coverage: every reachable property in every in-scope root has x-disclosure.
# ---------------------------------------------------------------------------


class TestDisclosureCoverage:
    def test_every_reachable_property_has_an_x_disclosure_annotation(self) -> None:
        positions = _collect_all_positions()
        assert positions, "traversal found no properties at all -- the walker is broken"

        missing = [
            (doc, ptr)
            for doc, ptr, node, _name in positions
            if "x-disclosure" not in node
        ]
        assert missing == [], f"properties missing x-disclosure: {missing}"

    def test_every_x_disclosure_annotation_is_well_formed(self) -> None:
        positions = _collect_all_positions()
        for doc, ptr, node, _name in positions:
            annotation = node["x-disclosure"]
            assert set(annotation) == {"rule", "artifact"}, f"{doc}{ptr}: malformed {annotation}"
            assert annotation["artifact"] == REGISTER_ARTIFACT, f"{doc}{ptr}: wrong artifact"
            assert annotation["rule"] in RULE_VOCABULARY, f"{doc}{ptr}: unknown rule"

    def test_no_annotation_is_poisoned(self) -> None:
        """A poisoned annotation is syntactically valid but semantically
        false: its rule differs from the manifest override (if any) or the
        deterministic assignment for its exact (document, pointer)
        (PART1_CONTRACT_FREEZE_DRAFT.md:408)."""
        manifest = _load_manifest()
        overrides = _manifest_override_index(manifest)
        positions = _collect_all_positions()

        poisoned = []
        for doc, ptr, node, name in positions:
            in_ref_object = _is_ref_definition_document_pointer(doc, ptr.rsplit("/properties/", 1)[0])
            expected = _expected_rule(doc, ptr, name, in_ref_object, overrides)
            actual = node["x-disclosure"]["rule"]
            if actual != expected:
                poisoned.append((doc, ptr, name, actual, expected))

        assert poisoned == [], f"poisoned x-disclosure rule(s): {poisoned}"

    def test_rule_vocabulary_matches_the_registered_meta_schema(self) -> None:
        """Guards against this test module's copy of the 19-rule vocabulary
        drifting from traigent_schema/schemas/x_extensions_meta_schema.json's
        registered x-disclosure.rule enum."""
        with open(SCHEMAS_DIR / "x_extensions_meta_schema.json", encoding="utf-8") as handle:
            meta = json.load(handle)
        registered = set(meta["properties"]["x-disclosure"]["properties"]["rule"]["enum"])
        assert registered == RULE_VOCABULARY
        assert len(RULE_VOCABULARY) == 19


# ---------------------------------------------------------------------------
# Poison-guard proofs (in-memory, permanent regression). Each demonstrates
# the guard is load-bearing: a corrupted copy fails, the untouched original
# does not.
# ---------------------------------------------------------------------------


def _find_position(document: str, pointer: str) -> dict[str, Any]:
    node = _load_json(document)
    return _resolve_pointer(node, pointer)


class TestDisclosurePoisonGuardsAreLoadBearing:
    def test_removing_an_annotation_is_detected_by_the_coverage_scan(self) -> None:
        schemas_cache: dict[str, dict[str, Any]] = {
            root: _load_json(root) for root in _IN_SCOPE_ROOTS
        }
        target_document = "agent_lifecycle_record/agent_lifecycle_receipt_submit_request_schema.json"
        target_node = schemas_cache[target_document]["properties"]["nonce"]
        assert "x-disclosure" in target_node
        del target_node["x-disclosure"]

        visited: set[tuple[str, str]] = set()
        all_positions: list[tuple[str, str, dict[str, Any], str]] = []
        for root in _IN_SCOPE_ROOTS:
            all_positions.extend(
                _iter_property_positions(root, "#", schemas_cache[root], schemas_cache, visited)
            )
        missing = [(doc, ptr) for doc, ptr, node, _name in all_positions if "x-disclosure" not in node]
        assert (target_document, "#/properties/nonce") in missing

    def test_poisoning_a_rule_is_detected_as_a_mismatch(self) -> None:
        schemas_cache: dict[str, dict[str, Any]] = {
            root: _load_json(root) for root in _IN_SCOPE_ROOTS
        }
        target_document = "agent_lifecycle_record/agent_lifecycle_run_plan_issue_response_schema.json"
        target_pointer = "#/properties/state"
        target_node = schemas_cache[target_document]["properties"]["state"]
        assert target_node["x-disclosure"]["rule"] == "closed_interop_vocabulary"
        # Poison it to a plausible-but-wrong rule from the same closed vocabulary.
        target_node["x-disclosure"] = {"rule": "protocol_accounting_count", "artifact": REGISTER_ARTIFACT}

        manifest = _load_manifest()
        overrides = _manifest_override_index(manifest)
        expected = _expected_rule(target_document, target_pointer, "state", False, overrides)
        actual = target_node["x-disclosure"]["rule"]
        assert actual != expected, "mutation sanity check failed: poison did not diverge from expected"

    def test_manifest_with_a_nonliteral_pointer_is_rejected(self) -> None:
        poisoned_entry = {
            "document": "agent_lifecycle_record/agent_lifecycle_run_plan_issue_response_schema.json",
            "pointer": "#/properties/*",
            "rule": "closed_interop_vocabulary",
            "artifact": REGISTER_ARTIFACT,
        }
        assert not _pointer_is_literal(poisoned_entry["pointer"])

    def test_manifest_pointing_at_a_nonexistent_document_is_rejected(self) -> None:
        """ALR-1106: agent_lifecycle_agent_revision_register_request_schema.json
        now exists (it was this exact poison example's stand-in for a
        not-yet-built Route 1/2 document under ALR-1102's four-root scope) --
        swapped for a document name that remains genuinely nonexistent under
        the now nine-root scope, so this still exercises real poison
        detection rather than accidentally validating a real file."""
        poisoned_entry = {
            "document": "agent_lifecycle_record/agent_lifecycle_qualification_register_request_schema.json",
            "pointer": "#/properties/agent_ref",
            "rule": "opaque_lifecycle_reference",
            "artifact": REGISTER_ARTIFACT,
        }
        document_path = _resolve_document_path(poisoned_entry["document"])
        assert not document_path.is_file()

    def test_manifest_wrong_artifact_is_rejected(self) -> None:
        poisoned_entry = {
            "document": "agent_lifecycle_record/agent_lifecycle_run_plan_issue_response_schema.json",
            "pointer": "#/properties/nonce",
            "rule": "single_consumption_capability",
            "artifact": "agent_lifecycle_disclosure_register.v2",
        }
        assert poisoned_entry["artifact"] != REGISTER_ARTIFACT

    def test_duplicate_manifest_pair_is_detected(self) -> None:
        manifest = copy.deepcopy(_load_manifest())
        manifest["disclosure_manifest"].append(dict(manifest["disclosure_manifest"][0]))
        pairs = [(e["document"], e["pointer"]) for e in manifest["disclosure_manifest"]]
        assert len(pairs) != len(set(pairs))


# ---------------------------------------------------------------------------
# Row 17 sanity: at least one real annotation exists at every exact override
# pointer named in the scoped manifest (a corpus/manifest consistency check,
# distinct from poisoning).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "document,pointer",
    [
        (e["document"], e["pointer"])
        for e in _load_manifest()["disclosure_manifest"]
    ],
)
def test_manifest_override_pointer_has_a_real_annotation(document: str, pointer: str) -> None:
    node = _find_position(document, pointer)
    assert "x-disclosure" in node
