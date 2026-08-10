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

P1 correction (Terra review, 2026-08-10): an earlier revision of this module
resolved ``$ref`` only when it appeared inside an ``allOf`` branch, so every
*bare* ``$ref`` use site -- record_response_schema.json's
``governance_profile``/``identity_state``/``comparability_verdict``/
``measurement_coverage``/``pending_episode``/``rescorability``/``bindings``
items/``evidence_episodes`` items, Route 1's own ``identity_state``, and (one
level deeper) the axis-value oneOf branches inside ``agent_lifecycle_common_
schema.json`` and ``BindingProjection``'s four version-slot properties in
this file -- was walked only down to its own top-level property position,
never into its nested fields. That was not a narrow caveat: those nested
fields could carry no annotation at all and this guard would not notice, so
row 17 was not actually executable across nine roots, only nine top-level
positions with unguarded interiors. ``_iter_property_positions`` now
resolves ``$ref`` wherever it appears (see its own docstring and
``_is_walkable_fragment`` for the allOf/if-then-else narrowing-fragment
distinction, which is real and preserved, not a loophole reintroducing the
same hole). Every position the corrected walker newly discovers now carries
a real ``x-disclosure`` annotation -- see the ALR-1106 story report for the
complete enumeration of what was missing and where it was added.

Two things are proved here, matching the contract's own split:
1. Coverage -- every reachable property in every in-scope root carries a
   present, well-formed x-disclosure annotation (nothing silently missing).
2. Non-poison -- every present annotation's `rule` matches either an exact
   manifest override or the deterministic-assignment algorithm
   (PART1_CONTRACT_FREEZE_DRAFT.md:404) for its exact (document, pointer);
   `artifact` matches the containing register version.

ALR-1107 (sensitive-source / privacy-capture manifest sink guard, 2026-08-10)
extends this module with a second, distinct guard living at its own
``test_sensitive_ingress_manifest_has_no_unlisted_sink`` entry point
(PART1_CONTRACT_FREEZE_DRAFT.md:492-533): not "does every property carry an
annotation" but "can a sensitive source structurally reach a log, telemetry,
export, URL, or response sink". It reuses this module's traversal machinery
(``_iter_property_positions``, ``_resolve_ref``, ``_collect_all_positions``,
``_pointer_is_literal``) unchanged rather than building a second engine -- see
that section's own header comment for what it proves, what it deliberately
cannot prove (TraigentBackend-owned sinks with no JSON Schema in this repo),
and why ``authorized_source_handle_response_manifest`` is empty today.
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
    # ALR-1106 P1 fix (Terra review, 2026-08-10): the closed-vocabulary
    # discriminator scalar inside every axis-value oneOf branch
    # (GovernanceProfileAxisValue/IdentityStateAxisValue/
    # ComparabilityVerdictAxisValue.value), newly reachable now the walker
    # resolves bare $ref -- e.g. {"const": "OBSERVED"}. Used only in that
    # one context across the nine in-scope roots.
    "value",
    # ALR-1106 P1 fix: BindingProjection.origin / EpisodeProjection.origin
    # (both const "LIVE"), newly reachable now bindings[]/evidence_
    # episodes[]'s bare $ref item schemas are resolved.
    "origin",
    # ALR-1106 P1 fix: ArtifactVersionSlotBase.schema (the fp2 schema-name
    # discriminator: afp2/fp1/dfp2o/efp2/cfp2), newly reachable now the
    # four named version-slot properties' bare $ref is resolved.
    "schema",
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
    # ALR-1106 P1 fix (Terra review, 2026-08-10): BindingProjection's four
    # named fp2 version slots, newly reachable now the walker resolves
    # bare $ref -- each is a closed structural container (schema/state/ref
    # fields, already independently annotated on ArtifactVersionSlotBase).
    "agent_version_slot",
    "dataset_version_slot",
    "evaluator_version_slot",
    "configuration_version_slot",
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
    if property_name == "ref" or property_name.endswith(_REF_SUFFIX):
        # ALR-1106 P1 fix: the bare "ref" property name (ArtifactVersionSlot
        # Base.ref, const null) is the fp2 slot's own ref field -- the same
        # rule as every *_ref-suffixed field, just not suffixed itself.
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


_WALKABLE_FRAGMENT_SIGNAL_KEYS = frozenset({"$ref", "type", "oneOf", "anyOf", "items"})


def _is_walkable_fragment(node: dict[str, Any]) -> bool:
    """PART1_CONTRACT_FREEZE_DRAFT.md:406-408's traversal rule descends
    through allOf and if/then/else, but neither construct is used in this
    corpus to ever declare a NEW property -- both are used exclusively to
    layer an additional constraint on top of a property whose authoritative
    home (where its x-disclosure annotation actually lives) is elsewhere: a
    $ref target, or a sibling directly on the containing object's own
    `properties`. A branch/if/then/else fragment is genuinely walkable (may
    introduce a position worth checking) only when it is self-contained --
    carries its own $ref, type, oneOf, anyOf, or items. A bare
    {"properties": {...}, "required": [...]} wrapper with none of those
    (a kind=const narrowing branch, an if/then sibling-value check) is
    re-stating an already-covered property's legal values through a
    different JSON Pointer path, not declaring a new one; walking it would
    manufacture a disclosure requirement for a pointer that is not a
    property's real home. Applied uniformly to allOf branches and
    if/then/else because both are the same JSON Schema layered-composition
    mechanism, just spelled differently."""
    return bool(_WALKABLE_FRAGMENT_SIGNAL_KEYS & node.keys())


def _iter_property_positions(
    document: str,
    pointer: str,
    node: Any,
    schemas_cache: dict[str, dict[str, Any]],
    visited: set[tuple[str, str]],
) -> list[tuple[str, str, dict[str, Any], str]]:
    """Yield (document, pointer, node, property_name) for every reachable
    property position under `node`. Resolves EVERY local or cross-file $ref
    wherever it appears -- not only inside allOf branches (ALR-1106 P1 fix,
    Terra review 2026-08-10: the prior version only resolved $ref inside
    allOf, so record_response_schema.json's governance_profile/identity_
    state/measurement_coverage/pending_episode/comparability_verdict/
    bindings-items/evidence_episodes-items (all bare $ref), Route 1's own
    identity_state, and the common-schema axis/coverage definitions those
    bare refs point to were never walked past their own top-level property
    position -- a real, undisclosed-property-shaped hole, not a narrow
    caveat) -- and descends recursively through properties, array items,
    oneOf, anyOf, allOf, and if/then/else, exactly matching PART1_CONTRACT_
    FREEZE_DRAFT.md:406-408's traversal rule. `visited` tracks every
    resolved (document, pointer) pair so a cycle (e.g. a self-referential
    or mutually-referential $ref graph) neither skips a branch it hasn't
    seen from THIS path nor recurses forever -- each unique pair is walked
    exactly once, from wherever it is first reached. allOf branches and
    if/then/else fragments that carry no $ref/type/oneOf/anyOf/items of
    their own (pure sibling-narrowing wrappers) are deliberately not walked
    -- see _is_walkable_fragment's docstring for why that is not a loophole
    but the correct reading of what 'declares a new property' means."""
    positions: list[tuple[str, str, dict[str, Any], str]] = []
    if (document, pointer) in visited:
        return positions
    visited.add((document, pointer))

    if not isinstance(node, dict):
        return positions

    if "$ref" in node and isinstance(node["$ref"], str):
        target_document, target_pointer, target_node = _resolve_ref(
            document, node["$ref"], schemas_cache
        )
        positions.extend(
            _iter_property_positions(target_document, target_pointer, target_node, schemas_cache, visited)
        )

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
        for index, branch in enumerate(node["allOf"]):
            if not isinstance(branch, dict) or not _is_walkable_fragment(branch):
                continue
            branch_pointer = f"{pointer}/allOf/{index}"
            positions.extend(
                _iter_property_positions(document, branch_pointer, branch, schemas_cache, visited)
            )

    for keyword in ("if", "then", "else"):
        candidate = node.get(keyword)
        if isinstance(candidate, dict) and _is_walkable_fragment(candidate):
            kw_pointer = f"{pointer}/{keyword}"
            positions.extend(
                _iter_property_positions(document, kw_pointer, candidate, schemas_cache, visited)
            )

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


# ---------------------------------------------------------------------------
# ALR-1107: sensitive-source / privacy-capture manifest sink guard.
#
# Authoritative contract: PART1_CONTRACT_FREEZE_DRAFT.md:492-533. The freeze
# names four literal arrays -- sensitive_source_manifest, privacy_capture_
# manifest, response_root_manifest, authorized_source_handle_response_
# manifest -- consumed directly by a test named exactly
# test_sensitive_ingress_manifest_has_no_unlisted_sink, and requires the
# guard to prove no sensitive-marked ingress field can reach a log,
# telemetry, export, URL, or response sink.
#
# Two things this repo can and cannot prove, stated up front (do not paper
# over the gap -- see the ALR-1107 story report for the full accounting):
#
# 1. RESPONSE sink (response_root_manifest, 6 real JSON Schema documents)
#    and the two schema-shaped privacy captures that are themselves
#    response bytes (validation_error_body == validation_error_schema.json;
#    idempotency_replay == the byte-identical replay of one of the four
#    Idempotency-Key-bearing routes' own responses, PART1_CONTRACT_FREEZE_
#    DRAFT.md:390/577/585/632/722) are REAL JSON Schema documents this repo
#    owns. For these, the guard performs a genuine structural containment
#    check: every sensitive source reduces, by exhaustive corpus grep (see
#    the ALR-1107 story report), to exactly one of two shared common-schema
#    definitions -- RequestOnlyRandomLabel or StableSourceRef -- and the
#    guard proves neither definition is reachable anywhere in a covered
#    sink's transitive, cross-file-$ref-resolved property graph, reusing
#    _iter_property_positions unchanged (no second traversal engine).
#
# 2. The URL sink is checked against the five route path templates named at
#    PART1_CONTRACT_FREEZE_DRAFT.md:537/581/628/697/756 (this repo has no
#    agent_lifecycle_endpoints.json catalogue yet -- PART1_CONTRACT_FREEZE_
#    DRAFT.md:406-408 names it as belonging to "a separate guard", not this
#    one, so this packet does not create it): the exact set of path
#    parameters is asserted closed and disjoint from every sensitive
#    source's own property-name fragment.
#
# 3. structured_log, application_log, audit_log, analytics_event,
#    telemetry_event, export_row, and idempotency_storage have NO JSON
#    Schema representation anywhere in this repo -- TraigentBackend owns
#    their wire/storage shape, not TraigentSchema. PART1_CONTRACT_FREEZE_
#    DRAFT.md:315/596 promises exclusion for these sinks in PROSE only. This
#    guard cannot and does not claim to structurally verify them; instead it
#    (a) keeps each one a literal, resolvable, closed-vocabulary manifest
#    entry so its existence cannot silently disappear or drift, and (b)
#    asserts by exact-membership that the set of schema-unmodeled captures
#    is exactly this named set -- so a later PR that adds real schema
#    backing for one of them, or that adds a new capture without deciding
#    its status, is forced to touch this test. TraigentBackend must carry
#    the equivalent guard for these seven; this repo cannot substitute for
#    that runtime-enforcement guard from a schema-only vantage point.
#
# authorized_source_handle_response_manifest is empty today, not merely
# unused: PART1_CONTRACT_FREEZE_DRAFT.md:315/327-334 requires StableSourceRef
# to be returned only via the additive `lifecycle_source_ref` field on
# dataset_schema.json / evaluator_definition_schema.json, but neither
# document has that field yet (grepped exhaustively -- see the ALR-1107
# story report). Building that producer is a Route 2 discovery-flow change
# far outside "build the sink guard" (it would add a new public response
# field to two schemas this story does not own) and is out of scope here.
# Until it exists, an empty exception list is not an oversight -- it is the
# only honest reading: the guard is currently STRICTER than the contract's
# steady-state design (zero StableSourceRef reachability anywhere, no
# exceptions), which is the safe direction to err on. The day that producer
# is built, this list -- and this comment -- must be updated in the same PR,
# or this guard will (correctly) go red.
# ---------------------------------------------------------------------------

_SENSITIVE_INGRESS_MANIFEST_PATH = (
    Path(__file__).parent / "data" / "agent_lifecycle_record" / "sensitive_ingress_manifest.json"
)
_PRIVACY_CAPTURE_TARGETS_RELATIVE_PATH = (
    "tests/data/agent_lifecycle_record/sensitive_ingress_privacy_captures.json"
)
_REPO_ROOT = Path(__file__).parent.parent

_SENSITIVE_MARKER_DOCUMENT = _COMMON_SCHEMA_RELATIVE_PATH
_SENSITIVE_MARKER_POINTERS = (
    "#/definitions/RequestOnlyRandomLabel",
    "#/definitions/StableSourceRef",
)
_SENSITIVE_MARKERS = frozenset(
    (_SENSITIVE_MARKER_DOCUMENT, pointer) for pointer in _SENSITIVE_MARKER_POINTERS
)

_EXPECTED_SCHEMA_UNMODELED_CAPTURES = frozenset(
    {
        "structured_log",
        "application_log",
        "audit_log",
        "analytics_event",
        "telemetry_event",
        "export_row",
        "idempotency_storage",
    }
)


def _load_sensitive_ingress_manifest() -> dict[str, Any]:
    with open(_SENSITIVE_INGRESS_MANIFEST_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _resolve_repo_relative_path(relative_path: str) -> Path:
    """privacy_capture_manifest documents are repo-root-relative (matching
    PART1_CONTRACT_FREEZE_DRAFT.md:505's own literal example
    'tests/data/agent_lifecycle_contract_v1beta.json') because they name a
    test-fixture corpus document, not a production schema under
    SCHEMAS_DIR -- unlike the other three arrays, which stay schema-dir-
    relative to match the pre-existing disclosure_manifest.json convention
    (_resolve_document_path above)."""
    return _REPO_ROOT / relative_path


def _load_privacy_capture_targets() -> dict[str, Any]:
    with open(
        _resolve_repo_relative_path(_PRIVACY_CAPTURE_TARGETS_RELATIVE_PATH), encoding="utf-8"
    ) as handle:
        return json.load(handle)


def _immediate_ref_targets(
    document: str, node: dict[str, Any], schemas_cache: dict[str, dict[str, Any]]
) -> set[tuple[str, str]]:
    """The (document, pointer) pair(s) `node` itself $refs directly: a bare
    top-level `$ref`, or a `$ref` inside one of `node`'s own `allOf`
    branches. Deliberately ONE HOP, not the transitive closure
    `_iter_property_positions` walks -- a transitive walk would also
    surface shared generic leaf definitions (e.g. OpaqueRefId, reused by
    every opaque ref in the corpus, sensitive and non-sensitive alike) and
    turn every ordinary `*_ref.id` field into a false-positive sensitive-
    shape match. Exhaustive corpus grep (ALR-1107 story report) confirms
    RequestOnlyRandomLabel and StableSourceRef are always the IMMEDIATE
    $ref target at every position that uses them, so one hop is sufficient
    and does not under-match."""
    targets: set[tuple[str, str]] = set()
    if isinstance(node.get("$ref"), str):
        targets.add(_resolve_ref(document, node["$ref"], schemas_cache)[:2])
    all_of = node.get("allOf")
    if isinstance(all_of, list):
        for branch in all_of:
            if isinstance(branch, dict) and isinstance(branch.get("$ref"), str):
                targets.add(_resolve_ref(document, branch["$ref"], schemas_cache)[:2])
    return targets


def _reachable_sensitive_markers(
    document: str, pointer: str, node: dict[str, Any]
) -> set[tuple[str, str]]:
    """Which of _SENSITIVE_MARKERS are reachable anywhere in `node`'s
    transitive, cross-file-$ref-resolved property graph. Reuses
    _iter_property_positions unchanged: when it resolves a $ref it recurses
    into the target and records (target_document, target_pointer) in
    `visited` before checking whether the target itself declares further
    properties/items/etc -- so a leaf scalar (RequestOnlyRandomLabel has
    none) still leaves a `visited` trace even though it contributes zero
    new `positions`. That trace is exactly what this function reads; no
    second traversal engine."""
    schemas_cache: dict[str, dict[str, Any]] = {document: _load_json(document)}
    visited: set[tuple[str, str]] = set()
    _iter_property_positions(document, pointer, node, schemas_cache, visited)
    return visited & _SENSITIVE_MARKERS


def _resolve_entry(document: str, pointer: str) -> dict[str, Any]:
    return _resolve_pointer(_load_json(document), pointer)


def _collect_all_positions_and_visited() -> tuple[
    list[tuple[str, str, dict[str, Any], str]], set[tuple[str, str]]
]:
    """The exact body of _collect_all_positions above, except it also
    returns the `visited` set that function discards. Not a second
    traversal engine -- same _IN_SCOPE_ROOTS, same _iter_property_positions,
    same loop; the only difference is which local survives the return."""
    schemas_cache: dict[str, dict[str, Any]] = {root: _load_json(root) for root in _IN_SCOPE_ROOTS}
    visited: set[tuple[str, str]] = set()
    all_positions: list[tuple[str, str, dict[str, Any], str]] = []
    for root in _IN_SCOPE_ROOTS:
        all_positions.extend(
            _iter_property_positions(root, "#", schemas_cache[root], schemas_cache, visited)
        )
    return all_positions, visited


def _scan_corpus_for_sensitive_positions() -> set[tuple[str, str]]:
    """The coverage half of this guard, symmetric to TestDisclosureCoverage
    above: every position in the nine in-scope roots' transitive property
    graph whose OWN immediate $ref target is one of the two sensitive
    marker definitions. Compared for exact equality against the declared
    sensitive_source_manifest below -- so deleting a manifest entry for a
    still-present sensitive source is caught here, not only a poisoned
    rule.

    Pre-existing gap discovered while building this guard (distinct from
    row 17's allOf-only $ref bug, PART1_CONTRACT_FREEZE_DRAFT.md:1155):
    _iter_property_positions appends a position for every `properties`
    child (self + recurse), but for the `items` keyword it only recurses --
    it never appends a position for the `items` node itself. Two of this
    guard's six sensitive sources (the dataset_source/slice_definition
    `item_keys.items` RequestOnlyRandomLabel positions) live exactly there,
    so `_collect_all_positions()` alone silently never sees them -- proven
    by deleting their x-disclosure and confirming the existing coverage
    test's `missing` list stays empty (ALR-1107 story report has the
    transcript). This function does not modify the shared walker (that
    would also require authoring correct x-disclosure annotations for the
    ~15 OTHER items-positions the same blind spot hides across this
    corpus -- reason_codes array items and Route 5's bindings/evidence_
    episodes array items -- which is disclosure-register-completeness work
    outside this story's named scope, flagged for a follow-up rather than
    silently bundled here). Instead it recovers exactly the positions this
    guard itself needs from `visited`, which _iter_property_positions
    already populates correctly for `items` targets (its own top line adds
    every (document, pointer) it recurses into, whether or not it later
    appends a `positions` entry for it) -- the same fact _reachable_
    sensitive_markers above already relies on."""
    positions, visited = _collect_all_positions_and_visited()
    schemas_cache: dict[str, dict[str, Any]] = {}
    found: set[tuple[str, str]] = set()
    for doc, ptr, node, _name in positions:
        if doc not in schemas_cache:
            schemas_cache[doc] = _load_json(doc)
        if _immediate_ref_targets(doc, node, schemas_cache) & _SENSITIVE_MARKERS:
            found.add((doc, ptr))

    # Only the documented `items` blind spot is recovered here -- NOT every
    # other (document, pointer) `visited` happens to contain. `visited` also
    # accumulates synthetic intermediate positions the shared walker visits
    # while resolving ($ref targets, walkable allOf-branch pointers like
    # `.../source_ref/allOf/0`) that are not real declared-property
    # positions and would otherwise show up here as spurious extra "sources"
    # duplicating their own parent position. Filtering to pointers literally
    # ending `/items` keeps this recovery exactly as narrow as the gap it
    # patches.
    known_pointers = {(doc, ptr) for doc, ptr, _node, _name in positions}
    for doc, ptr in visited - known_pointers:
        if not ptr.endswith("/items"):
            continue
        if doc not in schemas_cache:
            schemas_cache[doc] = _load_json(doc)
        try:
            node = _resolve_pointer(schemas_cache[doc], ptr)
        except (KeyError, IndexError, TypeError):
            continue
        if not isinstance(node, dict):
            continue
        if _immediate_ref_targets(doc, node, schemas_cache) & _SENSITIVE_MARKERS:
            found.add((doc, ptr))
    return found


_URL_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")


def _sensitive_property_name_fragments(
    sensitive_source_manifest: list[dict[str, str]],
) -> set[str]:
    """The literal property-name each sensitive_source_manifest pointer
    names: its own last segment, or (for the two `.../item_keys/items`
    array-item pointers, whose last segment is the structural token
    'items') the second-to-last segment instead."""
    names: set[str] = set()
    for entry in sensitive_source_manifest:
        segments = entry["pointer"].rsplit("/", 2)
        last = segments[-1]
        names.add(segments[-2] if last == "items" else last)
    return names


class TestSensitiveIngressManifestIsLiteralAndResolvable:
    """Mirrors TestDisclosureManifestIsLiteralAndResolvable's literal-grammar
    checks (PART1_CONTRACT_FREEZE_DRAFT.md:133: 'separately literal
    ingress/capture/response manifests'), applied to all four ALR-1107
    arrays."""

    def test_all_four_arrays_use_closed_entries_and_literal_pointers(self) -> None:
        manifest = _load_sensitive_ingress_manifest()
        for array_name in (
            "sensitive_source_manifest",
            "privacy_capture_manifest",
            "response_root_manifest",
            "authorized_source_handle_response_manifest",
        ):
            entries = manifest[array_name]
            for entry in entries:
                assert set(entry) == {"document", "pointer"}, (array_name, entry)
                assert _pointer_is_literal(entry["pointer"]), f"{array_name}: {entry}"

    def test_sensitive_source_and_response_root_documents_resolve(self) -> None:
        manifest = _load_sensitive_ingress_manifest()
        for array_name in (
            "sensitive_source_manifest",
            "response_root_manifest",
            "authorized_source_handle_response_manifest",
        ):
            for entry in manifest[array_name]:
                document_path = _resolve_document_path(entry["document"])
                assert document_path.is_file(), f"{array_name}: {entry}"
                with open(document_path, encoding="utf-8") as handle:
                    data = json.load(handle)
                _resolve_pointer(data, entry["pointer"])

    def test_privacy_capture_manifest_documents_and_targets_resolve(self) -> None:
        manifest = _load_sensitive_ingress_manifest()
        entries = manifest["privacy_capture_manifest"]
        assert entries, "privacy_capture_manifest must not be empty"
        for entry in entries:
            document_path = _resolve_repo_relative_path(entry["document"])
            assert document_path.is_file(), entry
            with open(document_path, encoding="utf-8") as handle:
                data = json.load(handle)
            _resolve_pointer(data, entry["pointer"])  # must not raise

    def test_no_duplicate_pairs_within_any_array(self) -> None:
        manifest = _load_sensitive_ingress_manifest()
        for array_name in (
            "sensitive_source_manifest",
            "privacy_capture_manifest",
            "response_root_manifest",
            "authorized_source_handle_response_manifest",
        ):
            pairs = [(e["document"], e["pointer"]) for e in manifest[array_name]]
            assert len(pairs) == len(set(pairs)), f"{array_name}: duplicate pairs {pairs}"

    def test_authorized_source_handle_response_manifest_is_empty_pending_producer(self) -> None:
        """PART1_CONTRACT_FREEZE_DRAFT.md:315/327-334 names
        dataset_schema.json#/properties/lifecycle_source_ref and
        evaluator_definition_schema.json#/properties/lifecycle_source_ref as
        the only legitimate StableSourceRef response carve-out, but neither
        property exists in this repo yet (grepped exhaustively). An empty
        list here is the correct, strict-by-default state, not a stray
        omission -- see this module's ALR-1107 header comment."""
        manifest = _load_sensitive_ingress_manifest()
        assert manifest["authorized_source_handle_response_manifest"] == []
        for document in (
            "datasets/dataset_schema.json",
            "observability/evaluator_definition_schema.json",
        ):
            data = _load_json(document)
            assert "lifecycle_source_ref" not in data.get("properties", {}), (
                f"{document} now defines lifecycle_source_ref -- "
                "authorized_source_handle_response_manifest must be updated "
                "in the same change, not left empty"
            )

    def test_privacy_capture_manifest_names_exactly_the_ten_declared_captures(self) -> None:
        manifest = _load_sensitive_ingress_manifest()
        names = {
            entry["pointer"].rsplit("/", 1)[-1] for entry in manifest["privacy_capture_manifest"]
        }
        assert names == {
            "validation_error_body",
            "structured_log",
            "application_log",
            "audit_log",
            "analytics_event",
            "telemetry_event",
            "export_row",
            "idempotency_storage",
            "idempotency_replay",
            "url",
        }


class TestPrivacyCaptureTargetsAreClosedAndHonest:
    """The separate targets file each privacy_capture_manifest pointer
    resolves into. Every entry is either schema_owned (backed by a real,
    walkable JSON Schema document this guard can check) or explicitly
    schema_owned=false with a named owner -- never silently vacuous."""

    def test_every_capture_target_is_a_closed_schema_owned_or_unmodeled_shape(self) -> None:
        targets = _load_privacy_capture_targets()["privacy_captures"]
        for name, target in targets.items():
            assert "schema_owned" in target, name
            if target["schema_owned"]:
                assert target.get("covered_by"), f"{name}: schema_owned but no covered_by"
                for covering in target["covered_by"]:
                    assert set(covering) == {"document", "pointer"}, (name, covering)
            else:
                assert target.get("owner"), f"{name}: schema_owned=false needs a real owner"

    def test_schema_owned_captures_are_exactly_validation_error_body_and_idempotency_replay(
        self,
    ) -> None:
        targets = _load_privacy_capture_targets()["privacy_captures"]
        schema_owned = {name for name, target in targets.items() if target["schema_owned"]}
        assert schema_owned == {"validation_error_body", "idempotency_replay"}

    def test_schema_unmodeled_captures_are_exactly_the_declared_set(self) -> None:
        """Anti-vacuity: if a later change silently marks one of the seven
        schema-unmodeled captures schema_owned=true without adding real
        covered_by backing, or adds a new capture without deciding its
        status, this fails -- forcing a conscious update rather than a
        silent claim of coverage this repo cannot back."""
        targets = _load_privacy_capture_targets()["privacy_captures"]
        unmodeled = {name for name, target in targets.items() if not target["schema_owned"]}
        assert unmodeled == set(_EXPECTED_SCHEMA_UNMODELED_CAPTURES) | {"url"}

    def test_url_target_declares_its_own_literal_path_templates(self) -> None:
        target = _load_privacy_capture_targets()["privacy_captures"]["url"]
        assert target["checked_via"] == "route_path_templates"
        assert target["path_templates"], "url capture must declare at least one path template"


def test_sensitive_ingress_manifest_has_no_unlisted_sink() -> None:
    """PART1_CONTRACT_FREEZE_DRAFT.md:492: the exact test name the contract
    names. Executes the finite source-by-response and source-by-capture
    products across all six declared sensitive sources, proving each
    cannot reach a log, telemetry, export, URL, or response sink -- to the
    extent this schema-only repo can structurally prove it (see this
    module's ALR-1107 header comment for exactly which sinks that is)."""
    manifest = _load_sensitive_ingress_manifest()
    sensitive_source_manifest = manifest["sensitive_source_manifest"]
    privacy_capture_manifest = manifest["privacy_capture_manifest"]
    response_root_manifest = manifest["response_root_manifest"]
    authorized = {
        (e["document"], e["pointer"])
        for e in manifest["authorized_source_handle_response_manifest"]
    }

    # --- coverage: every structurally-sensitive corpus position is declared,
    # and every declared position is real (row-17-style two-way equality).
    declared_sources = {(e["document"], e["pointer"]) for e in sensitive_source_manifest}
    scanned_sources = _scan_corpus_for_sensitive_positions()
    assert scanned_sources == declared_sources, (
        f"sensitive_source_manifest drift -- declared {declared_sources}, "
        f"scanned corpus has {scanned_sources}"
    )

    # --- source-by-response product: no response root may reach either
    # sensitive marker, except at an authorized position.
    response_leaks: list[tuple[str, str, tuple[str, str]]] = []
    for entry in response_root_manifest:
        document, pointer = entry["document"], entry["pointer"]
        node = _resolve_entry(document, pointer)
        reachable = _reachable_sensitive_markers(document, pointer, node)
        if reachable and (document, pointer) not in authorized:
            response_leaks.append((document, pointer, next(iter(reachable))))
    assert response_leaks == [], (
        f"sensitive shape reachable from a response root: {response_leaks}"
    )

    # --- source-by-capture product.
    targets = _load_privacy_capture_targets()["privacy_captures"]
    capture_leaks: list[tuple[str, tuple[str, str]]] = []
    for entry in privacy_capture_manifest:
        capture_name = entry["pointer"].rsplit("/", 1)[-1]
        target = targets[capture_name]
        if not target["schema_owned"]:
            continue
        for covering in target["covered_by"]:
            document, pointer = covering["document"], covering["pointer"]
            node = _resolve_entry(document, pointer)
            reachable = _reachable_sensitive_markers(document, pointer, node)
            if reachable:
                capture_leaks.append((capture_name, next(iter(reachable))))
    assert capture_leaks == [], (
        f"sensitive shape reachable from a privacy capture: {capture_leaks}"
    )

    # --- URL sink: closed path-parameter set, disjoint from every sensitive
    # source's own property-name fragment.
    url_target = targets["url"]
    placeholders: set[str] = set()
    for template in url_target["path_templates"]:
        placeholders |= set(_URL_PLACEHOLDER_RE.findall(template))
    assert placeholders == {"project_id", "run_plan_ref", "agent_revision_ref"}
    sensitive_names = _sensitive_property_name_fragments(sensitive_source_manifest)
    leaked_in_url = placeholders & sensitive_names
    assert leaked_in_url == set(), (
        f"sensitive property name(s) embedded in a URL template: {leaked_in_url}"
    )

    # --- schema-unmodeled captures stay honestly declared, not silently
    # claimed or silently dropped.
    unmodeled = {
        entry["pointer"].rsplit("/", 1)[-1]
        for entry in privacy_capture_manifest
        if not targets[entry["pointer"].rsplit("/", 1)[-1]]["schema_owned"]
    }
    assert unmodeled == set(_EXPECTED_SCHEMA_UNMODELED_CAPTURES) | {"url"}


# ---------------------------------------------------------------------------
# ALR-1107 poison-guard proofs (in-memory, permanent regression) -- mirrors
# TestDisclosurePoisonGuardsAreLoadBearing's shape: each demonstrates the
# guard is load-bearing by making a corrupted copy fail while the untouched
# original does not.
# ---------------------------------------------------------------------------


class TestSensitiveIngressPoisonGuardsAreLoadBearing:
    def test_leak_into_a_response_root_is_detected(self) -> None:
        """Canary: inject a RequestOnlyRandomLabel-shaped field into a copy
        of Route 5's response schema (a real response_root_manifest
        document) and prove the leak-detection primitive flags it. This is
        the in-memory permanent twin of the real ephemeral repo mutation
        exercised for the ALR-1107 story report."""
        document = "agent_lifecycle_record/agent_lifecycle_record_response_schema.json"
        mutated = _load_json(document)
        mutated["properties"]["debug_local_identity_echo"] = {
            "allOf": [
                {"$ref": "agent_lifecycle_common_schema.json#/definitions/RequestOnlyRandomLabel"}
            ]
        }
        schemas_cache = {document: mutated}
        visited: set[tuple[str, str]] = set()
        _iter_property_positions(document, "#", mutated, schemas_cache, visited)
        assert visited & _SENSITIVE_MARKERS, "mutation sanity check failed: canary did not leak"

    def test_clean_response_root_reaches_no_sensitive_marker(self) -> None:
        """Negative control for the canary above: the untouched document
        must NOT trip the same check."""
        document = "agent_lifecycle_record/agent_lifecycle_record_response_schema.json"
        node = _load_json(document)
        assert _reachable_sensitive_markers(document, "#", node) == set()

    def test_removing_a_sensitive_source_manifest_entry_breaks_coverage_equality(self) -> None:
        manifest = copy.deepcopy(_load_sensitive_ingress_manifest())
        removed = manifest["sensitive_source_manifest"].pop()
        declared = {(e["document"], e["pointer"]) for e in manifest["sensitive_source_manifest"]}
        scanned = _scan_corpus_for_sensitive_positions()
        assert (removed["document"], removed["pointer"]) in scanned
        assert declared != scanned

    def test_duplicate_privacy_capture_pair_is_detected(self) -> None:
        manifest = copy.deepcopy(_load_sensitive_ingress_manifest())
        manifest["privacy_capture_manifest"].append(
            dict(manifest["privacy_capture_manifest"][0])
        )
        pairs = [(e["document"], e["pointer"]) for e in manifest["privacy_capture_manifest"]]
        assert len(pairs) != len(set(pairs))

    def test_nonliteral_response_root_pointer_is_rejected(self) -> None:
        poisoned_entry = {
            "document": "agent_lifecycle_record/agent_lifecycle_record_response_schema.json",
            "pointer": "#/properties/*",
        }
        assert not _pointer_is_literal(poisoned_entry["pointer"])

    def test_manifest_pointing_at_a_nonexistent_document_is_rejected(self) -> None:
        poisoned_entry = {
            "document": (
                "agent_lifecycle_record/"
                "agent_lifecycle_qualification_register_response_schema.json"
            ),
            "pointer": "#",
        }
        assert not _resolve_document_path(poisoned_entry["document"]).is_file()

    def test_wrong_rooted_privacy_capture_pointer_is_rejected(self) -> None:
        """A pointer rooted at the wrong top-level key (a singular-typo
        '#/privacy_capture/url' instead of the real '#/privacy_captures/url')
        fails resolution rather than silently matching something else."""
        targets = _load_privacy_capture_targets()
        with pytest.raises(KeyError):
            _resolve_pointer(targets, "#/privacy_capture/url")
