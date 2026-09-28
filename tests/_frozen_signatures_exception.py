# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Shared guard for the disclosed exceptions to the frozen-v0 byte-identity
tests.

Exception 1 (owner ruling D-T4.1 = A, 2026-09-11):
``certificate_signatures_v0_schema.json`` may differ from a frozen-v0 anchor
ONLY in its top-level ``description`` (the v0 issuer signing key's custody
clause, reworded from GitHub-OIDC to AWS KMS non-exportable custody; C6
Ruling 4's invariant is restated verbatim).

``test_agent_quality_v1_schema.py``, ``test_evaluator_quality_v1_schema.py``,
and ``test_dataset_record_v1_schema.py`` each exclude this file from their own
frozen-v0 byte-identity loop and call :func:`assert_description_only_exception`
with their own anchor ref instead.

Exception 2 (owner ruling 2026-09-28, "1A"):
``certificate_claim_payloads_v0_schema.json`` may differ from a frozen-v0
anchor ONLY in its ``workload_class`` enum member and accompanying
``description``, and only by the exact verbatim rename pinned below
(``mock_grid_no_integrations_no_analytics_no_langfuse`` ->
``mock_grid_no_integrations_no_analytics_no_external_tracing``) -- a
competitor's product name must not appear in shipped source or contracts.
Rationale for exempting this one field rather than moving the whole file's
anchor: no issued certificate ever carried the old literal, and no consumer
references it -- ``git grep -in no_langfuse`` at ``origin/develop`` returns 0
hits in ``Traigent``, ``traigent-js``, ``TraigentFrontend``, and
``traigent-smartopt`` (verified 2026-09-28); ``TraigentBackend``'s
``origin/develop`` still has 2 hits (its own vendored copy of this schema, and
the ``WITNESSED_WORKLOAD_CLASS`` constant that stamps this value onto
witness-mode evidence), both already renamed on TraigentBackend#3569, which
this rename unblocks via ``contract.installed_package_agreement``.

``test_agent_quality_v1_schema.py`` and ``test_evaluator_quality_v1_schema.py``
(the only two files whose frozen-v0 loop globs the certification directory
broadly enough to reach this file) exclude it from their byte-identity loop
and call :func:`assert_workload_class_rename_exception` with their own anchor
ref instead. This module is the one place either exception is implemented.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

SIGNATURES_REL = "traigent_schema/schemas/certification/certificate_signatures_v0_schema.json"
#: SHA-256 of SIGNATURES_REL after its sole disclosed edit. Catches ANY
#: further edit, including another description change, until deliberately
#: moved again for a new disclosed ruling.
SIGNATURES_SHA256 = "683f378ffc36c6ff650a00426279a30726b43237a58ec0489b988bfba2657671"

CLAIM_PAYLOADS_REL = (
    "traigent_schema/schemas/certification/certificate_claim_payloads_v0_schema.json"
)
#: SHA-256 of CLAIM_PAYLOADS_REL after its sole disclosed edit (the
#: workload_class enum member + description rename below). Catches ANY
#: further edit, until deliberately moved again for a new disclosed ruling.
CLAIM_PAYLOADS_SHA256 = "7a542ad0b0813f8e5e4fbc2c7333934bf71f33148ae88e271bdad726d004dd4b"

#: JSON Pointer (as a tuple of keys/indices) to the one field Exception 2
#: covers, resolved against the raw file (``allOf[0]`` is a
#: ``$ref: "#/definitions/ClaimPayloadV0"`` in the raw JSON; the equivalent
#: reference-resolved pointer breaking_schema_check.py reports is
#: ``#/allOf/0/oneOf/3/properties/params/properties/workload_class``):
#: ``#/definitions/ClaimPayloadD2V0/properties/params/properties/workload_class``.
_WORKLOAD_CLASS_POINTER: tuple[str | int, ...] = (
    "definitions",
    "ClaimPayloadD2V0",
    "properties",
    "params",
    "properties",
    "workload_class",
)
#: The field's content at the frozen-v0 anchor, before the disclosed rename --
#: pinned as data, the same way SIGNATURES_SHA256 pins a whole-file digest.
_WORKLOAD_CLASS_OLD: dict[str, object] = {
    "description": (
        "Closed workload-class vocabulary. The only witnessed class today is "
        "the mock-mode grid-search shape with no integrations, no analytics "
        "clients, and no Langfuse (the truth-test scope, carried verbatim as "
        "the class definition)."
    ),
    "type": "string",
    "enum": ["mock_grid_no_integrations_no_analytics_no_langfuse"],
}
#: The field's content after the disclosed rename. Same concept as the OLD
#: pin above (mock-mode grid-search shape with no integrations, no analytics
#: clients, no external tracing client); only the vendor-specific token is
#: replaced with a neutral, generic one.
_WORKLOAD_CLASS_NEW: dict[str, object] = {
    "description": (
        "Closed workload-class vocabulary. The only witnessed class today is "
        "the mock-mode grid-search shape with no integrations, no analytics "
        "clients, and no external tracing client (the truth-test scope, "
        "carried verbatim as the class definition)."
    ),
    "type": "string",
    "enum": ["mock_grid_no_integrations_no_analytics_no_external_tracing"],
}


def _commit_is_reachable(ref: str, repo_root: Path) -> bool:
    """Whether ``ref`` resolves to a commit object this clone actually has.

    A shallow checkout (the workspace's ``test`` CI job's default
    ``fetch-depth``) has no object for a historical anchor at all; matching on
    ``git show``'s stderr text for that case is backwards, since a shallow
    checkout produces the unrelated-sounding "path exists on disk, but not in
    '<ref>'" rather than an "unknown revision" error.
    """

    result = subprocess.run(
        ["git", "cat-file", "-e", f"{ref}^{{commit}}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _git_show(ref: str, rel_path: str, repo_root: Path) -> bytes | None:
    """The blob at ``ref``, or ``None`` when the commit is not in this clone.

    ``None`` only when the commit object itself is absent (a shallow CI
    checkout). Once the commit is confirmed present, any further git failure
    is raised, since that is a real finding rather than something to skip.
    """

    if not _commit_is_reachable(ref, repo_root):
        return None
    result = subprocess.run(
        ["git", "show", f"{ref}:{rel_path}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout
    stderr = result.stderr.decode("utf-8", "replace")
    raise AssertionError(f"git show {ref}:{rel_path} failed unexpectedly: {stderr}")


def assert_description_only_exception(anchor_ref: str, repo_root: Path) -> None:
    """The sha256 pin catches any further edit; the structural comparison
    catches an edit that happens to preserve the pinned sha256's length but
    changes a keyword, required field, or shape. Skips (rather than fails) if
    ``anchor_ref`` is unreachable, e.g. a shallow CI checkout.
    """

    current_bytes = (repo_root / SIGNATURES_REL).read_bytes()
    assert hashlib.sha256(current_bytes).hexdigest() == SIGNATURES_SHA256, (
        f"{SIGNATURES_REL} no longer matches the disclosed exception's pin"
    )

    anchor_bytes = _git_show(anchor_ref, SIGNATURES_REL, repo_root)
    if anchor_bytes is None:
        pytest.skip(f"anchor {anchor_ref} is not in this clone (shallow checkout)")

    current = json.loads(current_bytes)
    anchor = json.loads(anchor_bytes)
    del current["description"]
    del anchor["description"]
    assert current == anchor, (
        f"{SIGNATURES_REL} differs from {anchor_ref} by more than its description"
    )


def _get_pointer(doc: object, pointer: tuple[str | int, ...]) -> object:
    node = doc
    for key in pointer:
        node = node[key]  # type: ignore[index]
    return node


def _without_pointer(doc: object, pointer: tuple[str | int, ...]) -> object:
    """A deep copy of ``doc`` with the field at ``pointer`` removed, so the
    surrounding structure can still be compared for exact equality."""

    doc = copy.deepcopy(doc)
    node = doc
    for key in pointer[:-1]:
        node = node[key]  # type: ignore[index]
    del node[pointer[-1]]  # type: ignore[arg-type]
    return doc


def assert_workload_class_rename_exception(anchor_ref: str, repo_root: Path) -> None:
    """Exception 2 (owner ruling 2026-09-28, "1A"): CLAIM_PAYLOADS_REL may
    differ from a frozen-v0 anchor ONLY in its ``workload_class`` field, and
    only by the exact old->new rename pinned above. The sha256 pin catches
    any further edit to the file; the OLD/NEW dict pins catch a "rename" that
    isn't actually this exact, disclosed rename; the structural comparison
    (with that one field removed from both sides) catches any other drift in
    the rest of the document. Skips (rather than fails) if ``anchor_ref`` is
    unreachable, e.g. a shallow CI checkout.
    """

    current_bytes = (repo_root / CLAIM_PAYLOADS_REL).read_bytes()
    assert hashlib.sha256(current_bytes).hexdigest() == CLAIM_PAYLOADS_SHA256, (
        f"{CLAIM_PAYLOADS_REL} no longer matches the disclosed exception's pin"
    )

    anchor_bytes = _git_show(anchor_ref, CLAIM_PAYLOADS_REL, repo_root)
    if anchor_bytes is None:
        pytest.skip(f"anchor {anchor_ref} is not in this clone (shallow checkout)")

    current = json.loads(current_bytes)
    anchor = json.loads(anchor_bytes)

    current_field = _get_pointer(current, _WORKLOAD_CLASS_POINTER)
    anchor_field = _get_pointer(anchor, _WORKLOAD_CLASS_POINTER)
    assert current_field == _WORKLOAD_CLASS_NEW, (
        f"{CLAIM_PAYLOADS_REL}'s workload_class field no longer matches the disclosed NEW pin"
    )
    assert anchor_field == _WORKLOAD_CLASS_OLD, (
        f"{anchor_ref}:{CLAIM_PAYLOADS_REL}'s workload_class field no longer "
        "matches the disclosed OLD pin"
    )

    current_rest = _without_pointer(current, _WORKLOAD_CLASS_POINTER)
    anchor_rest = _without_pointer(anchor, _WORKLOAD_CLASS_POINTER)
    assert current_rest == anchor_rest, (
        f"{CLAIM_PAYLOADS_REL} differs from {anchor_ref} by more than the "
        "disclosed workload_class rename"
    )
