# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Shared guard for the one disclosed exception to the frozen-v0 byte-identity
tests (owner ruling D-T4.1 = A, 2026-09-11): ``certificate_signatures_v0_schema.json``
may differ from a frozen-v0 anchor ONLY in its top-level ``description`` (the
v0 issuer signing key's custody clause, reworded from GitHub-OIDC to AWS KMS
non-exportable custody; C6 Ruling 4's invariant is restated verbatim).

``test_agent_quality_v1_schema.py``, ``test_evaluator_quality_v1_schema.py``,
and ``test_dataset_record_v1_schema.py`` each exclude this file from their own
frozen-v0 byte-identity loop and call :func:`assert_description_only_exception`
with their own anchor ref instead. This module is the one place the exception
is implemented.
"""

from __future__ import annotations

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
