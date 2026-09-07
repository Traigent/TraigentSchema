# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the prohibited-claims register baseline (P-1..P-40).

The register document (``traigent_schema/data/certification/
prohibited_register_baseline.json``) and its CI pin (the sibling
``.digest.json``) are the owner-ratified transcription of
``runs/response-comparison-debugging/prohibited-register-P1-P40-DRAFT.md``
(decision A, 2026-09-07). These tests exist to catch the 2026-08-23 collision
class this whole register was designed against: TWO different 40-row
registers, both numbered P-1..P-40 (this compiler register, and an unrelated
GTM/competitive-claims register in ``research/step2-committee-report.md``
Section 5), so a document that merely has the right SHAPE (40 entries,
CERT-P-1..CERT-P-40, valid schema) is not evidence it has the right CONTENT.
The pin file's digest is what catches content substitution; the schema only
catches shape. See test (f) below.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import fp2
from traigent_schema.certification import (
    PROHIBITED_REGISTER_BASELINE_DIGEST,
    PROHIBITED_REGISTER_BASELINE_PINNED_DIGEST,
    load_prohibited_register_baseline,
)
from traigent_schema.certification.prohibited_register import (
    ProhibitedRegisterBaselineError,
    _verify_baseline,
)
from traigent_schema.utils import get_schemas_dir

# schemas_dir / "certification" / "..." literal, so this schema is not flagged
# as an unreferenced orphan by tests/test_schemas.py::TestOrphanSchemas.
schemas_dir = get_schemas_dir()
SCHEMA_PATH = schemas_dir / "certification" / "prohibited_register_baseline_v1_schema.json"

DATA_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "data" / "certification"
DOCUMENT_PATH = DATA_DIR / "prohibited_register_baseline.json"
PIN_PATH = DATA_DIR / "prohibited_register_baseline.digest.json"

SOURCE_DOCUMENT_SHA256 = "10412328ce256599b150dfa87b67109ad79bf540b5f68da81db5bfb625e5898f"

# sha256 of the 40 "Prohibited sentence form" texts, joined by "\n" in P-1..P-40
# order, computed ONCE directly from
# runs/response-comparison-debugging/prohibited-register-P1-P40-DRAFT.md (the
# same digest as TraigentBackend's stale PROHIBITED_REGISTER_BASELINE_ENTRIES
# tuple at commit 47a87f5bb86ba3e86ce1f108aac58bdfbff2fbdb -- see test (h)).
# This is a fixed test oracle, independent of both the shipped document and
# the loader; it is not read from either.
DRAFT_TEXTS_JOINED_SHA256 = "50cfd04e63204287c67d95e692dae47aa195cebbe9b6d27082dbe93703752964"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in schemas_dir.rglob("*.json"):
        document = _load_json(path)
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


def _oracle_digest(document: object) -> str:
    """An independent re-implementation of the pin's digest construction.

    Does NOT call the loader's digest function
    (``prohibited_register.PROHIBITED_REGISTER_BASELINE_DIGEST`` /
    ``_plain_digest``) -- this is the CI pin oracle, so it must be able to
    catch a bug in the loader's own digest computation, not just agree with
    it by construction.
    """
    canonical = fp2.canonicalize(document).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


@pytest.fixture(scope="module")
def document() -> dict:
    return _load_json(DOCUMENT_PATH)


@pytest.fixture(scope="module")
def pin() -> dict:
    return _load_json(PIN_PATH)


@pytest.fixture(scope="module")
def schema() -> dict:
    return _load_json(SCHEMA_PATH)


@pytest.fixture(scope="module")
def registry() -> Registry:
    return _registry()


class TestDocumentValidatesAgainstSchema:
    def test_document_validates(self, document: dict, schema: dict, registry: Registry) -> None:
        validator = Draft7Validator(schema, registry=registry)
        errors = list(validator.iter_errors(document))
        assert errors == [], [e.message for e in errors]

    def test_schema_itself_is_valid_draft7(self, schema: dict) -> None:
        Draft7Validator.check_schema(schema)

    def test_shape_fields_fixed(self, document: dict) -> None:
        assert document["schema_version"] == "traigent.certification.prohibited_register_baseline.v1"
        assert document["hash_algorithm"] == "sha256"
        assert document["closed"] is True
        assert document["baseline_size"] == 40
        assert document["entry_count"] == 40
        assert len(document["entries"]) == 40


class TestPinDigestIsTheOracle:
    """(b) The independently-recomputed digest is the CI pin -- not the loader's."""

    def test_recomputed_digest_matches_pin(self, document: dict, pin: dict) -> None:
        assert _oracle_digest(document) == pin["digest"]

    def test_pin_digest_shape(self, pin: dict) -> None:
        assert pin["digest"].startswith("sha256:")
        assert len(pin["digest"]) == len("sha256:") + 64
        int(pin["digest"][len("sha256:") :], 16)  # must be valid hex

    def test_pin_source_document_sha256(self, pin: dict) -> None:
        # (j)
        assert pin["source_document_sha256"] == SOURCE_DOCUMENT_SHA256
        assert pin["source_document_sha256"] == pin["source_document_sha256"].lower()


class TestLoaderAgreesWithPin:
    """(c) computed == PROHIBITED_REGISTER_BASELINE_DIGEST == pinned."""

    def test_loader_module_digest_equals_pin(self, pin: dict) -> None:
        assert PROHIBITED_REGISTER_BASELINE_DIGEST == pin["digest"]
        assert PROHIBITED_REGISTER_BASELINE_PINNED_DIGEST == pin["digest"]
        assert PROHIBITED_REGISTER_BASELINE_DIGEST == PROHIBITED_REGISTER_BASELINE_PINNED_DIGEST

    def test_oracle_digest_equals_loader_digest(self, document: dict) -> None:
        assert _oracle_digest(document) == PROHIBITED_REGISTER_BASELINE_DIGEST

    def test_load_prohibited_register_baseline_returns_the_shipped_document(
        self, document: dict
    ) -> None:
        assert load_prohibited_register_baseline() == document


class TestDigestIsSensitiveToContent:
    """(d)/(e): the pin -- not the schema -- is what catches a wrong register."""

    def test_altering_one_character_changes_the_digest(self, document: dict, pin: dict) -> None:
        import copy

        mutated = copy.deepcopy(document)
        mutated["entries"][0]["text"] = mutated["entries"][0]["text"] + "!"
        assert _oracle_digest(mutated) != pin["digest"]

    def test_swapping_two_entries_changes_the_digest(self, document: dict, pin: dict) -> None:
        import copy

        mutated = copy.deepcopy(document)
        mutated["entries"][0]["text"], mutated["entries"][1]["text"] = (
            mutated["entries"][1]["text"],
            mutated["entries"][0]["text"],
        )
        assert _oracle_digest(mutated) != pin["digest"]

    def test_foreign_register_validates_shape_but_fails_digest(
        self, document: dict, schema: dict, registry: Registry, pin: dict
    ) -> None:
        """(f) A same-shape foreign 40-entry register is schema-valid, digest-wrong.

        This is the exact collision class the module docstring calls out:
        two different 40-row P-1..P-40 registers cannot be told apart by
        shape alone. Only the pin catches it.
        """
        foreign = {
            **document,
            "entries": [
                {
                    "catalog_id": document["catalog_id"],
                    "local_id": f"CERT-P-{i}",
                    "text": f"Synthetic foreign claim sentence number {i}, unrelated to the "
                    "ratified register, used only to exercise the digest-vs-schema "
                    "distinction in this test.",
                }
                for i in range(1, 41)
            ],
        }
        validator = Draft7Validator(schema, registry=registry)
        assert list(validator.iter_errors(foreign)) == []
        assert _oracle_digest(foreign) != pin["digest"]


class TestEntryIdentity:
    """(g) local_ids are exactly CERT-P-1..CERT-P-40, in order, unique."""

    def test_local_ids_in_order(self, document: dict) -> None:
        expected = [f"CERT-P-{i}" for i in range(1, 41)]
        actual = [entry["local_id"] for entry in document["entries"]]
        assert actual == expected

    def test_local_ids_unique(self, document: dict) -> None:
        local_ids = [entry["local_id"] for entry in document["entries"]]
        assert len(set(local_ids)) == len(local_ids)

    def test_entry_count_matches_len_and_declared_size(self, document: dict) -> None:
        assert document["entry_count"] == len(document["entries"]) == 40
        assert document["baseline_size"] == 40


class TestCrossCheckAgainstDraft:
    """(h) The 40 texts equal the DRAFT (and the stale Backend-branch tuple)."""

    def test_texts_match_draft_oracle_digest(self, document: dict) -> None:
        texts = [entry["text"] for entry in document["entries"]]
        joined_digest = hashlib.sha256("\n".join(texts).encode("utf-8")).hexdigest()
        assert joined_digest == DRAFT_TEXTS_JOINED_SHA256


class TestImportTimeMismatchIsContentFree:
    """(i) A document whose digest != pin raises the content-free error.

    Exercises the loader's own boundary function, ``_verify_baseline``,
    directly -- not the module import (which cannot be re-triggered per-test)
    -- with a synthetic document carrying a sentinel string, and asserts the
    sentinel appears NOWHERE in the raised exception: not in its message, not
    in its args, and not in its exception chain (``__cause__``/``__context__``).
    """

    def test_mismatched_digest_raises_content_free(
        self, document: dict, schema: dict, registry: Registry
    ) -> None:
        sentinel = "SENTINEL-DO-NOT-LEAK-93f7c1"
        planted = {
            **document,
            "entries": [
                {**document["entries"][0], "text": sentinel},
                *document["entries"][1:],
            ],
        }
        wrong_pin = "sha256:" + "0" * 64

        with pytest.raises(ProhibitedRegisterBaselineError) as excinfo:
            _verify_baseline(planted, schema, registry, wrong_pin)

        exc = excinfo.value
        assert str(exc) == "PROHIBITED_REGISTER_BASELINE_INVALID"
        assert sentinel not in str(exc)
        assert exc.args == ("PROHIBITED_REGISTER_BASELINE_INVALID",)
        assert exc.__cause__ is None
        assert exc.__context__ is None

        chain_text = "".join(str(a) for a in exc.args)
        node: BaseException | None = exc
        seen = 0
        while node is not None and seen < 10:
            chain_text += str(node)
            node = node.__cause__ or node.__context__
            seen += 1
        assert sentinel not in chain_text

    def test_schema_violation_also_raises_content_free(
        self, document: dict, schema: dict, registry: Registry, pin: dict
    ) -> None:
        sentinel = "SENTINEL-SCHEMA-VIOLATION-2b91"
        broken = {**document, "entries": [*document["entries"], {"extra": sentinel}]}

        with pytest.raises(ProhibitedRegisterBaselineError) as excinfo:
            _verify_baseline(broken, schema, registry, pin["digest"])

        exc = excinfo.value
        assert sentinel not in str(exc)
        assert exc.__cause__ is None
        assert exc.__context__ is None

    def test_matching_digest_returns_it(
        self, document: dict, schema: dict, registry: Registry, pin: dict
    ) -> None:
        assert _verify_baseline(document, schema, registry, pin["digest"]) == pin["digest"]
