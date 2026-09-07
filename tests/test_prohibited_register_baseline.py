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
import os
import shutil
import subprocess
import sys
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import fp2
from traigent_schema.certification import (
    PROHIBITED_REGISTER_BASELINE_DIGEST,
    PROHIBITED_REGISTER_BASELINE_PINNED_DIGEST,
    load_prohibited_register_baseline,
    prohibited_register,
)
from traigent_schema.certification.prohibited_register import (
    ProhibitedRegisterBaselineError,
    _reject_duplicate_keys,
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


def _load_json_strict(path: Path) -> dict:
    # Strict reader (finding R2): same duplicate-key-rejecting object_pairs_hook
    # the loader module uses, applied only to the register document/pin (the
    # same scope the production loader applies it in) -- so this test oracle
    # cannot be fooled by a shipped document that merely LOOKS unambiguous
    # under plain json.loads' last-wins duplicate-key handling. NOT used for
    # the generic multi-schema registry scan below: that walks every *.json
    # under schemas_dir for unrelated schemas outside this packet's scope.
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)


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
    return _load_json_strict(DOCUMENT_PATH)


@pytest.fixture(scope="module")
def pin() -> dict:
    return _load_json_strict(PIN_PATH)


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
        assert (
            document["schema_version"] == "traigent.certification.prohibited_register_baseline.v1"
        )
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


class TestLoadReturnsIndependentCopy:
    """(R1) ``load_prohibited_register_baseline()`` must not return the
    module's verified singleton. Before this fix it returned
    ``_BASELINE_DOCUMENT`` directly, so a caller mutating
    ``result["entries"][0]["text"]`` would corrupt what every later caller
    (and the module's own verified state) sees, even though both exported
    digests stayed unchanged.
    """

    def test_mutating_the_returned_document_does_not_leak_to_later_callers(self) -> None:
        first = load_prohibited_register_baseline()
        original_text = first["entries"][0]["text"]
        first["entries"][0]["text"] = "MUTATED-BY-TEST-SENTINEL-b7c1"
        first["entries"].append({"catalog_id": "x", "local_id": "y", "text": "z"})

        second = load_prohibited_register_baseline()
        assert second["entries"][0]["text"] == original_text
        assert len(second["entries"]) == 40
        assert second is not first

    def test_repeated_calls_return_distinct_objects(self) -> None:
        assert load_prohibited_register_baseline() is not load_prohibited_register_baseline()

    def test_module_does_not_expose_the_singleton_under_another_name(self) -> None:
        singleton = prohibited_register._BASELINE_DOCUMENT
        for name in dir(prohibited_register):
            if name.startswith("_"):
                continue
            value = getattr(prohibited_register, name)
            assert value is not singleton, name


class TestDuplicateKeysRejected:
    """(R2) A shipped document with a duplicated JSON member must not
    silently last-wins collapse into a document that parses, hashes, and
    validates as if it were unambiguous. Plain ``json.loads`` (used both by
    the pre-fix loader and by this test file's own reader) does exactly
    that; the factored reader (``prohibited_register._strict_json_loads``)
    must reject it instead, through the same content-free error path used
    for a digest mismatch or schema violation.
    """

    def test_duplicated_entries_member_rejected(self) -> None:
        sentinel = "SENTINEL-DUP-ENTRIES-4b1a"
        text = (
            "{"
            '"schema_version": "x", '
            f'"entries": [{{"text": "{sentinel}"}}], '
            '"entries": []'
            "}"
        )

        with pytest.raises(ProhibitedRegisterBaselineError) as excinfo:
            prohibited_register._strict_json_loads(text)

        exc = excinfo.value
        assert str(exc) == "PROHIBITED_REGISTER_BASELINE_INVALID"
        assert sentinel not in str(exc)
        assert exc.__cause__ is None
        assert exc.__context__ is None

    def test_duplicated_nested_text_member_rejected(self) -> None:
        sentinel = "SENTINEL-DUP-TEXT-9c2e"
        text = (
            "{"
            '"entries": [{'
            '"local_id": "CERT-P-1", '
            f'"text": "{sentinel}", '
            '"text": "other-value"'
            "}]"
            "}"
        )

        with pytest.raises(ProhibitedRegisterBaselineError) as excinfo:
            prohibited_register._strict_json_loads(text)

        exc = excinfo.value
        assert str(exc) == "PROHIBITED_REGISTER_BASELINE_INVALID"
        assert sentinel not in str(exc)
        assert exc.__cause__ is None
        assert exc.__context__ is None

    def test_document_without_duplicates_still_decodes(self, document: dict) -> None:
        # Control: the strict reader must not reject ordinary, unambiguous
        # JSON -- only content with an actual duplicate key.
        text = json.dumps(document)
        assert prohibited_register._strict_json_loads(text) == document


class TestSchemaPinsEachPositionToItsExactId:
    """(R3) Before this fix, ``entries`` was a homogeneous-``items`` array:
    every position accepted any pattern-matching ``CERT-P-<n>``, so a
    document with forty COPIES of the CERT-P-1 entry validated against the
    schema (only ``TestEntryIdentity``, which reads the real shipped
    document, would have caught the drift -- a synthetic all-CERT-P-1
    document would have PASSED schema validation at HEAD 6bda65e). The fix
    pins each array position to its own exact ``local_id`` via a
    ``prefixItems``-equivalent draft-07 ``items`` array + ``additionalItems:
    false``, so position 2 requiring CERT-P-2 now rejects a CERT-P-1 there.
    """

    def test_forty_copies_of_the_first_entry_fail_schema(
        self, document: dict, schema: dict, registry: Registry
    ) -> None:
        entry_one = document["entries"][0]
        forty_of_one = {**document, "entries": [dict(entry_one) for _ in range(40)]}

        validator = Draft7Validator(schema, registry=registry)
        errors = list(validator.iter_errors(forty_of_one))
        assert errors != [], "forty CERT-P-1 copies must fail positional schema validation"

    def test_schema_items_is_the_draft7_positional_array_form(self, schema: dict) -> None:
        # Guards against a future edit accidentally reverting to the
        # homogeneous single-schema ``items`` form this finding fixed.
        items = schema["properties"]["entries"]["items"]
        assert isinstance(items, list)
        assert len(items) == 40
        assert schema["properties"]["entries"]["additionalItems"] is False


class TestLocalIdRejectsTrailingNewline:
    """(R4) Under Python's ``re`` module, a pattern ending in ``$`` matches
    just before a trailing newline, so ``"CERT-P-1\\n"`` matched the old
    ``^CERT-P-([1-9]|[1-3][0-9]|40)$`` pattern. With R3's positional
    ``const``/enum in place the free-form pattern is redundant, so it was
    replaced with a closed enum of the 40 exact ids -- an enum does exact
    string equality, so a trailing newline no longer matches.
    """

    def test_trailing_newline_local_id_rejected(
        self, document: dict, schema: dict, registry: Registry
    ) -> None:
        mutated = {
            **document,
            "entries": [
                {**document["entries"][0], "local_id": "CERT-P-1\n"},
                *document["entries"][1:],
            ],
        }
        validator = Draft7Validator(schema, registry=registry)
        errors = list(validator.iter_errors(mutated))
        assert errors != []

    def test_local_id_definition_has_no_pattern_and_uses_enum(self, schema: dict) -> None:
        local_id_schema = schema["definitions"]["ProhibitedRegisterBaselineEntryV1"]["properties"][
            "local_id"
        ]
        assert "pattern" not in local_id_schema
        assert local_id_schema["enum"] == [f"CERT-P-{i}" for i in range(1, 41)]


class TestPinProvenanceFieldsAsserted:
    """(R5) The pin file's provenance fields (everything besides ``digest``)
    are operator-asserted metadata, NOT covered by the digest computation --
    see the loader module's "TRUST BOUNDARY" docstring section. This test
    only proves the shipped pin's provenance text has not silently drifted;
    it is not, and cannot be, proof that the provenance itself is true.
    """

    def test_provenance_fields_exact(self, pin: dict) -> None:
        assert pin["ratified_by"] == "owner"
        assert pin["ratified_on"] == "2026-09-07"
        assert (
            pin["decision_ref"]
            == "chat_decision:certified-agent-prohibited-register-ratify-A-20260907"
        )
        assert pin["spine_trail"] == "st_a7f607179358"
        assert (
            pin["source_document"]
            == "runs/response-comparison-debugging/prohibited-register-P1-P40-DRAFT.md"
        )
        assert pin["source_document_sha256"] == SOURCE_DOCUMENT_SHA256

    def test_trust_boundary_documented_in_loader_docstring(self) -> None:
        doc = prohibited_register.__doc__ or ""
        assert "TRUST BOUNDARY" in doc
        assert "operator-asserted" in doc


class TestImportBoundarySubprocess:
    """(R6) Every negative test above exercises ``_verify_baseline`` or
    ``_strict_json_loads`` directly -- all of them would keep passing even
    if the module-level ``_load_and_verify()`` call at import time were
    deleted. This copies the ``traigent_schema`` package into a temp
    directory, proves the PRISTINE copy imports cleanly in a fresh
    subprocess (control), then corrupts the copy and re-imports in another
    fresh subprocess, asserting the failure actually happens at the real
    import boundary. The control runs first, against the SAME temp copy
    before corruption, so a failure to import is attributable to the
    corruption and not to some unrelated breakage in the copy/env/PYTHONPATH
    (mirrors ``tests/test_process_record_verifier.py``'s
    ``test_importing_the_verifier_fails_when_shipped_registry_data_is_malformed``
    on branch ``agent/process-record-v1-integrated-20260905``).
    """

    @staticmethod
    def _copy_package(tmp_path: Path) -> tuple[Path, Path]:
        source_package = Path(str(resources.files("traigent_schema")))
        root = tmp_path / "root"
        root.mkdir()
        destination = root / "traigent_schema"
        shutil.copytree(source_package, destination, ignore=shutil.ignore_patterns("__pycache__"))
        return root, destination

    @staticmethod
    def _env(root: Path) -> dict:
        return {**os.environ, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"}

    @staticmethod
    def _run(code: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            cwd=str(cwd),
            capture_output=True,
            text=True,
        )

    def _assert_control_imports_cleanly(self, root: Path, destination: Path, env: dict) -> None:
        control = self._run(
            "import traigent_schema.certification.prohibited_register as m\nprint(m.__file__)\n",
            env,
            root,
        )
        assert control.returncode == 0, control.stderr
        assert Path(control.stdout.strip()).is_relative_to(destination), control.stdout

    def test_corrupted_document_fails_import_content_free(self, tmp_path: Path) -> None:
        root, destination = self._copy_package(tmp_path)
        env = self._env(root)

        # CONTROL: pristine copy, same interpreter/env/cwd as the treatment,
        # imported BEFORE any corruption.
        self._assert_control_imports_cleanly(root, destination, env)

        sentinel = "SENTINEL-SUBPROCESS-DOC-71ad"
        target = destination / "data" / "certification" / "prohibited_register_baseline.json"
        corrupted_doc = json.loads(target.read_text(encoding="utf-8"))
        corrupted_doc["entries"][0]["text"] = sentinel
        target.write_text(json.dumps(corrupted_doc, indent=2) + "\n", encoding="utf-8")

        imported = self._run(
            "import traigent_schema.certification.prohibited_register", env, root
        )
        assert imported.returncode != 0
        assert "ProhibitedRegisterBaselineError" in imported.stderr
        assert sentinel not in imported.stderr

        probe = (
            "import sys\n"
            "try:\n"
            "    import traigent_schema.certification.prohibited_register\n"
            "except Exception as exc:\n"
            "    assert type(exc).__name__ == 'ProhibitedRegisterBaselineError', "
            "type(exc).__name__\n"
            "    name = 'traigent_schema.certification.prohibited_register'\n"
            "    assert name not in sys.modules, 'partial module left in sys.modules'\n"
            "    print('CLEAN')\n"
            "    sys.exit(0)\n"
            "sys.exit(9)\n"
        )
        probed = self._run(probe, env, root)
        assert probed.returncode == 0, probed.stderr
        assert probed.stdout.strip() == "CLEAN"
        assert sentinel not in probed.stderr

    @pytest.mark.parametrize("corrupt", ["malformed_json", "missing_resource"])
    def test_other_corruptions_also_fail_import_content_free(
        self, tmp_path: Path, corrupt: str
    ) -> None:
        root, destination = self._copy_package(tmp_path)
        env = self._env(root)

        # CONTROL: pristine copy imports cleanly, before this case's corruption.
        self._assert_control_imports_cleanly(root, destination, env)

        target = destination / "data" / "certification" / "prohibited_register_baseline.json"
        sentinel = f"SENTINEL-{corrupt.upper()}-2f6c"
        if corrupt == "malformed_json":
            corrupted_text = target.read_text(encoding="utf-8") + "// " + sentinel
            target.write_text(corrupted_text, encoding="utf-8")
        elif corrupt == "missing_resource":
            target.unlink()
        else:  # pragma: no cover - parametrize guards this
            raise AssertionError(corrupt)

        imported = self._run(
            "import traigent_schema.certification.prohibited_register", env, root
        )
        assert imported.returncode != 0
        assert "ProhibitedRegisterBaselineError" in imported.stderr
        if corrupt == "malformed_json":
            assert sentinel not in imported.stderr

        # Attempt the failing import IN the probing interpreter and check
        # ``sys.modules`` in that same process: a fresh interpreter that never
        # imported the module would trivially satisfy an absence assertion.
        probe = (
            "import sys\n"
            "try:\n"
            "    import traigent_schema.certification.prohibited_register\n"
            "except Exception as exc:\n"
            "    assert type(exc).__name__ == 'ProhibitedRegisterBaselineError', "
            "type(exc).__name__\n"
            "    name = 'traigent_schema.certification.prohibited_register'\n"
            "    assert name not in sys.modules, 'partial module left in sys.modules'\n"
            "    print('CLEAN')\n"
            "    sys.exit(0)\n"
            "sys.exit(9)\n"
        )
        probed = self._run(probe, env, root)
        assert probed.returncode == 0, probed.stderr
        assert probed.stdout.strip() == "CLEAN"
        if corrupt == "malformed_json":
            assert sentinel not in probed.stderr
