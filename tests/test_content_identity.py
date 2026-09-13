# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the R3 dataset-version content digest and evaluator
judge-config digest: schemas/datasets/dataset_version_schema.json,
schemas/observability/evaluator_version_schema.json, and the additive
`current_version` field on dataset_schema.json and
observability/evaluator_definition_schema.json.

Both contracts are additive and optional: old readers unaware of
`content_digest` / `judge_config_digest` / `current_version` are unaffected,
and every one of those fields accepts `null` for legacy records. Nothing in
the certification family's process-record V1 digest-domain registry changes.

The judge_config_digest preimage is pinned to the real persisted object: the
observability EvaluatorDefinition's `judge_config` field
(observability/evaluator_definition_schema.json#/definitions/JudgeConfig),
NOT the datasets-bucket evaluator_config_schema.json resource, which is a
different resource this contract does not touch.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traigent_schema import (
    DATASET_VERSION_CONTENT_DIGEST_DOMAIN,
    EVALUATOR_JUDGE_CONFIG_DIGEST_DOMAIN,
    SchemaValidator,
    compute_dataset_version_content_digest,
    compute_judge_config_digest,
)
from traigent_schema.content_identity import _role_digest
from traigent_schema.utils import get_schemas_dir

ROOT = Path(__file__).resolve().parents[1]
_VECTORS_PATH = ROOT / "tests" / "data" / "content_identity_vectors.json"
VECTORS = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))
DATASETS_DIR = get_schemas_dir() / "datasets"
OBSERVABILITY_DIR = get_schemas_dir() / "observability"
CERTIFICATION_DIR = get_schemas_dir() / "certification"


def _load(directory: Path, name: str) -> dict:
    with open(directory / name, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# Digest domain constants match the schema's own "const" declarations.
# --------------------------------------------------------------------------


def test_dataset_version_digest_domain_matches_schema_const():
    schema = _load(DATASETS_DIR, "dataset_version_schema.json")
    domain_def = schema["definitions"]["DatasetVersionContentDigestDomainV1"]
    assert domain_def["const"] == DATASET_VERSION_CONTENT_DIGEST_DOMAIN


def test_evaluator_judge_config_digest_domain_matches_schema_const():
    schema = _load(OBSERVABILITY_DIR, "evaluator_version_schema.json")
    domain_def = schema["definitions"]["EvaluatorJudgeConfigDigestDomainV1"]
    assert domain_def["const"] == EVALUATOR_JUDGE_CONFIG_DIGEST_DOMAIN


# --------------------------------------------------------------------------
# Golden vectors: same set -> same digest, one-byte change -> different
# digest, reordered input -> same digest (sorting is part of the projection).
# --------------------------------------------------------------------------


_DATASET_VERSION_VECTORS = VECTORS["dataset_version_content_digest_vectors"]


@pytest.mark.parametrize("vector", _DATASET_VERSION_VECTORS, ids=lambda v: v["name"])
def test_dataset_version_content_digest_golden_vectors(vector):
    assert compute_dataset_version_content_digest(vector["preimage"]) == vector["expected_digest"]


def test_dataset_version_content_digest_reordering_is_a_noop():
    vectors = {v["name"]: v for v in VECTORS["dataset_version_content_digest_vectors"]}
    baseline = vectors["two_example_set"]
    reordered = vectors["two_example_set_reordered"]
    assert baseline["expected_digest"] == reordered["expected_digest"]
    baseline_digest = compute_dataset_version_content_digest(baseline["preimage"])
    reordered_digest = compute_dataset_version_content_digest(reordered["preimage"])
    assert baseline_digest == reordered_digest


def test_dataset_version_content_digest_one_byte_change_differs():
    vectors = {v["name"]: v for v in VECTORS["dataset_version_content_digest_vectors"]}
    baseline = vectors["two_example_set"]
    changed = vectors["two_example_set_one_byte_change"]
    assert baseline["expected_digest"] != changed["expected_digest"]


def test_dataset_version_content_digest_duplicate_ids_are_preserved_not_collapsed():
    vectors = {v["name"]: v for v in VECTORS["dataset_version_content_digest_vectors"]}
    dup = vectors["duplicate_example_ids"]
    single = [dup["preimage"][0]]
    # The duplicate-id set's digest must differ from either half alone: both
    # rows survive into the hashed preimage.
    dup_digest = compute_dataset_version_content_digest(dup["preimage"])
    single_digest = compute_dataset_version_content_digest(single)
    assert dup_digest != single_digest


def test_dataset_version_content_digest_duplicate_id_tie_break_is_content_not_position():
    """F1 regression: same example_id, different content, opposite input
    order -> SAME digest. The tie-break for rows sharing an example_id is the
    jcs_v1 bytes of each row's own projection, never producer enumeration
    order -- a stable sort keyed on example_id alone (the pre-fix behaviour)
    would make these two orderings hash differently."""
    vectors = {v["name"]: v for v in VECTORS["dataset_version_content_digest_vectors"]}
    forward = vectors["duplicate_example_ids"]
    reversed_input = vectors["duplicate_ids_reversed_input_same_digest"]
    assert forward["expected_digest"] == reversed_input["expected_digest"]
    forward_digest = compute_dataset_version_content_digest(forward["preimage"])
    reversed_digest = compute_dataset_version_content_digest(reversed_input["preimage"])
    assert forward_digest == reversed_digest
    assert forward_digest == forward["expected_digest"]


def test_dataset_version_content_digest_sorts_by_utf16_code_unit_not_codepoint():
    """example_id order is UTF-16 code-unit ascending (spec, jcs_v1, JS
    default sort()), not Python's default code-point order -- the two
    disagree on a surrogate-pair id vs a BMP id above U+D800."""
    vectors = {v["name"]: v for v in VECTORS["dataset_version_content_digest_vectors"]}
    vector = vectors["sort_order_utf16_vs_codepoint"]

    # The public function always sorts internally, so argument order is a
    # no-op and must match the frozen golden digest either way.
    assert compute_dataset_version_content_digest(vector["preimage"]) == vector["expected_digest"]
    assert (
        compute_dataset_version_content_digest(list(reversed(vector["preimage"])))
        == vector["expected_digest"]
    )

    # Bypass the function's own sort to prove which ordering the digest
    # actually corresponds to: hash the two projected rows directly, once in
    # UTF-16 code-unit order (U+1F600 first) and once in code-point order
    # (U+FF21 first, since 0xFF21 < 0x1F600 as raw code points).
    utf16_order_projected = [
        {"input_text": "a", "expected_output": None},
        {"input_text": "b", "expected_output": None},
    ]
    codepoint_order_projected = [
        {"input_text": "b", "expected_output": None},
        {"input_text": "a", "expected_output": None},
    ]
    utf16_order_digest = _role_digest(DATASET_VERSION_CONTENT_DIGEST_DOMAIN, utf16_order_projected)
    codepoint_order_digest = _role_digest(
        DATASET_VERSION_CONTENT_DIGEST_DOMAIN, codepoint_order_projected
    )
    assert utf16_order_digest == vector["expected_digest"]
    assert codepoint_order_digest != vector["expected_digest"]


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("example_id", 123),
        ("input_text", ["ok", 5]),
        ("expected_output", 42),
    ],
)
def test_dataset_version_content_digest_rejects_wrong_types(field, bad_value):
    example = {"example_id": "ex-1", "input_text": "hi", "expected_output": "ok"}
    example[field] = bad_value
    with pytest.raises(TypeError, match=field):
        compute_dataset_version_content_digest([example])


def test_dataset_version_content_digest_rejects_missing_example_id():
    with pytest.raises(TypeError, match="example_id"):
        compute_dataset_version_content_digest([{"input_text": "hi"}])


@pytest.mark.parametrize(
    "bad_row",
    ["bad", 5],
    ids=["string_row", "int_row"],
)
def test_dataset_version_content_digest_rejects_non_mapping_row(bad_row):
    """F2 regression: a non-mapping row must raise the documented TypeError,
    not an AttributeError from calling .get() on a non-dict (e.g. 'bad'.get()
    raised AttributeError on the pre-fix implementation)."""
    with pytest.raises(TypeError, match="mapping"):
        compute_dataset_version_content_digest([bad_row])  # type: ignore[list-item]


def test_dataset_version_content_digest_rejects_bare_mapping_as_preimage():
    """F2 regression: a bare dict passed as the whole preimage (instead of a
    list of per-example mappings) must not silently iterate its keys as
    example_ids -- it must raise TypeError."""
    with pytest.raises(TypeError, match="sequence"):
        compute_dataset_version_content_digest({"example_id": "ex-1"})  # type: ignore[arg-type]


def test_dataset_version_content_digest_rejects_string_preimage():
    """F2 regression: a string preimage is technically a Sequence[str] in
    Python and must be rejected, not iterated character-by-character."""
    with pytest.raises(TypeError, match="sequence"):
        compute_dataset_version_content_digest("not-a-list")  # type: ignore[arg-type]


@pytest.mark.parametrize("vector", VECTORS["judge_config_digest_vectors"], ids=lambda v: v["name"])
def test_judge_config_digest_golden_vectors(vector):
    assert compute_judge_config_digest(vector["judge_config"]) == vector["expected_digest"]


def test_judge_config_digest_is_key_order_independent():
    vectors = {v["name"]: v for v in VECTORS["judge_config_digest_vectors"]}
    baseline = vectors["baseline_config"]
    permuted = vectors["baseline_config_key_order_permuted"]
    assert baseline["expected_digest"] == permuted["expected_digest"]


def test_judge_config_digest_value_change_differs():
    vectors = {v["name"]: v for v in VECTORS["judge_config_digest_vectors"]}
    baseline = vectors["baseline_config"]
    changed = vectors["baseline_config_value_changed"]
    assert baseline["expected_digest"] != changed["expected_digest"]


def test_judge_config_digest_absent_key_differs_from_null_value():
    """{"context_source": null} must differ from {} -- absence != null."""
    vectors = {v["name"]: v for v in VECTORS["judge_config_digest_vectors"]}
    baseline = vectors["baseline_config"]
    with_null = vectors["baseline_config_context_source_null_added"]
    assert baseline["expected_digest"] != with_null["expected_digest"]


def test_judge_config_digest_rejects_non_mapping():
    with pytest.raises(TypeError, match="Mapping"):
        compute_judge_config_digest(["not", "a", "mapping"])  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Schema shape: both fields are optional/additive; null is a valid legacy
# marker; the digest pattern is a closed sha256:<hex> form.
# --------------------------------------------------------------------------


def test_dataset_version_content_digest_field_is_optional_and_nullable():
    schema = _load(DATASETS_DIR, "dataset_version_schema.json")
    version = schema["definitions"]["DatasetVersionV1"]
    assert "content_digest" not in version["required"]
    field = version["properties"]["content_digest"]
    kinds = {branch.get("type") for branch in field["oneOf"]}
    assert kinds == {"string", "null"}
    assert field["default"] is None


def test_evaluator_judge_config_digest_field_is_optional_and_nullable():
    schema = _load(OBSERVABILITY_DIR, "evaluator_version_schema.json")
    version = schema["definitions"]["EvaluatorVersionV1"]
    assert "judge_config_digest" not in version["required"]
    field = version["properties"]["judge_config_digest"]
    kinds = {branch.get("type") for branch in field["oneOf"]}
    assert kinds == {"string", "null"}
    assert field["default"] is None


def test_dataset_current_version_is_optional_and_additive():
    schema = _load(DATASETS_DIR, "dataset_schema.json")
    assert "current_version" not in schema["required"]
    field = schema["properties"]["current_version"]
    assert {"null"} <= {branch.get("type") for branch in field["oneOf"] if "type" in branch}
    assert field["default"] is None
    assert schema["required"] == [
        "id",
        "name",
        "label",
        "description",
        "type",
        "examples_count",
    ]


def test_evaluator_config_schema_has_no_current_version():
    """current_version was moved to observability/evaluator_definition_schema.json
    (P1-1c): the datasets-bucket evaluator_config resource is a different
    resource from the observability EvaluatorDefinition this contract pins,
    so it does not carry this field."""
    schema = _load(DATASETS_DIR, "evaluator_config_schema.json")
    assert "current_version" not in schema["properties"]
    assert schema["required"] == [
        "id",
        "model_parameters_id",
        "instructions",
        "context_type",
        "context_source",
    ]


def test_evaluator_definition_current_version_is_optional_and_additive():
    schema = _load(OBSERVABILITY_DIR, "evaluator_definition_schema.json")
    field = schema["properties"]["current_version"]
    assert {"null"} <= {branch.get("type") for branch in field["oneOf"] if "type" in branch}
    assert field["default"] is None
    # additionalProperties: true means this addition cannot be BREAKING for
    # old validating readers of this schema.
    assert schema["additionalProperties"] is True
    assert "current_version" not in schema["required"]


def test_process_record_v1_digest_domain_registry_is_unchanged_by_this_change():
    """Explicit compatibility statement: this change adds no member to, and
    otherwise does not touch, the process-record V1 family's own registry."""
    schema = _load(CERTIFICATION_DIR, "process_record_v1_schema.json")
    registry = schema["definitions"]["ProcessRecordDigestDomainRegistryV1"]
    assert "dataset_version" not in registry["required"]
    assert "evaluator_version" not in registry["required"]
    assert "content_digest" not in json.dumps(registry)
    assert "judge_config_digest" not in json.dumps(registry)


# --------------------------------------------------------------------------
# End-to-end: SchemaValidator (which builds the cross-file $ref registry over
# every schema under schemas/) validates real instances, including the
# evaluator_config -> evaluator_version cross-file $ref and the null cases.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def validator() -> SchemaValidator:
    return SchemaValidator()


def test_dataset_version_instance_validates_with_content_digest(validator):
    instance = {
        "id": "dsv_1",
        "dataset_id": "ds_1",
        "revision": 1,
        "content_digest": compute_dataset_version_content_digest(
            VECTORS["dataset_version_content_digest_vectors"][0]["preimage"]
        ),
        "created_at": "2026-09-13T00:00:00Z",
    }
    assert validator.validate_json(instance, "dataset_version_schema") == []


def test_dataset_version_instance_validates_with_null_content_digest(validator):
    instance = {"id": "dsv_legacy", "dataset_id": "ds_1", "revision": 1, "content_digest": None}
    assert validator.validate_json(instance, "dataset_version_schema") == []


def test_dataset_version_instance_validates_without_content_digest_at_all(validator):
    instance = {"id": "dsv_legacy", "dataset_id": "ds_1", "revision": 1}
    assert validator.validate_json(instance, "dataset_version_schema") == []


def test_evaluator_version_instance_validates_with_judge_config_digest(validator):
    instance = {
        "id": "ev_1",
        "evaluator_id": "evaluator_def_1",
        "version": 1,
        "judge_config_digest": compute_judge_config_digest(
            VECTORS["judge_config_digest_vectors"][0]["judge_config"]
        ),
        "created_at": "2026-09-13T00:00:00Z",
    }
    assert validator.validate_json(instance, "evaluator_version_schema") == []


def test_evaluator_version_instance_validates_with_null_judge_config_digest(validator):
    instance = {
        "id": "ev_legacy",
        "evaluator_id": "evaluator_def_1",
        "version": 1,
        "judge_config_digest": None,
    }
    assert validator.validate_json(instance, "evaluator_version_schema") == []


def _evaluator_definition_instance(**overrides):
    instance = {
        "name": "exact-match-judge",
        "measure_id": "measure_1",
        "target_type": "experiment_run",
        "judge_config": {
            "instructions": "Score for accuracy.",
            "model_id": "gpt-4o-mini",
            "context_type": "none",
        },
    }
    instance.update(overrides)
    return instance


def test_evaluator_definition_with_current_version_null_still_validates(validator):
    instance = _evaluator_definition_instance(current_version=None)
    assert validator.validate_json(instance, "evaluator_definition_schema") == []


def test_evaluator_definition_with_current_version_resolves_cross_file_ref(validator):
    instance = _evaluator_definition_instance(
        current_version={
            "id": "ev_1",
            "evaluator_id": "eval_def_1",
            "version": 1,
            "judge_config_digest": compute_judge_config_digest(
                VECTORS["judge_config_digest_vectors"][0]["judge_config"]
            ),
        }
    )
    assert validator.validate_json(instance, "evaluator_definition_schema") == []


def test_evaluator_definition_without_current_version_still_validates(validator):
    """A pre-existing evaluator definition, unaware of current_version, remains valid."""
    instance = _evaluator_definition_instance()
    assert validator.validate_json(instance, "evaluator_definition_schema") == []


def test_dataset_with_current_version_resolves_cross_file_ref(validator):
    instance = {
        "id": "ds_1",
        "name": "my_ds",
        "label": "My Dataset",
        "description": "d",
        "type": "input-output",
        "examples_count": 2,
        "current_version": {
            "id": "dsv_1",
            "dataset_id": "ds_1",
            "revision": 1,
            "content_digest": compute_dataset_version_content_digest(
                VECTORS["dataset_version_content_digest_vectors"][0]["preimage"]
            ),
        },
    }
    assert validator.validate_json(instance, "dataset_schema") == []


def test_dataset_without_current_version_still_validates(validator):
    """A pre-existing dataset, unaware of current_version, remains valid."""
    instance = {
        "id": "ds_legacy",
        "name": "legacy_ds",
        "label": "Legacy Dataset",
        "description": "d",
        "type": "input-output",
        "examples_count": 0,
    }
    assert validator.validate_json(instance, "dataset_schema") == []
