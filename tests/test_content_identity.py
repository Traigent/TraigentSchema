# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the R3 dataset-version content digest and evaluator
judge-config digest: schemas/datasets/dataset_version_schema.json,
schemas/datasets/evaluator_version_schema.json, and the additive
`current_version` field on evaluator_config_schema.json.

Both contracts are additive and optional: old readers unaware of
`content_digest` / `judge_config_digest` / `current_version` are unaffected,
and every one of those fields accepts `null` for legacy records. Nothing in
the certification family's process-record V1 digest-domain registry changes.
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
from traigent_schema.utils import get_schemas_dir

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests" / "data" / "content_identity_vectors.json").read_text(encoding="utf-8"))
DATASETS_DIR = get_schemas_dir() / "datasets"
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
    schema = _load(DATASETS_DIR, "evaluator_version_schema.json")
    domain_def = schema["definitions"]["EvaluatorJudgeConfigDigestDomainV1"]
    assert domain_def["const"] == EVALUATOR_JUDGE_CONFIG_DIGEST_DOMAIN


# --------------------------------------------------------------------------
# Golden vectors: same set -> same digest, one-byte change -> different
# digest, reordered input -> same digest (sorting is part of the projection).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("vector", VECTORS["dataset_version_content_digest_vectors"], ids=lambda v: v["name"])
def test_dataset_version_content_digest_golden_vectors(vector):
    assert compute_dataset_version_content_digest(vector["preimage"]) == vector["expected_digest"]


def test_dataset_version_content_digest_reordering_is_a_noop():
    vectors = {v["name"]: v for v in VECTORS["dataset_version_content_digest_vectors"]}
    baseline = vectors["two_example_set"]
    reordered = vectors["two_example_set_reordered"]
    assert baseline["expected_digest"] == reordered["expected_digest"]
    assert compute_dataset_version_content_digest(baseline["preimage"]) == compute_dataset_version_content_digest(
        reordered["preimage"]
    )


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
    assert compute_dataset_version_content_digest(dup["preimage"]) != compute_dataset_version_content_digest(single)


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
    schema = _load(DATASETS_DIR, "evaluator_version_schema.json")
    version = schema["definitions"]["EvaluatorVersionV1"]
    assert "judge_config_digest" not in version["required"]
    field = version["properties"]["judge_config_digest"]
    kinds = {branch.get("type") for branch in field["oneOf"]}
    assert kinds == {"string", "null"}
    assert field["default"] is None


def test_evaluator_config_current_version_is_optional_and_additive():
    schema = _load(DATASETS_DIR, "evaluator_config_schema.json")
    assert "current_version" not in schema["required"]
    field = schema["properties"]["current_version"]
    assert {"null"} <= {branch.get("type") for branch in field["oneOf"] if "type" in branch}
    assert field["default"] is None
    # The pre-existing required/anyOf shape is untouched by this addition.
    assert schema["required"] == [
        "id",
        "model_parameters_id",
        "instructions",
        "context_type",
        "context_source",
    ]


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
        "evaluator_id": "evaluator_config_1",
        "version": 1,
        "judge_config_digest": compute_judge_config_digest(
            VECTORS["judge_config_digest_vectors"][0]["judge_config"]
        ),
        "created_at": "2026-09-13T00:00:00Z",
    }
    assert validator.validate_json(instance, "evaluator_version_schema") == []


def test_evaluator_version_instance_validates_with_null_judge_config_digest(validator):
    instance = {"id": "ev_legacy", "evaluator_id": "evaluator_config_1", "version": 1, "judge_config_digest": None}
    assert validator.validate_json(instance, "evaluator_version_schema") == []


def test_evaluator_config_with_current_version_null_still_validates(validator):
    instance = {
        "id": "eval_cfg_1",
        "dataset_id": "ds_1",
        "model_parameters_id": "mp_1",
        "instructions": "Score for accuracy.",
        "context_type": "text",
        "context_source": "dataset",
        "current_version": None,
    }
    assert validator.validate_json(instance, "evaluator_config_schema") == []


def test_evaluator_config_with_current_version_resolves_cross_file_ref(validator):
    instance = {
        "id": "eval_cfg_1",
        "dataset_id": "ds_1",
        "model_parameters_id": "mp_1",
        "instructions": "Score for accuracy.",
        "context_type": "text",
        "context_source": "dataset",
        "current_version": {
            "id": "ev_1",
            "evaluator_id": "eval_cfg_1",
            "version": 1,
            "judge_config_digest": compute_judge_config_digest(
                VECTORS["judge_config_digest_vectors"][0]["judge_config"]
            ),
        },
    }
    assert validator.validate_json(instance, "evaluator_config_schema") == []


def test_evaluator_config_without_current_version_still_validates(validator):
    """A pre-existing evaluator_config, unaware of current_version, remains valid."""
    instance = {
        "id": "eval_cfg_legacy",
        "dataset_id": "ds_1",
        "model_parameters_id": "mp_1",
        "instructions": "Score for accuracy.",
        "context_type": "text",
        "context_source": "dataset",
    }
    assert validator.validate_json(instance, "evaluator_config_schema") == []
