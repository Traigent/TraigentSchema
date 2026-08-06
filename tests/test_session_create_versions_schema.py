"""Derived artifact-version contract (FR-OPT-IDENTITY-VERSIONING-V1).

Versions are digests over a specified manifest. Anything that cannot be
completed is explicitly `unknown`, and unknown must never read as equal.
"""

from __future__ import annotations

from typing import Any

from traigent_schema import SchemaValidator


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def _versions() -> dict[str, Any]:
    return {
        "agent": {"schema": "afp2", "digest": "sha256:" + "a" * 64, "state": "verified"},
        "dataset": {"schema": "dfp2o", "digest": "sha256:" + "b" * 64, "state": "verified"},
        "evaluator": {"schema": "efp2", "digest": None, "state": "unknown"},
        "config_space": {"schema": "cfp2", "digest": "sha256:" + "c" * 64, "state": "verified"},
    }


def _validator() -> SchemaValidator:
    return SchemaValidator(contract="sdk_tuning")


def test_session_create_accepts_artifact_versions() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions",
        "POST",
        _payload(
            artifact_versions=_versions(),
            code_revision="9f2c1ab3d4e5f60718293a4b5c6d7e8f90a1b2c3",
            identity_version=2,
            # identity_version 2 requires the identity sources: declaring the
            # version and then sending no identity is what B1 closed.
            agent_id="ticket-classifier",
            agent_id_source="declared",
            dataset_id="refunds-golden",
            dataset_id_source="declared",
        ),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_versions_are_optional() -> None:
    errors = _validator().validate_request("/api/v1/sessions", "POST", _payload())

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_unknown_state_is_expressible_without_a_digest() -> None:
    versions = _versions()
    versions["dataset"] = {"schema": "dfp2o", "digest": None, "state": "unknown"}

    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(artifact_versions=versions)
    )

    assert errors == [], f"unknown state must be expressible without a digest: {errors}"


def test_unknown_state_must_not_carry_a_digest() -> None:
    """The other direction, and the one that matters for fail-closed.

    'unknown' means the manifest could not be completed, so there is nothing
    for a digest to be a digest OF. Letting one through gives a consumer a
    comparable-looking value for an incomparable run: unknown would read as
    equal to something, which is exactly what the state exists to prevent.
    """
    versions = _versions()
    versions["evaluator"] = {
        "schema": "efp2",
        "digest": "sha256:" + "d" * 64,
        "state": "unknown",
    }

    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(artifact_versions=versions)
    )

    assert errors, "An 'unknown' version carrying a digest must be rejected"


def test_unknown_state_may_omit_the_digest_key_entirely() -> None:
    """Absent and explicit-null are both honest ways to say 'no digest'."""
    versions = _versions()
    versions["evaluator"] = {"schema": "efp2", "state": "unknown"}

    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(artifact_versions=versions)
    )

    assert errors == [], f"omitting digest under unknown must validate: {errors}"


def test_verified_state_requires_a_digest() -> None:
    versions = _versions()
    versions["agent"] = {"schema": "afp2", "digest": None, "state": "verified"}

    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(artifact_versions=versions)
    )

    assert errors, "A 'verified' version without a digest must be rejected"


def test_state_rejects_values_outside_the_enum() -> None:
    versions = _versions()
    versions["agent"]["state"] = "probably"

    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(artifact_versions=versions)
    )

    assert errors, "state must be exactly 'verified' or 'unknown'"


def test_digest_must_be_algorithm_prefixed() -> None:
    versions = _versions()
    versions["agent"]["digest"] = "a" * 64

    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(artifact_versions=versions)
    )

    assert errors, "A digest must carry its algorithm prefix, e.g. 'sha256:...'"


def test_unknown_artifact_keys_are_rejected() -> None:
    versions = _versions()
    versions["prompt"] = {"schema": "pfp2", "digest": None, "state": "unknown"}

    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(artifact_versions=versions)
    )

    assert errors, "artifact_versions is a closed set for this contract version"


def _v2_payload(**overrides: Any) -> dict[str, Any]:
    payload = _payload(
        identity_version=2,
        agent_id="a",
        agent_id_source="declared",
        dataset_id="d",
        dataset_id_source="declared",
        artifact_versions=_versions(),
    )
    payload.update(overrides)
    return payload


def test_v2_requires_all_four_version_slots() -> None:
    """An ABSENT slot is an unknown one in disguise.

    Two v2 runs that both omit a slot look alike to any consumer comparing
    what it was given, so silence reads as agreement -- the same defect as an
    'unknown' carrying a digest, one level up. Saying unknown costs one field.
    """
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _v2_payload(artifact_versions=None)
    )
    assert errors, "v2 must require artifact_versions"

    for slot in ("agent", "dataset", "evaluator", "config_space"):
        versions = _versions()
        versions.pop(slot)
        errors = _validator().validate_request(
            "/api/v1/sessions", "POST", _v2_payload(artifact_versions=versions)
        )
        assert errors, f"v2 must require the {slot} slot"


def test_each_slot_is_bound_to_its_own_algorithm_family() -> None:
    """A dataset digest filed under agent would make two unrelated artifacts
    compare equal, and a free-string schema let it happen."""
    mismatches = {
        "agent": "dfp2o",
        "dataset": "afp2",
        "evaluator": "cfp2",
        "config_space": "efp2",
    }
    for slot, wrong in mismatches.items():
        versions = _versions()
        versions[slot] = {**versions[slot], "schema": wrong}
        errors = _validator().validate_request(
            "/api/v1/sessions", "POST", _v2_payload(artifact_versions=versions)
        )
        assert errors, f"{slot} must reject a {wrong} digest"

    versions = _versions()
    versions["agent"] = {**versions["agent"], "schema": "lol"}
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _v2_payload(artifact_versions=versions)
    )
    assert errors, "schema must not be a free string"


def test_legacy_fp1_remains_admissible_in_every_slot() -> None:
    """fp1 digests are valid history and are never recomputed."""
    for slot in ("agent", "dataset", "evaluator", "config_space"):
        versions = _versions()
        versions[slot] = {"schema": "fp1", "digest": "sha256:" + "e" * 64, "state": "verified"}
        errors = _validator().validate_request(
            "/api/v1/sessions", "POST", _v2_payload(artifact_versions=versions)
        )
        assert errors == [], f"fp1 must stay valid in {slot}: {errors}"


def test_identity_version_rejects_unknown_versions() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(identity_version=99)
    )

    assert errors, "identity_version must be a known contract version"
