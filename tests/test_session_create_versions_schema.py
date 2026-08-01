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
        ),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_versions_are_optional() -> None:
    errors = _validator().validate_request("/api/v1/sessions", "POST", _payload())

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_unknown_state_requires_no_digest() -> None:
    versions = _versions()
    versions["dataset"] = {"schema": "dfp2o", "digest": None, "state": "unknown"}

    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(artifact_versions=versions)
    )

    assert errors == [], f"unknown state must be expressible without a digest: {errors}"


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


def test_identity_version_rejects_unknown_versions() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(identity_version=99)
    )

    assert errors, "identity_version must be a known contract version"
