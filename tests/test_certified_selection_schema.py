# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the Phase 8 certified-selection wire schemas.

Pins: CertifiedSelectionReport content-freedom (closed shapes, trial binding by
id only, NO value-bearing fields — subject_value_hash is deliberately absent),
and the finalize response's selection_basis / selection_attestation additions.
"""

from __future__ import annotations

from traigent_schema import SchemaValidator

_VALIDATOR = SchemaValidator()
# The finalize endpoint lives in the sdk_tuning contract root
# (sdk_tuning_endpoints.json -> optimization/optimization_endpoints.json);
# the default "backend" contract does not map it at all.
_SDK_VALIDATOR = SchemaValidator(contract="sdk_tuning")

REPORT = "certified_selection_schema"
FINALIZE = "session_finalize_response_schema"

_SHA = "a" * 64


def _errors(schema_name: str, instance: dict) -> list:
    return _VALIDATOR.validate_json(instance, schema_name)


def _valid_report() -> dict:
    return {
        "trial_id": "trial_1b3d089d864845c2",
        "certificates": [
            {
                "cvar_name": "retriever.k",
                "decision": "CERTIFIED_SELECTION",
                "freshness_hash": _SHA,
            }
        ],
        "attestation": "sdk_client_attested",
    }


class TestCertifiedSelectionReport:
    def test_valid_report_accepted(self) -> None:
        assert not _errors(REPORT, _valid_report())

    def test_trial_id_required(self) -> None:
        report = _valid_report()
        del report["trial_id"]
        assert _errors(REPORT, report)

    def test_certificates_required_and_nonempty(self) -> None:
        report = _valid_report()
        report["certificates"] = []
        assert _errors(REPORT, report)
        del report["certificates"]
        assert _errors(REPORT, report)

    def test_top_level_closed(self) -> None:
        report = _valid_report()
        report["best_config"] = {"model": "gpt-4o"}
        assert _errors(REPORT, report)

    def test_config_never_crosses_as_certificate_field(self) -> None:
        """The winner's config comes from the SERVER's trial record — any
        value-bearing sibling on a certificate entry must reject."""
        report = _valid_report()
        report["certificates"][0]["calibrated_value"] = 7
        assert _errors(REPORT, report)

    def test_subject_value_hash_deliberately_absent(self) -> None:
        """Dictionary-invertible on low-entropy values (P8) — not in the shape."""
        report = _valid_report()
        report["certificates"][0]["subject_value_hash"] = _SHA
        assert _errors(REPORT, report)

    def test_evidence_fields_never_cross(self) -> None:
        report = _valid_report()
        report["certificates"][0]["evidence_n"] = 200
        assert _errors(REPORT, report)

    def test_decision_enum_enforced(self) -> None:
        report = _valid_report()
        report["certificates"][0]["decision"] = "CERTIFIED"
        assert _errors(REPORT, report)

    def test_freshness_hash_is_lowercase_sha256(self) -> None:
        report = _valid_report()
        report["certificates"][0]["freshness_hash"] = "A" * 64
        assert _errors(REPORT, report)
        report["certificates"][0]["freshness_hash"] = "a" * 63
        assert _errors(REPORT, report)

    def test_trial_id_pattern(self) -> None:
        report = _valid_report()
        report["trial_id"] = "trial id with spaces"
        assert _errors(REPORT, report)
        report["trial_id"] = ""
        assert _errors(REPORT, report)

    def test_attestation_enum(self) -> None:
        report = _valid_report()
        report["attestation"] = "server_verified"
        assert _errors(REPORT, report)

    def test_attestation_required(self) -> None:
        """A certified report is never unattributed."""
        report = _valid_report()
        del report["attestation"]
        assert _errors(REPORT, report)

    def test_freshness_hash_required(self) -> None:
        """A certified report must bind freshness (unlike the optional
        declaration-time tvl_governance.certificates[] entries)."""
        report = _valid_report()
        del report["certificates"][0]["freshness_hash"]
        assert _errors(REPORT, report)

    def test_overlong_identifiers_rejected(self) -> None:
        report = _valid_report()
        report["trial_id"] = "t" * 129
        assert _errors(REPORT, report)
        report = _valid_report()
        report["certificates"][0]["cvar_name"] = "a" * 257
        assert _errors(REPORT, report)

    def test_certificates_max_items(self) -> None:
        report = _valid_report()
        entry = report["certificates"][0]
        report["certificates"] = [
            {**entry, "cvar_name": f"cvar_{i}"} for i in range(257)
        ]
        assert _errors(REPORT, report)

    def test_exact_duplicate_entries_rejected(self) -> None:
        """uniqueItems catches byte-identical duplicates; SAME-cvar conflicts
        with different hashes are a SERVER-side coverage rule (P2)."""
        report = _valid_report()
        report["certificates"] = [report["certificates"][0]] * 2
        assert _errors(REPORT, report)


class TestFinalizeSelectionBasis:
    def _base(self) -> dict:
        return {
            "session_id": "s-1",
            "best_config": {"model": "gpt-4o-mini"},
            "total_trials": 3,
        }

    def test_winner_without_basis_rejected(self) -> None:
        """Closed taxonomy (oneOf): a winner must say HOW it was selected."""
        assert _errors(FINALIZE, self._base())

    def test_no_winner_without_reason_rejected(self) -> None:
        """Closed taxonomy (oneOf): a no-winner must say WHY."""
        resp = self._base()
        resp["best_config"] = {}
        assert _errors(FINALIZE, resp)

    def test_certified_selection_basis_accepted(self) -> None:
        resp = self._base()
        resp["selection_basis"] = "certified_selection"
        resp["selection_attestation"] = {
            "type": "client_attested",
            "attested_by": "python_sdk",
            "sdk_version": "0.12.0",
        }
        assert not _errors(FINALIZE, resp)

    def test_objective_best_basis_accepted(self) -> None:
        resp = self._base()
        resp["selection_basis"] = "objective_best"
        assert not _errors(FINALIZE, resp)

    def test_selection_basis_enum_enforced(self) -> None:
        resp = self._base()
        resp["selection_basis"] = "server_verified"
        assert _errors(FINALIZE, resp)

    def test_attestation_closed_shape(self) -> None:
        resp = self._base()
        resp["selection_basis"] = "certified_selection"
        resp["selection_attestation"] = {
            "type": "client_attested",
            "evidence": {"n": 200},
        }
        assert _errors(FINALIZE, resp)

    def test_attestation_type_required_and_enum(self) -> None:
        resp = self._base()
        resp["selection_basis"] = "certified_selection"
        resp["selection_attestation"] = {"attested_by": "python_sdk"}
        assert _errors(FINALIZE, resp)
        resp["selection_attestation"] = {"type": "server_verified"}
        assert _errors(FINALIZE, resp)

    def test_basis_and_reason_code_mutually_exclusive(self) -> None:
        resp = self._base()
        resp["best_config"] = {}
        resp["reason_code"] = "NO_CERTIFIED_SELECTION"
        resp["selection_basis"] = "objective_best"
        assert _errors(FINALIZE, resp)

    def test_basis_requires_non_empty_winner(self) -> None:
        resp = self._base()
        resp["best_config"] = {}
        resp["selection_basis"] = "objective_best"
        assert _errors(FINALIZE, resp)

    def test_reason_code_requires_empty_best_config(self) -> None:
        """The Phase 7 fail-closed prose is now an enforced conditional."""
        resp = self._base()
        resp["reason_code"] = "NO_CERTIFIED_SELECTION"
        assert _errors(FINALIZE, resp)
        resp["best_config"] = {}
        assert not _errors(FINALIZE, resp)

    def test_attestation_without_basis_rejected(self) -> None:
        resp = self._base()
        resp["selection_attestation"] = {"type": "client_attested"}
        assert _errors(FINALIZE, resp)

    def test_attestation_with_objective_best_rejected(self) -> None:
        resp = self._base()
        resp["selection_basis"] = "objective_best"
        resp["selection_attestation"] = {"type": "client_attested"}
        assert _errors(FINALIZE, resp)

    def test_certified_basis_requires_attestation(self) -> None:
        """A certified winner is never unattributed (reverse direction)."""
        resp = self._base()
        resp["selection_basis"] = "certified_selection"
        assert _errors(FINALIZE, resp)

    def test_sdk_version_is_anchored_token(self) -> None:
        resp = self._base()
        resp["selection_basis"] = "certified_selection"
        resp["selection_attestation"] = {
            "type": "client_attested",
            "sdk_version": "calibrated value leaked here",
        }
        assert _errors(FINALIZE, resp)

    def test_finalize_endpoint_request_ref_wiring(self) -> None:
        """Pin the endpoint registry resolves the certified_selection $ref —
        a broken ref must fail THIS test, not first appear at runtime."""
        valid = {
            "include_full_history": False,
            "certified_selection": _valid_report(),
        }
        assert not _SDK_VALIDATOR.validate_request(
            "/api/v1/sessions/sess-123/finalize", "POST", valid
        )
        smuggle = {
            "certified_selection": {
                **_valid_report(),
                "best_config": {"model": "gpt-4o"},
            }
        }
        assert _SDK_VALIDATOR.validate_request(
            "/api/v1/sessions/sess-123/finalize", "POST", smuggle
        )
