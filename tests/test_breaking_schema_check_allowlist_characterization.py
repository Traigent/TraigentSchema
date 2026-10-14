"""Characterization tests for allowlist matching and report printing in breaking_schema_check.

Pins ``find_allow_entry`` (which entry is accepted, identified by its position in the
entry list, and every rejected near-miss with its reason, in order) and ``print_report``
(the exact text printed for every report shape). The expected values in
tests/data/breaking_schema_check_allowlist_characterization.json were recorded from the
implementation before both functions were split into smaller helpers. The cases reach
every branch of both functions.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any

import pytest

from tests._characterization import REPO_ROOT, Case, load_golden, load_script, observe

GOLDEN_FILE = "breaking_schema_check_allowlist_characterization.json"
TARGET = load_script(
    "breaking_schema_check_allowlist_characterization_target",
    REPO_ROOT / "scripts" / "breaking_schema_check.py",
)

FILE = "widgets/widget_request_schema.json"
REASON = "This deliberate v0 contract tightening was reviewed."


def _finding(m: ModuleType, **overrides: Any) -> Any:
    fields: dict[str, Any] = {
        "file": FILE,
        "pointer": "#/properties/color",
        "rule": "required",
        "severity": "BREAKING",
        "role": "request",
        "message": "color became required",
        "subject": "color",
        "old": False,
        "new": True,
    }
    fields.update(overrides)
    return m.Finding(**fields)


def _stored(m: ModuleType, finding: Any, **updates: Any) -> dict[str, Any]:
    identity = {**finding.identity(), **updates}
    identity["fingerprint"] = m._fingerprint_for_identity(
        finding.file,
        finding.rule,
        {key: identity[key] for key in ("pointer", "role", "subject", "old", "new")},
    )
    return identity


def _structured(m: ModuleType, finding: Any, *identities: Any, **overrides: Any) -> Any:
    entry: dict[str, Any] = {
        "file": finding.file,
        "rule": finding.rule,
        "findings": list(identities) if identities else [_stored(m, finding)],
        "reason": REASON,
        "version": "5.8.0",
        "pr": "#123",
    }
    for key, value in overrides.items():
        if value is _DROP:
            entry.pop(key, None)
        else:
            entry[key] = value
    return entry


_DROP = object()


def _legacy(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {"file": FILE, "reason": REASON, "version": "5.8.0", "pr": "#9"}
    for key, value in overrides.items():
        if value is _DROP:
            entry.pop(key, None)
        else:
            entry[key] = value
    return entry


def _match(build: Any) -> Case:
    """``build(m)`` returns ``(finding, entries)``; the match is reported by entry index."""

    def run(m: ModuleType) -> Any:
        finding, entries = build(m)
        result = m.find_allow_entry(finding, entries)

        def position(entry: Any) -> int:
            return next(i for i, candidate in enumerate(entries) if candidate is entry)

        return {
            "entry": None if result.entry is None else position(result.entry),
            "rejected": [[position(entry), why] for entry, why in result.rejected],
        }

    return run


def _one(entry_builder: Any, **finding_overrides: Any) -> Case:
    def build(m: ModuleType) -> Any:
        finding = _finding(m, **finding_overrides)
        return finding, [entry_builder(m, finding)]

    return _match(build)


def _skewed_identity_bytes(mode: str) -> Case:
    """Make ``_canonical_json_bytes`` raise on, or disagree about, bare identities.

    Fingerprint payloads carry a ``file`` key and are serialized normally, so the stored
    fingerprint still verifies; this reaches the defensive identity comparison that
    follows it, which a real identity cannot reach without a digest collision.
    """

    def run(m: ModuleType) -> Any:
        original = m._canonical_json_bytes
        calls: list[int] = []

        def skewed(value: Any) -> bytes:
            if isinstance(value, dict) and "file" not in value:
                calls.append(1)
                if mode == "raise":
                    raise ValueError("skewed")
                if len(calls) % 2 == 0:
                    return b"stored side differs"
            return original(value)

        def build(mod: ModuleType) -> Any:
            finding = _finding(mod)
            return finding, [_structured(mod, finding)]

        m._canonical_json_bytes = skewed
        try:
            return _match(build)(m)
        finally:
            m._canonical_json_bytes = original

    return run


def _current_fingerprint_differs(m: ModuleType) -> Any:
    """Skew only the first fingerprint computed: the finding's own, taken before the loop.

    The stored fingerprint then verifies against its identity but not against the
    finding, which is the comparison this case pins.
    """
    original = m._fingerprint_for_identity
    calls: list[int] = []

    def skewed(file: str, rule: str, identity: dict[str, Any]) -> str:
        calls.append(1)
        if len(calls) == 1:
            return "f" * 64
        return original(file, rule, identity)

    def build(mod: ModuleType) -> Any:
        finding = _finding(mod)
        entry = _structured(mod, finding)
        mod._fingerprint_for_identity = skewed
        return finding, [entry]

    try:
        return _match(build)(m)
    finally:
        m._fingerprint_for_identity = original


MATCH_CASES: dict[str, Case] = {
    "structured_exact": _one(lambda m, f: _structured(m, f)),
    "structured_second_identity_matches": _one(
        lambda m, f: _structured(m, f, _stored(m, f, pointer="#/other"), _stored(m, f))
    ),
    "structured_only_other_identity": _one(
        lambda m, f: _structured(m, f, _stored(m, f, pointer="#/other"))
    ),
    "structured_empty_findings": _one(lambda m, f: _structured(m, f, findings=[])),
    "structured_findings_none": _one(lambda m, f: _structured(m, f, findings=None)),
    "structured_findings_dict": _one(lambda m, f: _structured(m, f, findings={})),
    "structured_findings_non_dict_item": _one(
        lambda m, f: _structured(m, f, findings=[_stored(m, f), 7])
    ),
    "structured_rule_missing": _one(lambda m, f: _structured(m, f, rule=_DROP)),
    "structured_rule_empty": _one(lambda m, f: _structured(m, f, rule="")),
    "structured_rule_not_str": _one(lambda m, f: _structured(m, f, rule=["required"])),
    "structured_rule_other": _one(lambda m, f: _structured(m, f, rule="type")),
    "structured_extra_identity_key": _one(
        lambda m, f: _structured(m, f, {**_stored(m, f), "extra": 1})
    ),
    "structured_missing_fingerprint": _one(
        lambda m, f: _structured(
            m, f, {k: v for k, v in _stored(m, f).items() if k != "fingerprint"}
        )
    ),
    "structured_fingerprint_not_str": _one(
        lambda m, f: _structured(m, f, {**_stored(m, f), "fingerprint": True})
    ),
    "structured_fingerprint_uppercase": _one(
        lambda m, f: _structured(
            m, f, {**_stored(m, f), "fingerprint": _stored(m, f)["fingerprint"].upper()}
        )
    ),
    "structured_fingerprint_short": _one(
        lambda m, f: _structured(m, f, {**_stored(m, f), "fingerprint": "0" * 63})
    ),
    "structured_fingerprint_wrong": _one(
        lambda m, f: _structured(m, f, {**_stored(m, f), "fingerprint": "0" * 64})
    ),
    "structured_identity_tampered": _one(
        lambda m, f: _structured(m, f, {**_stored(m, f), "subject": "size"})
    ),
    "structured_identity_unhashable_mixed_keys": _one(
        lambda m, f: _structured(
            m, f, {**_stored(m, f), "subject": {1: "a", "b": 2}}
        )
    ),
    "structured_identity_nan": _one(
        lambda m, f: _structured(m, f, {**_stored(m, f), "old": float("nan")})
    ),
    "structured_bool_int_alias": _one(lambda m, f: _structured(m, f, _stored(m, f, old=0))),
    "structured_stored_for_other_finding": _one(
        lambda m, f: _structured(m, f, _stored(m, _finding(m, subject="size")))
    ),
    "structured_set_values_canonical": _one(
        lambda m, f: _structured(m, f), subject={"b", "a"}, old=("x", 1)
    ),
    "structured_finding_unserializable": _one(
        lambda m, f: _structured(m, f, {"pointer": "#"}), old=float("inf")
    ),
    "structured_identity_bytes_raise": _skewed_identity_bytes("raise"),
    "structured_identity_bytes_differ": _skewed_identity_bytes("differ"),
    "structured_current_fingerprint_differs": _current_fingerprint_differs,
    "structured_empty_rule_on_both_sides": _one(
        lambda m, f: _structured(m, f, rule=""), rule=""
    ),
    "pointer_only_entry": _one(lambda m, f: _legacy(pointer=f.pointer, rule=f.rule)),
    "pointers_entry": _one(lambda m, f: _legacy(pointers=[f.pointer])),
    "legacy_no_rule_no_prefix": _one(lambda m, f: _legacy()),
    "legacy_rule_matches": _one(lambda m, f: _legacy(rule="required")),
    "legacy_rule_differs": _one(lambda m, f: _legacy(rule="type")),
    "legacy_empty_rule_wildcard": _one(lambda m, f: _legacy(rule="")),
    "legacy_prefix_matches": _one(lambda m, f: _legacy(pointer_prefix="#/properties")),
    "legacy_prefix_differs": _one(lambda m, f: _legacy(pointer_prefix="#/definitions")),
    "other_file": _one(lambda m, f: _legacy(file="other.json")),
    "entry_without_file": _one(lambda m, f: _legacy(file=_DROP)),
    "reason_missing": _one(lambda m, f: _legacy(reason=_DROP)),
    "reason_placeholder": _one(lambda m, f: _legacy(reason="TODO")),
    "reason_short": _one(lambda m, f: _legacy(reason="because reasons")),
    "reason_single_token": _one(lambda m, f: _legacy(reason="x" * 30)),
    "version_missing": _one(lambda m, f: _legacy(version=_DROP)),
    "version_empty": _one(lambda m, f: _legacy(version="")),
    "reason_and_version_bad": _one(lambda m, f: _legacy(reason="", version=None)),
    "structured_reason_bad": _one(lambda m, f: _structured(m, f, reason="see PR #3")),
    "no_entries": _match(lambda m: (_finding(m), [])),
    "first_good_entry_wins_after_rejections": _match(
        lambda m: (
            _finding(m),
            [
                _legacy(file="other.json"),
                _legacy(reason="TODO"),
                _structured(m, _finding(m), version=_DROP),
                _legacy(rule="type"),
                _legacy(pointer_prefix="#/properties/c"),
                _legacy(),
                _legacy(reason="wip", version=""),
            ],
        )
    ),
    "all_rejected": _match(
        lambda m: (
            _finding(m),
            [_legacy(reason="n/a"), _structured(m, _finding(m), version=""), _legacy(pr=None)],
        )
    ),
}


# ---------------------------------------------------------------------------
# print_report
# ---------------------------------------------------------------------------


def _report(m: ModuleType, spec: dict[str, Any]) -> Any:
    findings = [
        _finding(m, **overrides) for overrides in spec.get("findings", [])
    ]
    unacked = [findings[i] for i in spec.get("unacked", [])]
    acked = [(findings[i], entry) for i, entry in spec.get("acked", [])]
    near_miss = {
        id(findings[i]): [(entry, why) for entry, why in misses]
        for i, misses in spec.get("near_miss", {}).items()
    }
    return m.Report(
        "base-label",
        "head-label",
        spec.get("changed", [("M", FILE)]),
        findings,
        unacked,
        acked,
        near_miss,
        spec.get("role_notes", {}),
    )


def _print(spec: dict[str, Any], *, quiet_info: bool = False) -> Case:
    return lambda m: m.print_report(_report(m, spec), quiet_info=quiet_info)


def _info(**overrides: Any) -> dict[str, Any]:
    return {"severity": "INFO", "rule": "description", "message": "doc changed", **overrides}


MIXED = {
    "changed": [("M", FILE), ("M", "b/second.json"), ("A", "c/new.json")],
    "findings": [
        _info(pointer="#/z"),
        {"pointer": "#/properties/b"},
        {"pointer": "#/properties/a", "subject": "a"},
        _info(file="b/second.json", pointer="#/a"),
        {"file": "b/second.json", "rule": "type", "pointer": "#/properties/t"},
        {"file": "c/new.json", "rule": "new_file", "pointer": "#", "severity": "INFO"},
    ],
    "role_notes": {FILE: ("request", "reached only from request bodies")},
}

PRINT_CASES: dict[str, Case] = {
    "nothing_changed": _print({"changed": [], "findings": [_info()]}),
    "changed_without_findings": _print({}),
    "info_only": _print({"findings": [_info(), _info(pointer="#/a")]}),
    "info_only_quiet": _print({"findings": [_info()]}, quiet_info=True),
    "mixed_unacked": _print({**MIXED, "unacked": [1, 2, 4]}),
    "mixed_unacked_quiet": _print({**MIXED, "unacked": [1, 2, 4]}, quiet_info=True),
    "all_acked": _print(
        {
            **MIXED,
            "acked": [
                [1, {"pr": "#12", "reason": REASON}],
                [2, {"reason": "no pr key on this entry, reason only"}],
                [4, {"pr": "#13"}],
            ],
        }
    ),
    "acked_and_unacked": _print(
        {**MIXED, "unacked": [4], "acked": [[1, {"pr": "#1", "reason": REASON}]]}
    ),
    "single_group": _print({"findings": [{"pointer": "#/x"}], "unacked": [0]}),
    "group_of_two_same_pointer": _print(
        {
            "findings": [
                {"pointer": "#", "subject": "b", "message": "b became required"},
                {"pointer": "#", "subject": "a", "message": "a became required"},
            ],
            "unacked": [0, 1],
        }
    ),
    "near_miss_for_some": _print(
        {
            **MIXED,
            "unacked": [1, 2, 4],
            "near_miss": {
                2: [({"file": FILE}, "reason is empty"), ({"file": FILE}, "version is missing")],
                4: [({"file": "b/second.json"}, "reason is only 4 chars")],
            },
        }
    ),
    "near_miss_only_for_acked_finding": _print(
        {
            **MIXED,
            "unacked": [4],
            "acked": [[1, {"pr": "#1", "reason": REASON}]],
            "near_miss": {1: [({"file": FILE}, "ignored for an acked finding")]},
        }
    ),
    "role_note_for_file_without_findings": _print(
        {"findings": [_info()], "role_notes": {"other.json": ("response", "why")}}
    ),
}

ALL_CASES: dict[str, Case] = {
    **{f"find_allow_entry/{k}": v for k, v in MATCH_CASES.items()},
    **{f"print_report/{k}": v for k, v in PRINT_CASES.items()},
}


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], TARGET) == _golden()[case_id]
