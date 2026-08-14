#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""
check_required_gate.py — verify every dependency of ``ci-required`` actually
finished green, closing the "skipped == pass, no questions asked" hole.

Why
---
``ci-required`` is the single synthetic required status check for this repo:
the branch ruleset requires ONLY that context, and it fans in from every real
job via ``needs:``. Before this script, the fan-in was an inline shell
``case`` that accepted ``skipped`` as a pass for EVERY dependency,
unconditionally — the same shape of hole TraigentBackend's and Traigent's own
required-gate scripts closed on 2026-08-07 (see those repos'
``scripts/ci/check_required_gate.py``, the reference this port is based on):
a bug in a content classifier and a legitimately-inapplicable job produce the
exact same observable, ``skipped``, and a blanket accept can't tell them
apart.

This repo adds exactly ONE classifier-gated job to the mix —
``breaking-schema-check`` (moved into ci.yml from its own path-filtered
workflow file specifically so it CAN be a ``needs:`` dependency here; see
TraigentSchema#392) — so this port is deliberately smaller than Backend's/the
SDK's: no generic N-job ``CLASSIFIER_GATED`` table, just one dedicated
verification function for the one job that needs it
(``verify_breaking_schema_check_skip``). If a second classifier-gated job is
ever added to ci.yml, generalize back to a table at that point rather than
duplicating the function.

The rule (same shape as the Backend/SDK precedent): a ``skipped``
``breaking-schema-check`` is accepted ONLY when the ``changes`` classifier
job PROVES the skip was legitimate:

  1. ``changes`` itself concluded ``success`` — an unsuccessful classifier
     run cannot be trusted to have set any output correctly.
  2. EITHER
     a. ``changes.outputs.event_applicable`` is the LITERAL string
        ``'false'`` — this run's event has no PR/merge_group diff range to
        classify at all (a ``push``/``schedule``/``workflow_dispatch``
        trigger of ci.yml), an unforgeable ``github.event_name`` fact, OR
     b. ``changes.outputs.schema_relevant`` is the LITERAL string ``'false'``
        — not empty, not missing, not any other value — AND
        ``changes.outputs.changed_file_count`` is a NON-ZERO integer. A
        range that produced zero files is a broken/empty range, not a
        "nothing schema-relevant changed" verdict -- except when the trusted
        classifier proves the narrowly-defined ancestry-only topology and emits
        the literal ``ancestry_only='true'``.

Any of those failing -> the gate fails, naming which condition broke. All
holding -> the gate passes, and the log states the output value that
justified it.

``lint-type`` has no ``needs:`` and no ``if:`` of its own, so it can never
legitimately skip — it is deliberately NOT in ``UNCONDITIONAL_SKIP_OK``; a
skip there is a workflow bug, not a pass. ``test``/``package`` depend only on
``lint-type`` and carry no ``if:`` of their own, so they skip (via GitHub's
default ``if: success()``) exactly when ``lint-type`` itself failed or
skipped — independently caught because ``lint-type`` is itself a required
dependency of THIS gate. ``changes`` likewise has no ``if:`` of its own and
is deliberately NOT allowlisted: if a future edit gives it one, this script
should go red until that new skip path is explicitly reasoned about here,
rather than silently inheriting an old allowlist entry that no longer
describes it.

Extracted out of the workflow YAML (instead of an inline heredoc) so it has
unit tests — see tests/test_check_required_gate.py.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field

# Jobs allowed to report "skipped" with NO further verification, mapped to WHY
# each one is safe. The bar for an entry here: this job's skip can NEVER be
# caused by a bug in the `changes` classifier — only by `lint-type` (itself an
# independently-checked required dependency) not succeeding.
UNCONDITIONAL_SKIP_OK: dict[str, str] = {
    "test": (
        "Depends only on `lint-type` via `needs:` and carries no `if:` of "
        "its own, so it skips (GitHub's default `if: success()`) exactly "
        "when `lint-type` failed or skipped. `lint-type` is itself a "
        "required dependency of this gate, so its failure is independently "
        "caught -- allowlisting this cascade opens no new hole."
    ),
    "package": (
        "Same reasoning as `test`: depends only on `lint-type`, no `if:` of "
        "its own, skip cascades from a `lint-type` failure that is "
        "independently caught."
    ),
}

CHANGES_JOB = "changes"
BREAKING_SCHEMA_JOB = "breaking-schema-check"
EVENT_APPLICABLE_OUTPUT = "event_applicable"
SCHEMA_RELEVANT_OUTPUT = "schema_relevant"
FILE_COUNT_OUTPUT = "changed_file_count"
# Emitted only after the changes job proves an immutable, same-repository
# ancestry-only topology. It is not a caller-controlled waiver.
ANCESTRY_ONLY_OUTPUT = "ancestry_only"


@dataclass
class GateResult:
    ok: bool
    problems: list[str] = field(default_factory=list)
    justifications: list[str] = field(default_factory=list)


def verify_breaking_schema_check_skip(needs: dict) -> tuple[bool, str]:
    """Decide whether breaking-schema-check's `skipped` result is provably safe.

    Returns (True, justification) if the rule in the module docstring holds,
    else (False, problem). Never guesses: a missing `changes` entry, a
    non-dict `outputs`, or a non-integer file count are all failures, not
    "probably fine".
    """
    changes_entry = needs.get(CHANGES_JOB)
    changes_result = changes_entry.get("result") if isinstance(changes_entry, dict) else None
    if changes_result != "success":
        return False, (
            f"{BREAKING_SCHEMA_JOB}=skipped, but '{CHANGES_JOB}' did not "
            f"succeed (result={changes_result!r}) -- its outputs cannot be "
            "trusted to justify this skip"
        )

    outputs = changes_entry.get("outputs") if isinstance(changes_entry, dict) else None
    outputs = outputs if isinstance(outputs, dict) else {}

    event_applicable = outputs.get(EVENT_APPLICABLE_OUTPUT)
    if event_applicable == "false":
        return True, (
            f"{BREAKING_SCHEMA_JOB}: skip verified safe ({CHANGES_JOB}.outputs."
            f"{EVENT_APPLICABLE_OUTPUT}='false' -- no PR/merge_group diff "
            "range exists for this event)"
        )
    if event_applicable != "true":
        return False, (
            f"{BREAKING_SCHEMA_JOB}=skipped, but '{CHANGES_JOB}.outputs."
            f"{EVENT_APPLICABLE_OUTPUT}'={event_applicable!r}, expected the "
            "literal string 'true' or 'false'"
        )

    schema_relevant = outputs.get(SCHEMA_RELEVANT_OUTPUT)
    if schema_relevant is None:
        return False, (
            f"{BREAKING_SCHEMA_JOB}=skipped, but '{CHANGES_JOB}.outputs."
            f"{SCHEMA_RELEVANT_OUTPUT}' is missing entirely"
        )
    if schema_relevant != "false":
        return False, (
            f"{BREAKING_SCHEMA_JOB}=skipped, but '{CHANGES_JOB}.outputs."
            f"{SCHEMA_RELEVANT_OUTPUT}'={schema_relevant!r}, expected the "
            "literal string 'false'"
        )

    count_raw = outputs.get(FILE_COUNT_OUTPUT)
    if count_raw is None:
        return False, (
            f"{BREAKING_SCHEMA_JOB}=skipped, but '{CHANGES_JOB}.outputs."
            f"{FILE_COUNT_OUTPUT}' is missing entirely"
        )
    try:
        count = int(count_raw)
    except (TypeError, ValueError):
        return False, (
            f"{BREAKING_SCHEMA_JOB}=skipped, but '{CHANGES_JOB}.outputs."
            f"{FILE_COUNT_OUTPUT}'={count_raw!r} is not a valid integer"
        )
    if count < 0:
        return False, (
            f"{BREAKING_SCHEMA_JOB}=skipped, and '{CHANGES_JOB}.outputs."
            f"{FILE_COUNT_OUTPUT}'={count} -- the classifier saw a negative "
            "changed-file count, which is invalid"
        )

    if count == 0:
        ancestry_only = outputs.get(ANCESTRY_ONLY_OUTPUT)
        if ancestry_only != "true":
            return False, (
                f"{BREAKING_SCHEMA_JOB}=skipped, and '{CHANGES_JOB}.outputs."
                f"{FILE_COUNT_OUTPUT}'={count} -- the classifier saw zero "
                "changed files in a PR/merge_group range, which is a "
                "broken/empty range, not a legitimate 'nothing "
                "schema-relevant changed' verdict"
            )
        return True, (
            f"{BREAKING_SCHEMA_JOB}: skip verified safe for declared "
            f"ancestry-only topology ({CHANGES_JOB}.outputs."
            f"{ANCESTRY_ONLY_OUTPUT}='true', {CHANGES_JOB}.outputs."
            f"{FILE_COUNT_OUTPUT}=0)"
        )

    ancestry_only = outputs.get(ANCESTRY_ONLY_OUTPUT)
    if ancestry_only not in (None, "false"):
        return False, (
            f"{BREAKING_SCHEMA_JOB}=skipped, but '{CHANGES_JOB}.outputs."
            f"{ANCESTRY_ONLY_OUTPUT}'={ancestry_only!r} with a non-zero "
            f"{FILE_COUNT_OUTPUT}"
        )

    return True, (
        f"{BREAKING_SCHEMA_JOB}: skip verified safe ({SCHEMA_RELEVANT_OUTPUT}="
        f"'false', {FILE_COUNT_OUTPUT}={count})"
    )


def evaluate(needs: dict[str, dict]) -> GateResult:
    """Decide whether every dependency in ``needs`` is green enough to pass.

    ``needs`` is the raw ``needs`` context GitHub Actions hands the job: one
    entry per job actually listed in THIS job's own ``needs:``, each at least
    carrying a ``result`` key (``success`` / ``failure`` / ``cancelled`` /
    ``skipped``), and -- for ``changes`` -- an ``outputs`` map.

    Fails closed: an empty ``needs`` map, a stale allowlist/job-name entry,
    a ``cancelled`` result, and an empty/absent ``result`` all count as
    failures. Nothing ever passes by falling through an unrecognised case.
    """
    problems: list[str] = []
    justifications: list[str] = []

    if not needs:
        problems.append(
            "needs map is empty -- this job has no declared dependencies to "
            "verify, which is never correct for a required gate. Check the "
            "`needs:` list on this job in the workflow."
        )
        return GateResult(ok=False, problems=problems)

    for allowlisted_job in UNCONDITIONAL_SKIP_OK:
        if allowlisted_job not in needs:
            problems.append(
                f"UNCONDITIONAL_SKIP_OK names '{allowlisted_job}', which is "
                "not a declared dependency of this job (absent from "
                "`needs`). The allowlist is stale -- most likely the job "
                "was renamed -- and the real job it used to cover is now "
                "unguarded."
            )
    if BREAKING_SCHEMA_JOB not in needs:
        problems.append(
            f"'{BREAKING_SCHEMA_JOB}' is not a declared dependency of this "
            "job (absent from `needs`). check_required_gate.py's "
            "classifier-gated verification is dead code if this job was "
            "renamed -- fix the name here and in ci.yml together."
        )

    for job, info in needs.items():
        result = info.get("result") if isinstance(info, dict) else None
        if result == "success":
            continue
        if result == "skipped" and job in UNCONDITIONAL_SKIP_OK:
            continue
        if result == "skipped" and job == BREAKING_SCHEMA_JOB:
            safe, message = verify_breaking_schema_check_skip(needs)
            if safe:
                justifications.append(message)
                continue
            problems.append(message)
            continue
        problems.append(f"{job}={result!r}")

    return GateResult(ok=not problems, problems=problems, justifications=justifications)


def main(argv: list[str] | None = None) -> int:
    del argv  # No CLI args; input comes from the NEEDS_JSON env var (see below).

    raw = os.environ.get("NEEDS_JSON", "")
    if not raw.strip():
        print("::error::NEEDS_JSON is empty or unset; cannot verify the gate.")
        return 1
    try:
        needs = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"::error::NEEDS_JSON is not valid JSON: {exc}")
        return 1

    # Print the full result map before deciding, so a future reader debugging
    # a red (or unexpectedly green) gate can see exactly what every
    # dependency reported, including `changes`'s outputs.
    print("Dependency result map:")
    print(json.dumps(needs, indent=2, sort_keys=True))

    result = evaluate(needs)
    for justification in result.justifications:
        print(f"  {justification}")

    if not result.ok:
        print("::error::ci-required FAILED:")
        for problem in result.problems:
            print(f"::error::  {problem}")
        return 1

    print(
        "ci-required passed: every dependency succeeded, or skipped for a "
        "verified-safe reason."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
