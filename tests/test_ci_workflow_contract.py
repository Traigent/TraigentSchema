from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SPINE_PIN = "0144cdc8d6e3fb6a7a08d27e1b6caafbe87a28ca"


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text()


def test_spine_core_caller_contract() -> None:
    text = _workflow("spine-core.yml")

    assert f"spine-core-reusable.yml@{SPINE_PIN}" in text
    assert "repo_id: TraigentSchema" in text
    assert "mode: advisory" in text
    assert f"spine_sha: {SPINE_PIN}" in text
    assert "VALIDATION_CI_PAT: ${{ secrets.VALIDATION_CI_PAT }}" in text
    assert "secrets: inherit" not in text
    assert "pull_request_target" not in text
    assert "permissions:\n  contents: read" in text
    assert re.search(r"(?m)^\s+\w[\w-]*:\s+write\s*$", text) is None
    assert "branches: [develop, main]" in text
    assert "types: [opened, edited, synchronize, reopened, ready_for_review]" in text
    assert "merge_group:" in text
    assert "types: [checks_requested]" in text
    assert "base_ref: ${{ github.event.pull_request.base.ref || github.event.merge_group.base_ref }}" in text
    assert "head_ref: ${{ github.event.pull_request.head.ref || github.event.merge_group.head_ref }}" in text
    assert "head_sha: ${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}" in text
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in text


def test_g8_dispatch_preserves_exact_head_sha_and_fails_without_pat() -> None:
    text = _workflow("validation-g8-dispatch.yml")

    assert "SOURCE_HEAD_SHA: ${{ github.event.workflow_run.head_sha }}" in text
    assert 'source_sha="${SOURCE_HEAD_SHA:-$GITHUB_SHA}"' in text
    assert '-f client_payload[source_head_sha]="$source_sha"' in text
    missing_pat = re.search(
        r'if \[ -z "\$\{GH_TOKEN:-\}" \]; then(?P<body>.*?)\n\s*fi',
        text,
        re.DOTALL,
    )
    assert missing_pat is not None
    assert "::error::VALIDATION_CI_PAT is not configured" in missing_pat.group("body")
    assert "exit 1" in missing_pat.group("body")
    assert "::warning::VALIDATION_CI_PAT is not configured" not in text


def test_validation_spine_preflight_fails_closed_but_keeps_dependabot_exception() -> None:
    text = _workflow("validation-spine-pr.yml")

    assert "spine-token-preflight:" in text
    assert "name: Spine token preflight (advisory)" in text
    assert "needs: spine-token-preflight" in text
    assert "needs.spine-token-preflight.outputs.has_token == 'true'" in text
    assert "secrets.SPINE_RO_TOKEN || secrets.VALIDATION_CI_PAT" in text
    assert "::error::validation-spine-pr (missing-secret):" in text
    assert 'if [ "$ACTOR" = "dependabot[bot]" ]; then' in text
    assert "::notice::SPINE_RO_TOKEN unavailable for dependabot PR" in text
    assert text.index("dependabot[bot]") < text.index("::error::validation-spine-pr")


def test_schema_policy_surface_session_link_is_additive_and_merge_queue_safe() -> None:
    text = _workflow("spine-session-link.yml")
    trail = _workflow("spine-trail-gate.yml")

    assert "name: policy-surface session link (advisory)" in text
    assert "types: [opened, edited, synchronize, reopened, ready_for_review, labeled, unlabeled]" in text
    assert "merge_group:" in text
    assert "github.event_name == 'merge_group'" in text
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in text
    assert "pull_request_target" not in text
    assert "pull-requests: read" in text
    assert "traigent_schema/schemas/auth/**" in text
    assert "traigent_schema/schemas/billing/**" in text
    assert "traigent_schema/schemas/observability/**" in text
    assert "Spine-Session:" in text
    assert "Spine-Trail:" in text
    assert "Spine: none" in text
    assert "spine-exempt" in text
    assert "Spine-Trail:" in trail
    assert "Spine: cs_" in trail
    assert "Spine: none" in trail
