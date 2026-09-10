"""Offline structural guard for the package job's certification witness."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

import traigent_schema

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_PROVENANCE_FRAGMENTS = (
    "python -I - <<'PY'",
    "Path(sys.prefix).resolve()",
    "site.getsitepackages()",
    "for module in (traigent_schema, relying_party_verifier)",
    "CLIENT_CO_ATTESTATION_CONTEXT_FIELDS,",
    "ClientCoAttestationContext,",
    "len(CLIENT_CO_ATTESTATION_CONTEXT_FIELDS) == 19",
    "RelyingPartyVerificationError,",
    "derive_client_key_ref,",
    "prepare_client_co_attestation,",
    "prepare_client_co_attestation({}, context=object())",
    'assert exc.code == "CO_PROJECTION", exc.code',
    "Path(module.__file__).resolve()",
    "module_path.is_relative_to(environment_root)",
    "any(module_path.is_relative_to(path) for path in site_packages)",
)


def _jobs() -> dict[str, Any]:
    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict), "ci.yml must parse as a workflow mapping"
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), "ci.yml must define jobs"
    return jobs


def _named_step(job: dict[str, Any], name: str) -> dict[str, Any]:
    matching = [step for step in job.get("steps", []) if step.get("name") == name]
    assert len(matching) == 1, f"package job must contain exactly one {name!r} step"
    return matching[0]


def _assert_installed_module_provenance(witness: str) -> None:
    for fragment in _PROVENANCE_FRAGMENTS:
        assert fragment in witness, f"wheel witness lost provenance guard: {fragment}"


def test_required_package_job_owns_plain_certification_wheel_witness() -> None:
    """The required package job, not ordinary pytest, proves the installed wheel."""
    jobs = _jobs()
    package_job = jobs["package"]
    ci_required_needs = jobs["ci-required"]["needs"]

    assert "package" in ci_required_needs
    assert package_job.get("needs") == "lint-type"

    install_tools = str(_named_step(package_job, "Install packaging tools").get("run", ""))
    assert "pip==26.2.1" in install_tools
    assert "build==1.5.0 twine==7.0.0" in install_tools
    assert install_tools.count("--only-binary :all:") == 2

    witness = str(_named_step(package_job, "Test installation from built wheel").get("run", ""))
    assert "python -m venv test_env" in witness
    assert "--only-binary :all:" in witness
    assert "--constraint requirements-dev.txt dist/*.whl" in witness
    assert "[certification]" not in witness
    assert 'metadata("traigent-schema")' in witness
    assert 'get_all("Requires-Dist")' in witness
    assert 'get_all("Provides-Extra")' in witness
    assert '"certification" in' in witness
    assert "import cryptography" in witness
    assert "from traigent_schema.certification import relying_party_verifier" in witness
    _assert_installed_module_provenance(witness)


@pytest.mark.parametrize("fragment", _PROVENANCE_FRAGMENTS)
def test_wheel_witness_provenance_guard_rejects_each_removed_check(fragment: str) -> None:
    package_job = _jobs()["package"]
    witness = str(_named_step(package_job, "Test installation from built wheel").get("run", ""))
    mutated = witness.replace(fragment, "", 1)

    with pytest.raises(AssertionError, match="lost provenance guard"):
        _assert_installed_module_provenance(mutated)


# --------------------------------------------------------------------------
# P1-V2.6 commit 1 (G10): importing ``traigent_schema.certification`` must
# validate the four agent-quality package documents (objective registry,
# aggregation policy, non-claim catalog, quantile table) against their
# pinned digests INSIDE the content-free boundary -- a tampered installed
# document makes the import fail loudly with ``PACKAGE_DATA_INVALID``, never
# silently succeed with stale/corrupt package data. The eager, import-time
# validation loop already lives at the bottom of
# ``agent_quality_verifier.py`` (it runs unconditionally as soon as that
# module is imported, and ``traigent_schema/certification/__init__.py`` now
# imports it); this proves the end-to-end behavior against a genuinely
# tampered SCRATCH COPY of the installed package, in a fresh subprocess, not
# merely a monkeypatched in-process loader.
# --------------------------------------------------------------------------

_AGENT_QUALITY_PACKAGE_DOCUMENT_STEMS = (
    "objective_registry",
    "aggregation_policy",
    "non_claim_catalog",
    "quantile_table",
)


def _scratch_copy_of_traigent_schema(dest_parent: Path) -> Path:
    """Copy the real, installed ``traigent_schema`` package tree under
    ``dest_parent`` and return the copy's own root. The copy is a real,
    importable package -- tampering one file inside it and prepending
    ``dest_parent`` to ``sys.path``/``PYTHONPATH`` makes a fresh interpreter
    import THIS copy instead of the real installation."""
    source_root = Path(traigent_schema.__file__).resolve().parent
    scratch_root = dest_parent / "traigent_schema"
    shutil.copytree(source_root, scratch_root)
    return scratch_root


def _tamper_document(document_path: Path) -> None:
    """Mutate a JSON document's content so it no longer matches its pinned
    digest, while staying valid JSON -- the digest is computed over the
    entire document, so adding one extra field is a minimal, unambiguous
    content mutation (the same class of change a single flipped byte in the
    raw file would cause, minus the risk of landing mid-escape-sequence and
    producing invalid JSON that would fail for the WRONG reason)."""
    payload = json.loads(document_path.read_text(encoding="utf-8"))
    tampered = dict(payload, _tamper_canary="CANARY_TAMPERED_PACKAGE_DATA")
    document_path.write_text(json.dumps(tampered), encoding="utf-8")


@pytest.mark.parametrize("stem", _AGENT_QUALITY_PACKAGE_DOCUMENT_STEMS)
def test_tampered_agent_quality_package_document_fails_import_loudly(
    stem: str, tmp_path: Path
) -> None:
    """A one-byte tamper to any of the four shipped agent-quality package
    documents, in a scratch copy of the installed package, makes
    ``import traigent_schema.certification`` fail with
    ``PACKAGE_DATA_INVALID`` in a FRESH interpreter -- proving the guard
    runs unconditionally at import time, not only when a caller happens to
    touch that registry first."""
    scratch_root = _scratch_copy_of_traigent_schema(tmp_path)
    document_path = scratch_root / "data" / "certification" / f"agent_quality_{stem}.json"
    assert document_path.is_file(), document_path
    _tamper_document(document_path)

    script = "import traigent_schema.certification"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert "PACKAGE_DATA_INVALID" in result.stderr, result.stderr
    assert "CANARY_TAMPERED_PACKAGE_DATA" not in result.stderr, (
        "tampered document content leaked into the import-time failure"
    )


def test_untampered_scratch_copy_imports_cleanly(tmp_path: Path) -> None:
    """Control for the tamper test above: the SAME scratch-copy-plus-
    subprocess mechanism, with no tamper applied, must import cleanly --
    proving a failure above is caused by the tamper, not by the harness."""
    _scratch_copy_of_traigent_schema(tmp_path)
    script = "import traigent_schema.certification"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


# --------------------------------------------------------------------------
# P1-V2.6 commit 1, wheel witness (G10): the public entry point verified
# end to end from a BUILT WHEEL installed into a FRESH venv -- not the
# editable/source install this whole test suite otherwise runs against.
# Proves the package as it will actually ship (declared dependencies,
# packaged data files, no dev-only path magic) can verify a real bundle.
# Skipped, with a reason, when the ``build`` package is unavailable -- the
# packet brief requires this test to be run once un-skipped as part of the
# commit's own proof, not to gate every future CI run on network/build
# availability.
# --------------------------------------------------------------------------

_WHEEL_WITNESS_SCRIPT = """\
import json

from traigent_schema.certification import (
    AgentQualityVerificationContext,
    ProcessRecordVerificationContext,
    verify_agent_quality_certificate,
)
from traigent_schema.certification.relying_party_verifier import VerificationContext

with open("vectors.json") as f:
    vectors = json.load(f)


def _process_record_context(d):
    d = dict(d)
    d["base_context"] = VerificationContext(**d["base_context"])
    return ProcessRecordVerificationContext(**d)


def _agent_quality_context(d):
    d = dict(d)
    d["process_record_context"] = _process_record_context(d["process_record_context"])
    return AgentQualityVerificationContext(**d)


result = verify_agent_quality_certificate(
    vectors["golden"],
    context=_agent_quality_context(vectors["context"]),
    process_record_bundle=vectors["process_record"],
)
assert result.code == "AGENT_QUALITY_VERIFIED", result.code

abstained_result = verify_agent_quality_certificate(
    vectors["abstained"],
    context=_agent_quality_context(vectors["context_abstained"]),
    process_record_bundle=vectors["process_record"],
)
assert abstained_result.code == "AGENT_QUALITY_CLAIM_ABSTAINED", abstained_result.code

print("WHEEL WITNESS OK")
"""


def _agent_quality_test_module():
    """Import ``tests/test_agent_quality_verifier.py`` as a plain module (not
    via pytest collection) so this test can reach its golden-bundle/context
    builders without this file importing a sibling test module at
    collection time."""
    import importlib.util

    module_path = _REPO_ROOT / "tests" / "test_agent_quality_verifier.py"
    spec = importlib.util.spec_from_file_location("_gv_wheel_witness_source", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wheel_witness_verifies_golden_and_abstained_agent_quality_bundles(
    tmp_path: Path,
) -> None:
    """Build the wheel, install it into a fresh venv under
    ``/tmp/claude-1000/``, and -- in THAT interpreter, cwd outside the repo,
    ``PYTHONPATH`` unset -- verify the golden bundle to
    ``AGENT_QUALITY_VERIFIED`` and the abstained golden to
    ``AGENT_QUALITY_CLAIM_ABSTAINED`` through the public entry point."""
    pytest.importorskip("build", reason="the 'build' package is not installed")
    import dataclasses
    import uuid

    dist_dir = tmp_path / "dist"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir)],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    wheels = list(dist_dir.glob("*.whl"))
    assert len(wheels) == 1, wheels
    wheel_path = wheels[0]

    claude_1000 = Path("/tmp/claude-1000")
    claude_1000.mkdir(parents=True, exist_ok=True)
    venv_dir = claude_1000 / f"pv6-wheel-witness-{uuid.uuid4().hex[:12]}"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    venv_python = venv_dir / "bin" / "python"
    try:
        subprocess.run(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--quiet",
                "--only-binary",
                ":all:",
                "--constraint",
                str(_REPO_ROOT / "requirements-dev.txt"),
                str(wheel_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )

        gv = _agent_quality_test_module()
        vectors = {
            "golden": gv.build_agent_quality_bundle(),
            "abstained": gv.build_abstained_agent_quality_bundle(),
            "process_record": gv._GV_PROCESS_RECORD_BUNDLE,
            "context": dataclasses.asdict(gv.build_agent_quality_context()),
            "context_abstained": dataclasses.asdict(
                gv.build_agent_quality_context(accept_abstained_bundle=True)
            ),
        }

        work_dir = claude_1000 / f"pv6-wheel-witness-cwd-{uuid.uuid4().hex[:12]}"
        work_dir.mkdir()
        (work_dir / "vectors.json").write_text(json.dumps(vectors), encoding="utf-8")
        (work_dir / "witness.py").write_text(_WHEEL_WITNESS_SCRIPT, encoding="utf-8")

        result = subprocess.run(
            [str(venv_python), "-I", "witness.py"],
            cwd=work_dir,
            env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert "WHEEL WITNESS OK" in result.stdout, (result.stdout, result.stderr)
    finally:
        shutil.rmtree(venv_dir, ignore_errors=True)
        shutil.rmtree(claude_1000 / "pv6-wheel-witness-cwd", ignore_errors=True)
        for stray in claude_1000.glob("pv6-wheel-witness-cwd-*"):
            shutil.rmtree(stray, ignore_errors=True)
