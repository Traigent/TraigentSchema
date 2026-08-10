"""Tests for scripts/_path_safety.py and the two containment fixes that use it.

These are the negative-control tests for a security helper, so they are written to fail
loudly if the control is ever removed rather than to describe the current implementation.
Each "escape" case below was reachable before this module existed:

  - ``load_tree_from_dir`` used ``rglob("*.json")`` + ``read_text()``, both of which follow
    symlinks, so a symlinked ``*.json`` committed under traigent_schema/schemas/ would be
    read from outside the tree and its content compared (and logged) by the differ.
  - ``load_tree_from_ref`` piped ``git archive`` into ``tar -x`` with no member checking,
    so a member with ``..`` in its path, or a symlink member, was extracted unvalidated.
    The sibling script refresh_consumer_schema_references.py already validated members;
    the two copies of the hardening had diverged.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

_spec = importlib.util.spec_from_file_location("_path_safety", SCRIPTS / "_path_safety.py")
assert _spec and _spec.loader
ps = importlib.util.module_from_spec(_spec)
sys.modules["_path_safety"] = ps
_spec.loader.exec_module(ps)


def _load_gate_module():
    spec = importlib.util.spec_from_file_location(
        "breaking_schema_check", SCRIPTS / "breaking_schema_check.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- git refs


@pytest.mark.parametrize(
    "bad",
    [
        "--upload-pack=/bin/sh",  # would be read by git as a flag, not a ref
        "-x",
        "refs/../../etc",
        "a//b",
        "main@{yesterday}",
        "main.lock",
        "trailing/",
        " main",
        "",
        "x" * 201,
    ],
)
def test_safe_git_ref_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        ps.safe_git_ref(bad, "--ref")


@pytest.mark.parametrize("good", ["main", "origin/develop", "v1.2.3", "HEAD~2", "a/b/c"])
def test_safe_git_ref_accepts_real_refs(good: str) -> None:
    assert ps.safe_git_ref(good, "--ref") == good


# ------------------------------------------------------------------------ path within


def test_resolve_path_within_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ValueError):
        ps.resolve_path_within(root / ".." / "outside", root, "dest")


def test_resolve_path_within_allows_child_and_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    assert ps.resolve_path_within(root / "a", root, "dest") == (root / "a").resolve()
    assert ps.resolve_path_within(root, root, "dest") == root.resolve()


# ----------------------------------------------------------------------- tar members


def _tar_with(
    members: list[tarfile.TarInfo], payloads: dict[str, bytes] | None = None
) -> tarfile.TarFile:
    payloads = payloads or {}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for m in members:
            data = payloads.get(m.name)
            tar.addfile(m, io.BytesIO(data) if data is not None else None)
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r")


def test_tar_traversal_member_is_rejected(tmp_path: Path) -> None:
    m = tarfile.TarInfo("../escaped.json")
    m.size = 2
    with _tar_with([m], {"../escaped.json": b"{}"}) as tar:
        with pytest.raises(ValueError, match="escapes destination"):
            ps.validate_tar_members_stay_within(tar, tmp_path)


def test_tar_symlink_member_pointing_outside_is_rejected(tmp_path: Path) -> None:
    m = tarfile.TarInfo("link.json")
    m.type = tarfile.SYMTYPE
    m.linkname = "../../../../etc/passwd"
    with _tar_with([m]) as tar:
        with pytest.raises(ValueError, match="link escapes destination"):
            ps.validate_tar_members_stay_within(tar, tmp_path)


def test_ordinary_tar_is_accepted(tmp_path: Path) -> None:
    m = tarfile.TarInfo("traigent_schema/schemas/x.json")
    m.size = 2
    with _tar_with([m], {"traigent_schema/schemas/x.json": b"{}"}) as tar:
        ps.validate_tar_members_stay_within(tar, tmp_path)  # must not raise


# ------------------------------------------------- the differ must not read via symlink


def test_load_tree_from_dir_ignores_symlinked_json(tmp_path: Path) -> None:
    """A symlinked *.json must not be read, even though rglob still yields it."""
    gate = _load_gate_module()

    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.json"
    secret.write_text(json.dumps({"leaked": True}), encoding="utf-8")

    root = tmp_path / "tree"
    root.mkdir()
    (root / "real.json").write_text(json.dumps({"type": "object"}), encoding="utf-8")
    try:
        (root / "sneaky.json").symlink_to(secret)
    except (OSError, NotImplementedError):  # pragma: no cover - platform without symlinks
        pytest.skip("symlinks unavailable on this platform")

    tree = gate.load_tree_from_dir(root, "probe")

    assert "real.json" in tree.files, "the ordinary schema must still load"
    assert "sneaky.json" not in tree.files, (
        "a symlinked *.json was read — content from outside the schema tree can reach the "
        "diff and the CI log"
    )
    assert all(v != {"leaked": True} for v in tree.files.values())


def test_load_tree_from_dir_still_reads_ordinary_files(tmp_path: Path) -> None:
    """Negative control for the check above: the skip must be symlink-specific."""
    gate = _load_gate_module()
    root = tmp_path / "tree"
    (root / "nested").mkdir(parents=True)
    (root / "a.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
    (root / "nested" / "b.json").write_text(json.dumps({"b": 2}), encoding="utf-8")

    tree = gate.load_tree_from_dir(root, "probe")
    assert set(tree.files) == {"a.json", "nested/b.json"}
