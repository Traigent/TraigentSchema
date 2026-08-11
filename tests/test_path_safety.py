"""Tests for scripts/_path_safety.py and the two containment fixes that use it.

These are the negative-control tests for a security helper, so they are written to fail
loudly if the control is ever removed rather than to describe the current implementation.
Each "escape" case below was reachable before this module existed:

  - ``load_tree_from_dir`` used ``rglob("*.json")`` + ``read_text()``, both of which follow
    symlinks, so a symlinked ``*.json`` committed under traigent_schema/schemas/ would be
    read from outside the tree and its content compared (and logged) by the differ.
  - ``load_tree_from_ref`` piped ``git archive`` into ``tar -x`` with no member checking,
    so a member with ``..`` in its path, or a symlink member, was extracted unvalidated.
  - ``refresh_consumer_schema_references.py`` performed containment-only validation, then
    delegated to ``tarfile.extractall``; special members still depended on tarfile's
    platform-specific behavior.
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


def _load_refresh_module():
    spec = importlib.util.spec_from_file_location(
        "refresh_consumer_schema_references", SCRIPTS / "refresh_consumer_schema_references.py"
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
        with pytest.raises(ValueError, match="(unsafe tar member path|escapes destination)"):
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


@pytest.mark.parametrize(
    "member",
    [
        tarfile.TarInfo("safe-symlink"),
        tarfile.TarInfo("safe-hard-link"),
        tarfile.TarInfo("char-device"),
        tarfile.TarInfo("block-device"),
        tarfile.TarInfo("fifo"),
    ],
    ids=["symlink", "hardlink", "char-device", "block-device", "fifo"],
)
def test_refresh_archive_extraction_skips_nonregular_consumer_members(
    tmp_path: Path, member: tarfile.TarInfo
) -> None:
    """Consumer scans must not materialize archive links or special members."""
    refresh = _load_refresh_module()
    if member.name == "safe-symlink":
        member.type = tarfile.SYMTYPE
        member.linkname = "inside.json"
    elif member.name == "safe-hard-link":
        member.type = tarfile.LNKTYPE
        member.linkname = "inside.json"
    elif member.name == "char-device":
        member.type = tarfile.CHRTYPE
    elif member.name == "block-device":
        member.type = tarfile.BLKTYPE
    else:
        member.type = tarfile.FIFOTYPE

    source = tarfile.TarInfo("src/consumer.py")
    payload = b"schema = 'example_schema.json'\n"
    source.size = len(payload)
    with _tar_with([source, member], {source.name: payload}) as tar:
        refresh._extract_validated_tar_members(tar, tmp_path)

    assert (tmp_path / source.name).read_bytes() == payload
    assert not (tmp_path / member.name).exists()


def test_refresh_archive_extraction_skips_a_consumer_docs_symlink(tmp_path: Path) -> None:
    """A real consumer-repo-style docs symlink is irrelevant to source scanning."""
    refresh = _load_refresh_module()
    docs_link = tarfile.TarInfo("docs/concepts")
    docs_link.type = tarfile.SYMTYPE
    docs_link.linkname = "traceability/concepts"
    source = tarfile.TarInfo("src/consumer.py")
    payload = b"schema = 'example_schema.json'\n"
    source.size = len(payload)

    with _tar_with([docs_link, source], {source.name: payload}) as tar:
        refresh._extract_validated_tar_members(tar, tmp_path)

    assert (tmp_path / source.name).read_bytes() == payload
    assert not (tmp_path / "docs" / "concepts").exists()


def test_refresh_archive_extraction_materializes_regular_files(tmp_path: Path) -> None:
    """The hardening must preserve the ordinary git-archive materialization path."""
    refresh = _load_refresh_module()
    directory = tarfile.TarInfo("src")
    directory.type = tarfile.DIRTYPE
    file_member = tarfile.TarInfo("src/consumer.py")
    payload = b"schema = 'example_schema.json'\n"
    file_member.size = len(payload)

    with _tar_with([directory, file_member], {file_member.name: payload}) as tar:
        refresh._extract_validated_tar_members(tar, tmp_path)

    assert (tmp_path / "src" / "consumer.py").read_bytes() == payload


def test_tar_prevalidation_rejects_late_unsafe_member_without_writes(tmp_path: Path) -> None:
    """Every member must be approved before a preceding regular file is materialized."""
    source = tarfile.TarInfo("src/consumer.py")
    payload = b"schema = 'example_schema.json'\n"
    source.size = len(payload)
    unsafe = tarfile.TarInfo("late-fifo")
    unsafe.type = tarfile.FIFOTYPE

    with _tar_with([source, unsafe], {source.name: payload}) as tar:
        with pytest.raises(ValueError, match="unsafe tar member type"):
            ps.extract_validated_tar_members(tar, tmp_path)

    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("members", "payloads"),
    [
        (
            [tarfile.TarInfo("src/consumer.py"), tarfile.TarInfo("src/consumer.py")],
            {"src/consumer.py": b"first"},
        ),
        (
            [tarfile.TarInfo("src"), tarfile.TarInfo("src/consumer.py")],
            {"src": b"not a directory", "src/consumer.py": b"second"},
        ),
    ],
    ids=["duplicate-destination", "non-directory-parent"],
)
def test_tar_prevalidation_rejects_collisions_without_writes(
    tmp_path: Path, members: list[tarfile.TarInfo], payloads: dict[str, bytes]
) -> None:
    """Duplicate paths and file-as-directory collisions fail before materialization."""
    for member in members:
        member.size = len(payloads[member.name])

    with _tar_with(members, payloads) as tar:
        with pytest.raises(ValueError, match="(duplicate tar member|non-directory parent)"):
            ps.extract_validated_tar_members(tar, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_schema_archive_rejects_unsupported_target_member_without_writes(tmp_path: Path) -> None:
    """A link at the schema target is never skipped or materialized by the strict caller."""
    gate = _load_gate_module()
    source = tarfile.TarInfo("traigent_schema/schemas/ordinary_schema.json")
    source.size = 2
    unsupported = tarfile.TarInfo("traigent_schema/schemas/linked_schema.json")
    unsupported.type = tarfile.SYMTYPE
    unsupported.linkname = "ordinary_schema.json"

    with _tar_with([source, unsupported], {source.name: b"{}"}) as tar:
        with pytest.raises(ValueError, match="unsafe tar member type"):
            gate._extract_validated_tar_members(
                tar, tmp_path, required_paths=(gate.SCHEMAS_SUBDIR,)
            )

    assert list(tmp_path.iterdir()) == []


def test_schema_archive_requires_its_schema_target(tmp_path: Path) -> None:
    """A malformed archive cannot turn an absent schema path into an empty comparison."""
    gate = _load_gate_module()
    unrelated = tarfile.TarInfo("README.md")
    unrelated.size = 2

    with _tar_with([unrelated], {unrelated.name: b"{}"}) as tar:
        with pytest.raises(ValueError, match="required tar directory is missing"):
            gate._extract_validated_tar_members(
                tar, tmp_path, required_paths=(gate.SCHEMAS_SUBDIR,)
            )

    assert list(tmp_path.iterdir()) == []


def test_schema_archive_requires_a_directory_at_its_schema_target(tmp_path: Path) -> None:
    """A file named ``schemas`` must not become an empty schema-tree comparison."""
    gate = _load_gate_module()
    schema_target = tarfile.TarInfo(gate.SCHEMAS_SUBDIR)
    schema_target.size = 2

    with _tar_with([schema_target], {schema_target.name: b"{}"}) as tar:
        with pytest.raises(ValueError, match="required tar directory is missing"):
            gate._extract_validated_tar_members(
                tar, tmp_path, required_paths=(gate.SCHEMAS_SUBDIR,)
            )

    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.FIFOTYPE])
def test_required_schema_target_cannot_be_a_skipped_non_directory(
    tmp_path: Path, member_type: bytes
) -> None:
    """Skip policy cannot silently omit a directory a caller declared required."""
    gate = _load_gate_module()
    schema_target = tarfile.TarInfo(gate.SCHEMAS_SUBDIR)
    schema_target.type = member_type
    if member_type == tarfile.SYMTYPE:
        schema_target.linkname = "."

    with _tar_with([schema_target], {}) as tar:
        with pytest.raises(ValueError, match="required tar directory is missing"):
            ps.extract_validated_tar_members(
                tar,
                tmp_path,
                special_member_policy="skip",
                required_paths=(gate.SCHEMAS_SUBDIR,),
            )

    assert list(tmp_path.iterdir()) == []


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
