"""Tests for scripts/compile_changelog.py (changelog fragments)."""

from __future__ import annotations

import importlib.util
import re
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "compile_changelog.py"

_spec = importlib.util.spec_from_file_location("compile_changelog", SCRIPT)
assert _spec and _spec.loader
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

BASE_CHANGELOG = """# Changelog

Intro.

## [Unreleased]

Unreleased changes are kept as fragments in changelog.d/; see changelog.d/README.md

## [1.0.0] - 2026-01-01

### Added
- First release.

### Fixed
- Early fix.
"""


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "changelog.d").mkdir()
    (tmp_path / "changelog.d" / "README.md").write_text("readme\n")
    (tmp_path / "changelog.d" / ".gitkeep").write_text("")
    (tmp_path / "CHANGELOG.md").write_text(BASE_CHANGELOG)
    return tmp_path


def frag(root: Path, name: str, body: str = "- entry\n") -> Path:
    path = root / "changelog.d" / name
    path.write_text(body)
    return path


def run(root: Path, *args: str) -> int:
    return cc.main(["--root", str(root), *args])


def test_groups_and_orders_sections_and_sorts_by_slug(root: Path) -> None:
    frag(root, "zeta.fixed.md", "- fixed z\n")
    frag(root, "beta.added.md", "- added b\n")
    frag(root, "alpha.added.md", "- added a\n")
    frag(root, "gone.removed.md", "- removed g\n")
    frag(root, "mid.changed.md", "- changed m\n")
    frag(root, "brk.breaking.md", "- breaking b\n")
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 0
    text = (root / "CHANGELOG.md").read_text()
    section = text.split("## [1.1.0] - 2026-02-02\n", 1)[1].split("\n## [", 1)[0]
    headings = re.findall(r"^### (.+)$", section, re.MULTILINE)
    assert headings == ["Breaking", "Added", "Changed", "Removed", "Fixed"]
    assert section.index("- added a") < section.index("- added b")


def test_dated_section_sits_below_pointer_in_released_format(root: Path) -> None:
    frag(root, "one.added.md", "- one\n")
    run(root, "--version", "1.1.0", "--date", "2026-02-02")
    text = (root / "CHANGELOG.md").read_text()
    expected = (
        "Unreleased changes are kept as fragments in changelog.d/; see changelog.d/README.md\n\n"
        "## [1.1.0] - 2026-02-02\n\n### Added\n- one\n\n## [1.0.0] - 2026-01-01\n"
    )
    assert expected in text
    # Same shape as the existing released section: heading, blank, ### heading, bullets.
    assert re.search(r"^## \[1\.1\.0\] - \d{4}-\d{2}-\d{2}\n\n### Added\n- ", text, re.M)


def test_compiled_fragments_are_deleted_but_readme_and_gitkeep_stay(root: Path) -> None:
    a = frag(root, "a.added.md")
    b = frag(root, "b.fixed.md")
    run(root, "--version", "1.1.0", "--date", "2026-02-02")
    assert not a.exists() and not b.exists()
    assert (root / "changelog.d" / "README.md").exists()
    assert (root / "changelog.d" / ".gitkeep").exists()


def test_existing_version_is_refused_and_nothing_changes(root: Path) -> None:
    f = frag(root, "a.added.md")
    assert run(root, "--version", "1.0.0", "--date", "2026-02-02") == 2
    assert f.exists()
    assert (root / "CHANGELOG.md").read_text() == BASE_CHANGELOG


@pytest.mark.parametrize(
    "name",
    ["a.bogus.md", "Bad_Name.added.md", "noType.md", "a.added.txt", "a.b.added.md"],
)
def test_bad_type_or_name_is_refused(root: Path, name: str) -> None:
    frag(root, name)
    assert run(root, "--check") == 2
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert (root / "CHANGELOG.md").read_text() == BASE_CHANGELOG


@pytest.mark.parametrize("body", ["", "\n\n  \n", "not a bullet\n"])
def test_empty_or_bulletless_fragment_is_refused(root: Path, body: str) -> None:
    frag(root, "a.added.md", body)
    assert run(root, "--check") == 2
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2


def test_check_passes_on_valid_and_on_empty_directory(root: Path) -> None:
    assert run(root, "--check") == 0
    frag(root, "a.added.md")
    assert run(root, "--check") == 0
    assert (root / "changelog.d" / "a.added.md").exists()
    assert (root / "CHANGELOG.md").read_text() == BASE_CHANGELOG


def test_dry_run_prints_and_writes_nothing(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = frag(root, "a.added.md", "- dry\n")
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02", "--dry-run") == 0
    assert "## [1.1.0] - 2026-02-02" in capsys.readouterr().out
    assert f.exists()
    assert (root / "CHANGELOG.md").read_text() == BASE_CHANGELOG


def test_released_sections_are_untouched(root: Path) -> None:
    frag(root, "a.added.md")
    run(root, "--version", "1.1.0", "--date", "2026-02-02")
    data = (root / "CHANGELOG.md").read_bytes()
    base = BASE_CHANGELOG.encode()
    cut = base.index(b"## [1.0.0]")
    assert data.endswith(base[cut:])
    assert data.startswith(base[:cut])


def test_requires_version_and_date_and_valid_formats(root: Path) -> None:
    frag(root, "a.added.md")
    assert run(root) == 2
    assert run(root, "--version", "1.1", "--date", "2026-02-02") == 2
    assert run(root, "--version", "1.1.0", "--date", "02-02-2026") == 2


def test_no_fragments_refuses_compile(root: Path) -> None:
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2


def test_repository_fragments_and_pointer_are_valid() -> None:
    assert cc.main(["--check"]) == 0
    text = (REPO_ROOT / "CHANGELOG.md").read_text()
    assert re.search(r"^## \[Unreleased\]\n\n" + re.escape(cc.POINTER) + r"\n\n## \[", text, re.M)


def test_compiling_into_real_changelog_keeps_released_sections(tmp_path: Path) -> None:
    (tmp_path / "changelog.d").mkdir()
    shutil.copy(REPO_ROOT / "CHANGELOG.md", tmp_path / "CHANGELOG.md")
    (tmp_path / "changelog.d" / "x.added.md").write_text("- x\n")
    original = (tmp_path / "CHANGELOG.md").read_text()
    assert run(tmp_path, "--version", "99.0.0", "--date", "2030-01-01") == 0
    new = (tmp_path / "CHANGELOG.md").read_text()
    released_from = original.index("\n## [8.0.0]")
    assert new.encode().endswith(original[released_from:].encode())


# --- review hardening -------------------------------------------------------


def test_symlinked_fragment_directory_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "a.added.md").write_text("- x\n")
    base = tmp_path / "repo"
    base.mkdir()
    (base / "CHANGELOG.md").write_text(BASE_CHANGELOG)
    (base / "changelog.d").symlink_to(real, target_is_directory=True)
    assert run(base, "--check") == 2
    assert run(base, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert (real / "a.added.md").exists()


def test_symlinked_fragment_is_refused_even_named_like_an_exception(root: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside.md"
    target.write_text("- outside\n")
    (root / "changelog.d" / "a.added.md").symlink_to(target)
    assert run(root, "--check") == 2
    (root / "changelog.d" / "a.added.md").unlink()
    (root / "changelog.d" / "README.md").unlink()
    (root / "changelog.d" / "README.md").symlink_to(target)
    assert run(root, "--check") == 2
    (root / "changelog.d" / "README.md").unlink()
    (root / "changelog.d" / "README.md").write_text("r\n")
    (root / "changelog.d" / ".gitkeep").unlink()
    (root / "changelog.d" / ".gitkeep").symlink_to(target)
    assert run(root, "--check") == 2


def test_nested_directory_is_refused(root: Path) -> None:
    (root / "changelog.d" / "sub").mkdir()
    assert run(root, "--check") == 2
    (root / "changelog.d" / "sub").rmdir()
    (root / "changelog.d" / "README.md").unlink()
    (root / "changelog.d" / "README.md").mkdir()
    assert run(root, "--check") == 2


def test_write_failure_leaves_changelog_and_fragments_intact(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = frag(root, "a.added.md")

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(cc.os, "replace", boom)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") != 0
    assert (root / "CHANGELOG.md").read_bytes() == BASE_CHANGELOG.encode()
    assert f.exists()
    assert [p.name for p in (root / "changelog.d").iterdir() if p.name.endswith(".tmp")] == []
    assert sorted(p.name for p in root.iterdir()) == ["CHANGELOG.md", "changelog.d"]


def test_unlink_failure_after_replace_lists_remaining_paths_and_exits_1(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    frag(root, "a.added.md", "- alpha\n")
    frag(root, "b.added.md", "- beta\n")
    real_unlink = cc._unlink

    def flaky(path: Path) -> None:
        if path.name.endswith("b.added.md"):
            raise OSError("busy")
        real_unlink(path)

    monkeypatch.setattr(cc, "_unlink", flaky)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 1
    err = capsys.readouterr().err
    assert str(root / "changelog.d" / "b.added.md") in err
    assert "a.added.md" not in err
    assert "1.1.0" in err and "git rm" in err
    assert "## [1.1.0] - 2026-02-02" in (root / "CHANGELOG.md").read_text()
    assert (root / "changelog.d" / "b.added.md").exists()
    assert not (root / "changelog.d" / "a.added.md").exists()


def test_cleanup_option_no_longer_exists(root: Path) -> None:
    with pytest.raises(SystemExit) as info:
        run(root, "--cleanup-compiled", "--version", "1.1.0")
    assert info.value.code == 2


def test_junctioned_or_redirected_fragment_dir_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frag(root, "a.added.md")
    monkeypatch.setattr(Path, "is_junction", lambda self: self.name == "changelog.d", raising=False)
    assert run(root, "--check") == 2
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert (root / "changelog.d" / "a.added.md").exists()


def test_fragment_dir_realpath_must_equal_root_join(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    frag(root, "a.added.md")
    real = cc.os.path.realpath
    elsewhere = str(root / "elsewhere")
    monkeypatch.setattr(
        cc.os.path, "realpath",
        lambda p, **k: elsewhere if str(p).endswith("changelog.d") else real(p, **k),
    )
    assert run(root, "--check") == 2


def test_unclosed_fence_before_pointer_does_not_matter_structure_is_fixed(root: Path) -> None:
    frag(root, "a.added.md")
    text = (
        "# Changelog\n\n```\n## [Unreleased]\n\n"
        "## [1.0.0] - 2026-01-01\n\n### Added\n- F.\n"
    )
    (root / "CHANGELOG.md").write_text(text)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert (root / "CHANGELOG.md").read_text() == text


def test_fenced_version_example_cannot_hide_a_duplicate(root: Path) -> None:
    frag(root, "a.added.md")
    text = BASE_CHANGELOG + "\n```\n## [1.1.0] - 2026-02-02\n```\n"
    (root / "CHANGELOG.md").write_text(text)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-03") == 2
    assert (root / "CHANGELOG.md").read_text() == text


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("## [Unreleased]", "## [Unreleased] "),
        lambda t: t.replace("Unreleased changes are kept", "Pending changes are kept"),
        lambda t: t.replace("README.md\n\n## [1.0.0]", "README.md\n## [1.0.0]"),
        lambda t: t.replace("## [1.0.0] - 2026-01-01", "## [1.0.0]"),
        lambda t: t.replace("README.md\n\n## [1.0.0]", "README.md\n\nextra\n\n## [1.0.0]"),
    ],
)
def test_changelog_structure_deviations_are_refused(root: Path, mutate: object) -> None:
    frag(root, "a.added.md")
    text = mutate(BASE_CHANGELOG)  # type: ignore[operator]
    assert text != BASE_CHANGELOG
    (root / "CHANGELOG.md").write_text(text)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert (root / "CHANGELOG.md").read_text() == text


def test_blank_lines_before_pointer_are_allowed(root: Path) -> None:
    frag(root, "a.added.md")
    (root / "CHANGELOG.md").write_text(BASE_CHANGELOG.replace("## [Unreleased]\n\n", "## [Unreleased]\n\n\n"))
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 0


def test_fsync_failure_keeps_fragments_and_exits_1(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    f = frag(root, "a.added.md")

    def boom(_p: Path) -> None:
        raise OSError("io error")

    monkeypatch.setattr(cc, "_fsync_dir", boom)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 1
    err = capsys.readouterr().err
    assert "durable" in err and str(f) in err
    assert f.exists()


def test_invalid_utf8_fragment_exits_2(root: Path) -> None:
    (root / "changelog.d" / "a.added.md").write_bytes(b"- caf\xe9\n")
    assert run(root, "--check") == 2


def test_invalid_utf8_changelog_exits_2(root: Path) -> None:
    f = frag(root, "a.added.md")
    (root / "CHANGELOG.md").write_bytes(b"# Changelog\n\xff\xfe\n")
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert f.exists()


@pytest.mark.parametrize("raw", [b"- Entry\r## Notes\n", b"-    Entry\n  ## Notes\n", b"- a\rb\n"])
def test_bare_cr_and_under_indented_continuations_are_refused(root: Path, raw: bytes) -> None:
    (root / "changelog.d" / "a.added.md").write_bytes(raw)
    assert run(root, "--check") == 2


def test_continuation_at_content_column_is_accepted(root: Path) -> None:
    frag(root, "a.added.md", "- Entry\n  cont\n-    Wide\n     cont\n")
    assert run(root, "--check") == 0


def test_parent_directory_is_fsynced_after_replace_before_delete(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = frag(root, "a.added.md")
    calls: list[str] = []
    monkeypatch.setattr(cc, "_fsync_dir", lambda path: calls.append(f"fsync-dir:{f.exists()}"))
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 0
    assert calls == ["fsync-dir:True"]


def test_readonly_mode_is_not_applied_before_replace(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frag(root, "a.added.md")
    order: list[str] = []
    real_replace = cc.os.replace
    monkeypatch.setattr(
        cc.os, "replace",
        lambda a, b: (order.append("replace") if str(b).endswith("CHANGELOG.md") else None, real_replace(a, b))[1],
    )
    monkeypatch.setattr(cc.os, "chmod", lambda a, b: order.append("chmod"))
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 0
    assert order == ["replace", "chmod"]


def test_temp_unlink_failure_on_error_path_prints_its_path(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    frag(root, "a.added.md")

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("nope")

    monkeypatch.setattr(cc.os, "replace", boom)
    monkeypatch.setattr(cc.os, "unlink", boom)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 1
    assert ".changelog-" in capsys.readouterr().err


def test_dry_run_never_writes_or_deletes(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = frag(root, "a.added.md")

    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("dry-run must not write or delete")

    monkeypatch.setattr(cc, "write_atomic", forbidden)
    monkeypatch.setattr(cc, "_unlink", forbidden)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02", "--dry-run") == 0
    assert f.exists() and (root / "CHANGELOG.md").read_bytes() == BASE_CHANGELOG.encode()
    assert sorted(p.name for p in root.iterdir()) == ["CHANGELOG.md", "changelog.d"]


def test_missing_current_pointer_never_falls_back_to_a_historical_heading(root: Path) -> None:
    frag(root, "a.added.md")
    text = BASE_CHANGELOG.replace("## [Unreleased]\n\nUnreleased changes", "Unreleased changes")
    text = text.replace(
        "Unreleased changes are kept as fragments in changelog.d/; see changelog.d/README.md\n\n", ""
    )
    text += "\n## [Unreleased]\n\n### Added\n- old\n"
    (root / "CHANGELOG.md").write_text(text)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert (root / "CHANGELOG.md").read_text() == text


def test_crlf_changelog_keeps_its_line_endings(root: Path) -> None:
    frag(root, "a.added.md", "- one\n  more\n")
    crlf = BASE_CHANGELOG.replace("\n", "\r\n").encode()
    (root / "CHANGELOG.md").write_bytes(crlf)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 0
    data = (root / "CHANGELOG.md").read_bytes()
    assert b"\n" not in data.replace(b"\r\n", b"")
    cut = crlf.index(b"## [1.0.0]")
    assert data.endswith(crlf[cut:])
    assert b"## [1.1.0] - 2026-02-02\r\n\r\n### Added\r\n- one\r\n  more\r\n" in data


@pytest.mark.parametrize(
    "body",
    [
        "- ok\n# Heading\n",
        "- ok\nunindented continuation\n",
        "- \n",
        "-\n",
        "- ok\n- \n",
        "- ok\n ctl\n",
        "text first\n- ok\n",
    ],
)
def test_fragment_grammar_refuses_bad_lines(root: Path, body: str) -> None:
    frag(root, "a.added.md", body)
    assert run(root, "--check") == 2


def test_fragment_grammar_accepts_bullets_continuations_and_blank_lines(root: Path) -> None:
    frag(root, "a.added.md", "- one\n  cont\n\n- two\n    deeper\n")
    assert run(root, "--check") == 0


def test_trailing_newline_in_a_name_or_format_is_refused(root: Path) -> None:
    assert cc.FRAGMENT_RE.fullmatch("a.added.md\n") is None
    assert run(root, "--version", "1.1.0\n", "--date", "2026-02-02") == 2
    frag(root, "a.added.md")
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02\n") == 2


# --- final hardening ---------------------------------------------------------


@pytest.mark.parametrize("opener", ["```", "~~~", "   ```", "<!--", "  <!-- hidden"])
def test_fence_or_comment_before_the_pointer_is_refused(root: Path, opener: str) -> None:
    frag(root, "a.added.md")
    text = opener + "\n" + BASE_CHANGELOG
    (root / "CHANGELOG.md").write_text(text)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert (root / "CHANGELOG.md").read_text() == text


def test_indented_duplicate_heading_is_refused(root: Path) -> None:
    frag(root, "a.added.md")
    text = BASE_CHANGELOG + "\n   ## [1.1.0] - 2026-02-02\n"
    (root / "CHANGELOG.md").write_text(text)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-03") == 2


@pytest.mark.parametrize("body", ["- ok\n[x]: https://example.invalid\n", "- [x]: y\n", "- ok\n  [ref]: http://a\n"])
def test_link_reference_definitions_in_fragments_are_refused(root: Path, body: str) -> None:
    frag(root, "a.added.md", body)
    assert run(root, "--check") == 2


def test_extra_blank_line_after_the_pointer_survives(root: Path) -> None:
    frag(root, "a.added.md", "- one\n")
    text = BASE_CHANGELOG.replace("README.md\n\n## [1.0.0]", "README.md\n\n\n## [1.0.0]")
    (root / "CHANGELOG.md").write_bytes(text.encode())
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 0
    data = (root / "CHANGELOG.md").read_text()
    assert "README.md\n\n\n## [1.1.0] - 2026-02-02\n\n### Added\n- one\n\n## [1.0.0]" in data


def test_mixed_line_endings_outside_the_inserted_section_are_untouched(root: Path) -> None:
    frag(root, "a.added.md", "- one\n")
    head = b"# Changelog\n\n## [Unreleased]\n\n" + cc.POINTER.encode() + b"\n\n"
    rest = b"## [1.0.0] - 2026-01-01\r\n\r\n### Added\r\n- First.\n- mixed\r\n"
    (root / "CHANGELOG.md").write_bytes(head + rest)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 0
    data = (root / "CHANGELOG.md").read_bytes()
    assert data.startswith(head) and data.endswith(rest)
    inserted = data[len(head): -len(rest)]
    assert inserted == b"## [1.1.0] - 2026-02-02\r\n\r\n### Added\r\n- one\r\n\r\n"


def test_write_failure_lists_the_kept_fragments(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    f = frag(root, "a.added.md")

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(cc.os, "replace", boom)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 1
    assert str(f) in capsys.readouterr().err


def test_fragment_changed_during_compilation_is_kept_and_reported(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    a = frag(root, "a.added.md", "- alpha\n")
    b = frag(root, "b.added.md", "- beta\n")
    real_write = cc.write_atomic

    def write_then_edit(path: Path, text: str) -> None:
        real_write(path, text)
        b.write_text("- beta, edited after compile\n")

    monkeypatch.setattr(cc, "write_atomic", write_then_edit)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 1
    err = capsys.readouterr().err
    assert str(b) in err and "changed during compilation" in err
    assert "not in CHANGELOG.md" in err
    assert not a.exists()
    assert b.read_text() == "- beta, edited after compile\n"


def test_missing_changelog_exits_2_without_traceback(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = frag(root, "a.added.md")
    (root / "CHANGELOG.md").unlink()
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert "CHANGELOG.md" in capsys.readouterr().err
    assert f.exists()


def test_unreadable_changelog_exits_2(root: Path) -> None:
    f = frag(root, "a.added.md")
    (root / "CHANGELOG.md").unlink()
    (root / "CHANGELOG.md").mkdir()
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 2
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02", "--dry-run") == 2
    assert f.exists()


def test_edit_after_the_comparison_point_never_deletes_the_new_file(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = frag(root, "a.added.md", "- alpha\n")
    real_unlink = cc._unlink

    def edit_then_unlink(path: Path) -> None:
        original = path.with_name(path.name.removeprefix(".compiling-"))
        original.write_text("- saved by an editor after the comparison\n")
        real_unlink(path)

    monkeypatch.setattr(cc, "_unlink", edit_then_unlink)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 0
    assert f.read_text() == "- saved by an editor after the comparison\n"
    assert not list((root / "changelog.d").glob(".compiling-*"))


def test_change_that_only_differs_in_raw_bytes_counts_as_changed(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    b = frag(root, "b.added.md", "- beta\n")
    real_write = cc.write_atomic

    def write_then_edit(path: Path, text: str) -> None:
        real_write(path, text)
        b.write_bytes(b"- beta\r")

    monkeypatch.setattr(cc, "write_atomic", write_then_edit)
    assert run(root, "--version", "1.1.0", "--date", "2026-02-02") == 1
    assert str(b) in capsys.readouterr().err
    assert b.read_bytes() == b"- beta\r"
