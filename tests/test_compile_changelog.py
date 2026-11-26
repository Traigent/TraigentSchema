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
    text = (root / "CHANGELOG.md").read_text()
    released_before = BASE_CHANGELOG[BASE_CHANGELOG.index("## [1.0.0]"):]
    assert text.endswith(released_before)
    assert text.startswith(BASE_CHANGELOG[: BASE_CHANGELOG.index("## [1.0.0]")])


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
    assert new.endswith(original[released_from:])
