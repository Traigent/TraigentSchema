"""NOTICE must attribute exactly the package's direct runtime dependencies.

`NOTICE` is shipped in the wheel (`pyproject.toml` `license-files`) and is the
project's own third-party attribution list for a public, AGPL-licensed package.
It drifted once: `cryptography` was added to `[project].dependencies` without an
entry here (#578). This test pins the two lists together so the next addition
cannot drift silently.
"""

from __future__ import annotations

import re
from pathlib import Path

import tomllib

_REPO_ROOT = Path(__file__).resolve().parent.parent

# "- jsonschema (MIT License) - https://github.com/..." -> "jsonschema"
_NOTICE_ENTRY = re.compile(r"^-\s+(?P<name>[A-Za-z0-9._-]+)\s+\((?P<license>[^)]+)\)\s+-\s+\S+$")

# "cryptography>=46.0.0,<51.0.0" -> "cryptography"
_REQUIREMENT_NAME = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)")


def _normalize(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _declared_runtime_dependencies() -> set[str]:
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    names = set()
    for requirement in pyproject["project"]["dependencies"]:
        match = _REQUIREMENT_NAME.match(requirement.strip())
        assert match is not None, f"unparseable requirement: {requirement!r}"
        names.add(_normalize(match.group("name")))
    return names


def _notice_attributed_dependencies() -> set[str]:
    """Names in the NOTICE 'direct runtime third-party libraries' bullet list."""
    lines = (_REPO_ROOT / "NOTICE").read_text(encoding="utf-8").splitlines()
    heading = next(
        (i for i, line in enumerate(lines) if "direct runtime third-party libraries" in line),
        None,
    )
    assert heading is not None, "NOTICE no longer has a direct-runtime-dependency section"

    names = set()
    for line in lines[heading:]:
        if not line.startswith("-"):
            if names:  # the bullet list has ended
                break
            continue
        match = _NOTICE_ENTRY.match(line.strip())
        assert match is not None, f"malformed NOTICE attribution line: {line!r}"
        names.add(_normalize(match.group("name")))
    return names


def test_notice_lists_exactly_the_direct_runtime_dependencies() -> None:
    declared = _declared_runtime_dependencies()
    attributed = _notice_attributed_dependencies()

    assert attributed == declared, (
        "NOTICE and [project].dependencies disagree. "
        f"Missing from NOTICE: {sorted(declared - attributed)}; "
        f"listed in NOTICE but not a dependency: {sorted(attributed - declared)}"
    )


def test_notice_attribution_list_is_not_empty() -> None:
    # Guards the parser itself: a NOTICE rewrite that breaks the bullet format
    # must fail loudly rather than make the comparison above vacuously true.
    assert _notice_attributed_dependencies()
