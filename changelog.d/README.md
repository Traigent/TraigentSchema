# Changelog fragments

Pending release notes live here, one file per change, so that concurrent pull
requests do not conflict on the `[Unreleased]` section of `CHANGELOG.md`.
Fragments are combined into a dated `CHANGELOG.md` section at release time.

## Adding a fragment

Create `changelog.d/<slug>.<type>.md` in the same pull request as the change.

- `<slug>` is lowercase letters, digits and hyphens, for example
  `trial-number-on-grouped-run`. Fragments are sorted by slug within a type.
- `<type>` is one of the values below and picks the heading the entry lands under.
- The file holds one or more markdown bullet lines (continuation lines are
  indented). It must not be empty.

| type         | heading        |
|--------------|----------------|
| `breaking`   | `### Breaking`   |
| `added`      | `### Added`      |
| `changed`    | `### Changed`    |
| `deprecated` | `### Deprecated` |
| `removed`    | `### Removed`    |
| `fixed`      | `### Fixed`      |

Headings appear in the order of the table.

Example `changelog.d/trial-number-on-grouped-run.added.md`:

```markdown
- **`trial_number` on `GroupedConfigurationRun`.** New optional, nullable
  integer, purely additive.
```

## Checking and releasing

```bash
python scripts/compile_changelog.py --check                      # validate fragments (CI)
python scripts/compile_changelog.py --version X.Y.Z --date YYYY-MM-DD --dry-run
python scripts/compile_changelog.py --version X.Y.Z --date YYYY-MM-DD
```

The last command inserts a `## [X.Y.Z] - YYYY-MM-DD` section directly below the
`[Unreleased]` pointer in `CHANGELOG.md` and deletes the compiled fragments. It
refuses when that version already has a section.

Exit codes: 0 success; 1 a failure after validation: CHANGELOG.md could not be
written (it is left unchanged and the fragments are listed), the directory could not
be flushed to disk after the write (the fragments are kept and listed), or a
compiled fragment could not be deleted (the remaining paths are listed; remove them
with `git rm`); 2 a validation or usage error.
