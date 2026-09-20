# Release reconciliation — 2026-09-20

The `develop` merge queue squashed PR #508, retaining its reviewed allowlist union but discarding the `main` parent needed by the ordered `develop` to `main` release.

PR #509 restores that ancestry with a two-parent merge commit. Its resolved tree keeps the allowlist union already tested on `develop`; this audit record is the only content change introduced by the correction. The correction must use an administrator merge commit after exact-head checks pass because the queue's configured strategy would otherwise squash the ancestry again.
