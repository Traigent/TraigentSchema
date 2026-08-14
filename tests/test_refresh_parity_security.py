from __future__ import annotations

import json

from scripts import refresh_parity


def test_save_manifest_writes_serialized_content_to_the_fixed_manifest_path(
    tmp_path, monkeypatch
) -> None:
    manifest_path = tmp_path / "parity.json"
    monkeypatch.setattr(refresh_parity, "_MANIFEST_PATH", manifest_path)
    manifest = {"path_like_content": "../../outside", "schema_count": 2}

    refresh_parity._save_manifest(manifest)

    assert manifest_path.read_text(encoding="utf-8") == (
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    )
    assert sorted(tmp_path.iterdir()) == [manifest_path]
