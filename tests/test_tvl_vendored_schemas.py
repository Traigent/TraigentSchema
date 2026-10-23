"""TRAIG-101 S1: the vendored TVL runtime contract/local schemas are byte-exact and pinned."""
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

DATA = Path(__file__).resolve().parents[1] / "traigent_schema" / "data" / "tvl"
SOURCE = json.loads((DATA / "SOURCE.json").read_text(encoding="utf-8"))
EXPECTED = {
    "tvl-runtime-contract.schema.json": ("tvl-runtime-contract/1", "1.3"),
    "tvl-runtime-contract-v2.schema.json": ("tvl-runtime-contract/2", "1.4"),
    "tvl-runtime-local.schema.json": ("tvl-runtime-local/1", "1.3"),
    "tvl-runtime-local-v2.schema.json": ("tvl-runtime-local/2", "1.4"),
}


def test_source_record_pins_commit_and_all_four_files():
    assert len(SOURCE["source_commit"]) == 40 and set(SOURCE["files"]) == set(EXPECTED)
    assert SOURCE["release_tag"] == "v1.4.0" and SOURCE["identical_at_release_tag"] is True
    on_disk = {p.name for p in DATA.glob("*.schema.json")}
    assert on_disk == set(EXPECTED), "an unpinned or missing vendored schema"
    assert SOURCE["source_dir"] == "spec/grammar/"


def test_bytes_match_pinned_digest():
    for name, meta in SOURCE["files"].items():
        raw = (DATA / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == meta["sha256"], f"{name} drifted from its pin"
        assert len(raw) == meta["bytes"]
        assert "source_path" not in meta  # a basename citation would trip the shipped-path drift test


def test_schemas_are_valid_2020_12_and_carry_their_format_and_version():
    for name, (fmt, version) in EXPECTED.items():
        schema = json.loads((DATA / name).read_bytes())
        Draft202012Validator.check_schema(schema)
        assert schema["properties"]["format"]["const"] == fmt
        assert schema["properties"]["tvl_version"]["const"] == version
        assert schema["additionalProperties"] is False


def test_contract_v1_includes_deploy_and_v2_is_the_14_format():
    v1 = (DATA / "tvl-runtime-contract.schema.json").read_text(encoding="utf-8")
    v2 = (DATA / "tvl-runtime-contract-v2.schema.json").read_text(encoding="utf-8")
    assert '"deploy": { "enum": ["never", "if_promoted"] }' in v1
    assert "tvl-runtime-contract/2" in v2 and "tvl-runtime-contract/2" not in v1
