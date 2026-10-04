import time

import msgspec
import pytest
from pydantic import ValidationError

from ulpf.config import Config, load_config, split_hostport
from ulpf.model.envelope import RawEnvelope, decode_envelope, encode_envelope
from ulpf.model.event import get_path
from ulpf.model.ids import is_uuid7, uuid7, uuid7_ms
from ulpf.model.lineage import VaultRef, parse_raw_ref
from ulpf.model.ocsf import CATEGORY_UID, CLASS_UID, known_path


def test_uuid7_format_and_time():
    t0 = int(time.time() * 1000)
    u = uuid7()
    assert is_uuid7(u)
    assert abs(uuid7_ms(u) - t0) < 2000


def test_uuid7_monotonic_and_unique():
    ids = [uuid7() for _ in range(20000)]
    assert len(set(ids)) == len(ids)
    assert ids == sorted(ids)


def test_uuid7_fixed_ms_counter_overflow_still_sorted():
    ids = [uuid7(now_ms=1_800_000_000_000) for _ in range(5000)]
    assert ids == sorted(ids) and len(set(ids)) == 5000


def test_envelope_roundtrip_all_bytes():
    data = bytes(range(256))
    e = RawEnvelope(uuid7(), 1, "n1", "udp", "10.0.0.1", 514, data, "x")
    assert decode_envelope(encode_envelope(e)) == e
    with pytest.raises(AttributeError):
        e.data = b""  # type: ignore[misc]


def test_envelope_frozen_struct():
    assert issubclass(RawEnvelope, msgspec.Struct)


def test_vault_ref_str_and_parse():
    r = VaultRef("n1-000042", 17, 233, "ab" * 32)
    assert str(r) == "n1-000042/17/233"
    assert parse_raw_ref(str(r)) == ("n1-000042", 17, 233)


def test_ocsf_tables():
    assert CLASS_UID["network_activity"] == 4001 and CATEGORY_UID[4001] == 4
    assert known_path(4001, "src_endpoint.ip") and not known_path(4001, "bogus.path")
    assert known_path(4001, "unmapped.anything")


def test_get_path_dotted_keys():
    d = {"unmapped": {"alert.category": "x"}, "a": {"b": 1}}
    assert get_path(d, "unmapped.alert.category") == "x" and get_path(d, "a.b") == 1 and get_path(d, "a.c") is None


def test_config_defaults_and_shipped_yaml(tmp_path):
    c = load_config("configs/ulpf.yaml")
    assert c.bus.partitions == 16 and c.sinks.parquet.flush_rows == 50000 and c.vault.block_events == 1000
    r = c.rebase(tmp_path)
    assert r.vault.dir == str(tmp_path / "vault") and r.sinks.parquet.dir == str(tmp_path / "lake")
    assert Config().n_workers >= 1


def test_config_env_and_overrides(monkeypatch):
    monkeypatch.setenv("ULPF_API_TOKEN", "s3cret")
    c = load_config("configs/ulpf.yaml", {"node_id": "zz"})
    assert c.api.token == "s3cret" and c.node_id == "zz"


def test_config_rejects_unknown_keys():
    with pytest.raises(ValidationError):
        Config.model_validate({"nope": 1})


def test_split_hostport():
    assert split_hostport("0.0.0.0:5140") == ("0.0.0.0", 5140)
