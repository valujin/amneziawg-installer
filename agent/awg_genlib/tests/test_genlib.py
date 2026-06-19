"""Tests for awg_genlib (pure stdlib — run: python -m pytest agent/awg_genlib/tests/)."""
import sys
import zlib
import base64
import struct
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root for `agent.*`

from awg_genlib import (  # noqa: E402
    generate, validate, vpn_decode, vpn_encode, merge_obfuscation,
    generate_preset, list_presets,
)

SAMPLE_VPN = {
    "containers": [
        {
            "container": "amnezia-awg",
            "awg": {
                "Jc": "4", "Jmin": "40", "Jmax": "70",
                "last_config": '{"Jc":"4","H1":"1"}',
                "config": "[Interface]\nAddress = 10.8.0.2/32\nJc = 4\nDNS = 1.1.1.1\n",
            },
        }
    ],
    "defaultContainer": "amnezia-awg",
    "description": "тест",  # non-ASCII to exercise ensure_ascii=False
}


# ----------------------------- vpn:// codec -----------------------------
def test_vpn_roundtrip_object():
    link = vpn_encode(SAMPLE_VPN)
    assert link.startswith("vpn://")
    assert vpn_decode(link) == SAMPLE_VPN


def test_vpn_wire_format():
    link = vpn_encode(SAMPLE_VPN)
    b64 = link[len("vpn://"):]
    assert "=" not in b64 and "+" not in b64 and "/" not in b64  # base64url, no padding
    raw = base64.b64decode(b64.replace("-", "+").replace("_", "/") + "==")
    declared_len = struct.unpack(">I", raw[:4])[0]
    payload = zlib.decompress(raw[4:])
    assert declared_len == len(payload)  # 4-byte BE prefix == uncompressed JSON length


def test_vpn_decode_legacy_raw_json():
    import json
    raw = json.dumps(SAMPLE_VPN).encode()
    link = "vpn://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert vpn_decode(link) == SAMPLE_VPN


def test_vpn_decode_garbage_raises():
    with pytest.raises(ValueError):
        vpn_decode("vpn://!!!notbase64!!!")


# --------------------------- merge obfuscation --------------------------
def test_merge_patches_all_three_locations():
    import copy, json
    cfg = copy.deepcopy(SAMPLE_VPN)
    merge_obfuscation(cfg, {"Jc": 7, "Jmin": 50, "Jmax": 900, "I1": "<b 0xaa><r 100>"})
    awg = cfg["containers"][0]["awg"]
    assert awg["Jc"] == "7" and awg["Jmax"] == "900"            # top-level
    assert json.loads(awg["last_config"])["Jc"] == "7"          # last_config json
    assert "Jc = 7" in awg["config"]                            # wg-quick text
    assert "I1 = <b 0xaa><r 100>" in awg["config"]              # inserted (was absent)


def test_merge_roundtrips_through_link():
    link = vpn_encode(SAMPLE_VPN)
    from awg_genlib import merge_into_link
    out = merge_into_link(link, {"Jc": 9})
    assert vpn_decode(out)["containers"][0]["awg"]["Jc"] == "9"


# ------------------------------ validate --------------------------------
def test_validate_accepts_good():
    r = validate({"Jc": 5, "Jmin": 50, "Jmax": 900, "S1": 10, "S2": 100,
                  "H1": "100-200", "H2": "300-400", "I1": "<b 0xaa><r 50>"})
    assert r["ok"] and not r["errors"]


def test_validate_jc_range():
    assert not validate({"Jc": 200})["ok"]
    assert not validate({"Jc": 0})["ok"]


def test_validate_jmin_jmax():
    assert not validate({"Jmin": 500, "Jmax": 400})["ok"]


def test_validate_s1_s2_fingerprint_warns():
    r = validate({"S1": 10, "S2": 66})  # 10+56 == 66
    assert r["ok"] and any("fingerprint" in w for w in r["warnings"])


def test_validate_h_overlap():
    assert not validate({"H1": "100-300", "H2": "200-400"})["ok"]


def test_validate_bad_i_tag():
    assert not validate({"I1": "<bogus>"})["ok"]
    assert validate({"I1": "<b 0xdeadbeef><r 200><c><t>"})["ok"]


# ------------------------------ generator -------------------------------
@pytest.mark.parametrize("intensity", ["low", "medium", "high"])
@pytest.mark.parametrize("extreme", [False, True])
def test_generate_is_always_valid(intensity, extreme):
    p = generate(intensity=intensity, extreme=extreme, seed=1234)
    assert validate(p)["ok"], validate(p)["errors"]
    for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H4", "I1", "I5"):
        assert k in p


def test_generate_deterministic_with_seed():
    assert generate(seed=42) == generate(seed=42)


def test_generate_legacy_has_no_cps():
    p = generate(version="1.0", seed=7)
    assert "I1" not in p and int(p["Jc"]) >= 4


def test_generate_router_mode_small_s():
    p = generate(router_mode=True, seed=3)
    assert int(p["S1"]) <= 20 and int(p["S2"]) <= 20


# ------------------------------ presets ---------------------------------
@pytest.mark.parametrize("name", list_presets())
def test_every_preset_generates_valid(name):
    p = generate_preset(name, seed=99)
    assert validate(p)["ok"], (name, validate(p)["errors"])
