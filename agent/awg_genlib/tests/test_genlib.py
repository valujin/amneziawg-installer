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


# ===========================================================================
# Full Architect-fidelity coverage (ported from generator.test.ts /
# generator-protocols.test.ts plus the new full-port surface).
# ===========================================================================
import re  # noqa: E402

from awg_genlib import (  # noqa: E402
    gen_cfg, GeneratorInput, MIMIC_PROFILES, BROWSER_PROFILES, INTENSITIES,
    list_profiles, list_browsers, host_pool, host_pool_summary, PROFILE_LABELS,
    merge_vpn_configs, merge_links, build_obfuscation_patch, get_client_fields,
    describe_presets,
)
from awg_genlib.generator import (  # noqa: E402
    rnd, rh, hex_pad, assert_even_hex, r_range, split_pad, tag_overhead,
    calc_padding, align_to_128, gen_i1, _seed,
)

I_TAG = re.compile(r"^(<(b 0x[0-9a-fA-F]*|t|c|r \d+|rc \d+|rd \d+|d|ds|dz)>)+$")


# ----------------------------- primitives -------------------------------
def test_rh_length_and_charset():
    assert rh(0) == ""
    assert len(rh(4)) == 8 and len(rh(16)) == 32
    assert re.match(r"^[0-9a-f]*$", rh(32))


def test_hex_pad():
    assert hex_pad(0, 4) == "00000000"
    assert hex_pad(1, 4) == "00000001"
    assert hex_pad(255, 2) == "00ff"
    assert len(hex_pad(0x1ff, 1)) == 2  # overflow truncated to byte_len


def test_assert_even_hex():
    assert assert_even_hex("aabb") == "aabb"
    assert assert_even_hex("") == ""
    assert assert_even_hex("abc") == "abc0"


def test_split_pad():
    assert split_pad(0) == ""
    assert split_pad(500) == "<r 500>"
    assert split_pad(1000) == "<r 1000>"
    assert split_pad(1200) == "<r 1000><r 200>"
    assert split_pad(2500) == "<r 1000><r 1000><r 500>"
    assert split_pad(1200, "rd") == "<rd 1000><rd 200>"


def test_tag_overhead():
    assert tag_overhead(False, False) == 0
    assert tag_overhead(True, False) == 4
    assert tag_overhead(False, True) == 4
    assert tag_overhead(True, True) == 8


def test_calc_padding():
    # pads to reach minimum: occupied 48, range [1250,1250] -> 1202
    assert calc_padding(40, 8, (1250, 1250), 2, 1500) == 1202
    # MTU clamp: mtu 100 -> <= 52
    assert calc_padding(40, 8, (1250, 1350), 2, 100) <= 52
    # occupied >= max -> 0
    assert calc_padding(1300, 0, (1250, 1300), 2, 1500) == 0
    # entropy mode (no range) <= 500
    for _ in range(50):
        assert 0 <= calc_padding(40, 8, None, 2, 1500) <= 500


def test_align_to_128():
    assert align_to_128(0) == 0
    assert align_to_128(128) == 128
    assert align_to_128(129) == 256
    assert align_to_128(1) == 128
    assert align_to_128(256) == 256


def test_r_range_format():
    _seed(1)
    for _ in range(50):
        s = r_range(100_000_000)
        assert re.match(r"^\d+-\d+$", s)
        n, m = (int(x) for x in s.split("-"))
        assert n >= 100_000_000 and 1000 <= (m - n) <= 50_000


# --------------------------- protocol builders (genI1) -------------------
_PROTOCOL_PROFILES = ["quic_initial", "quic_0rtt", "tls_client_hello",
                      "wireguard_noise", "dtls", "http3", "sip"]


@pytest.mark.parametrize("profile", _PROTOCOL_PROFILES)
def test_geni1_shape(profile):
    inp = GeneratorInput(profile=profile, use_tag_c=False, use_tag_t=True,
                         use_tag_r=True, use_tag_rc=True, use_tag_rd=True, mtu=1500)
    r = gen_i1(inp, profile, 0)
    assert r and isinstance(r, str)
    assert "<b 0x" in r
    for m in re.findall(r"<b 0x([0-9a-fA-F]+)>", r):
        assert len(m) % 2 == 0           # even-length hex inside <b 0x...>
    assert "<t>" in r                    # useTagT
    assert I_TAG.match(r), r             # whole chain is a valid CPS sequence


@pytest.mark.parametrize("profile", _PROTOCOL_PROFILES)
def test_geni1_respects_tag_flags(profile):
    off = GeneratorInput(profile=profile, use_tag_r=False, use_tag_c=False)
    assert "<r " not in gen_i1(off, profile, 0)
    on = GeneratorInput(profile=profile, use_tag_c=True, use_tag_rc=True)
    r = gen_i1(on, on.profile, 0)
    assert "<rc " in r
    # mk_noise faithfully omits the <c> counter tag (matches Architect); all
    # other builders honour use_tag_c.
    if profile != "wireguard_noise":
        assert "<c>" in r


def test_geni1_random_nonempty():
    assert gen_i1(GeneratorInput(profile="random"), "random", 0)


def test_custom_host_is_used():
    inp = GeneratorInput(profile="sip", custom_host="sip.example.org")
    hexpart = re.search(r"<b 0x([0-9a-f]+)>", gen_i1(inp, "sip", 0)).group(1)
    assert bytes.fromhex(hexpart).startswith(b"REGISTER sip:sip.example.org")


# ----------------------- gen_cfg composite / dns ------------------------
def test_gencfg_tls_to_quic_composite():
    c = gen_cfg(GeneratorInput(profile="tls_to_quic", intensity="medium"))
    assert c["i1"].startswith("<b 0x160301")          # I1 = TLS ClientHello
    flag = c["i2"][len("<b 0x"):len("<b 0x") + 2].lower()
    assert flag in ("c0", "c1", "c2", "c3")           # I2 = QUIC Initial


def test_gencfg_quic_burst_composite():
    c = gen_cfg(GeneratorInput(profile="quic_burst", intensity="high"))
    assert all(c[k] for k in ("i1", "i2", "i3", "i4", "i5"))


def test_gencfg_dns_query():
    c = gen_cfg(GeneratorInput(profile="dns_query", mimic_all=True, intensity="low"))
    assert "0100" in c["i1"]                            # DNS standard-query flags


def test_gencfg_router_disables_extra_cps():
    c = gen_cfg(GeneratorInput(profile="quic_initial", router_mode=True))
    assert c["i1"] and not (c["i2"] or c["i3"] or c["i4"] or c["i5"])


def test_gencfg_h_ranges_never_overlap():
    for s in range(20):
        p = generate(seed=s, intensity="high", extreme=(s % 2 == 0))
        assert validate(p)["ok"], validate(p)["errors"]


@pytest.mark.parametrize("profile", list(MIMIC_PROFILES))
@pytest.mark.parametrize("version", ["1.0", "1.5", "2.0"])
def test_generate_every_profile_version_valid(profile, version):
    p = generate(version=version, profile=profile, intensity="high", seed=11,
                 use_browser_fp=True, browser_profile="chrome")
    r = validate(p, mtu=1280)
    assert r["ok"], (profile, version, r["errors"])
    if version == "1.0":
        assert "I1" not in p


@pytest.mark.parametrize("browser", list(BROWSER_PROFILES))
def test_browser_fp_pads_quic_initial(browser):
    # With a browser fingerprint on QUIC Initial, the packet is padded toward the
    # BFP target (>= ~1000 bytes of <r> padding at a generous MTU).
    inp = GeneratorInput(profile="quic_initial", use_browser_fp=True,
                         browser_profile=browser, mtu=1500, intensity="high")
    _seed(5)
    s = gen_i1(inp, "quic_initial", 3)
    total = sum(int(x) for x in re.findall(r"<r (\d+)>", s))
    assert total >= 1000, (browser, total)


# ------------------------- mergekeys extras -----------------------------
def test_get_client_fields():
    assert get_client_fields("1.0") == ["Jc", "Jmin", "Jmax"]
    assert get_client_fields("2.0") == ["Jc", "Jmin", "Jmax", "I1", "I2", "I3", "I4", "I5"]


def test_build_obfuscation_patch_from_gencfg():
    patch = build_obfuscation_patch(gen_cfg(GeneratorInput()), version="2.0")
    assert set(patch) == {"Jc", "Jmin", "Jmax", "I1", "I2", "I3", "I4", "I5"}
    assert all(isinstance(v, str) for v in patch.values())
    patch1 = build_obfuscation_patch(gen_cfg(GeneratorInput(version="1.0")), version="1.0")
    assert set(patch1) == {"Jc", "Jmin", "Jmax"}


def test_merge_vpn_configs_dedup():
    a = {"containers": [{"container": "amnezia-awg", "awg": {"Jc": "4"}}],
         "defaultContainer": "amnezia-awg", "description": "A"}
    b = {"containers": [{"container": "amnezia-xray", "xray": {}},
                        {"container": "amnezia-awg", "awg": {"Jc": "9"}}],
         "description": "B"}
    m = merge_vpn_configs([a, b])
    assert m["stats"] == {"total": 3, "unique": 2, "dupes": 1}
    names = [c["container"] for c in m["merged"]["containers"]]
    assert names == ["amnezia-awg", "amnezia-xray"]      # first AWG wins
    assert m["merged"]["description"] == "A + B"
    assert len(m["warnings"]) == 1


def test_merge_vpn_configs_needs_two():
    with pytest.raises(ValueError):
        merge_vpn_configs([{"containers": []}])


def test_merge_links_roundtrip():
    a = vpn_encode({"containers": [{"container": "amnezia-awg", "awg": {"Jc": "4"}}],
                    "description": "A"})
    b = vpn_encode({"containers": [{"container": "amnezia-xray", "xray": {}}],
                    "description": "B"})
    out = merge_links([a, b])
    merged = vpn_decode(out["link"])
    assert len(merged["containers"]) == 2 and out["stats"]["unique"] == 2


# ------------------------- introspection --------------------------------
def test_list_profiles_complete():
    profs = list_profiles()
    assert len(profs) == len(PROFILE_LABELS) == 11
    assert {p["key"] for p in profs} == set(MIMIC_PROFILES)


def test_list_browsers_and_pools():
    assert set(list_browsers()) == set(BROWSER_PROFILES)
    summ = host_pool_summary()
    assert summ["tls_client_hello"] > 100 and summ["sip"] > 50
    assert "8.8.8.8" in host_pool("dns_query")           # dns_query -> dns IP pool
    assert "yandex.net" in host_pool("quic_initial")


def test_describe_presets_metadata():
    desc = describe_presets()
    assert {d["name"] for d in desc} == set(list_presets())
    assert all(d["label"] and d["description"] for d in desc)


def test_host_pool_tiered():
    from awg_genlib import host_pool_tiered, tier_definitions
    tiered = host_pool_tiered("quic_initial")
    assert any(h["host"] == "yandex.net" and h["tier"] == "ru-domestic" for h in tiered)
    # http3 reuses the quic_initial tiered pool
    assert host_pool_tiered("http3")[0]["tier"]
    # dns has no tiered data -> flat fallback with tier "unknown"
    dns = host_pool_tiered("dns_query")
    assert dns and all(h["tier"] == "unknown" for h in dns)
    assert "ru-domestic" in tier_definitions()
