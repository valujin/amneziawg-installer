"""Tests for awg_genlib.xray — VLESS+REALITY config + share-link builder."""
import urllib.parse

from awg_genlib import xray


def test_exit_config_is_reality_vision():
    cfg = xray.build_exit_config(8443, "dl.google.com", "dl.google.com",
                                 "PRIV", ["aabbccdd"], [{"id": "u1", "email": "ru"}])
    inb = cfg["inbounds"][0]
    assert inb["port"] == 8443
    ss = inb["streamSettings"]
    assert ss["security"] == "reality"
    assert ss["realitySettings"]["dest"] == "dl.google.com:443"
    assert ss["realitySettings"]["serverNames"] == ["dl.google.com"]
    # shortIds always include the empty-string convention + the per-client id
    assert "" in ss["realitySettings"]["shortIds"]
    assert "aabbccdd" in ss["realitySettings"]["shortIds"]
    assert inb["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"
    # exit egresses locally: default outbound is freedom, no cascade
    assert [o["tag"] for o in cfg["outbounds"]] == ["direct", "block"]


def test_entry_with_cascade_and_geosplit():
    casc = {"host": "203.0.113.9", "port": 8443, "uuid": "cu",
            "pub": "PUBDE", "sni": "dl.google.com", "sid": "ffee"}
    cfg = xray.build_entry_config(443, "www.microsoft.com", None, "PRIV", [],
                                  [{"id": "alice", "email": "alice"}],
                                  cascade=casc, geo_split=True)
    assert [o["tag"] for o in cfg["outbounds"]] == ["direct", "block", "cascade"]
    out = cfg["outbounds"][2]
    assert out["settings"]["vnext"][0]["address"] == "203.0.113.9"
    assert out["settings"]["vnext"][0]["port"] == 8443
    assert out["streamSettings"]["realitySettings"]["publicKey"] == "PUBDE"
    rules = cfg["routing"]["rules"]
    # geoip:ru stays direct, catch-all → cascade
    assert any(r.get("ip") == ["geoip:ru"] for r in rules)
    assert rules[-1]["outboundTag"] == "cascade"
    # sni defaults to dest host when None
    assert cfg["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"] == ["www.microsoft.com"]


def test_entry_geosplit_off_routes_everything_to_cascade():
    casc = {"host": "h", "port": 443, "uuid": "u", "pub": "p", "sni": "s", "sid": ""}
    cfg = xray.build_entry_config(443, "d", "d", "P", [], [{"id": "a", "email": "a"}],
                                  cascade=casc, geo_split=False)
    rules = cfg["routing"]["rules"]
    assert not any(r.get("ip") == ["geoip:ru"] for r in rules)
    assert rules[-1]["outboundTag"] == "cascade"


def test_entry_without_cascade_is_direct():
    cfg = xray.build_entry_config(443, "d", "d", "P", [], [{"id": "a", "email": "a"}])
    assert [o["tag"] for o in cfg["outbounds"]] == ["direct", "block"]
    # only the private-block rule; default outbound (freedom) handles the rest
    assert cfg["routing"]["rules"] == [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]


def test_vless_link_roundtrip():
    link = xray.vless_link("198.51.100.7", 443, "the-uuid", "PUBKEY",
                           "www.microsoft.com", short_id="abcd1234", label="alice host")
    assert link.startswith("vless://the-uuid@198.51.100.7:443?")
    parsed = urllib.parse.urlparse(link)
    q = urllib.parse.parse_qs(parsed.query)
    assert q["security"] == ["reality"]
    assert q["flow"] == ["xtls-rprx-vision"]
    assert q["pbk"] == ["PUBKEY"]
    assert q["sid"] == ["abcd1234"]
    assert q["sni"] == ["www.microsoft.com"]
    assert q["fp"] == ["chrome"]
    assert urllib.parse.unquote(parsed.fragment) == "alice host"


def test_vless_link_omits_empty_shortid():
    link = xray.vless_link("h", 443, "u", "pk", "s")
    assert "sid=" not in link


def test_xhttp_transport_inbound_and_link():
    cfg = xray.build_entry_config(443, "ok.ru", "ok.ru", "P", ["aa"],
                                  [{"id": "u1", "email": "a"}], transport="xhttp")
    inb = cfg["inbounds"][0]
    assert inb["streamSettings"]["network"] == "xhttp"
    assert inb["streamSettings"]["xhttpSettings"]["path"] == "/"
    # XHTTP clients must NOT carry the Vision flow
    assert "flow" not in inb["settings"]["clients"][0]
    link = xray.vless_link("h", 443, "u1", "P", "ok.ru", short_id="aa", transport="xhttp")
    assert "type=xhttp" in link and "path=" in link and "flow=" not in link


def test_vision_remains_default():
    cfg = xray.build_exit_config(8443, "dl.google.com", None, "P", [], [{"id": "u", "email": "e"}])
    assert cfg["inbounds"][0]["streamSettings"]["network"] == "tcp"
    assert cfg["inbounds"][0]["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"


def test_client_config_has_fulltunnel_dns_fix():
    # The turnkey client config must bake in FakeDNS + sniffing + IPv4-only,
    # else a TUN client gets flaky DNS over the cascade ("connects, nothing loads").
    cfg = xray.client_config("1.2.3.4", 443, "u", "PBK", "ok.ru", short_id="aa", transport="xhttp")
    assert cfg["fakedns"][0]["ipPool"] == "198.18.0.0/15"
    assert cfg["dns"]["queryStrategy"] == "UseIPv4"
    assert "fakedns" in cfg["inbounds"][0]["sniffing"]["destOverride"]
    assert cfg["outbounds"][0]["streamSettings"]["network"] == "xhttp"
    assert "flow" not in cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    # DNS routed to the dns outbound; everything else to proxy
    rules = cfg["routing"]["rules"]
    assert rules[0]["port"] == 53 and rules[0]["outboundTag"] == "dns-out"
    assert rules[-1]["outboundTag"] == "proxy"
