"""awg_genlib.xray — VLESS + XTLS-Vision + REALITY config + share-link builder.

Renders the Xray-core ``config.json`` for the two cascade roles and the
``vless://`` share link clients import. Pure functions (dict/str in, dict/str
out) — the agent generates keys via ``awg-xray.sh keygen`` and per-client ids in
Python, then hands the rendered config to ``awg-xray.sh apply``.

Self-contained Xray cascade (mirrors the WireGuard cascade's entry/exit roles
but never touches its fwmark routing):

  EXIT  (e.g. DE): VLESS+REALITY inbound -> freedom (egress here). Its clients
                   are the upstream ENTRIES, not end users.
  ENTRY (e.g. RU): VLESS+REALITY inbound for end clients; Xray routing sends
                   geoip:ru -> direct (egress RU, when geo-split is on) and
                   everything else -> a VLESS+REALITY OUTBOUND to the exit.

REALITY hardening baked in: a real-site ``dest``/``serverNames`` (borrowed TLS),
``flow=xtls-rprx-vision`` (kills the TLS-in-TLS length signature), per-client
uuid + shortId (revocable/distinguishable), and a client ``fingerprint`` (uTLS).
"""
from __future__ import annotations

import urllib.parse
from typing import Optional

# Curated REALITY dest/serverName candidates: real TLS1.3 + HTTP/2 origins that
# are NOT CDN-fronted (a CDN-fronted dest turns the box into a port-forwarder and
# is more fingerprintable) and are NOT globally-watched "bait" (google/microsoft,
# which RU DPI specifically flags as proxy dests). The agent re-validates the
# chosen one at provision time via `awg-xray.sh test-dest`.
#
# For a RU client->entry leg, mimic a *Russian* resource: a TLS connection to a
# popular .ru site is the most innocuous possible traffic on a Russian network and
# is never SNI-throttled. The list below is ordered Russian-first and was verified
# (TLS1.3+h2 reachable from the RU server, 2026-06-21). Telecom sites (mts/beeline)
# are especially plausible on their own carrier networks.
# RU clients MUST use a Russian whitelisted SNI: RU mobile/home DPI runs an SNI
# whitelist + a ~16-20 KB cutoff — a non-whitelisted/foreign SNI (e.g.
# www.microsoft.com) completes the handshake then gets the flow SEVERED after
# ~16-20 KB, so "it connects but nothing loads". A whitelisted .ru SNI disables
# that filter for the flow. The list below is whitelisted AND verified working as
# a REALITY dest end-to-end from a clean (non-RU) vantage on 2026-06-21: clean
# HTTP 200 on the apex (no off-domain redirect), TLS1.3+h2.
#   Avoid: vk.com (302->m.vk.com), avito.ru apex (301->www), yandex.ru / ya.ru /
#   kinopoisk.ru (Yandex SSO/captcha redirect), mail.ru/dzen.ru/gosuslugi.ru
#   (CDN-fronted, no clean TLS1.3+h2). These break REALITY despite being whitelisted.
DEFAULT_DESTS = [
    # Russian-resource mimicry — whitelisted + verified working REALITY dests:
    "ok.ru", "www.avito.ru", "sberbank.ru", "www.tbank.ru", "www.kaspersky.ru",
    "www.rbc.ru", "cbr.ru", "hh.ru",
    # Foreign fallbacks — ONLY for entries/exits ABROAD (a RU client gets cut):
    "dl.google.com", "swdlp.apple.com",
]

DEFAULT_DEST = "ok.ru"
DEFAULT_FLOW = "xtls-rprx-vision"
DEFAULT_FP = "chrome"


def _norm_dest(dest: str) -> tuple[str, str]:
    """('host:port', 'host') from 'host' or 'host:port' (default :443)."""
    dest = (dest or DEFAULT_DEST).strip()
    if ":" in dest:
        host, _, port = dest.partition(":")
        return f"{host}:{port or '443'}", host
    return f"{dest}:443", dest


def _reality_inbound(listen_port: int, dest: str, sni: str, private_key: str,
                     short_ids: list[str], clients: list[dict],
                     transport: str = "vision", path: str = "/") -> dict:
    """A VLESS + REALITY inbound.

    transport='vision' → XTLS-Vision over raw TCP (max throughput; best blend on
    permissive networks). transport='xhttp' → VLESS-over-XHTTP (HTTP/2 framing);
    the flow looks like ordinary web browsing, which survives RU TSPU TLS-flow
    policing that severs a raw Vision tunnel. XHTTP clients MUST NOT set `flow`.
    """
    dest_hostport, dest_host = _norm_dest(dest)
    server_names = [sni or dest_host]
    # Always allow the empty shortId (REALITY '' convention) + every per-client id.
    sids = list(dict.fromkeys([""] + [s for s in short_ids if s]))
    xhttp = (transport == "xhttp")
    client_entries = []
    for c in clients:
        entry = {"id": c["id"], "email": c.get("email", c["id"][:8])}
        if not xhttp:
            entry["flow"] = DEFAULT_FLOW   # Vision is TCP-only; XHTTP must omit flow
        client_entries.append(entry)
    stream = {
        "network": "xhttp" if xhttp else "tcp",
        "security": "reality",
        "realitySettings": {
            "show": False,
            "dest": dest_hostport,
            "xver": 0,
            "serverNames": server_names,
            "privateKey": private_key,
            "shortIds": sids,
            "maxTimeDiff": 0,
        },
    }
    if xhttp:
        stream["xhttpSettings"] = {"path": path, "mode": "auto"}
    return {
        "tag": "vless-in",
        "listen": "0.0.0.0",
        "port": int(listen_port),
        "protocol": "vless",
        "settings": {"clients": client_entries, "decryption": "none"},
        "streamSettings": stream,
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
    }


def _cascade_outbound(exit_host: str, exit_port: int, exit_uuid: str,
                      exit_pub: str, exit_sni: str, exit_sid: str) -> dict:
    """VLESS+REALITY outbound from the entry to the exit (carries non-RU traffic)."""
    return {
        "tag": "cascade",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": exit_host,
                "port": int(exit_port),
                "users": [{
                    "id": exit_uuid,
                    "encryption": "none",
                    "flow": DEFAULT_FLOW,
                }],
            }],
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "fingerprint": DEFAULT_FP,
                "serverName": exit_sni,
                "publicKey": exit_pub,
                "shortId": exit_sid,
                "spiderX": "/",
            },
        },
    }


def _base_outbounds() -> list[dict]:
    return [
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ]


def build_exit_config(listen_port: int, dest: str, sni: str, private_key: str,
                      short_ids: list[str], clients: list[dict],
                      transport: str = "vision", loglevel: str = "warning") -> dict:
    """DE exit: REALITY inbound -> freedom. `clients` = the upstream entries."""
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [_reality_inbound(listen_port, dest, sni, private_key, short_ids,
                                      clients, transport=transport)],
        "outbounds": _base_outbounds(),
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}],
        },
    }


def build_entry_config(listen_port: int, dest: str, sni: str, private_key: str,
                       short_ids: list[str], clients: list[dict],
                       cascade: Optional[dict] = None, geo_split: bool = True,
                       transport: str = "vision", loglevel: str = "warning") -> dict:
    """RU entry: REALITY inbound for end clients.

    cascade = {host, port, uuid, pub, sni, sid} → non-RU traffic egresses there;
    with geo_split, geoip:ru egresses locally (direct). Without a cascade the
    entry is a plain direct REALITY proxy (egress here).
    """
    outbounds = _base_outbounds()
    rules = [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]

    if cascade:
        outbounds.append(_cascade_outbound(
            cascade["host"], cascade.get("port", 443), cascade["uuid"],
            cascade["pub"], cascade["sni"], cascade.get("sid", "")))
        if geo_split:
            # RU destinations stay on the RU entry; everything else → exit.
            rules.append({"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"})
            rules.append({"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"})
        # Catch-all → cascade (Xray's implicit default is the first outbound,
        # so a non-RU flow needs an explicit rule to reach the exit).
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "cascade"})

    return {
        "log": {"loglevel": loglevel},
        "inbounds": [_reality_inbound(listen_port, dest, sni, private_key, short_ids,
                                      clients, transport=transport)],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


def vless_link(host: str, port: int, uuid: str, public_key: str, sni: str,
               short_id: str = "", fingerprint: str = DEFAULT_FP,
               label: str = "", transport: str = "vision", path: str = "/") -> str:
    """A vless:// REALITY share link (v2rayNG/Hiddify/NekoBox/sing-box/amnezia).

    transport='vision' → type=tcp + flow=xtls-rprx-vision.
    transport='xhttp'  → type=xhttp + path (no flow).
    """
    params = {
        "encryption": "none",
        "security": "reality",
        "sni": sni,
        "fp": fingerprint or DEFAULT_FP,
        "pbk": public_key,
        "spx": "/",
    }
    if transport == "xhttp":
        params["type"] = "xhttp"
        params["path"] = path
        params["mode"] = "auto"
    else:
        params["type"] = "tcp"
        params["flow"] = DEFAULT_FLOW
    if short_id:
        params["sid"] = short_id
    query = urllib.parse.urlencode(params, safe="/")
    frag = ("#" + urllib.parse.quote(label)) if label else ""
    return f"vless://{uuid}@{host}:{int(port)}?{query}{frag}"
