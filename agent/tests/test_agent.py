"""Unit tests for awg_agent (Phase A).

These exercise the HTTP surface with the bash layer and `awg show` mocked, so
they run anywhere (no AmneziaWG / root needed). Run with: pytest agent/tests/
"""
import importlib
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

AGENT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(AGENT_DIR))

TOKEN = "secret-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

SAMPLE_CONF = """\
[Interface]
PrivateKey = SERVERPRIV
Address = 172.16.17.1/24
ListenPort = 39743
Jc = 4
Jmin = 40
Jmax = 70
S1 = 30
S2 = 60
S3 = 0
S4 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
#_Name = alice
#_Exit = de
PublicKey = ALICEPUB
AllowedIPs = 172.16.17.2/32

[Peer]
#_Name = bob
PublicKey = BOBPUB
AllowedIPs = 172.16.17.3/32
"""


@pytest.fixture
def agent(monkeypatch, tmp_path):
    monkeypatch.setenv("AWG_AGENT_TOKEN", TOKEN)
    monkeypatch.setenv("AWG_AGENT_BIND", "127.0.0.1")
    monkeypatch.setenv("AWG_DIR", str(tmp_path))
    monkeypatch.setenv("AWG_MANAGE", str(tmp_path / "manage_amneziawg.sh"))
    monkeypatch.setenv("AWG_SERVER_CONF", str(tmp_path / "awg0.conf"))
    monkeypatch.setenv("AWG_CONFIG_INIT", str(tmp_path / "awgsetup_cfg.init"))
    monkeypatch.setenv("AWG_EXITS_DIR", str(tmp_path / "exits"))
    mod = importlib.import_module("awg_agent")
    importlib.reload(mod)  # re-read Settings from the patched env
    mod._tmp = tmp_path
    return mod


@pytest.fixture
def client(agent):
    return TestClient(agent.app)


@pytest.fixture
def record_manage(agent, monkeypatch):
    """Replace run_manage with a recorder that returns success."""
    calls = []

    def fake(args, timeout=None):
        calls.append(list(args))
        return types.SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(agent, "run_manage", fake)
    return calls


def write_conf(agent, text=SAMPLE_CONF):
    (agent._tmp / "awg0.conf").write_text(text)


# ----------------------------- auth --------------------------------------
def test_no_token_configured_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("AWG_AGENT_TOKEN", "")
    monkeypatch.setenv("AWG_DIR", str(tmp_path))
    mod = importlib.import_module("awg_agent")
    importlib.reload(mod)
    c = TestClient(mod.app)
    assert c.get("/v1/status").status_code == 503


def test_missing_token_401(client):
    assert client.get("/v1/status").status_code == 401


def test_wrong_token_403(client):
    r = client.get("/v1/status", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 403


def test_health_needs_no_auth(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["version"]


def test_health_does_not_leak_fingerprint(client):
    # role/installed/running/hostname must NOT appear on the unauthenticated probe
    body = client.get("/health").json()
    assert set(body.keys()) == {"status", "version"}


def test_bind_guard(agent):
    # wildcard + globally-routable => unsafe; loopback / RFC1918 / CGNAT(tailnet) => safe
    assert agent.bind_is_unsafe("0.0.0.0") is True
    assert agent.bind_is_unsafe("::") is True
    assert agent.bind_is_unsafe("8.8.8.8") is True
    assert agent.bind_is_unsafe("127.0.0.1") is False
    assert agent.bind_is_unsafe("10.87.183.128") is False
    assert agent.bind_is_unsafe("100.75.35.64") is False  # Tailscale CGNAT 100.64/10
    assert agent.bind_is_unsafe("vpn.example.com") is False  # hostname: operator's call


# ----------------------------- status / reads ---------------------------
def test_status_parses_interface(client, agent, monkeypatch):
    write_conf(agent)
    (agent._tmp / "awgsetup_cfg.init").write_text("export AWG_ROLE='entry'\n")
    r = client.get("/v1/status", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["installed"] is True
    assert body["role"] == "entry"
    assert body["port"] == "39743"
    assert body["awgParams"]["Jc"] == "4"
    assert body["clientsCount"] == 2


def test_clients_list_includes_exit_assignment(client, agent, monkeypatch):
    write_conf(agent)
    monkeypatch.setattr(agent, "awg_show", lambda: {})
    r = client.get("/v1/clients", headers=AUTH)
    assert r.status_code == 200
    clients = {c["name"]: c for c in r.json()["clients"]}
    assert clients["alice"]["exit"] == "de"
    assert clients["alice"]["ip"] == "172.16.17.2"
    assert clients["bob"]["exit"] == "direct"


def test_exits_list(client, agent):
    exits = agent._tmp / "exits"
    exits.mkdir()
    (exits / "de.conf").write_text(
        "EXIT_CC=de\nEXIT_IFACE=awg-de\nEXIT_ENDPOINT=203.0.113.7\n"
        "EXIT_FWMARK=0x1\nEXIT_TABLE=101\nEXIT_TRANSPORT=amneziawg\n"
    )
    r = client.get("/v1/exits", headers=AUTH)
    assert r.status_code == 200
    de = r.json()["exits"][0]
    assert de["cc"] == "de" and de["endpoint"] == "203.0.113.7" and de["table"] == "101"


# ----------------------------- clients mutations ------------------------
def test_add_client_invokes_manage_and_returns_config(client, agent, record_manage):
    (agent._tmp / "alice.conf").write_text("[Interface]\nAddress = 172.16.17.2/32\n")
    write_conf(agent)
    r = client.post("/v1/clients", headers=AUTH, json={"name": "alice"})
    assert r.status_code == 201
    assert record_manage[-1] == ["add", "alice"]
    assert "[Interface]" in r.json()["config"]
    assert r.json()["publicKey"] == "ALICEPUB"


def test_add_client_with_expires_and_psk(client, agent, record_manage):
    (agent._tmp / "x.conf").write_text("[Interface]\n")
    r = client.post("/v1/clients", headers=AUTH, json={"name": "x", "expires": "7d", "psk": True})
    assert r.status_code == 201
    assert record_manage[-1] == ["--psk", "--expires=7d", "add", "x"]


def test_add_client_bad_name_400(client, record_manage):
    assert client.post("/v1/clients", headers=AUTH, json={"name": "-rm"}).status_code == 400
    assert client.post("/v1/clients", headers=AUTH, json={"name": "a b"}).status_code == 400
    assert client.post("/v1/clients", headers=AUTH, json={"name": "a.b"}).status_code == 400   # '.' rejected (matches bash)
    assert client.post("/v1/clients", headers=AUTH, json={"name": "ok\n"}).status_code == 400  # trailing newline (\Z)
    assert not record_manage  # bash never invoked


def test_run_manage_pins_conf_dir(agent, monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    agent.run_manage(["list"])
    # the conf-dir flag must precede the command so bash + agent share a working dir
    assert captured["cmd"][2] == f"--conf-dir={agent.SETTINGS.awg_dir}"
    assert captured["cmd"][3] == "list"


def test_add_client_bad_expires_400(client, record_manage):
    r = client.post("/v1/clients", headers=AUTH, json={"name": "ok", "expires": "soon"})
    assert r.status_code == 400


def test_remove_client(client, record_manage):
    r = client.request("DELETE", "/v1/clients/alice", headers=AUTH)
    assert r.status_code == 200
    assert record_manage[-1] == ["remove", "alice"]


def test_set_exit_cc_and_direct(client, record_manage):
    assert client.post("/v1/clients/alice/exit", headers=AUTH, json={"exit": "de"}).status_code == 200
    assert record_manage[-1] == ["set-exit", "alice", "de"]
    client.post("/v1/clients/alice/exit", headers=AUTH, json={"exit": "direct"})
    assert record_manage[-1] == ["set-exit", "alice", "direct"]


def test_set_exit_bad_cc_400(client, record_manage):
    r = client.post("/v1/clients/alice/exit", headers=AUTH, json={"exit": "ZZ"})
    assert r.status_code == 400
    assert not record_manage


# ----------------------------- exits mutations --------------------------
def test_add_exit_amneziawg_requires_config(client, record_manage):
    r = client.post("/v1/exits", headers=AUTH, json={"cc": "de", "transport": "amneziawg"})
    assert r.status_code == 400
    assert not record_manage


def test_add_exit_amneziawg_writes_temp_and_calls_manage(client, agent, record_manage):
    (agent._tmp / "exits").mkdir()
    body = {"cc": "de", "transport": "amneziawg", "config": "[Interface]\nPrivateKey=X\n"}
    r = client.post("/v1/exits", headers=AUTH, json=body)
    assert r.status_code == 201
    assert record_manage[-1][0:2] == ["add-exit", "de"]
    assert record_manage[-1][2].endswith(".conf")  # temp file path


def test_add_exit_tailscale_requires_ts_ip(client, record_manage):
    r = client.post("/v1/exits", headers=AUTH, json={"cc": "sg", "transport": "tailscale"})
    assert r.status_code == 400
    r = client.post("/v1/exits", headers=AUTH,
                    json={"cc": "sg", "transport": "tailscale", "ts_ip": "100.64.0.9"})
    assert r.status_code == 201
    assert record_manage[-1] == ["add-exit", "sg", "--transport=tailscale", "--ts-ip=100.64.0.9"]


def test_add_exit_bad_ts_ip_400(client, record_manage):
    r = client.post("/v1/exits", headers=AUTH,
                    json={"cc": "sg", "transport": "tailscale", "ts_ip": "not-an-ip"})
    assert r.status_code == 400


def test_remove_exit_force(client, agent, record_manage):
    (agent._tmp / "exits").mkdir()
    r = client.request("DELETE", "/v1/exits/de", headers=AUTH, params={"force": "true"})
    assert r.status_code == 200
    assert record_manage[-1] == ["remove-exit", "de", "--force"]


def test_remove_exit_invalid_cc_400(client, record_manage):
    assert client.request("DELETE", "/v1/exits/XX", headers=AUTH).status_code == 400


# ----------------------------- routing / geo ----------------------------
def test_geo_split_toggle(client, record_manage):
    client.post("/v1/geo-split", headers=AUTH, json={"enabled": False})
    assert record_manage[-1] == ["geo-split", "off"]
    client.post("/v1/geo-split", headers=AUTH, json={"enabled": True})
    assert record_manage[-1] == ["geo-split", "on"]


def test_routing_reload_and_ru_update(client, record_manage):
    assert client.post("/v1/routing/reload", headers=AUTH).status_code == 200
    assert record_manage[-1] == ["reload-routing"]
    assert client.post("/v1/ru-list/update", headers=AUTH).status_code == 200
    assert record_manage[-1] == ["update-ru-list"]


def test_genlib_presets(client):
    r = client.get("/v1/presets", headers=AUTH)
    assert r.status_code == 200
    assert "home" in r.json()["presets"]


def test_genlib_generate_preset(client):
    r = client.post("/v1/generate", headers=AUTH, json={"preset": "home"})
    assert r.status_code == 200
    body = r.json()
    assert body["validation"]["ok"] is True
    assert "Jc" in body["params"] and "I1" in body["params"]


def test_genlib_generate_bad_preset_400(client):
    assert client.post("/v1/generate", headers=AUTH, json={"preset": "nope"}).status_code == 400


def test_genlib_validate(client):
    assert client.post("/v1/validate", headers=AUTH, json={"params": {"Jc": 5}}).json()["ok"] is True
    assert client.post("/v1/validate", headers=AUTH, json={"params": {"Jc": 999}}).json()["ok"] is False


def test_genlib_merge(client, agent):
    from awg_genlib import vpn_encode, vpn_decode
    link = vpn_encode({"containers": [{"awg": {"Jc": "4"}}]})
    r = client.post("/v1/merge", headers=AUTH, json={"link": link, "params": {"Jc": 9}})
    assert r.status_code == 200
    assert vpn_decode(r.json()["link"])["containers"][0]["awg"]["Jc"] == "9"


def test_genlib_presets_have_details(client):
    body = client.get("/v1/presets", headers=AUTH).json()
    assert "home" in body["presets"]
    names = {d["name"] for d in body["details"]}
    assert names == set(body["presets"])
    assert all(d["label"] and d["description"] for d in body["details"])


def test_genlib_profiles_metadata(client):
    body = client.get("/v1/profiles", headers=AUTH).json()
    keys = {p["key"] for p in body["profiles"]}
    assert {"quic_initial", "tls_to_quic", "dns_query", "random"} <= keys
    assert "chrome" in body["browsers"] and "yandex_mobile" in body["browsers"]
    assert body["host_pool_summary"]["tls_client_hello"] > 100


def test_genlib_hostpool_lookup(client):
    r = client.get("/v1/hostpools/quic_initial", headers=AUTH)
    assert r.status_code == 200 and "yandex.net" in r.json()["hosts"]
    # dns_query maps to the DNS-IP pool
    assert "8.8.8.8" in client.get("/v1/hostpools/dns_query", headers=AUTH).json()["hosts"]
    assert client.get("/v1/hostpools/bogus", headers=AUTH).status_code == 404


def test_genlib_hostpool_tiered(client):
    body = client.get("/v1/hostpools/quic_initial", headers=AUTH, params={"tiered": "true"}).json()
    assert any(h["host"] == "yandex.net" and h["tier"] == "ru-domestic" for h in body["hosts"])
    assert "ru-domestic" in body["tiers"]


def test_genlib_generate_full_knobs(client):
    r = client.post("/v1/generate", headers=AUTH, json={
        "profile": "tls_to_quic", "intensity": "high", "browser_profile": "chrome",
        "use_browser_fp": True, "mimic_all": True, "seed": 7, "mtu": 1280,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["validation"]["ok"] is True
    assert body["used"]["profile"] == "tls_to_quic"
    assert body["params"]["I1"].startswith("<b 0x160301")  # TLS ClientHello


def test_genlib_generate_seed_reproducible(client):
    a = client.post("/v1/generate", headers=AUTH, json={"profile": "quic_initial", "seed": 99}).json()
    b = client.post("/v1/generate", headers=AUTH, json={"profile": "quic_initial", "seed": 99}).json()
    assert a["params"] == b["params"]


def test_genlib_generate_bad_profile_400(client):
    assert client.post("/v1/generate", headers=AUTH,
                       json={"profile": "no-such"}).status_code == 400


def test_genlib_merge_links_container_merge(client):
    from awg_genlib import vpn_encode, vpn_decode
    a = vpn_encode({"containers": [{"container": "amnezia-awg", "awg": {"Jc": "4"}}], "description": "A"})
    b = vpn_encode({"containers": [{"container": "amnezia-xray", "xray": {}}], "description": "B"})
    r = client.post("/v1/merge-links", headers=AUTH, json={"links": [a, b]})
    assert r.status_code == 200
    body = r.json()
    assert body["stats"]["unique"] == 2
    assert len(vpn_decode(body["link"])["containers"]) == 2
    # single link rejected
    assert client.post("/v1/merge-links", headers=AUTH, json={"links": [a]}).status_code == 400


def test_manage_failure_surfaces_500(client, agent, monkeypatch):
    def boom(args, timeout=None):
        return types.SimpleNamespace(returncode=1, stdout="", stderr="kaboom")
    monkeypatch.setattr(agent, "run_manage", boom)
    r = client.post("/v1/routing/reload", headers=AUTH)
    assert r.status_code == 500
    assert "kaboom" in r.json()["detail"]
