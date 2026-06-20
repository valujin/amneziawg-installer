#!/usr/bin/env python3
"""awg-agent — per-server management API for the AmneziaWG cascade platform.

Phase A: a thin, authenticated HTTP surface over the proven bash management
layer (``manage_amneziawg.sh`` + ``awg-routing``). Mutations shell out to the
bash script (``AWG_YES=1``, argv list — no shell, so no command injection);
reads parse the live config files and ``awg show`` straight into JSON.

Security model — this is a ROOT-LEVEL management API:
  * MUST bind to the Tailscale interface only (``AWG_AGENT_BIND=<100.x>``),
    never to a public address. Defaults to 127.0.0.1 so a misconfigured unit
    fails safe rather than exposing the host.
  * Bearer-token auth on every ``/v1`` route, constant-time compared. Fails
    CLOSED: if no token is configured the API refuses all authed requests.

The bash scripts remain the documented fallback / source of truth; the agent
never owns state of its own (Phase B will move config generation in-process).
See agent/README.md.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import uuid as uuidlib
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

AGENT_VERSION = "0.1.0"

# Config-generation library (Architect port). Optional: the agent still serves
# client/exit/routing management if awg_genlib was not deployed alongside it.
try:
    from awg_genlib import (
        generate as genlib_generate,
        validate as genlib_validate,
        merge_into_link as genlib_merge_into_link,
        merge_links as genlib_merge_links,
        generate_preset as genlib_generate_preset,
        list_presets as genlib_list_presets,
        describe_presets as genlib_describe_presets,
        list_profiles as genlib_list_profiles,
        list_browsers as genlib_list_browsers,
        host_pool as genlib_host_pool,
        host_pool_summary as genlib_host_pool_summary,
        host_pool_tiered as genlib_host_pool_tiered,
        tier_definitions as genlib_tier_definitions,
        MIMIC_PROFILES as GENLIB_PROFILES,
        BROWSER_PROFILES as GENLIB_BROWSERS,
        xray_build_entry_config as genlib_xray_entry,
        xray_build_exit_config as genlib_xray_exit,
        xray_vless_link as genlib_vless_link,
        XRAY_DEFAULT_DESTS as GENLIB_XRAY_DESTS,
        XRAY_DEFAULT_DEST as GENLIB_XRAY_DEST,
    )
    GENLIB_OK = True
except ImportError:  # pragma: no cover
    GENLIB_OK = False


# --------------------------------------------------------------------------
# Configuration (environment, typically from /etc/awg-agent/agent.env)
# --------------------------------------------------------------------------
class Settings:
    def __init__(self) -> None:
        self.bind = os.environ.get("AWG_AGENT_BIND", "127.0.0.1")
        self.port = int(os.environ.get("AWG_AGENT_PORT", "8080"))
        self.token = os.environ.get("AWG_AGENT_TOKEN", "").strip()
        self.awg_dir = os.environ.get("AWG_DIR", "/root/awg")
        self.manage = os.environ.get(
            "AWG_MANAGE", os.path.join(self.awg_dir, "manage_amneziawg.sh")
        )
        self.server_conf = os.environ.get(
            "AWG_SERVER_CONF", "/etc/amnezia/amneziawg/awg0.conf"
        )
        self.config_init = os.environ.get(
            "AWG_CONFIG_INIT", os.path.join(self.awg_dir, "awgsetup_cfg.init")
        )
        self.exits_dir = os.environ.get(
            "AWG_EXITS_DIR", os.path.join(self.awg_dir, "exits")
        )
        self.cmd_timeout = int(os.environ.get("AWG_CMD_TIMEOUT", "300"))
        self.awg_iface = os.environ.get("AWG_IFACE", "awg0")
        # VLESS+REALITY (Xray) entry/exit — thin bash manager + agent-owned state.
        self.xray_script = os.environ.get(
            "AWG_XRAY", os.path.join(self.awg_dir, "awg-xray.sh")
        )
        self.xray_state_dir = os.environ.get(
            "AWG_XRAY_STATE", os.path.join(self.awg_dir, "xray")
        )
        self.allow_public = os.environ.get("AWG_AGENT_ALLOW_PUBLIC", "").lower() in ("1", "true", "yes")


SETTINGS = Settings()

# Conservative validators. argv is never passed through a shell, so the only
# real hazard is a value that looks like a flag (leading '-'); these patterns
# block that and keep names within what the bash layer accepts. We match the
# bash validate_client_name set (^[A-Za-z0-9_-]+$ — no dot) so a name the bash
# layer would reject is rejected here with a clean 400, not a 500. \Z (not $)
# so a trailing newline cannot slip through.
CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]{0,63}\Z")
CC_RE = re.compile(r"^[a-z]{2}[0-9]?$")
EXPIRES_RE = re.compile(r"^[0-9]+[hdw]$")


def valid_client_name(name: str) -> bool:
    return bool(name) and bool(CLIENT_NAME_RE.match(name))


def valid_cc(cc: str) -> bool:
    return bool(CC_RE.match(cc))


# --------------------------------------------------------------------------
# Command runner — shells out to the bash management layer
# --------------------------------------------------------------------------
def run_manage(args: list[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Run manage_amneziawg.sh <args> non-interactively. Returns the process.

    Args are passed as a list (execve, no shell). AWG_YES=1 suppresses the
    interactive confirm prompts.
    """
    # Pin the bash layer to the SAME working dir the agent reads from:
    # manage_amneziawg.sh hard-sets AWG_DIR=/root/awg internally and only honours
    # the --conf-dir flag, so without this a non-default AWG_DIR would write
    # client/exit files where the agent never looks (read/write split-brain).
    cmd = ["bash", SETTINGS.manage, f"--conf-dir={SETTINGS.awg_dir}", *args]
    env = {**os.environ, "AWG_YES": "1"}
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout or SETTINGS.cmd_timeout,
        env=env,
    )


def manage_or_raise(args: list[str], timeout: Optional[int] = None) -> str:
    """Run manage; raise 500 with the stderr/stdout tail on non-zero exit."""
    try:
        proc = run_manage(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, detail="manage script timed out")
    except FileNotFoundError:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="manage script not found")
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-1500:]
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"manage {' '.join(args[:2])} failed (rc={proc.returncode}): {tail}",
        )
    return proc.stdout or ""


def run_cmd(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Run an arbitrary read-only command; never raises. (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return 1, "", str(e)


# --------------------------------------------------------------------------
# VLESS+REALITY (Xray) — thin bash driver + agent-owned state
# --------------------------------------------------------------------------
# Unlike the WireGuard layer (where manage_amneziawg.sh owns state), the Xray
# entry/exit has no bash state layer: awg-xray.sh is a thin binary/systemd
# manager and the agent owns the server params + client registry as JSON, then
# rebuilds the whole config.json on every change (robust; no in-place surgery).
def _xray_server_path() -> str:
    return os.path.join(SETTINGS.xray_state_dir, "server.json")


def _xray_clients_path() -> str:
    return os.path.join(SETTINGS.xray_state_dir, "clients.json")


def _xray_read_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def _xray_write_json(path: str, obj) -> None:
    os.makedirs(SETTINGS.xray_state_dir, mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def run_xray(args: list[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    cmd = ["bash", SETTINGS.xray_script, *args]
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout or SETTINGS.cmd_timeout, env={**os.environ})


def xray_keygen() -> dict:
    """Generate a REALITY x25519 keypair + uuid + shortId via awg-xray.sh keygen."""
    try:
        proc = run_xray(["keygen"], timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"xray keygen failed: {e}")
    if proc.returncode != 0:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"xray keygen rc={proc.returncode}: {(proc.stderr or '')[-400:]}")
    out = {}
    for line in (proc.stdout or "").splitlines():
        k, _, v = line.strip().partition("=")
        if k in ("PRIVATE", "PUBLIC", "UUID", "SHORTID") and v:
            out[k.lower()] = v
    if not out.get("private") or not out.get("public"):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="xray keygen produced no keypair")
    return out


def xray_installed() -> bool:
    return os.path.isfile(_xray_server_path())


def xray_active() -> bool:
    rc, out, _ = run_cmd(["systemctl", "is-active", "awg-xray"])
    return out.strip().split("\n", 1)[0] == "active"


def xray_apply_or_raise(config: dict, listen_port: int) -> None:
    """Render config.json to a temp file and hand it to awg-xray.sh apply."""
    try:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, dir="/tmp")
    except OSError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"cannot stage xray config: {e}")
    try:
        json.dump(config, tmp, indent=2)
        tmp.close()
        try:
            proc = run_xray(["apply", tmp.name, str(listen_port)])
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"xray apply failed: {e}")
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip()[-1200:]
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"xray apply rc={proc.returncode}: {tail}")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def xray_rebuild_and_apply() -> dict:
    """Re-render the entry/exit config.json from stored server params + clients."""
    if not GENLIB_OK:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, detail="awg_genlib not deployed (no xray builder)")
    srv = _xray_read_json(_xray_server_path(), None)
    if not srv:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="xray server not provisioned (POST /v1/reality/server first)")
    clients = _xray_read_json(_xray_clients_path(), [])
    cl = [{"id": c["uuid"], "email": c.get("name", c["uuid"][:8])} for c in clients]
    short_ids = [c["shortid"] for c in clients if c.get("shortid")]
    listen = int(srv.get("listen", 443))
    if srv.get("role") == "exit":
        cfg = genlib_xray_exit(listen, srv["dest"], srv["sni"], srv["private_key"], short_ids, cl)
    else:
        cfg = genlib_xray_entry(listen, srv["dest"], srv["sni"], srv["private_key"],
                                short_ids, cl, cascade=srv.get("cascade"),
                                geo_split=bool(srv.get("geo_split", True)))
    xray_apply_or_raise(cfg, listen)
    return srv


# --------------------------------------------------------------------------
# Read helpers — parse live config files + `awg show` into JSON
# --------------------------------------------------------------------------
def read_server_conf() -> str:
    try:
        with open(SETTINGS.server_conf, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def server_installed() -> bool:
    return os.path.isfile(SETTINGS.server_conf)


def service_active() -> bool:
    rc, out, _ = run_cmd(["systemctl", "is-active", f"awg-quick@{SETTINGS.awg_iface}"])
    return out.strip().split("\n", 1)[0] == "active"


_AWG_KEY_MAP = {
    "jc": "Jc", "jmin": "Jmin", "jmax": "Jmax",
    "s1": "S1", "s2": "S2", "s3": "S3", "s4": "S4",
    "h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4",
    "i1": "I1", "i2": "I2", "i3": "I3", "i4": "I4", "i5": "I5",
    "listenport": "ListenPort", "mtu": "MTU",
}


def read_interface_params(text: Optional[str] = None) -> dict:
    """Extract [Interface] Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5/ListenPort/MTU."""
    if text is None:
        text = read_server_conf()
    params: dict[str, str] = {}
    in_iface = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[Interface]"):
            in_iface = True
            continue
        if s.startswith("["):
            in_iface = False
            continue
        if not in_iface or not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        mapped = _AWG_KEY_MAP.get(k.strip().lower())
        if mapped:
            params[mapped] = v.strip()
    return params


def interface_address(text: Optional[str] = None) -> str:
    if text is None:
        text = read_server_conf()
    in_iface = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[Interface]"):
            in_iface = True
            continue
        if s.startswith("["):
            in_iface = False
            continue
        if in_iface and s.lower().startswith("address"):
            _, _, v = s.partition("=")
            return v.strip()
    return ""


def parse_peers(text: Optional[str] = None) -> list[dict]:
    """Walk awg0.conf → [{name, public_key, allowed_ips, exit}, ...].

    Peers are marked by the installer with `#_Name =` and, when assigned to a
    cascade exit, `#_Exit =` comment lines in the same [Peer] block.
    """
    if text is None:
        text = read_server_conf()
    peers: list[dict] = []
    current: Optional[dict] = None
    in_peer = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[Peer]"):
            if current is not None:
                peers.append(current)
            current = {"name": "", "public_key": "", "allowed_ips": "", "exit": "direct"}
            in_peer = True
            continue
        if line.startswith("["):
            if current is not None:
                peers.append(current)
                current = None
            in_peer = False
            continue
        if not in_peer or current is None:
            continue
        if line.startswith("#_Name"):
            current["name"] = line.partition("=")[2].strip()
            continue
        if line.startswith("#_Exit"):
            ex = line.partition("=")[2].strip()
            current["exit"] = ex or "direct"
            continue
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "publickey":
            current["public_key"] = v
        elif k == "allowedips":
            current["allowed_ips"] = v
    if current is not None:
        peers.append(current)
    return [p for p in peers if p.get("public_key")]


def _parse_bytes(size_str: str) -> int:
    try:
        parts = (size_str or "").strip().split()
        if len(parts) != 2:
            return 0
        units = {"B": 1, "KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3, "TiB": 1024 ** 4}
        return int(float(parts[0]) * units.get(parts[1], 1))
    except (ValueError, IndexError):
        return 0


def awg_show() -> dict:
    """`awg show <iface>` → {pubkey: {endpoint, allowedIps, latestHandshake, ...}}."""
    rc, out, _ = run_cmd(["awg", "show", SETTINGS.awg_iface])
    if rc != 0 or not out.strip():
        return {}
    result: dict[str, dict] = {}
    current = None
    for raw in out.split("\n"):
        line = raw.strip()
        if line.startswith("peer:"):
            current = line.split(":", 1)[1].strip()
            result[current] = {}
            continue
        if not current or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "latest handshake":
            result[current]["latestHandshake"] = value
        elif key == "allowed ips":
            result[current]["allowedIps"] = value
        elif key == "endpoint":
            result[current]["endpoint"] = value
        elif key == "transfer":
            parts = value.split(",")
            if len(parts) == 2:
                rx = parts[0].strip().replace(" received", "")
                tx = parts[1].strip().replace(" sent", "")
                result[current].update(
                    dataReceived=rx, dataSent=tx,
                    dataReceivedBytes=_parse_bytes(rx), dataSentBytes=_parse_bytes(tx),
                )
    return result


def list_clients() -> list[dict]:
    peers = parse_peers()
    live = awg_show()
    out = []
    for p in peers:
        pub = p["public_key"]
        show = live.get(pub, {})
        allowed = p.get("allowed_ips") or show.get("allowedIps", "")
        client_ip = allowed.split(",")[0].strip().split("/")[0] if allowed else ""
        out.append({
            "name": p.get("name") or f"external({client_ip})",
            "publicKey": pub,
            "ip": client_ip,
            "allowedIps": allowed,
            "exit": p.get("exit", "direct"),
            "external": not bool(p.get("name")),
            "latestHandshake": show.get("latestHandshake", ""),
            "dataReceived": show.get("dataReceived", ""),
            "dataSent": show.get("dataSent", ""),
            "dataReceivedBytes": show.get("dataReceivedBytes", 0),
            "dataSentBytes": show.get("dataSentBytes", 0),
        })
    return out


def read_kv_file(path: str, key: str) -> str:
    """Read a single KEY=value (optionally 'export', quoted) from a kv file."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return ""
    rx = re.compile(rf"^(?:export\s+)?{re.escape(key)}=(.*)$")
    val = ""
    for line in text.splitlines():
        m = rx.match(line.strip())
        if m:
            val = m.group(1).strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
        val = val[1:-1]
    return val


def list_exits() -> list[dict]:
    exits = []
    try:
        files = sorted(f for f in os.listdir(SETTINGS.exits_dir) if f.endswith(".conf"))
    except OSError:
        return []
    for fn in files:
        path = os.path.join(SETTINGS.exits_dir, fn)
        cc = read_kv_file(path, "EXIT_CC") or fn[:-5]
        exits.append({
            "cc": cc,
            "transport": read_kv_file(path, "EXIT_TRANSPORT") or "amneziawg",
            "iface": read_kv_file(path, "EXIT_IFACE"),
            "endpoint": read_kv_file(path, "EXIT_ENDPOINT"),
            "tsIp": read_kv_file(path, "EXIT_TS_IP"),
            "fwmark": read_kv_file(path, "EXIT_FWMARK"),
            "table": read_kv_file(path, "EXIT_TABLE"),
        })
    return exits


def server_role() -> str:
    return read_kv_file(SETTINGS.config_init, "AWG_ROLE") or "standalone"


def geo_split_enabled() -> bool:
    # Default ON (matches awg-routing.sh: GEO_SPLIT_ENABLED defaults to 1), but
    # only meaningful on an installed host — don't report ON for a bare/missing config.
    return server_installed() and read_kv_file(SETTINGS.config_init, "GEO_SPLIT_ENABLED") != "0"


def read_client_file(name: str, ext: str) -> Optional[str]:
    path = os.path.join(SETTINGS.awg_dir, f"{name}.{ext}")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------
class AddClientRequest(BaseModel):
    name: str
    expires: Optional[str] = None
    psk: bool = False


class SetExitRequest(BaseModel):
    exit: str = Field(..., description="exit country code (e.g. 'de') or 'direct'")


class AddExitRequest(BaseModel):
    cc: str
    transport: str = "amneziawg"
    config: Optional[str] = Field(None, description="exit client .conf text (amneziawg/wstunnel transport)")
    ts_ip: Optional[str] = Field(None, description="Tailscale IP of the exit (tailscale transport)")
    # wstunnel transport: the exit's wstunnel server endpoint (host[:port], default
    # :443) and the exit's local AmneziaWG UDP port the server forwards to.
    wstunnel_server: Optional[str] = Field(None, description="exit wstunnel server host[:port] (wstunnel transport)")
    wstunnel_awg_port: int = Field(9443, description="exit AmneziaWG UDP port behind the wstunnel server")


class WstunnelServerRequest(BaseModel):
    # Exit role: expose the local AmneziaWG server over TLS/WebSocket.
    awg_port: int = Field(9443, description="local AmneziaWG UDP port to forward to")
    listen_port: int = Field(443, description="public TCP port for the TLS/WS listener")
    sni: str = Field("www.microsoft.com", description="CN/SNI for the self-signed cert")


class RealityServerRequest(BaseModel):
    role: str = "entry"                    # entry | exit
    listen_port: int = 443
    dest: str = "dl.google.com"            # real TLS1.3+h2 origin to borrow
    sni: Optional[str] = None              # default = dest host
    public_host: Optional[str] = None      # public addr clients dial (link building)
    geo_split: bool = True
    cascade: Optional[dict] = Field(None, description="entry: {host,port,uuid,pub,sni,sid} of the exit")
    validate_dest: bool = True             # probe dest for TLS1.3+h2 before applying
    regen_keys: bool = False               # re-mint the REALITY keypair (breaks existing client links)


class RealityClientRequest(BaseModel):
    name: str


class GeoSplitRequest(BaseModel):
    enabled: bool


class GenerateRequest(BaseModel):
    preset: Optional[str] = None          # if set, overrides the knobs below
    version: str = "2.0"                   # 1.0 | 1.5 | 2.0
    intensity: str = "medium"             # low | medium | high
    profile: str = "quic_initial"         # mimicry profile (see /v1/profiles)
    extreme: bool = False                  # widen S3/S4 + Jc ceiling + tighter H
    router_mode: bool = False             # minimal sizes for low-power routers
    cps: bool = True                       # emit the I1-I5 CPS chain (AWG 2.0)
    mtu: int = 1280
    # full Architect knobs (optional)
    browser_profile: str = ""             # chrome|edge|firefox|safari|yandex_*|""
    use_browser_fp: bool = False
    mimic_all: bool = False                # mimic every I-slot (vs entropy fill)
    custom_host: str = ""                  # pin the fake SNI/host
    junk_level: int = 5                    # Jc base
    use_tag_c: bool = True
    use_tag_t: bool = True
    use_tag_r: bool = True
    use_tag_rc: bool = True
    use_tag_rd: bool = False
    seed: Optional[int] = None             # reproducible output


class ValidateRequest(BaseModel):
    params: dict
    mtu: int = 1280


class MergeRequest(BaseModel):
    link: str                              # a vpn:// link
    params: dict                           # {Jc,Jmin,Jmax,I1..I5} to patch in


class MergeLinksRequest(BaseModel):
    links: List[str]                       # ≥2 vpn:// links to container-merge


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
def require_token(request: Request) -> None:
    """Bearer-token gate. Fails CLOSED when no token is configured."""
    if not SETTINGS.token:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent has no AWG_AGENT_TOKEN configured (refusing all requests)",
        )
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not secrets.compare_digest(presented.strip(), SETTINGS.token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="invalid token")


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------
app = FastAPI(title="awg-agent", version=AGENT_VERSION)
authed = [Depends(require_token)]


@app.get("/health")
def health() -> dict:
    """Liveness probe — no auth. Deliberately minimal: returns only that the
    process is up and its version, so an unauthenticated probe cannot fingerprint
    the host or its deployment state (role/installed/running live behind the
    authed /v1/status). Also avoids spawning systemctl on every unauthed hit.
    """
    return {"status": "ok", "version": AGENT_VERSION}


@app.get("/v1/status", dependencies=authed)
def status_endpoint() -> dict:
    installed = server_installed()
    info = {
        "version": AGENT_VERSION,
        "role": server_role(),
        "installed": installed,
        "running": service_active() if installed else False,
        "geoSplit": geo_split_enabled(),
    }
    if installed:
        params = read_interface_params()
        info["port"] = params.get("ListenPort", "")
        info["address"] = interface_address()
        info["awgParams"] = params
        info["clientsCount"] = len(parse_peers())
        info["exitsCount"] = len(list_exits())
    return info


# ----- clients -----
@app.get("/v1/clients", dependencies=authed)
def clients_list() -> dict:
    return {"clients": list_clients()}


@app.post("/v1/clients", dependencies=authed, status_code=status.HTTP_201_CREATED)
def clients_add(req: AddClientRequest) -> dict:
    if not valid_client_name(req.name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    args = ["add", req.name]
    if req.expires is not None:
        if not EXPIRES_RE.match(req.expires):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid expires (e.g. 7d, 12h, 4w)")
        args = [f"--expires={req.expires}", *args]
    if req.psk:
        args = ["--psk", *args]
    manage_or_raise(args)
    conf = read_client_file(req.name, "conf")
    if conf is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="client config not found after add")
    peer = next((p for p in parse_peers() if p.get("name") == req.name), {})
    return {
        "name": req.name,
        "publicKey": peer.get("public_key", ""),
        "ip": (peer.get("allowed_ips", "").split(",")[0].split("/")[0] or ""),
        "config": conf,
        "vpnuri": read_client_file(req.name, "vpnuri"),
    }


@app.get("/v1/clients/{name}", dependencies=authed)
def clients_get(name: str) -> dict:
    if not valid_client_name(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    peer = next((p for p in parse_peers() if p.get("name") == name), None)
    conf = read_client_file(name, "conf")
    if peer is None and conf is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="client not found")
    return {
        "name": name,
        "publicKey": (peer or {}).get("public_key", ""),
        "ip": ((peer or {}).get("allowed_ips", "").split(",")[0].split("/")[0] or ""),
        "exit": (peer or {}).get("exit", "direct"),
        "config": conf,
        "vpnuri": read_client_file(name, "vpnuri"),
    }


@app.get("/v1/clients/{name}/config", dependencies=authed, response_class=PlainTextResponse)
def clients_get_config(name: str) -> str:
    if not valid_client_name(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    conf = read_client_file(name, "conf")
    if conf is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="client config not found")
    return conf


@app.delete("/v1/clients/{name}", dependencies=authed)
def clients_remove(name: str) -> dict:
    if not valid_client_name(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    manage_or_raise(["remove", name])
    return {"removed": name}


@app.post("/v1/clients/{name}/regen", dependencies=authed)
def clients_regen(name: str) -> dict:
    if not valid_client_name(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    manage_or_raise(["regen", name])
    return {"regenerated": name, "vpnuri": read_client_file(name, "vpnuri")}


@app.post("/v1/clients/{name}/exit", dependencies=authed)
def clients_set_exit(name: str, req: SetExitRequest) -> dict:
    if not valid_client_name(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    target = req.exit.strip()
    if target != "direct" and not valid_cc(target):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="exit must be a country code or 'direct'")
    manage_or_raise(["set-exit", name, target])
    return {"name": name, "exit": target}


# ----- exits (cascade) -----
@app.get("/v1/exits", dependencies=authed)
def exits_list() -> dict:
    return {"exits": list_exits()}


@app.post("/v1/exits", dependencies=authed, status_code=status.HTTP_201_CREATED)
def exits_add(req: AddExitRequest) -> dict:
    if not valid_cc(req.cc):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid country code")
    if req.transport not in ("amneziawg", "tailscale", "wstunnel"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="transport must be amneziawg|wstunnel|tailscale")

    if req.transport == "tailscale":
        if not req.ts_ip:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="tailscale transport requires ts_ip")
        try:
            ipaddress.ip_address(req.ts_ip)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid ts_ip")
        manage_or_raise(["add-exit", req.cc, "--transport=tailscale", f"--ts-ip={req.ts_ip}"])
    else:
        # amneziawg + wstunnel both need the exit client .conf; wstunnel also needs
        # the exit's wstunnel server endpoint (the carrier rides TLS to it).
        if not req.config or "[Interface]" not in req.config:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail=f"{req.transport} transport requires the exit client 'config' text")
        extra: list[str] = []
        if req.transport == "wstunnel":
            if not req.wstunnel_server:
                raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                    detail="wstunnel transport requires wstunnel_server (host[:port])")
            extra = ["--transport=wstunnel",
                     f"--wstunnel-server={req.wstunnel_server}",
                     f"--wstunnel-awg-port={req.wstunnel_awg_port}"]
        try:
            # NamedTemporaryFile uses O_CREAT|O_EXCL at mode 0600 — no world-readable window.
            tmp = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False, dir="/tmp")
        except OSError as e:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"cannot create temp config: {e}")
        try:
            tmp.write(req.config)
            tmp.close()
            manage_or_raise(["add-exit", req.cc, tmp.name, *extra])
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
    return {"added": req.cc, "exits": list_exits()}


@app.post("/v1/wstunnel/server", dependencies=authed)
def wstunnel_server(req: WstunnelServerRequest) -> dict:
    """Exit role: stand up the wstunnel server so an entry can carry the WG flow
    inside TLS/443. Idempotent (rewrites + restarts the systemd unit)."""
    manage_or_raise(["wstunnel-server", str(req.awg_port), str(req.listen_port), req.sni])
    return {"wstunnelServer": True, "listen": req.listen_port, "awgPort": req.awg_port}


# ----- VLESS+REALITY (Xray) entry/exit -----
def _reality_link_for(srv: dict, client_uuid: str, short_id: str, label: str) -> str:
    host = (srv.get("public_host") or "").strip()
    if not host or not GENLIB_OK:
        return ""  # panel can build the link from the public IP it already knows
    return genlib_vless_link(host, int(srv.get("listen", 443)), client_uuid,
                             srv["public_key"], srv["sni"], short_id=short_id, label=label)


@app.get("/v1/reality", dependencies=authed)
def reality_status() -> dict:
    srv = _xray_read_json(_xray_server_path(), None)
    if not srv:
        return {"provisioned": False}
    clients = _xray_read_json(_xray_clients_path(), [])
    return {
        "provisioned": True, "role": srv.get("role"), "listen": srv.get("listen"),
        "dest": srv.get("dest"), "sni": srv.get("sni"), "publicKey": srv.get("public_key"),
        "publicHost": srv.get("public_host"), "geoSplit": srv.get("geo_split"),
        "cascade": bool(srv.get("cascade")), "clientsCount": len(clients),
        "active": xray_active(),
    }


@app.post("/v1/reality/server", dependencies=authed)
def reality_provision(req: RealityServerRequest) -> dict:
    _require_genlib()
    if req.role not in ("entry", "exit"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="role must be entry|exit")
    dest_host = req.dest.partition(":")[0].strip()
    sni = (req.sni or dest_host).strip()
    if req.validate_dest:
        rc, out, err = run_cmd(["bash", SETTINGS.xray_script, "test-dest", dest_host], timeout=20)
        if rc != 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail=f"dest '{dest_host}' is not REALITY-suitable (needs TLS1.3+h2): {(err or out).strip()[-200:]}")
    prev = _xray_read_json(_xray_server_path(), None) or {}
    if prev.get("private_key") and not req.regen_keys:
        priv, pub = prev["private_key"], prev["public_key"]
    else:
        kp = xray_keygen()
        priv, pub = kp["private"], kp["public"]
    cascade = None
    if req.role == "entry" and req.cascade:
        c = req.cascade
        for k in ("host", "uuid", "pub", "sni"):
            if not c.get(k):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"cascade missing '{k}'")
        cascade = {"host": c["host"], "port": int(c.get("port", 443)), "uuid": c["uuid"],
                   "pub": c["pub"], "sni": c["sni"], "sid": c.get("sid", "")}
    srv = {"role": req.role, "listen": int(req.listen_port), "dest": dest_host, "sni": sni,
           "private_key": priv, "public_key": pub, "public_host": (req.public_host or "").strip(),
           "geo_split": bool(req.geo_split), "cascade": cascade}
    _xray_write_json(_xray_server_path(), srv)
    if _xray_read_json(_xray_clients_path(), None) is None:
        _xray_write_json(_xray_clients_path(), [])
    xray_rebuild_and_apply()
    return {"role": req.role, "listen": srv["listen"], "dest": dest_host, "sni": sni,
            "publicKey": pub, "publicHost": srv["public_host"],
            "geoSplit": srv["geo_split"], "cascade": bool(cascade), "active": xray_active()}


@app.delete("/v1/reality", dependencies=authed)
def reality_down() -> dict:
    try:
        run_xray(["down"], timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    for p in (_xray_server_path(), _xray_clients_path()):
        try:
            os.unlink(p)
        except OSError:
            pass
    return {"removed": True}


@app.get("/v1/reality/clients", dependencies=authed)
def reality_clients_list() -> dict:
    srv = _xray_read_json(_xray_server_path(), None) or {}
    clients = _xray_read_json(_xray_clients_path(), [])
    return {"clients": [
        {"name": c["name"], "uuid": c["uuid"], "shortid": c.get("shortid", ""),
         "link": _reality_link_for(srv, c["uuid"], c.get("shortid", ""), c["name"]) if srv else ""}
        for c in clients
    ]}


@app.post("/v1/reality/clients", dependencies=authed, status_code=status.HTTP_201_CREATED)
def reality_clients_add(req: RealityClientRequest) -> dict:
    _require_genlib()
    if not valid_client_name(req.name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    srv = _xray_read_json(_xray_server_path(), None)
    if not srv:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="provision the reality server first")
    clients = _xray_read_json(_xray_clients_path(), [])
    if any(c["name"] == req.name for c in clients):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="client already exists")
    cu = str(uuidlib.uuid4())
    sid = secrets.token_hex(8)
    clients.append({"name": req.name, "uuid": cu, "shortid": sid})
    _xray_write_json(_xray_clients_path(), clients)
    xray_rebuild_and_apply()
    return {"name": req.name, "uuid": cu, "shortid": sid,
            "link": _reality_link_for(srv, cu, sid, req.name)}


@app.delete("/v1/reality/clients/{name}", dependencies=authed)
def reality_clients_remove(name: str) -> dict:
    if not valid_client_name(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    clients = _xray_read_json(_xray_clients_path(), [])
    new = [c for c in clients if c["name"] != name]
    if len(new) == len(clients):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="client not found")
    _xray_write_json(_xray_clients_path(), new)
    xray_rebuild_and_apply()
    return {"removed": name}


@app.get("/v1/reality/clients/{name}/link", dependencies=authed, response_class=PlainTextResponse)
def reality_client_link(name: str) -> str:
    if not valid_client_name(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid client name")
    srv = _xray_read_json(_xray_server_path(), None)
    clients = _xray_read_json(_xray_clients_path(), [])
    c = next((x for x in clients if x["name"] == name), None)
    if not srv or not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="client not found")
    link = _reality_link_for(srv, c["uuid"], c.get("shortid", ""), name)
    if not link:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="server public_host not set; rebuild the link from the panel")
    return link


@app.delete("/v1/exits/{cc}", dependencies=authed)
def exits_remove(cc: str, force: bool = False) -> dict:
    if not valid_cc(cc):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid country code")
    args = ["remove-exit", cc]
    if force:
        args.append("--force")
    manage_or_raise(args)
    return {"removed": cc, "exits": list_exits()}


# ----- routing / geo -----
@app.post("/v1/routing/reload", dependencies=authed)
def routing_reload() -> dict:
    manage_or_raise(["reload-routing"])
    return {"reloaded": True}


@app.post("/v1/geo-split", dependencies=authed)
def geo_split(req: GeoSplitRequest) -> dict:
    manage_or_raise(["geo-split", "on" if req.enabled else "off"])
    return {"geoSplit": req.enabled}


@app.post("/v1/ru-list/update", dependencies=authed)
def ru_list_update() -> dict:
    manage_or_raise(["update-ru-list"])
    return {"updated": True}


@app.get("/v1/show", dependencies=authed, response_class=PlainTextResponse)
def show() -> str:
    rc, out, err = run_cmd(["awg", "show", SETTINGS.awg_iface], timeout=15)
    if rc != 0:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=err.strip() or "awg show failed")
    return out


# ----- config generator (awg_genlib / Architect port) -----
def _require_genlib() -> None:
    if not GENLIB_OK:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, detail="awg_genlib not deployed on this agent")


@app.get("/v1/presets", dependencies=authed)
def presets() -> dict:
    """Named scenario presets (with labels/descriptions for the panel picker)."""
    _require_genlib()
    return {"presets": genlib_list_presets(), "details": genlib_describe_presets()}


@app.get("/v1/profiles", dependencies=authed)
def profiles() -> dict:
    """Mimicry profiles, browser fingerprints, intensities, versions (UI metadata)."""
    _require_genlib()
    return {
        "profiles": genlib_list_profiles(),
        "browsers": genlib_list_browsers(),
        "intensities": ["low", "medium", "high"],
        "versions": ["1.0", "1.5", "2.0"],
        "host_pool_summary": genlib_host_pool_summary(),
    }


@app.get("/v1/hostpools/{profile}", dependencies=authed)
def hostpool(profile: str, tiered: bool = False) -> dict:
    """The fake-host/SNI pool for a profile (for a custom-host picker).

    ``?tiered=true`` annotates each host with its Architect tier + note and
    includes the tier taxonomy.
    """
    _require_genlib()
    if profile not in GENLIB_PROFILES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="unknown profile")
    if tiered:
        return {"profile": profile, "hosts": genlib_host_pool_tiered(profile),
                "tiers": genlib_tier_definitions()}
    return {"profile": profile, "hosts": genlib_host_pool(profile)}


@app.post("/v1/generate", dependencies=authed)
def generate_params(req: GenerateRequest) -> dict:
    _require_genlib()
    try:
        if req.preset:
            params = genlib_generate_preset(req.preset, seed=req.seed)
            used = {"preset": req.preset}
        else:
            params = genlib_generate(
                version=req.version, intensity=req.intensity, profile=req.profile,
                extreme=req.extreme, router_mode=req.router_mode, cps=req.cps,
                mtu=req.mtu, browser_profile=req.browser_profile,
                use_browser_fp=req.use_browser_fp, mimic_all=req.mimic_all,
                custom_host=req.custom_host, junk_level=req.junk_level,
                use_tag_c=req.use_tag_c, use_tag_t=req.use_tag_t,
                use_tag_r=req.use_tag_r, use_tag_rc=req.use_tag_rc,
                use_tag_rd=req.use_tag_rd, seed=req.seed,
            )
            used = {"version": req.version, "intensity": req.intensity,
                    "profile": req.profile, "extreme": req.extreme,
                    "router_mode": req.router_mode, "cps": req.cps}
    except (KeyError, ValueError) as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))
    return {"params": params, "validation": genlib_validate(params, mtu=req.mtu),
            "used": used}


@app.post("/v1/validate", dependencies=authed)
def validate_params(req: ValidateRequest) -> dict:
    _require_genlib()
    return genlib_validate(req.params, mtu=req.mtu)


@app.post("/v1/merge", dependencies=authed)
def merge_link(req: MergeRequest) -> dict:
    """Patch obfuscation params into a vpn:// link and return the new link."""
    _require_genlib()
    try:
        return {"link": genlib_merge_into_link(req.link, req.params)}
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"invalid vpn:// link: {e}")


@app.post("/v1/merge-links", dependencies=authed)
def merge_multi_links(req: MergeLinksRequest) -> dict:
    """Container-merge ≥2 vpn:// links into one master key (AWG + XRay, etc.)."""
    _require_genlib()
    if len(req.links) < 2:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="need at least 2 links")
    try:
        return genlib_merge_links(req.links)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"invalid vpn:// link: {e}")


def bind_is_unsafe(bind: str) -> bool:
    """A bind address that would expose this root-level API beyond the host/tailnet:
    the 0.0.0.0/:: wildcards (all interfaces) or any globally-routable IP. Loopback,
    RFC1918, CGNAT/Tailscale (100.64/10) and link-local are safe; a hostname we
    can't classify is left to the operator (returns False)."""
    if bind in ("0.0.0.0", "::"):
        return True
    try:
        return ipaddress.ip_address(bind).is_global
    except ValueError:
        return False


def main() -> None:  # pragma: no cover — runtime entrypoint
    import uvicorn

    if not SETTINGS.token:
        print("WARNING: AWG_AGENT_TOKEN is not set — the API will refuse all authed requests.")
    # Fail-safe: this is a ROOT-LEVEL API. Refuse to bind somewhere the whole
    # internet could reach it, unless the operator explicitly opts in.
    if bind_is_unsafe(SETTINGS.bind) and not SETTINGS.allow_public:
        sys.stderr.write(
            f"FATAL: refusing to bind the root management API to a public address "
            f"({SETTINGS.bind}:{SETTINGS.port}). Bind to the Tailscale/loopback interface, "
            f"or set AWG_AGENT_ALLOW_PUBLIC=1 to override (NOT recommended).\n"
        )
        sys.exit(2)
    uvicorn.run(app, host=SETTINGS.bind, port=SETTINGS.port, log_level="info")


if __name__ == "__main__":  # pragma: no cover
    main()
