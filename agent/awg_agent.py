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
import os
import re
import secrets
import subprocess
import sys
import tempfile
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

AGENT_VERSION = "0.1.0"


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
    config: Optional[str] = Field(None, description="exit client .conf text (amneziawg transport)")
    ts_ip: Optional[str] = Field(None, description="Tailscale IP of the exit (tailscale transport)")


class GeoSplitRequest(BaseModel):
    enabled: bool


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
    if req.transport not in ("amneziawg", "tailscale"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="transport must be amneziawg|tailscale")

    if req.transport == "tailscale":
        if not req.ts_ip:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="tailscale transport requires ts_ip")
        try:
            ipaddress.ip_address(req.ts_ip)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid ts_ip")
        manage_or_raise(["add-exit", req.cc, "--transport=tailscale", f"--ts-ip={req.ts_ip}"])
    else:
        if not req.config or "[Interface]" not in req.config:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="amneziawg transport requires the exit client 'config' text")
        try:
            # NamedTemporaryFile uses O_CREAT|O_EXCL at mode 0600 — no world-readable window.
            tmp = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False, dir="/tmp")
        except OSError as e:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"cannot create temp config: {e}")
        try:
            tmp.write(req.config)
            tmp.close()
            manage_or_raise(["add-exit", req.cc, tmp.name])
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
    return {"added": req.cc, "exits": list_exits()}


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
