# awg-agent — per-server management API

A lightweight FastAPI daemon that exposes the AmneziaWG cascade management
surface over HTTP, so the central panel can drive each server through an API
instead of SSH-ing and running bash. **Phase A** (this version) is a thin,
authenticated wrapper over the proven bash layer
(`manage_amneziawg.sh` + `awg-routing`): mutations shell out to the script,
reads parse the live config files and `awg show` into JSON. The bash scripts
remain the documented fallback and the source of truth for on-disk state, so
the API and a human operator interoperate freely.

## Security model

This is a **root-level management API**. It is protected by two things:

1. **Network binding.** It must bind to the **Tailscale interface only**
   (`AWG_AGENT_BIND=<100.x>`), never a public address. The default is
   `127.0.0.1` so a misconfigured unit fails safe.
2. **Bearer token.** Every `/v1` route requires `Authorization: Bearer <token>`,
   compared in constant time. It **fails closed**: with no token configured the
   API rejects all authed requests (503).

Tailscale's WireGuard transport provides the encryption; mTLS/HTTPS is a
Phase 5 hardening follow-up. Never expose the agent port publicly.

## Install

```bash
sudo agent/install_agent.sh                 # binds to the Tailscale IP if present
sudo agent/install_agent.sh --bind=100.x.y.z --port=8080
sudo agent/install_agent.sh --print-token   # show the generated token for the panel
```

This creates a venv at `/opt/awg-agent/venv`, installs the unit
`awg-agent.service`, writes `/etc/awg-agent/agent.env` (mode 600, holds the
token), and starts the service. Re-running updates the code/unit and keeps the
existing token unless `--token=` is given.

## Endpoints (v1)

| Method & path | Purpose |
| --- | --- |
| `GET /health` | liveness (no auth): version, role, installed, running |
| `GET /v1/status` | server status: role, port, AWG params, client/exit counts, geo-split |
| `GET /v1/clients` | list clients (+ live `awg show` stats, exit assignment) |
| `POST /v1/clients` | add client `{name, expires?, psk?}` → config + vpn:// |
| `GET /v1/clients/{name}` | client details + config |
| `GET /v1/clients/{name}/config` | raw `.conf` (text/plain) |
| `POST /v1/clients/{name}/regen` | regenerate client files |
| `DELETE /v1/clients/{name}` | remove client |
| `POST /v1/clients/{name}/exit` | set exit `{exit: "de"\|"direct"}` |
| `GET /v1/exits` | list registered cascade exits |
| `POST /v1/exits` | add exit `{cc, transport, config?, ts_ip?}` |
| `DELETE /v1/exits/{cc}?force=` | remove exit (force repoints clients to direct) |
| `POST /v1/routing/reload` | re-apply cascade routing |
| `POST /v1/geo-split` | `{enabled: bool}` — RU-traffic-stays-local toggle |
| `POST /v1/ru-list/update` | refresh the RU ipset + re-apply routing |
| `GET /v1/show` | raw `awg show awg0` |

### Example

```bash
TOKEN=$(sudo sed -n 's/^AWG_AGENT_TOKEN=//p' /etc/awg-agent/agent.env)
BASE=http://100.x.y.z:8080
curl -s $BASE/health | jq
curl -s -H "Authorization: Bearer $TOKEN" $BASE/v1/status | jq
curl -s -H "Authorization: Bearer $TOKEN" -X POST $BASE/v1/clients \
     -d '{"name":"phone","expires":"30d"}' -H 'Content-Type: application/json' | jq
```

## Configuration (`/etc/awg-agent/agent.env`)

| Var | Default | Meaning |
| --- | --- | --- |
| `AWG_AGENT_BIND` | `127.0.0.1` | listen address — set to the tailnet IP. The agent **refuses to start** on a `0.0.0.0`/public bind unless `AWG_AGENT_ALLOW_PUBLIC=1` |
| `AWG_AGENT_ALLOW_PUBLIC` | _(unset)_ | set to `1` to override the public-bind guard (not recommended) |
| `AWG_AGENT_PORT` | `8080` | listen port |
| `AWG_AGENT_TOKEN` | _(empty)_ | bearer token (required; empty ⇒ fail closed). Preferred way to supply a token at install (avoids `ps`/history exposure of `--token=`) |
| `AWG_DIR` | `/root/awg` | installer working dir |
| `AWG_MANAGE` | `$AWG_DIR/manage_amneziawg.sh` | management script |
| `AWG_SERVER_CONF` | `/etc/amnezia/amneziawg/awg0.conf` | live server config |
| `AWG_CONFIG_INIT` | `$AWG_DIR/awgsetup_cfg.init` | bootstrap params |
| `AWG_EXITS_DIR` | `$AWG_DIR/exits` | cascade exit registry |
| `AWG_IFACE` | `awg0` | server interface |

## Tests

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt pytest httpx
pytest agent/tests/
```

The tests mock the bash layer and `awg show`, so they need neither root nor
AmneziaWG.
