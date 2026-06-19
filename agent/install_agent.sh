#!/bin/bash
# install_agent.sh — deploy the awg-agent management API on this server.
#
# Creates a dedicated venv, installs the agent + systemd unit, generates a
# bearer token, and binds the API to the Tailscale interface by default (so it
# is reachable only from the tailnet). For lab/LXD testing without Tailscale,
# pass --bind=<reachable-ip> explicitly.
#
# Usage:
#   ./install_agent.sh [--bind=IP] [--port=N] [--token=TOK] [--awg-dir=DIR]
#                      [--no-start] [--print-token]
#
# Prefer supplying a token via the AWG_AGENT_TOKEN env var rather than --token=
# (an argv value is visible in `ps` / shell history). Precedence:
#   --token=  >  $AWG_AGENT_TOKEN  >  existing env file  >  auto-generated.
#
# Idempotent: re-running updates the code + unit and preserves the existing
# token unless --token / $AWG_AGENT_TOKEN is given.
set -euo pipefail

AGENT_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/opt/awg-agent"
VENV="$PREFIX/venv"
ENV_DIR="/etc/awg-agent"
ENV_FILE="$ENV_DIR/agent.env"
UNIT_DST="/etc/systemd/system/awg-agent.service"
AWG_DIR_DEFAULT="/root/awg"

BIND=""
PORT="8080"
TOKEN=""
AWG_DIR="$AWG_DIR_DEFAULT"
START=1
PRINT_TOKEN=0

for arg in "$@"; do
    case "$arg" in
        --bind=*)     BIND="${arg#*=}" ;;
        --port=*)     PORT="${arg#*=}" ;;
        --token=*)    TOKEN="${arg#*=}" ;;
        --awg-dir=*)  AWG_DIR="${arg#*=}" ;;
        --no-start)   START=0 ;;
        --print-token) PRINT_TOKEN=1 ;;
        -h|--help)
            sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "install_agent: unknown argument '$arg'" >&2; exit 2 ;;
    esac
done

log() { echo "install_agent: $*" >&2; }

[[ "$(id -u)" -eq 0 ]] || { log "ERROR: must run as root"; exit 1; }

# --- pick a bind address ----------------------------------------------------
if [[ -z "$BIND" ]]; then
    if command -v tailscale >/dev/null 2>&1; then
        BIND="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
    fi
    if [[ -z "$BIND" ]]; then
        BIND="127.0.0.1"
        log "WARN: no --bind and no Tailscale IP found — binding to 127.0.0.1."
        log "      Set --bind=<tailnet-ip> so the panel can reach the agent."
    fi
fi

# --- token precedence: --token= > $AWG_AGENT_TOKEN env > existing env file > generate
# Prefer the env var over --token= so operators can supply a secret without it
# landing in `ps`/shell history.
if [[ -z "$TOKEN" && -n "${AWG_AGENT_TOKEN:-}" ]]; then
    TOKEN="$AWG_AGENT_TOKEN"
fi
if [[ -z "$TOKEN" && -f "$ENV_FILE" ]]; then
    TOKEN="$(sed -n 's/^AWG_AGENT_TOKEN=//p' "$ENV_FILE" | head -n1)"
    [[ -z "$TOKEN" ]] && log "WARN: $ENV_FILE exists but has no AWG_AGENT_TOKEN — generating a new one (panel must be re-paired)."
fi
if [[ -z "$TOKEN" ]]; then
    TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    log "Generated a new agent token."
fi

# --- system deps ------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    log "Installing python3..."
    apt-get update -qq && apt-get install -y -qq python3 || { log "ERROR: cannot install python3"; exit 1; }
fi
# `python3 -m venv` can exist while ensurepip (needed to bootstrap pip in the
# venv) does not — that is the python3.X-venv package on Debian/Ubuntu.
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    log "Installing python3-venv (ensurepip missing)..."
    pyver="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    apt-get update -qq
    apt-get install -y -qq "python${pyver}-venv" python3-venv >/dev/null 2>&1 \
        || apt-get install -y python3-venv \
        || { log "ERROR: cannot install python3-venv"; exit 1; }
fi

# --- deploy code ------------------------------------------------------------
mkdir -p "$PREFIX"
install -m 0644 "$AGENT_SRC_DIR/awg_agent.py" "$PREFIX/awg_agent.py"
install -m 0644 "$AGENT_SRC_DIR/requirements.txt" "$PREFIX/requirements.txt"

if [[ ! -x "$VENV/bin/python" ]]; then
    log "Creating venv at $VENV..."
    python3 -m venv "$VENV"
fi
log "Installing Python dependencies (this may take a minute)..."
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$PREFIX/requirements.txt"

# --- env file ---------------------------------------------------------------
mkdir -p "$ENV_DIR"
umask 077
cat > "$ENV_FILE" <<EOF
# awg-agent configuration (managed by install_agent.sh)
AWG_AGENT_BIND=$BIND
AWG_AGENT_PORT=$PORT
AWG_AGENT_TOKEN=$TOKEN
AWG_DIR=$AWG_DIR
AWG_MANAGE=$AWG_DIR/manage_amneziawg.sh
AWG_SERVER_CONF=/etc/amnezia/amneziawg/awg0.conf
AWG_CONFIG_INIT=$AWG_DIR/awgsetup_cfg.init
AWG_EXITS_DIR=$AWG_DIR/exits
AWG_IFACE=awg0
EOF
chmod 600 "$ENV_FILE"

# --- systemd unit -----------------------------------------------------------
install -m 0644 "$AGENT_SRC_DIR/awg-agent.service" "$UNIT_DST"
systemctl daemon-reload
systemctl enable awg-agent.service >/dev/null 2>&1 || true

if [[ "$START" -eq 1 ]]; then
    systemctl restart awg-agent.service
    sleep 1
    if systemctl is-active --quiet awg-agent.service; then
        log "awg-agent is running on http://$BIND:$PORT"
    else
        log "ERROR: awg-agent failed to start — see: journalctl -u awg-agent -n 50"
        exit 1
    fi
else
    log "Deployed (not started). Start with: systemctl start awg-agent"
fi

log "Bind:  $BIND:$PORT"
if [[ "$PRINT_TOKEN" -eq 1 ]]; then
    log "Token: $TOKEN"
else
    log "Token stored in $ENV_FILE (use --print-token to display)"
fi
