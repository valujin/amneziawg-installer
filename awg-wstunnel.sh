#!/bin/bash
# awg-wstunnel.sh — manage wstunnel (WireGuard-over-WebSocket-over-TLS) units for
# the AmneziaWG cascade. Defeats WireGuard-flow DPI: a censor that fingerprints
# the WG handshake/transport and drops the flow (while leaving generic UDP/TCP
# alone — the observed TSPU behaviour) sees only a TLS/443 session here.
#
# Roles:
#   EXIT  (e.g. DE): runs a wstunnel SERVER on TCP/443 (real TLS) that forwards
#                    the inner UDP to the local AmneziaWG server (awg0).
#   ENTRY (e.g. RU): runs a wstunnel CLIENT that presents a local UDP port the
#                    cascade carrier (awg-<cc>) dials, tunnelling it to the exit's
#                    :443 over TLS. The carrier's Endpoint is 127.0.0.1:<lport>.
#
# Usage:
#   awg-wstunnel.sh ensure-bin
#   awg-wstunnel.sh server <awg_udp_port> [<listen_port=443>] [<sni=www.microsoft.com>]
#   awg-wstunnel.sh client <cc> <exit_host> <exit_port> <local_port> <exit_awg_port>
#   awg-wstunnel.sh client-down <cc>
#   awg-wstunnel.sh server-down
#
# Env overrides (tests): WSTUNNEL_BIN, WSTUNNEL_VERSION, WST_CERT_DIR, UNIT_DIR,
#   WST_SKIP_APPLY=1 (write files, skip systemctl), WST_DRY_RUN=1 (print only).
set -euo pipefail

WSTUNNEL_BIN="${WSTUNNEL_BIN:-/usr/local/bin/wstunnel}"
WSTUNNEL_VERSION="${WSTUNNEL_VERSION:-10.5.5}"
WST_CERT_DIR="${WST_CERT_DIR:-/etc/amnezia/amneziawg/wstunnel}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
WST_SKIP_APPLY="${WST_SKIP_APPLY:-0}"
WST_DRY_RUN="${WST_DRY_RUN:-0}"

log() { echo "awg-wstunnel: $*" >&2; }
run() { if [[ "$WST_DRY_RUN" == "1" ]]; then printf 'RUN: %s\n' "$*"; else "$@"; fi; }
_sysctl_apply() { [[ "$WST_SKIP_APPLY" == "1" || "$WST_DRY_RUN" == "1" ]] && return 0; return 1; }

# ---- wstunnel binary -------------------------------------------------------
ensure_bin() {
    [[ -x "$WSTUNNEL_BIN" ]] && { log "wstunnel present ($WSTUNNEL_BIN)"; return 0; }
    [[ "$WST_DRY_RUN" == "1" ]] && { log "(dry-run) would download wstunnel"; return 0; }
    local arch tgz url
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log "ERROR: unsupported arch $(uname -m)"; return 1 ;;
    esac
    url="https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/wstunnel_${WSTUNNEL_VERSION}_linux_${arch}.tar.gz"
    tgz="$(mktemp /tmp/wstunnel-XXXXXX.tgz)"
    log "Downloading wstunnel v${WSTUNNEL_VERSION} ($arch)..."
    if ! curl -fsSL --retry 3 --max-time 120 -o "$tgz" "$url"; then
        rm -f "$tgz"; log "ERROR: wstunnel download failed"; return 1
    fi
    tar xzf "$tgz" -C "$(dirname "$WSTUNNEL_BIN")" wstunnel
    chmod 0755 "$WSTUNNEL_BIN"
    rm -f "$tgz"
    [[ -x "$WSTUNNEL_BIN" ]] || { log "ERROR: wstunnel not installed"; return 1; }
    log "wstunnel installed: $($WSTUNNEL_BIN --version 2>&1 | head -1)"
}

# ---- self-signed TLS cert (exit side) --------------------------------------
ensure_cert() {
    local sni="${1:-www.microsoft.com}"
    mkdir -p "$WST_CERT_DIR"; chmod 700 "$WST_CERT_DIR"
    if [[ -s "$WST_CERT_DIR/cert.pem" && -s "$WST_CERT_DIR/key.pem" ]]; then return 0; fi
    [[ "$WST_DRY_RUN" == "1" ]] && { log "(dry-run) would gen cert CN=$sni"; return 0; }
    log "Generating self-signed TLS cert (CN=$sni)..."
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$WST_CERT_DIR/key.pem" -out "$WST_CERT_DIR/cert.pem" \
        -subj "/CN=$sni" >/dev/null 2>&1
    chmod 600 "$WST_CERT_DIR/key.pem" "$WST_CERT_DIR/cert.pem"
}

# ---- EXIT: wstunnel server -------------------------------------------------
do_server() {
    local awg_port="$1" listen="${2:-443}" sni="${3:-www.microsoft.com}"
    [[ -n "$awg_port" ]] || { log "ERROR: server needs <awg_udp_port>"; return 1; }
    ensure_bin; ensure_cert "$sni"
    local unit="$UNIT_DIR/awg-wstunnel-server.service"
    log "Writing $unit (wss://0.0.0.0:$listen -> 127.0.0.1:$awg_port)"
    cat > "$unit" <<EOF
[Unit]
Description=AmneziaWG cascade wstunnel server (WG-over-TLS exit)
After=network-online.target awg-quick@awg0.service
Wants=network-online.target

[Service]
Type=simple
# Restrict forwarding to the local AWG server so the TLS endpoint can't be
# abused as an open relay.
ExecStart=$WSTUNNEL_BIN server --tls-certificate $WST_CERT_DIR/cert.pem --tls-private-key $WST_CERT_DIR/key.pem --restrict-to 127.0.0.1:$awg_port wss://0.0.0.0:$listen
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$unit"
    if [[ "$WST_SKIP_APPLY" == "1" || "$WST_DRY_RUN" == "1" ]]; then return 0; fi
    # Open the TLS port; AmneziaWG cascade uses ufw on entries, exits may too.
    command -v ufw >/dev/null 2>&1 && ufw allow "${listen}/tcp" >/dev/null 2>&1 || true
    systemctl daemon-reload
    systemctl enable --now awg-wstunnel-server.service
    sleep 1
    systemctl is-active --quiet awg-wstunnel-server.service \
        && log "wstunnel server active on :$listen" \
        || { log "ERROR: wstunnel server failed to start"; journalctl -u awg-wstunnel-server -n5 --no-pager >&2 || true; return 1; }
}

# ---- ENTRY: wstunnel client ------------------------------------------------
do_client() {
    local cc="$1" host="$2" port="${3:-443}" lport="$4" awg_port="${5:-9443}"
    [[ -n "$cc" && -n "$host" && -n "$lport" ]] || { log "ERROR: client needs <cc> <exit_host> <exit_port> <local_port> <exit_awg_port>"; return 1; }
    ensure_bin
    local unit="$UNIT_DIR/awg-wst-${cc}.service"
    log "Writing $unit (udp://127.0.0.1:$lport -> wss://$host:$port -> 127.0.0.1:$awg_port)"
    cat > "$unit" <<EOF
[Unit]
Description=AmneziaWG cascade wstunnel client to exit '$cc' (WG-over-TLS)
After=network-online.target
Wants=network-online.target
Before=awg-quick@awg-${cc}.service

[Service]
Type=simple
# Self-signed cert on the exit => the client must not verify it. timeout_sec=0
# keeps the WireGuard UDP session from idle-closing.
ExecStart=$WSTUNNEL_BIN client -L udp://127.0.0.1:$lport:127.0.0.1:$awg_port?timeout_sec=0 wss://$host:$port
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$unit"
    if [[ "$WST_SKIP_APPLY" == "1" || "$WST_DRY_RUN" == "1" ]]; then return 0; fi
    systemctl daemon-reload
    systemctl enable --now "awg-wst-${cc}.service"
    sleep 1
    systemctl is-active --quiet "awg-wst-${cc}.service" \
        && log "wstunnel client for '$cc' active (local udp :$lport)" \
        || { log "ERROR: wstunnel client failed"; journalctl -u "awg-wst-${cc}" -n5 --no-pager >&2 || true; return 1; }
}

do_client_down() {
    local cc="$1"
    [[ -n "$cc" ]] || return 0
    systemctl disable --now "awg-wst-${cc}.service" 2>/dev/null || true
    rm -f "$UNIT_DIR/awg-wst-${cc}.service"
    systemctl daemon-reload 2>/dev/null || true
    log "wstunnel client for '$cc' removed."
}

do_server_down() {
    systemctl disable --now awg-wstunnel-server.service 2>/dev/null || true
    rm -f "$UNIT_DIR/awg-wstunnel-server.service"
    systemctl daemon-reload 2>/dev/null || true
    log "wstunnel server removed."
}

cmd="${1:-}"; shift || true
case "$cmd" in
    ensure-bin)   ensure_bin ;;
    server)       do_server "$@" ;;
    client)       do_client "$@" ;;
    client-down)  do_client_down "$@" ;;
    server-down)  do_server_down ;;
    *) echo "usage: awg-wstunnel.sh {ensure-bin|server <awg_port> [listen] [sni]|client <cc> <host> <port> <lport> <awg_port>|client-down <cc>|server-down}" >&2; exit 2 ;;
esac
