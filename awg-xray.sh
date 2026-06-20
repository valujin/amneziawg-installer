#!/bin/bash
# awg-xray.sh — manage an Xray-core VLESS + XTLS-Vision + REALITY listener as a
# third CLIENT ENTRY transport for the AmneziaWG platform (alongside AmneziaWG-UDP
# and wstunnel). REALITY is the most DPI-durable transport in RU as of 2026: it
# borrows a real reachable site's TLS handshake + certificate (no self-signed
# tell), replays a real browser fingerprint (uTLS), and reverse-proxies any
# unauthenticated probe to that real site — so the box is indistinguishable from
# the borrowed site under active probing.
#
# Self-contained Xray cascade (does NOT touch the WireGuard fwmark cascade):
#   ENTRY (e.g. RU): VLESS+REALITY inbound on TCP:443 for clients; Xray routing
#                    sends geoip:ru -> freedom (egress RU) and everything else ->
#                    a VLESS+REALITY OUTBOUND to the exit (egress exit). geo-split
#                    on/off = whether the geoip:ru->direct rule is present.
#   EXIT  (e.g. DE): VLESS+REALITY inbound -> freedom (egress here). The entry's
#                    cascade outbound authenticates to this inbound.
#
# This script is a THIN binary/systemd/keygen manager. The config.json itself is
# rendered by the agent (awg_genlib.xray) and handed to `apply`, so client CRUD
# is a full-config rebuild (robust, no in-place JSON surgery).
#
# Usage:
#   awg-xray.sh ensure-bin
#   awg-xray.sh keygen                       # -> PRIVATE/PUBLIC/UUID/SHORTID lines
#   awg-xray.sh apply <config.json> [<listen_port=443>]
#   awg-xray.sh test-dest <host> [<port=443>]   # TLS1.3 + h2 reachability probe
#   awg-xray.sh status
#   awg-xray.sh down
#
# Env overrides (tests): XRAY_BIN, XRAY_VERSION, XRAY_DIR, XRAY_ASSET_DIR,
#   UNIT_DIR, XRAY_SKIP_APPLY=1 (write files, skip systemctl), XRAY_DRY_RUN=1.
set -euo pipefail

XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
XRAY_VERSION="${XRAY_VERSION:-26.3.27}"
XRAY_DIR="${XRAY_DIR:-/etc/amnezia/amneziawg/xray}"
XRAY_ASSET_DIR="${XRAY_ASSET_DIR:-/usr/local/share/xray}"
XRAY_CONF="${XRAY_CONF:-$XRAY_DIR/config.json}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="awg-xray.service"
XRAY_SKIP_APPLY="${XRAY_SKIP_APPLY:-0}"
XRAY_DRY_RUN="${XRAY_DRY_RUN:-0}"

log() { echo "awg-xray: $*" >&2; }
_skip() { [[ "$XRAY_SKIP_APPLY" == "1" || "$XRAY_DRY_RUN" == "1" ]]; }

# ---- xray binary + geodata -------------------------------------------------
ensure_bin() {
    if [[ -x "$XRAY_BIN" ]]; then log "xray present ($XRAY_BIN)"; return 0; fi
    [[ "$XRAY_DRY_RUN" == "1" ]] && { log "(dry-run) would download xray v$XRAY_VERSION"; return 0; }
    local arch asset url zip
    case "$(uname -m)" in
        x86_64|amd64)  asset="Xray-linux-64.zip" ;;
        aarch64|arm64) asset="Xray-linux-arm64-v8a.zip" ;;
        *) log "ERROR: unsupported arch $(uname -m)"; return 1 ;;
    esac
    url="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${asset}"
    zip="$(mktemp /tmp/xray-XXXXXX.zip)"
    log "Downloading Xray-core v${XRAY_VERSION} ($asset)..."
    if ! curl -fsSL --retry 3 --max-time 180 -o "$zip" "$url"; then
        rm -f "$zip"; log "ERROR: xray download failed ($url)"; return 1
    fi
    mkdir -p "$(dirname "$XRAY_BIN")" "$XRAY_ASSET_DIR"
    # Extract via python3 zipfile (no unzip dependency).
    python3 - "$zip" "$(dirname "$XRAY_BIN")" "$XRAY_ASSET_DIR" <<'PY'
import sys, zipfile, os, stat
zpath, bindir, assetdir = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(zpath) as z:
    for n in z.namelist():
        data = z.read(n)
        if n == "xray":
            p = os.path.join(bindir, "xray")
            open(p, "wb").write(data); os.chmod(p, 0o755)
        elif n.endswith(".dat"):
            open(os.path.join(assetdir, os.path.basename(n)), "wb").write(data)
PY
    rm -f "$zip"
    [[ -x "$XRAY_BIN" ]] || { log "ERROR: xray not installed"; return 1; }
    log "xray installed: $($XRAY_BIN version 2>&1 | head -1)"
}

# ---- key / id generation ---------------------------------------------------
# Emits shell-evalable lines: PRIVATE=, PUBLIC=, UUID=, SHORTID=
keygen() {
    ensure_bin
    if [[ "$XRAY_DRY_RUN" == "1" ]]; then
        echo "PRIVATE=DRYRUNPRIV"; echo "PUBLIC=DRYRUNPUB"
        echo "UUID=00000000-0000-0000-0000-000000000000"; echo "SHORTID=0123456789abcdef"
        return 0
    fi
    local kp priv pub uuid sid
    kp="$($XRAY_BIN x25519)"
    # Output format varies by version: "Private key: X" / "Public key: Y"
    # (older) or "PrivateKey: X" / "Password: Y" (newer). Match both.
    priv="$(printf '%s\n' "$kp" | grep -iE 'private' | head -1 | sed -E 's/.*: *//')"
    pub="$(printf '%s\n'  "$kp" | grep -iE 'public|password' | head -1 | sed -E 's/.*: *//')"
    uuid="$($XRAY_BIN uuid)"
    sid="$(openssl rand -hex 8)"
    [[ -n "$priv" && -n "$pub" && -n "$uuid" ]] || { log "ERROR: keygen failed"; return 1; }
    echo "PRIVATE=$priv"; echo "PUBLIC=$pub"; echo "UUID=$uuid"; echo "SHORTID=$sid"
}

# ---- provision-time dest reachability probe --------------------------------
# A good REALITY dest must speak TLS1.3 + HTTP/2. Returns 0 if both seen.
test_dest() {
    local host="$1" port="${2:-443}"
    [[ -n "$host" ]] || { log "ERROR: test-dest needs <host>"; return 2; }
    local out
    out="$(echo | timeout 12 openssl s_client -connect "${host}:${port}" -servername "$host" \
            -tls1_3 -alpn h2 2>/dev/null)" || { log "dest $host: TLS1.3 handshake failed"; return 1; }
    if printf '%s' "$out" | grep -q "TLSv1.3" && printf '%s' "$out" | grep -qi "ALPN protocol: h2"; then
        log "dest $host:$port OK (TLS1.3 + h2)"; return 0
    fi
    log "dest $host:$port lacks TLS1.3+h2 (unsuitable REALITY target)"; return 1
}

# ---- apply a rendered config.json + (re)start the unit ---------------------
do_apply() {
    local src="$1" listen="${2:-443}"
    [[ -s "$src" ]] || { log "ERROR: apply needs a non-empty <config.json>"; return 1; }
    ensure_bin
    mkdir -p "$XRAY_DIR"; chmod 755 "$XRAY_DIR"
    # Validate before swapping in (fail-fast, like the deploy step the research asks for).
    if [[ "$XRAY_DRY_RUN" != "1" ]]; then
        if ! "$XRAY_BIN" run -test -c "$src" >/tmp/awg-xray-test.log 2>&1; then
            log "ERROR: xray config failed validation:"; tail -n 20 /tmp/awg-xray-test.log >&2 || true; return 1
        fi
    fi
    install -m 600 "$src" "$XRAY_CONF"
    mkdir -p "$UNIT_DIR"
    local unit="$UNIT_DIR/$UNIT_NAME"
    cat > "$unit" <<EOF
[Unit]
Description=AmneziaWG VLESS+REALITY entry/exit (Xray-core)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=XRAY_LOCATION_ASSET=$XRAY_ASSET_DIR
ExecStart=$XRAY_BIN run -c $XRAY_CONF
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$unit"
    _skip && { log "(skip-apply) wrote $XRAY_CONF + unit"; return 0; }
    command -v ufw >/dev/null 2>&1 && ufw allow "${listen}/tcp" >/dev/null 2>&1 || true
    systemctl daemon-reload
    systemctl enable --now "$UNIT_NAME"
    systemctl restart "$UNIT_NAME"
    sleep 1
    if systemctl is-active --quiet "$UNIT_NAME"; then
        log "xray active on :$listen"
    else
        log "ERROR: xray failed to start"; journalctl -u awg-xray -n 15 --no-pager >&2 || true; return 1
    fi
}

do_status() {
    [[ -x "$XRAY_BIN" ]] && echo "binary: $($XRAY_BIN version 2>&1 | head -1)" || echo "binary: (absent)"
    [[ -s "$XRAY_CONF" ]] && echo "config: $XRAY_CONF ($(wc -c <"$XRAY_CONF") bytes)" || echo "config: (absent)"
    systemctl is-active "$UNIT_NAME" 2>/dev/null || echo "inactive"
}

do_down() {
    systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
    rm -f "$UNIT_DIR/$UNIT_NAME" "$XRAY_CONF"
    systemctl daemon-reload 2>/dev/null || true
    log "xray entry/exit removed."
}

cmd="${1:-}"; shift || true
case "$cmd" in
    ensure-bin) ensure_bin ;;
    keygen)     keygen ;;
    test-dest)  test_dest "$@" ;;
    apply)      do_apply "$@" ;;
    status)     do_status ;;
    down)       do_down ;;
    *) echo "usage: awg-xray.sh {ensure-bin|keygen|test-dest <host> [port]|apply <config.json> [listen]|status|down}" >&2; exit 2 ;;
esac
