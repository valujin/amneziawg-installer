#!/bin/bash
# awg-routing.sh — cascade split-routing for the entry (AWG0 / RU) server.
#
# Russian-destined traffic from VPN clients breaks out locally (direct via WAN);
# all other traffic is policy-routed into a per-exit tunnel (AmneziaWG or
# Tailscale) on a foreign exit server, chosen per client. RU IPs never leave RU.
#
# Data-driven and idempotent — safe to re-run (also refreshes the RU ipset):
#   * exits are read from $EXITS_DIR/*.conf (one file per exit),
#   * per-client exit assignment is read from the #_Exit metadata in awg0.conf,
#   * the RU network set is loaded into ipset "ru" via atomic swap.
#
# Based on the proven recipe by @glfenix, validated/published by @bivlked as
# CASCADE.md (discussion #120), generalized here to N exits with per-client
# exit selection, an IPv4/IPv6 carrier, and a Tailscale transport option.
#
# Usage:
#   awg-routing.sh [apply]     # (re)build ipset + routing + marks   (default)
#   awg-routing.sh flush       # tear everything down
#   awg-routing.sh --dry-run [apply]   # print commands, change nothing
#
# Environment overrides (mainly for tests):
#   AWG_DIR, EXITS_DIR, SERVER_CONF_FILE, RU_ZONE, RU_ZONE_SNAPSHOT,
#   RU_IPSET_URL, CONFIG_FILE, RULE_PRIO, WAN_IF, WAN_GW, RU_SKIP_DOWNLOAD
set -euo pipefail

AWG_DIR="${AWG_DIR:-/root/awg}"
EXITS_DIR="${EXITS_DIR:-$AWG_DIR/exits}"
SERVER_CONF="${SERVER_CONF_FILE:-/etc/amnezia/amneziawg/awg0.conf}"
CONFIG_FILE="${CONFIG_FILE:-$AWG_DIR/awgsetup_cfg.init}"
RU_ZONE="${RU_ZONE:-$AWG_DIR/ru.zone}"
RU_ZONE_SNAPSHOT="${RU_ZONE_SNAPSHOT:-$AWG_DIR/ru.zone.snapshot}"
RU_IPSET_URL="${RU_IPSET_URL:-https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone}"
RULE_PRIO="${RULE_PRIO:-10000}"
RU_SET="ru"

DRY_RUN=0
ACTION="apply"
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        apply|flush) ACTION="$arg" ;;
        *) echo "awg-routing: unknown argument '$arg'" >&2; exit 2 ;;
    esac
done

log() { echo "awg-routing: $*" >&2; }

# run CMD... — execute, or in dry-run print to stdout (one command per line).
run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%s\n' "$*"
    else
        "$@"
    fi
}

# Read a single KEY=value (or 'export KEY=value', quoted or not) from a file.
read_kv() {
    local file="$1" key="$2" line val
    [[ -f "$file" ]] || return 1
    line=$(grep -E "^(export[[:space:]]+)?${key}=" "$file" | tail -n1) || return 1
    [[ -n "$line" ]] || return 1
    val="${line#*=}"
    val="${val%$'\r'}"
    # strip surrounding single or double quotes
    if [[ "$val" == \'*\' ]]; then val="${val#\'}"; val="${val%\'}";
    elif [[ "$val" == \"*\" ]]; then val="${val#\"}"; val="${val%\"}"; fi
    printf '%s' "$val"
}

# ---- global cascade settings (from awgsetup_cfg.init) ----------------------
DEFAULT_EXIT="$(read_kv "$CONFIG_FILE" DEFAULT_EXIT || true)"
GEO_SPLIT_ENABLED="$(read_kv "$CONFIG_FILE" GEO_SPLIT_ENABLED || true)"
GEO_SPLIT_ENABLED="${GEO_SPLIT_ENABLED:-1}"
_url="$(read_kv "$CONFIG_FILE" RU_IPSET_URL || true)"
[[ -n "$_url" ]] && RU_IPSET_URL="$_url"

# ---- client subnet (Address in awg0.conf [Interface]) ----------------------
client_subnet() {
    local addr
    addr=$(awk -F'=' '/^\[/{s=($0 ~ /^\[Interface\]/)} s && /^[[:space:]]*Address[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SERVER_CONF" 2>/dev/null)
    [[ -n "$addr" ]] || return 1
    # 172.16.17.1/24 -> 172.16.17.0/24 (zero the host part for a /24-style net)
    local ip="${addr%/*}" mask="${addr#*/}" a b c
    IFS='.' read -r a b c _ <<<"$ip"
    printf '%s.%s.%s.0/%s' "$a" "$b" "$c" "${mask:-24}"
}

# ---- exit registry ---------------------------------------------------------
# Populates parallel maps keyed by country code.
declare -A EX_IFACE EX_ENDPOINT EX_FWMARK EX_TABLE EX_TRANSPORT EX_TSIP
EXIT_CCS=()
load_exits() {
    local f cc
    [[ -d "$EXITS_DIR" ]] || return 0
    shopt -s nullglob
    for f in "$EXITS_DIR"/*.conf; do
        cc="$(read_kv "$f" EXIT_CC || true)"
        [[ -n "$cc" ]] || cc="$(basename "$f" .conf)"
        EX_IFACE[$cc]="$(read_kv "$f" EXIT_IFACE || true)"
        EX_ENDPOINT[$cc]="$(read_kv "$f" EXIT_ENDPOINT || true)"
        EX_FWMARK[$cc]="$(read_kv "$f" EXIT_FWMARK || true)"
        EX_TABLE[$cc]="$(read_kv "$f" EXIT_TABLE || true)"
        EX_TRANSPORT[$cc]="$(read_kv "$f" EXIT_TRANSPORT || echo amneziawg)"
        EX_TSIP[$cc]="$(read_kv "$f" EXIT_TS_IP || true)"
        EXIT_CCS+=("$cc")
    done
    shopt -u nullglob
}

# ip / ip -6 selector based on an address literal
ip_fam() { case "$1" in *:*) echo "ip -6" ;; *) echo "ip -4" ;; esac; }

# ---- RU ipset --------------------------------------------------------------
refresh_ru_zone() {
    mkdir -p "$AWG_DIR"
    if [[ "${RU_SKIP_DOWNLOAD:-0}" != "1" && "$DRY_RUN" -eq 0 ]]; then
        if curl -fsS --retry 2 --max-time 60 -o "$RU_ZONE.tmp" "$RU_IPSET_URL" && [[ -s "$RU_ZONE.tmp" ]]; then
            mv -f "$RU_ZONE.tmp" "$RU_ZONE"
        else
            rm -f "$RU_ZONE.tmp"
            log "WARN: could not download RU zone, keeping previous list"
        fi
    fi
    # Fall back to a shipped snapshot so a clean machine never ends up with an
    # empty set (empty set => RETURN matches nothing => ALL traffic leaks abroad).
    if [[ ! -s "$RU_ZONE" && -s "$RU_ZONE_SNAPSHOT" ]]; then
        log "WARN: no live RU zone, using bundled snapshot"
        cp -f "$RU_ZONE_SNAPSHOT" "$RU_ZONE"
    fi
    [[ -s "$RU_ZONE" ]] || { log "ERROR: RU network list is empty and no snapshot — aborting to avoid leaking all traffic abroad"; return 1; }
}

load_ru_ipset() {
    run ipset create "$RU_SET" hash:net -exist
    run ipset create "${RU_SET}_tmp" hash:net -exist
    run ipset flush "${RU_SET}_tmp"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'ipset restore < %s (into %s_tmp)\n' "$RU_ZONE" "$RU_SET"
    else
        local net
        while read -r net; do
            [[ -n "$net" && "$net" != \#* ]] && ipset add "${RU_SET}_tmp" "$net" -exist
        done < "$RU_ZONE"
    fi
    run ipset swap "${RU_SET}_tmp" "$RU_SET"
    run ipset destroy "${RU_SET}_tmp"
}

# ---- per-exit routing (table + rule + loop-guard) --------------------------
setup_exit_routing() {
    local cc="$1"
    local iface="${EX_IFACE[$cc]}" fwmark="${EX_FWMARK[$cc]}" table="${EX_TABLE[$cc]}"
    local transport="${EX_TRANSPORT[$cc]}" endpoint="${EX_ENDPOINT[$cc]}" tsip="${EX_TSIP[$cc]}"
    [[ -n "$fwmark" && -n "$table" ]] || { log "WARN: exit '$cc' missing fwmark/table — skipping"; return 0; }

    # Boot-race tolerance: if the exit interface isn't up yet, skip it this run
    # (a later run — e.g. after awg-quick@awg-<cc> starts — applies it). Never
    # guard in dry-run, so tests still exercise full command emission.
    local _gif="${iface:-tailscale0}"
    if [[ "$DRY_RUN" -eq 0 ]] && ! ip link show "$_gif" &>/dev/null; then
        log "exit '$cc': interface $_gif not up yet — skipping (applied on next run)"; return 0
    fi

    # Default route for this exit's table.
    if [[ "$transport" == "tailscale" ]]; then
        [[ -n "$tsip" ]] || { log "WARN: tailscale exit '$cc' missing EXIT_TS_IP — skipping"; return 0; }
        run ip route replace default via "$tsip" dev "${iface:-tailscale0}" table "$table"
    else
        [[ -n "$iface" ]] || { log "WARN: exit '$cc' missing iface — skipping"; return 0; }
        run ip route replace default dev "$iface" table "$table"
    fi

    # fwmark -> table rule (delete-then-add for idempotency).
    run ip rule del fwmark "$fwmark" table "$table" 2>/dev/null || true
    run ip rule add fwmark "$fwmark" table "$table" priority "$RULE_PRIO"

    # Loop-guard: keep the route to the exit's own endpoint OUT of the tunnel,
    # otherwise the encrypted carrier packets get routed back into the tunnel.
    # (AmneziaWG carrier only; Tailscale manages its own underlay.)
    if [[ "$transport" != "tailscale" && -n "$endpoint" ]]; then
        local ipc wif wgw
        ipc="$(ip_fam "$endpoint")"
        wif="${WAN_IF:-}"; wgw="${WAN_GW:-}"
        if [[ -z "$wif" && "$DRY_RUN" -eq 0 ]]; then
            local r; r="$($ipc route get "$endpoint" 2>/dev/null | head -1 || true)"
            wif="$(printf '%s' "$r" | grep -oE 'dev [^ ]+' | awk '{print $2}')"
            wgw="$(printf '%s' "$r" | grep -oE 'via [^ ]+' | awk '{print $2}')"
        fi
        if [[ -n "$wif" && "$wif" != "$iface" ]]; then
            if [[ -n "$wgw" ]]; then
                run $ipc route replace "$endpoint" via "$wgw" dev "$wif"
            else
                run $ipc route replace "$endpoint" dev "$wif"
            fi
        else
            log "WARN: could not determine WAN toward exit '$cc' ($endpoint) — loop-guard skipped"
        fi
    fi
}

# ---- marking (mangle) ------------------------------------------------------
# Dedicated chain rebuilt each run; jump from PREROUTING installed once.
setup_marks() {
    local subnet="$1"
    run iptables -t mangle -N AWG_CASCADE 2>/dev/null || true
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'iptables -t mangle -C PREROUTING -i awg0 -j AWG_CASCADE || iptables -t mangle -A PREROUTING -i awg0 -j AWG_CASCADE\n'
    else
        iptables -t mangle -C PREROUTING -i awg0 -j AWG_CASCADE 2>/dev/null \
            || iptables -t mangle -A PREROUTING -i awg0 -j AWG_CASCADE
    fi
    run iptables -t mangle -F AWG_CASCADE

    # Russian destinations break out locally (must be first).
    if [[ "$GEO_SPLIT_ENABLED" == "1" ]]; then
        run iptables -t mangle -A AWG_CASCADE -s "$subnet" -m set --match-set "$RU_SET" dst -j RETURN
    fi

    # Per-client mark by resolved exit (explicit #_Exit, else DEFAULT_EXIT).
    local ip exit_cc fwmark
    while read -r ip exit_cc; do
        [[ -n "$ip" ]] || continue
        [[ "$exit_cc" == "DEFAULT" ]] && exit_cc="$DEFAULT_EXIT"
        [[ -z "$exit_cc" || "$exit_cc" == "direct" ]] && continue
        fwmark="${EX_FWMARK[$exit_cc]:-}"
        [[ -n "$fwmark" ]] || { log "WARN: client $ip -> exit '$exit_cc' not registered — left direct"; continue; }
        run iptables -t mangle -A AWG_CASCADE -s "${ip}/32" -j MARK --set-mark "$fwmark"
    done < <(parse_client_exits)
}

# Emit "<client_ip> <exit_cc|DEFAULT>" per peer in awg0.conf.
parse_client_exits() {
    [[ -f "$SERVER_CONF" ]] || return 0
    awk '
        /^\[Peer\]/      { ip=""; ex="DEFAULT" }
        /^#_Exit[[:space:]]*=/   { v=$0; sub(/^#_Exit[[:space:]]*=[[:space:]]*/,"",v); ex=v }
        /^AllowedIPs[[:space:]]*=/ {
            v=$0; sub(/^AllowedIPs[[:space:]]*=[[:space:]]*/,"",v);
            sub(/\/.*/,"",v); gsub(/[[:space:]]/,"",v); ip=v;
            if (ip != "") print ip, ex
        }
    ' "$SERVER_CONF"
}

# ---- NAT for exit-bound client traffic -------------------------------------
setup_nat() {
    local subnet="$1" cc iface transport
    for cc in "${EXIT_CCS[@]}"; do
        transport="${EX_TRANSPORT[$cc]}"
        iface="${EX_IFACE[$cc]}"
        # Tailscale exits SNAT on their side; AmneziaWG exits need entry-side NAT.
        [[ "$transport" == "tailscale" ]] && continue
        [[ -n "$iface" ]] || continue
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf 'iptables -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE || iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE\n' "$subnet" "$iface" "$subnet" "$iface"
        else
            iptables -t nat -C POSTROUTING -s "$subnet" -o "$iface" -j MASQUERADE 2>/dev/null \
                || iptables -t nat -A POSTROUTING -s "$subnet" -o "$iface" -j MASQUERADE
        fi
    done
}

do_apply() {
    local subnet
    subnet="$(client_subnet)" || { log "ERROR: cannot determine client subnet from $SERVER_CONF"; exit 1; }
    load_exits
    refresh_ru_zone || exit 1
    load_ru_ipset
    local cc
    for cc in "${EXIT_CCS[@]}"; do setup_exit_routing "$cc"; done
    setup_nat "$subnet"
    setup_marks "$subnet"
    log "OK: cascade routing applied (exits: ${EXIT_CCS[*]:-none}, geo-split=$GEO_SPLIT_ENABLED)"
}

do_flush() {
    load_exits
    run iptables -t mangle -F AWG_CASCADE 2>/dev/null || true
    run iptables -t mangle -D PREROUTING -i awg0 -j AWG_CASCADE 2>/dev/null || true
    run iptables -t mangle -X AWG_CASCADE 2>/dev/null || true
    local cc
    for cc in "${EXIT_CCS[@]}"; do
        [[ -n "${EX_FWMARK[$cc]:-}" && -n "${EX_TABLE[$cc]:-}" ]] || continue
        run ip rule del fwmark "${EX_FWMARK[$cc]}" table "${EX_TABLE[$cc]}" 2>/dev/null || true
        run ip route flush table "${EX_TABLE[$cc]}" 2>/dev/null || true
    done
    log "OK: cascade routing flushed"
}

case "$ACTION" in
    apply) do_apply ;;
    flush) do_flush ;;
esac
