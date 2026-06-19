#!/usr/bin/env bats
# Tests for awg-routing.sh — the cascade split-routing generator (entry server).
# Runs the script in --dry-run mode so it prints the ip/ipset/iptables commands
# it would execute, without touching the system (works on any platform / no root).
#
# Covers: RU ipset atomic swap + snapshot fallback, per-exit table/rule/loop-guard,
# RETURN-before-MARK ordering, per-client mark resolution (#_Exit / DEFAULT / direct),
# IPv6 carrier loop-guard, and the Tailscale transport variant.

bats_require_minimum_version 1.5.0

# Pick a bash >= 4 (awg-routing.sh uses associative arrays). macOS /bin/bash is 3.2.
_pick_bash() {
    local b
    for b in /opt/homebrew/bin/bash /usr/local/bin/bash "$(command -v bash)"; do
        [[ -x "$b" ]] || continue
        if "$b" -c '((BASH_VERSINFO[0] >= 4))' 2>/dev/null; then echo "$b"; return 0; fi
    done
    echo bash
}

setup() {
    BASH_BIN="$(_pick_bash)"
    SCRIPT="$BATS_TEST_DIRNAME/../awg-routing.sh"
    TEST_DIR="$(mktemp -d)"
    export AWG_DIR="$TEST_DIR"
    export EXITS_DIR="$TEST_DIR/exits"
    export SERVER_CONF_FILE="$TEST_DIR/awg0.conf"
    export CONFIG_FILE="$TEST_DIR/awgsetup_cfg.init"
    export RU_ZONE="$TEST_DIR/ru.zone"
    export RU_ZONE_SNAPSHOT="$TEST_DIR/ru.zone.snapshot"
    export RU_SKIP_DOWNLOAD=1
    export WAN_IF="eth0"
    export WAN_GW="192.0.2.1"
    mkdir -p "$EXITS_DIR"

    printf '5.8.0.0/13\n77.88.0.0/18\n' > "$RU_ZONE"

    cat > "$CONFIG_FILE" <<'CONF'
export AWG_TUNNEL_SUBNET='172.16.17.1/24'
export DEFAULT_EXIT='de'
export GEO_SPLIT_ENABLED=1
CONF

    cat > "$SERVER_CONF_FILE" <<'CONF'
[Interface]
PrivateKey = K
Address = 172.16.17.1/24
ListenPort = 39743

[Peer]
#_Name = alice
PublicKey = AAAA
AllowedIPs = 172.16.17.2/32

[Peer]
#_Name = bob
#_Exit = direct
PublicKey = BBBB
AllowedIPs = 172.16.17.3/32

[Peer]
#_Name = carol
#_Exit = de
PublicKey = CCCC
AllowedIPs = 172.16.17.4/32
CONF
}

teardown() { rm -rf "$TEST_DIR"; }

mk_exit_de() {
    cat > "$EXITS_DIR/de.conf" <<'CONF'
EXIT_CC=de
EXIT_IFACE=awg-de
EXIT_ENDPOINT=203.0.113.7
EXIT_FWMARK=0x1
EXIT_TABLE=101
EXIT_TRANSPORT=amneziawg
CONF
}

run_apply() { run "$BASH_BIN" "$SCRIPT" --dry-run apply; }

@test "applies cleanly and reports the registered exit" {
    mk_exit_de
    run_apply
    [ "$status" -eq 0 ]
}

@test "ipset is loaded via an atomic temp-set swap" {
    mk_exit_de
    run_apply
    [[ "$output" == *"ipset create ru hash:net -exist"* ]]
    [[ "$output" == *"ipset swap ru_tmp ru"* ]]
    [[ "$output" == *"ipset destroy ru_tmp"* ]]
}

@test "per-exit default route and fwmark rule use the registry values" {
    mk_exit_de
    run_apply
    [[ "$output" == *"ip route replace default dev awg-de table 101"* ]]
    [[ "$output" == *"ip rule add fwmark 0x1 table 101 priority 10000"* ]]
}

@test "loop-guard pins the exit endpoint out the WAN (IPv4)" {
    mk_exit_de
    run_apply
    [[ "$output" == *"ip -4 route replace 203.0.113.7 via 192.0.2.1 dev eth0"* ]]
}

@test "RU RETURN rule precedes the client MARK rules" {
    mk_exit_de
    run_apply
    local ret_line mark_line
    ret_line=$(printf '%s\n' "$output" | grep -n 'match-set ru dst -j RETURN' | head -1 | cut -d: -f1)
    mark_line=$(printf '%s\n' "$output" | grep -n 'MARK --set-mark 0x1' | head -1 | cut -d: -f1)
    [ -n "$ret_line" ] && [ -n "$mark_line" ]
    [ "$ret_line" -lt "$mark_line" ]
}

@test "client with explicit #_Exit=de is marked" {
    mk_exit_de
    run_apply
    [[ "$output" == *"-A AWG_CASCADE -s 172.16.17.4/32 -j MARK --set-mark 0x1"* ]]
}

@test "client without #_Exit inherits DEFAULT_EXIT and is marked" {
    mk_exit_de
    run_apply
    [[ "$output" == *"-A AWG_CASCADE -s 172.16.17.2/32 -j MARK --set-mark 0x1"* ]]
}

@test "client with #_Exit=direct is NOT marked" {
    mk_exit_de
    run_apply
    [[ "$output" != *"172.16.17.3/32"* ]]
}

@test "NAT masquerades the client subnet out the exit interface" {
    mk_exit_de
    run_apply
    [[ "$output" == *"-s 172.16.17.0/24 -o awg-de -j MASQUERADE"* ]]
}

@test "geo-split off: no RU RETURN rule emitted" {
    mk_exit_de
    sed 's/GEO_SPLIT_ENABLED=1/GEO_SPLIT_ENABLED=0/' "$CONFIG_FILE" > "$CONFIG_FILE.x" && mv "$CONFIG_FILE.x" "$CONFIG_FILE"
    run_apply
    [[ "$output" != *"match-set ru dst -j RETURN"* ]]
    [[ "$output" == *"MARK --set-mark 0x1"* ]]
}

@test "empty RU list with no snapshot aborts (no leak)" {
    mk_exit_de
    : > "$RU_ZONE"
    run_apply
    [ "$status" -ne 0 ]
    [[ "$output" == *"aborting to avoid leaking"* ]]
}

@test "falls back to bundled snapshot when live zone missing" {
    mk_exit_de
    rm -f "$RU_ZONE"
    printf '5.8.0.0/13\n' > "$RU_ZONE_SNAPSHOT"
    run_apply
    [ "$status" -eq 0 ]
    [[ "$output" == *"using bundled snapshot"* ]]
}

@test "IPv6 carrier endpoint uses ip -6 loop-guard" {
    cat > "$EXITS_DIR/nl.conf" <<'CONF'
EXIT_CC=nl
EXIT_IFACE=awg-nl
EXIT_ENDPOINT=2001:db8::7
EXIT_FWMARK=0x2
EXIT_TABLE=102
EXIT_TRANSPORT=amneziawg
CONF
    export WAN_IF="eth0"; export WAN_GW=""
    run_apply
    [[ "$output" == *"ip -6 route replace 2001:db8::7 dev eth0"* ]]
}

@test "tailscale transport routes via the tailscale IP and skips entry NAT" {
    cat > "$EXITS_DIR/sg.conf" <<'CONF'
EXIT_CC=sg
EXIT_IFACE=tailscale0
EXIT_TS_IP=100.64.0.9
EXIT_FWMARK=0x3
EXIT_TABLE=103
EXIT_TRANSPORT=tailscale
CONF
    # reassign carol to sg so a mark is produced for this exit
    sed 's/#_Exit = de/#_Exit = sg/' "$SERVER_CONF_FILE" > "$SERVER_CONF_FILE.x" && mv "$SERVER_CONF_FILE.x" "$SERVER_CONF_FILE"
    sed "s/DEFAULT_EXIT='de'/DEFAULT_EXIT='sg'/" "$CONFIG_FILE" > "$CONFIG_FILE.x" && mv "$CONFIG_FILE.x" "$CONFIG_FILE"
    run_apply
    [[ "$output" == *"ip route replace default via 100.64.0.9 dev tailscale0 table 103"* ]]
    [[ "$output" != *"-o tailscale0 -j MASQUERADE"* ]]
}
