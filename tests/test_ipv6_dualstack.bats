#!/usr/bin/env bats
# Tests for dual-stack IPv6 inside the tunnel (default-on, ::/0 anti-leak).
#
# Client gets an IPv6 inner address; full-tunnel clients route ::/0 ALWAYS
# (even without native server IPv6) so IPv6 never leaks past the VPN. Custom
# split-tunnels get the tunnel ULA only (never ::/0). Controlled by
# ALLOW_IPV6_TUNNEL (default 1) + IPV6_SUBNET.

load test_helper
bats_require_minimum_version 1.5.0

setup() {
    TEST_DIR=$(mktemp -d)
    export AWG_DIR="$TEST_DIR"
    export KEYS_DIR="$TEST_DIR/keys"
    export SERVER_CONF_FILE="$TEST_DIR/awg0.conf"
    export AWG_TUNNEL_SUBNET="172.16.17.1/24"
    export IPV6_SUBNET="fddd:2c4:2c4:2c4::/64"
    mkdir -p "$KEYS_DIR"
    echo "SERVERPRIVKEY" > "$AWG_DIR/server_private.key"
    log() { :; }; log_warn() { :; }; log_error() { :; }; log_debug() { :; }
    export -f log log_warn log_error log_debug
    source "$BATS_TEST_DIRNAME/../awg_common.sh"
    # Stub the heavy deps so render_* can run in isolation.
    load_awg_params() {
        AWG_Jc=5 AWG_Jmin=50 AWG_Jmax=1000 AWG_S1=10 AWG_S2=20 AWG_S3=30 AWG_S4=40
        AWG_H1=1 AWG_H2=2 AWG_H3=3 AWG_H4=4 AWG_I1="" AWG_PORT=51820
        export AWG_Jc AWG_Jmin AWG_Jmax AWG_S1 AWG_S2 AWG_S3 AWG_S4 AWG_H1 AWG_H2 AWG_H3 AWG_H4 AWG_I1 AWG_PORT
        return 0
    }
    get_main_nic() { echo "eth0"; }
    _extract_mtu_from_server_conf() { return 1; }
    export -f load_awg_params get_main_nic _extract_mtu_from_server_conf
}

teardown() { rm -rf "$TEST_DIR"; }

# --------------------------- helpers ---------------------------
@test "_derive_ipv6_server_addr: PREFIX::/MASK -> PREFIX::1/MASK" {
    run _derive_ipv6_server_addr "fddd:2c4:2c4:2c4::/64"
    [ "$output" = "fddd:2c4:2c4:2c4::1/64" ]
}

@test "get_next_client_ipv6: mirrors the IPv4 last octet" {
    run get_next_client_ipv6 "172.16.17.5"
    [ "$output" = "fddd:2c4:2c4:2c4::5" ]
    run get_next_client_ipv6 "10.9.9.250"
    [ "$output" = "fddd:2c4:2c4:2c4::250" ]
}

@test "_ipv6_tunnel_on: default is ON (unset == 1)" {
    unset ALLOW_IPV6_TUNNEL
    _ipv6_tunnel_on
    ALLOW_IPV6_TUNNEL=0
    ! _ipv6_tunnel_on
}

# --------------------------- server config ---------------------------
@test "render_server_config: dual-stack Address (::1) + ip6tables when tunnel on" {
    ALLOW_IPV6_TUNNEL=1 render_server_config
    grep -qE '^Address = 172\.16\.17\.1/24, fddd:2c4:2c4:2c4::1/64$' "$SERVER_CONF_FILE"
    grep -q 'ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE' "$SERVER_CONF_FILE"
}

@test "render_server_config: IPv4-only Address when tunnel off" {
    ALLOW_IPV6_TUNNEL=0 DISABLE_IPV6=1 render_server_config
    grep -qE '^Address = 172\.16\.17\.1/24$' "$SERVER_CONF_FILE"
    ! grep -q 'ip6tables' "$SERVER_CONF_FILE"
}

# --------------------------- client config ---------------------------
@test "render_client_config: dual-stack Address + ::/0 on full tunnel (anti-leak)" {
    export ALLOWED_IPS="0.0.0.0/0, ::/0"
    render_client_config cli 172.16.17.5 CPRIV SPUB 198.51.100.1 51820 "fddd:2c4:2c4:2c4::5"
    grep -qE '^Address = 172\.16\.17\.5/32, fddd:2c4:2c4:2c4::5/128$' "$AWG_DIR/cli.conf"
    grep -qE '^AllowedIPs = 0\.0\.0\.0/0, ::/0$' "$AWG_DIR/cli.conf"
}

@test "render_client_config: full IPv4 (0.0.0.0/0, no ::/0) gets ::/0 appended (anti-leak)" {
    export ALLOWED_IPS="0.0.0.0/0"
    render_client_config cli 172.16.17.6 CPRIV SPUB 198.51.100.1 51820 "fddd:2c4:2c4:2c4::6"
    grep -qE '^AllowedIPs = 0\.0\.0\.0/0, ::/0$' "$AWG_DIR/cli.conf"
}

@test "render_client_config: custom split gets tunnel ULA only, never ::/0" {
    export ALLOWED_IPS="10.0.0.0/8, 192.168.0.0/16"
    render_client_config cli 172.16.17.7 CPRIV SPUB 198.51.100.1 51820 "fddd:2c4:2c4:2c4::7"
    grep -qE '^AllowedIPs = 10\.0\.0\.0/8, 192\.168\.0\.0/16, fddd:2c4:2c4:2c4::/64$' "$AWG_DIR/cli.conf"
    ! grep -q '::/0' "$AWG_DIR/cli.conf"
}

@test "render_client_config: IPv4-only when no client_ipv6 (tunnel off)" {
    export ALLOWED_IPS="0.0.0.0/0, ::/0"
    render_client_config cli 172.16.17.8 CPRIV SPUB 198.51.100.1 51820 ""
    grep -qE '^Address = 172\.16\.17\.8/32$' "$AWG_DIR/cli.conf"
}

# --------------------------- server peer ---------------------------
@test "add_peer_to_server: dual-stack peer AllowedIPs when client_ipv6 given" {
    ALLOW_IPV6_TUNNEL=1 render_server_config
    add_peer_to_server alice PUBKEY 172.16.17.5 "fddd:2c4:2c4:2c4::5"
    grep -qE '^AllowedIPs = 172\.16\.17\.5/32, fddd:2c4:2c4:2c4::5/128$' "$SERVER_CONF_FILE"
}

@test "add_peer_to_server: IPv4-only peer when no client_ipv6" {
    ALLOW_IPV6_TUNNEL=1 render_server_config
    add_peer_to_server bob PUBKEY 172.16.17.9
    grep -qE '^AllowedIPs = 172\.16\.17\.9/32$' "$SERVER_CONF_FILE"
}
