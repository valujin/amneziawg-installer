#!/usr/bin/env bats
# Tests for the cascade (multi-hop) registry + per-client exit metadata helpers
# in awg_common.sh: exit registration, #_Exit metadata, slot allocation, and the
# inter-tunnel config transform (Table=off / DNS-stripped).

load test_helper
bats_require_minimum_version 1.5.0

# A server config with three peers (alice/bob/carol), no #_Exit yet.
make_peers_config() {
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
PublicKey = BBBB
AllowedIPs = 172.16.17.3/32

[Peer]
#_Name = carol
PublicKey = CCCC
AllowedIPs = 172.16.17.4/32
CONF
}

# A client config as produced on an exit server (the inter-tunnel source).
make_exit_client_conf() {
    cat > "$TEST_DIR/de_client.conf" <<'CONF'
[Interface]
PrivateKey = EXITPRIV
Address = 172.16.61.4/32
DNS = 1.1.1.1
MTU = 1280
Jc = 4

[Peer]
PublicKey = EXITPUB
Endpoint = 203.0.113.7:39743
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 33
CONF
}

@test "_cascade_valid_cc: accepts de/nl/us2, rejects junk" {
    run _cascade_valid_cc de; [ "$status" -eq 0 ]
    run _cascade_valid_cc nl; [ "$status" -eq 0 ]
    run _cascade_valid_cc us2; [ "$status" -eq 0 ]
    run _cascade_valid_cc "DE"; [ "$status" -ne 0 ]
    run _cascade_valid_cc "a"; [ "$status" -ne 0 ]
    run _cascade_valid_cc "x/y"; [ "$status" -ne 0 ]
}

@test "_extract_endpoint_host: IPv4, bracketed IPv6, hostname" {
    run _extract_endpoint_host "Endpoint = 203.0.113.7:39743"
    [ "$output" = "203.0.113.7" ]
    run _extract_endpoint_host "Endpoint = [2001:db8::7]:51820"
    [ "$output" = "2001:db8::7" ]
    run _extract_endpoint_host "Endpoint = vpn.example.com:443"
    [ "$output" = "vpn.example.com" ]
}

@test "get_client_exit: absent metadata returns direct" {
    make_peers_config
    run get_client_exit alice
    [ "$output" = "direct" ]
}

@test "_install_inter_conf: adds Table=off and strips DNS, keeps [Peer]" {
    make_exit_client_conf
    run _install_inter_conf de "$TEST_DIR/de_client.conf"
    [ "$status" -eq 0 ]
    local dst="$AWG_CONF_DIR/awg-de.conf"
    [ -f "$dst" ]
    grep -qx "Table = off" "$dst"
    ! grep -qE "^[[:space:]]*DNS[[:space:]]*=" "$dst"
    grep -qxF "[Peer]" "$dst"
    grep -q "Endpoint = 203.0.113.7:39743" "$dst"
}

@test "cascade_add_exit: registers exit, allocates slot, writes registry" {
    make_exit_client_conf
    run cascade_add_exit de "$TEST_DIR/de_client.conf"
    [ "$status" -eq 0 ]
    local reg="$EXITS_DIR/de.conf"
    [ -f "$reg" ]
    grep -qx "EXIT_CC=de" "$reg"
    grep -qx "EXIT_IFACE=awg-de" "$reg"
    grep -qx "EXIT_ENDPOINT=203.0.113.7" "$reg"
    grep -qx "EXIT_FWMARK=0x1" "$reg"
    grep -qx "EXIT_TABLE=101" "$reg"
    grep -qx "EXIT_TRANSPORT=amneziawg" "$reg"
}

@test "cascade_add_exit: second exit gets the next free slot" {
    make_exit_client_conf
    cascade_add_exit de "$TEST_DIR/de_client.conf"
    run cascade_add_exit nl "$TEST_DIR/de_client.conf"
    [ "$status" -eq 0 ]
    grep -qx "EXIT_FWMARK=0x2" "$EXITS_DIR/nl.conf"
    grep -qx "EXIT_TABLE=102" "$EXITS_DIR/nl.conf"
}

@test "cascade_add_exit: refuses duplicate registration" {
    make_exit_client_conf
    cascade_add_exit de "$TEST_DIR/de_client.conf"
    run cascade_add_exit de "$TEST_DIR/de_client.conf"
    [ "$status" -ne 0 ]
}

@test "cascade_add_exit: tailscale transport requires a ts-ip" {
    run cascade_add_exit sg "" tailscale
    [ "$status" -ne 0 ]
    run cascade_add_exit sg "" tailscale 100.64.0.9
    [ "$status" -eq 0 ]
    grep -qx "EXIT_TRANSPORT=tailscale" "$EXITS_DIR/sg.conf"
    grep -qx "EXIT_TS_IP=100.64.0.9" "$EXITS_DIR/sg.conf"
    grep -qx "EXIT_IFACE=tailscale0" "$EXITS_DIR/sg.conf"
}

@test "cascade_list_exits: lists registered exits" {
    make_exit_client_conf
    cascade_add_exit de "$TEST_DIR/de_client.conf"
    run cascade_list_exits
    [[ "$output" == *"de"* ]]
    [[ "$output" == *"amneziawg"* ]]
    [[ "$output" == *"203.0.113.7"* ]]
}

@test "set_client_exit/get_client_exit: round-trip and direct reset" {
    require_flock
    make_peers_config
    make_exit_client_conf
    cascade_add_exit de "$TEST_DIR/de_client.conf"

    run set_client_exit alice de
    [ "$status" -eq 0 ]
    run get_client_exit alice
    [ "$output" = "de" ]
    run get_client_exit bob
    [ "$output" = "direct" ]

    # changing it must not duplicate the #_Exit line
    set_client_exit alice direct
    run get_client_exit alice
    [ "$output" = "direct" ]
    run grep -c "#_Exit" "$SERVER_CONF_FILE"
    [ "$output" -eq 1 ]
}

@test "set_client_exit: rejects unregistered exit" {
    require_flock
    make_peers_config
    run set_client_exit alice zz
    [ "$status" -ne 0 ]
}

@test "cascade_clients_using_exit + remove: refuse bound, --force repoints" {
    require_flock
    make_peers_config
    make_exit_client_conf
    cascade_add_exit de "$TEST_DIR/de_client.conf"
    set_client_exit alice de
    set_client_exit carol de

    run cascade_clients_using_exit de
    [[ "$output" == *"alice"* ]]
    [[ "$output" == *"carol"* ]]

    run cascade_remove_exit de
    [ "$status" -ne 0 ]            # refuses while clients are bound
    [ -f "$EXITS_DIR/de.conf" ]

    run cascade_remove_exit de --force
    [ "$status" -eq 0 ]
    [ ! -f "$EXITS_DIR/de.conf" ]
    run get_client_exit alice
    [ "$output" = "direct" ]
}
