#!/usr/bin/env bats
# Tests for _ensure_server_public_key helper (v5.11.1 Phase A).
#
# The helper is a fallback for manual installs where /root/awg is not
# populated by our installer step 6 — it reconstructs server_public.key
# from the [Interface] PrivateKey in awg0.conf so that manage add / regen
# can still run.

load test_helper

setup_with_psk_stub() {
    # test_helper's setup() runs first and sets up TEST_DIR + sourcing.
    # Override `awg pubkey` with a deterministic stub so tests do not
    # depend on the real wireguard-tools being installed. The stub
    # prints a base64-like string derived from the input private key.
    # shellcheck disable=SC2317
    awg() {
        case "$1" in
            pubkey)
                # Read private key from stdin, echo a deterministic "pubkey".
                local _pk
                _pk=$(cat)
                # Prefix with "pub_" so tests can assert derivation.
                echo "pub_${_pk:0:20}"
                ;;
            genpsk)
                echo "psk_$(date +%N)"
                ;;
            *)
                command awg "$@"
                ;;
        esac
    }
    export -f awg
}

write_server_conf_with_privkey() {
    local pk="${1:-TESTSERVER_PRIVKEY_1234567890}"
    cat > "$SERVER_CONF_FILE" <<EOF
[Interface]
PrivateKey = ${pk}
Address = 10.9.9.1/24
ListenPort = 39743
Jc = 4
Jmin = 40
Jmax = 90
S1 = 72
S2 = 56
S3 = 32
S4 = 16
H1 = 100000-200000
H2 = 300000-400000
H3 = 500000-600000
H4 = 700000-800000
EOF
}

@test "_ensure_server_public_key: no-op when cache exists" {
    setup_with_psk_stub
    write_server_conf_with_privkey "OLD_PRIV"
    echo "CACHED_PUBKEY" > "$AWG_DIR/server_public.key"

    run _ensure_server_public_key
    [ "$status" -eq 0 ]
    # Must not overwrite
    [ "$(cat "$AWG_DIR/server_public.key")" = "CACHED_PUBKEY" ]
}

@test "_ensure_server_public_key: reconstructs from awg0.conf when cache missing" {
    setup_with_psk_stub
    write_server_conf_with_privkey "RECONSTRUCT_ME_PRIVKEY_12345"
    rm -f "$AWG_DIR/server_public.key"

    run _ensure_server_public_key
    [ "$status" -eq 0 ]
    [ -f "$AWG_DIR/server_public.key" ]
    # Stub produced pub_ + first 20 chars of private key
    [ "$(cat "$AWG_DIR/server_public.key")" = "pub_RECONSTRUCT_ME_PRIVK" ]
    # Permissions tightened on Unix — skip check on platforms where
    # chmod is a no-op (Windows NTFS via Git Bash, WSL on 9p mount).
    if [[ "$(uname -s)" == "Linux" || "$(uname -s)" == "Darwin" ]]; then
        [ "$(stat -c '%a' "$AWG_DIR/server_public.key")" = "600" ]
    fi
}

@test "_ensure_server_public_key: fails when SERVER_CONF_FILE missing" {
    setup_with_psk_stub
    rm -f "$SERVER_CONF_FILE" "$AWG_DIR/server_public.key"

    run _ensure_server_public_key
    [ "$status" -ne 0 ]
    [ ! -f "$AWG_DIR/server_public.key" ]
}

@test "_ensure_server_public_key: fails when PrivateKey missing from config" {
    setup_with_psk_stub
    cat > "$SERVER_CONF_FILE" <<'EOF'
[Interface]
Address = 10.9.9.1/24
ListenPort = 39743
EOF
    rm -f "$AWG_DIR/server_public.key"

    run _ensure_server_public_key
    [ "$status" -ne 0 ]
    [ ! -f "$AWG_DIR/server_public.key" ]
}

@test "_ensure_server_public_key: handles indented PrivateKey (hand-edited config)" {
    # User-edited configs may indent key/value lines. The awk extractor
    # must tolerate leading whitespace.
    setup_with_psk_stub
    cat > "$SERVER_CONF_FILE" <<'EOF'
[Interface]
    PrivateKey = INDENTED_PRIVKEY_ABCDEFGHI
    Address = 10.9.9.1/24
EOF
    rm -f "$AWG_DIR/server_public.key"

    run _ensure_server_public_key
    [ "$status" -eq 0 ]
    # Stub returns "pub_${_pk:0:20}" — first 20 chars of "INDENTED_PRIVKEY_ABCDEFGHI"
    # = "INDENTED_PRIVKEY_ABC" (stops before the D).
    [ "$(cat "$AWG_DIR/server_public.key")" = "pub_INDENTED_PRIVKEY_ABC" ]
}

@test "_ensure_server_public_key: ignores PrivateKey in [Peer] sections" {
    # Only PrivateKey in [Interface] should be used. A rogue [Peer]
    # PrivateKey (which would never exist in a real awg0.conf) must
    # not confuse the awk extractor.
    setup_with_psk_stub
    cat > "$SERVER_CONF_FILE" <<'EOF'
[Interface]
PrivateKey = INTERFACE_KEY_ABCDEFGHIJKL
Address = 10.9.9.1/24

[Peer]
PublicKey = SOMEPEER
AllowedIPs = 10.9.9.2/32
EOF
    rm -f "$AWG_DIR/server_public.key"

    run _ensure_server_public_key
    [ "$status" -eq 0 ]
    # Must derive from INTERFACE_KEY_*, not anything in [Peer]
    [ "$(cat "$AWG_DIR/server_public.key")" = "pub_INTERFACE_KEY_ABCDEF" ]
}

