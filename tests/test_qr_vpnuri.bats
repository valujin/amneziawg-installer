#!/usr/bin/env bats
# Tests for generate_qr_vpnuri helper (v5.11.2).
#
# The helper renders <name>.vpnuri.png from <name>.vpnuri so that users can
# one-tap-import a client into the Amnezia VPN app (Android/iOS/Desktop),
# complementing the existing <name>.png which is scanned by classic
# WireGuard-compatible clients.

load test_helper

# Install a fake qrencode binary in an isolated PATH entry.
# The shim reads stdin (the vpn:// URI) and writes the content to the -o
# target so tests can assert the file was produced from stdin.
mock_qrencode() {
    local bin="$TEST_DIR/bin"
    mkdir -p "$bin"
    cat > "$bin/qrencode" <<'SHIM'
#!/bin/bash
out=""
while (( $# > 0 )); do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -t) shift 2 ;;
        *)  shift ;;
    esac
done
[[ -z "$out" ]] && { echo "qrencode shim: missing -o" >&2; exit 2; }
cat > "$out"
exit 0
SHIM
    chmod +x "$bin/qrencode"
    # Prepend so our shim wins over any system qrencode.
    export PATH="$bin:$PATH"
}

# Install a fake qrencode that always exits non-zero — to exercise the
# error branch of generate_qr_vpnuri.
mock_qrencode_failing() {
    local bin="$TEST_DIR/bin"
    mkdir -p "$bin"
    cat > "$bin/qrencode" <<'SHIM'
#!/bin/bash
echo "qrencode shim: simulated failure" >&2
exit 1
SHIM
    chmod +x "$bin/qrencode"
    export PATH="$bin:$PATH"
}

@test "generate_qr_vpnuri: happy path writes PNG from .vpnuri" {
    mock_qrencode
    echo "vpn://TEST_URI_PAYLOAD" > "$AWG_DIR/foo.vpnuri"

    run generate_qr_vpnuri "foo"
    [ "$status" -eq 0 ]
    [ -f "$AWG_DIR/foo.vpnuri.png" ]
    # Shim round-trips stdin to $out, so we can verify content provenance.
    [ "$(cat "$AWG_DIR/foo.vpnuri.png")" = "vpn://TEST_URI_PAYLOAD" ]
}

@test "generate_qr_vpnuri: fails when .vpnuri missing" {
    mock_qrencode
    rm -f "$AWG_DIR/missing.vpnuri"

    run generate_qr_vpnuri "missing"
    [ "$status" -ne 0 ]
    [ ! -f "$AWG_DIR/missing.vpnuri.png" ]
}

@test "generate_qr_vpnuri: fails when qrencode exits non-zero" {
    mock_qrencode_failing
    echo "vpn://ANY" > "$AWG_DIR/qfail.vpnuri"

    run generate_qr_vpnuri "qfail"
    [ "$status" -ne 0 ]
    [ ! -f "$AWG_DIR/qfail.vpnuri.png" ]
}

@test "generate_qr_vpnuri: atomic - pre-existing PNG preserved when qrencode fails" {
    # Pre-populate a stale .vpnuri.png; a failing qrencode run must leave
    # the old file intact (no half-written replacement, no orphan tmp).
    echo "OLD_PNG_CONTENT" > "$AWG_DIR/atom.vpnuri.png"
    echo "vpn://ANY" > "$AWG_DIR/atom.vpnuri"
    mock_qrencode_failing

    run generate_qr_vpnuri "atom"
    [ "$status" -ne 0 ]
    # Old file must still be there with untouched content.
    [ -f "$AWG_DIR/atom.vpnuri.png" ]
    [ "$(cat "$AWG_DIR/atom.vpnuri.png")" = "OLD_PNG_CONTENT" ]
    # No orphan <name>.vpnuri.png.tmp.* files.
    run compgen -G "$AWG_DIR/atom.vpnuri.png.tmp.*"
    [ "$status" -ne 0 ]
}

@test "generate_qr_vpnuri: chmod 600 on created PNG (Linux/Darwin)" {
    mock_qrencode
    echo "vpn://PERMTEST" > "$AWG_DIR/permtest.vpnuri"

    run generate_qr_vpnuri "permtest"
    [ "$status" -eq 0 ]
    [ -f "$AWG_DIR/permtest.vpnuri.png" ]
    # chmod is a no-op on NTFS via Git Bash / 9p WSL mount — skip there.
    if [[ "$(uname -s)" == "Linux" || "$(uname -s)" == "Darwin" ]]; then
        [ "$(stat -c '%a' "$AWG_DIR/permtest.vpnuri.png")" = "600" ]
    fi
}





