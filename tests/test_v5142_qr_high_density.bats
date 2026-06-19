#!/usr/bin/env bats
# Tests for v5.14.2 QR-code fix (issue #72).
#
# Background: AmneziaVPN on iOS reported "error 900 ImportInvalidConfigError"
# when scanning the .vpnuri.png QR. Investigation in issue #72 showed the PNG
# was rendered at the default qrencode scale (3 pixels per module) - modules
# were physically too small for the iPhone camera to resolve when reading the
# image off a computer screen. The actual fix is `-s 6` (module size). The
# accompanying flags `-l L` and `-m 4` pin existing qrencode defaults
# explicitly so future libqrencode changes cannot regress this fix.
#
# Reporter: @haritos90 in issue #72 (5 may 2026, Debian 12 + AmneziaVPN iOS 4.8.15.4).

load test_helper

# Capture-mode qrencode shim: write the full argv to a file we can inspect.
mock_qrencode_capture() {
    local bin="$TEST_DIR/bin"
    mkdir -p "$bin"
    cat > "$bin/qrencode" <<SHIM
#!/bin/bash
# Dump argv as one arg per line into the capture file.
printf '%s\n' "\$@" > "$TEST_DIR/qrencode-args"
out=""
while (( \$# > 0 )); do
    case "\$1" in
        -o) out="\$2"; shift 2 ;;
        -t|-l|-s|-m) shift 2 ;;
        *)  shift ;;
    esac
done
[[ -z "\$out" ]] && { echo "qrencode shim: missing -o" >&2; exit 2; }
cat > "\$out"
exit 0
SHIM
    chmod +x "$bin/qrencode"
    export PATH="$bin:$PATH"
}

@test "v5.14.2: generate_qr_vpnuri passes -l L (low EC) to qrencode" {
    mock_qrencode_capture
    echo "vpn://LONG_PAYLOAD" > "$AWG_DIR/c1.vpnuri"

    run generate_qr_vpnuri "c1"
    [ "$status" -eq 0 ]
    grep -q '^-l$' "$TEST_DIR/qrencode-args"
    # Confirm L follows -l (not M/Q/H).
    awk '/^-l$/{getline; print}' "$TEST_DIR/qrencode-args" | grep -qx 'L'
}

@test "v5.14.2: generate_qr_vpnuri passes -s 6 (module size) to qrencode" {
    mock_qrencode_capture
    echo "vpn://X" > "$AWG_DIR/c2.vpnuri"

    run generate_qr_vpnuri "c2"
    [ "$status" -eq 0 ]
    grep -q '^-s$' "$TEST_DIR/qrencode-args"
    awk '/^-s$/{getline; print}' "$TEST_DIR/qrencode-args" | grep -qx '6'
}

@test "v5.14.2: generate_qr_vpnuri passes -m 4 (quiet zone) to qrencode" {
    mock_qrencode_capture
    echo "vpn://X" > "$AWG_DIR/c3.vpnuri"

    run generate_qr_vpnuri "c3"
    [ "$status" -eq 0 ]
    grep -q '^-m$' "$TEST_DIR/qrencode-args"
    awk '/^-m$/{getline; print}' "$TEST_DIR/qrencode-args" | grep -qx '4'
}

@test "v5.14.2: -t png is still present alongside the new flags" {
    mock_qrencode_capture
    echo "vpn://X" > "$AWG_DIR/c4.vpnuri"

    run generate_qr_vpnuri "c4"
    [ "$status" -eq 0 ]
    grep -q '^-t$' "$TEST_DIR/qrencode-args"
    awk '/^-t$/{getline; print}' "$TEST_DIR/qrencode-args" | grep -qx 'png'
}

@test "v5.14.2: PNG file is still produced from .vpnuri payload (regression of v5.11.2)" {
    mock_qrencode_capture
    echo "vpn://REGRESSION_GUARD" > "$AWG_DIR/c5.vpnuri"

    run generate_qr_vpnuri "c5"
    [ "$status" -eq 0 ]
    [ -f "$AWG_DIR/c5.vpnuri.png" ]
    [ "$(cat "$AWG_DIR/c5.vpnuri.png")" = "vpn://REGRESSION_GUARD" ]
}


