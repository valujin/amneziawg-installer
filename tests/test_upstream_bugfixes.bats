#!/usr/bin/env bats
# Tests for the high-value upstream bugfixes ported into our fork:
#   - e016bb6  detect_ssh_ports (anti-lockout: UFW must open the real SSH port)
#   - 01fb44c  iOS tunnel-drop fix (routing mode 2 must not lead with 0.0.0.0/5)
#   - 8eb24d1  fail2ban backend forced to systemd

bats_require_minimum_version 1.5.0

RU_SCRIPT="$BATS_TEST_DIRNAME/../install_amneziawg.sh"

# Pull a single function body out of the installer into the current shell.
_load_fn() {
    eval "$(awk "/^$1\\(\\) \\{/,/^\\}/" "$RU_SCRIPT")"
}

setup() {
    log() { :; }; log_warn() { :; }; log_error() { :; }
    export -f log log_warn log_error
    _load_fn detect_ssh_ports
}

@test "detect_ssh_ports: --ssh-port override wins" {
    CLI_SSH_PORT=2222
    run detect_ssh_ports
    [ "$status" -eq 0 ]
    [ "$output" = "2222" ]
}

@test "detect_ssh_ports: rejects a non-numeric override" {
    CLI_SSH_PORT="notaport"
    run detect_ssh_ports
    [ -z "$output" ]
}

@test "detect_ssh_ports: falls back to 22 with no sshd/ss/config" {
    CLI_SSH_PORT=""
    # Hide sshd/ss and point config lookups at an empty dir so only the
    # default-22 fallback remains.
    command() { return 1; }            # `command -v sshd|ss` -> not found
    export -f command
    run detect_ssh_ports
    [ "$status" -eq 0 ]
    [[ "$output" == *"22"* ]]
}

@test "iOS fix: routing mode 2 list does NOT start with the reserved 0.0.0.0/5" {
    # Static guard: the mode-2 ALLOWED_IPS must lead with 1.0.0.0/8 (not 0.0.0.0/5),
    # which would cover the unroutable 0.0.0.0/8 block and stall iOS tunnels.
    run grep -E 'ALLOWED_IPS="1\.0\.0\.0/8, 2\.0\.0\.0/7, 4\.0\.0\.0/6, 8\.0\.0\.0/7,' "$RU_SCRIPT"
    [ "$status" -eq 0 ]
    run grep -E 'ALLOWED_IPS="0\.0\.0\.0/5,' "$RU_SCRIPT"
    [ "$status" -ne 0 ]
}

@test "fail2ban: backend forced to systemd (not auto)" {
    run grep -E 'local f2b_backend="systemd"' "$RU_SCRIPT"
    [ "$status" -eq 0 ]
}
