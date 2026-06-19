#!/usr/bin/env bats
# v5.11.4 apt_wait_for_ppa_package — issue #68 regression test.
#
# Bug fixed: a brief ppa.launchpadcontent.net outage at install-time used to
# kill the script with "Ошибка apt update" / "apt update error". The new
# helper retries up to N times until the canonical PPA package appears in
# apt-cache, with exponential backoff between attempts. It explicitly does
# NOT trust the rc of apt-get update — Debian apt returns 0 tolerantly even
# when an InRelease did not download, which is the actual #68 scenario.
#
# These tests extract apt_wait_for_ppa_package from each install script and
# exercise it against stubbed apt-cache + apt_update_tolerant + sleep so no
# real apt call happens during the test.

extract_helper() {
    # awk extracts the function body verbatim; eval puts it in this shell.
    # shellcheck disable=SC2046
    eval "$(awk '/^apt_wait_for_ppa_package\(\) \{/,/^\}/' "$1")"
}

setup() {
    log_warn()  { :; }
    log_error() { :; }
    log()       { :; }
    log_debug() { :; }
    export -f log log_warn log_error log_debug
    # Reset state.
    _attempts=0
    _delays=()
    _update_calls=0
    # Stub sleep so tests run in milliseconds even with backoff math.
    sleep() { _delays+=("$1"); }
    # Stub apt_update_tolerant — counts retry-driven re-runs only.
    apt_update_tolerant() { _update_calls=$((_update_calls + 1)); return 0; }
    export -f sleep apt_update_tolerant
}

# ---------- RU install script ----------

@test "v5.11.4 PPA retry: RU helper succeeds on first attempt when package is visible" {
    extract_helper "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    apt-cache() { return 0; }

    run apt_wait_for_ppa_package amneziawg-dkms 3 1
    [ "$status" -eq 0 ]
}

@test "v5.11.4 PPA retry: RU helper retries until apt-cache shows the package" {
    extract_helper "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    # First two checks fail, third succeeds — counter lives in current shell.
    apt-cache() {
        _attempts=$((_attempts + 1))
        (( _attempts >= 3 ))
    }
    apt_wait_for_ppa_package amneziawg-dkms 3 1
    rc=$?
    [ "$rc" -eq 0 ]
    [ "$_attempts" -eq 3 ]
    # apt_update_tolerant must be called between retries (attempts 2 and 3),
    # but NOT before the first attempt.
    [ "$_update_calls" -eq 2 ]
}

@test "v5.11.4 PPA retry: RU helper returns 1 after exhausting max attempts" {
    extract_helper "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    apt-cache() {
        _attempts=$((_attempts + 1))
        return 1
    }
    set +e
    apt_wait_for_ppa_package amneziawg-dkms 3 1
    rc=$?
    set -e
    [ "$rc" -ne 0 ]
    [ "$_attempts" -eq 3 ]
}

@test "v5.11.4 PPA retry: RU helper uses exponential backoff (delay doubles)" {
    extract_helper "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    apt-cache() { return 1; }
    set +e
    apt_wait_for_ppa_package amneziawg-dkms 4 10
    set -e
    # 4 attempts → 3 sleeps between them: 10, 20, 40.
    [ "${#_delays[@]}" -eq 3 ]
    [ "${_delays[0]}" -eq 10 ]
    [ "${_delays[1]}" -eq 20 ]
    [ "${_delays[2]}" -eq 40 ]
}

@test "v5.11.4 PPA retry: RU helper caps delay at 1800s (overflow guard)" {
    extract_helper "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    apt-cache() { return 1; }
    set +e
    # initial=2000 already above cap; subsequent doublings would all stay capped.
    apt_wait_for_ppa_package amneziawg-dkms 4 2000
    set -e
    [ "${#_delays[@]}" -eq 3 ]
    [ "${_delays[0]}" -eq 2000 ]
    [ "${_delays[1]}" -eq 1800 ]
    [ "${_delays[2]}" -eq 1800 ]
}

# ---------- EN install script ----------




# ---------- RU/EN parity ----------


@test "v5.11.4 PPA retry: friendly final error in RU references issue #68" {
    run grep -F 'issues/68' "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    [ "$status" -eq 0 ]
}

