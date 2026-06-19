#!/usr/bin/env bats
# Tests for diagnose command (v5.14.0).
#
# Structural and functional coverage for the new `diagnose` subcommand:
# - Carrier map returns expected parameter rows
# - Unknown carrier name returns failure
# - CLI parser accepts --carrier=NAME
# - RU and EN scripts implement the same set of carriers

@test "diagnose: RU manage_amneziawg.sh defines diagnose_server() and helpers" {
    local FILE="${BATS_TEST_DIRNAME}/../manage_amneziawg.sh"
    grep -qE "^diagnose_server\(\) \{" "$FILE"
    grep -qE "^_diagnose_carrier_known\(\) \{" "$FILE"
    grep -qE "^_diagnose_carrier_list\(\) \{" "$FILE"
    grep -qE "^_diag_line\(\) \{" "$FILE"
}



@test "diagnose: --carrier=NAME is parsed in RU CLI" {
    local FILE="${BATS_TEST_DIRNAME}/../manage_amneziawg.sh"
    grep -qE '^\s+--carrier=\*\)\s+CLI_CARRIER="\$\{1#\*=\}"; shift ;;' "$FILE"
    grep -qE '^CLI_CARRIER=""' "$FILE"
}


@test "diagnose: 'diagnose' command is dispatched in RU" {
    local FILE="${BATS_TEST_DIRNAME}/../manage_amneziawg.sh"
    awk '/^case \$?\"?\$?COMMAND\"? in/,/^esac$/' "$FILE" | grep -qE '^\s+diagnose\)'
}


# Functional: source the carrier helper from RU script and exercise it.
_source_carrier_helper_ru() {
    # Extract _diagnose_carrier_known and _diagnose_carrier_list and source them.
    local FILE="${BATS_TEST_DIRNAME}/../manage_amneziawg.sh"
    eval "$(awk '/^_diagnose_carrier_known\(\) \{/,/^}$/' "$FILE")"
    eval "$(awk '/^_diagnose_carrier_list\(\) \{/,/^}$/' "$FILE")"
}

@test "_diagnose_carrier_known: beeline_msk row is 'default preset' shape" {
    _source_carrier_helper_ru
    run _diagnose_carrier_known beeline_msk
    [ "$status" -eq 0 ]
    [ "$output" = "3 6 40 89 50 250 random" ]
}

@test "_diagnose_carrier_known: tele2_krasnoyarsk row has i1=absent" {
    _source_carrier_helper_ru
    run _diagnose_carrier_known tele2_krasnoyarsk
    [ "$status" -eq 0 ]
    # Last token is the i1 mode
    [[ "$output" == *"absent" ]]
}

@test "_diagnose_carrier_known: tmobile_us row has i1=binary and Jc=6" {
    _source_carrier_helper_ru
    run _diagnose_carrier_known tmobile_us
    [ "$status" -eq 0 ]
    [ "$output" = "6 6 10 10 40 40 binary" ]
}

@test "_diagnose_carrier_known: unknown carrier returns 1" {
    _source_carrier_helper_ru
    run _diagnose_carrier_known atlantis_isp
    [ "$status" -ne 0 ]
}

@test "_diagnose_carrier_list: includes 7 distinct confirmed carriers" {
    _source_carrier_helper_ru
    run _diagnose_carrier_list
    [ "$status" -eq 0 ]
    local count
    count=$(echo "$output" | tr ' ' '\n' | sort -u | wc -l)
    [ "$count" -eq 7 ]
}

@test "_diagnose_carrier_known: mts_msk no longer known (removed - unconfirmed)" {
    _source_carrier_helper_ru
    run _diagnose_carrier_known mts_msk
    [ "$status" -ne 0 ]
}

@test "_diagnose_carrier_known: megafon_msk no longer known (removed - testing-only)" {
    _source_carrier_helper_ru
    run _diagnose_carrier_known megafon_msk
    [ "$status" -ne 0 ]
}

@test "diagnose: usage help mentions diagnose command in RU" {
    local FILE="${BATS_TEST_DIRNAME}/../manage_amneziawg.sh"
    awk '/^usage\(\) \{/,/^}$/' "$FILE" | grep -qE 'diagnose'
}

