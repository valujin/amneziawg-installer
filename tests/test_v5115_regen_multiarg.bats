#!/usr/bin/env bats
# v5.11.5 hotfix regression tests.
#
# Two bundled fixes:
#   1. manage regen multi-arg (Issue #70 from @Barmem) — `manage regen c1 c2 c3`
#      used to process only c1; the rest were silently dropped. Now matches
#      add/remove pattern (loop over ARGS[@]).
#   2. apt strict mode on rc!=0 in step 2 (PR #69 review finding) —
#      apt_update_tolerant gained --ppa-amnezia-tolerant flag so step 2 dies
#      on base-mirror / GPG / dpkg-lock errors but still defers to
#      apt_wait_for_ppa_package retry on PPA Amnezia outage (issue #68).

# ---------- Fix 1: regen multi-arg ----------

@test "v5.11.5: RU regen case iterates ARGS[@]" {
    # Extract the regen case body and confirm the for-loop is there.
    block=$(awk '/^    regen\)/,/^[[:space:]]+;;[[:space:]]*$/' "$BATS_TEST_DIRNAME/../manage_amneziawg.sh")
    [[ "$block" == *'for _cname in "${ARGS[@]}"'* ]]
}


@test "v5.11.5: RU regen has counter and 'Обработано N из M' summary" {
    block=$(awk '/^    regen\)/,/^[[:space:]]+;;[[:space:]]*$/' "$BATS_TEST_DIRNAME/../manage_amneziawg.sh")
    [[ "$block" == *'_regen_count'* ]]
    [[ "$block" == *'Обработано'* ]]
}





# ---------- Fix 2: apt strict mode + --ppa-amnezia-tolerant ----------

@test "v5.11.5: RU apt_update_tolerant accepts --ppa-amnezia-tolerant flag" {
    # The flag string and the local var both must be present.
    run grep -F -- '--ppa-amnezia-tolerant' "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    [ "$status" -eq 0 ]
    run grep -E '^\s*local ppa_tolerant=0' "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    [ "$status" -eq 0 ]
}


@test "v5.11.5: step 2 uses --ppa-amnezia-tolerant and dies on hard error (RU)" {
    # The step 2 callsite must invoke the flag AND die() on rc!=0; without die
    # the install would proceed on a stale apt-cache (PR #69 review finding).
    run grep -B0 -A6 'apt_update_tolerant --ppa-amnezia-tolerant' \
        "$BATS_TEST_DIRNAME/../install_amneziawg.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *'die'* ]]
}



# ---------- Version markers ----------

