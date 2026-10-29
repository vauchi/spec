#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The drift checks run nightly against the Core and relay mains, so a
# Core merge that invalidates a vector copy or renames a cited function
# is found the next morning and not when someone next edits the spec
# (vauchi/private#874). This checks the contract in .gitlab-ci.yml: the
# workflow admits scheduled pipelines, exactly the drift checks run on
# them, and every other job that runs on the default branch refuses a
# schedule, since $CI_COMMIT_BRANCH is the default branch there too.

set -eu

ci_config="${1:-.gitlab-ci.yml}"
failures=0

fail() {
    echo "FAIL: $1" >&2
    failures=$((failures + 1))
}

job_block() {
    awk -v job="$1" '
        $0 == job ":" { in_job = 1 }
        in_job && $0 != job ":" && /^[^[:space:]#]/ { exit }
        in_job { print }
    ' "$ci_config"
}

job_names() {
    awk '/^[a-z][a-z0-9_:-]*:$/ { sub(":$", ""); print }' "$ci_config" |
        grep -vE '^(workflow|default|include|variables|stages)$'
}

has_schedule_rule() {
    printf '%s\n' "$1" | grep -q 'CI_PIPELINE_SOURCE == "schedule"'
}

refuses_schedule() {
    printf '%s\n' "$1" | grep -n 'CI_PIPELINE_SOURCE == "schedule"' | head -1 |
        cut -d: -f1 | {
            read -r line || line=""
            [ -n "$line" ] &&
                printf '%s\n' "$1" | sed -n "$((line + 1))p" | grep -q 'when: never'
        }
}

if has_schedule_rule "$(job_block workflow)"; then
    echo "PASS: workflow admits scheduled pipelines"
else
    fail "workflow rules must admit CI_PIPELINE_SOURCE == \"schedule\""
fi

for job in check:vectors check:claim-names; do
    block=$(job_block "$job")
    if has_schedule_rule "$block" && ! refuses_schedule "$block"; then
        echo "PASS: $job runs on the nightly schedule"
    else
        fail "$job must run on CI_PIPELINE_SOURCE == \"schedule\""
    fi
done

for job in $(job_names); do
    case "$job" in check:vectors | check:claim-names) continue ;; esac
    block=$(job_block "$job")
    # shellcheck disable=SC2016 # matches the literal YAML text
    if ! printf '%s\n' "$block" | grep -q 'CI_COMMIT_BRANCH == \$CI_DEFAULT_BRANCH'; then
        continue
    fi
    if refuses_schedule "$block"; then
        echo "PASS: $job refuses the nightly schedule"
    else
        fail "$job runs on the default branch and must refuse CI_PIPELINE_SOURCE == \"schedule\" with when: never"
    fi
done

[ "$failures" -eq 0 ]
