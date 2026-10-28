#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Every test function, lemma and invariant the claims chapter names must
# exist in the code it points at, or the claim is backed by nothing
# (vauchi/private#874). A renamed or deleted test used to leave the
# sentence standing; this fails the pipeline instead.
#
# Usage:
#   check-claim-names.sh <claims.md> <search-root>...
#   check-claim-names.sh --self-test
#
# A candidate is any backticked identifier of the form [a-z][a-z0-9_]*
# longer than eight characters. File names (with a dot), lane names
# (with a colon) and flags or info strings (with a dash) are not
# identifiers and are left alone. A candidate passes when it occurs as a
# whole word in any file under the search roots.
#
# A name that lives in an open merge request is listed in
# `claim-names.pending` (next to this script, or $CLAIM_NAMES_PENDING):
# missing then means PENDING, not FAIL, and the check fails once the name
# is present so the line is removed.

set -eu

usage() {
    echo "usage: $0 <claims.md> <search-root>... | --self-test" >&2
    exit 2
}

candidates() {
    grep -oE '`[a-z][a-z0-9_]*`' "$1" | tr -d '`' | awk 'length($0) > 8' | sort -u
}

pending_names() {
    [ -f "$1" ] || return 0
    # grep exits 1 on an empty list, which is a valid list, not a failure.
    { grep -vE '^[[:space:]]*(#|$)' "$1" || true; } | awk '{ print $1 }'
}

is_pending() {
    for pending in $PENDING; do
        [ "$pending" = "$1" ] && return 0
    done
    return 1
}

check() {
    claims=$1
    shift
    [ -f "$claims" ] || { echo "ERROR: no such file: $claims" >&2; exit 2; }
    [ "$#" -ge 1 ] || usage
    PENDING=$(pending_names "${CLAIM_NAMES_PENDING:-$(dirname "$0")/claim-names.pending}")
    missing=0
    checked=0
    for name in $(candidates "$claims"); do
        checked=$((checked + 1))
        if grep -rqw -- "$name" "$@"; then
            if is_pending "$name"; then
                echo "FAIL: $name is on main now; remove it from claim-names.pending" >&2
                missing=$((missing + 1))
            fi
        elif is_pending "$name"; then
            echo "PENDING: $name is in an open merge request (claim-names.pending)"
        else
            echo "MISSING: $name is named in $claims and found nowhere under: $*" >&2
            missing=$((missing + 1))
        fi
    done
    if [ "$missing" -gt 0 ]; then
        echo "FAIL: $missing of $checked names in $claims back nothing" >&2
        return 1
    fi
    echo "OK: all $checked test, lemma and invariant names in $claims exist or are pending"
}

# CC-27: the check ships with the run that shows it failing.
self_test() {
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/root/tests"
    printf 'fn a_real_test_name() {}\nlemma a_real_lemma_name:\n' > "$tmp/root/tests/x.rs"
    printf -- '- **Backed by**: `a_real_test_name`, `a_real_lemma_name`, `a_real_test_name_prefix`\n' > "$tmp/bad.md"
    printf -- '- **Backed by**: `a_real_test_name` and `a_real_lemma_name`; file `foo_tests.rs`; lane `test:release-rg7`; flag `-DNO_SIGNATURE`\n' > "$tmp/good.md"
    : > "$tmp/empty.pending"

    if CLAIM_NAMES_PENDING="$tmp/empty.pending" check "$tmp/bad.md" "$tmp/root" 2>"$tmp/err"; then
        echo "SELF-TEST FAILED: a missing name was not reported" >&2
        exit 1
    fi
    grep -q 'MISSING: a_real_test_name_prefix' "$tmp/err" || {
        echo "SELF-TEST FAILED: the missing name was not named:" >&2
        cat "$tmp/err" >&2
        exit 1
    }
    CLAIM_NAMES_PENDING="$tmp/empty.pending" check "$tmp/good.md" "$tmp/root" >/dev/null

    printf 'a_real_test_name_prefix core!0 (self-test)\n' > "$tmp/one.pending"
    CLAIM_NAMES_PENDING="$tmp/one.pending" check "$tmp/bad.md" "$tmp/root" >/dev/null || {
        echo "SELF-TEST FAILED: a pending name must not fail the check" >&2
        exit 1
    }
    printf 'a_real_test_name core!0 (self-test)\n' > "$tmp/stale.pending"
    if CLAIM_NAMES_PENDING="$tmp/stale.pending" check "$tmp/good.md" "$tmp/root" 2>/dev/null; then
        echo "SELF-TEST FAILED: a pending name that exists must fail until the line is removed" >&2
        exit 1
    fi
    echo "self-test OK: missing fails, present and non-identifiers pass, pending waits, stale pending fails"
}

[ "$#" -ge 1 ] || usage
case "$1" in
    --self-test) self_test ;;
    *) check "$@" ;;
esac
