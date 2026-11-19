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
# A `Backed by` line also says where: in a clause (the text between two
# `; ` or `. `) that names `.rs` or `.spthy` files, every candidate must
# occur in a file of one of those names. A name found elsewhere is
# MISPLACED; that is how a claim pointed at the wrong file and passed
# (vauchi/private#950). A clause naming no file is checked as before.
#
# A name that lives in an open merge request is listed in
# `claim-names.pending` (next to this script, or $CLAIM_NAMES_PENDING):
# missing then means PENDING, not FAIL, and the check fails once the name
# is present so the line is removed. When the search roots are that merge
# request's own branch rather than main, the caller sets
# CLAIM_NAMES_SOURCES_MAY_LAND=1 and a present pending name is LANDING,
# not stale: the line comes out after the merge (vauchi/private#937).

set -eu

usage() {
    echo "usage: $0 <claims.md> <search-root>... | --self-test" >&2
    exit 2
}

candidates() {
    # Commit hashes in backticks are all hex; they are references, not names.
    grep -oE '`[a-z][a-z0-9_]*`' "$1" | tr -d '`' | awk 'length($0) > 8' |
        grep -vE '^[0-9a-f]+$' | sort -u
}

# Prints "name<TAB>file,file" for every candidate in a `Backed by` clause
# that names files.
placed_candidates() {
    awk '
        /^- \*\*Backed by\*\*:/ {
            n = split($0, clauses, /; |\. /)
            for (c = 1; c <= n; c++) {
                text = clauses[c]; files = ""; names = ""
                while (match(text, /`[^`]+`/)) {
                    tok = substr(text, RSTART + 1, RLENGTH - 2)
                    text = substr(text, RSTART + RLENGTH)
                    if (tok ~ /^[A-Za-z0-9_\/.-]+\.(rs|spthy)$/) {
                        sub(/^.*\//, "", tok)
                        files = files (files == "" ? "" : ",") tok
                    } else if (tok ~ /^[a-z][a-z0-9_]*$/ && length(tok) > 8 && tok !~ /^[0-9a-f]+$/) {
                        names = names (names == "" ? "" : " ") tok
                    }
                }
                if (files != "" && names != "") {
                    m = split(names, each, " ")
                    for (i = 1; i <= m; i++) print each[i] "\t" files
                }
            }
        }
    ' "$1" | sort -u
}

# Every candidate listed in $1 that occurs as a whole word under the
# roots, one per line. The roots are read once for all candidates: one
# recursive grep per name took four minutes for the seven chapters
# against Core (vauchi/private#1305). A whole word is a maximal run of
# letters, digits and underscores, which is what grep -w matches for
# these names.
present_names() {
    wanted=$1
    shift
    [ -s "$wanted" ] || return 0
    find "$@" -type f -exec cat {} + | LC_ALL=C tr -cs 'A-Za-z0-9_' '\n' |
        awk 'NR == FNR { want[$0]; next } ($0 in want) && !seen[$0]++' "$wanted" -
}

is_present() {
    grep -qxF -- "$1" "$WORK/present"
}

# Whether $1 occurs as a whole word in a file named one of $2 (comma list)
# among the files listed in $WORK/files.
in_a_named_file() {
    name=$1
    for base in $(echo "$2" | tr ',' ' '); do
        while IFS= read -r path; do
            [ -n "$path" ] || continue
            grep -qw -- "$name" "$path" && return 0
        done << EOF
$(awk -F/ -v base="$base" '$NF == base' "$WORK/files")
EOF
    done
    return 1
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
    # A root that is gone holds no name, and the others still do: the
    # callers list crates by name, and Core has dropped one before.
    for root in "$@"; do
        shift
        if [ -e "$root" ]; then
            set -- "$@" "$root"
        else
            echo "WARN: no such search root: $root" >&2
        fi
    done
    [ "$#" -ge 1 ] || { echo "ERROR: none of the search roots exists" >&2; exit 2; }
    WORK=$(mktemp -d)
    candidates "$claims" > "$WORK/names"
    find "$@" -type f > "$WORK/files"
    present_names "$WORK/names" "$@" > "$WORK/present"
    for name in $(cat "$WORK/names"); do
        checked=$((checked + 1))
        if is_present "$name"; then
            if is_pending "$name" && [ "${CLAIM_NAMES_SOURCES_MAY_LAND:-0}" = 1 ]; then
                echo "LANDING: $name is in these sources; remove it from claim-names.pending once they merge"
            elif is_pending "$name"; then
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
    placed_candidates "$claims" > "$WORK/places"
    while IFS="$(printf '\t')" read -r name files; do
        is_pending "$name" && continue
        is_present "$name" || continue
        if ! in_a_named_file "$name" "$files"; then
            echo "MISPLACED: $name is named with $files in $claims and is in none of them" >&2
            missing=$((missing + 1))
        fi
    done < "$WORK/places"
    rm -rf "$WORK"
    if [ "$missing" -gt 0 ]; then
        echo "FAIL: $missing of $checked names in $claims back nothing or sit in another file" >&2
        return 1
    fi
    echo "OK: all $checked test, lemma and invariant names in $claims exist or are pending"
}

# CC-27: the check ships with the run that shows it failing.
self_test() {
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/root/tests"
    # The leading byte is no valid UTF-8: the roots hold binary fixtures,
    # and a word split that stops at one finds none of the names after it.
    printf '\377\nfn a_real_test_name() {}\nlemma a_real_lemma_name:\n' > "$tmp/root/tests/x.rs"
    printf -- '- **Backed by**: `a_real_test_name`, `a_real_lemma_name`, `a_real_test_name_prefix`\n' > "$tmp/bad.md"
    printf -- '- **Backed by**: `a_real_test_name` and `a_real_lemma_name`; file `foo_tests.rs`; lane `test:release-rg7`; flag `-DNO_SIGNATURE`; commit `a4e7c6eed`\n' > "$tmp/good.md"
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

    CLAIM_NAMES_PENDING="$tmp/empty.pending" check "$tmp/good.md" "$tmp/gone" "$tmp/root" >/dev/null 2>"$tmp/err" || {
        echo "SELF-TEST FAILED: a search root that is gone must not hide the names in the others:" >&2
        cat "$tmp/err" >&2
        exit 1
    }
    grep -q "WARN: no such search root: $tmp/gone" "$tmp/err" || {
        echo "SELF-TEST FAILED: a search root that is gone was not named" >&2
        exit 1
    }
    if (CLAIM_NAMES_PENDING="$tmp/empty.pending" check "$tmp/good.md" "$tmp/gone") >/dev/null 2>&1; then
        echo "SELF-TEST FAILED: a check with no search root left must not pass" >&2
        exit 1
    fi

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
    CLAIM_NAMES_SOURCES_MAY_LAND=1 CLAIM_NAMES_PENDING="$tmp/stale.pending" check "$tmp/good.md" "$tmp/root" >/dev/null || {
        echo "SELF-TEST FAILED: a pending name present in a merge request's own sources must pass" >&2
        exit 1
    }
    printf 'fn another_real_test() {}\n' > "$tmp/root/tests/y.rs"
    printf -- '- **Backed by**: test `a_real_test_name` in `y.rs`; lemma `a_real_lemma_name` in `x.rs`\n' > "$tmp/misplaced.md"
    printf -- '- **Backed by**: tests `a_real_test_name` in `x.rs` and `another_real_test` in `tests/y.rs`; then `a_real_lemma_name`\n' > "$tmp/placed.md"
    if CLAIM_NAMES_PENDING="$tmp/empty.pending" check "$tmp/misplaced.md" "$tmp/root" 2>"$tmp/err"; then
        echo "SELF-TEST FAILED: a name in another file than the one named was not reported" >&2
        exit 1
    fi
    grep -q 'MISPLACED: a_real_test_name is named with y.rs' "$tmp/err" || {
        echo "SELF-TEST FAILED: the misplaced name was not named:" >&2
        cat "$tmp/err" >&2
        exit 1
    }
    if grep -q 'a_real_lemma_name' "$tmp/err"; then
        echo "SELF-TEST FAILED: a name in the file it is named with was reported" >&2
        exit 1
    fi
    CLAIM_NAMES_PENDING="$tmp/empty.pending" check "$tmp/placed.md" "$tmp/root" >/dev/null || {
        echo "SELF-TEST FAILED: names in the files they are named with must pass" >&2
        exit 1
    }
    echo "self-test OK: missing fails, present and non-identifiers pass, pending waits, stale pending fails, a landing name passes, a name in another file than the one named fails"
}

[ "$#" -ge 1 ] || usage
case "$1" in
    --self-test) self_test ;;
    *) check "$@" ;;
esac
