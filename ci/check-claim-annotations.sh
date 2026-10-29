#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The inverse of check-claim-names.sh: tests, lemmas and invariants declare
# the claim they back with a comment `@claim: S<n>`, and this checks both
# directions (vauchi/private#874). Every annotation must name a claim the
# claims chapter has, so a deleted or renumbered claim cannot leave tests
# pointing at nothing; and every claim whose status is shipped or partial
# must have at least one annotation in the search roots, so a claim cannot
# outlive the last test that backed it. A planned claim needs none.
#
# Usage: check-claim-annotations.sh <claims.md> <search-root>... | --self-test

set -eu

usage() {
    echo "usage: $0 <claims.md> <search-root>... | --self-test" >&2
    exit 2
}

# One line per claim: "S4 partial".
claims_with_status() {
    awk '
        /^## S[0-9]+\./ { sub(/^## /, ""); sub(/\..*$/, ""); id = $0 }
        id != "" && /^- \*\*Status\*\*:/ { sub(/^- \*\*Status\*\*:[[:space:]]*/, ""); sub(/[[:space:]]*$/, ""); print id, $0; id = "" }
    ' "$1"
}

annotations_in() {
    grep -rhoE '@claim: S[0-9]+' "$@" 2>/dev/null | sed 's/@claim: //' | sort -u
}

check() {
    claims=$1
    shift
    failures=0
    table=$(claims_with_status "$claims")
    if [ -z "$table" ]; then
        echo "FAIL: no claims found in $claims" >&2
        return 1
    fi
    found=$(annotations_in "$@")
    for id in $found; do
        if ! printf '%s\n' "$table" | awk '{ print $1 }' | grep -qx "$id"; then
            echo "FAIL: @claim: $id is annotated but $claims has no claim $id" >&2
            failures=$((failures + 1))
        fi
    done
    printf '%s\n' "$table" | while read -r id status; do
        case "$status" in
            planned) continue ;;
        esac
        if ! printf '%s\n' "$found" | grep -qx "$id"; then
            echo "FAIL: $id is $status but nothing is annotated @claim: $id in the search roots" >&2
            echo "x" >> "${SCRATCH:-/tmp}/.claim-annotations-missing"
        fi
    done
    if [ -f "${SCRATCH:-/tmp}/.claim-annotations-missing" ]; then
        failures=$((failures + $(wc -l < "${SCRATCH:-/tmp}/.claim-annotations-missing")))
        rm -f "${SCRATCH:-/tmp}/.claim-annotations-missing"
    fi
    if [ "$failures" -ne 0 ]; then
        return 1
    fi
    claim_count=$(printf '%s\n' "$table" | grep -vc ' planned$' || true)
    annotation_count=$(printf '%s\n' "$found" | grep -c . || true)
    echo "OK: every annotation names a claim, and all $claim_count shipped or partial claims in $claims have one ($annotation_count claims annotated)"
}

self_test() {
    dir=$(mktemp -d)
    SCRATCH=$dir
    export SCRATCH
    trap 'rm -rf "$dir"' EXIT
    cat > "$dir/claims.md" <<'EOF'
## S1. Shipped and backed

- **Status**: shipped

## S2. Planned, needs nothing

- **Status**: planned

## S3. Partial and backed

- **Status**: partial
EOF
    mkdir -p "$dir/roots/a" "$dir/roots/b"
    printf '// @claim: S1\n#[test]\nfn one() {}\n' > "$dir/roots/a/t.rs"
    printf '// @claim: S3\nlemma three:\n' > "$dir/roots/b/m.spthy"
    check "$dir/claims.md" "$dir/roots/a" "$dir/roots/b" > /dev/null 2>&1 ||
        { echo "self-test FAIL: a fully annotated chapter must pass" >&2; exit 1; }

    printf '// @claim: S9\n#[test]\nfn nine() {}\n' > "$dir/roots/a/u.rs"
    if check "$dir/claims.md" "$dir/roots/a" "$dir/roots/b" > /dev/null 2>&1; then
        echo "self-test FAIL: an annotation naming no claim must fail" >&2
        exit 1
    fi
    rm "$dir/roots/a/u.rs"

    rm "$dir/roots/b/m.spthy"
    if check "$dir/claims.md" "$dir/roots/a" "$dir/roots/b" > /dev/null 2>&1; then
        echo "self-test FAIL: a partial claim without an annotation must fail" >&2
        exit 1
    fi

    sed -i.bak 's/^- \*\*Status\*\*: partial$/- **Status**: planned/' "$dir/claims.md"
    check "$dir/claims.md" "$dir/roots/a" "$dir/roots/b" > /dev/null 2>&1 ||
        { echo "self-test FAIL: a planned claim must need no annotation" >&2; exit 1; }

    echo "self-test OK: annotated passes, unknown claim fails, missing annotation fails, planned needs none"
}

[ $# -ge 1 ] || usage
if [ "$1" = "--self-test" ]; then
    self_test
    exit 0
fi
[ $# -ge 2 ] || usage
[ -f "$1" ] || { echo "FAIL: $1 is not a file" >&2; exit 1; }
SCRATCH=$(mktemp -d)
export SCRATCH
trap 'rm -rf "$SCRATCH"' EXIT
check "$@"
