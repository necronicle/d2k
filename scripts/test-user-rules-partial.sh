#!/bin/sh
# Isolated function-level regression: no actual firewall or router access.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
INIT=${1:-$ROOT/files/S99d2k}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
STATE_DIR=$TMP/state
USER_RULES=$STATE_DIR/user-rules
# Used by the extracted production function below.
# shellcheck disable=SC2034
CHAIN_OUT=D2K_OUT
# shellcheck disable=SC2034
CHAIN_IN=D2K_IN
mkdir -p "$STATE_DIR" "$TMP/fw"
iptables() {
    [ "$1" = -t ] && [ "$2" = mangle ] && [ "$3" = -S ] || return 2
    [ -f "$TMP/fw/$4" ] || return 1
    cat "$TMP/fw/$4"
}
ip6tables() { return 1; }
awk '/^user_rules_save\(\)/ {copy=1} copy {print} copy && /^}/ {exit}' "$INIT" > "$TMP/functions"
# shellcheck disable=SC1091
. "$TMP/functions"
printf '%s\n' '-A D2K_OUT -s 192.168.1.145/32 -m comment --comment d2k-nintendo-bypass -j RETURN' > "$TMP/fw/D2K_OUT"
printf '%s\n' '-A D2K_IN -d 192.168.1.145/32 -m comment --comment d2k-nintendo-bypass -j RETURN' > "$TMP/fw/D2K_IN"
user_rules_save
cp "$USER_RULES" "$TMP/expected"
rm "$TMP/fw/D2K_IN"
user_rules_save
cmp -s "$USER_RULES" "$TMP/expected" || { echo 'FAIL: missing input chain erased saved Nintendo input exclusion'; exit 1; }
# An explicitly emptied, present chain must not resurrect its old rule.
: > "$TMP/fw/D2K_IN"
user_rules_save
if grep -q ' -A D2K_IN ' "$USER_RULES"; then echo 'FAIL: explicitly deleted rule resurrected'; exit 1; fi
grep -q ' -A D2K_OUT ' "$USER_RULES"
# Missing output chain must not hide a new input exclusion.
rm "$TMP/fw/D2K_OUT"
printf '%s\n' '-A D2K_IN -d 192.168.1.146/32 -m comment --comment another-device -j RETURN' > "$TMP/fw/D2K_IN"
user_rules_save
grep -q 'another-device' "$USER_RULES" || { echo 'FAIL: missing output chain hid live input exclusion'; exit 1; }
grep -q ' -A D2K_OUT ' "$USER_RULES"
echo 'PASS: partial chain loss preserves snapshots; explicit deletion stays deleted'
