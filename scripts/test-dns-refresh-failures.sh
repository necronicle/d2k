#!/bin/sh
# shellcheck disable=SC1091,SC2034 # dynamic shell fixtures or runtime config
set -eu
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
mkdir "$task_tmp/run" "$task_tmp/state"
awk '/^dns_excl_apply\(\)/,/^}/' "${DNS_TEST_SERVICE:-files/S99d2k}" > "$task_tmp/functions"
awk '/^dns_excl_sync_unlocked\(\)/,/^}/' "${DNS_TEST_SERVICE:-files/S99d2k}" >> "$task_tmp/functions"
awk '/^dns_excl_sync\(\)/,/^}/' "${DNS_TEST_SERVICE:-files/S99d2k}" >> "$task_tmp/functions"
. "$task_tmp/functions"
RUN="$task_tmp/run" STATE_DIR="$task_tmp/state" FW_BACKEND=iptables FW_V4ONLY="$task_tmp/run/v4-only"
fw_lock_acquire() { return 0; }
fw_lock_release() { return 0; }
dns_config_snapshot() { return 0; }
dns_upstreams() { printf '%s\n' 'resolver.example.test 443'; }
nslookup() { printf '%s\n' 'Name: resolver.example.test' 'Address 1: 192.0.2.2'; }
dns_local_routes_prune() { [ "$failure" != prune ]; }
dns_excl_rule() {
    case "$failure:$1" in delete:-D|add:-A) return 1 ;; esac
    return 0
}
printf '%s\n' 'resolver.example.test 192.0.2.1 443' > "$RUN/dns-excl"
cp "$RUN/dns-excl" "$task_tmp/old"
for failure in delete add prune; do
    if dns_excl_sync; then echo "failed DNS rule update was reported successful: $failure" >&2;exit 1;fi
    cmp "$RUN/dns-excl" "$task_tmp/old"
done
failure=none
dns_excl_sync
[ "$(cat "$RUN/dns-excl")" = 'resolver.example.test 192.0.2.2 443' ]
printf '%s\n' 'DNS refresh: failed delete/add/prune retains prior cache and failure status; successful retry commits'
