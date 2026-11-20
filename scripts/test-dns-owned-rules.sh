#!/bin/sh
# shellcheck disable=SC1091,SC2034 # dynamic shell fixtures or runtime config
set -eu
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
for fn in dns_local_routes_down dns_local_routes_prune; do
    awk -v name="$fn" '$0 ~ "^"name"\\(\\)" {on=1} on {print} on && /^\)/ {exit}' "${DNS_TEST_SERVICE:-files/S99d2k}" >> "$task_tmp/functions"
done
. "$task_tmp/functions"
RUN=$task_tmp CHAIN_IN=D2K_IN MODE_TEST=keep
printf '%s\n' 'resolver.example.test 192.0.2.53 853 tcp' 'resolver.example.test 2001:db8::53 853 tcp' > "$RUN/dns-routes"
printf '%s\n' 'resolver.example.test 192.0.2.53 853' 'resolver.example.test 2001:db8::53 853' > "$RUN/targets"
iptables() {
    case "$*" in
        '-t mangle -S OUTPUT')
            [ "$MODE_TEST" != enumerate-fail ] || return 1
            if [ "$MODE_TEST" = protocol ]; then
                printf '%s\n' '-A OUTPUT -p udp -d 192.0.2.53/32 --dport 853 -m mark --mark 0 -m comment --comment "d2k-dns-route" -j MARK --set-xmark 0x2e/0xffffffff'
            fi
            printf '%s\n' '-A OUTPUT -p tcp -d 192.0.2.53/32 --dport 853 -m mark --mark 0 -m comment --comment "d2k-dns-route" -j MARK --set-xmark 0x2e/0xffffffff' ;;
        '-t mangle -S INPUT') printf '%s\n' '-A INPUT -p tcp -s 192.0.2.53/32 --sport 853 -m comment --comment "d2k-dns-route" -j NFQUEUE --queue-num 2000 --queue-bypass' ;;
        '-t mangle -S D2K_IN') : ;;
        '-t mangle -n -L POSTROUTING') return 0 ;;
        '-t mangle -D '*) printf '%s\n' "$*" >> "$RUN/deleted";[ "$MODE_TEST" != delete-fail ] ;;
        *) return 1 ;;
    esac
}
ip6tables() {
    case "$*" in
        '-t mangle -S OUTPUT') printf '%s\n' '-A OUTPUT -p tcp -d 2001:db8::53/128 --dport 853 -m mark --mark 0 -m comment --comment "d2k-dns-route" -j MARK --set-xmark 0x2e/0xffffffff' ;;
        '-t mangle -S INPUT'|'-t mangle -S D2K_IN') : ;;
        '-t mangle -n -L POSTROUTING') return 0 ;;
        '-t mangle -D '*) printf '%s\n' "$*" >> "$RUN/deleted";[ "$MODE_TEST" != delete-fail ] ;;
        *) return 1 ;;
    esac
}
: > "$RUN/deleted"
dns_local_routes_prune "$RUN/targets"
[ ! -s "$RUN/deleted" ] || { echo 'active DNS permission was removed after kernel CIDR normalization' >&2;exit 1; }
MODE_TEST=protocol
dns_local_routes_prune "$RUN/targets"
[ "$(wc -l < "$RUN/deleted" | tr -d ' ')" = 1 ]
rg -q -- '-p udp' "$RUN/deleted"
: > "$RUN/deleted"
printf '%s\n' 'resolver.example.test 192.0.2.53 853 udp' >> "$RUN/dns-routes"
dns_local_routes_prune "$RUN/targets"
[ ! -s "$RUN/deleted" ]
MODE_TEST=delete-fail
if dns_local_routes_down; then echo 'DNS cleanup deletion failure was hidden' >&2;exit 1;fi
: > "$RUN/dns-routes"
if dns_local_routes_prune "$RUN/targets"; then echo 'DNS prune deletion failure was hidden' >&2;exit 1;fi
MODE_TEST=enumerate-fail
if dns_local_routes_down; then echo 'DNS cleanup enumeration failure was hidden' >&2;exit 1;fi
if dns_local_routes_prune "$RUN/targets"; then echo 'DNS prune enumeration failure was hidden' >&2;exit 1;fi
MODE_TEST=revoke
: > "$RUN/deleted"
dns_local_routes_down
[ "$(wc -l < "$RUN/deleted" | tr -d ' ')" = 3 ]
printf '%s\n' 'owned DNS rules: IPv4/IPv6 CIDR permission, cleanup/prune failures and revocation PASS'

awk '/^dns_excl_sync_unlocked\(\)/,/^\)/' "${DNS_TEST_SERVICE:-files/S99d2k}" > "$RUN/routed"
. "$RUN/routed"
FW_BACKEND=iptables FW_V4ONLY="$RUN/v4-only"
first='resolver.example.test 192.0.2.53 53 udp'
second='resolver.example.test 192.0.2.53 53 tcp'
dns_excl_apply() {
    [ "$MODE_TEST" != fail ] || return 1
    printf '%s\n' 'resolver.example.test 192.0.2.53 53' > "$RUN/dns-excl"
    printf '%s\n' "$second" > "$RUN/dns-routes"
}
printf '%s\n' "$first" 'missing.example.test 192.0.2.54 53 tcp' > "$RUN/dns-routes"
dns_excl_sync_unlocked
[ "$(cat "$RUN/dns-routes.applied")" = "$first" ]
if cmp -s "$RUN/dns-routes" "$RUN/dns-routes.reconciled"; then exit 1; fi
dns_excl_sync_unlocked
[ "$(cat "$RUN/dns-routes.applied")" = "$second" ]
cmp -s "$RUN/dns-routes" "$RUN/dns-routes.reconciled"
MODE_TEST=fail
if dns_excl_sync_unlocked; then echo 'failed DNS application was acknowledged' >&2;exit 1;fi
[ ! -e "$RUN/dns-routes.applied" ] && [ ! -e "$RUN/dns-routes.reconciled" ]
printf '%s\n' 'DNS firewall acknowledgement: coherent snapshot, exact applied rows and failed update PASS'
