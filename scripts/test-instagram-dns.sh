#!/bin/sh
# Regression tests for the installer-owned Instagram/WhatsApp static DNS lifecycle.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SCRIPT=$ROOT/files/d2k-instagram-dns.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
export D2K_IP_CA_BUNDLE="$TMP/ca-bundle.pem"
printf 'test CA handled by the probe double\n' > "$D2K_IP_CA_BUNDLE"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }

[ -x "$SCRIPT" ] || fail "Instagram resolver lifecycle script is missing or not executable"

# One host list: the router script, the d2ktg certificate check and the VPS
# allowlist must carry exactly the same names in the same order.
EXPECTED='instagram.com www.instagram.com graph.instagram.com api.instagram.com i.instagram.com instagram.c10r.instagram.com static.cdninstagram.com scontent.cdninstagram.com static.xx.fbcdn.net scontent.xx.fbcdn.net web.whatsapp.com www.whatsapp.com scontent.whatsapp.net graph.whatsapp.com v.whatsapp.com static.whatsapp.net mmg.whatsapp.net pps.whatsapp.net'
c_hosts() {
    sed -n '/META_HOSTS_BEGIN/,/META_HOSTS_END/p' "$1" | grep -o '"[a-z0-9.-]*"' | tr -d '"' | tr '\n' ' ' | sed 's/ $//'
}
script_hosts=$(sed -n "s/^HOSTS='\(.*\)'$/\1/p" "$SCRIPT")
[ "$script_hosts" = "$EXPECTED" ] || fail "router script host list differs: $script_hosts"
[ "$(c_hosts "$ROOT/telegram/src/main.c")" = "$EXPECTED" ] || fail "d2ktg check list differs: $(c_hosts "$ROOT/telegram/src/main.c")"
[ "$(c_hosts "$ROOT/relay-enroll/main.c")" = "$EXPECTED" ] || fail "VPS /resolve allowlist differs: $(c_hosts "$ROOT/relay-enroll/main.c")"
[ "$(echo "$EXPECTED" | wc -w | tr -d ' ')" = 18 ] || fail "host list must contain 18 names"
! grep -n 'instagram.com|www.instagram.com|' "$SCRIPT" >/dev/null || fail "managed_host carries a second hand-written host list"
ok "router script, d2ktg and VPS allowlist share one 18-name list"

mkdir -p "$TMP/bin" "$TMP/d2k/state" "$TMP/d2k/files" "$TMP/d2k/log"
printf 'D2K_RESOLVE_SECRET="test-secret"\nZ2K_RESOLVE_SECRET="old-secret"\n' > "$TMP/d2k/config"
printf '157.240.0.0/16\n57.144.0.0/14\n' > "$TMP/d2k/files/meta-ranges.txt"
cat > "$TMP/ndmc-state" <<'EOF'
ip host www.instagram.com 157.240.9.175
ip host instagram.com 203.0.113.10
ip host unrelated.example 192.0.2.7
EOF

cat > "$TMP/bin/ndmc" <<'EOF'
#!/bin/sh
case "$*" in
    *"show running-config"*) [ "${NDMC_FAIL_SHOW:-0}" = 1 ] && exit 7; [ "${NDMC_EMPTY_SHOW:-0}" = 1 ] && exit 0; cat "$NDMC_STATE" ;;
    *"system configuration save"*) [ "${NDMC_FAIL_SAVE:-0}" = 1 ] && exit 8; printf '%s\n' "$*" >> "$NDMC_CALLS" ;;
    "-c ip host "*)
        if [ "${NDMC_TERM_DURING_ADD:-0}" = 1 ]; then
            printf '%s\n' "$*" >> "$NDMC_CALLS"
            kill -TERM "$PPID"; sleep 1
            printf 'ip host %s %s\n' "$(echo "$2" | awk '{print $3}')" "$(echo "$2" | awk '{print $4}')" >> "$NDMC_STATE"
            exit 0
        fi
        [ "${NDMC_FAIL_ADD:-0}" = 1 ] && exit 6
        printf '%s\n' "$*" >> "$NDMC_CALLS"
        printf 'ip host %s %s\n' "$(echo "$2" | awk '{print $3}')" "$(echo "$2" | awk '{print $4}')" >> "$NDMC_STATE"
        # Simulates uninstall stopping a background refresh right after NDM
        # accepted a record.
        [ "${NDMC_KILL_AFTER_ADD:-0}" = 1 ] && kill -9 "$PPID"
        :
        ;;
    "-c no ip host "*)
        printf '%s\n' "$*" >> "$NDMC_CALLS"
        host=$(echo "$2" | awk '{print $4}')
        ip=$(echo "$2" | awk '{print $5}')
        awk -v h="$host" -v ip="$ip" '!( $1=="ip" && $2=="host" && $3==h && $4==ip )' "$NDMC_STATE" > "$NDMC_STATE.new"
        mv "$NDMC_STATE.new" "$NDMC_STATE"
        ;;
    *) printf 'unexpected ndmc call: %s\n' "$*" >&2; exit 2 ;;
esac
EOF
cat > "$TMP/bin/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$CURL_CALLS"
case "$*" in
    */resolve*)
        [ "${RESOLVE_FAIL:-0}" = 1 ] && exit 22
        calls=$(grep -c '/resolve' "$CURL_CALLS" 2>/dev/null || echo 0)
        [ "$calls" -le "${RESOLVE_FAIL_FIRST:-0}" ] && exit 28
        if [ -n "${RESOLVE_BODY:-}" ]; then printf '%s' "$RESOLVE_BODY"; exit 0; fi
        printf '{"results":{"instagram.com":["%s","8.8.8.8","%s","157.240.9.177","157.240.9.178"],"www.instagram.com":["157.240.9.175"],"not-instagram.example":["157.240.9.179"],"i.instagram.com":["157.240.9.63"],"static.xx.fbcdn.net":["%s"],"scontent.xx.fbcdn.net":["%s"],"web.whatsapp.com":["%s","57.144.245.33"],"v.whatsapp.com":[],"static.whatsapp.net":["57.144.245.32"],"evil.whatsapp.com":["57.144.245.40"]}}' \
            "${VPS_IP1:-157.240.9.174}" "${VPS_IP2:-157.240.9.176}" "${FB_IP:-157.240.205.11}" "${FB_IP:-157.240.205.11}" "${WA_IP:-57.144.245.32}"
        ;;
    *)
        probes=$(grep -vc '/resolve' "$CURL_CALLS" 2>/dev/null || echo 0)
        if [ "$probes" -le "${PROBE_FAIL_FIRST:-0}" ]; then printf '000'; exit 28; fi
        printf '200'
        ;;
esac
EOF
cat > "$TMP/bin/openssl" <<'EOF'
#!/bin/sh
printf 'openssl %s\n' "$*" >> "$OPENSSL_KEY"
exit 1
EOF
cat > "$TMP/bin/d2ktg" <<'EOF'
#!/bin/sh
[ "$1" = --check-instagram-ip ] && [ "$#" = 4 ] || exit 2
printf '%s\n' "$*" >> "$CURL_CALLS"
[ "${PROBE_FAIL_ALL:-0}" = 1 ] && exit 1
# PROBE_DEAD: "ip" (dead for every name) or "name:ip" (certificate/edge fails for that name).
for dead in ${PROBE_DEAD:-}; do
    case "$dead" in *:*) [ "$2:$3" = "$dead" ] && exit 1 ;; *) [ "$3" = "$dead" ] && exit 1 ;; esac
done
probes=$(grep -c -- '--check-instagram-ip' "$CURL_CALLS" || true)
[ "$probes" -gt "${PROBE_FAIL_FIRST:-0}" ]
EOF
chmod +x "$TMP/bin/ndmc" "$TMP/bin/curl" "$TMP/bin/openssl" "$TMP/bin/d2ktg"

env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" \
    D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" \
    CURL_CALLS="$TMP/curl-calls" OPENSSL_KEY="$TMP/openssl-key" \
    D2K_IP_PROBE_RETRY_DELAY=0 PROBE_FAIL_FIRST=1 \
    D2K_INSTAGRAM_LOG="$TMP/refresh.log" sh "$SCRIPT" refresh || fail "refresh failed"

grep -q '^ip host instagram.com 157.240.9.174$' "$TMP/ndmc-state" || { cat "$TMP/refresh.log" >&2; cat "$TMP/ndmc-calls" >&2; fail "VPS Instagram address was not added"; }
grep -q '^ip host instagram.com 157.240.9.176$' "$TMP/ndmc-state" || fail "second live Instagram edge was not added"
for ip in 157.240.9.177 157.240.9.178; do
    grep -q "^ip host instagram.com $ip$" "$TMP/ndmc-state" || fail "working direct address was lost: $ip"
done
grep -q '^ip host instagram.com 203.0.113.10$' "$TMP/ndmc-state" || fail "pre-existing user mapping was changed"
grep -q '^ip host www.instagram.com 157.240.9.175$' "$TMP/ndmc-state" || fail "identical pre-existing mapping was lost"
! grep -q '8.8.8.8\|not-instagram.example' "$TMP/ndmc-calls" || fail "untrusted or non-Instagram answer reached ndmc"
grep -q '^instagram.com 157.240.9.174$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "ownership manifest omitted added address"
grep -q '^instagram.com 157.240.9.176$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "ownership manifest omitted second added address"
! grep -q '^www.instagram.com ' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "pre-existing mapping was incorrectly claimed"
! grep -qi 'X-Z2K-Auth\|hmac\|test-secret\|old-secret' "$TMP/curl-calls" || fail "d2k resolver request still carries z2k HMAC authentication"
[ ! -e "$TMP/openssl-key" ] || fail "refresh still computes an HMAC with openssl"
body=$(printf '{"hosts":["%s"]}' "$(echo "$EXPECTED" | sed 's/ /","/g')")
grep -qF -- "--data $body" "$TMP/curl-calls" || fail "VPS request did not contain all 18 names in order"
grep -q '^ip host i.instagram.com 157.240.9.63$' "$TMP/ndmc-state" || fail "i.instagram.com was not pinned"
grep -q '^ip host static.xx.fbcdn.net 157.240.205.11$' "$TMP/ndmc-state" || fail "static.xx.fbcdn.net was not pinned"
grep -q '^ip host scontent.xx.fbcdn.net 157.240.205.11$' "$TMP/ndmc-state" || fail "scontent.xx.fbcdn.net was not pinned"
grep -q '^ip host web.whatsapp.com 57.144.245.32$' "$TMP/ndmc-state" || fail "WhatsApp Web address was not pinned"
grep -q '^ip host web.whatsapp.com 57.144.245.33$' "$TMP/ndmc-state" || fail "second WhatsApp Web edge was not pinned"
grep -q '^ip host static.whatsapp.net 57.144.245.32$' "$TMP/ndmc-state" || fail "WhatsApp Web static assets host was not pinned"
grep -q -- '--check-instagram-ip static.whatsapp.net 57.144.245.32' "$TMP/curl-calls" || fail "static.whatsapp.net skipped the certificate check"
grep -q '^web.whatsapp.com 57.144.245.32$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "manifest does not own the WhatsApp pin"
grep -q '^static.xx.fbcdn.net 157.240.205.11$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "manifest does not own the fbcdn pin"
! grep -q 'evil.whatsapp.com\|57.144.245.40' "$TMP/ndmc-calls" "$TMP/curl-calls" || fail "a name outside the list reached ndmc or the certificate check"
grep -q -- '--check-instagram-ip web.whatsapp.com 57.144.245.32' "$TMP/curl-calls" || fail "WhatsApp address skipped the certificate check"
grep -q -- '--check-instagram-ip instagram.com 157.240.9.174' "$TMP/curl-calls" || fail "DNS health still depends on blocked application HTTPS instead of certificate-verified edge health"
grep -q 'повтор TLS-пробы 1/2' "$TMP/refresh.log" || fail "transient IP probe failure was not retried"
ok "refresh pins VPS-verified Instagram, fbcdn and WhatsApp IPs and records only D2K-owned pairs"

# Without an override the router asks d2k's own C resolver on the enrollment
# port, pinning the nip.io name to its literal address on that same port.
DEF="$TMP/default"
mkdir -p "$DEF/d2k/state" "$DEF/d2k/files" "$DEF/d2k/log"
: > "$DEF/d2k/config"; cp "$TMP/d2k/files/meta-ranges.txt" "$DEF/d2k/files/"
printf 'system name test-router\n' > "$DEF/ndmc-state"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$DEF/d2k" D2K_CONFIG="$DEF/d2k/config" \
    D2K_META_RANGES="$DEF/d2k/files/meta-ranges.txt" \
    NDMC_STATE="$DEF/ndmc-state" NDMC_CALLS="$DEF/ndmc-calls" \
    CURL_CALLS="$DEF/curl-calls" OPENSSL_KEY="$DEF/openssl-key" \
    D2K_INSTAGRAM_LOG="$DEF/refresh.log" sh "$SCRIPT" refresh || { cat "$DEF/refresh.log" >&2; fail "refresh against the default resolver failed"; }
grep -q -- '--resolve 85.192.60.175.nip.io:9443:85.192.60.175 -X POST https://85.192.60.175.nip.io:9443/resolve' "$DEF/curl-calls" \
    || { cat "$DEF/curl-calls" >&2; fail "default resolver is not d2k's own https://85.192.60.175.nip.io:9443/resolve"; }
! grep -q 'nip.io/resolve\|:443:' "$DEF/curl-calls" || fail "refresh still calls the z2k relay /resolve on 443"
ok "default resolver is d2k's own C /resolve on port 9443 without authentication"

: > "$TMP/curl-calls"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" \
    D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" D2K_RELAY_URL=https://resolve.example/resolve \
    VPS_IP1=157.240.9.180 VPS_IP2=157.240.9.181 \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    OPENSSL_KEY="$TMP/openssl-key" D2K_INSTAGRAM_LOG="$TMP/replace.log" sh "$SCRIPT" refresh \
    || fail "refresh could not replace old D2K-owned pairs"
grep -q '^ip host instagram.com 157.240.9.180$' "$TMP/ndmc-state" || fail "new edge was not installed"
grep -q '^ip host instagram.com 157.240.9.181$' "$TMP/ndmc-state" || fail "second new edge was not installed"
! grep -q '^ip host instagram.com 157.240.9.174$\|^ip host instagram.com 157.240.9.176$' "$TMP/ndmc-state" || fail "stale D2K-owned edges survived replacement"
grep -q '^ip host instagram.com 203.0.113.10$' "$TMP/ndmc-state" || fail "replacement removed a user-owned record"
grep -q '^instagram.com 157.240.9.180$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "manifest lacks the refreshed edge"
! grep -q '^instagram.com 157.240.9.174$\|^instagram.com 157.240.9.176$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "manifest retained stale edges"
ok "successful refresh replaces stale D2K-owned pairs without touching user DNS"

cp "$TMP/ndmc-state" "$TMP/before-add-failure"
if env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" NDMC_FAIL_ADD=1 \
    D2K_RELAY_URL=https://resolve.example/resolve VPS_IP1=157.240.9.182 VPS_IP2=157.240.9.183 \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    OPENSSL_KEY="$TMP/openssl-key" D2K_INSTAGRAM_LOG="$TMP/add-failure.log" sh "$SCRIPT" refresh; then
    fail "refresh reported success although NDM rejected new pins"
fi
cmp -s "$TMP/before-add-failure" "$TMP/ndmc-state" || fail "old working pins removed despite failure to install replacements"
ok "failed NDM additions preserve previous pins and report failure"

if env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" PROBE_FAIL_ALL=1 \
    D2K_IP_PROBE_ATTEMPTS=1 D2K_RELAY_URL=https://resolve.example/resolve \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    OPENSSL_KEY="$TMP/openssl-key" D2K_INSTAGRAM_LOG="$TMP/tls-failure.log" sh "$SCRIPT" refresh; then
    fail "refresh accepted failed certificate/reachability probes"
fi
cmp -s "$TMP/before-add-failure" "$TMP/ndmc-state" || fail "failed TLS controls changed DNS"
ok "failed edge verification never replaces working DNS"

env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" \
    D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    D2K_INSTAGRAM_LOG="$TMP/remove.log" sh "$SCRIPT" remove || fail "remove failed"

! grep -q '^ip host instagram.com 157.240.9.180$\|^ip host instagram.com 157.240.9.181$' "$TMP/ndmc-state" || fail "D2K-owned mappings survived removal"
! grep -q 'whatsapp\|fbcdn\|i.instagram.com' "$TMP/ndmc-state" || fail "D2K-owned WhatsApp/fbcdn/i.instagram pins survived removal"
grep -q '^ip host instagram.com 203.0.113.10$' "$TMP/ndmc-state" || fail "removal deleted a user-owned mapping"
grep -q '^ip host www.instagram.com 157.240.9.175$' "$TMP/ndmc-state" || fail "removal deleted a pre-existing identical mapping"
[ ! -e "$TMP/d2k/state/instagram-ip-hosts.tsv" ] || fail "ownership manifest survived removal"
ok "remove deletes exact D2K-owned pairs and preserves user mappings"

cp "$TMP/ndmc-state" "$TMP/before-failed-refresh"
: > "$TMP/curl-calls"
if env D2K_STUB_PATH="$TMP/bin" RESOLVE_FAIL=1 D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" \
    D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" D2K_RELAY_URL=https://resolve.example/resolve \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" OPENSSL_KEY="$TMP/openssl-key" \
    D2K_RESOLVE_RETRY_DELAY=0 \
    D2K_INSTAGRAM_LOG="$TMP/failure.log" sh "$SCRIPT" refresh; then
    fail "refresh treated unavailable VPS as successful"
fi
cmp -s "$TMP/before-failed-refresh" "$TMP/ndmc-state" || fail "VPS failure changed static DNS records"
[ "$(grep -c '/resolve' "$TMP/curl-calls")" = 3 ] || fail "resolver failure did not use the configured retry budget"
grep -q 'текущие DNS-записи не изменены' "$TMP/failure.log" || fail "VPS failure was not clearly logged"
ok "resolver failure retries three times and leaves all DNS records untouched"

: > "$TMP/curl-calls"
env D2K_STUB_PATH="$TMP/bin" RESOLVE_FAIL_FIRST=2 D2K_RESOLVE_RETRY_DELAY=0 \
    D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve NDMC_STATE="$TMP/ndmc-state" \
    NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" OPENSSL_KEY="$TMP/openssl-key" \
    D2K_INSTAGRAM_LOG="$TMP/retry.log" sh "$SCRIPT" refresh || fail "refresh did not recover after transient VPS failures"
[ "$(grep -c '/resolve' "$TMP/curl-calls")" = 3 ] || fail "refresh did not recover on its third VPS attempt"
grep -q '^ip host instagram.com 157.240.9.174$' "$TMP/ndmc-state" || fail "recovered VPS answer was not applied"
! grep -Eqi 'fallback|резервн' "$TMP/retry.log" || fail "refresh introduced a hard-coded fallback"
ok "resolver retry recovers and applies only live VPS results"

env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" NDMC_STATE="$TMP/ndmc-state" \
    NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    D2K_INSTAGRAM_LOG="$TMP/retry-remove.log" sh "$SCRIPT" remove || fail "retry-result cleanup failed"

printf 'ip host instagram.com 157.240.9.174\n' >> "$TMP/ndmc-state"
printf 'instagram.com 157.240.9.174\n' > "$TMP/d2k/state/instagram-ip-hosts.tsv"
if env D2K_STUB_PATH="$TMP/bin" NDMC_FAIL_SAVE=1 D2K_DIR="$TMP/d2k" \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    D2K_INSTAGRAM_LOG="$TMP/remove-failure.log" sh "$SCRIPT" remove; then
    fail "remove hid an NDM save failure"
fi
[ -s "$TMP/d2k/state/instagram-ip-hosts.tsv" ] || fail "failed cleanup discarded ownership manifest"
ok "failed NDM save keeps the ownership manifest for retry"

env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    D2K_INSTAGRAM_LOG="$TMP/remove-retry.log" sh "$SCRIPT" remove || fail "cleanup retry failed"
[ ! -e "$TMP/d2k/state/instagram-ip-hosts.tsv" ] || fail "successful cleanup retry kept the manifest"
ok "cleanup retry persists removal and then clears the manifest"

# A refresh killed right after NDM accepted a pin (service stop, uninstall)
# must already own it, so remove can take it back.
KILL="$TMP/killed"
mkdir -p "$KILL/d2k/state" "$KILL/d2k/files" "$KILL/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$KILL/d2k/files/"
printf 'ip host unrelated.example 192.0.2.7\n' > "$KILL/ndmc-state"
if (env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$KILL/d2k" D2K_META_RANGES="$KILL/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve NDMC_KILL_AFTER_ADD=1 \
    NDMC_STATE="$KILL/ndmc-state" NDMC_CALLS="$KILL/ndmc-calls" CURL_CALLS="$KILL/curl-calls" \
    D2K_INSTAGRAM_LOG="$KILL/refresh.log" sh "$SCRIPT" refresh; exit $?) 2>/dev/null; then
    fail "killed refresh reported success"
fi
added=$(awk '$1=="ip"&&$2=="host"&&$3!="unrelated.example"{print $3" "$4}' "$KILL/ndmc-state")
[ -n "$added" ] || fail "kill simulation did not add a record"
[ "$(cat "$KILL/d2k/state/instagram-ip-hosts.tsv" 2>/dev/null)" = "$added" ] || fail "pin added before the kill is not in the ownership manifest"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$KILL/d2k" NDMC_STATE="$KILL/ndmc-state" NDMC_CALLS="$KILL/ndmc-calls" \
    D2K_INSTAGRAM_LOG="$KILL/remove.log" sh "$SCRIPT" remove || fail "remove after an interrupted refresh failed"
[ "$(cat "$KILL/ndmc-state")" = 'ip host unrelated.example 192.0.2.7' ] || fail "interrupted refresh left an unowned pin"
ok "a refresh interrupted after an NDM add already owns that pin"

# A stop request (TERM from the scheduler during uninstall) while NDM is still
# applying an add: the helper lets that add finish, then exits without any
# further change, so the removal that follows sees and removes the pin.
STOP="$TMP/stopped"
mkdir -p "$STOP/d2k/state" "$STOP/d2k/files" "$STOP/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$STOP/d2k/files/"
printf 'ip host unrelated.example 192.0.2.7\n' > "$STOP/ndmc-state"
rc=0
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$STOP/d2k" D2K_META_RANGES="$STOP/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve NDMC_TERM_DURING_ADD=1 \
    NDMC_STATE="$STOP/ndmc-state" NDMC_CALLS="$STOP/ndmc-calls" CURL_CALLS="$STOP/curl-calls" \
    D2K_INSTAGRAM_LOG="$STOP/refresh.log" sh "$SCRIPT" refresh || rc=$?
[ "$rc" -ne 0 ] || fail "stopped refresh reported success"
[ "$(grep -c '^-c ip host ' "$STOP/ndmc-calls")" = 1 ] || fail "refresh continued adding after a stop request"
added=$(awk '$1=="ip"&&$2=="host"&&$3!="unrelated.example"{print $3" "$4}' "$STOP/ndmc-state")
[ -n "$added" ] || fail "helper exited before the in-flight NDM add finished"
[ "$(cat "$STOP/d2k/state/instagram-ip-hosts.tsv")" = "$added" ] || fail "in-flight add is not owned"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$STOP/d2k" NDMC_STATE="$STOP/ndmc-state" NDMC_CALLS="$STOP/ndmc-calls" \
    D2K_INSTAGRAM_LOG="$STOP/remove.log" sh "$SCRIPT" remove || fail "remove after a stopped refresh failed"
[ "$(cat "$STOP/ndmc-state")" = 'ip host unrelated.example 192.0.2.7' ] || fail "stopped refresh left an unowned pin"
ok "a stop request lets the in-flight NDM add finish, then exits; removal takes the pin back"

# A pair claimed by a refresh that died before NDM received it is dropped by
# the next refresh, so it can never cover the user's own later pin.
CLAIM="$TMP/claimed"
mkdir -p "$CLAIM/d2k/state" "$CLAIM/d2k/files" "$CLAIM/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$CLAIM/d2k/files/"
printf 'system name test-router\n' > "$CLAIM/ndmc-state"
printf 'graph.instagram.com 157.240.9.199\n' > "$CLAIM/d2k/state/instagram-ip-hosts.tsv"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$CLAIM/d2k" D2K_META_RANGES="$CLAIM/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve \
    NDMC_STATE="$CLAIM/ndmc-state" NDMC_CALLS="$CLAIM/ndmc-calls" CURL_CALLS="$CLAIM/curl-calls" \
    D2K_INSTAGRAM_LOG="$CLAIM/refresh.log" sh "$SCRIPT" refresh || fail "refresh with a stale claim failed"
! grep -q '^graph.instagram.com 157.240.9.199$' "$CLAIM/d2k/state/instagram-ip-hosts.tsv" || fail "claim of a pair absent from NDM survived a refresh"
printf 'ip host graph.instagram.com 157.240.9.199\n' >> "$CLAIM/ndmc-state"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$CLAIM/d2k" NDMC_STATE="$CLAIM/ndmc-state" NDMC_CALLS="$CLAIM/ndmc-calls" \
    D2K_INSTAGRAM_LOG="$CLAIM/remove.log" sh "$SCRIPT" remove || fail "remove failed"
grep -q '^ip host graph.instagram.com 157.240.9.199$' "$CLAIM/ndmc-state" || fail "a stale claim removed the user's own later pin"
ok "a claim that never reached NDM is dropped at the next refresh"

# NDM answering an empty configuration with exit 0 is a read failure, not
# "no pins": every owned claim must survive it.
EMPTY="$TMP/empty-show"
mkdir -p "$EMPTY/d2k/state" "$EMPTY/d2k/files" "$EMPTY/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$EMPTY/d2k/files/"
printf 'ip host graph.instagram.com 157.240.9.199\n' > "$EMPTY/ndmc-state"
printf 'graph.instagram.com 157.240.9.199\n' > "$EMPTY/d2k/state/instagram-ip-hosts.tsv"
cp "$EMPTY/d2k/state/instagram-ip-hosts.tsv" "$EMPTY/manifest-before"
if env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$EMPTY/d2k" D2K_META_RANGES="$EMPTY/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve NDMC_EMPTY_SHOW=1 \
    NDMC_STATE="$EMPTY/ndmc-state" NDMC_CALLS="$EMPTY/ndmc-calls" CURL_CALLS="$EMPTY/curl-calls" \
    D2K_INSTAGRAM_LOG="$EMPTY/refresh.log" sh "$SCRIPT" refresh; then
    fail "refresh treated an empty NDM configuration as valid"
fi
cmp -s "$EMPTY/manifest-before" "$EMPTY/d2k/state/instagram-ip-hosts.tsv" || fail "empty NDM read dropped owned claims"
[ ! -s "$EMPTY/ndmc-calls" ] || fail "empty NDM read still changed DNS"
ok "an empty NDM configuration read is a failure and keeps every claim"

# Family fallback: the VPS answer for static.whatsapp.net is dead from the
# router, but a sibling of the same family already verified this refresh
# serves it. Every borrowed address is verified for THIS name; families never
# mix; a candidate failing this name's check is not pinned.
FAM="$TMP/family"
mkdir -p "$FAM/d2k/state" "$FAM/d2k/files" "$FAM/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$FAM/d2k/files/"
: > "$FAM/ndmc-state"
printf 'pps.whatsapp.net 57.144.249.32\n' > "$FAM/d2k/state/instagram-ip-hosts.tsv"
printf 'ip host pps.whatsapp.net 57.144.249.32\n' > "$FAM/ndmc-state"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$FAM/d2k" D2K_META_RANGES="$FAM/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve D2K_IP_PROBE_ATTEMPTS=1 \
    RESOLVE_BODY='{"results":{"instagram.com":["157.240.9.174"],"web.whatsapp.com":["57.144.245.32"],"static.whatsapp.net":["157.240.0.60","157.240.0.63","57.144.247.32"],"mmg.whatsapp.net":["157.240.0.61"],"pps.whatsapp.net":[],"static.xx.fbcdn.net":["157.240.0.62"],"graph.whatsapp.com":["8.8.4.4"]}}' \
    PROBE_DEAD='157.240.0.60 157.240.0.63 157.240.0.61 157.240.0.62 mmg.whatsapp.net:57.144.245.32 mmg.whatsapp.net:57.144.249.32 mmg.whatsapp.net:57.144.247.32' \
    NDMC_STATE="$FAM/ndmc-state" NDMC_CALLS="$FAM/ndmc-calls" CURL_CALLS="$FAM/curl-calls" \
    D2K_INSTAGRAM_LOG="$FAM/refresh.log" sh "$SCRIPT" refresh || { cat "$FAM/refresh.log" >&2; fail "family refresh failed"; }
grep -q '^ip host static.whatsapp.net 57.144.245.32$' "$FAM/ndmc-state" || { cat "$FAM/refresh.log" >&2; fail "static.whatsapp.net did not get a verified sibling address"; }
grep -q -- '--check-instagram-ip static.whatsapp.net 57.144.245.32' "$FAM/curl-calls" || fail "borrowed address was not verified for this name"
grep -q 'адрес семейства' "$FAM/refresh.log" || fail "family fallback is not logged"
grep -q '^static.whatsapp.net 57.144.245.32$' "$FAM/d2k/state/instagram-ip-hosts.tsv" || fail "family pin is not owned"
# An owned sibling pin (pps, from the manifest) is a candidate too.
grep -q -- '--check-instagram-ip static.whatsapp.net 57.144.249.32' "$FAM/curl-calls" || fail "owned sibling address was not tried"
! grep -q '^ip host mmg.whatsapp.net ' "$FAM/ndmc-state" || fail "candidate failing this name's TLS check was pinned"
grep -q -- '--check-instagram-ip mmg.whatsapp.net 57.144.245.32' "$FAM/curl-calls" || fail "mmg.whatsapp.net did not try its family"
! grep -q '^ip host static.xx.fbcdn.net ' "$FAM/ndmc-state" || fail "fbcdn borrowed an address from another family"
! grep -Eq -- '--check-instagram-ip static.xx.fbcdn.net (57.144.245.32|157.240.9.174|57.144.249.32)' "$FAM/curl-calls" || fail "fbcdn was checked against another family's address"
! grep -Eq -- '--check-instagram-ip (www.instagram.com|i.instagram.com) (57.144.245.32|57.144.249.32)' "$FAM/curl-calls" || fail "Instagram borrowed from WhatsApp"
grep -q '^ip host www.instagram.com 157.240.9.174$' "$FAM/ndmc-state" || fail "Instagram sibling without a VPS address did not use its family"
# graph.whatsapp.com: its VPS address is outside Meta ranges and dropped; a
# family address is still range-checked before use.
grep -q '^ip host graph.whatsapp.com 57.144.245.32$' "$FAM/ndmc-state" || fail "graph.whatsapp.com did not use its family after a non-Meta answer"
! grep -q '8.8.4.4' "$FAM/ndmc-calls" || fail "non-Meta address reached ndmc"
grep -q '^ip host static.whatsapp.net 57.144.247.32$' "$FAM/ndmc-state" || fail "working VPS address was lost"
grep -q '^ip host static.whatsapp.net 57.144.249.32$' "$FAM/ndmc-state" || fail "second failed VPS address was not replaced"
[ "$(grep -c '^ip host static.whatsapp.net ' "$FAM/ndmc-state")" -eq 3 ] || fail "expected one direct address and two replacements"
ok "family fallback pins only same-family addresses verified for this very name"

# Addresses outside Meta ranges do not use up the per-name probe tries: a Meta
# address after four junk answers is still tried and pinned.
JUNK="$TMP/junk"
mkdir -p "$JUNK/d2k/state" "$JUNK/d2k/files" "$JUNK/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$JUNK/d2k/files/"
printf 'system name test-router\n' > "$JUNK/ndmc-state"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$JUNK/d2k" D2K_META_RANGES="$JUNK/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve D2K_IP_PROBE_ATTEMPTS=1 \
    RESOLVE_BODY='{"results":{"instagram.com":["8.8.8.8","8.8.4.4","1.1.1.1","9.9.9.9","157.240.9.174"]}}' \
    NDMC_STATE="$JUNK/ndmc-state" NDMC_CALLS="$JUNK/ndmc-calls" CURL_CALLS="$JUNK/curl-calls" \
    D2K_INSTAGRAM_LOG="$JUNK/refresh.log" sh "$SCRIPT" refresh || { cat "$JUNK/refresh.log" >&2; fail "refresh with junk answers failed"; }
grep -q '^ip host instagram.com 157.240.9.174$' "$JUNK/ndmc-state" || fail "non-Meta answers pushed out the real Meta address"
ok "non-Meta answers do not use up the probe tries"

# A refresh that changes nothing does not write the router's flash: NDM's
# configuration is saved only after an add or a removal; the success mark
# carries the date and the time of the success.
SAVE="$TMP/save"
mkdir -p "$SAVE/d2k/state" "$SAVE/d2k/files" "$SAVE/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$SAVE/d2k/files/"
printf 'system name test-router\n' > "$SAVE/ndmc-state"
save_refresh() {
    env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$SAVE/d2k" D2K_META_RANGES="$SAVE/d2k/files/meta-ranges.txt" \
        D2K_RELAY_URL=https://resolve.example/resolve D2K_IP_PROBE_ATTEMPTS=1 \
        RESOLVE_BODY='{"results":{"instagram.com":["157.240.9.174"],"web.whatsapp.com":["57.144.245.32"]}}' \
        NDMC_STATE="$SAVE/ndmc-state" NDMC_CALLS="$SAVE/ndmc-calls" CURL_CALLS="$SAVE/curl-calls" \
        D2K_INSTAGRAM_LOG="$SAVE/refresh.log" sh "$SCRIPT" refresh
}
save_refresh || { cat "$SAVE/refresh.log" >&2; fail "first refresh failed"; }
[ "$(grep -c 'system configuration save' "$SAVE/ndmc-calls")" = 1 ] || fail "a changing refresh did not save NDM exactly once"
[ "$(sed -n 2p "$SAVE/d2k/state/instagram-dns-last-success")" -gt 1700000000 ] 2>/dev/null || fail "success mark lacks the success time"
: > "$SAVE/ndmc-calls"
save_refresh || fail "unchanged refresh failed"
! grep -q 'system configuration save' "$SAVE/ndmc-calls" || fail "a refresh without changes saved NDM configuration (flash write)"
ok "NDM configuration is saved only when a pin changed"

# Each family is pinned on its own: an unverifiable instagram.com keeps the
# Instagram family as it was, but WhatsApp and fbcdn are still refreshed.
FAMS="$TMP/families"
mkdir -p "$FAMS/d2k/state" "$FAMS/d2k/files" "$FAMS/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$FAMS/d2k/files/"
printf 'ip host i.instagram.com 157.240.9.60\n' > "$FAMS/ndmc-state"
printf 'i.instagram.com 157.240.9.60\n' > "$FAMS/d2k/state/instagram-ip-hosts.tsv"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$FAMS/d2k" D2K_META_RANGES="$FAMS/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve D2K_IP_PROBE_ATTEMPTS=1 \
    RESOLVE_BODY='{"results":{"instagram.com":["157.240.9.174"],"i.instagram.com":["157.240.9.63"],"web.whatsapp.com":["57.144.245.32"],"static.xx.fbcdn.net":["157.240.205.11"]}}' \
    PROBE_DEAD='instagram.com:157.240.9.174 instagram.com:157.240.9.60 instagram.com:157.240.9.63' \
    NDMC_STATE="$FAMS/ndmc-state" NDMC_CALLS="$FAMS/ndmc-calls" CURL_CALLS="$FAMS/curl-calls" \
    D2K_INSTAGRAM_LOG="$FAMS/refresh.log" sh "$SCRIPT" refresh || { cat "$FAMS/refresh.log" >&2; fail "refresh without instagram.com failed although WhatsApp/fbcdn verified"; }
grep -q '^ip host web.whatsapp.com 57.144.245.32$' "$FAMS/ndmc-state" || fail "WhatsApp pin depended on instagram.com"
grep -q '^ip host static.xx.fbcdn.net 157.240.205.11$' "$FAMS/ndmc-state" || fail "fbcdn pin depended on instagram.com"
! grep -q '^ip host i.instagram.com 157.240.9.63$' "$FAMS/ndmc-state" || fail "Instagram family pinned without a verified instagram.com"
grep -q '^ip host i.instagram.com 157.240.9.60$' "$FAMS/ndmc-state" || fail "Instagram family pins changed without a verified instagram.com"
grep -q 'семейство instagram' "$FAMS/refresh.log" || fail "skipped Instagram family is not logged"
ok "WhatsApp and fbcdn are pinned independently of instagram.com"

# I3: owned pins heal without the VPS. Each owned pin is re-checked locally;
# a dead one is removed (normal DNS takes over) even when /resolve fails.
HEAL="$TMP/heal"
mkdir -p "$HEAL/d2k/state" "$HEAL/d2k/files" "$HEAL/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$HEAL/d2k/files/"
printf 'ip host instagram.com 157.240.9.174\nip host web.whatsapp.com 57.144.245.32\nip host graph.instagram.com 157.240.9.50\n' > "$HEAL/ndmc-state"
printf 'instagram.com 157.240.9.174\nweb.whatsapp.com 57.144.245.32\n' > "$HEAL/d2k/state/instagram-ip-hosts.tsv"
heal_refresh() {
    env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$HEAL/d2k" D2K_META_RANGES="$HEAL/d2k/files/meta-ranges.txt" \
        D2K_RELAY_URL=https://resolve.example/resolve D2K_IP_PROBE_ATTEMPTS=1 D2K_RESOLVE_RETRY_DELAY=0 \
        RESOLVE_FAIL=1 NDMC_STATE="$HEAL/ndmc-state" NDMC_CALLS="$HEAL/ndmc-calls" CURL_CALLS="$HEAL/curl-calls" \
        D2K_INSTAGRAM_LOG="$HEAL/refresh.log" "$@" sh "$SCRIPT" refresh
}
# Every owned pin dead and no VPS: most likely the router's own uplink, so
# nothing is removed.
if heal_refresh PROBE_FAIL_ALL=1; then fail "refresh without the VPS reported success"; fi
grep -q '^ip host instagram.com 157.240.9.174$' "$HEAL/ndmc-state" || fail "all-dead check without the VPS removed pins (uplink outage)"
grep -q '^ip host web.whatsapp.com 57.144.245.32$' "$HEAL/ndmc-state" || fail "all-dead check without the VPS removed pins (uplink outage)"
# One pin dead, another alive: the dead one goes, the live one stays, a
# user's own record is never touched.
if heal_refresh PROBE_DEAD=157.240.9.174; then fail "refresh without the VPS reported success"; fi
grep -q -- '--check-instagram-ip instagram.com 157.240.9.174' "$HEAL/curl-calls" || fail "owned pin was not re-checked locally"
! grep -q '^ip host instagram.com 157.240.9.174$' "$HEAL/ndmc-state" || { cat "$HEAL/refresh.log" >&2; fail "dead owned pin survived without the VPS"; }
grep -q '^ip host web.whatsapp.com 57.144.245.32$' "$HEAL/ndmc-state" || fail "live owned pin was removed"
grep -q '^ip host graph.instagram.com 157.240.9.50$' "$HEAL/ndmc-state" || fail "a user-owned record was touched"
! grep -q '^instagram.com 157.240.9.174$' "$HEAL/d2k/state/instagram-ip-hosts.tsv" || fail "dead pin still owned in the manifest"
grep -q '^web.whatsapp.com 57.144.245.32$' "$HEAL/d2k/state/instagram-ip-hosts.tsv" || fail "live pin lost from the manifest"
grep -q 'system configuration save' "$HEAL/ndmc-calls" || fail "removal of a dead pin was not saved"
ok "dead owned pins are removed locally without the VPS; an all-dead outage keeps them"

echo "Instagram DNS lifecycle: all checks passed"
