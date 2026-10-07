#!/bin/sh
# files/S99d2k on OpenWrt without Entware: firewall rules through nftables.
# 25.12 ships no iptables at all (07.10.2026: no iptables/ip6tables package
# for aarch64, arm, mipsel, x86_64). Stateful nft double: one file per table,
# a transaction from `nft -f` applies whole or not at all. The real syntax is
# checked on the lab VMs (docs/spec/2026-10-07-openwrt-native.md).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
S99=$ROOT/files/S99d2k
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }

mkdir -p "$TMP/bin" "$TMP/fw" "$TMP/nft" "$TMP/run" "$TMP/proc"
cat > "$TMP/bin/nft" <<'EOF'
#!/bin/sh
# Stateful double: $NFT_STATE/<family>_<table> is the table's text.
printf '%s\n' "$*" >> "$NFT_STATE/calls"
[ "${STUB_NFT_FAIL:-0}" = 0 ] || exit 1
case "$1 ${2:-}" in
    "-f "*)
        f=$2
        # The transaction checks every delete first, then applies.
        while read -r w1 w2 fam name _; do
            [ "$w1 $w2" = "delete table" ] || continue
            [ -e "$NFT_STATE/${fam}_$name" ] || { echo "No such file or directory" >&2; exit 1; }
        done < "$f"
        while read -r w1 w2 fam name _; do
            [ "$w1 $w2" = "delete table" ] && rm -f "$NFT_STATE/${fam}_$name"
        done < "$f"
        awk -v dir="$NFT_STATE" '
            /^table / { out = dir "/" $2 "_" $3; printf "" > out }
            out { print >> out }
            /^}/ { out = "" }' "$f" ;;
    "list table") cat "$NFT_STATE/${3}_$4" 2>/dev/null || exit 1 ;;
    "delete table") [ -e "$NFT_STATE/${3}_$4" ] || exit 1; rm -f "$NFT_STATE/${3}_$4" ;;
    *) exit 0 ;;
esac
EOF
chmod +x "$TMP/bin/nft"
# Leftover rules from an Entware-era install are removed by the same stub
# iptables the iptables test uses: one rule per line, matched verbatim.
cat > "$TMP/bin/iptables" <<'EOF'
#!/bin/sh
tool=$(basename "$0")
table=filter op= chain= spec=
while [ $# -gt 0 ]; do
    case "$1" in
        -w|-n) shift ;;
        -t) table=$2; shift 2 ;;
        -N|-A|-I|-C|-D|-F|-X|-L) op=$1; chain=${2:-}; shift; [ $# -gt 0 ] && shift; break ;;
        -S) op=-S; chain=${2:-}; break ;;
        *) exit 2 ;;
    esac
done
[ $# -eq 0 ] || spec=$(printf '%s ' "$@" | sed -e 's/ $//' -e 's/"//g')
dir=$FW_STATE/$tool/$table
mkdir -p "$dir"
for b in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do [ -e "$dir/$b" ] || : > "$dir/$b"; done
f=$dir/$chain
case "$op" in
    -N) [ ! -e "$f" ] || exit 1; : > "$f"; : > "$f.user" ;;
    -A) [ -e "$f" ] || exit 1; printf '%s\n' "$spec" >> "$f" ;;
    -I) [ -e "$f" ] || exit 1; { printf '%s\n' "$spec"; cat "$f"; } > "$f.new"; mv "$f.new" "$f" ;;
    -C) [ -e "$f" ] && grep -qxF -- "$spec" "$f" ;;
    -D) [ -e "$f" ] && grep -qxF -- "$spec" "$f" || exit 1
        awk -v s="$spec" '!d && $0==s {d=1; next} {print}' "$f" > "$f.new"; mv "$f.new" "$f" ;;
    -F) [ -e "$f" ] || exit 1; : > "$f" ;;
    -X) [ -e "$f.user" ] && [ ! -s "$f" ] || exit 1; rm -f "$f" "$f.user" ;;
    -L) [ -e "$f" ] ;;
    -S) for c in "$dir"/*; do case "$c" in *.user|*.new) continue;; esac
            n=$(basename "$c"); [ -e "$c.user" ] && echo "-N $n"; sed "s/^/-A $n /" "$c"; done ;;
esac
EOF
chmod +x "$TMP/bin/iptables"
ln -s iptables "$TMP/bin/ip6tables"
printf "DISTRIB_ID='OpenWrt'\n" > "$TMP/openwrt_release"

# shellcheck disable=SC2016  # literal text searched for in S99d2k
CASE_LINE=$(grep -n '^case "$1" in' "$S99" | head -1 | cut -d: -f1)
[ -n "$CASE_LINE" ] || fail "S99d2k layout changed"
# The backend is chosen while the file is sourced: keep the doubles on PATH.
head -n "$((CASE_LINE - 1))" "$S99" | sed '/^PATH=/d' > "$TMP/s99funcs.sh"

# The S99d2k functions with the doubles first on PATH. $1 — PATH directory
# with the doubles (iptables can be hidden), then env, the snippet last.
s99() {
    bindir=$1; shift
    # shellcheck disable=SC2016  # expanded by the inner shell
    env FW_STATE="$TMP/fw" NFT_STATE="$TMP/nft" D2K_OPENWRT_RELEASE="$TMP/openwrt_release" \
        D2K_DIR="$TMP/d2k" "$@" sh -c '
        PATH="$2:/usr/bin:/bin"
        . "$1/s99funcs.sh"
        RUN=$1/run; FW_V4ONLY=$RUN/fw-ipv4-only; FW_LOCK=$1/fw.lock; PROC_DIR=$1/proc
        MODE=observe
        eval "$3"' sh "$TMP" "$bindir" "$S99_SNIPPET"
}
# Without iptables: the stock OpenWrt 25.12 case.
mkdir -p "$TMP/nftonly"
ln -s "$TMP/bin/nft" "$TMP/nftonly/nft"
table() { cat "$TMP/nft/inet_$1" 2>/dev/null; }

# --- backend selection -------------------------------------------------------
# shellcheck disable=SC2016  # expanded by the inner shell
S99_SNIPPET='echo "$FW_BACKEND $D2K_FW"'
[ "$(s99 "$TMP/nftonly")" = "nft nft" ] || fail "OpenWrt with nft must pick nft and export D2K_FW for d2kc"
[ "$(s99 "$TMP/bin")" = "nft nft" ] || fail "OpenWrt with Entware iptables must still pick nft"
[ "$(s99 "$TMP/bin" D2K_OPENWRT_RELEASE="$TMP/none")" = "iptables iptables" ] || fail "Keenetic must stay on iptables"
[ "$(s99 "$TMP/bin" FW_BACKEND=iptables)" = "iptables iptables" ] || fail "explicit FW_BACKEND=iptables ignored"
ok "OpenWrt picks nftables, Keenetic stays on iptables, explicit choice wins"

# --- the ruleset ------------------------------------------------------------
S99_SNIPPET='fw_up && fw_installed' s99 "$TMP/nftonly" || fail "nft fw_up failed"
r=$(table d2k)
[ -n "$r" ] || fail "table inet d2k not loaded"
for c in 'chain out {' 'chain in_rules {' 'chain in_forward {' 'chain in_input {' 'chain nat_post {'; do
    printf '%s\n' "$r" | grep -qF "$c" || fail "missing $c"
done
want() { printf '%s\n' "$r" | grep -qF -- "$1" || fail "missing rule: $1"; }
want 'type filter hook postrouting priority mangle; policy accept;'
want 'type filter hook forward priority mangle; policy accept;'
want 'type filter hook input priority mangle; policy accept;'
want 'type nat hook postrouting priority srcnat - 1; policy accept;'
want 'ip saddr 127.0.0.0/8 return'
want 'ip6 daddr ::1 return'
want 'meta nfproto ipv4 fib daddr type broadcast return'
want 'ip daddr 224.0.0.0/4 return'
want 'ip6 daddr ff00::/8 return'
want 'meta mark 0x2d return'
want 'meta mark 0x2f return'
want 'meta l4proto { tcp, udp } th dport { 53, 853 } return'
want 'meta l4proto { tcp, udp } th sport { 53, 853 } return'
want 'meta l4proto tcp ct direction original th dport { 0-65535 } ct original packets 1-8 queue num 2000 bypass'
want 'meta l4proto tcp ct direction original th dport { 0-65535 } ct original packets 9-18446744073709551615 tcp flags & rst == rst queue num 2000 bypass'
want 'meta l4proto tcp ct direction reply th sport { 0-65535 } ct reply packets 9-18446744073709551615 tcp flags & fin == fin queue num 2000 bypass'
want 'meta l4proto tcp ct direction original th dport { 80 } ct original packets 9-18446744073709551615 tcp flags & psh == psh queue num 2000 bypass'
want 'meta l4proto udp ct direction reply th sport { 0-65535 } ct reply packets 1-8 queue num 2000 bypass'
want 'meta l4proto udp ct direction original th dport { 50000-50099, 1400, 3478-3481, 5349, 19294-19344 } ct original packets 1-4 queue num 2000 bypass'
want 'icmp type time-exceeded icmp code 0 queue num 2000 bypass'
want 'icmpv6 type time-exceeded icmpv6 code 0 queue num 2000 bypass'
want 'meta nfproto ipv4 meta l4proto udp meta mark 0x2d masquerade'
want 'jump in_rules'
[ "$(printf '%s\n' "$r" | grep -c 'queue num 2000 bypass')" -eq 13 ] || fail "expected 13 queue rules (6 out, 7 in)"
# Order inside out: exclusions before the first queue rule.
first_queue=$(printf '%s\n' "$r" | grep -n 'queue num' | head -1 | cut -d: -f1)
last_return=$(printf '%s\n' "$r" | sed -n '/chain out {/,/^	}/p' | grep -n 'return' | tail -1 | cut -d: -f1)
[ -n "$last_return" ] && [ -n "$first_queue" ] || fail "cannot locate rules"
printf '%s\n' "$r" | sed -n '/chain out {/,/^	}/p' | awk '/queue num/{q=1} q && /return/{bad=1} END{exit bad}' \
    || fail "a RETURN after a queue rule in chain out"
rst=$(table d2k_rst)
# Ключ — кортеж зонда (порт . цель . порт цели), не один порт (ревью 07.10).
printf '%s\n' "$rst" | grep -qF 'set rst4 { type inet_service . ipv4_addr . inet_service; flags timeout; }' || fail "inet d2k_rst rst4 set"
printf '%s\n' "$rst" | grep -qF 'set rst6 { type inet_service . ipv6_addr . inet_service; flags timeout; }' || fail "inet d2k_rst rst6 set"
printf '%s\n' "$rst" | grep -qF 'type filter hook output priority filter - 1; policy accept;' || fail "rst chain hook"
printf '%s\n' "$rst" | grep -qF 'meta nfproto ipv4 tcp flags & rst == rst tcp sport . ip daddr . tcp dport @rst4 drop' || fail "rst4 drop rule"
printf '%s\n' "$rst" | grep -qF 'meta nfproto ipv6 tcp flags & rst == rst tcp sport . ip6 daddr . tcp dport @rst6 drop' || fail "rst6 drop rule"
# Окно с 1, а не с 0: у потока без расширения учёта (создан при
# nf_conntrack_acct=0, до загрузки таблицы) nft читает счётчик как 0, и окно
# 0-N держало бы его в очереди всю жизнь; connbytes такой поток не берёт.
! printf '%s\n' "$r" | grep -q 'packets 0-' || fail "a window starts at 0: uncounted flows would be queued whole"
ok "inet d2k mirrors the iptables rules; inet d2k_rst holds the probe RST sets"

# Custom ports from the config reach nft syntax.
S99_SNIPPET='PORTS=443,8443:8445; CONNBYTES=0:5; fw_up' s99 "$TMP/nftonly" || fail "custom ports"
table d2k | grep -qF 'th dport { 443, 8443-8445 } ct original packets 1-5 queue' || fail "PORTS/CONNBYTES not converted"
table d2k | grep -qF 'ct original packets 6-18446744073709551615 tcp flags & rst' || fail "late window from CONNBYTES"
S99_SNIPPET='fw_up' s99 "$TMP/nftonly"
ok "PORTS and CONNBYTES from the config are converted to nft ranges"

# --- replace atomically, keep the RST sets ----------------------------------
printf '\t# live probe element\n' >> "$TMP/nft/inet_d2k_rst"
: > "$TMP/nft/calls"
S99_SNIPPET='fw_up' s99 "$TMP/nftonly" || fail "second fw_up"
grep -q 'live probe element' "$TMP/nft/inet_d2k_rst" || fail "fw_up rebuilt inet d2k_rst and dropped live probe elements"
loads=$(grep -c '^-f ' "$TMP/nft/calls")
[ "$loads" -eq 1 ] || fail "rebuild of inet d2k is not one transaction ($loads loads)"
ok "rebuild replaces inet d2k in one transaction and keeps live RST elements"

# --- the watchdog notices a loss --------------------------------------------
S99_SNIPPET='fw_installed' s99 "$TMP/nftonly" || fail "installed rules not recognised"
sed '/icmpv6 type time-exceeded/d' "$TMP/nft/inet_d2k" > "$TMP/x" && mv "$TMP/x" "$TMP/nft/inet_d2k"
if S99_SNIPPET='fw_installed' s99 "$TMP/nftonly"; then fail "a lost queue rule went unnoticed"; fi
S99_SNIPPET='fw_up' s99 "$TMP/nftonly"
rm -f "$TMP/nft/inet_d2k_rst"
if S99_SNIPPET='fw_installed' s99 "$TMP/nftonly"; then fail "a lost inet d2k_rst went unnoticed"; fi
S99_SNIPPET='fw_up' s99 "$TMP/nftonly"
sed 's/queue num 2000/queue num 2001/' "$TMP/nft/inet_d2k" > "$TMP/x" && mv "$TMP/x" "$TMP/nft/inet_d2k"
if S99_SNIPPET='fw_installed' s99 "$TMP/nftonly"; then fail "rules for another queue taken as ours"; fi
S99_SNIPPET='fw_up' s99 "$TMP/nftonly"
rm -f "$TMP/nft/inet_d2k"
if S99_SNIPPET='fw_installed' s99 "$TMP/nftonly"; then fail "a deleted table went unnoticed"; fi
S99_SNIPPET='fw_up && fw_installed' s99 "$TMP/nftonly" || fail "fw_up did not restore the table"
ok "fw_installed sees a lost rule, table, RST table or a foreign queue number"

# --- stop -------------------------------------------------------------------
S99_SNIPPET='fw_down' s99 "$TMP/nftonly"
[ ! -e "$TMP/nft/inet_d2k" ] || fail "fw_down left inet d2k"
[ -e "$TMP/nft/inet_d2k_rst" ] || fail "fw_down (engine restart) removed a running probe's RST table"
S99_SNIPPET='rst_rules_down dead' s99 "$TMP/nftonly"
[ -e "$TMP/nft/inet_d2k_rst" ] || fail "engine stop removed RST elements of a live search"
S99_SNIPPET='rst_rules_down all' s99 "$TMP/nftonly"
[ ! -e "$TMP/nft/inet_d2k_rst" ] || fail "service stop left inet d2k_rst"
printf 'table inet fw4 {\n}\n' > "$TMP/nft/inet_fw4"
S99_SNIPPET='fw_up; fw_down; rst_rules_down all' s99 "$TMP/nftonly"
[ -e "$TMP/nft/inet_fw4" ] || fail "a foreign table was removed"
ok "stop removes only D2K's own tables"

# --- a failed load leaves nothing -------------------------------------------
if S99_SNIPPET='fw_up' s99 "$TMP/nftonly" STUB_NFT_FAIL=1 2>/dev/null; then fail "fw_up ignored an nft failure"; fi
[ ! -e "$TMP/nft/inet_d2k" ] || fail "failed fw_up left a table"
ok "a failed nft transaction is reported"

# --- migration from an Entware-era install ----------------------------------
rm -f "$TMP/nft/inet_"*
S99_SNIPPET='fw_up' s99 "$TMP/bin" FW_BACKEND=iptables || fail "iptables setup for migration"
grep -rq NFQUEUE "$TMP/fw/iptables/mangle" || fail "migration fixture has no iptables rules"
out=$(S99_SNIPPET='fw_up && fw_installed && echo INSTALLED' s99 "$TMP/bin" 2>&1) || { echo "$out" >&2; fail "nft fw_up over iptables rules"; }
printf '%s\n' "$out" | grep -q INSTALLED || fail "migrated rules not recognised"
! grep -rqs 'D2K\|NFQUEUE\|MASQUERADE' "$TMP/fw/iptables" "$TMP/fw/ip6tables" || fail "iptables D2K rules survived the switch to nft"
! printf '%s\n' "$out" | grep -q PPE || fail "PPE (KeeneticOS) touched under nft: $out"
ok "switching an Entware install to nft removes its iptables rules"

# status: the KeeneticOS PPE accelerator lines do not belong on OpenWrt.
out=$(S99_SNIPPET='d2k_ppe_status() { echo PPE-LINE; }; status' s99 "$TMP/nftonly" 2>&1 || true)
! printf '%s\n' "$out" | grep -q PPE-LINE || fail "status prints PPE lines under nft"
out=$(S99_SNIPPET='d2k_ppe_status() { echo PPE-LINE; }; status' s99 "$TMP/bin" FW_BACKEND=iptables 2>&1 || true)
printf '%s\n' "$out" | grep -q PPE-LINE || fail "status lost the PPE lines on Keenetic"
ok "status shows PPE only on the iptables (Keenetic) path"

# --- fw4 flow offloading (лаборатория 07.10, 25.12.5) ------------------------
# С ним поток уходит в flowtable после рукопожатия: в очередь попадало 4-5
# пакетов вместо 17-18, ClientHello клиента D2K не видел. Как ускоритель NAT
# Keenetic: выключается на время работы, прежнее значение возвращается.
cat > "$TMP/nftonly/uci" <<'EOF'
#!/bin/sh
printf 'uci %s\n' "$*" >> "$NFT_STATE/calls"
f=$NFT_STATE/uci-flow
case "$*" in
    "-q get firewall.@defaults[0].flow_offloading") cat "$f" 2>/dev/null || exit 1 ;;
    "set firewall.@defaults[0].flow_offloading="*) echo "${2#*=}" > "$f" ;;
    "commit firewall") ;;
    *) exit 1 ;;
esac
EOF
# shellcheck disable=SC2016  # expanded by the double, not here
printf '#!/bin/sh\nprintf "fw4 %%s\\n" "$*" >> "$NFT_STATE/calls"\n' > "$TMP/nftonly/fw4"
chmod +x "$TMP/nftonly/uci" "$TMP/nftonly/fw4"
echo 1 > "$TMP/nft/uci-flow"
: > "$TMP/nft/calls"
out=$(S99_SNIPPET='flowoffload_off' s99 "$TMP/nftonly" 2>&1)
[ "$(cat "$TMP/nft/uci-flow")" = 0 ] || fail "flow offloading left on"
grep -q '^fw4 reload' "$TMP/nft/calls" || fail "fw4 not reloaded after the change"
printf '%s\n' "$out" | grep -q 'flow offloading' || fail "the change is not reported: $out"
S99_SNIPPET='flowoffload_off' s99 "$TMP/nftonly" >/dev/null 2>&1
S99_SNIPPET='flowoffload_restore' s99 "$TMP/nftonly"
[ "$(cat "$TMP/nft/uci-flow")" = 1 ] || fail "owner's flow offloading not restored (a second start must not overwrite the saved value)"
[ ! -e "$TMP/run/flow-offloading.saved" ] || fail "saved value kept after restore"
# Выключенное владельцем не трогается и не «возвращается» включённым.
echo 0 > "$TMP/nft/uci-flow"; : > "$TMP/nft/calls"
S99_SNIPPET='flowoffload_off; flowoffload_restore' s99 "$TMP/nftonly"
[ "$(cat "$TMP/nft/uci-flow")" = 0 ] || fail "flow offloading switched on by D2K"
! grep -q 'set\|fw4' "$TMP/nft/calls" || fail "untouched setting was rewritten"
# Keenetic (iptables): uci не трогается.
echo 1 > "$TMP/nft/uci-flow"; : > "$TMP/nft/calls"
S99_SNIPPET='flowoffload_off' s99 "$TMP/nftonly" FW_BACKEND=iptables
[ "$(cat "$TMP/nft/uci-flow")" = 1 ] || fail "iptables path changed fw4 settings"
grep -q 'flowoffload_off' "$S99" || fail "engine start does not switch flow offloading off"
grep -q 'flowoffload_restore' "$S99" || fail "engine stop does not restore flow offloading"
ok "fw4 flow offloading is off while D2K runs and the owner's value comes back"

echo "S99d2k nftables (stub): all checks passed"
