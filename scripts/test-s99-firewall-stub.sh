#!/bin/sh
# shellcheck disable=SC2016,SC2094 # dynamic shell fixtures or runtime config
# Unit-level check of files/S99d2k firewall bookkeeping with a stateful
# iptables/ip6tables double: IPv4-only start when ip6tables mangle is
# unusable (I4), and removal of leftover d2k-rst: RST-drop rules on stop.
# No Docker, no root, no netfilter: the real-iptables check stays
# scripts/check_firewall.sh (Docker). The double stores rules verbatim
# (minus "-m tcp" and quotes, as iptables -S normalises them) and matches
# -C/-D exactly, which is what these functions rely on.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
S99=$ROOT/files/S99d2k
TMP=$(mktemp -d)
SLEEPER=
HU_OTHER=
cleanup() {
    [ -z "$SLEEPER" ] || kill "$SLEEPER" 2>/dev/null || true
    [ -z "$HU_OTHER" ] || kill "$HU_OTHER" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }

mkdir -p "$TMP/bin" "$TMP/fw" "$TMP/run" "$TMP/proc"
cat > "$TMP/bin/iptables" <<'EOF'
#!/bin/sh
# Stateful double: $FW_STATE/<tool>/<table>/<chain> holds one rule per line.
tool=$(basename "$0")
table=filter
op= chain=
spec=
wait_lock=0
while [ $# -gt 0 ]; do
    case "$1" in
        -w) wait_lock=1; shift ;;
        -n) shift ;;
        -t) table=$2; shift 2 ;;
        -N|-A|-I|-C|-D|-F|-X|-L) op=$1; chain=${2:-}; shift; [ $# -gt 0 ] && shift; break ;;
        -S) op=-S; chain=${2:-}; break ;;
        -m) # capability probe: `iptables -m u32|connmark --help`; STUB_NO_U32=1 /
            # STUB_NO_CONNMARK=1 — расширения нет
            case "$2" in
                u32) [ "${STUB_NO_U32:-0}" = 1 ] && exit 2 || exit 0 ;;
                connmark) [ "${STUB_NO_CONNMARK:-0}" = 1 ] && exit 2 || exit 0 ;;
                *) echo "stub: unexpected $1 $2" >&2; exit 2 ;;
            esac ;;
        *) echo "stub: unexpected $1" >&2; exit 2 ;;
    esac
done
[ $# -eq 0 ] || spec=$(printf '%s ' "$@" | sed -e 's/ $//' -e 's/-m tcp //' -e 's/"//g')
# Чужой процесс держит блокировку xtables: настоящий iptables 1.4.21 без -w
# отвечает сразу кодом 4, с -w ждёт её (поле 15.10.2026, Keenetic).
if [ "${STUB_XTABLES_BUSY:-0}" = 1 ] && [ "$wait_lock" = 0 ]; then
    echo "Another app is currently holding the xtables lock. Perhaps you want to use the -w option?" >&2
    exit 4
fi
if [ "$tool" = ip6tables ] && [ "$table" = mangle ] && [ "${STUB_V6_MANGLE_BROKEN:-0}" = 1 ]; then
    echo "ip6tables v1.4.21: can't initialize ip6tables table \`mangle': Table does not exist" >&2
    exit 3
fi
case " $spec " in *" ${STUB_FAIL_MATCH:-@none@} "*) [ "$tool" = "${STUB_FAIL_TOOL:-ip6tables}" ] && [ "$op" = -A ] && exit 1;; esac
dir=$FW_STATE/$tool/$table
mkdir -p "$dir"
for builtin in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do [ -e "$dir/$builtin" ] || : > "$dir/$builtin"; done
f=$dir/$chain
case "$op" in
    -N) [ ! -e "$f" ] || exit 1; : > "$f"; : > "$f.user" ;;
    -A) [ -e "$f" ] || exit 1; printf '%s\n' "$spec" >> "$f" ;;
    -I) [ -e "$f" ] || exit 1
        # «-I цепочка 1 …»: номер — позиция, не часть правила (как у iptables -S).
        case "$spec" in [0-9]*' '*) spec=${spec#* } ;; esac
        { printf '%s\n' "$spec"; cat "$f"; } > "$f.new"; mv "$f.new" "$f" ;;
    -C) [ -e "$f" ] && grep -qxF -- "$spec" "$f" ;;
    -D) [ -e "$f" ] && grep -qxF -- "$spec" "$f" || exit 1
        awk -v s="$spec" '!d && $0==s {d=1; next} {print}' "$f" > "$f.new"; mv "$f.new" "$f" ;;
    -F) [ -e "$f" ] || exit 1; : > "$f" ;;
    -X) [ -e "$f.user" ] && [ ! -s "$f" ] || exit 1; rm -f "$f" "$f.user" ;;
    -L) [ -e "$f" ] ;;
    -S) if [ -n "$chain" ]; then
            [ -e "$f" ] || exit 1; sed "s/^/-A $chain /" "$f"
        else
            for c in "$dir"/*; do case "$c" in *.user|*.new) continue;; esac
                n=$(basename "$c"); [ -e "$c.user" ] && echo "-N $n"; sed "s/^/-A $n /" "$c"; done
        fi ;;
esac
EOF
chmod +x "$TMP/bin/iptables"
ln -s iptables "$TMP/bin/ip6tables"

# shellcheck disable=SC2016  # literal text searched for in S99d2k
CASE_LINE=$(grep -n '^case "$1" in' "$S99" | head -1 | cut -d: -f1)
[ -n "$CASE_LINE" ] || fail "S99d2k layout changed: no 'case \"\$1\" in'"
head -n "$((CASE_LINE - 1))" "$S99" > "$TMP/s99funcs.sh"

# Runs a snippet with the S99d2k functions, the doubles first on PATH and
# runtime paths inside the sandbox.
s99() {
    # shellcheck disable=SC2016  # expanded by the inner shell
    env FW_STATE="$TMP/fw" "$@" sh -c '
        . "$1/s99funcs.sh"
        PATH="$1/bin:$PATH"
        STATE_DIR=$1/state; RUN=$1/run; FW_V4ONLY=$RUN/fw-ipv4-only; FW_LOCK=$1/fw.lock; PROC_DIR=$1/proc
        USER_RULES=$STATE_DIR/user-rules
        MODE=observe
        shift; eval "$1"' sh "$TMP" "$S99_SNIPPET"
}
rules() { FW_STATE="$TMP/fw" "$TMP/bin/$1" -t "$2" -S 2>/dev/null; }

# Task7: produce real rule output, then run packet fixtures through both backends.
S99_SNIPPET='D2K_PREFLIGHT=1; MODE=apply; LATE_WATCH=0; VOICE_LATE=0; fw_up && fw_installed; nft_ruleset > "$RUN/nft.rules"' s99 >/dev/null 2>&1 || fail "preflight rules install"
cp "$TMP/run/nft.rules" "$TMP/fw/nft.rules"
python3 "$ROOT/scripts/test-preflight-firewall.py" "$TMP/fw" || fail "preflight packet contracts"
# Numeric aliases of the reserved marks are conflicts too.
if S99_SNIPPET='D2K_PREFLIGHT=1; MARK=49; preflight_validate' s99 >/dev/null 2>&1; then fail "preflight numeric mark collision accepted"; fi
S99_SNIPPET='D2K_PREFLIGHT=1; KEENETIC_POLICY=Policy7;
    policy_mark() { echo 08000042; };
    preflight_validate && [ "$D2K_PREFLIGHT" = 0 ] &&
    [ "$(policy_args 2>/dev/null)" = "--only-mark 0x08000042/0xffffffff" ]' s99 ||
    fail "policy mark collision must keep ordinary processing for the selected policy"
S99_SNIPPET='D2K_PREFLIGHT=1; KEENETIC_POLICY=Policy7;
    policy_mark() { echo 04000042; };
    preflight_validate && [ "$D2K_PREFLIGHT" = 1 ]' s99 ||
    fail "an unrelated policy mark with the release bit must keep preflight enabled"
S99_SNIPPET='D2K_PREFLIGHT=1; KEENETIC_POLICY=Policy7;
    policy_mark() { echo 04000032; };
    preflight_validate && [ "$D2K_PREFLIGHT" = 0 ]' s99 ||
    fail "a policy cannot use the exact preflight SYN release mark"

# Every new iptables rule participates in the existing installed contract.
for chain in D2K_OUT D2K_IN D2K_PFCLR; do
    cp "$TMP/fw/iptables/mangle/$chain" "$TMP/pf-chain"
    while IFS= read -r pf_rule; do
        case "$pf_rule" in *D2K_PFCLR*|*0x08000000*|*0x04000000*|*0x31*|*0x32*|*0x33*|'-j ACCEPT') ;; *) continue ;; esac
        awk -v r="$pf_rule" '$0!=r' "$TMP/pf-chain" > "$TMP/fw/iptables/mangle/$chain"
        if S99_SNIPPET='D2K_PREFLIGHT=1; MODE=apply; LATE_WATCH=0; VOICE_LATE=0; fw_installed' s99 >/dev/null 2>&1; then fail "missing preflight rule accepted: $chain $pf_rule"; fi
        cp "$TMP/pf-chain" "$TMP/fw/iptables/mangle/$chain"
    done < "$TMP/pf-chain"
done
ok "iptables preflight missing rules detected"
# Removing a clear jump changes no queue count, but must trigger repair.
# shellcheck disable=SC2016
S99_SNIPPET='D2K_PREFLIGHT=1; nft_ruleset > "$RUN/nft-good.rules";
    nft_has() { return 0; }; nft() { cat "$RUN/nft-listed.rules"; };
    cp "$RUN/nft-good.rules" "$RUN/nft-listed.rules";
    fw_nft_installed || exit 1;
    for needle in "jump pf_clear" "ct direction original ct mark" "ct direction reply ct mark" "ct mark set ct mark &" "meta mark.*33.*drop" "meta mark set 0x31" "tcp.*31.*masquerade"; do
        sed "/$needle/d" "$RUN/nft-good.rules" > "$RUN/nft-listed.rules";
        if fw_nft_installed; then echo "missing nft preflight rule accepted: $needle"; exit 1; fi;
    done' s99 || fail "nft preflight completeness"
ok "nft preflight missing rules detected"
# shellcheck disable=SC2016  # variables belong to the shell running S99
S99_SNIPPET='D2K_PREFLIGHT=1; FW_BACKEND=nft; mkdir -p "$PROC_DIR/net"; : > "$PROC_DIR/net/if_inet6";
    ip6tables() { printf "%s\n" "$IP6_NAT"; }
    nft() { printf "%s\n" "$NFT_RULES"; }
    IP6_NAT=; NFT_RULES="table inet fw4 {
        chain srcnat {
            meta nfproto ipv4 masquerade
        }
    }";
    preflight_ipv6_available || exit 1;
    D2K_PREFLIGHT_V6=1;
    preflight_family ip6tables || exit 1;
    nft_ruleset > "$RUN/nft-routed.rules";
    grep -qE "^[[:space:]]+meta l4proto tcp ct direction reply ct mark .* queue " "$RUN/nft-routed.rules" || exit 1;
    grep -q "meta nfproto ipv4 meta l4proto tcp meta mark 0x31 masquerade" "$RUN/nft-routed.rules" || exit 1;
    if grep -qE "^[[:space:]]*meta (nfproto ipv6 meta )?l4proto tcp meta mark 0x31 masquerade" "$RUN/nft-routed.rules"; then exit 1; fi;
    IP6_NAT="-A POSTROUTING -s fd00::/64 -o eth0 -j MASQUERADE";
    preflight_ipv6_available || exit 1;
    IP6_NAT="-A POSTROUTING -s fd00::/64 -o eth0 -j SNAT --to-source fd01::1";
    preflight_ipv6_available || exit 1;
    IP6_NAT="-A POSTROUTING -s fd00::/64 -o eth0 -j NETMAP --to fd01::/64";
    preflight_ipv6_available || exit 1;
    IP6_NAT="-A POSTROUTING -s fd00::/64 -p tcp -j SNAT --to-source [fd01::1]:41500-41531";
    if preflight_ipv6_available; then exit 1; fi;
    IP6_NAT="-A POSTROUTING -p tcp -j MASQUERADE --to-ports 41500-41531";
    if preflight_ipv6_available; then exit 1; fi;
    IP6_NAT=; NFT_RULES="table inet fw4 {
        chain srcnat {
            oifname eth0 masquerade
        }
    }";
    preflight_ipv6_available || exit 1;
    NFT_RULES="table ip6 native {
        chain post {
            snat ip6 prefix to ip6 saddr map { fd00::/64 : fd01::/64 }
        }
    }";
    if preflight_ipv6_available; then exit 1; fi;
    NFT_RULES="table ip6 native {
        chain post {
            masquerade to :41500-41531
        }
    }";
    if preflight_ipv6_available; then exit 1; fi;
    rm -f "$PROC_DIR/net/if_inet6"' s99 || fail "IPv6 preflight NAT selection"
ok "IPv6 preflight: routed path, native source NAT and NETMAP; forced port translation excluded"
S99_SNIPPET='D2K_PREFLIGHT=0; fw_down' s99 >/dev/null 2>&1 || fail "preflight stop"
if rules iptables mangle | grep -qE 'D2K_PF|0x(08000000|04000000|31|32|33)'; then fail "preflight_rules_removed_on_stop"; fi
if rules iptables nat | grep -q '0x31'; then fail "preflight NAT remains after stop"; fi
ok "preflight_rules_removed_on_stop"
S99_SNIPPET='D2K_PREFLIGHT=0; MODE=apply; fw_up && fw_installed; nft_ruleset > "$RUN/nft-off.rules"' s99 >/dev/null 2>&1 || fail "preflight off install"
if { rules iptables mangle; rules iptables nat; cat "$TMP/run/nft-off.rules"; } | grep -qE 'D2K_PF|0x(08000000|04000000|31|32|33)|pf_clear'; then fail "preflight_off_no_rules"; fi
ok "preflight_off_no_rules"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1 || fail "preflight off stop"
# nft lifecycle is exercised only through a table-file double, never host nft.
# shellcheck disable=SC2016
S99_SNIPPET='FW_BACKEND=nft; D2K_PREFLIGHT=1; MODE=apply; LATE_WATCH=0; VOICE_LATE=0;
    nft() { case "$1" in
        list) [ -s "$RUN/nft-table" ] && cat "$RUN/nft-table" ;;
        -f) cp "$2" "$RUN/nft-table" ;;
        delete) rm -f "$RUN/nft-table" ;;
        *) return 2 ;;
    esac; };
    fw_up && fw_installed || exit 1;
    D2K_PREFLIGHT=0; fw_down || exit 1;
    [ ! -e "$RUN/nft-table" ]' s99 >/dev/null 2>&1 || fail "nft preflight_rules_removed_on_stop"
ok "nft preflight_rules_removed_on_stop"
[ "${TASK07_ONLY:-0}" != 1 ] || exit 0

# A new service invocation must resolve auto modes before checking rules.
S99_SNIPPET='MODE=apply; fw_up && fw_installed' s99 >/dev/null 2>&1 || fail "initial auto rules"
for tool in iptables ip6tables; do
    for chain in D2K_OUT D2K_IN; do
        for match in 'connmark --mark 0x40000000' '-m u32' '-j D2K_LATE_'; do
            rule_file=$TMP/fw/$tool/mangle/$chain
            cp "$rule_file" "$TMP/saved-rule-chain"
            awk -v s="$match" 'index($0,s)==0' "$rule_file" > "$rule_file.new"
            mv "$rule_file.new" "$rule_file"
            if S99_SNIPPET='MODE=apply; fw_installed' s99 >/dev/null 2>&1; then
                fail "missing $tool $chain $match accepted as complete"
            fi
            cp "$TMP/saved-rule-chain" "$rule_file"
            S99_SNIPPET='MODE=apply; fw_installed' s99 >/dev/null 2>&1 || fail "restored rules rejected"
        done
    done
done
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
ok "late delivery and STUN rules checked in both directions and families"

# --- ЖИВОСТЬ ПОСЛЕ ЗАПУСКА: PID-ФАЙЛ НЕ ЕДИНСТВЕННЫЙ СВИДЕТЕЛЬ -------------
# Поле 13.10.2026, OpenWrt 25.12 (mipsel): служба объявила «контроллер
# завершился сразу после запуска», а журнал контроллера говорит «запущен,
# сокет …» и следом «останавливаюсь» — остановили его мы. Проверялся один раз
# pid-файл чужого start-stop-daemon. Живой процесс обязан быть признан живым.
mkdir -p "$TMP/proc/4242"
echo d2kc > "$TMP/proc/4242/comm"
echo "4242 (d2kc) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0" > "$TMP/proc/4242/stat"
echo 99999 > "$TMP/run/d2kc.pid"   # номер мёртвого процесса
# shellcheck disable=SC2016  # $RUN раскрывает ВНУТРЕННЯЯ оболочка, не эта
S99_SNIPPET='wait_running "$RUN/d2kc.pid" d2kc' s99 >/dev/null 2>&1 \
    || fail "живой процесс по имени не признан живым"
[ "$(cat "$TMP/run/d2kc.pid")" = "4242" ] \
    || fail "pid-файл не поправлен на живой номер: $(cat "$TMP/run/d2kc.pid")"
# Процесса нет вовсе — отказ, а не выдумка.
rm -rf "$TMP/proc/4242"
echo 99999 > "$TMP/run/d2kc.pid"
# shellcheck disable=SC2016  # то же: раскрытие во внутренней оболочке
if S99_SNIPPET='wait_running "$RUN/d2kc.pid" d2kc' s99 >/dev/null 2>&1; then
    fail "wait_running признал живым то, чего нет"
fi
ok "живой процесс признаётся живым даже с негодным pid-файлом"

# --- ПРИЧИНА ОТКАЗА ЗАПУСКА — ИЗ ЖУРНАЛА УПАВШЕГО ---------------------------
# Поле 13.10.2026: у пользователя служба сказала «контроллер завершился сразу
# после запуска» и замолчала, хотя причина лежала в его же журнале строкой
# ниже. Диагноз пришлось воспроизводить под QEMU вместо того, чтобы прочитать.
mkdir -p "$TMP/log"
printf 'd2kc: каталога нет — начинаю с пустого\nd2kc: связь с датапатом: No such file or directory\n' \
    > "$TMP/log/d2kc.log"
out=$(S99_SNIPPET='die_with_log "контроллер завершился сразу после запуска" "'"$TMP"'/log/d2kc.log"' \
    s99 2>&1) && fail "die_with_log вернул успех"
printf '%s\n' "$out" | grep -q 'контроллер завершился сразу после запуска' \
    || fail "die_with_log не назвал сам отказ: $out"
printf '%s\n' "$out" | grep -q 'связь с датапатом' \
    || fail "die_with_log не показал причину из журнала: $out"
: > "$TMP/log/empty.log"
out=$(S99_SNIPPET='die_with_log "движок не встал" "'"$TMP"'/log/empty.log"' s99 2>&1) \
    && fail "die_with_log на пустом журнале вернул успех"
printf '%s\n' "$out" | grep -q 'журнал .* пуст' \
    || fail "пустой журнал не назван пустым: $out"
ok "отказ запуска печатает причину из журнала упавшего"

# --- I4: ip6tables mangle unusable → IPv4-only, with a clear warning --------
S99_SNIPPET='fw_up && fw_installed' s99 || fail "baseline fw_up failed"
rules ip6tables mangle | grep -q -- '-N D2K_OUT' || fail "baseline did not set up IPv6"
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "IPv4-only marker without a reason"
S99_SNIPPET='fw_down' s99
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"

out=$(S99_SNIPPET='fw_up && fw_installed && echo INSTALLED' s99 STUB_V6_MANGLE_BROKEN=1 2>&1) \
    || { echo "$out" >&2; fail "fw_up refused to start without ip6tables mangle"; }
printf '%s\n' "$out" | grep -q 'только по IPv4' || fail "no clear IPv4-only warning: $out"
printf '%s\n' "$out" | grep -q INSTALLED || fail "fw_installed rejects the IPv4-only state"
[ -e "$TMP/run/fw-ipv4-only" ] || fail "IPv4-only state is not recorded"
rules iptables mangle | grep -q -- '-A POSTROUTING -j D2K_OUT' || fail "IPv4 rules missing in IPv4-only mode"
rules iptables mangle | grep -q -- '--queue-bypass' || fail "IPv4 queue rules missing in IPv4-only mode"
# The heal watchdog still notices an IPv4 rule removed by NDM.
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -D FORWARD -j D2K_IN
if S99_SNIPPET='fw_installed' s99 STUB_V6_MANGLE_BROKEN=1; then fail "IPv4-only fw_installed missed a removed IPv4 jump"; fi
S99_SNIPPET='fw_down' s99 STUB_V6_MANGLE_BROKEN=1
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "fw_down kept the IPv4-only marker"
[ -z "$(rules iptables mangle | grep D2K || true)" ] || fail "fw_down left IPv4 rules in IPv4-only mode"
if S99_SNIPPET='fw_installed' s99 STUB_V6_MANGLE_BROKEN=1; then fail "fw_installed true after fw_down"; fi
ok "without ip6tables mangle the service runs IPv4-only and says so"

# --- ICMP time-exceeded на свои фальшивки (поле 04.10.2026, icmp-rua.pcap) --
# В очередь — только TTL-истечение в пути (11/0, ICMPv6 3/0), только в
# ответной цепочке, с --queue-bypass; потеря правила видна сторожу; fw_down
# снимает его вместе с цепочкой.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 || fail "fw_up with the ICMP rule failed"
for tool in iptables ip6tables; do
    rules "$tool" mangle | grep -qx -- '-A D2K_IN -p tcp -m conntrack --ctdir REPLY -m multiport --sports 80 -m connbytes --connbytes 9: --connbytes-dir reply --connbytes-mode packets -j NFQUEUE --queue-num 2000 --queue-bypass' || fail "$tool: late HTTP replies are invisible"
done
rules iptables mangle | grep -qx -- '-A D2K_IN -p icmp --icmp-type 11/0 -j NFQUEUE --queue-num 2000 --queue-bypass' \
    || fail "IPv4 time-exceeded is not queued in D2K_IN"
rules ip6tables mangle | grep -qx -- '-A D2K_IN -p ipv6-icmp --icmpv6-type 3/0 -j NFQUEUE --queue-num 2000 --queue-bypass' \
    || fail "ICMPv6 time-exceeded is not queued in D2K_IN"
[ "$(rules iptables mangle | grep -c icmp)" -eq 1 ] || fail "IPv4: more than the one time-exceeded ICMP rule"
[ "$(rules ip6tables mangle | grep -c icmp)" -eq 1 ] || fail "IPv6: more than the one time-exceeded ICMP rule"
! rules iptables mangle | grep -- '-A D2K_OUT' | grep -q icmp || fail "ICMP rule leaked into D2K_OUT"
for tool in iptables ip6tables; do
    if [ "$tool" = iptables ]; then
        FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -D D2K_IN -p icmp --icmp-type 11/0 \
            -j NFQUEUE --queue-num 2000 --queue-bypass
    else
        FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -D D2K_IN -p ipv6-icmp --icmpv6-type 3/0 \
            -j NFQUEUE --queue-num 2000 --queue-bypass
    fi
    if S99_SNIPPET='fw_installed' s99; then fail "$tool: a lost ICMP rule went unnoticed"; fi
    S99_SNIPPET='fw_up' s99 || fail "$tool: fw_up did not restore the ICMP rule"
    S99_SNIPPET='fw_installed' s99 || fail "$tool: restored rules not recognised"
done
S99_SNIPPET='fw_down' s99
! rules iptables mangle | grep -q icmp || fail "fw_down left the IPv4 ICMP rule"
! rules ip6tables mangle | grep -q icmp || fail "fw_down left the IPv6 ICMP rule"
ok "time-exceeded ICMP is queued with bypass in both families and removed on stop"

# --- Проброс портов (issue #23, Keenetic) ------------------------------------
# Соединение С WAN на проброшенный порт идёт по conntrack в направлении
# ORIGINAL и проходит POSTROUTING: правило D2K_OUT «--ctdir ORIGINAL» брало
# его как исходящее из LAN, и проброс на NAS переставал работать. Такие
# соединения несут признак DNAT в обоих направлениях. Исключение — в обеих
# цепочках, раньше любого правила очереди; сторож замечает его пропажу.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 || fail "fw_up with the DNAT exclusion failed"
for tool in iptables ip6tables; do
    for ch in D2K_OUT D2K_IN; do
        rules "$tool" mangle | grep -- "-A $ch " | awk -v ch="$ch" '
            $0 == "-A " ch " -m conntrack --ctstate DNAT -j RETURN" { if (!q) seen = 1 }
            /NFQUEUE/ { q = 1 }
            END { exit !seen }' \
            || fail "$tool $ch: no DNAT RETURN before the first queue rule (port forwards get queued)"
    done
    FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -D D2K_OUT -m conntrack --ctstate DNAT -j RETURN
    if S99_SNIPPET='fw_installed' s99; then fail "$tool: a lost DNAT exclusion went unnoticed"; fi
    S99_SNIPPET='fw_up' s99 || fail "$tool: fw_up did not restore the DNAT exclusion"
done
S99_SNIPPET='fw_down' s99
ok "port-forwarded (DNAT) connections never enter the queue, in both directions"

# --- Проводник установки на VPS — канал самого D2K, не цель ------------------
# Поле 14.10.2026: туннель CONNECT к 85.192.60.175:9444 датапат принял за
# поток к «github.com», и контроллер начал искать обход своему же каналу.
# RETURN в обе стороны, раньше очереди, только IPv4; сторож замечает пропажу;
# пустой D2K_GATE исключение снимает.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 || fail "fw_up with the gate exclusion failed"
for spec in "D2K_OUT -p tcp -d 85.192.60.175 --dport 9444 -j RETURN" \
            "D2K_IN -p tcp -s 85.192.60.175 --sport 9444 -j RETURN"; do
    ch=${spec%% *}
    rules iptables mangle | grep -- "-A $ch " | awk -v want="-A $spec" '
        $0 == want { if (!q) seen = 1 }
        /NFQUEUE/ { q = 1 }
        END { exit !seen }' || fail "iptables $ch: no gate RETURN before the first queue rule"
done
if rules ip6tables mangle | grep -q '85.192.60.175'; then fail "ip6tables must not carry an IPv4 gate rule"; fi
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -D D2K_OUT -p tcp -d 85.192.60.175 --dport 9444 -j RETURN
if S99_SNIPPET='fw_installed' s99; then fail "a lost gate exclusion went unnoticed"; fi
S99_SNIPPET='fw_up' s99 || fail "fw_up did not restore the gate exclusion"
S99_SNIPPET='fw_down' s99
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 D2K_GATE= || fail "fw_up without a gate failed"
if rules iptables mangle | grep -q '9444'; then fail "empty D2K_GATE must leave no gate rule"; fi
S99_SNIPPET='fw_down' s99 D2K_GATE=
ok "the VPS install gate is D2K's own channel: never queued, in both directions"

# --- DNS роутера — не цель (поле 15.10.2026) ---------------------------------
# Keenetic резолвит через DoH (https-dns-proxy → geohide.ru:443). Поток к нему
# шёл через очередь D2K как обычный TLS; прокси при всплесках падал «too
# many». DNS роутера, какой ни заведён (DoH, DoT, обычный на нестандартном
# порту), исключается по адресу и порту из `ndmc show dns-proxy`: RETURN в
# обе стороны, раньше очереди, TCP и UDP. Адреса DoH сверяются на каждом
# круге сторожа; неразрешившееся имя прежних правил не снимает.
cat > "$TMP/bin/ndmc" <<'NDMC'
#!/bin/sh
printf '\033[K\n     proxy-status: \n              proxy-name: System\n\n'
printf 'timeout = 7000\n'
printf 'dns_server = 127.0.0.1:40508 . # https://doh.test/dns-query@dnsm\n'
printf 'dns_server = 127.0.0.1:40500 . # 9.9.9.9:853@dns.quad9.net\n'
printf 'dns_server = 192.0.2.53:5353 .\n'
printf 'static_a = my.keenetic.net 198.51.100.11 1\n'
[ ! -f "$NSL_FAIL" ] || printf 'static_a = doh.test 198.51.100.9 0\n'
NDMC
cat > "$TMP/bin/nslookup" <<'NSL'
#!/bin/sh
[ "$1" = doh.test ] || exit 1
[ -f "$NSL_FAIL" ] && exit 1
printf 'Server:    127.0.0.1\nAddress 1: 127.0.0.1 localhost\n\nName:      doh.test\n'
i=1; for a in $(cat "$NSL_ADDRS"); do printf 'Address %d: %s\n' $i "$a"; i=$((i+1)); done
NSL
chmod +x "$TMP/bin/ndmc" "$TMP/bin/nslookup"
printf '198.51.100.7\n2001:db8::7\n' > "$TMP/nsl-addrs"
dns_before_queue() { # <tool> <chain> <spec>
    rules "$1" mangle | grep -- "-A $2 " | awk -v want="-A $2 $3" '
        $0 == want { if (!q) seen = 1 }
        /NFQUEUE/ { q = 1 }
        END { exit !seen }'
}
rm -rf "$TMP/fw" "$TMP/run/dns-excl"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail" \
    || fail "fw_up with router DNS exclusions failed"
for want in "iptables 198.51.100.7 443" "ip6tables 2001:db8::7 443" "iptables 9.9.9.9 853" \
            "iptables 192.0.2.53 5353"; do
    # Разбиение по словам намеренное: «инструмент адрес порт» в одной строке.
    # shellcheck disable=SC2086
    set -- $want
    for pr in tcp udp; do
        dns_before_queue "$1" D2K_OUT "-p $pr -d $2 --dport $3 -m mark ! --mark 0x2e -j RETURN" \
            || fail "$1: no $pr RETURN to router DNS $2:$3 before the queue"
        dns_before_queue "$1" D2K_IN "-p $pr -s $2 --sport $3 -j RETURN" \
            || fail "$1: no $pr RETURN from router DNS $2:$3 before the queue"
    done
done
if rules iptables mangle | grep -q '127.0.0.1 --dport 40508\|198.51.100.11'; then
    fail "local proxy port or static_a records must not become exclusions"
fi
# DoH сменил адрес — старое снято, новое стоит.
printf '198.51.100.8\n' > "$TMP/nsl-addrs"
S99_SNIPPET='dns_excl_sync' s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail"
dns_before_queue iptables D2K_OUT "-p tcp -d 198.51.100.8 --dport 443 -m mark ! --mark 0x2e -j RETURN" \
    || fail "a new DoH address was not excluded"
if rules iptables mangle | grep -q '198.51.100.7'; then fail "a stale DoH address stayed excluded"; fi
if rules ip6tables mangle | grep -q '2001:db8::7'; then fail "a stale IPv6 DoH address stayed excluded"; fi
# Имя сейчас не разрешилось — прежнее исключение остаётся.
: > "$TMP/nsl-fail"
S99_SNIPPET='dns_excl_sync' s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail"
dns_before_queue iptables D2K_OUT "-p tcp -d 198.51.100.8 --dport 443 -m mark ! --mark 0x2e -j RETURN" \
    || fail "a failed lookup removed the DoH exclusion"
dns_before_queue iptables D2K_OUT "-p tcp -d 198.51.100.9 --dport 443 -m mark ! --mark 0x2e -j RETURN" \
    || fail "the configured bootstrap address was lost when DNS failed"
rm -f "$TMP/nsl-fail"
# Сброс извне снёс исключение — круг сторожа его возвращает.
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -D D2K_OUT -p tcp -d 9.9.9.9 --dport 853 -m mark ! --mark 0x2e -j RETURN
S99_SNIPPET='dns_excl_sync' s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail"
dns_before_queue iptables D2K_OUT "-p tcp -d 9.9.9.9 --dport 853 -m mark ! --mark 0x2e -j RETURN" \
    || fail "the watchdog round did not restore a lost DNS exclusion"
# Explicitly measured DoH must not be hidden from the datapath.
mkdir -p "$TMP/state"
printf 'doh.test 443 /dns-query 198.51.100.8\n' > "$TMP/state/doh-targets"
S99_SNIPPET='dns_excl_sync' s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail"
if rules iptables mangle | grep -q '198.51.100.8'; then fail "selected DoH stayed excluded"; fi
dns_before_queue iptables D2K_OUT "-p tcp -d 9.9.9.9 --dport 853 -m mark ! --mark 0x2e -j RETURN" || fail "unrelated DNS exclusion removed"
rm -f "$TMP/state/doh-targets"
S99_SNIPPET='dns_excl_sync' s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail"
printf 'doh.test 198.51.100.8 443 tcp\n' > "$TMP/run/dns-routes"
S99_SNIPPET='dns_excl_sync' s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail"
rules iptables mangle | grep -q -- '-A OUTPUT -p tcp -d 198.51.100.8 --dport 443 -m mark --mark 0 -m comment --comment d2k-dns-route -j MARK --set-xmark 0x2e/0xffffffff' || fail "router DNS cannot use its recovery program with a selected client policy"
dns_before_queue iptables D2K_OUT "-p tcp -d 198.51.100.8 --dport 443 -m mark ! --mark 0x2e -j RETURN" \
    || fail "automatic DoH recovery removed the forwarded TCP protection"
dns_before_queue iptables D2K_IN "-p tcp -s 198.51.100.8 --sport 443 -j RETURN" \
    || fail "automatic DoH recovery admitted forwarded TCP replies"
rules iptables mangle | grep -q -- '-A INPUT -p tcp -s 198.51.100.8 --sport 443 -m comment --comment d2k-dns-route -j NFQUEUE --queue-num 2000 --queue-bypass' \
    || fail "automatic DoH did not admit its local reply"
dns_before_queue iptables D2K_OUT "-p udp -d 198.51.100.8 --dport 443 -m mark ! --mark 0x2e -j RETURN" || fail "automatic TCP recovery removed UDP protection"
dns_before_queue iptables D2K_OUT "-p tcp -d 9.9.9.9 --dport 853 -m mark ! --mark 0x2e -j RETURN" || fail "automatic recovery touched a healthy upstream"
: > "$TMP/run/dns-routes"
S99_SNIPPET='dns_excl_sync' s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail"
dns_before_queue iptables D2K_OUT "-p tcp -d 198.51.100.8 --dport 443 -m mark ! --mark 0x2e -j RETURN" || fail "retired DNS recovery did not restore protection"
rm -f "$TMP/run/dns-routes"
S99_SNIPPET='dns_local_route_rule -A 192.0.2.90 853; user_rules_save' s99
if grep -q 'd2k-dns-route' "$TMP/state/user-rules"; then fail "owned DNS route was saved as an owner rule"; fi
S99_SNIPPET='fw_down'  s99 NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail"
if rules iptables mangle | grep -q 'd2k-dns-route'; then fail "stop left owned local DNS route rules"; fi
rm -f "$TMP/bin/ndmc" "$TMP/bin/nslookup" "$TMP/run/dns-excl"
ok "router DNS servers (DoH, DoT, plain) from ndmc are excluded both ways, kept fresh"

# A working ip6tables whose rule fails half-way is still a real error: both
# families roll back, as before.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
if S99_SNIPPET='fw_up' s99 STUB_FAIL_MATCH=connbytes STUB_FAIL_TOOL=ip6tables >/dev/null 2>&1; then
    fail "a failing IPv6 rule was taken for a missing IPv6 table"
fi
[ -z "$(rules iptables mangle | grep D2K || true)$(rules ip6tables mangle | grep D2K || true)" ] \
    || fail "partial IPv6 failure did not roll back both families"
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "partial IPv6 failure set IPv4-only"
ok "a partial IPv6 failure still rolls back both families"

# Прошивка без xt_addrtype (поле 03.10.2026, Keenetic mipsel 3.4_kn: «No
# chain/target/match by that name», служба не запускалась): исключения
# ставятся явными адресами, служба стартует и проверка правил её принимает.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
out=$(S99_SNIPPET='fw_up && fw_installed && echo INSTALLED' s99 STUB_FAIL_MATCH=addrtype STUB_FAIL_TOOL=iptables 2>&1) \
    || { echo "$out" >&2; fail "fw_up refused to start without xt_addrtype"; }
printf '%s\n' "$out" | grep -q INSTALLED || { echo "$out" >&2; fail "rules without xt_addrtype not accepted as installed"; }
printf '%s\n' "$out" | grep -q "нет xt_addrtype" || fail "missing xt_addrtype not reported"
rules iptables mangle | grep -qx -- "-A D2K_OUT -d 255.255.255.255 -j RETURN" || fail "explicit broadcast RETURN missing"
! rules iptables mangle | grep -q addrtype || fail "addrtype rule present although unsupported"
ok "without xt_addrtype the service starts with explicit broadcast exclusions"

# --- Блокировка xtables занята чужим процессом (поле 15.10.2026) -------------
# Сразу после запуска Telegram и разгрузка PPE работают с iptables
# одновременно со сторожем. iptables без -w на занятой блокировке отвечает
# кодом 4 (на роутере 18 из 300 проверок): fw_installed принимал это за
# пропажу правил, сторож звал reapply, тот падал на том же и снимал всё —
# установка 15.10 оставила роутер без единого правила на 55 с.
S99_SNIPPET='fw_up && fw_installed' s99 STUB_XTABLES_BUSY=1 \
    || fail "busy xtables lock: fw_up/fw_installed must wait for it, not fail"
S99_SNIPPET='fw_down' s99 STUB_XTABLES_BUSY=1
for tool in iptables ip6tables; do
    if rules "$tool" mangle | grep -q 'NFQUEUE'; then fail "$tool: fw_down left queue rules under a busy lock"; fi
done
ok "a busy xtables lock is waited for, not mistaken for missing rules"

# Модули ядра лежат файлами в прошивке, но не загружены (Keenetic: modprobe из
# Entware ищет в /opt/lib/modules) — служба загружает их сама через insmod.
# Уже доступные (в /proc/net/ip_tables_matches) не трогаются.
mkdir -p "$TMP/mods/9.9-test" "$TMP/proc/net"
for m in xt_addrtype xt_comment xt_conntrack nf_conntrack_netlink xt_mark; do : > "$TMP/mods/9.9-test/$m.ko"; done
mkdir -p "$TMP/sysmod/xt_mark"   # встроен в ядро: есть в /sys/module, нет в lsmod
printf 'multiport\nconnbytes\nmark\nconnmark\n' > "$TMP/proc/net/ip_tables_matches"
printf 'NFQUEUE\nCONNMARK\n' > "$TMP/proc/net/ip_tables_targets"
cat > "$TMP/bin/uname" <<'EOF2'
#!/bin/sh
echo 9.9-test
EOF2
cat > "$TMP/bin/modprobe" <<'EOF2'
#!/bin/sh
exit 1
EOF2
cat > "$TMP/bin/insmod" <<'EOF2'
#!/bin/sh
echo "$1" >> "$INSMOD_LOG"
EOF2
cat > "$TMP/bin/lsmod" <<'EOF2'
#!/bin/sh
exit 0
EOF2
chmod +x "$TMP/bin/uname" "$TMP/bin/modprobe" "$TMP/bin/insmod" "$TMP/bin/lsmod"
: > "$TMP/insmod.log"
out=$(S99_SNIPPET='load_modules' s99 D2K_MODULES_DIR="$TMP/mods" D2K_SYS_MODULE_DIR="$TMP/sysmod" INSMOD_LOG="$TMP/insmod.log" 2>&1) || { echo "$out" >&2; fail "load_modules failed"; }
for m in xt_addrtype xt_comment xt_conntrack nf_conntrack_netlink; do
    grep -q "/$m.ko$" "$TMP/insmod.log" || fail "$m not loaded from the firmware tree"
done
! grep -q "multiport\|connbytes\|NFQUEUE\|xt_mark" "$TMP/insmod.log" || fail "an already available module was reloaded"
printf '%s\n' "$out" | grep -q "загружен модуль ядра xt_addrtype" || fail "module load not reported"
rm -f "$TMP/bin/uname" "$TMP/bin/modprobe" "$TMP/bin/insmod" "$TMP/bin/lsmod"
ok "kernel modules present as files are loaded by the service itself"

# --- Leftover d2k-rst: rules (filter OUTPUT, both families) ------------------
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
sleep 300 >/dev/null 2>&1 & SLEEPER=$!
dead=999990
while kill -0 "$dead" 2>/dev/null; do dead=$((dead + 1)); done
mkdir -p "$TMP/proc/$$" "$TMP/proc/$SLEEPER"
printf 'd2k-detect\n' > "$TMP/proc/$$/comm"     # a live d2k process
printf 'sshd\n' > "$TMP/proc/$SLEEPER/comm"      # a live foreign process
for tool in iptables ip6tables; do
    t() { FW_STATE="$TMP/fw" "$TMP/bin/$tool" -w "$@"; }
    t -A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40751 --tcp-flags RST RST -m comment --comment "d2k-rst:$$" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40752 --tcp-flags RST RST -m comment --comment "d2k-rst:$SLEEPER" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40753 --tcp-flags RST RST -m comment --comment "other:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 22 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40754 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j ACCEPT
done
# engine stop: only rules whose owner is gone (a live search keeps its own).
S99_SNIPPET='rst_rules_down dead' s99
for tool in iptables ip6tables; do
    r=$(rules "$tool" filter)
    ! printf '%s\n' "$r" | grep -q -- "--sport 40750 " || fail "$tool: rule of a dead owner survived engine stop"
    printf '%s\n' "$r" | grep -q -- "--sport 40751 " || fail "$tool: engine stop removed a live d2k process's rule"
done
# service stop / uninstall: every d2k-owned rule goes; foreign ones stay.
S99_SNIPPET='rst_rules_down all' s99
for tool in iptables ip6tables; do
    r=$(rules "$tool" filter)
    ! printf '%s\n' "$r" | grep -q -- "--sport 40751 " || fail "$tool: rule of a live d2k process survived service stop"
    printf '%s\n' "$r" | grep -q -- "--sport 40752 " || fail "$tool: rule owned by a non-d2k process was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 40753 " || fail "$tool: rule with a foreign comment was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 22 " || fail "$tool: rule outside the d2k port range was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 40754 " || fail "$tool: rule with another target was removed"
done
grep -q 'rst_rules_down dead' "$S99" || fail "engine_stop does not clean dead-owner RST rules"
grep -q 'rst_rules_down all' "$S99" || fail "stop does not clean d2k RST rules"
ok "stop removes leftover d2k-rst: rules in both families and nothing else"

# --- Миграция с прокси d2khttp (задача 51) ------------------------------------
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
v4() { FW_STATE="$TMP/fw" "$TMP/bin/iptables" -w "$@"; }
v4 -t nat -N D2K_HTTP
v4 -t nat -A D2K_HTTP -p tcp --dport 80 -j REDIRECT --to-ports 18080
v4 -t nat -I PREROUTING -j D2K_HTTP
v4 -t mangle -N D2K_HTTP_MARK
v4 -t mangle -A D2K_HTTP_MARK -m mark --mark 0x30 -j CONNMARK --save-mark
v4 -t mangle -I OUTPUT -j D2K_HTTP_MARK
v4 -t nat -A PREROUTING -j FOREIGN_NAT
S99_SNIPPET='fw_up && fw_installed' s99 || fail "fw_up over the old d2khttp rules failed"
! rules iptables nat | grep -q D2K_HTTP || fail "old nat D2K_HTTP survived fw_up"
! rules iptables mangle | grep -q D2K_HTTP_MARK || fail "old D2K_HTTP_MARK survived fw_up"
rules iptables nat | grep -qx -- '-A PREROUTING -j FOREIGN_NAT' || fail "migration removed a foreign nat rule"
! rules iptables mangle | grep -q 18080 || fail "the :18080 proxy exclusion is still installed"
! rules iptables nat | grep -q REDIRECT || fail "a port-80 REDIRECT is still installed"
S99_SNIPPET='fw_down' s99
ok "fw_up removes the old d2khttp nat/mangle rules and adds none"

# Старый pid-файл d2khttp: гасится только процесс с именем d2khttp (ревью M3).
sleep 300 >/dev/null 2>&1 & HU_OTHER=$!
mkdir -p "$TMP/proc/$HU_OTHER"
printf 'sshd\n' > "$TMP/proc/$HU_OTHER/comm"
printf '%s\n' "$HU_OTHER" > "$TMP/run/d2k-http.pid"
# shellcheck disable=SC2016  # раскрывает S99d2k, не этот скрипт
if S99_SNIPPET='HU_PID=$RUN/d2k-http.pid; legacy_http_present' s99; then
    kill "$HU_OTHER"; fail "a reused pid of a foreign process counted as d2khttp"
fi
# shellcheck disable=SC2016  # раскрывает S99d2k, не этот скрипт
S99_SNIPPET='HU_PID=$RUN/d2k-http.pid; legacy_http_stop' s99
kill -0 "$HU_OTHER" 2>/dev/null || fail "legacy cleanup killed a foreign process by a stale pid"
[ ! -e "$TMP/run/d2k-http.pid" ] || fail "stale d2khttp pid file kept"
printf 'd2khttp\n' > "$TMP/proc/$HU_OTHER/comm"
printf '%s\n' "$HU_OTHER" > "$TMP/run/d2k-http.pid"
# shellcheck disable=SC2016  # раскрывает S99d2k, не этот скрипт
S99_SNIPPET='HU_PID=$RUN/d2k-http.pid; legacy_http_present' s99 || fail "a live d2khttp not seen"
# shellcheck disable=SC2016  # раскрывает S99d2k, не этот скрипт
S99_SNIPPET='HU_PID=$RUN/d2k-http.pid; legacy_http_stop' s99
i=0; while kill -0 "$HU_OTHER" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$HU_OTHER" 2>/dev/null; then kill "$HU_OTHER"; fail "a live d2khttp was not stopped"; fi
ok "legacy d2khttp cleanup checks the process name, not the pid alone"

# --- Только политика Keenetic (задача 59) -------------------------------------
# Заглушка ndmc повторяет вывод роутера владельца 14.10.2026: управляющий
# символ в начале, внутреннее имя Policy0 и описание «VPN политика» с
# двоеточием в конце. Имя принимается в обоих видах; неизвестное — none и
# предупреждение; без KEENETIC_POLICY ключа нет.
printf '%s\n' '#!/bin/sh' "printf '\033[K\n           policy, name = Policy0, description = VPN политика: \n                 mark: ffffaaa\n               table4: 4096\n           policy, name = Policy1, description = D2K: \n                 mark: ffffaab\n           policy, name = D2Ktest: \n                 mark: ffffaac\n'" > "$TMP/bin/ndmc"
chmod +x "$TMP/bin/ndmc"
# shellcheck disable=SC2016  # expanded by the inner shell
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY=Policy0)" = "--only-mark 0xffffaaa/0xffffffff" ] \
    || fail "policy by internal name: wrong datapath key"
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY='VPN политика')" = "--only-mark 0xffffaaa/0xffffffff" ] \
    || fail "policy by its web-interface description: wrong datapath key"
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY=D2K)" = "--only-mark 0xffffaab/0xffffffff" ] \
    || fail "second policy: wrong mark"
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY=D2Ktest)" = "--only-mark 0xffffaac/0xffffffff" ] \
    || fail "a policy without a description (name ends with a colon) must be found"
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY=Нет)" = "--only-mark none" ] \
    || fail "unknown policy must serve no device"
S99_SNIPPET='policy_args 2>&1 >/dev/null' s99 KEENETIC_POLICY=Нет | grep -q 'не найдена' \
    || fail "unknown policy must be reported"
[ -z "$(S99_SNIPPET='policy_args 2>/dev/null' s99)" ] || fail "no KEENETIC_POLICY: no key"
rm -f "$TMP/bin/ndmc"
ok "KEENETIC_POLICY: the policy mark from ndmc goes to the datapath; unknown — none"


# Opt-in TCP watch: both families, full release contract, missing-rule heal,
# failed setup rollback and cleanup after configuration is disabled.
S99_SNIPPET='MODE=apply; TCP_WATCH=1; fw_up && fw_installed' s99 || fail "watch install"
for tool in iptables ip6tables; do
    rules "$tool" mangle | grep -q -- '-N D2K_WCLR' || fail "$tool watch release chain absent"
    rules "$tool" mangle | grep -q -- '--set-xmark 0/0x40000000' || fail "$tool watch clear missing"
    rules "$tool" mangle | grep -q -- '--set-xmark 0/0x20000000' || fail "$tool packet mark clear missing"
done
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -D D2K_WCLR -j MARK --set-xmark 0/0x20000000
if S99_SNIPPET='MODE=apply; TCP_WATCH=1; fw_installed' s99; then fail "missing release step accepted"; fi
S99_SNIPPET='MODE=apply; TCP_WATCH=1; fw_up && fw_installed; TCP_WATCH=0; fw_down' s99 || fail "watch repair/removal"
for tool in iptables ip6tables; do
    if rules "$tool" mangle | grep -q D2K_WCLR; then fail "$tool leaked release chain"; fi
done
for code in 'MODE=observe; TCP_WATCH=1' 'MODE=apply; TCP_WATCH=1; MARK=0x20000001' 'MODE=apply; TCP_WATCH=1; FW_BACKEND=nft'; do
    if S99_SNIPPET="$code; watch_validate" s99 >/dev/null 2>&1; then fail "invalid watch config accepted: $code"; fi
done

# Actual lifecycle functions, harmless substitutes for process/network effects.
# The snippet is evaluated inside S99d2k later, so $RUN must stay unexpanded.
# shellcheck disable=SC2016
order=$(S99_SNIPPET='mkdir -p "$RUN"; : > "$RUN/tcp-watch-active";
    HL_PID=heal; CT_PID=controller; DP_PID=datapath;
    stop_pidfile() { case "$1" in heal|controller|datapath) echo "stop:$1" ;; esac; }; fw_down() { echo firewall-down; };
    legacy_http_stop() { :; }; fastnat_restore() { :; }; flowoffload_restore() { :; };
    rst_rules_down() { :; }; say() { :; }; SOCK=$RUN/no-socket;
    engine_stop' s99)
[ "$order" = "stop:heal
stop:controller
stop:datapath
firewall-down
stop:controller
stop:datapath" ] || fail "watch stop removes firewall before datapath: $order"
if S99_SNIPPET='MODE=apply; TCP_WATCH=1; fw_up' s99 STUB_FAIL_MATCH=0/0x20000000 STUB_FAIL_TOOL=ip6tables; then
    fail "watch install ignored IPv6 release failure"
fi
for tool in iptables ip6tables; do
    if rules "$tool" mangle | grep -q D2K_WCLR; then fail "partial install left watch rules"; fi
done
S99_SNIPPET='TCP_WATCH=1; TG_ENABLED=0; engine_stop() { return 99; }; start_engine() { return 99; }; telegram_reapply' s99 || fail "Telegram heal must not restart datapath"
ok "TCP watch: lifecycle, missing-rule detection, both families and mark validation"

# Поздние STUN-запросы (этап 13, opt-in VOICE_LATE): с xt_u32 — правила по
# magic cookie за окном в обе стороны; без модуля — правил нет, журнал говорит
# об этом, подъём правил не падает (fallback — только окно).
S99_SNIPPET='MODE=apply; VOICE_LATE=1; fw_up && fw_installed; fw_down' s99 >"$TMP/late.out" 2>&1 || fail "VOICE_LATE install/check/down"
S99_SNIPPET='MODE=apply; VOICE_LATE=1; fw_up' s99 >/dev/null 2>&1 || fail "VOICE_LATE fw_up"
for tool in iptables ip6tables; do
    cookie='0>>22&0x3C@12=0x2112A442'
    [ "$tool" != ip6tables ] || cookie='4>>8&0xFF=17&&52=0x2112A442'
    rules "$tool" mangle | grep -Fq -- "--connbytes 5: --connbytes-dir original --connbytes-mode packets -m u32 --u32 $cookie" \
        || fail "$tool: late STUN request rule absent with VOICE_LATE=1"
    rules "$tool" mangle | grep -Fq -- "--connbytes 5: --connbytes-dir reply --connbytes-mode packets -m u32 --u32 $cookie" \
        || fail "$tool: late STUN reply rule absent with VOICE_LATE=1"
done
S99_SNIPPET='MODE=apply; VOICE_LATE=1; fw_down' s99 >/dev/null 2>&1 || fail "VOICE_LATE fw_down"
STUB_NO_U32=1 S99_SNIPPET='MODE=apply; VOICE_LATE=1; fw_up && fw_installed' s99 >"$TMP/late-nou32.out" 2>&1 || fail "VOICE_LATE without xt_u32 must still bring rules up"
if rules iptables mangle | grep -q -- 'u32'; then fail "late STUN rule installed without xt_u32"; fi
grep -q "xt_u32" "$TMP/late-nou32.out" || fail "missing xt_u32 fallback was not reported"
S99_SNIPPET='MODE=apply; VOICE_LATE=0; fw_down; fw_up' s99 >/dev/null 2>&1 || fail "VOICE_LATE=0 fw_up"
if rules iptables mangle | grep -q -- 'u32'; then fail "late STUN rule installed with VOICE_LATE=0"; fi
S99_SNIPPET='MODE=apply; fw_down' s99 >/dev/null 2>&1 || true
ok "late STUN visibility: opt-in rules with xt_u32, honest fallback without it"

# Поздняя доставка (этап 17, opt-in LATE_WATCH): пакеты записей conntrack с
# битом 0x40000000 — в очередь (TCP и UDP, обе стороны); при TCP_WATCH=1
# TCP-правила общие (без дубликата); d2kd получает --late-watch-mark; метки,
# пересекающиеся со служебными битами, отвергаются; LATE_WATCH=0 — правил нет.
S99_SNIPPET='MODE=apply; LATE_WATCH=1; fw_up && fw_installed; fw_down' s99 >"$TMP/lw.out" 2>&1 || fail "LATE_WATCH install/check/down"
S99_SNIPPET='MODE=apply; LATE_WATCH=1; fw_up' s99 >/dev/null 2>&1 || fail "LATE_WATCH fw_up"
for tool in iptables ip6tables; do
    for pr in tcp udp; do
        [ "$(rules "$tool" mangle | grep -c -- "-p $pr .*--ctdir ORIGINAL.*-m connmark --mark 0x40000000/0x40000000 -j NFQUEUE")" = 1 ] \
            || fail "$tool: $pr late-watch client rule absent/duplicated with LATE_WATCH=1"
        [ "$(rules "$tool" mangle | grep -c -- "-p $pr .*--ctdir REPLY.*-m connmark --mark 0x40000000/0x40000000 -j NFQUEUE")" = 1 ] \
            || fail "$tool: $pr late-watch reply rule absent/duplicated with LATE_WATCH=1"
    done
    # Правило метки стоит ПЕРЕД окном connbytes: иначе пакеты за окном его не видят.
    rules "$tool" mangle | awk '/connmark --mark 0x40000000\/0x40000000 -j NFQUEUE/ { seen=1 } /--connbytes 0:8/ && !seen { bad=1 } END { exit bad }' \
        || fail "$tool: late-watch rule after the connbytes window rule"
done
S99_SNIPPET='MODE=apply; LATE_WATCH=1; fw_down' s99 >/dev/null 2>&1 || fail "LATE_WATCH fw_down"
S99_SNIPPET='MODE=apply; LATE_WATCH=1; TCP_WATCH=1; fw_up' s99 >/dev/null 2>&1 || fail "LATE_WATCH+TCP_WATCH fw_up"
[ "$(rules iptables mangle | grep -c -- "-p tcp .*--ctdir ORIGINAL.*-m connmark --mark 0x40000000/0x40000000 -j NFQUEUE")" = 1 ] \
    || fail "LATE_WATCH+TCP_WATCH: duplicate tcp connmark rule"
[ "$(rules iptables mangle | grep -c -- "-p udp .*-m connmark --mark 0x40000000/0x40000000 -j NFQUEUE")" = 2 ] \
    || fail "LATE_WATCH+TCP_WATCH: udp connmark rules absent"
S99_SNIPPET='MODE=apply; LATE_WATCH=1; TCP_WATCH=1; fw_down' s99 >/dev/null 2>&1 || true
if S99_SNIPPET='MODE=apply; LATE_WATCH=1; MARK=0x40000001; fw_up' s99 >/dev/null 2>&1; then fail "LATE_WATCH accepted a mark overlapping the service bits"; fi
if S99_SNIPPET='MODE=observe; LATE_WATCH=1; fw_up' s99 >/dev/null 2>&1; then fail "LATE_WATCH accepted MODE=observe"; fi
S99_SNIPPET='MODE=apply; LATE_WATCH=0; fw_down; fw_up' s99 >/dev/null 2>&1 || fail "LATE_WATCH=0 fw_up"
if rules iptables mangle | grep -q -- 'connmark --mark 0x40000000'; then fail "late-watch rule installed with LATE_WATCH=0"; fi

# Этап 33: LATE_WATCH=auto и VOICE_LATE=auto — по умолчанию. Включаются там,
# где выполнимы (iptables, MODE=apply, метки не пересекаются, расширение есть),
# и НЕ срывают запуск там, где нет. Ядро отвергло правило — режим auto
# выключается с меткой, fw_installed это учитывает (иначе сторож гонял бы
# reapply каждый круг); явное значение 1 по-прежнему отказывает громко.
# Префикс VAR=… у вызова shell-функции переживает вызов (выше так ставится
# STUB_NO_U32=1): снимаем, а свои флаги передаём аргументами s99.
unset STUB_NO_U32 STUB_NO_CONNMARK
lw_rules() { rules iptables mangle | grep -c -- 'connmark --mark 0x40000000/0x40000000'; }
S99_SNIPPET='MODE=apply; LATE_WATCH=auto; fw_down; fw_up && fw_installed' s99 >/dev/null 2>&1 || fail "LATE_WATCH=auto: fw_up/fw_installed"
[ "$(lw_rules)" -ge 2 ] || fail "LATE_WATCH=auto под iptables+apply: правил поздней доставки нет"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
S99_SNIPPET='MODE=observe; LATE_WATCH=auto; fw_up && fw_installed' s99 >/dev/null 2>&1 || fail "LATE_WATCH=auto сорвал MODE=observe"
[ "$(lw_rules)" = 0 ] || fail "LATE_WATCH=auto поставил правила в MODE=observe"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
S99_SNIPPET='MODE=apply; LATE_WATCH=auto; MARK=0x40000001; fw_up && fw_installed' s99 >/dev/null 2>&1 || fail "LATE_WATCH=auto сорвал запуск при пересечении меток"
[ "$(lw_rules)" = 0 ] || fail "LATE_WATCH=auto поставил правила при пересечении меток"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
S99_SNIPPET='MODE=apply; LATE_WATCH=auto; fw_up && fw_installed' s99 STUB_NO_CONNMARK=1 >/dev/null 2>&1 || fail "LATE_WATCH=auto без xt_connmark сорвал запуск"
[ "$(lw_rules)" = 0 ] || fail "LATE_WATCH=auto без xt_connmark поставил правила"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
S99_SNIPPET='MODE=apply; LATE_WATCH=auto; fw_up && fw_installed' s99 STUB_FAIL_MATCH=0x40000000/0x40000000 STUB_FAIL_TOOL=iptables >/dev/null 2>&1 \
    || fail "LATE_WATCH=auto: отвергнутое ядром правило сорвало fw_up или fw_installed (шторм reapply)"
[ "$(lw_rules)" = 0 ] || fail "LATE_WATCH=auto: после отказа ядра остались правила поздней доставки"
S99_SNIPPET='fw_installed' s99 >/dev/null 2>&1 || fail "LATE_WATCH=auto: после отказа ядра fw_installed ложно (шторм reapply)"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
if S99_SNIPPET='MODE=apply; LATE_WATCH=1; fw_up' s99 STUB_FAIL_MATCH=0x40000000/0x40000000 STUB_FAIL_TOOL=iptables >/dev/null 2>&1; then
    fail "LATE_WATCH=1 (явно): отвергнутое правило принято молча"
fi
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
u32_rules() { rules iptables mangle | grep -c -- '-m u32'; }
S99_SNIPPET='MODE=apply; VOICE_LATE=auto; fw_up && fw_installed' s99 >/dev/null 2>&1 || fail "VOICE_LATE=auto: fw_up/fw_installed"
[ "$(u32_rules)" -ge 2 ] || fail "VOICE_LATE=auto с xt_u32: правил поздних STUN нет"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
S99_SNIPPET='MODE=apply; VOICE_LATE=auto; fw_up && fw_installed' s99 STUB_NO_U32=1 >/dev/null 2>&1 || fail "VOICE_LATE=auto без xt_u32 сорвал запуск"
[ "$(u32_rules)" = 0 ] || fail "VOICE_LATE=auto без xt_u32 поставил правила"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
S99_SNIPPET='MODE=apply; VOICE_LATE=auto; fw_up && fw_installed' s99 STUB_FAIL_MATCH=--u32 STUB_FAIL_TOOL=iptables >/dev/null 2>&1 \
    || fail "VOICE_LATE=auto: отвергнутое ядром правило сорвало fw_up или fw_installed (шторм reapply)"
S99_SNIPPET='fw_installed' s99 >/dev/null 2>&1 || fail "VOICE_LATE: после отказа ядра fw_installed ложно (шторм reapply)"
S99_SNIPPET='fw_down' s99 >/dev/null 2>&1
ok "late delivery/STUN auto: on where possible, never blocks start, kernel rejection degrades without reapply storm"
S99_SNIPPET='MODE=apply; fw_down' s99 >/dev/null 2>&1 || true
ok "late delivery: opt-in connmark queue rules before the connbytes window, no duplicates with TCP_WATCH, bits validated"

# Этап 53 (ревью 30.10.2026): содержимое D2K_LATE_OUT/IN — живое состояние
# d2kd (правила точного кортежа его наблюдений, он подтвердил их готовность).
# reapply (сторож NDM, d2k-fw-heal) при живом d2kd пересобирает цепочки
# службы и прежде стирал и эти — наблюдение считалось доставляемым, а правил
# не было. Служба не трогает их содержимое, пока d2kd жив; снимает их после
# его остановки; остатки упавшего d2kd снимаются, как прежде.
rm -rf "$TMP/fw" "$TMP/run"; mkdir -p "$TMP/fw" "$TMP/run"
# DP_PID вычислен при чтении S99d2k от настоящего RUN — во фрагментах свой.
# shellcheck disable=SC2016  # раскрывает внутренняя оболочка
LWS='MODE=apply; LATE_WATCH=1; DP_PID=$RUN/d2kd.pid; STATE_DIR=$RUN/state; USER_RULES=$STATE_DIR/user-rules;'
mkdir -p "$TMP/proc/5151"
echo d2kd > "$TMP/proc/5151/comm"
echo "5151 (d2kd) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 0 0" > "$TMP/proc/5151/stat"
echo 5151 > "$TMP/run/d2kd.pid"; echo 777 > "$TMP/run/d2kd.pid.start"
LW_OBS='-p tcp -m conntrack --ctdir ORIGINAL --ctproto 6 --ctorigsrc 192.168.1.20 --ctorigdst 203.0.113.7 --ctorigsrcport 42001 --ctorigdstport 443 -j NFQUEUE --queue-num 200 --queue-bypass'
lw_obs_count() { rules "$1" mangle | grep -cxF -- "-A $2 $LW_OBS"; }
lw_jumps() { rules "$1" mangle | grep -cxF -- "-A $2 -j $3"; }
S99_SNIPPET="$LWS fw_up" s99 >/dev/null 2>&1 || fail "LATE_WATCH fw_up (живой d2kd)"
for tool in iptables ip6tables; do
    # shellcheck disable=SC2086  # спецификация правила — отдельными словами
    for ch in D2K_LATE_OUT D2K_LATE_IN; do FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -A "$ch" $LW_OBS; done
    FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -N FOREIGN
    FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -A FOREIGN -j RETURN
done
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -I D2K_OUT 1 -s 192.168.1.50 -m comment --comment owner -j RETURN
for round in 1 2; do
    S99_SNIPPET="$LWS fw_up" s99 >/dev/null 2>&1 || fail "reapply $round (живой d2kd)"
    for tool in iptables ip6tables; do
        [ "$(lw_obs_count "$tool" D2K_LATE_OUT)" = 1 ] && [ "$(lw_obs_count "$tool" D2K_LATE_IN)" = 1 ] \
            || fail "$tool: reapply $round при живом d2kd стёр правила его наблюдений: $(rules "$tool" mangle | grep D2K_LATE)"
        [ "$(lw_jumps "$tool" D2K_OUT D2K_LATE_OUT)" = 1 ] && [ "$(lw_jumps "$tool" D2K_IN D2K_LATE_IN)" = 1 ] \
            || fail "$tool: reapply $round: переход в свои цепочки d2kd не ровно один"
        [ "$(rules "$tool" mangle | grep -cxF -- '-A FOREIGN -j RETURN')" = 1 ] || fail "$tool: reapply задел чужую цепочку"
    done
    rules iptables mangle | grep -qF -- '-A D2K_OUT -s 192.168.1.50 -m comment --comment owner -j RETURN' \
        || fail "reapply $round: исключение владельца потеряно"
done
# Откат неудавшегося reapply (fw_down) при живом d2kd — правила наблюдений целы.
S99_SNIPPET="$LWS fw_down" s99 >/dev/null 2>&1 || fail "fw_down (живой d2kd)"
for tool in iptables ip6tables; do
    [ "$(lw_obs_count "$tool" D2K_LATE_OUT)" = 1 ] || fail "$tool: fw_down при живом d2kd стёр правила его наблюдений"
done
# Остановка движка: цепочки d2kd снимаются, когда d2kd остановлен; чужое цело.
# shellcheck disable=SC2016  # раскрывает внутренняя оболочка
S99_SNIPPET="$LWS"' HL_PID=heal; CT_PID=controller;
    stop_pidfile() { [ "$1" != "$DP_PID" ] || rm -rf "$PROC_DIR/5151"; };
    legacy_http_stop() { :; }; fastnat_restore() { :; }; flowoffload_restore() { :; };
    rst_rules_down() { :; }; say() { :; }; SOCK=$RUN/no-socket;
    engine_stop' s99 >/dev/null 2>&1 || fail "engine_stop"
for tool in iptables ip6tables; do
    if rules "$tool" mangle | grep -q D2K_LATE; then fail "$tool: после остановки d2kd его цепочки остались: $(rules "$tool" mangle | grep D2K_LATE)"; fi
    [ "$(rules "$tool" mangle | grep -cxF -- '-A FOREIGN -j RETURN')" = 1 ] || fail "$tool: остановка задела чужую цепочку"
done
# Упавший d2kd (процесса нет): остатки его правил снимаются пересборкой.
S99_SNIPPET="$LWS fw_up" s99 >/dev/null 2>&1 || fail "fw_up после остановки"
# shellcheck disable=SC2086
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -A D2K_LATE_OUT $LW_OBS
S99_SNIPPET="$LWS fw_up" s99 >/dev/null 2>&1 || fail "fw_up после падения d2kd"
[ "$(lw_obs_count iptables D2K_LATE_OUT)" = 0 ] || fail "остатки упавшего d2kd пережили пересборку"
[ "$(lw_jumps iptables D2K_OUT D2K_LATE_OUT)" = 1 ] || fail "после падения d2kd переход в его цепочку не ровно один"
S99_SNIPPET='MODE=apply; fw_down' s99 >/dev/null 2>&1 || true
rm -f "$TMP/run/d2kd.pid" "$TMP/run/d2kd.pid.start"
ok "late delivery rules of a live d2kd survive reapply/rollback; removed after its stop; crash leftovers cleaned"

echo "S99d2k firewall (stub): all checks passed"
