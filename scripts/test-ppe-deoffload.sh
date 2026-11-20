#!/bin/sh
# Проверка files/d2k-ppe-deoffload.sh и его встраивания в files/S99d2k.
#
# Настоящий iptables не трогается: iptables/ip6tables подменены функциями,
# которые ведут правила в файлах по цепочкам (-I в начало, -A в конец, -C/-D
# по точному совпадению, -S как у iptables). Это проверяет не только форму
# правил, но и порядок в цепочке, повторный запуск и уборку «только своего».
#
# Что сторожим (ТЗ задачи 26):
#   * парные правила: исходящее по --dports в mangle PREROUTING и FORWARD,
#     ответное по --sports в mangle FORWARD; TCP — PORTS d2k, UDP — 443 и
#     VOICE_PORTS; v4 и v6; помечены комментарием d2k;
#   * connskip не меньше окон d2k (CONNBYTES / VOICE_CONNBYTES из S99d2k);
#   * нет цели PPE в прошивке — ни одного -I; D2K_PPE_DEOFFLOAD=0 — ничего
#     (и снятие уже стоящего своего);
#   * снятие удаляет ровно своё: чужие -j PPE (z2k, NDM) остаются;
#   * в FORWARD разгрузка стоит ДО перехода в очередь d2k: пакет, отданный в
#     NFQUEUE, до правил ниже по цепочке не доходит.
# POSIX sh (busybox ash). Запуск: sh scripts/test-ppe-deoffload.sh
# Переменные внутри подоболочек читают функции S99d2k — shellcheck их не видит.
# shellcheck disable=SC2034
set -u

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
LIB=$ROOT/files/d2k-ppe-deoffload.sh
TMP=$(mktemp -d "${TMPDIR:-/tmp}/d2k-ppe-test.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

PASSED=0
FAILED=0
ok()   { PASSED=$((PASSED + 1)); printf 'PASS: %s\n' "$1"; }
bad()  { FAILED=$((FAILED + 1)); printf 'FAIL: %s\n' "$1"; }
check() { # описание, затем команда
    d=$1; shift
    if "$@"; then ok "$d"; else bad "$d"; fi
}

[ -r "$LIB" ] || { echo "FAIL: нет $LIB"; exit 1; }

# --- подмена iptables -------------------------------------------------------
RULES=$TMP/rules
CALLS=$TMP/calls
mkdir -p "$RULES"
: > "$CALLS"

_ipt() {
    fam=$1; shift
    printf '%s %s\n' "$fam" "$*" >> "$CALLS"
    [ "${1:-}" != -w ] || shift
    [ "${1:-}" = -t ] || return 2
    tbl=$2; shift 2
    [ "${1:-}" != -n ] || shift
    op=$1; shift
    ch=${1:-}
    [ $# -eq 0 ] || shift
    f=$RULES/$fam.$tbl.$ch
    rule=$*
    case "$op" in
        -N) [ ! -e "$f" ] || return 1; : > "$f" ;;
        -L) [ -e "$f" ] ;;
        -F) [ -e "$f" ] || return 1; : > "$f" ;;
        -X) [ -e "$f" ] || return 1; rm -f "$f" ;;
        -C) grep -qxF -- "$rule" "$f" 2>/dev/null ;;
        -A) printf '%s\n' "$rule" >> "$f" ;;
        -I) { printf '%s\n' "$rule"; cat "$f" 2>/dev/null; } > "$f.n"; mv "$f.n" "$f" ;;
        -D) grep -qxF -- "$rule" "$f" 2>/dev/null || return 1
            awk -v r="$rule" '!d && $0 == r { d = 1; next } { print }' "$f" > "$f.n"
            mv "$f.n" "$f" ;;
        -S) [ -e "$f" ] || return 1
            printf -- '-P %s ACCEPT\n' "$ch"
            sed "s/^/-A $ch /" "$f" ;;
        *) return 2 ;;
    esac
}
iptables()  { _ipt v4 "$@"; }
ip6tables() { _ipt v6 "$@"; }

reset_rules() {
    rm -rf "$RULES"; mkdir -p "$RULES"; : > "$CALLS"
    for fam in v4 v6; do
        for ch in PREROUTING FORWARD POSTROUTING INPUT OUTPUT; do
            : > "$RULES/$fam.mangle.$ch"
        done
        for ch in PREROUTING POSTROUTING; do : > "$RULES/$fam.nat.$ch"; done
    done
}
chain() { cat "$RULES/$1.mangle.$2" 2>/dev/null; }
count_tag() { chain "$1" "$2" | grep -c -- '--comment d2k-ppe -j PPE$'; }

# Наличие цели PPE в прошивке — через подменённый /proc/net.
PROC=$TMP/proc
mkdir -p "$PROC"
targets() { # v4 v6: 1 — цель есть
    printf 'NFQUEUE\n%s' "$( [ "$1" = 1 ] && echo PPE)" > "$PROC/ip_tables_targets"
    printf 'NFQUEUE\n%s' "$( [ "$2" = 1 ] && echo PPE)" > "$PROC/ip6_tables_targets"
}

CONFIG=$TMP/config
: > "$CONFIG"
export D2K_PPE_PROC="$PROC" D2K_PPE_CONFIG="$CONFIG"
export D2K_PPE_BINDS="$TMP/binds" D2K_PPE_DPLOG="$TMP/d2kd.log"

# Порты и окна — как их объявляет S99d2k, а не переписанные сюда копии.
PORTS=$(sed -n 's/^PORTS=//p' "$ROOT/files/S99d2k" | head -1)
VOICE_PORTS=$(sed -n 's/^VOICE_PORTS=//p' "$ROOT/files/S99d2k" | head -1)
CONNBYTES=$(sed -n 's/^CONNBYTES=//p' "$ROOT/files/S99d2k" | head -1)
VOICE_CONNBYTES=$(sed -n 's/^VOICE_CONNBYTES=//p' "$ROOT/files/S99d2k" | head -1)
export PORTS VOICE_PORTS

# shellcheck disable=SC1090
. "$LIB"

UDP="0:65535"
T="-m connskip --connskip 30 -m comment --comment d2k-ppe -j PPE"
TH="-m connskip --connskip 1000000 -m comment --comment d2k-ppe -j PPE"

# --- connskip против окон d2k ----------------------------------------------
# connskip считает пакеты соединения в ОБЕ стороны, окна d2k — каждую сторону
# отдельно (connbytes original/reply). Запас — на повторы приветствия и
# ретрансмиссии внутри окна.
win=${CONNBYTES#0:}
vwin=${VOICE_CONNBYTES#0:}
[ "$vwin" -le "$win" ] || win=$vwin
check "connskip $D2K_PPE_CONNSKIP >= 2*окно($win) + 8 на повторы" \
    [ "$D2K_PPE_CONNSKIP" -ge $((2 * win + 8)) ]
check "connskip по умолчанию 30, как у z2k" [ "$D2K_PPE_CONNSKIP" = 30 ]
nports=$(printf '%s' "$UDP" | awk -F, '{ n = 0; for (i = 1; i <= NF; i++) n += ($i ~ /:/) ? 2 : 1; print n }')
check "UDP-набор помещается в multiport (<=15, сейчас $nports)" [ "$nports" -le 15 ]

# --- форма правил ----------------------------------------------------------
reset_rules
targets 1 1
d2k_ppe_ensure; rc=$?
check "ensure: успех при цели PPE" [ "$rc" = 0 ]
for fam in v4 v6; do
    check "$fam PREROUTING: TCP исходящее по --dports" \
        grep -qxF -- "-p tcp -m multiport --dports $PORTS $T" "$RULES/$fam.mangle.PREROUTING"
    check "$fam PREROUTING: UDP включая неизвестные приложения исходящее по --dports" \
        grep -qxF -- "-p udp -m multiport --dports $UDP $T" "$RULES/$fam.mangle.PREROUTING"
    check "$fam FORWARD: TCP исходящее по --dports" \
        grep -qxF -- "-p tcp -m multiport --dports $PORTS $T" "$RULES/$fam.mangle.FORWARD"
    check "$fam FORWARD: TCP ответ по --sports" \
        grep -qxF -- "-p tcp -m multiport --sports $PORTS $T" "$RULES/$fam.mangle.FORWARD"
    check "$fam FORWARD: UDP исходящее по --dports" \
        grep -qxF -- "-p udp -m multiport --dports $UDP $T" "$RULES/$fam.mangle.FORWARD"
    check "$fam FORWARD: UDP ответ по --sports" \
        grep -qxF -- "-p udp -m multiport --sports $UDP $T" "$RULES/$fam.mangle.FORWARD"
    check "$fam: ответного --sports в PREROUTING нет (там обратный NAT ещё не отработал)" \
        [ "$(chain $fam PREROUTING | grep -c -- '--sports')" = 0 ]
    # Keep-alive открытого HTTP (поле 04.10.2026): порт 80, только сторона
    # клиента, широкий connskip — следующие запросы соединения видны.
    check "$fam PREROUTING: HTTP-клиент по --dports 80, широкий connskip" \
        grep -qxF -- "-p tcp -m multiport --dports 80 $TH" "$RULES/$fam.mangle.PREROUTING"
    check "$fam FORWARD: HTTP-клиент по --dports 80, широкий connskip" \
        grep -qxF -- "-p tcp -m multiport --dports 80 $TH" "$RULES/$fam.mangle.FORWARD"
    check "$fam: ответ HTTP (--sports 80) с широким connskip не снят с ускорителя" \
        sh -c "! grep -q -- '--sports 80 .*--connskip $D2K_PPE_HTTP_CONNSKIP' '$RULES/$fam.mangle.FORWARD'"
    check "$fam: ровно 3 своих в PREROUTING" [ "$(count_tag $fam PREROUTING)" = 3 ]
    check "$fam: ровно 5 своих в FORWARD" [ "$(count_tag $fam FORWARD)" = 5 ]
    check "$fam: POSTROUTING не тронут" [ ! -s "$RULES/$fam.mangle.POSTROUTING" ]
done
check "nat не тронут" sh -c "! grep -q -- '-t nat' '$CALLS'"

# --- повторный запуск ------------------------------------------------------
d2k_ppe_ensure
d2k_ppe_ensure
check "повтор ensure не плодит дубликатов (v4)" \
    [ "$(count_tag v4 PREROUTING)/$(count_tag v4 FORWARD)" = 3/5 ]
check "повтор ensure не плодит дубликатов (v6)" \
    [ "$(count_tag v6 PREROUTING)/$(count_tag v6 FORWARD)" = 3/5 ]

# --- снятие только своего --------------------------------------------------
Z2K="-p tcp -m multiport --dports 80,443,2053 -m connskip --connskip 30 -j PPE"
NDM="-p tcp --dport 443 -m connskip --connskip 2 -m comment --comment ndm -j PPE"
NEAR="-p tcp --dport 443 -m connskip --connskip 30 -m comment --comment d2k-ppe-other -j PPE"
for fam in v4 v6; do
    for ch in PREROUTING FORWARD; do
        for r in "$Z2K" "$NDM" "$NEAR"; do
            printf '%s\n' "$r" >> "$RULES/$fam.mangle.$ch"
        done
    done
done
# Порты в окружении сменились после установки: снимать всё равно по метке.
D2K_PPE_TCP_PORTS=1:2 D2K_PPE_UDP_PORTS=3 d2k_ppe_remove
for fam in v4 v6; do
    for ch in PREROUTING FORWARD; do
        check "$fam $ch: своих не осталось" [ "$(count_tag $fam $ch)" = 0 ]
        check "$fam $ch: правило z2k на месте" grep -qxF -- "$Z2K" "$RULES/$fam.mangle.$ch"
        check "$fam $ch: правило NDM на месте" grep -qxF -- "$NDM" "$RULES/$fam.mangle.$ch"
        check "$fam $ch: похожая чужая метка на месте" grep -qxF -- "$NEAR" "$RULES/$fam.mangle.$ch"
    done
done

# --- нет цели PPE ----------------------------------------------------------
reset_rules
targets 0 0
d2k_ppe_ensure; rc=$?
check "нет цели: ensure сообщает «недоступно» (2)" [ "$rc" = 2 ]
check "нет цели: ни одного -I" sh -c "! grep -q -- ' -I ' '$CALLS'"
d2k_ppe_status > "$TMP/status"
check "нет цели: статус говорит «недоступна»" grep -q 'недоступна' "$TMP/status"

reset_rules
targets 1 0
d2k_ppe_ensure
check "нет v6-цели: v4 поставлен" [ "$(count_tag v4 FORWARD)" = 5 ]
check "нет v6-цели: в v6 ни одного -I" sh -c "! grep -q '^v6 .* -I ' '$CALLS'"

# --- выключено владельцем --------------------------------------------------
reset_rules
targets 1 1
d2k_ppe_ensure
printf 'D2K_PPE_DEOFFLOAD=0\n' > "$CONFIG"
: > "$CALLS"
d2k_ppe_ensure; rc=$?
check "=0: ensure сообщает «выключено» (3)" [ "$rc" = 3 ]
check "=0: ни одного -I" sh -c "! grep -q -- ' -I ' '$CALLS'"
check "=0: уже стоявшие свои сняты" \
    [ "$(count_tag v4 FORWARD)/$(count_tag v6 PREROUTING)" = 0/0 ]
d2k_ppe_status > "$TMP/status"
check "=0: статус говорит «выключена владельцем»" grep -q 'выключена владельцем' "$TMP/status"
D2K_PPE_DEOFFLOAD=1 d2k_ppe_ensure; rc=$?
check "переменная окружения важнее файла" [ "$rc" = 0 ]
: > "$CONFIG"

# --- статус: оракул binds и счётчик датапата -------------------------------
reset_rules
targets 1 1
d2k_ppe_ensure
cat > "$TMP/binds" <<'EOF'
BND idx=1 TCP 192.168.1.67:47901->1.2.3.4:443
BND idx=2 UDP 192.168.1.67:51000->5.6.7.8:443
EOF
cat > "$TMP/d2kd.log" <<'EOF'
ответ невидим очереди: 0 из 3 TCP-потоков с приветствием
ответ невидим очереди: 12 из 40 TCP-потоков с приветствием
EOF
d2k_ppe_status 1.2.3.4 > "$TMP/status"
check "статус: включена и число правил" grep -q 'разгрузка PPE: включена' "$TMP/status"
check "статус: число привязок ускорителя" grep -q 'binds: 2 ' "$TMP/status"
check "статус: адрес найден в binds" grep -q '1.2.3.4: в ускорителе' "$TMP/status"
check "статус: последняя сводка датапата, с долей" grep -q '12 из 40 (30%)' "$TMP/status"
check "статус: рекомендация no ppe hardware при высокой доле" grep -q 'no ppe hardware' "$TMP/status"
check "статус: ограничение поздних RST/FIN названо" grep -q 'поздние RST/FIN' "$TMP/status"
d2k_ppe_status 9.9.9.9 > "$TMP/status"
check "статус: чужой адрес в binds не найден" grep -q '9.9.9.9: в binds нет' "$TMP/status"
printf 'ответ невидим очереди: 1 из 40 TCP-потоков с приветствием\n' > "$TMP/d2kd.log"
d2k_ppe_status > "$TMP/status"
check "статус: при малой доле без рекомендации" sh -c "! grep -q 'no ppe hardware' '$TMP/status'"
rm -f "$TMP/binds"
d2k_ppe_status > "$TMP/status"
check "статус: нет binds — так и сказано" grep -q 'binds: нет' "$TMP/status"

# Настоящий формат binds (KN-1811, 02.10.2026): строка-заголовок PPE0: и
# записи вида «адрес:порт -> адрес:порт ===>>> …». Поиск адреса — точный:
# 1.2.3.4 не должен находиться в 11.2.3.4, точка — не подстановочный знак.
cat > "$TMP/binds" <<'EOF'
PPE0:
IPv4_NAPT=802: 87.228.47.201:443 -> 88.87.93.11:50016 ===>>> 87.228.47.201:443 -> 192.168.1.67:50016 (DSCP 28/VLAN.PCP (0.0),(4032.1)/QID 1) [50:ff:20:b9:fa:91 ==>> 68:5e:dd:83:16:1a] {0}
IPv4_NAPT=803: 11.2.3.4:443 -> 88.87.93.11:50017 ===>>> 11.2.3.4:443 -> 192.168.1.68:50017 (DSCP 0/VLAN.PCP (0.0),(4032.1)/QID 1) [50:ff:20:b9:fa:91 ==>> 68:5e:dd:83:16:1a] {0}
EOF
binds_has() { d2k_ppe_status "$1" > "$TMP/st.b"; grep -qF -- "$1: в ускорителе" "$TMP/st.b"; }
binds_hasnt() { d2k_ppe_status "$1" > "$TMP/st.b"; grep -qF -- "$1: в binds нет" "$TMP/st.b"; }
d2k_ppe_status > "$TMP/status"
check "binds: заголовок PPE0: не считается записью" grep -q 'binds: 2 ' "$TMP/status"
check "binds: 87.228.47.201 найден" binds_has 87.228.47.201
check "binds: 192.168.1.67 найден" binds_has 192.168.1.67
check "binds: 7.228.47.201 (хвост чужого адреса) не найден" binds_hasnt 7.228.47.201
check "binds: 87.228.47.20 (начало чужого адреса) не найден" binds_hasnt 87.228.47.20
check "binds: 1.2.3.4 не найден в 11.2.3.4" binds_hasnt 1.2.3.4
check "binds: 87x228x47x201 — точка не подстановка" binds_hasnt 87x228x47x201
check "binds: 11.2.3.4 найден" binds_has 11.2.3.4
rm -f "$TMP/binds"

# «включена» учитывает v6, если v6 доступен: неполный v6 — «не стоит».
reset_rules
targets 1 1
d2k_ppe_ensure
: > "$RULES/v6.mangle.FORWARD"
d2k_ppe_status > "$TMP/status"
check "статус: v6 неполон — не «включена»" sh -c "! grep -q 'разгрузка PPE: включена' '$TMP/status'"
check "статус: v6 неполон — «не стоит»" grep -q 'разгрузка PPE: не стоит' "$TMP/status"

# Совет честный: причина вероятная, и названы другие.
printf 'ответ невидим очереди: 12 из 40 TCP-потоков с приветствием\n' > "$TMP/d2kd.log"
d2k_ppe_status > "$TMP/status"
check "совет: «вероятно»" grep -q 'вероятно' "$TMP/status"
check "совет: названы переполнение очереди и перезапуск" \
    sh -c "grep -q 'переполн' '$TMP/status' && grep -q 'перезапуск' '$TMP/status'"
check "конфигурация: D2K_PPE_TCP_PORTS описан в files/config" grep -q 'D2K_PPE_TCP_PORTS' "$ROOT/files/config"

# --- встраивание в S99d2k: порядок в FORWARD, снятие при остановке ---------
# Функции службы без диспетчера команд — как в scripts/test-runtime-files.cjs.
sed '/^case "\$1" in/,$d' "$ROOT/files/S99d2k" > "$TMP/init"
# Обёртки S99d2k ждут блокировку xtables через `command iptables -w` — мимо
# заглушки-функции этого теста, прямо в настоящий бинарь. Здесь тот же вызов
# с тем же ключом -w уходит в заглушку.
cat >> "$TMP/init" <<'SHIM'
xt_wait() {
    xt_tool=$1; shift
    [ "${1:-}" != -w ] || shift
    case "$xt_tool" in iptables) _ipt v4 -w "$@" ;; *) _ipt v6 -w "$@" ;; esac
}
SHIM
reset_rules
targets 1 1
FOREIGN="-p tcp -m multiport --dports 80,443 -m connskip --connskip 30 -j PPE"
printf '%s\n' "$FOREIGN" >> "$RULES/v4.mangle.FORWARD"
(
    # shellcheck disable=SC1090,SC1091
    . "$TMP/init"
    DIR=$TMP/d2k; RUN=$DIR/run; FW_LOCK=$TMP/fw.lock
    PPE_LIB=$LIB
    # shellcheck disable=SC1090
    . "$PPE_LIB"
    fw_up || exit 11
    # reapply: fw_up второй раз вставляет переходы в цепочки d2k наверх;
    # разгрузка обязана остаться выше перехода в очередь.
    fw_up || exit 12
    exit 0
)
rc=$?
check "S99d2k fw_up с разгрузкой прошёл (rc=$rc)" [ "$rc" = 0 ]
for fam in v4 v6; do
    first_q=$(chain $fam FORWARD | grep -n -- '^-j D2K_IN$' | head -1 | cut -d: -f1)
    last_p=$(chain $fam FORWARD | grep -n -- '--comment d2k-ppe -j PPE$' | tail -1 | cut -d: -f1)
    check "$fam FORWARD: разгрузка (${last_p:-нет}) выше перехода в очередь (${first_q:-нет})" \
        [ "${last_p:-99}" -lt "${first_q:-0}" ]
    check "$fam: после двух fw_up по-прежнему 5+3 своих" \
        [ "$(count_tag $fam FORWARD)/$(count_tag $fam PREROUTING)" = 5/3 ]
done
(
    # shellcheck disable=SC1090,SC1091
    . "$TMP/init"
    DIR=$TMP/d2k; RUN=$DIR/run; FW_LOCK=$TMP/fw.lock
    PPE_LIB=$LIB
    # shellcheck disable=SC1090
    . "$PPE_LIB"
    fw_down
)
for fam in v4 v6; do
    check "$fam: fw_down снял свою разгрузку" \
        [ "$(count_tag $fam FORWARD)/$(count_tag $fam PREROUTING)" = 0/0 ]
done
check "fw_down оставил чужое -j PPE" grep -qxF -- "$FOREIGN" "$RULES/v4.mangle.FORWARD"

# Отказ разгрузки не валит правила очереди: d2k без неё хуже видит, но
# работает (как до задачи 26).
reset_rules
targets 1 1
(
    # shellcheck disable=SC1090,SC1091
    . "$TMP/init"
    DIR=$TMP/d2k; RUN=$DIR/run; FW_LOCK=$TMP/fw.lock
    PPE_LIB=$LIB
    # shellcheck disable=SC1090
    . "$PPE_LIB"
    # shellcheck disable=SC2329  # зовёт ppe_up из S99d2k
    # shellcheck disable=SC2317  # вызывается из подключённого S99d2k
    d2k_ppe_ensure() { return 1; }
    fw_up || exit 21
    fw_installed || exit 22
)
rc=$?
check "отказ разгрузки не отменяет правила очереди (rc=$rc)" [ "$rc" = 0 ]

# --- сторож: возвращает снесённую разгрузку, не трогая правил очереди ------
# NDM пересобирает mangle и сносит чужое; хук 001-d2k.sh зовёт сторожа, а
# сторож при целых правилах очереди обязан хотя бы вернуть разгрузку.
cat > "$TMP/fake-init" <<'INIT'
#!/bin/sh
printf '%s\n' "$*" >> "$HEAL_CALLS"
case "$1" in
    status)
        echo "  датапат: работает (pid 1)"
        [ "${FAKE_RULES:-1}" = 1 ] && echo "  правила: стоят" || echo "  правила: отсутствуют или неполны"
        ;;
esac
exit 0
INIT
chmod +x "$TMP/fake-init"
HEAL_CALLS=$TMP/heal-calls; export HEAL_CALLS
: > "$HEAL_CALLS"
INIT_SCRIPT=$TMP/fake-init HEAL_LOCK=$TMP/heal.lock HEAL_LAST=$TMP/heal.last \
    sh "$ROOT/files/d2k-fw-heal.sh"
check "сторож при целых правилах зовёт ppe-ensure" grep -qx 'ppe-ensure' "$HEAL_CALLS"
check "сторож при целых правилах не переставляет очередь" sh -c "! grep -qx reapply '$HEAL_CALLS'"
check "сторож спрашивает состояние один раз" [ "$(grep -cx status "$HEAL_CALLS")" = 1 ]
: > "$HEAL_CALLS"
FAKE_RULES=0 INIT_SCRIPT=$TMP/fake-init HEAL_LOCK=$TMP/heal.lock HEAL_LAST=$TMP/heal.last \
    sh "$ROOT/files/d2k-fw-heal.sh" 2>/dev/null
check "сторож при снесённой очереди делает reapply (он ставит и разгрузку)" grep -qx reapply "$HEAL_CALLS"

# An explicit owner restriction must still override broad default coverage.
reset_rules
targets 1 1
D2K_PPE_UDP_PORTS=27015 d2k_ppe_ensure
for fam in v4 v6; do
    check "$fam explicit UDP restriction retained" \
        grep -qxF -- "-p udp -m multiport --dports 27015 $T" "$RULES/$fam.mangle.PREROUTING"
    check "$fam explicit UDP restriction not widened" \
        sh -c "! grep -qxF -- '-p udp -m multiport --dports 0:65535 $T' '$RULES/$fam.mangle.PREROUTING'"
done

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
