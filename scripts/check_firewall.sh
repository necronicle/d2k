#!/bin/sh
# Проверка правил files/S99d2k НАСТОЯЩИМ iptables, а не чтением текста.
#
# Почему отдельно от scripts/check.sh: единственный способ прогнать iptables
# с машины разработки (Mac, без родного netfilter) — Linux-контейнер, а
# Docker как новая ЖЁСТКАЯ зависимость всего гейта — решение отдельное от
# этой проверки и не принято здесь явочным порядком. Docker в проекте уже
# используется для Linux-специфичной проверки (см. память про
# loopback-буферы: "Linux-проверка через docker+tar") — тот же приём,
# оформленный в отдельный, вызываемый по требованию скрипт.
#
# Нужна затем, что files/S99d2k — самый рискованный файл всей QUIC-вертикали
# (ставит правила firewall на живом роутере Марка, через который ходит вся
# его сеть), а до ревью задачи 4 (круг 2) он не был проверен вообще ничем,
# даже shellcheck'ом. "Прочитали и согласились" проверкой не является:
# здесь fw_up/fw_down исполняются настоящим iptables в изолированном сетевом
# namespace контейнера, и утверждения проверяются по РЕАЛЬНОМУ выводу
# `iptables -S`, а не по тому, что скрипт, как кажется на взгляд, должен
# делать.
#
# Требует Docker (docker info должен отвечать). Ничего не трогает на хосте:
# все правила ставятся и снимаются в СЕТЕВОМ NAMESPACE КОНТЕЙНЕРА, который
# создаётся и уничтожается заново при каждом запуске.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)
S99="$ROOT/files/S99d2k"

if ! docker info >/dev/null 2>&1; then
    echo "check_firewall.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Только определения функций — без хвостового `case "$1" in ... esac`,
# который иначе исполнился бы прямо при source'инге (это `exit`, а не
# управление, — sh на этом действительно выйдет) и сорвал бы проверку раньше
# первого вызова fw_up. Строка отреза — первая строка `case "$1" in`, она
# должна остаться ПОСЛЕДНЕЙ строкой файла, которую видит эта команда: если
# структура S99d2k когда-нибудь изменится и это перестанет быть так, grep
# ниже провалится явно, а не тихо обрежет не там.
#
# $1 в шаблоне ниже — буквальный текст, который ищем В ЧУЖОМ ФАЙЛЕ ($S99), а
# не параметр этого скрипта: раскрывать его нельзя, двойные кавычки были бы
# ошибкой, а не стилем.
# shellcheck disable=SC2016
CASE_LINE=$(grep -n '^case "$1" in' "$S99" | head -1 | cut -d: -f1)
if [ -z "$CASE_LINE" ]; then
    echo "check_firewall.sh: не нашёл 'case \"\$1\" in' в $S99 — разметка файла изменилась" >&2
    exit 1
fi
head -n "$((CASE_LINE - 1))" "$S99" > "$WORK/s99funcs.sh"
cp "$ROOT/scripts/uninstall.sh" "$WORK/uninstall.sh"

cat > "$WORK/driver.sh" <<'DRIVER'
#!/bin/sh
set -e
. /work/s99funcs.sh
MODE=observe
mkdir -p /opt/d2k/run

fail() { echo "ПРОВАЛ: $*" >&2; exit 1; }

# A foreign rule must survive all D2K install/heal/remove operations.
ip6tables -t mangle -A INPUT -p ipv6-icmp -j ACCEPT
echo "== fw_up =="
fw_up
fw_installed || fail "полный набор правил не распознан"
for proto in tcp udp; do
    ip6tables -t mangle -C D2K_OUT -p "$proto" -m conntrack --ctdir ORIGINAL \
        -m multiport --dports "$PORTS" \
        -m connbytes --connbytes "$CONNBYTES" --connbytes-dir original \
        --connbytes-mode packets -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass \
        || fail "нет IPv6 $proto перехвата"
done
ip6tables -t mangle -C D2K_OUT -m mark --mark "$MARK" -j RETURN || fail "нет IPv6 raw bypass"
ip6tables -t mangle -C D2K_OUT -m mark --mark "$MEASURE_MARK" -j RETURN || fail "нет IPv6 measurement bypass"
# Кроме TCP/UDP в очередь идёт ровно одно: ICMP time-exceeded в пути на свои
# фальшивки (поле 04.10.2026) — и только в ответной цепочке.
ip6tables -t mangle -S | grep 'NFQUEUE' | grep -vE -- '-p (tcp|udp) ' \
    | grep -vxE -- '-A D2K_IN -p ipv6-icmp -m icmp6 --icmpv6-type 3/0 -j NFQUEUE --queue-num [0-9]+ --queue-bypass' \
    && fail "IPv6 очередь захватывает не TCP/UDP"
iptables -t mangle -S | grep 'NFQUEUE' | grep -vE -- '-p (tcp|udp) ' \
    | grep -vxE -- '-A D2K_IN -p icmp -m icmp --icmp-type 11/0 -j NFQUEUE --queue-num [0-9]+ --queue-bypass' \
    && fail "IPv4 очередь захватывает не TCP/UDP"
iptables -t mangle -C D2K_IN -p icmp --icmp-type 11/0 -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass \
    || fail "нет IPv4 time-exceeded в D2K_IN"
ip6tables -t mangle -C D2K_IN -p ipv6-icmp --icmpv6-type 3/0 -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass \
    || fail "нет ICMPv6 time-exceeded в D2K_IN"
if ip6tables -t nat -S | grep -q MASQUERADE; then fail "IPv4 MASQUERADE скопирован в IPv6"; fi
RULES=$(iptables -t mangle -S)
echo "$RULES"

for tool in iptables ip6tables; do
    loopback=127.0.0.0/8
    [ "$tool" != ip6tables ] || loopback=::1/128
    for chain in D2K_OUT D2K_IN; do
        "$tool" -t mangle -C "$chain" -s "$loopback" -j RETURN || fail "$tool queues local resolver IPC"
        "$tool" -t mangle -C "$chain" -d "$loopback" -j RETURN || fail "$tool queues local resolver IPC"
    done
    for proto in tcp udp; do
        "$tool" -t mangle -C D2K_OUT -p "$proto" -m multiport --dports 53,853 -j RETURN || fail "$tool queues DNS"
        "$tool" -t mangle -C D2K_IN -p "$proto" -m multiport --sports 53,853 -j RETURN || fail "$tool queues DNS replies"
    done
done

# Broadcast and multicast never enter the queue (field 03.10: raw re-send to a
# broadcast destination fails with EACCES; there is no NAT clash to cure).
iptables -t mangle -C D2K_OUT -m addrtype --dst-type BROADCAST -j RETURN \
    || fail "IPv4 broadcast queued"
iptables -t mangle -C D2K_OUT -d 224.0.0.0/4 -j RETURN || fail "IPv4 multicast queued"
ip6tables -t mangle -C D2K_OUT -d ff00::/8 -j RETURN || fail "IPv6 multicast queued"
for tool in iptables ip6tables; do
    OUT_RULES=$("$tool" -t mangle -S D2K_OUT)
    first_q=$(echo "$OUT_RULES" | grep -n NFQUEUE | head -1 | cut -d: -f1)
    last_bm=$(echo "$OUT_RULES" | grep -nE -- '--dst-type BROADCAST|-d (224\.0\.0\.0/4|ff00::/8)' \
        | tail -1 | cut -d: -f1)
    [ -n "$first_q" ] && [ -n "$last_bm" ] && [ "$last_bm" -lt "$first_q" ] \
        || fail "$tool: broadcast/multicast RETURN не стоит раньше NFQUEUE"
done
if iptables -t mangle -S D2K_IN | grep -qE -- 'addrtype|224\.0\.0\.0/4'; then
    fail "исключение broadcast/multicast попало в D2K_IN (ответы)"
fi

echo "$RULES" | grep -qE -- '-A D2K_OUT -p udp .*--dports 0:65535.*--queue-bypass' \
    || fail "нет исходящего UDP-правила полного диапазона с --queue-bypass"
echo "$RULES" | grep -qE -- '-A D2K_IN -p udp .*--sports 0:65535.*--queue-bypass' \
    || fail "нет входящего UDP-правила полного диапазона (ответ) с --queue-bypass"
echo "$RULES" | grep -qE -- '-A D2K_OUT -p tcp .*--dports 0:65535.*--queue-bypass' \
    || fail "нет исходящего TCP-правила полного диапазона с --queue-bypass (регресс задачи 3)"
echo "$RULES" | grep -qE -- '-A D2K_IN -p tcp .*--sports 0:65535.*--queue-bypass' \
    || fail "нет входящего TCP-правила полного диапазона с --queue-bypass (регресс задачи 3)"

# connbytes-dir выбирает счётчик направления, а не направление текущего
# пакета. При диапазоне 0:8 счётчик противоположной стороны равен нулю и
# тоже проходит фильтр; для PORTS=0:65535 это ловит исходящий SYN в D2K_IN
# до Keenetic NDMMARK и ломает SNAT. Направление пакета фиксируется отдельно.
echo "$RULES" | grep -qE -- '-A D2K_OUT -p tcp -m conntrack --ctdir ORIGINAL .*--dports 0:65535' \
    || fail "D2K_OUT не ограничен conntrack-направлением ORIGINAL"
echo "$RULES" | grep -qE -- '-A D2K_OUT -p udp -m conntrack --ctdir ORIGINAL .*--dports 0:65535' \
    || fail "D2K_OUT UDP не ограничен conntrack-направлением ORIGINAL"
echo "$RULES" | grep -qE -- '-A D2K_IN -p tcp -m conntrack --ctdir REPLY .*--sports 0:65535' \
    || fail "D2K_IN TCP не ограничен conntrack-направлением REPLY"
echo "$RULES" | grep -qE -- '-A D2K_IN -p udp -m conntrack --ctdir REPLY .*--sports 0:65535' \
    || fail "D2K_IN UDP не ограничен conntrack-направлением REPLY"
echo "$RULES" | grep -qE -- '-A D2K_OUT -p udp -m conntrack --ctdir ORIGINAL .*--dports 50000:50099,1400,3478:3481,5349,19294:19344' \
    || fail "голосовое UDP-правило D2K_OUT не ограничено conntrack-направлением ORIGINAL"
echo "$RULES" | grep -qE -- '-A D2K_IN -p udp -m conntrack --ctdir REPLY .*--sports 50000:50099,1400,3478:3481,5349,19294:19344' \
    || fail "голосовое UDP-правило D2K_IN не ограничено conntrack-направлением REPLY"

# Complete HTTP framing needs non-PSH body segments in both directions.
echo "$RULES" | grep -qE -- '-A D2K_OUT -p tcp -m conntrack --ctdir ORIGINAL .*--dports 80 .*--connbytes 9[: ].*--queue-bypass' \
    || fail "нет полного наблюдения следующих запросов HTTP"
echo "$RULES" | grep -qE -- '-A D2K_IN -p tcp -m conntrack --ctdir REPLY .*--sports 80 .*--connbytes 9[: ].*--queue-bypass' \
    || fail "нет полного наблюдения следующих ответов HTTP"
echo "$RULES" | grep -E -- '-A D2K_(OUT|IN) .*--(dports|sports) 80 ' | grep -q -- '--tcp-flags' \
    && fail "наблюдение HTTP ограничено флагами TCP"
iptables -t mangle -D D2K_OUT -p tcp -m conntrack --ctdir ORIGINAL -m multiport --dports 80 \
    -m connbytes --connbytes 9: --connbytes-dir original --connbytes-mode packets \
    -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass \
    || fail "правило следующих запросов HTTP не снимается точным описанием"
if fw_installed; then fail "потеря правила следующих запросов HTTP не обнаружена"; fi
fw_up
RULES=$(iptables -t mangle -S)

MARK_LINE=$(echo "$RULES" | grep -E -- '-A D2K_OUT -m mark .* -j RETURN' || true)
[ -n "$MARK_LINE" ] || fail "нет правила RETURN по метке в исходящей цепочке"
echo "$MARK_LINE" | grep -q -- '-p ' && fail "правило RETURN по метке сузили протоколом -p — UDP перестанет исключаться"
echo "$MARK_LINE" | grep -q -- '--mark 0x2f' || fail "измерительный зонд контроллера не исключён из собственного NFQUEUE"

echo "== fw_up повторно (идемпотентность) =="
fw_up
COUNT_OUT=$(iptables -t mangle -S D2K_OUT | wc -l)
# -N, 2 loopback, broadcast + multicast, 2 marks, 2 DNS, TCP/UDP queue, late
# RST/FIN, HTTP keep-alive, voice UDP. (The old 11 predates the voice and
# late-close rules.)
[ "$COUNT_OUT" -eq 16 ] || fail "повторный fw_up размножил правила D2K_OUT (строк: $COUNT_OUT, ждали 16 включая -N)"

echo "== пустые цепочки с сохранёнными переходами — НЕ работающий firewall =="
iptables -t mangle -F D2K_OUT
iptables -t mangle -F D2K_IN
iptables -t mangle -A D2K_OUT -m mark --mark "$MARK" -j RETURN
if fw_installed; then fail "переходы в пустые цепочки объявлены рабочими правилами"; fi
fw_up

echo "== потеря любого обязательного правила должна обнаруживаться =="
for round in 1 2 3; do
    fw_up >/tmp/fw-first.log 2>&1 & first=$!
    fw_up >/tmp/fw-second.log 2>&1 & second=$!
    wait "$first" || fail "first concurrent recovery failed"
    wait "$second" || fail "second concurrent recovery failed"
    fw_installed || fail "concurrent recovery left incomplete IPv4/IPv6 rules"
done
for proto in tcp udp; do
    for chain in D2K_OUT D2K_IN; do
        if [ "$chain" = D2K_OUT ]; then
            ports=--dports; direction=original; ctdir=ORIGINAL
        else
            ports=--sports; direction=reply; ctdir=REPLY
        fi
        iptables -t mangle -D "$chain" -p "$proto" -m conntrack --ctdir "$ctdir" \
            -m multiport "$ports" "$PORTS" \
            -m connbytes --connbytes "$CONNBYTES" --connbytes-dir "$direction" \
            --connbytes-mode packets -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass
        if fw_installed; then fail "потеря $proto в $chain не обнаружена"; fi
        fw_up
    done
done
for hook in POSTROUTING FORWARD INPUT; do
    chain=D2K_IN
    [ "$hook" = POSTROUTING ] && chain=D2K_OUT
    iptables -t mangle -D "$hook" -j "$chain"
    if fw_installed; then fail "потеря перехода из $hook не обнаружена"; fi
    fw_up
done
iptables -t mangle -D D2K_OUT -m mark --mark "$MARK" -j RETURN
if fw_installed; then fail "потеря исключения собственных пакетов не обнаружена"; fi
fw_up
iptables -t mangle -D D2K_OUT -m addrtype --dst-type BROADCAST -j RETURN
if fw_installed; then fail "потеря исключения IPv4 broadcast не обнаружена"; fi
fw_up
iptables -t mangle -D D2K_OUT -d 224.0.0.0/4 -j RETURN
if fw_installed; then fail "потеря исключения IPv4 multicast не обнаружена"; fi
fw_up
ip6tables -t mangle -D D2K_OUT -d ff00::/8 -j RETURN
if fw_installed; then fail "потеря исключения IPv6 multicast не обнаружена"; fi
fw_up

# Соседний случай выше доказывает, что пропажа ВИДНА. Здесь — вторая половина
# того же отказа: что восстановление её ЛЕЧИТ, и после него правила снова
# распознаются целиком. Без этой половины сторож правил (files/d2k-fw-heal.sh)
# опирался бы на необоснованное «ну fw_up же поставит».
#
# Сам отказ полевой: 12.09.2026 на роутере автора NDM сбросил правила внутри
# цепочек, оставив зацепки; служба рапортовала «правила: стоят» прежней
# проверкой, и обход был мёртв полтора часа.
iptables -t mangle -D D2K_IN -p icmp --icmp-type 11/0 -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass
if fw_installed; then fail "потеря IPv4 time-exceeded не обнаружена"; fi
fw_up
ip6tables -t mangle -D D2K_IN -p ipv6-icmp --icmpv6-type 3/0 -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass
if fw_installed; then fail "потеря ICMPv6 time-exceeded не обнаружена"; fi
fw_up

echo "== восстановление после внешнего сброса =="
iptables -t mangle -F D2K_OUT
iptables -t mangle -F D2K_IN
if fw_installed; then fail "пустые цепочки объявлены рабочими правилами"; fi
fw_up
fw_installed || fail "после восстановления правила не распознаны"

echo "== восстановление только IPv6 после сброса =="
ip6tables -t mangle -F D2K_IN
if fw_installed; then fail "потеря IPv6 ответов не обнаружена"; fi
fw_up
fw_installed || fail "IPv6 не восстановлен"
COUNT6=$(ip6tables -t mangle -S D2K_OUT | wc -l)
[ "$COUNT6" -eq 15 ] || fail "IPv6 дубли после восстановления (строк: $COUNT6, ждали 15: как IPv4, но одно multicast-исключение)"

echo "== fw_down =="
fw_down
if fw_installed; then fail "после fw_down правила объявлены установленными"; fi
LEFT=$(iptables -t mangle -S | grep -ic d2k || true)
[ "$LEFT" -eq 0 ] || fail "fw_down оставил $LEFT правил(о) с упоминанием D2K"
LEFT6=$(ip6tables -t mangle -S | grep -ic d2k || true)
[ "$LEFT6" -eq 0 ] || fail "fw_down оставил IPv6 правила"
ip6tables -t mangle -C INPUT -p ipv6-icmp -j ACCEPT || fail "чужое IPv6 правило удалено"

echo "== частичный отказ IPv6 откатывает обе семьи =="
# Fail a real IPv6 insertion after chain creation, without replacing IPv4.
ip6tables() {
    case "$*" in
        *"-A D2K_IN -p udp"*) return 1 ;;
    esac
    command ip6tables "$@"
}
if fw_up; then fail "ошибка IPv6 скрыта успешным IPv4"; fi
for tool in iptables ip6tables; do
    if "$tool" -t mangle -S | grep -q D2K; then fail "частичная установка $tool не откачена"; fi
done
unset -f ip6tables
fw_up
fw_installed || fail "запуск после частичного отказа не восстановлен"
fw_down

echo "== открытый HTTP без прокси: миграция с d2khttp (задача 51) =="
MODE=apply
# Правила прежней версии: nat-перехват порта 80 и метка его upstream.
iptables -t nat -N D2K_HTTP
iptables -t nat -A D2K_HTTP -p tcp --dport 80 -j REDIRECT --to-ports 18080
iptables -t nat -I PREROUTING -j D2K_HTTP
iptables -t mangle -N D2K_HTTP_MARK
iptables -t mangle -A D2K_HTTP_MARK -m mark --mark 0x30 -j CONNMARK --save-mark
iptables -t mangle -I OUTPUT -j D2K_HTTP_MARK
fw_up
fw_installed || fail "правила без d2khttp не распознаны"
if iptables -t nat -S | grep -q D2K_HTTP; then fail "прежний nat-перехват HTTP пережил запуск"; fi
if iptables -t mangle -S | grep -q D2K_HTTP_MARK; then fail "прежняя метка upstream HTTP пережила запуск"; fi
if iptables -t mangle -S D2K_IN | grep -q 18080; then fail "исключение порта прокси осталось"; fi
fw_down
if iptables -t nat -S | grep -q D2K_HTTP; then fail "HTTP redirect остался после остановки"; fi
if iptables -t mangle -S | grep -q D2K; then fail "метка осталась после остановки"; fi
ip6tables -t mangle -C INPUT -p ipv6-icmp -j ACCEPT || fail "миграция удалила чужое IPv6 правило"

echo "== удаление без init-скрипта =="
fw_up
sh /work/uninstall.sh
for tool in iptables ip6tables; do
    if "$tool" -t mangle -S | grep -q D2K; then fail "uninstall оставил $tool mangle цепочку"; fi
    if "$tool" -t nat -S | grep -q D2K; then fail "uninstall оставил $tool nat цепочку"; fi
done
ip6tables -t mangle -C INPUT -p ipv6-icmp -j ACCEPT || fail "uninstall удалил чужое правило"

echo "ВСЁ ЗЕЛЕНО: правила files/S99d2k проверены настоящим iptables"
DRIVER

docker run --rm --cap-add=NET_ADMIN -v "$WORK:/work" debian:bookworm-slim \
    sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq iptables >/dev/null && sh /work/driver.sh'
