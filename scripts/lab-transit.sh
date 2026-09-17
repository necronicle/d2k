#!/bin/sh
# lab-transit.sh — КЛИЕНТ ЗА РОУТЕРОМ, А НЕ РЯДОМ С ДАТАПАТОМ.
#
# ЗАЧЕМ ЭТОТ СТЕНД СУЩЕСТВУЕТ. 13.09.2026 на живом роутере выяснилось, что
# обход работал ТОЛЬКО для трафика самого роутера: собственный зонд получал
# на цели 200, а любое устройство за роутером — ноль. Разбор в
# docs/field/2026-09-13-transit-vs-local.md.
#
# Дефект прожил незамеченным потому, что его нечем было заметить: и полевая
# приёмка, и все лаборатории запускали клиента ТАМ ЖЕ, где живёт датапат. У
# такого клиента адрес уже внешний, NAT к нему не применяется, и целый класс
# ошибок — «посылка ушла не с того адреса» — невидим по построению.
#
# Здесь клиент живёт в ОТДЕЛЬНОМ сетевом пространстве и ходит через NAT
# контейнера, как устройство за роутером. Роутер не трогается ничем.
#
# ЧТО ИМЕННО ПРОВЕРЯЕТСЯ: обход доходит до клиента ЗА NAT. Не «план
# применился», не «зонд подтвердил» — оба этих факта были верны и тогда,
# когда у человека ничего не работало.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)

if ! docker info >/dev/null 2>&1; then
    echo "lab-transit.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$ROOT" -cf - --exclude='.git' --exclude='*.o' --exclude='state' . | tar -C "$WORK" -xf -

cat > "$WORK/transit.sh" <<'DRIVER'
#!/bin/sh
set -e
cd /w

NAME=${D2K_LAB_TRANSIT_NAME:-tranzit.example}
TARGET=${D2K_LAB_TRANSIT_TARGET:-local}
QUEUE=2101
MARK=0x2d
CLNS=cl
CL_IP=10.99.0.2
RT_IP=10.99.0.1
SRVNS=srv
SRV_IP=10.50.0.2
SRV_GW=10.50.0.1

fail() { echo "ПРОВАЛ: $*" >&2; dump; exit 1; }
dump() {
    echo "--- цензор ---";  tail -5 /tmp/labdpi.log 2>/dev/null || true
    echo "--- d2kd ---";    tail -25 /tmp/d2kd.log 2>/dev/null || true
    echo "--- d2kc ---";    tail -25 /tmp/d2kc.log 2>/dev/null || true
    echo "--- правила ---"; iptables -t mangle -S 2>/dev/null | grep -i d2k || true
}
inns() { ip netns exec "$CLNS" "$@"; }

echo "== подготовка =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iptables iproute2 curl iputils-ping libssl-dev >/dev/null 2>&1

# ЦЕЛЬ ПО УМОЛЧАНИЮ — СВОЙ СЕРВЕР В ОТДЕЛЬНОМ ПРОСТРАНСТВЕ, А НЕ ХОСТ В СЕТИ.
#
# Прежде стенд ходил к настоящему www.google.com, то есть его трафик уходил с
# машины и проходил через линию оператора. У автора на роутере поднят z2k, и
# его правило ловит ВЕСЬ трафик на 443 по порту (zport_tcp — набор портов, а не
# адресов). Тогда измеряются три коробки сразу: игрушечный цензор, наш датапат
# и чужой десинк, а красный результат не говорит о транзите ничего.
#
# Замер 17.09, одна и та же коробка и один и тот же код:
#   местная цель  — приём найден за 55 с, 18 зондов (disorder, вопрос 2);
#   внешняя цель  — 294 зонда за 16,8 минуты и не найдено НИЧЕГО.
#
# Свойство, ради которого стенд написан, при этом сохраняется целиком: клиент
# живёт в своём пространстве и ходит через NAT контейнера. Просто «снаружи»
# теперь тоже наше — ещё одно пространство, а не чужая сеть.
#
# Внешняя цель остаётся ключом D2K_LAB_TRANSIT_TARGET=external: это другой
# опыт, и читать его надо с оговоркой про чужую линию.
if [ "$TARGET" = "local" ]; then
    IP=$SRV_IP
    echo "цель: $NAME ($IP, своё пространство за NAT)"
else
    IP=$(getent ahostsv4 "$NAME" | awk '{print $1; exit}')
    [ -n "$IP" ] || fail "имя $NAME не разрешается"
    echo "цель: $NAME ($IP, ВНЕШНЯЯ — в замере участвует чужая линия)"
fi

echo "== сеть: клиент за NAT =="
# Отдельное сетевое пространство — это и есть «устройство за роутером».
# Контейнер играет роль роутера: у него включён форвардинг и стоит NAT.
ip netns add "$CLNS"
ip link add veth-cl type veth peer name veth-rt
ip link set veth-cl netns "$CLNS"
ip addr add "$RT_IP/24" dev veth-rt
ip link set veth-rt up
inns ip addr add "$CL_IP/24" dev veth-cl
inns ip link set veth-cl up
inns ip link set lo up
inns ip route add default via "$RT_IP"
# Форвардинг включается ключом docker run (--sysctl): /proc/sys в контейнере
# только для чтения, и менять его изнутри нельзя даже с SYS_ADMIN.
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ] || \
    fail "форвардинг выключен — контейнер не может быть роутером"
OUTIF=$(ip route show default | awk '{print $5; exit}')
[ -n "$OUTIF" ] || fail "не нашёлся выходной интерфейс контейнера"
# Клиент ходит по адресу, имена ему не нужны — но curl просит резолвер.
mkdir -p /etc/netns/"$CLNS"
echo "nameserver 8.8.8.8" > /etc/netns/"$CLNS"/resolv.conf

if [ "$TARGET" = "local" ]; then
    # «СНАРУЖИ» — ТОЖЕ НАШЕ ПРОСТРАНСТВО. Третий netns играет роль сервера в
    # интернете: клиент до него доходит только через маршрутизацию и NAT
    # контейнера, то есть ровно тот путь, ради которого стенд и написан.
    ip netns add "$SRVNS"
    ip link add veth-srv type veth peer name veth-out
    ip link set veth-out netns "$SRVNS"
    ip addr add "$SRV_GW/24" dev veth-srv
    ip link set veth-srv up
    ip netns exec "$SRVNS" ip addr add "$SRV_IP/24" dev veth-out
    ip netns exec "$SRVNS" ip link set veth-out up
    ip netns exec "$SRVNS" ip link set lo up
    ip netns exec "$SRVNS" ip route add default via "$SRV_GW"
    iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o veth-srv -j MASQUERADE
    inns ping -c 1 -W 2 "$SRV_IP" >/dev/null 2>&1 \
        || fail "клиент за NAT не видит цель — стенд неисправен, а не продукт"
    echo "клиент за NAT доходит до цели через маршрут и NAT"
else
    iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o "$OUTIF" -j MASQUERADE
    inns curl -4 -s -o /dev/null --max-time 12 "https://example.com/" \
        || fail "клиент за NAT не выходит в сеть — стенд неисправен, а не продукт"
    echo "клиент за NAT выходит в сеть"
fi

echo "== сборка =="
cc -std=c99 -O2 -Wall -Wextra -Werror -Idatapath/include -Icore/include \
   -o /tmp/labdpi spike/labdpi.c datapath/nfq.c datapath/nl.c \
   core/quic.c core/quicwire.c core/crypto.c
make -s -C datapath d2kd
make -s -C core d2kc
if [ "$TARGET" = "local" ]; then
    # Тот же форкающий сервер, что в lab-censor.sh, и по той же причине:
    # s_server обслуживает по очереди и виснет на зарезанном рукопожатии.
    cc -std=c99 -O2 -Wall -Wextra -o /tmp/labtls spike/labtls.c -lssl -lcrypto
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /tmp/k.pem -out /tmp/c.pem -days 1 -nodes -subj "/CN=$NAME" \
        -addext "subjectAltName=DNS:$NAME" >/dev/null 2>&1
    ip netns exec "$SRVNS" /tmp/labtls 443 /tmp/c.pem /tmp/k.pem >/tmp/server.log 2>&1 &
    SRV=$!
    i=0
    while ! (inns timeout 3 openssl s_client -connect "$SRV_IP:443" </dev/null \
             >/dev/null 2>&1) && [ $i -lt 50 ]; do i=$((i+1)); sleep 0.2; done
    [ $i -lt 50 ] || fail "сервер цели не поднялся"
    echo "сервер цели поднят в своём пространстве"
fi

echo "== цензор =="
# Цензор стоит ПОСЛЕ NAT и после датапата: он видит то, что реально ушло в
# сеть, — ровно как коробка провайдера. 62 хопа: то же число и та же причина,
# что в остальных лабораториях.
#
# КОРОБКА БЕЗ СБОРКИ ПОТОКА (--naive), и это выбор, а не упрощение из лени.
# Здесь проверяется ОДНО утверждение: найденный обход доходит до клиента ЗА
# NAT. Значит цензор обязан быть таким, обход которого уже доказан отдельно
# (lab-censor.sh, разрез против `-m string`). С собирающей коробкой обход —
# открытый вопрос сам по себе, и красный результат не говорил бы о транзите
# ничего: 13.09.2026 прогон с ней честно упёрся в «выведенные планы
# исчерпаны», то есть в другой вопрос.
#
# Очередь, а не `-j DROP`: вердикт очереди приходит ПОСЛЕ возврата sendto, а
# DROP локально рождённого пакета возвращает отправителю EPERM — и датапат
# мерил бы собственную реакцию на локальный отказ вместо цензуры (найдено в
# lab-censor.sh).
iptables -t mangle -N D2KQ 2>/dev/null || iptables -t mangle -F D2KQ
iptables -t mangle -A POSTROUTING -j D2KQ
iptables -t mangle -A D2KQ -p tcp --dport 443 -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
/tmp/labdpi "$QUEUE" "$NAME" 62 --naive > /tmp/labdpi.log 2>&1 &
DPI=$!
sleep 1

if inns curl -4 -sk -o /dev/null --resolve "$NAME:443:$IP" --max-time 12 "https://$NAME/" 2>/dev/null; then
    fail "цензор не режет: клиент за NAT прошёл мимо него"
fi
echo "цензор на месте: клиент за NAT к $NAME не проходит"

echo "== d2k =="
mkdir -p /tmp/d2kst
# Правила — ТЕ ЖЕ, что ставит files/S99d2k на роутере, включая MASQUERADE для
# собственных посылок по UDP: стенд обязан проверять продукт, а не свою
# выдумку о нём.
iptables -t mangle -N D2K_OUT 2>/dev/null || iptables -t mangle -F D2K_OUT
iptables -t mangle -N D2K_IN  2>/dev/null || iptables -t mangle -F D2K_IN
iptables -t mangle -A D2K_OUT -m mark --mark "$MARK" -j RETURN
iptables -t mangle -A D2K_OUT -p tcp --dport 443 \
    -m connbytes --connbytes 0:8 --connbytes-dir original --connbytes-mode packets \
    -j NFQUEUE --queue-num 2000 --queue-bypass
iptables -t mangle -A D2K_IN -p tcp --sport 443 \
    -m connbytes --connbytes 0:8 --connbytes-dir reply --connbytes-mode packets \
    -j NFQUEUE --queue-num 2000 --queue-bypass
iptables -t nat -A POSTROUTING -p udp -m mark --mark "$MARK" -j MASQUERADE
# ИСХОДЯЩЕЕ ЛОВИМ В OUTPUT И FORWARD, А НЕ В POSTROUTING — требование
# СТЕНДА, не продукта. Вердикт очереди завершает проход ЦЕПОЧКИ: правило
# цензора, стоящее в той же цепочке после d2k, не выполняется вовсе (та же
# находка, что в docs/field/2026-09-13-lab-censor.md про --queue-bypass).
# Цензор обязан видеть то, что ВЫПУСТИЛ датапат, — значит он остаётся один в
# POSTROUTING, а датапат разводится по двум цепочкам, которые проходятся
# раньше: FORWARD для транзита клиента и OUTPUT для собственных зондов
# контроллера. Без OUTPUT зонд подтверждения не получает плана и не может
# подтвердить ничего.
#
# На роутере обе роли берёт одна цепочка в POSTROUTING (files/S99d2k); здесь
# она разделена только затем, чтобы поместить между ними цензор.
iptables -t mangle -I FORWARD -j D2K_OUT
iptables -t mangle -I FORWARD -j D2K_IN
iptables -t mangle -I OUTPUT -j D2K_OUT
iptables -t mangle -I INPUT -j D2K_IN

./datapath/d2kd --mode apply --control /tmp/d2kst/sock --queue 2000 --mark 45 \
    --journal 400 --duration 300 --stats 30 > /tmp/d2kd.log 2>&1 &
DPID=$!
i=0; while [ ! -S /tmp/d2kst/sock ] && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.1; done
[ -S /tmp/d2kst/sock ] || fail "датапат не открыл управляющий сокет"
./core/d2kc --control /tmp/d2kst/sock --catalog /tmp/d2kst/catalog.json > /tmp/d2kc.log 2>&1 &
CPID=$!
sleep 1

echo "== обращение КЛИЕНТА ЗА NAT =="
for n in 1 2 3 4; do
    inns curl -4 -sk -o /dev/null --resolve "$NAME:443:$IP" --max-time 15 "https://$NAME/" 2>/dev/null || true
    sleep 4
done

# СКОЛЬКО ЖДАТЬ ПОИСКА — ЧИСЛО ИЗМЕРЕННОЕ, А НЕ КРУГЛОЕ.
#
# Прежние две минуты были меньше, чем поиск здесь идёт: прогон 17.09 отчитался
# «клиент не прошёл» на замере, который в тот момент шёл третью минуту. Стенд
# мерил собственное окно, а не движок. Потолок самого движка — срок задачи
# (SCHED_TASK_LIFE_MS, десять минут), и ждать дольше него бессмысленно: после
# него поиск бросается и в журнале появляется «брошен».
#
# Ждём до шести минут и ВСЛУХ говорим, сколько прождали: если стенд снова
# упрётся в окно, это будет видно из вывода, а не из чужого секундомера.
WAITED=0
i=0
while [ $i -lt 120 ]; do
    grep -q "ПОДТВЕРЖДЕНО" /tmp/d2kc.log 2>/dev/null && break
    grep -q "брошен" /tmp/d2kc.log 2>/dev/null && break
    i=$((i+1)); WAITED=$((WAITED+3)); sleep 3
done
echo "ждали подтверждения $WAITED с"
sed -n 's/.*вердикт: \(.*\)/  вердикт: \1/p' /tmp/d2kc.log | tail -2

echo "== проверка: прошёл ли КЛИЕНТ, а не зонд =="
OK=0
for n in 1 2 3; do
    CODE=$(inns curl -4 -sk -o /dev/null --resolve "$NAME:443:$IP" -w "%{http_code}" --max-time 20 "https://$NAME/" 2>/dev/null) || CODE=""
    [ -n "$CODE" ] || CODE=000
    echo "  попытка $n: код=$CODE"
    [ "$CODE" = "200" ] && OK=$((OK+1))
    sleep 2
done

# ЦЕНЗОР ОБЯЗАН БЫТЬ ЖИВ И ОБЯЗАН БЫЛ РЕЗАТЬ. Правило очереди стоит с
# --queue-bypass (иначе смерть стенда остановила бы весь трафик), а значит
# умерший цензор пропускает всё — и «клиент прошёл» означало бы ровно
# ничего. Первый же прогон этого стенда 13.09.2026 отчитался «3 из 3» при
# нуле подозрений и нуле применённых планов: клиент прошёл сам.
kill -0 "$DPI" 2>/dev/null || fail "цензор умер во время прогона — проверять было нечем"
kill "$DPI" 2>/dev/null || true
i=0
while kill -0 "$DPI" 2>/dev/null && [ $i -lt 50 ]; do i=$((i+1)); sleep 0.2; done
kill -0 "$DPI" 2>/dev/null && fail "цензор не вышел по сигналу — счётчики не прочитать"
wait "$DPI" 2>/dev/null || true
DROPPED=$(sed -n 's/.*снято по имени \([0-9]*\).*/\1/p' /tmp/labdpi.log | tail -1)
[ -n "$DROPPED" ] || DROPPED=0

kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true
[ -n "${SRV:-}" ] && { kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; }
kill "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true

dump
echo "цензор снял по имени: $DROPPED"
[ "$DROPPED" -gt 0 ] || fail "цензор не снял НИ ОДНОГО пакета по имени — прогон ничего не проверил"

# Обход обязан быть НАЙДЕН И ПРИМЕНЁН, а не «клиент случайно прошёл».
grep -q "ПОДТВЕРЖДЕНО" /tmp/d2kc.log 2>/dev/null || \
    fail "клиент прошёл, но план никто не подтверждал — прошёл не обход"

if [ "$OK" -ge 2 ]; then
    echo
    echo "ОБХОД ДОШЁЛ ДО КЛИЕНТА ЗА NAT: $OK из 3"
    exit 0
fi

# Зонд, подтвердивший план, при неработающем клиенте — это ровно тот случай,
# ради которого стенд написан: доказательство настоящее, но не про тот путь.
if grep -q "ПОДТВЕРЖДЕНО" /tmp/d2kc.log 2>/dev/null; then
    fail "зонд подтвердил план, а клиент за NAT не прошёл — обход не доходит до транзита"
fi
fail "обход не найден вовсе (клиент за NAT: $OK из 3)"
DRIVER

# SYS_ADMIN нужен ровно для одного: завести сетевое пространство клиента
# (`ip netns` монтирует /run/netns). Без него стенд не отличается от прежних —
# клиент оказывается рядом с датапатом, и проверять нечего.
docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SYS_ADMIN \
    --sysctl net.ipv4.ip_forward=1 \
    -e "D2K_LAB_TRANSIT_NAME=${D2K_LAB_TRANSIT_NAME:-tranzit.example}" \
    -e "D2K_LAB_TRANSIT_TARGET=${D2K_LAB_TRANSIT_TARGET:-local}" \
    -v "$WORK:/w" -w /w gcc:14 sh /w/transit.sh
