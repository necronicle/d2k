#!/bin/sh
# lab-quic.sh — АВТОНОМНЫЙ ПОИСК ОБХОДА ПО QUIC, без роутера.
#
# Чем отличается от lab-censor.sh. Там цель — свой сервер на петле, и цензор
# режет TCP. Здесь иначе: СЕРВЕР НАСТОЯЩИЙ, из интернета, а цензор свой и стоит
# на выходе контейнера. Причина не в лени: своего сервера QUIC у нас нет, а
# писать его ради опыта значило бы проверять себя собой. Настоящий сервер даёт
# то, чего петля не даёт никогда — чужую реализацию на том конце.
#
# Цензор (spike/labdpi.c --quic) достаёт имя из ЗАШИФРОВАННОГО Initial ровно
# так же, как настоящая коробка: ключами, выведенными из идентификатора
# соединения, который лежит открытым текстом. Это не игрушка в том смысле, в
# каком игрушечно строковое правило: механизм здесь тот же, что у настоящего
# DPI по QUIC.
#
# Требует Docker и выход в интернет. Роутер не трогает ничем.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)

if ! docker info >/dev/null 2>&1; then
    echo "lab-quic.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$ROOT" -cf - --exclude='.git' --exclude='*.o' --exclude='state' . | tar -C "$WORK" -xf -

cat > "$WORK/quic.sh" <<'DRIVER'
#!/bin/sh
set -e
cd /w

fail() { echo "ПРОВАЛ: $*" >&2; dump; exit 1; }
dump() {
    echo "--- цензор ---"; tail -5 /tmp/labdpi.log 2>/dev/null || true
    echo "--- d2kd ---"; tail -30 /tmp/d2kd.log 2>/dev/null || true
    echo "--- d2kc ---"; tail -40 /tmp/d2kc.log 2>/dev/null || true
}

NAME=${D2K_LAB_QUIC_NAME:-www.google.com}
QUEUE=2101
MARK=0x2d
# КАКАЯ КОРОБКА. first — заводит состояние на пятёрку и разбирает ПЕРВУЮ
# датаграмму потока (ради таких в каталоге плеч есть приманки); all — разбирает
# КАЖДУЮ датаграмму и приманкой не обманывается вовсе. Обе настоящие, и
# ответы у вертикали на них РАЗНЫЕ: на первой обход обязан найтись, на второй
# — честно не найтись. Умолчание — first: она замыкает петлю целиком.
BOX=${D2K_LAB_QUIC_BOX:-first}

echo "== подготовка =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iptables iproute2 >/dev/null 2>&1
ip link set lo mtu 1500 2>/dev/null || true

IP=$(getent ahostsv4 "$NAME" | awk '{print $1; exit}')
[ -n "$IP" ] || fail "имя $NAME не разрешается"
echo "цель: $NAME ($IP)"

echo "== сборка =="
cc -std=c99 -O2 -Wall -Wextra -Werror -Idatapath/include -Icore/include \
   -o /tmp/labdpi spike/labdpi.c datapath/nfq.c datapath/nl.c \
   core/quic.c core/quicwire.c core/crypto.c
cc -std=c99 -O2 -Wall -Wextra -Werror -Icore/include -o /tmp/quicping \
   spike/quicping.c core/quicconn.c core/quicwire.c core/tls13core.c \
   core/h3.c core/crypto.c core/x25519.c core/meas.c
make -s -C datapath d2kd >/dev/null
cp datapath/d2kd /tmp/d2kd
make -s -C core d2kc >/dev/null

echo "== линия без цензора: клиент обязан работать =="
timeout 20 /tmp/quicping "$IP" "$NAME" || fail "по чистой линии QUIC не работает — опыт мерил бы нас, а не цензора"

echo "== цензор по QUIC =="
# 62 хопа — то же число и та же причина, что в lab-censor.sh: плечо с
# укороченным TTL обязано умереть до сервера, но быть увиденным коробкой.
BOXFLAG=
[ "$BOX" = "first" ] && BOXFLAG=--first
/tmp/labdpi "$QUEUE" "$NAME" 62 --quic $BOXFLAG > /tmp/labdpi.log 2>&1 &
DPI=$!
sleep 1
# ЦЕНЗОР — В POSTROUTING, ПОСЛЕ d2k, и это не стиль.
# Датапат стоит в OUTPUT: он ВИДОИЗМЕНЯЕТ поток, а цензор смотрит на то, что
# получилось. Поставь цензор раньше — он снимет датаграмму до того, как
# датапат её увидит, и поиск не начнётся вовсе: ровно это и вышло на первом
# прогоне (приветствий 0, подозрений 0). Собственные посылки датапата идут
# сырым сокетом и начинают путь заново с raw OUTPUT, поэтому до цензора в
# POSTROUTING они доходят — то есть цензор видит ИМЕННО то, что выпустил d2k.
iptables -t mangle -N D2KQ 2>/dev/null || iptables -t mangle -F D2KQ
iptables -t mangle -A POSTROUTING -j D2KQ
# БЕЗ ПРИВЯЗКИ К АДРЕСУ. Коробка режет по ИМЕНИ и адресом не интересуется —
# а подтверждение плеча вертикаль нарочно уносит на свежий адрес из того же
# резолвера (чтобы не попасть в остаточную блокировку). Оставь здесь -d $IP,
# и подтверждение ушло бы мимо цензора: стенд подтверждал бы сам себя.
iptables -t mangle -A D2KQ -p udp --dport 443 \
    -j NFQUEUE --queue-num "$QUEUE" --queue-bypass

if timeout 20 /tmp/quicping "$IP" "$NAME" >/dev/null 2>&1; then
    fail "цензор не режет: QUIC прошёл мимо него"
fi
echo "цензор на месте ($BOX): имя достаётся из зашифрованного Initial, датаграмма снимается"

CAT=/tmp/labq-catalog.json; rm -f "$CAT"
SOCK=/tmp/labq.sock; rm -f "$SOCK"

echo "== датапат и контроллер, каталог ПУСТОЙ =="
# Очередь d2k — СВОЯ и ПОСЛЕ цензора в цепочке: датапат обязан видеть то, что
# уже прошло цензора, а его собственные посылки идут мимо цензора по метке.
iptables -t mangle -N D2KD 2>/dev/null || iptables -t mangle -F D2KD
iptables -t mangle -A OUTPUT -j D2KD
iptables -t mangle -A D2KD -m mark --mark "$MARK" -j RETURN
# Тоже без привязки к адресу, и по той же причине: датапат обязан видеть те
# же потоки, что и цензор, включая уходящие на свежий адрес.
iptables -t mangle -A D2KD -p udp --dport 443 \
    -m connbytes --connbytes 0:8 --connbytes-dir original --connbytes-mode packets \
    -j NFQUEUE --queue-num 2102 --queue-bypass
iptables -t mangle -A INPUT -p udp --sport 443 \
    -m connbytes --connbytes 0:8 --connbytes-dir reply --connbytes-mode packets \
    -j NFQUEUE --queue-num 2102 --queue-bypass

/tmp/d2kd --mode apply --control "$SOCK" --queue 2102 --mark 45 \
    --journal 400 --duration 300 > /tmp/d2kd.log 2>&1 &
DPID=$!
i=0; while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.1; done
[ -S "$SOCK" ] || fail "датапат не открыл управляющий сокет"
./core/d2kc --control "$SOCK" --catalog "$CAT" > /tmp/d2kc.log 2>&1 &
CPID=$!
sleep 1

echo "== обращение пользователя по QUIC =="
for n in 1 2 3; do
    timeout 20 /tmp/quicping "$IP" "$NAME" >/dev/null 2>&1 || true
    sleep 3
done

# Ждём КОНЦА поиска, а не первого обнадёживающего слова. «Плечо подобрано» —
# ещё не обход: план после этого надо собрать, поставить и подтвердить
# зондом. А на коробке без состояния поиск честно кончается ничем, и это
# тоже конец — но наступает он через минуты: лестница плеч разворачивает TTL
# снизу, шаг за шагом. Пять минут потолка на обе развязки.
i=0
while [ $i -lt 100 ]; do
    grep -q "ПОДТВЕРЖДЕНО" /tmp/d2kc.log 2>/dev/null && break
    grep -q "плечо не \|вердикта нет\|верить нельзя" /tmp/d2kc.log 2>/dev/null && break
    i=$((i+1)); sleep 3
done

echo "== настоящий клиент через цензора =="
if timeout 25 /tmp/quicping "$IP" "$NAME"; then
    CLIENT_OK=1
else
    CLIENT_OK=0
fi

kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true
kill "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true
kill "$DPI" 2>/dev/null || true

dump
echo "--- каталог ---"; cat "$CAT" 2>/dev/null || echo "(каталога нет)"

grep -q "подозрение\|начинаю поиск" /tmp/d2kc.log || \
    fail "d2k не заметил проблемного трафика по QUIC — поиск не начался"

if [ "$CLIENT_OK" = "1" ] && [ -s "$CAT" ] && grep -q '"target"' "$CAT"; then
    echo "ОБХОД ПО QUIC НАЙДЕН АВТОНОМНО: привязка записана И настоящий клиент прошёл"
    exit 0
fi
if [ -s "$CAT" ] && grep -q '"target"' "$CAT"; then
    fail "привязка есть, а клиент не прошёл — ложное подтверждение по QUIC"
fi
if [ "$BOX" = "first" ]; then
    # На коробке с состоянием плечо ОБЯЗАНО найтись: приманка перед
    # приветствием — ровно то воздействие, ради которого каталог плеч и
    # существует. Не нашлось — это провал вертикали, а не свойство сети.
    fail "плеча не нашлось на коробке, разбирающей ТОЛЬКО первую датаграмму — приманка обязана её обманывать"
fi
echo "ПЛЕЧА ПО QUIC НЕ НАШЛОСЬ — это находка, а не поломка: запас воздействий"
echo "d2k не покрывает коробку, читающую имя из КАЖДОЙ датаграммы."
exit 0
DRIVER

docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -e "D2K_LAB_QUIC_NAME=${D2K_LAB_QUIC_NAME:-www.google.com}" \
    -e "D2K_LAB_QUIC_BOX=${D2K_LAB_QUIC_BOX:-first}" \
    -v "$WORK:/w" -w /w gcc:14 sh /w/quic.sh
