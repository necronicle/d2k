#!/bin/sh
# lab-censor.sh — АВТОНОМНЫЙ ПОИСК ОБХОДА на игрушечном цензоре, без роутера.
#
# Зачем. Полевой прогон стоит окна, в котором у автора дома нет обхода. Всё,
# что можно проверить до него, надо проверить до него. lab-pair.sh доказывает,
# что пара разговаривает; здесь проверяется то, ради чего d2k существует:
# пустой каталог → заблокированная цель → автономно найденное воздействие.
#
# Цензор игрушечный и назван таковым: правило iptables -m string режет ПАКЕТ,
# в котором встретилось имя. Это не модель реального DPI, а его самая простая
# форма — и она честно обходится тем же, чем обходится настоящая: если имя
# разнесено между сегментами, ни в одном пакете целой строки нет.
#
# Чего здесь НЕТ: настоящего цензора, настоящей линии, переносимости на
# клиента. Зелёный результат значит «механизм поиска работает от начала до
# конца», а не «обход работает у пользователя».
#
# Требует Docker. Ничего не трогает на хосте и на роутере.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)

if ! docker info >/dev/null 2>&1; then
    echo "lab-censor.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$ROOT" -cf - --exclude='.git' --exclude='*.o' --exclude='state' . | tar -C "$WORK" -xf -

cat > "$WORK/censor.sh" <<'DRIVER'
#!/bin/sh
set -e
cd /w

fail() { echo "ПРОВАЛ: $*" >&2; dump; exit 1; }
dump() {
    echo "--- ошибки отправки (все) ---"
    grep -iE "sendto|d2kd: " /tmp/d2kd.log 2>/dev/null | sort | uniq -c | head -20 || true
    echo "--- d2kd ---"; tail -40 /tmp/d2kd.log 2>/dev/null || true
    echo "--- d2kc ---"; tail -60 /tmp/d2kc.log 2>/dev/null || true
    echo "--- правила ---"; iptables -t mangle -S 2>/dev/null || true
}

NAME=zablokirovano.example
PORT=4443
QUEUE=2001
MARK=0x2d

echo "== подготовка =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iptables socat >/dev/null 2>&1

# Цель: настоящий сервер TLS 1.3, ФОРКАЮЩИЙ.
#
# openssl s_server однопоточен, и это ломает опыт целиком: зарезанное цензором
# рукопожатие оставляет его ждать внутри SSL_accept, и следующие соединения —
# включая контрольное — не обслуживаются вовсе. Отличить «цензор режет» от
# «сервер занят» стало бы нечем.
#
# Свой сертификат: проверка подлинности здесь не предмет опыта (её и наш зонд
# не делает, см. 0006). Предмет — доходит ли приветствие до сервера.
openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem \
    -days 1 -nodes -subj "/CN=$NAME" >/dev/null 2>&1
cat /tmp/c.pem /tmp/k.pem > /tmp/both.pem
socat "OPENSSL-LISTEN:$PORT,fork,reuseaddr,cert=/tmp/both.pem,verify=0" \
    SYSTEM:'printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"' \
    >/tmp/server.log 2>&1 &
SRV=$!
i=0
while ! (timeout 3 openssl s_client -connect "127.0.0.1:$PORT" </dev/null >/dev/null 2>&1) && [ $i -lt 50 ]; do
    i=$((i+1)); sleep 0.2
done
[ $i -lt 50 ] || fail "сервер цели не поднялся" 

echo "== сборка =="
cc -std=c99 -O2 -Wall -Wextra -Werror -Idatapath/include -Icore/include \
   -o /tmp/d2kd datapath/d2kd.c datapath/nfq.c datapath/raw.c \
   datapath/plan_parse.c datapath/plan_apply.c datapath/tls.c datapath/wire.c \
   datapath/wire_udp.c datapath/track.c datapath/session.c datapath/nl.c \
   datapath/sched.c datapath/journal.c datapath/plans.c datapath/ctl.c \
   datapath/ctlsrv.c core/quic.c core/crypto.c
make -s -C core d2kc >/dev/null

echo "== цензор: режем пакет, в котором встретилось имя =="
# ОЧЕРЕДЬ И ЦЕНЗОР — В РАЗНЫХ ХУКАХ, и это не стиль, а необходимость.
#
# Замерено здесь же: `-j NFQUEUE --queue-bypass` БЕЗ слушателя не «пропускает
# дальше по цепочке», а завершает обход хука целиком — правило, стоящее в той
# же цепочке следом, не выполняется вовсе. Поставив цензор за очередью в одной
# цепочке, мы получали бы «цензор не режет» ровно тогда, когда датапат не
# запущен, то есть в самый неудачный момент.
#
# Поэтому: очередь в mangle OUTPUT, цензор в mangle POSTROUTING. Для локально
# рождённого пакета порядок хуков — raw OUTPUT, mangle OUTPUT, nat OUTPUT,
# filter OUTPUT, mangle POSTROUTING. Пакеты, которые датапат выпускает сам,
# идут сырым сокетом и начинают путь заново с raw OUTPUT, в mangle OUTPUT
# отсекаются по метке и доходят до цензора в POSTROUTING — то есть цензор
# видит ИМЕННО то, что выпустил датапат.
iptables -t mangle -N D2KLAB 2>/dev/null || iptables -t mangle -F D2KLAB
iptables -t mangle -A OUTPUT -j D2KLAB
# Свои пакеты мимо очереди — иначе выпущенное датапатом вернётся ему же.
iptables -t mangle -A D2KLAB -m mark --mark "$MARK" -j RETURN
iptables -t mangle -A D2KLAB -p tcp --dport "$PORT" \
    -m connbytes --connbytes 0:20 --connbytes-dir original --connbytes-mode packets \
    -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
# ЦЕНЗОР — НА ПРИЁМНОЙ СТОРОНЕ, и это не мелочь.
#
# Замерено здесь же: DROP локально рождённого пакета в ИСХОДЯЩЕМ пути
# возвращает отправителю EPERM из sendto. Датапат честно считает это ошибкой
# отправки, объявляет опыт несостоявшимся и уходит к следующему кандидату —
# то есть лаборатория меряла бы собственную реакцию на локальный отказ, а не
# обход цензуры. Настоящий DPI роняет пакет на проводе, и отправитель об этом
# не узнаёт.
#
# Для петли путь такой: OUTPUT → POSTROUTING → (петля) → PREROUTING → INPUT.
# Роняем в PREROUTING: отправка уже состоялась, до сервера не дошло — ровно
# то, что делает цензор.
iptables -t mangle -A PREROUTING -p tcp --dport "$PORT" \
    -m string --string "$NAME" --algo bm -j DROP

echo "== цензор работает? =="
if timeout 5 openssl s_client -connect "127.0.0.1:$PORT" -servername "$NAME" \
       -tls1_3 </dev/null >/dev/null 2>&1; then
    fail "цензор не режет: соединение с заблокированным именем прошло"
fi
if ! timeout 5 openssl s_client -connect "127.0.0.1:$PORT" -servername control.example \
       -tls1_3 </dev/null >/dev/null 2>&1; then
    fail "цензор режет ЛИШНЕЕ: контрольное имя тоже не проходит"
fi
echo "цензор на месте: заблокированное имя не проходит, контрольное проходит"

CAT=/tmp/lab-catalog.json
rm -f "$CAT"
SOCK=/tmp/lab-ctl.sock; rm -f "$SOCK"

echo "== датапат в режиме apply =="
# Журнал включён: без него «подготовлен 15, доисполнен 1» остаётся загадкой,
# а с ним видно судьбу КАЖДОЙ попытки.
/tmp/d2kd --mode apply --control "$SOCK" --queue "$QUEUE" --mark 45 \
    --journal 400 --duration 120 > /tmp/d2kd.log 2>&1 &
DPID=$!
i=0; while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.1; done
[ -S "$SOCK" ] || fail "датапат не открыл управляющий сокет"

echo "== контроллер, каталог ПУСТОЙ =="
./core/d2kc --control "$SOCK" --catalog "$CAT" > /tmp/d2kc.log 2>&1 &
CPID=$!
sleep 1

echo "== обращение пользователя к заблокированной цели =="
for n in 1 2 3; do
    timeout 8 openssl s_client -connect "127.0.0.1:$PORT" -servername "$NAME" \
        -tls1_3 </dev/null >/dev/null 2>&1 || true
    sleep 2
done

# Поиск идёт своим ходом: ждём результата, а не спим наугад.
i=0
while [ $i -lt 60 ]; do
    grep -q "подтверждено\|привязк" /tmp/d2kc.log 2>/dev/null && break
    i=$((i+1)); sleep 2
done

kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true
kill "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true
kill "$SRV" 2>/dev/null || true

dump

grep -q "подозрение\|начинаю поиск" /tmp/d2kc.log || \
    fail "d2k не заметил проблемного трафика — поиск не начался"
echo "ВСЁ ЗЕЛЕНО (предварительно): поиск начался; смотри выше, чем он кончился"
DRIVER

docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -v "$WORK:/w" -w /w gcc:14 sh /w/censor.sh
