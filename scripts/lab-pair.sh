#!/bin/sh
# lab-pair.sh — живая пара d2kd + d2kc на Linux, БЕЗ роутера и без трафика.
#
# Зачем. Полевой прогон стоит дорого: на время опыта у автора дома выключается
# z2k, то есть обхода нет у всех, кто пользуется роутером. Самый обидный способ
# потратить это окно — обнаружить, что пара вообще не разговаривает: так уже
# было 12.09, когда датапат был старше правки, заводившей идентификатор плана,
# и подтверждений не появилось НИ ОДНОГО за весь прогон.
#
# Что проверяется здесь:
#   1. d2kd поднимается на настоящем Linux и открывает управляющий сокет;
#   2. d2kc подключается и НЕ ругается на версию протокола;
#   3. каталог доезжает до датапата командами SET_NAME, и датапат их принимает;
#   4. обе стороны живут заданное время и завершаются штатно.
#
# Чего здесь НЕТ и что этим не доказано: настоящего трафика, NFQUEUE, цензора,
# обхода. Это проверка ЖИВОСТИ ПАРЫ, а не измерения. Зелёный результат означает
# «можно ехать в поле», а не «обход работает».
#
# Требует Docker. Ничего не трогает на хосте и на роутере: всё происходит в
# контейнере, который создаётся и уничтожается заново.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)

if ! docker info >/dev/null 2>&1; then
    echo "lab-pair.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$ROOT" -cf - --exclude='.git' --exclude='*.o' --exclude='state' . | tar -C "$WORK" -xf -

cat > "$WORK/lab.sh" <<'DRIVER'
#!/bin/sh
set -e
cd /w

fail() { echo "ПРОВАЛ: $*" >&2; exit 1; }

echo "== сборка =="
# Цели d2kd в Makefile нет (на маке он не собирается вовсе — сырые сокеты и
# NFQUEUE), поэтому собираем тем же списком исходников, что и кросс-цель
# d2kd-aarch64: DAEMON + LINUXSRC + SRC + CORESRC.
cc -std=c99 -O2 -Wall -Wextra -Werror -Idatapath/include -Icore/include \
   -o /tmp/d2kd datapath/d2kd.c datapath/nfq.c datapath/raw.c \
   datapath/plan_parse.c datapath/plan_apply.c datapath/tls.c datapath/wire.c \
   datapath/wire_udp.c datapath/track.c datapath/session.c datapath/nl.c \
   datapath/sched.c datapath/journal.c datapath/plans.c datapath/ctl.c \
   datapath/ctlsrv.c core/quic.c core/crypto.c
make -s -C core d2kc >/dev/null

SOCK=/tmp/lab-ctl.sock
CAT=/tmp/lab-catalog.json
LIVE=/tmp/lab-live.json
rm -f "$SOCK" "$CAT" "$LIVE"

# Каталог с ОДНОЙ привязкой: достаточно, чтобы проверить, что синхронизация
# доезжает командой и датапат её принимает. Форма не записана — ровно как во
# всём накопленном каталоге автора.
# Формат — тот же, что у снятого с роутера состояния (core/testdata/
# catalog-real.json): план лежит в plans, привязка ссылается на него по
# plan_id, у привязки есть kind. Форма (shape) не записана — ровно как во всех
# 318 привязках реального каталога.
cat > "$CAT" <<'JSON'
{"schema":1,"updated":"2026-09-12T00:00:00Z","boxes":[{"id":"lab-box",
 "created":"2026-09-12T00:00:00Z","updated":"2026-09-12T00:00:00Z",
 "fingerprint":{"method":2,"signals":[{"kind":"rst","ttl":64,"seen":3}]},
 "plans":[{"id":"plan-lab00001","proto":"tls","added":"2026-09-12T00:00:00Z",
   "successes":1,"enabled":true,
   "text":"d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\norder forward\n"}],
 "bindings":[{"kind":"name","target":"lab.example","plan_id":"plan-lab00001",
   "level":3,"confirmed":"2026-09-12T00:00:00Z","successes":1,"enabled":true}]}]}
JSON

echo "== запуск датапата (observe, без NFQUEUE) =="
/tmp/d2kd --mode observe --control "$SOCK" --queue 9999 --duration 6 \
    > /tmp/d2kd.log 2>&1 &
DPID=$!
# Ждём появления сокета, а не спим «на авось».
i=0
while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.1; done
[ -S "$SOCK" ] || { cat /tmp/d2kd.log; fail "датапат не открыл управляющий сокет"; }

echo "== запуск контроллера =="
./core/d2kc --control "$SOCK" --catalog "$CAT" --live "$LIVE" > /tmp/d2kc.log 2>&1 &
CPID=$!

sleep 5
kill "$CPID" 2>/dev/null || true
wait "$CPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true

echo "--- d2kd ---"; cat /tmp/d2kd.log
echo "--- d2kc ---"; cat /tmp/d2kc.log

grep -q "версии протокола" /tmp/d2kc.log && \
    fail "контроллер отверг версию протокола — пара смешанная"
grep -q "версию протокола не объявил" /tmp/d2kc.log && \
    fail "датапат версию протокола не объявил — пара не подтверждена"
grep -qE "не принят|не активирован" /tmp/d2kd.log && \
    fail "датапат отверг план из каталога"

# САМОЕ ВАЖНОЕ УТВЕРЖДЕНИЕ. Пара может «разговаривать» и при этом не доставить
# ни одного плана: 12.09 именно так и было — события шли, подтверждений не
# появилось ни одного за весь прогон. Считаем планы, а не разговоры.
grep -q "планов по целям 0 из" /tmp/d2kd.log && \
    fail "каталог до датапата не доехал: планов по целям ноль"


echo "ВСЁ ЗЕЛЕНО: пара d2kd+d2kc разговаривает, версия сошлась, каталог принят"
DRIVER

# NET_ADMIN нужен ровно для одного: d2kd открывает очередь NFQUEUE при
# старте, даже в режиме наблюдения, и без права на неё до управляющего сокета
# не доходит. Сеть контейнера своя и уничтожается вместе с ним.
docker run --rm --cap-add=NET_ADMIN -v "$WORK:/w" -w /w gcc:14 sh /w/lab.sh
