#!/bin/sh
# lab-quic-compare.sh — ПРИЁМКА ПЕРЕНОСА QUIC: эталон и порт обязаны дать один
# и тот же ответ на одну и ту же коробку.
#
# Это то самое «тесты соответствия» из пункта 4 чеклиста, и единственная его
# часть, которую можно показать БЕЗ роутера: коробка здесь своя (spike/labdpi.c
# в режиме --quic), а значит одна и та же для обоих инструментов, и её
# способности известны по коду — то есть известен и ПРАВИЛЬНЫЙ ответ.
#
# ЧЕГО ЭТА СВЕРКА НЕ ДАЁТ, И ЭТО НАЗВАНО ЗДЕСЬ, А НЕ ПРОПУЩЕНО.
#
# 1. ПРИВЕТСТВИЯ У ДВОИХ РАЗНЫЕ. Эталон собирает своё (crypto/tls), порт
#    ПЕРЕСОБИРАЕТ снятое у живого клиента — это осознанное расхождение, ради
#    которого весь core/quichello.c и написан (коробка сличает форму
#    настоящего клиента). У TCP-сверки общий триггер снимается ключом
#    --dump-trigger; у QUIC такого ключа у эталона нет. Против ЭТОЙ коробки
#    расхождение не мешает: она достаёт из Initial только имя и на форму не
#    смотрит вовсе. Против настоящей — помешало бы, и сверять там надо иначе.
# 2. Восьмого вопроса эталона (фальшивка с разрешённым именем) нет ни у
#    кого: файлов блобов в контейнере нет, эталон честно скажет «не измерено».
# 3. Это ЛАБОРАТОРИЯ. Совпадение здесь не переносится на живую коробку.
#
# Требует Docker и выход в интернет (сервер настоящий: своего QUIC-сервера у
# нас нет, а писать его ради опыта значило бы проверять себя собой).
# Роутер не трогает ничем.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)
REF=${D2K_REF_BIN:-/tmp/z2k-detect-linux-arm64}

if ! docker info >/dev/null 2>&1; then
    echo "lab-quic-compare.sh: нужен запущенный Docker" >&2
    exit 1
fi
if [ ! -f "$REF" ]; then
    cat >&2 <<MSG
lab-quic-compare.sh: нет эталонного бинарника $REF

Собрать под ту же арку, что у контейнера:
  cd /Library/Zapret2/z2k/z2k-detect
  GOOS=linux GOARCH=\$(docker run --rm gcc:14 uname -m | sed s/aarch64/arm64/) \\
    CGO_ENABLED=0 \$HOME/go/bin/go1.25.12 build -o $REF ./cmd/z2k-detect
MSG
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$ROOT" -cf - --exclude='.git' --exclude='*.o' --exclude='state' . | tar -C "$WORK" -xf -
cp "$REF" "$WORK/z2k-detect"
chmod +x "$WORK/z2k-detect"

cat > "$WORK/cmp.sh" <<'DRIVER'
#!/bin/sh
set -e
cd /w

fail() { echo "ПРОВАЛ: $*" >&2; exit 1; }

NAME=${D2K_LAB_QUIC_NAME:-www.google.com}
BOX=${D2K_LAB_QUIC_BOX:-first}
QUEUE=2101
MARK=0x2d

echo "== подготовка =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iptables iproute2 python3 >/dev/null 2>&1
ip link set lo mtu 1500 2>/dev/null || true

IP=$(getent ahostsv4 "$NAME" | awk '{print $1; exit}')
[ -n "$IP" ] || fail "имя $NAME не разрешается"
echo "цель: $NAME ($IP), коробка: $BOX"

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
timeout 20 /tmp/quicping "$IP" "$NAME" >/dev/null 2>&1 \
    || fail "по чистой линии QUIC не работает — сверка мерила бы нас, а не коробку"

echo "== цензор по QUIC =="
BOXFLAG=
[ "$BOX" = "first" ] && BOXFLAG=--first
/tmp/labdpi "$QUEUE" "$NAME" 62 --quic $BOXFLAG > /tmp/labdpi.log 2>&1 &
sleep 1
iptables -t mangle -N D2KQ 2>/dev/null || iptables -t mangle -F D2KQ
iptables -t mangle -A POSTROUTING -j D2KQ
iptables -t mangle -A D2KQ -p udp --dport 443 -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
if timeout 20 /tmp/quicping "$IP" "$NAME" >/dev/null 2>&1; then
    fail "цензор не режет: QUIC прошёл мимо него"
fi
echo "цензор на месте"

echo "== ПОРТ =="
# Порт работает от ТРАФИКА: снимок приветствия ему приносит датапат. Поэтому
# поднимается вся вертикаль, а ответы вопросника читаются из журнала — он
# печатает их построчно (см. d2k_quic_step).
CAT=/tmp/labq-catalog.json; rm -f "$CAT"
SOCK=/tmp/labq.sock; rm -f "$SOCK"
iptables -t mangle -N D2KD 2>/dev/null || iptables -t mangle -F D2KD
iptables -t mangle -A OUTPUT -j D2KD
iptables -t mangle -A D2KD -m mark --mark "$MARK" -j RETURN
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
for n in 1 2 3; do timeout 20 /tmp/quicping "$IP" "$NAME" >/dev/null 2>&1 || true; sleep 3; done
i=0; while [ $i -lt 120 ]; do
    grep -q 'вердикт:' /tmp/d2kc.log && break
    i=$((i+1)); sleep 1
done
if ! grep -qa 'вопрос «' /tmp/d2kc.log; then
    echo "--- d2kc ---"; tail -25 /tmp/d2kc.log || true
    echo "--- d2kd ---"; tail -15 /tmp/d2kd.log || true
fi
grep -a 'вопрос «' /tmp/d2kc.log || true

# ВЕРТИКАЛЬ ГАСИТСЯ ДО ЗАПУСКА ЭТАЛОНА, и это не уборка, а условие сверки.
# Порт ставит НАЙДЕННЫЙ план по ИМЕНИ, и план применяется к любому потоку на
# это имя — включая зонды эталона. Мерил бы тогда эталон не коробку, а наш
# обход, и «совпало» означало бы обратное тому, что написано.
# Управление заданиями в неинтерактивном sh выключено, поэтому по PID'ам.
kill "$CPID" "$DPID" 2>/dev/null || true
sleep 1
iptables -t mangle -D OUTPUT -j D2KD 2>/dev/null || true
iptables -t mangle -F D2KD 2>/dev/null || true
iptables -t mangle -D INPUT -p udp --sport 443 \
    -m connbytes --connbytes 0:8 --connbytes-dir reply --connbytes-mode packets \
    -j NFQUEUE --queue-num 2102 --queue-bypass 2>/dev/null || true
echo "вертикаль порта остановлена"

echo "== ЭТАЛОН =="
# Эталон ходит сам, без датапата: он сам себе и зонд, и решение.
# --addr у эталона ждёт «адрес:порт», а не голый адрес.
timeout 300 ./z2k-detect quic --json --addr "$IP:443" "$NAME" > /tmp/ref.json 2>/tmp/ref.err || true
head -c 400 /tmp/ref.json || true; echo

echo
echo "== СВЕРКА ПОСВОЙСТВЕННО =="
python3 - <<'PY'
import json, re, sys

# Свойство эталона -> метка вопроса порта. Восьмого вопроса эталона
# (фальшивка с разрешённым именем) в вопроснике порта нет намеренно: он живёт
# у подбора плеча вместе с числом копий и развёрткой TTL.
# ИЗВЕСТНЫЕ РАСХОЖДЕНИЯ — ПОИМЕННО, а не общим послаблением. Тот же приём,
# что у TCP-сверки с текстами ошибок libc: общее послабление заглушило бы
# настоящую разницу, если бы она появилась.
KNOWN = {
    "мусор": "у эталона между датаграммами одной попытки паузы НЕТ (probe.go: "
             "conn.Write в цикле), у порта 60 мс. Замер 17.09 на www.google.com "
             "без цензора: мусор+Initial подряд — 0/3, с паузой 15 мс — 3/3. "
             "То есть «нет» эталона про его собственную отправку, а не про коробку",
}

PAIRS = [
    ("junk_ahead_helps",       "мусор"),
    ("split_crypto_helps",     "кадры"),
    ("split_datagrams_helps",  "датаграммы"),
    ("version_two_helps",      "версия2"),
    ("clear_fixed_bit_helps",  "бит"),
    ("low_source_port_helps",  "низкийпорт"),
    ("udplen",                 "длина"),
]

try:
    ref = json.load(open("/tmp/ref.json"))
except Exception as e:
    print("эталон не дал JSON:", e)
    print(open("/tmp/ref.err").read()[:500])
    sys.exit(1)

props = ref.get("props", {})
port = {}
for line in open("/tmp/d2kc.log", encoding="utf-8", errors="replace"):
    m = re.search(r'вопрос «([^»]+)»: (\d+)/(\d+)', line)
    if m:
        port[m.group(1)] = (int(m.group(2)), int(m.group(3)))

print("вердикт эталона: %s — %s" % (ref.get("verdict"), ref.get("reason", "")[:90]))
print()
print("трасса эталона:")
for st in ref.get("trace", []):
    line = "  %-46s %d/%d" % (st.get("name", "")[:46], st.get("answered", 0), st.get("sent", 0))
    if st.get("not_built"):
        line += " не собрано %d" % st["not_built"]
    if st.get("refused"):
        line += " отказов %d" % st["refused"]
    if st.get("note"):
        line += "  — " + st["note"][:70]
    print(line)
for n in ref.get("notes", []):
    print("  оговорка: " + n[:120])
print()
print("%-24s %-14s %-14s %s" % ("вопрос", "эталон", "порт", "итог"))
bad = 0
unmeasured = 0
for key, label in PAIRS:
    if key == "udplen":
        r = props.get(key)
        rv = None if r is None else (r > 0)
    else:
        rv = props.get(key)
    pv = port.get(label)
    if pv is None:
        pstr, pb = "не задан", None
    else:
        pb = (pv[0] == pv[1] and pv[1] > 0)
        pstr = "%d/%d" % pv
    rstr = "не измерено" if rv is None else ("помогает" if rv else "нет")
    if rv is None or pb is None:
        verdict = "— не сверить"
        unmeasured += 1
    elif rv == pb:
        verdict = "совпало"
    elif label in KNOWN:
        verdict = "разошлось — ИЗВЕСТНО"
    else:
        verdict = "РАЗОШЛОСЬ"
        bad += 1
    print("%-24s %-14s %-14s %s" % (label, rstr, pstr, verdict))

print()
for label, why in KNOWN.items():
    print("известное расхождение «%s»: %s" % (label, why))
print()
if bad:
    print("РАСХОЖДЕНИЙ: %d" % bad)
    sys.exit(1)
if unmeasured == len(PAIRS):
    print("СВЕРИТЬ НЕ УДАЛОСЬ: ни одно свойство не измерено обоими")
    sys.exit(1)
print("СВЕРКА СОШЛАСЬ: расхождений нет (не сверено %d из %d)" % (unmeasured, len(PAIRS)))
PY
DRIVER

docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -e "D2K_LAB_QUIC_NAME=${D2K_LAB_QUIC_NAME:-www.google.com}" \
    -e "D2K_LAB_QUIC_BOX=${D2K_LAB_QUIC_BOX:-first}" \
    -v "$WORK:/w" -w /w gcc:14 sh /w/cmp.sh
