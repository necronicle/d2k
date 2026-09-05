#!/bin/sh
# Второй заход матрицы этапа 0: то, что не покрывается сравнением C и Go.
#   A. две очереди и два процесса — упирается ли датапат в одно ядро;
#   B. восемь параллельных клиентских потоков — поведение под ветвлением;
#   C. QUIC поверх UDP/443 — виден ли он тем же рычагом де-оффлоада.
#
# Запускается НА МАКЕ. Нагрузку обязан создавать клиент за роутером.
set -u

ROUTER=${ROUTER:-192.168.1.1}
RPORT=${RPORT:-222}
RPASS=${RPASS:?переменная RPASS обязательна}
SCOPE=${SCOPE:-192.168.1.67}
DEOFF=${DEOFF:-1000000}
LOADSZ=${LOADSZ:-50000000}
URL=${URL:-https://speed.cloudflare.com/__down?bytes=}
RESULTS=${RESULTS:-./results2}

# -n обязателен: иначе ssh вычитывает stdin, из которого читаются списки.
rsh() { sshpass -p "$RPASS" ssh -n -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$RPORT" root@"$ROUTER" "$@"; }

mkdir -p "$RESULTS"

wait_bound() {
    w=0
    while [ "$w" -lt 15 ]; do
        sleep 1
        rsh "grep -qE '^ *$1 ' /proc/net/netfilter/nfnetlink_queue" 2>/dev/null && return 0
        w=$((w + 1))
    done
    return 1
}

# ---------------------------------------------------------------- A. два ядра
echo "=== A. две очереди, два процесса (проверка второго ядра) ==="
rsh "SCOPE=$SCOPE DEOFF=$DEOFF DEOFF_DIR=both QBAL=200:201 DUR=45s OUT=/tmp/m2-2q BIN=/tmp/nfqview-c ARGS='-copylen 128' sh /tmp/run-measure.sh" \
    > "$RESULTS/c-2q.log" 2>&1 &
runner=$!
if wait_bound 200; then
    sleep 2
    sp=""
    i=0
    while [ "$i" -lt 3 ]; do
        sp="$sp $(curl -4 -s -o /dev/null -w '%{speed_download}' "${URL}${LOADSZ}" 2>/dev/null || echo 0)"
        i=$((i + 1))
    done
    echo "  скорость (Б/с):$sp"
    echo "скорость_байт_в_секунду:$sp" >> "$RESULTS/c-2q.log"
else
    echo "  ПРОПУСК: очередь не привязалась"
    kill "$runner" 2>/dev/null
fi
wait "$runner" 2>/dev/null
grep -E '^\[|packets"|cpu_percent' "$RESULTS/c-2q.log" | tail -8 | sed 's/^/  /'
echo

# ------------------------------------------------- B. восемь параллельных
echo "=== B. восемь параллельных потоков, один процесс ==="
rsh "SCOPE=$SCOPE DEOFF=$DEOFF DEOFF_DIR=both DUR=45s OUT=/tmp/m2-par BIN=/tmp/nfqview-c ARGS='-copylen 128' sh /tmp/run-measure.sh" \
    > "$RESULTS/c-par8.log" 2>&1 &
runner=$!
if wait_bound 200; then
    sleep 2
    tmp=$(mktemp -d)
    i=0
    while [ "$i" -lt 8 ]; do
        ( curl -4 -s -o /dev/null -w '%{speed_download}\n' "${URL}$((LOADSZ / 4))" > "$tmp/$i" 2>/dev/null ) &
        i=$((i + 1))
    done
    wait
    total=0
    for f in "$tmp"/*; do
        v=$(cut -d. -f1 < "$f" 2>/dev/null)
        [ -n "$v" ] && total=$((total + v))
    done
    echo "  суммарная скорость восьми потоков: $total Б/с"
    echo "суммарная_скорость:$total" >> "$RESULTS/c-par8.log"
    rm -rf "$tmp"
else
    echo "  ПРОПУСК: очередь не привязалась"
    kill "$runner" 2>/dev/null
fi
wait "$runner" 2>/dev/null
grep -E '^\[|packets"|cpu_percent' "$RESULTS/c-par8.log" | tail -6 | sed 's/^/  /'
echo

# ------------------------------------------------------------------- C. QUIC
echo "=== C. QUIC на udp/443, весь транзит через WAN ==="
echo "нагрузку не подаём: QUIC генерируют сами устройства в сети"
rsh "DEOFF= DUR=60s OUT=/tmp/m2-quic BIN=/tmp/nfqview-c ARGS='-copylen 128' sh /tmp/run-measure.sh" \
    > "$RESULTS/quic-baseline.log" 2>&1 &
runner=$!
wait_bound 200 && echo "  идёт базовый прогон без де-оффлоада..."
wait "$runner" 2>/dev/null
echo "  --- базовый (без де-оффлоада) ---"
grep -E '^\[' "$RESULTS/quic-baseline.log" | tail -2 | sed 's/^/  /'

rsh "SCOPE=$SCOPE DEOFF=$DEOFF DEOFF_DIR=both DEOFF_PROTO=both DUR=60s OUT=/tmp/m2-quic2 BIN=/tmp/nfqview-c ARGS='-copylen 128' sh /tmp/run-measure.sh" \
    > "$RESULTS/quic-deoff.log" 2>&1 &
runner=$!
wait_bound 200 && echo "  идёт прогон с де-оффлоадом udp/443..."
wait "$runner" 2>/dev/null
echo "  --- с де-оффлоадом udp/443 ---"
grep -E '^\[' "$RESULTS/quic-deoff.log" | tail -2 | sed 's/^/  /'

echo
echo "готово, логи в $RESULTS"
