#!/bin/sh
# Переделка двух опытов второго захода, которые вышли негодными.
#
# B. Восемь параллельных потоков. Первая попытка мерила пустоту: Cloudflare
#    отдаёт 403 на восемь одновременных запросов с одного адреса, все восемь
#    потоков получили по одному байту. Нагрузки не было вовсе, а выглядело это
#    как «датапат ничего не увидел». Источник заменён на тот, что одновременность
#    выдерживает.
#
# C. QUIC. Первая попытка сравнивала прогон по всему транзиту с прогоном по
#    одному хосту — то есть разные множества трафика. Здесь знаменателем служит
#    conntrack на тех же самых потоках, и второе плечо не нужно.
set -u

ROUTER=${ROUTER:-192.168.1.1}
RPORT=${RPORT:-222}
RPASS=${RPASS:?переменная RPASS обязательна}
SCOPE=${SCOPE:-192.168.1.67}
LANSCOPE=${LANSCOPE:-192.168.1.0/24}
DEOFF=${DEOFF:-1000000}
PARURL=${PARURL:-https://mirror.yandex.ru/ubuntu/ls-lR.gz}
RESULTS=${RESULTS:-./results5}

rsh() { sshpass -p "$RPASS" ssh -n -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$RPORT" root@"$ROUTER" "$@"; }

mkdir -p "$RESULTS"

wait_bound() {
    w=0
    while [ "$w" -lt 15 ]; do
        sleep 1
        rsh "grep -qE '^ *200 ' /proc/net/netfilter/nfnetlink_queue" 2>/dev/null && return 0
        w=$((w + 1))
    done
    return 1
}

echo "=== B. восемь параллельных потоков (источник выдерживает одновременность) ==="
rsh "SCOPE=$SCOPE DEOFF=$DEOFF DEOFF_DIR=both DUR=60s OUT=/tmp/m5-par BIN=/tmp/nfqview-c ARGS='-copylen 128 -batch' sh /tmp/run-measure.sh" \
    > "$RESULTS/c-par8.log" 2>&1 &
runner=$!
if wait_bound; then
    sleep 2
    tmp=$(mktemp -d)
    i=0
    while [ "$i" -lt 8 ]; do
        ( curl -4 -s -o /dev/null -w '%{http_code} %{size_download} %{speed_download}\n' "$PARURL" > "$tmp/$i" 2>&1 ) &
        i=$((i + 1))
    done
    wait
    echo "  код / байт / Б/с по каждому потоку:"
    cat "$tmp"/* | sed 's/^/    /'
    ok=$(awk '$1==200' "$tmp"/* 2>/dev/null | wc -l | tr -d ' ')
    sum=$(awk '$1==200{s+=$3} END{printf "%.0f", s}' "$tmp"/* 2>/dev/null)
    echo "  успешных потоков: $ok, суммарная скорость: $sum Б/с"
    rm -rf "$tmp"
else
    echo "  ПРОПУСК: очередь не привязалась"
    kill "$runner" 2>/dev/null
fi
wait "$runner" 2>/dev/null
grep -E '^\[' "$RESULTS/c-par8.log" | tail -3 | sed 's/^/  /'
echo

echo "=== C. QUIC: видит ли рычаг де-оффлоада udp/443 ==="
echo "нагрузку не подаём — QUIC создают сами устройства сети; знаменатель берём из conntrack"
rsh "SCOPE=$LANSCOPE DEOFF=$DEOFF DEOFF_DIR=both DEOFF_PROTO=both DUR=120s OUT=/tmp/m5-quic BIN=/tmp/nfqview-c ARGS='-copylen 128 -batch -lan $LANSCOPE' sh /tmp/run-measure.sh" \
    > "$RESULTS/quic.log" 2>&1 &
runner=$!
wait_bound && echo "  идёт двухминутный прогон..."
wait "$runner" 2>/dev/null
grep -E '^\[' "$RESULTS/quic.log" | tail -3 | sed 's/^/  /'

echo
echo "  --- udp/443 глазами очереди против conntrack ---"
# Одинарные кавычки намеренные: доллары внутри — это поля awk, они обязаны
# доехать до роутера как есть, а не раскрыться здесь.
# shellcheck disable=SC2016
rsh 'awk -F"\t" "\$1==17 && \$5==443" /tmp/m5-quic.flows.tsv | cut -f2,3,4,6,7 | head -15' | sed 's/^/    /'
echo "  --- те же потоки в conntrack ---"
# shellcheck disable=SC2016
rsh 'grep "udp" /tmp/m5-quic.ct-after.txt | grep "dport=443" | awk "{for(i=1;i<=NF;i++) if(\$i ~ /^(src|sport|packets)=/) printf \"%s \", \$i; print \"\"}" | head -15' | sed 's/^/    /'

echo
echo "готово, логи в $RESULTS"
