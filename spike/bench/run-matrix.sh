#!/bin/sh
# Матрица замеров этапа 0. Запускается НА МАКЕ, а не на роутере.
#
# Зачем отдельный оркестратор: нагрузку обязан создавать клиент за роутером —
# curl с самого роутера не проходит через FORWARD и меряет не то. Значит на
# каждый прогон нужно синхронно поднять замер на роутере и прокачать нагрузку
# отсюда. Руками это восемь пар действий; здесь — один заход.
#
# Каждая конфигурация получает ОДИНАКОВУЮ нагрузку, иначе числа несравнимы.
set -u

ROUTER=${ROUTER:-192.168.1.1}
RPORT=${RPORT:-222}
RPASS=${RPASS:?переменная RPASS обязательна}
SCOPE=${SCOPE:-192.168.1.67}
DUR=${DUR:-45s}
DEOFF=${DEOFF:-1000000}
LOADS=${LOADS:-3}
LOADSZ=${LOADSZ:-50000000}
URL=${URL:-https://speed.cloudflare.com/__down?bytes=}
# Полный адрес нагрузки, если источник не принимает размер параметром.
# Понадобился, когда Cloudflare начал отдавать 403 после долгой серии
# прогонов: два скачивания из трёх возвращали по четыре байта, и конфигурация
# получала нагрузку втрое меньше соседней. Такие числа несравнимы.
FIXEDURL=${FIXEDURL:-}
RESULTS=${RESULTS:-./results}

# -n обязателен: список конфигураций читается циклом из stdin, а ssh без -n
# вычитывает stdin себе. Матрица от этого отрабатывала ровно одну строку и
# молча заканчивалась — выглядело как «всё прогнали».
rsh() { sshpass -p "$RPASS" ssh -n -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$RPORT" root@"$ROUTER" "$@"; }

mkdir -p "$RESULTS"

# Конфигурации: имя | бинарник | аргументы | направление де-оффлоада
# Пустое DEOFF_DIR=none означает «правил де-оффлоада не ставить».
CONFIGS=${CONFIGS:-"
go-perpkt|/tmp/nfqview|-copylen 128|both
go-batch|/tmp/nfqview|-copylen 128 -batch|both
c-perpkt|/tmp/nfqview-c|-copylen 128|both
c-batch|/tmp/nfqview-c|-copylen 128 -batch|both
c-meta|/tmp/nfqview-c|-copylen 0|both
c-copy1500|/tmp/nfqview-c|-copylen 1500|both
c-qlen1024|/tmp/nfqview-c|-copylen 128 -qlen 1024|both
"}

echo "матрица: нагрузка ${LOADS}x${LOADSZ} байт на конфигурацию, окно $DUR"
echo

printf '%s\n' "$CONFIGS" | while IFS='|' read -r name bin args dir; do
    [ -n "$name" ] || continue

    echo "=== $name ==="
    if ! rsh "test -x $bin"; then
        echo "  ПРОПУСК: $bin на роутере нет"
        continue
    fi

    out="/tmp/m-$name"
    rsh "SCOPE=$SCOPE DEOFF=$DEOFF DEOFF_DIR=$dir DUR=$DUR OUT=$out BIN=$bin ARGS='$args' sh /tmp/run-measure.sh" \
        > "$RESULTS/$name.log" 2>&1 &
    runner=$!

    # Правилам и процессу нужен момент, чтобы встать, иначе первая загрузка
    # пойдёт мимо замера и конфигурация получит меньше нагрузки, чем соседняя.
    # Проверяем факт привязки очереди, а не ждём вслепую: тихий замер выглядит
    # ровно как «железо всё забрало», и такую подмену легко принять за вывод.
    bound=0
    w=0
    while [ "$w" -lt 15 ]; do
        sleep 1
        if rsh "grep -qE '^ *${QNUM:-200} ' /proc/net/netfilter/nfnetlink_queue" 2>/dev/null; then
            bound=1
            break
        fi
        w=$((w + 1))
    done
    if [ "$bound" -eq 0 ]; then
        echo "  ПРОПУСК: очередь не привязалась за 15 с"
        kill "$runner" 2>/dev/null
        wait "$runner" 2>/dev/null
        continue
    fi
    sleep 2

    speeds=""
    i=0
    while [ "$i" -lt "$LOADS" ]; do
        if [ -n "$FIXEDURL" ]; then
            r=$(curl -4 -s -o /dev/null -w '%{speed_download} %{http_code} %{size_download}' "$FIXEDURL" 2>/dev/null || echo "0 000 0")
        else
            r=$(curl -4 -s -o /dev/null -w '%{speed_download} %{http_code} %{size_download}' "${URL}${LOADSZ}" 2>/dev/null || echo "0 000 0")
        fi
        code=$(echo "$r" | cut -d" " -f2)
        [ "$code" = 200 ] || echo "  ВНИМАНИЕ: загрузка вернула код $code — конфигурация недогружена"
        s=$(echo "$r" | cut -d" " -f1)
        speeds="$speeds $s"
        i=$((i + 1))
    done
    echo "  скорость (Б/с):$speeds"
    echo "скорость_байт_в_секунду:$speeds" >> "$RESULTS/$name.log"

    wait "$runner" 2>/dev/null
    grep -E '^\[' "$RESULTS/$name.log" | tail -2 | sed 's/^/  /'
    echo
done

echo "готово, логи в $RESULTS"
