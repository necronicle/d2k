#!/bin/sh
# shellcheck disable=SC2016,SC2034 # dynamic shell fixtures or runtime config
# router-round.sh <label> : прогон поля ЦЕЛИКОМ с роутера, без браузеров (решение
# владельца 17.10.2026). Чистый каталог, затем curl-impersonate по каждой цели: обучающие
# запросы в t0, t0+60, t0+120 с, контрольный — через WAIT с от t0. Итог по каждой
# цели и входа: код curl (0 — ответ полный), HTTP-код, размер, протокол; плюс
# журнал d2kc за прогон.
#   EXPECT=<release-id> — остановиться, если на роутере другая сборка.
#   EXPECT_FETCH=<release-id> — версия прибора (по умолчанию EXPECT).
#   D2KFETCH=<path>      — отдельный диагностический бинарь на роутере.
#   Diagnostic build: make -C core fetch-release RELEASE_ID=<id>;
#   copy builds/d2kfetch-linux-arm64 and set D2KFETCH/EXPECT_FETCH to that id.
#   WAIT=<s>            — от t0 до контроля (по умолчанию 240).
#   CLEAR=0             — каталог не чистить.
# Инструмент: /opt/d2k-tools/curl-impersonate (Chrome 150 с ECH, Safari 26, HTTP/3).
# После диагностики — site-round.py: h3-визит, затем TCP с ресурсами из HTML/CSS.
# CLI: обнаружение ресурсов, затем один curl на origin с главной и ресурсами.
# SITE_BACKEND=cli (default), SITE_CURL/SITE_CA — пути на роутере; worker опционален.
# SITE_REFERENCES — JSON на маке: URL → размер декодированного тела.
# Проверка выбранного backend до очистки/обучения (без URL).
set -u
L=${1:?run label}
case "$L" in *[!a-zA-Z0-9._-]*|''|.|..) echo "invalid label" >&2; exit 4;; esac
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
R=$RUNS/$L; rm -rf "$R"; mkdir -p "$R"
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=10 -p 222 root@192.168.1.1"
SITE_BACKEND=${SITE_BACKEND:-cli}
SITE_CURL=${SITE_CURL:-/opt/d2k-tools/curl-impersonate}
SITE_WORKER=${SITE_WORKER:-/opt/d2k-tools/field19-site-fetch}
SITE_CURL_LIB=${SITE_CURL_LIB:-/opt/d2k-tools/libcurl-impersonate.so}
SITE_CA=${SITE_CA:-/opt/d2k-tools/cacert.pem}
for site_path in "$SITE_CURL" "$SITE_WORKER" "$SITE_CURL_LIB" "$SITE_CA"; do
    case "$site_path" in /*) ;; *) echo 'site paths must be absolute' >&2; exit 4;; esac
    case "$site_path" in *[!a-zA-Z0-9/._-]*) echo 'invalid site path' >&2; exit 4;; esac
done
site_visit() {
    set -- "$R" --router --backend "$SITE_BACKEND" --curl "$SITE_CURL" --worker "$SITE_WORKER" --library "$SITE_CURL_LIB" --cacert "$SITE_CA" "$@"
    [ -z "${SITE_REFERENCES:-}" ] || set -- "$@" --references "$SITE_REFERENCES"
    python3 -I "$(dirname "$0")/site-round.py" "$@"
}
site_visit --check-only || { echo "round-stopped $L: site backend не готов" >&2; exit 4; }
W=${WAIT:-240}
WMAX=${WAIT_MAX:-600}
FETCH=${D2KFETCH:-/opt/sbin/d2kfetch}
case "$FETCH" in *[!a-zA-Z0-9/._-]*|'') echo "invalid D2KFETCH path"; exit 4;; esac
FV=$($SSH "$FETCH --version") || { echo "round-stopped $L: не удалось получить версию $FETCH" >&2; exit 4; }
FE=${EXPECT_FETCH:-${EXPECT:-}}
if [ -n "$FE" ] && [ "$FV" != "d2kfetch $FE" ]; then
    echo "round-stopped $L: прибор $FV, ожидался d2kfetch $FE"; exit 4
fi
printf '%s\n' "$FV" > "$R/instrument.txt"
$SSH "sha256sum $FETCH" >> "$R/instrument.txt" || exit 4
if [ "$SITE_BACKEND" = worker ]; then
    $SSH "sha256sum $SITE_WORKER $SITE_CURL_LIB" >> "$R/instrument.txt" || exit 4
else
    $SSH "sha256sum $SITE_CURL" >> "$R/instrument.txt" || exit 4
fi
shasum -a 256 "$(dirname "$0")/site-round.py" >> "$R/instrument.txt" || exit 4
RID=$($SSH "cat /opt/d2k/release-id")
if [ -n "${EXPECT:-}" ] && [ "$RID" != "$EXPECT" ]; then
    echo "round-stopped $L: на роутере $RID, ожидалась $EXPECT"; exit 4
fi
# цель|входы|путь   входы: chrome (Chrome 150, ECH если есть в HTTPS RR),
# safari (Safari 26, без ECH), h3 (HTTP/3 — свой d2kfetch --quic: HTTP/3 curl-impersonate
# на ядре 4.9 роутера не отправляет), http (открытый HTTP)
TARGETS='rutracker.org|chrome,safari,h3|/
fost.club|chrome,safari,h3|/
nnmclub.to|chrome,safari,h3|/
www.fast-torrent.ru|http|/
media5.cdnbase.com|http|/media/theme/fast.5.css
lostfilm.tv|chrome,safari,h3|/
kinozal.me|chrome,safari,h3|/
bible-center.ru|chrome,safari|/
ru.numista.com|chrome,safari|/
rua.gr|chrome,safari,h3|/
enimerosi.com|chrome,safari,h3|/
cdnb.enimerosi.com|chrome,safari|/photos/katsaitis1686837855.jpg?crop=240,240
romfea.gr|chrome,safari,h3|/
katzauction.com|chrome,safari,h3|/
spzh.eu|chrome,safari,h3|/ru/
flibusta.is|chrome,safari|/
web.facebook.com|chrome,safari,h3|/
static.xx.fbcdn.net|chrome,safari|/rsrc.php/v5/y6/l/0,cross/4beuxQDwe0W.css
adguard.com|chrome,safari,h3|/
mailsuite.com|chrome,safari|/
www.cloudflare.com|chrome,safari,h3|/
speed.cloudflare.com|chrome,safari,h3|/'
# СВОЙ СПИСОК ЦЕЛЕЙ (TARGETS_FILE). Список выше — те 22 цели, на которых
# сравниваются выпуски, и менять его нельзя: он и есть мерило. Но проверять
# правку надо там, где она вообще выполняется, а на этих целях поиск часто
# кончается первым же вопросом. Файл того же формата: цель|входы|путь.
if [ -n "${TARGETS_FILE:-}" ]; then
    [ -r "$TARGETS_FILE" ] || { echo "round-stopped $L: не читается список целей $TARGETS_FILE" >&2; exit 4; }
    TARGETS=$(cat "$TARGETS_FILE")
    [ -n "$TARGETS" ] || { echo "round-stopped $L: список целей пуст" >&2; exit 4; }
fi
printf '%s\n' "$TARGETS" > "$R/targets.txt"
# ЧИСТАЯ УСТАНОВКА С ДОКАЗАТЕЛЬСТВАМИ (FRESH=1).
#
# CLEAR=1 снимает каталог, планы HTTP и кэш HTTPS — этого достаточно, чтобы
# коробки учились заново, но прогон НЕ ДОКАЗЫВАЕТ, что так и было. Решение
# владельца 24.10.2026: мерить «как будто человек установил впервые» и
# доказательство чистоты складывать в каталог прогона, иначе это слова.
#
# ЧТО ПРОВЕРЯЕТСЯ И ЗАПИСЫВАЕТСЯ (clean.txt): каталога нет на диске; контроллер
# поднялся с НУЛЁМ коробок; постоянных планов датапату поставлено НОЛЬ; число
# записей conntrack; идентификатор сборки и живые процессы. Любое нарушение —
# остановка прогона: замер на грязном состоянии хуже отсутствия замера.
#
# ЧЕГО ЭТА ОЧИСТКА НЕ ДАЁТ, И ЭТО НАЗВАНО ПРЯМО. Записи conntrack не
# сбрасываются: утилиты conntrack на роутере нет, а решение датапат принимает
# по ключу НОВОГО потока, поэтому старые записи на исход не влияют — число
# пишется как наблюдение, не как гарантия. Настройки владельца (/opt/d2k/config)
# не трогаются: у свежей установки были бы умолчания. Состояние самой коробки
# DPI относительно нашего адреса не сбрасывается ничем и переживёт любую
# переустановку.
if [ "${FRESH:-0}" = 1 ]; then
    CT_BEFORE=$($SSH "wc -l < /proc/net/nf_conntrack" 2>/dev/null || echo "?")
    $SSH "/opt/etc/init.d/S99d2k stop >/dev/null 2>&1; rm -rf /opt/d2k/state/catalog.json /opt/d2k/state/http-plans.txt /opt/d2k/state/https-cache.txt /opt/d2k/state/measurements; /opt/etc/init.d/S99d2k start >/dev/null 2>&1" || {
        echo "round-stopped $L: чистая установка не удалась" >&2; exit 4; }
    sleep 6
    # ЧИТАТЬ ТОЛЬКО ХВОСТ ПОСЛЕ ПОСЛЕДНЕГО СТАРТА. Первая версия брала число
    # поставленных планов из последних сорока строк журнала и поймала строку,
    # написанную ДО перезапуска: прогон остановился на «планов 4», когда их
    # было ноль. Признак чистоты обязан смотреть на тот запуск, который сейчас
    # работает, а не на предыдущий.
    CLEAN=$($SSH 'post=$(awk "/d2kc: запущен/{b=\"\"} {b=b \$0 ORS} END{printf \"%s\", b}" /opt/d2k/log/d2kc.log)
printf "каталог-на-диске=%s\n" "$([ -e /opt/d2k/state/catalog.json ] && echo да || echo нет)"
printf "коробок-при-старте=%s\n" "$(printf "%s" "$post" | sed -n "s/.*(\([0-9]*\) коробок).*/\1/p" | tail -1)"
printf "планов-поставлено=%s\n" "$(printf "%s" "$post" | sed -n "s/.*поставлено планов по подтверждённым привязкам: \([0-9]*\).*/\1/p" | tail -1)"
printf "conntrack-после=%s\n" "$(wc -l < /proc/net/nf_conntrack)"
printf "процессы=%s\n" "$(for p in d2kc d2kd d2ktg d2kpanel; do printf "%s=%s " $p "$(pidof $p || echo НЕТ)"; done)"
printf "коробок-в-файле=%s\n" "$(tr "," "\n" < /opt/d2k/state/catalog.json 2>/dev/null | /opt/usr/bin/grep -c fingerprint || echo 0)"
printf "сборка=%s\n" "$(cat /opt/d2k/release-id)"') || { echo "round-stopped $L: доказательства чистоты не собраны" >&2; exit 4; }
    printf 'conntrack-до=%s\n%s\n' "$CT_BEFORE" "$CLEAN" > "$R/clean.txt"
    boxes=$(sed -n 's/^коробок-при-старте=//p' "$R/clean.txt")
    plans=$(sed -n 's/^планов-поставлено=//p' "$R/clean.txt")
    [ -n "$plans" ] || plans=0  # строки после старта не было — планов не ставили
    ondisk=$(sed -n 's/^каталог-на-диске=//p' "$R/clean.txt")
    # ЧИСТОТА — ЭТО «СТАРТОВАЛ С НУЛЯ КОРОБОК», А НЕ «ФАЙЛА НЕТ СЕЙЧАС».
    # Роутер несёт живой трафик дома, и за секунды между старом и t0
    # контроллер успевает выучить ЧУЖУЮ цель и сохранить каталог. Требовать
    # отсутствия файла значит требовать остановки сети: первая версия этой
    # проверки так и остановила прогон на «каталог=да, планов=1». Поэтому
    # обязателен ровно один признак — ноль коробок при старте, — а чужое
    # обучение до t0 записывается числом и читается при разборе: если оно не
    # ноль, часть целей прогона могла получить план переносом.
    if [ "${boxes:-x}" != 0 ]; then
        echo "round-stopped $L: контроллер стартовал не с нуля коробок ($boxes)" >&2
        cat "$R/clean.txt" >&2
        exit 4
    fi
    foreign=$(sed -n 's/^коробок-в-файле=//p' "$R/clean.txt")
    [ "${foreign:-0}" = 0 ] || echo "round-note $L: до t0 выучено чужих коробок: $foreign (трафик дома)" >&2
    case "$(sed -n 's/^процессы=//p' "$R/clean.txt")" in
        *НЕТ*) echo "round-stopped $L: после чистой установки не все службы живы" >&2; cat "$R/clean.txt" >&2; exit 4;;
    esac
    CLEAR=0  # уже очищено и доказано; второй clear-found внутри прогона лишний
fi
# Сценарий на роутере: каждая цель в своём фоне, запросы по расписанию.
cat > "$R/round-router.sh" <<EOF
#!/bin/sh
OUT=/tmp/rr-$L; rm -rf \$OUT; mkdir -p \$OUT
[ "${CLEAR:-1}" = 0 ] || /opt/etc/init.d/S99d2k clear-found >/dev/null 2>&1
sleep 5
date +%T > \$OUT/t0; T0=\$(date +%s)
fetch() { # host mode path tag
    m=\$2
        C="/opt/d2k-tools/curl-impersonate -4 -s -o /dev/null --cacert /opt/d2k-tools/cacert.pem --compressed -m 20 --doh-url https://1.1.1.1/dns-query"
        case \$m in
            chrome) a="--impersonate chrome150 --ech true"; u="https://\$1\$3" ;;
            safari) a="--impersonate safari260"; u="https://\$1\$3" ;;
            h3) a="--impersonate chrome150 --http3-only"; u="https://\$1\$3" ;;
            http) a="--impersonate chrome150 --http1.1"; u="http://\$1\$3" ;;
        esac
        if [ "\$m" = h3 ]; then
            # HTTP/3 curl-impersonate на ядре роутера не отправляет — свой d2kfetch;
            # адрес — тем же DoH, что у curl (DNS роутера может отдать чужой прокси).
            ip=\$(/opt/d2k-tools/curl-impersonate -s -m 8 --cacert /opt/d2k-tools/cacert.pem -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=\$1&type=A" | tr ',' '\n' | sed -n 's/.*"data":"\([0-9.]*\)".*/\1/p' | head -1)
            D2KFETCH="${D2KFETCH:-/opt/sbin/d2kfetch}" sh /tmp/rr-$L.record "\$OUT" "\$1" "\$ip" "\$3" "\$4"
            return
        else
            r=\$(\$C \$a -w '"code":%{http_code},"ver":"%{http_version}","size":%{size_download},"t":%{time_total},"ip":"%{remote_ip}","loc":"%{redirect_url}"' "\$u" 2>/dev/null); rc=\$?
        fi
        echo "\$(date +%T) \$4 {\"name\":\"\$1\",\"mode\":\"\$m\",\"rc\":\$rc,\$r}" >> \$OUT/\$4.jsonl
}
at() { now=\$(date +%s); d=\$((T0 + \$1 - now)); [ \$d -gt 0 ] && sleep \$d; }
rel() { [ \$1 -gt 0 ] && sleep \$1; }
# КОНТРОЛЬ — ПО ГОТОВНОСТИ ПОДБОРА, А НЕ ПО ЧАСАМ (решение владельца 24.10.2026).
#
# Прежде контроль шёл жёстко на t0+WAIT. Если к этому сроку поиск ещё идёт —
# или цель уже легла на десять минут отдыха после исчерпания кандидатов, —
# контроль мерил НЕЗАКОНЧЕННЫЙ подбор, и исход зависел от того, успел ли он,
# а не от сборки. В журнале это видно прямо: clubtone.net искался 162 с и ушёл
# отдыхать, а контроль пришёл поверх отдыха.
#
# Признак покоя: планировщик сообщает «замеров 0 из N» И за 30 с не появилось
# ни одного нового «итог поиска». WAIT остаётся НИЖНЕЙ границей (цели должны
# успеть попросить), WAIT_MAX — верхней: вечно ждать нельзя, и недождавшийся
# прогон обязан сказать это числом, а не промолчать.
# ПОКОЙ СЧИТАЕТСЯ ПО СВОИМ ЦЕЛЯМ, А НЕ ПО ВСЕМУ ПЛАНИРОВЩИКУ.
#
# Первая версия ждала «замеров 0 из N» — простоя ВСЕЙ системы. На роутере с
# живым домашним трафиком он не наступает: прогон rel-settle-1 не дождался
# покоя за 900 с, хотя все его цели давно были готовы. Ждать чужие цели
# незачем, и из-за этого контроль уходил на верхнюю границу.
#
# Цель считается готовой, если выполнено одно из двух: её последний обучающий
# запрос прошёл (rc=0 — значит обход уже работает), либо по ней завершился
# поиск («итог поиска … target=имя»). Второе нужно тем целям, которые так и не
# взялись: их исход тоже определён, и ждать дальше нечего.
settled_host() {
    h=\$1
    rc=\$(grep "\"name\":\"\$h\"" \$OUT/learn.jsonl 2>/dev/null | tail -1 | sed -n 's/.*"rc":\([0-9-]*\).*/\1/p')
    [ "\${rc:-1}" = 0 ] && return 0
    grep "итог поиска" /opt/d2k/log/d2kc.log | tail -300 | grep -q "target=\$h" && return 0
    return 1
}
settle() {
    end=\$((T0 + ${WMAX})); note=""
    while :; do
        now=\$(date +%s)
        if [ \$now -lt \$((T0 + ${W})) ]; then sleep 5; continue; fi
        left=""
        while IFS='|' read -r h ms p; do
            [ -n "\$h" ] || continue
            settled_host "\$h" || left="\$left \$h"
        done < /tmp/rr-$L.targets
        if [ -z "\$left" ]; then
            note="цели готовы через \$((\$(date +%s) - T0)) с от t0"; break
        fi
        if [ \$now -ge \$end ]; then
            note="не дождался готовности за ${WMAX} с; не готовы:\$left"; break
        fi
        sleep 10
    done
    printf '%s\n' "\$note" > \$OUT/settle.txt
}

trap '' HUP
i=0
while IFS='|' read -r h ms p; do
    [ -n "\$h" ] || continue
    for m in \$(echo "\$ms" | tr , ' '); do
        o=\$((i % 15)); i=\$((i + 1))
        ( at \$o; fetch "\$h" "\$m" "\$p" learn; at \$((60 + o)); fetch "\$h" "\$m" "\$p" learn;
          at \$((120 + o)); fetch "\$h" "\$m" "\$p" learn ) &
    done
done < /tmp/rr-$L.targets
wait
settle
i=0
while IFS='|' read -r h ms p; do
    [ -n "\$h" ] || continue
    for m in \$(echo "\$ms" | tr , ' '); do
        o=\$((i % 15)); i=\$((i + 1))
        ( rel \$o; fetch "\$h" "\$m" "\$p" control ) &
    done
done < /tmp/rr-$L.targets
wait
date +%T > \$OUT/t1
EOF
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "cat > /tmp/rr-$L.record" < "$(dirname "$0")/d2kfetch-record.sh" || exit 4
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "cat > /tmp/rr-$L.targets" < "$R/targets.txt" || exit 4
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "cat > /tmp/rr-$L.sh" < "$R/round-router.sh" || exit 4
transfer_rc=0
$SSH "sh /tmp/rr-$L.sh" || transfer_rc=4
# Actual full visits start only after the scheduled h3/control diagnostics.
# Failures are evidence in site.jsonl; process/collection failure is not a site failure.
if [ "$transfer_rc" = 0 ]; then
    site_visit || { echo "site collection incomplete" > "$R/collection-error.txt"; transfer_rc=4; }
fi
$SSH "cat /tmp/rr-$L/t0" > "$R/t0.txt" || transfer_rc=4
$SSH "cat /tmp/rr-$L/settle.txt" > "$R/settle.txt" 2>/dev/null || true
echo "$RID" >> "$R/t0.txt"
$SSH "cat /tmp/rr-$L/learn.jsonl" > "$R/learn.jsonl" || transfer_rc=4
$SSH "cat /tmp/rr-$L/control.jsonl" > "$R/control.jsonl" || transfer_rc=4
# One transfer preserves raw bytes; even a failed transfer must not lose d2kc.log.
# СМЕНА СУТОК НЕ СТИРАЕТ СРЕЗ (поле 25.10.2026, круг h3e-1). Прежде защита от
# прошлых дней гасила буфер на ЛЮБОМ шаге времени назад: круг 23:54→00:09
# терял весь журнал контроллера, а условие t >= t0 после полуночи уже не
# выполнялось («00:09» < «23:54» как строки) — и круг отчитывался «итогов 0,
# единиц 0», будто контроллер не сделал ничего. Теперь смена суток только
# ОТМЕЧАЕТСЯ: пока идёт сбор, он продолжается, а срез начинается заново лишь
# на первой строке t >= t0 ПОСЛЕ смены суток — то есть на свежем дне.
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "sh -s -- /tmp/rr-$L" < "$(dirname "$0")/d2kfetch-export.sh" > "$R/probes.bundle" || transfer_rc=4
python3 -I "$(dirname "$0")/d2kfetch-import.py" "$R/probes.bundle" "$R" || transfer_rc=4
T0=$(head -1 "$R/t0.txt")
case "$T0" in
    [0-2][0-9]:[0-5][0-9]:[0-5][0-9])
$SSH "awk -v t0=$T0 '{ t = substr(\$0, 1, 8); ts = t ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\$/ } ts && t < p { w = 1 } ts && t >= t0 && w { n = 0; w = 0 } ts { p = t } n || (ts && t >= t0) { b[++n] = \$0 } END { for (i = 1; i <= n; i++) print b[i] }' /opt/d2k/log/d2kc.log" > "$R/d2kc.log" || transfer_rc=4
        ;;
    *)
        # No trustworthy time boundary: retain evidence, but do not count it.
        $SSH "cat /opt/d2k/log/d2kc.log" > "$R/d2kc-unbounded.log"
        transfer_rc=4
        ;;
esac
if [ "$transfer_rc" = 0 ]; then
    $SSH "rm -rf /tmp/rr-$L /tmp/rr-$L.sh /tmp/rr-$L.targets /tmp/rr-$L.record"
else
    echo "неполный сбор; исходники оставлены на роутере" > "$R/collection-error.txt"
    echo "round-incomplete $L: исходники оставлены на роутере /tmp/rr-$L" >&2
fi
python3 -I "$(dirname "$0")/router-round-report.py" "$R" | tee "$R/report.txt"
[ "$transfer_rc" = 0 ] || exit "$transfer_rc"
echo "round-done $L"
