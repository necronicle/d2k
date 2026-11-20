#!/bin/sh
# lan-round.sh <label> : прогон поля инструментом, имитирующим браузеры, С КЛИЕНТА
# СЕТИ (этот мак, транзитом через роутер — как настоящий браузер), без браузеров.
# Свой трафик роутера режется на сегменты и ставится в очередь иначе, чем
# транзитный (поле 17.10.2026: ECH-приветствие Chrome с роутера — 1/3 неудач,
# с мака на той же сборке — 16/16), поэтому запросы идут отсюда, а на роутере —
# очистка каталога и журнал d2kc.
# Входы: chrome (Chrome 150, ECH из HTTPS RR), safari (Safari 26), h3 (Chrome по
# HTTP/3), http. Расписание: обучение t0, +60, +120 с, контроль через WAIT с.
#   EXPECT=<release-id>, WAIT=<s> (240), CLEAR=0 — как у router-round.sh.
# «Как в браузере»: через LATE с (600, 0 — выкл.) все сайты открываются ещё раз,
# каталог не стирается — то, что увидит человек, открыв сайт позже (late.jsonl).
# После диагностики site-round.py делает полный статический визит с keep-alive.
# SITE_BACKEND=cli (default), SITE_CURL/SITE_CA — локальные пути (не роутера).
# SITE_REFERENCES — JSON URL → декодированный размер. Worker — опциональный backend.
set -u
L=$1
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
R=$RUNS/$L; rm -rf "$R"; mkdir -p "$R"
CI=${CI:-/Library/Zapret2/d2k-field-runs/tools/curl-impersonate-v2.2.3-macos/x/curl-impersonate}
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=10 -p 222 root@192.168.1.1"
SITE_BACKEND=${SITE_BACKEND:-cli}
SITE_CURL=${SITE_CURL:-$CI}
SITE_WORKER=${SITE_WORKER:-/Library/Zapret2/d2k-field-runs/tools/field19-site-fetch}
SITE_CURL_LIB=${SITE_CURL_LIB:-}
SITE_CA=${SITE_CA:-/Library/Zapret2/d2k-field-runs/tools/cacert.pem}
if [ "$SITE_BACKEND" = worker ]; then
    : "${SITE_CURL_LIB:?set local libcurl-impersonate shared library path}"
fi
site_visit() {
    set -- "$R" --backend "$SITE_BACKEND" --curl "$SITE_CURL" --worker "$SITE_WORKER" --library "$SITE_CURL_LIB" --cacert "$SITE_CA" "$@"
    [ -z "${SITE_REFERENCES:-}" ] || set -- "$@" --references "$SITE_REFERENCES"
    python3 -I "$(dirname "$0")/site-round.py" "$@"
}
site_visit --check-only || exit 4
if [ "$SITE_BACKEND" = worker ]; then
    shasum -a 256 "$SITE_WORKER" "$SITE_CURL_LIB" > "$R/instrument.txt" || exit 4
else
    shasum -a 256 "$SITE_CURL" > "$R/instrument.txt" || exit 4
fi
shasum -a 256 "$(dirname "$0")/site-round.py" >> "$R/instrument.txt" || exit 4
W=${WAIT:-240}
LATE=${LATE:-600}
RID=$($SSH "cat /opt/d2k/release-id")
if [ -n "${EXPECT:-}" ] && [ "$RID" != "$EXPECT" ]; then
    echo "round-stopped $L: на роутере $RID, ожидалась $EXPECT"; exit 4
fi
cp "$(dirname "$0")/lan-targets.txt" "$R/targets.txt"
[ "${CLEAR:-1}" = 0 ] || $SSH "/opt/etc/init.d/S99d2k clear-found >/dev/null 2>&1"
sleep 5
T0S=$(date +%s)
$SSH "date +%T" > "$R/t0.txt"; echo "$RID" >> "$R/t0.txt"
fetch() { # host mode path tag
    case $2 in
        chrome) a="--impersonate chrome150 --ech true"; u="https://$1$3" ;;
        safari) a="--impersonate safari260"; u="https://$1$3" ;;
        h3) a="--impersonate chrome150 --http3-only"; u="https://$1$3" ;;
        http) a="--impersonate chrome150 --http1.1"; u="http://$1$3" ;;
    esac
    e="$R/.err.$$.$1.$2"
    # shellcheck disable=SC2086
    r=$("$CI" -4 -sS -o /dev/null --compressed -m 20 --doh-url https://1.1.1.1/dns-query $a \
        -w '"code":%{http_code},"ver":"%{http_version}","size":%{size_download},"t":%{time_total},"ip":"%{remote_ip}","loc":"%{redirect_url}"' \
        "$u" 2>"$e"); rc=$?
    # Причина ошибки curl — последней строкой stderr, без кавычек и обратных косых.
    # shellcheck disable=SC1003
    err=$(tail -1 "$e" 2>/dev/null | tr -d '"\\' | cut -c1-160); rm -f "$e"
    echo "$(date +%T) $4 {\"name\":\"$1\",\"mode\":\"$2\",\"rc\":$rc,$r,\"err\":\"$err\"}" >> "$R/$4.jsonl"
}
at() { d=$((T0S + $1 - $(date +%s))); [ $d -gt 0 ] && sleep $d; return 0; }
i=0
while IFS='|' read -r h ms p; do
    [ -n "$h" ] || continue
    for m in $(echo "$ms" | tr , ' '); do
        o=$((i % 15)); i=$((i + 1))
        ( at $o; fetch "$h" "$m" "$p" learn; at $((60 + o)); fetch "$h" "$m" "$p" learn;
          at $((120 + o)); fetch "$h" "$m" "$p" learn; at $((W + o)); fetch "$h" "$m" "$p" control
          if [ "$LATE" -gt "$W" ]; then at $((LATE + o)); fetch "$h" "$m" "$p" late; fi ) &
    done
done < "$R/targets.txt"
wait
site_rc=0
site_visit || { echo "site collection incomplete" > "$R/collection-error.txt"; site_rc=4; }
T0=$(head -1 "$R/t0.txt")
$SSH "awk -v t0=$T0 '{ t = substr(\$0, 1, 8); ts = t ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\$/ } ts { if (t < p) n = 0; p = t } n || (ts && t >= t0) { b[++n] = \$0 } END { for (i = 1; i <= n; i++) print b[i] }' /opt/d2k/log/d2kc.log" > "$R/d2kc.log"
python3 -I "$(dirname "$0")/router-round-report.py" "$R" | tee "$R/report.txt"
[ "$site_rc" = 0 ] || exit "$site_rc"
echo "round-done $L"
