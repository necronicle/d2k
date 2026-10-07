#!/bin/sh
# Автообновление D2K.
#
#   check    узнать, есть ли новый выпуск (подпись обязательна)
#   install  поставить последний выпуск: проверка, копия текущих файлов,
#            установщик из выпуска, минута проверки служб; успех — копия
#            удаляется (остаётся только новая версия), отказ — возвращается
#   run      фоновый цикл: раз в сутки в 03:00–04:59 проверка, при
#            AUTOUPDATE=1 — установка
#   auto on|off  включить или выключить ночную установку
#
# Выпуск публикует .github/workflows/release.yml: latest.json с хешами
# архивов по аркам и его подпись Ed25519. Ключ закреплён здесь, а не берётся
# из сети. Архив — это сам выпуск с его установщиком (scripts/install.sh,
# D2K_LOCAL): ставится ровно так же, как ручной установкой.
set -u
export PATH="${D2K_STUB_PATH:+$D2K_STUB_PATH:}/opt/sbin:/opt/bin:/sbin:/usr/sbin:/bin:/usr/bin"

DIR=${D2K_DIR:-/opt/d2k}
CONF=$DIR/config
AUTOUPDATE=1
# shellcheck disable=SC1090
[ ! -r "$CONF" ] || . "$CONF"
REPO=${D2K_REPO:-necronicle/d2k}
DOWNLOAD=${D2K_UPDATE_DOWNLOAD:-https://github.com/$REPO/releases/download}
LATEST=${D2K_UPDATE_LATEST:-https://github.com/$REPO/releases/latest/download}
KEY=${D2K_UPDATE_KEY:-MCowBQYDK2VwAyEAqZkq/DsxeFJ1MCEEyFa7yzm80XiWf+cHPR1JsybbMPQ=}
INIT=${D2K_INIT:-/opt/etc/init.d/S99d2k}
SBIN=${D2K_SBIN:-/opt/sbin}
NDM_HOOK=${D2K_NDM_HOOK:-/opt/etc/ndm/netfilter.d/001-d2k.sh}
ROOT=${D2K_FS_ROOT:-}
STATE=$DIR/state/update.json
WORK=$DIR/.update
# OpenWrt без USB-накопителя: /opt — каталог корневой ФС, то есть флеш.
# Архив, распаковка и копия прежней версии (~20 МБ) туда не помещаются или
# зря его изнашивают — они живут в RAM. Копия нужна только этому запуску.
if [ -f "${D2K_OPENWRT_RELEASE:-/etc/openwrt_release}" ] &&
   [ "$(df -P "$DIR" 2>/dev/null | awk 'NR == 2 { print $6 }')" = / ]; then
    WORK=${D2K_UPDATE_RAM:-/tmp/d2k-update}
fi
LOG=$DIR/log/update.log
HEALTH_WAIT=${D2K_UPDATE_HEALTH_WAIT:-60}
RUN_EVERY=${D2K_UPDATE_TICK:-60}

log() {
    mkdir -p "$DIR/log" 2>/dev/null || true
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG"
}
now() { date +%s; }
# Поле состояния из прежнего update.json: число или строка без кавычек.
field() { sed -n "s/.*\"$1\":\"\{0,1\}\([^\",}]*\).*/\1/p" "$STATE" 2>/dev/null | head -n 1; }
# Текст для JSON: кавычки и обратные косые экранируются, переводы строк — в пробел.
jtext() { printf '%s' "$1" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'; }

current_id() { head -n 1 "$DIR/release-id" 2>/dev/null; }
arch() { head -n 1 "$DIR/release-arch" 2>/dev/null; }

# Состояние для панели. Всё, что не передано, берётся из прежнего файла.
# $1 busy ("", checking, installing); остальное — через переменные.
write_state() {
    mkdir -p "$DIR/state" || return 1
    latest_json=null
    [ ! -s "$WORK/latest.json" ] || latest_json=$(tr -d '\n' < "$WORK/latest.json")
    tmp="$STATE.new.$$"
    printf '{"busy":"%s","current":"%s","arch":"%s","auto":%s,"checked_utc":%s,"check_ok":%s,"check_error":"%s","latest":%s,"last_utc":%s,"last_ok":%s,"last_release":"%s","last_message":"%s","bad_release":"%s"}\n' \
        "$1" "$(jtext "$(current_id)")" "$(jtext "$(arch)")" \
        "$([ "$AUTOUPDATE" = 1 ] && echo true || echo false)" \
        "${S_CHECKED:-$(field checked_utc)}" "${S_CHECK_OK:-$(field check_ok)}" \
        "$(jtext "${S_CHECK_ERROR-$(field check_error)}")" "$latest_json" \
        "${S_LAST_UTC:-$(field last_utc)}" "${S_LAST_OK:-$(field last_ok)}" \
        "$(jtext "${S_LAST_RELEASE-$(field last_release)}")" \
        "$(jtext "${S_LAST_MESSAGE-$(field last_message)}")" \
        "$(jtext "${S_BAD-$(field bad_release)}")" > "$tmp" &&
        mv -f "$tmp" "$STATE"
}
# Пустые поля прежнего файла — не JSON: подставить значения по умолчанию.
defaults() {
    [ -n "$(field checked_utc)" ] || S_CHECKED=${S_CHECKED:-0}
    [ -n "$(field check_ok)" ] || S_CHECK_OK=${S_CHECK_OK:-false}
    [ -n "$(field last_utc)" ] || S_LAST_UTC=${S_LAST_UTC:-0}
    [ -n "$(field last_ok)" ] || S_LAST_OK=${S_LAST_OK:-false}
}

fetch() { curl -fsL --proto '=https' --max-time "${3:-120}" -o "$2" "$1"; }

# Скачивает и проверяет latest.json в $WORK. Ноль — подпись сошлась.
check() {
    mkdir -p "$WORK" || return 1
    rm -f "$WORK/latest.json.new" "$WORK/latest.json.sig"
    if ! fetch "$LATEST/latest.json" "$WORK/latest.json.new" ||
       ! fetch "$LATEST/latest.json.sig" "$WORK/latest.json.sig"; then
        check_error="не удалось скачать сведения о выпуске"; return 1
    fi
    printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$KEY" > "$WORK/key.pem"
    if [ "$(wc -c < "$WORK/latest.json.sig" | tr -d ' ')" != 64 ] ||
       ! openssl pkeyutl -verify -pubin -inkey "$WORK/key.pem" -rawin \
            -in "$WORK/latest.json.new" -sigfile "$WORK/latest.json.sig" >/dev/null 2>&1; then
        rm -f "$WORK/latest.json.new"
        check_error="подпись выпуска не сошлась"; return 1
    fi
    mv -f "$WORK/latest.json.new" "$WORK/latest.json"
    check_error=
}
latest_id() { sed -n 's/.*"release_id":"\([A-Za-z0-9][A-Za-z0-9._-]*\)".*/\1/p' "$WORK/latest.json" 2>/dev/null; }
latest_sum() { sed -n "s/.*\"$1\":{\"sha256\":\"\([0-9a-f]\{64\}\)\".*/\1/p" "$WORK/latest.json" 2>/dev/null; }

do_check() {
    defaults
    write_state checking
    if check; then
        S_CHECKED=$(now) S_CHECK_OK=true S_CHECK_ERROR='' write_state ""
        log "проверка: последний выпуск $(latest_id), установлен ${current:-$(current_id)}"
        return 0
    fi
    S_CHECKED=$(now) S_CHECK_OK=false S_CHECK_ERROR=$check_error write_state ""
    log "проверка не удалась: $check_error"
    return 1
}

# Файлы, которые меняет установщик. Состояние, журнал и каталог знаний — нет.
installed_paths() {
    for p in "$SBIN/d2kd" "$SBIN/d2kc" "$SBIN/d2kpanel" "$SBIN/d2ktg" "$INIT" "$NDM_HOOK" \
             "$DIR/config" "$DIR/release-id" "$DIR/release-arch" "$DIR/panel" "$DIR/files"; do
        [ ! -e "$ROOT$p" ] || printf '%s\n' "${p#/}"
    done
    for p in "$ROOT$DIR"/*.sh; do [ ! -f "$p" ] || printf '%s\n' "${p#"$ROOT"/}"; done
}

healthy() {
    # Установщик сам ждёт привязки очереди и падает, если служба умерла
    # сразу. Здесь — что она не умерла за минуту после него.
    sleep "$HEALTH_WAIT"
    for pid in d2kd.pid d2k.pid; do
        p=$(cat "$DIR/run/$pid" 2>/dev/null) || return 1
        kill -0 "$p" 2>/dev/null || return 1
    done
    panel=$(sed -n 's/^PANEL_LISTEN=//p' "$DIR/config" 2>/dev/null | tail -n 1 | tr -d "\"'")
    if [ -n "$panel" ]; then
        p=$(cat "$DIR/run/d2k-panel.pid" 2>/dev/null) || return 1
        kill -0 "$p" 2>/dev/null || return 1
    fi
    return 0
}

# $1 — manual (ставить даже выпуск, однажды не прошедший проверку).
do_install() {
    mkdir -p "$WORK" || return 1
    if ! mkdir "$WORK/lock" 2>/dev/null; then
        old=$(cat "$WORK/lock/pid" 2>/dev/null || true)
        if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
            log "установка уже идёт (pid $old)"; return 1
        fi
        rm -rf "$WORK/lock"; mkdir "$WORK/lock" || return 1
    fi
    echo $$ > "$WORK/lock/pid"
    defaults
    write_state installing
    rc=0; install_release "${1:-}" || rc=$?
    rm -rf "$WORK/lock" "$WORK/release" "$WORK/release.tar.gz"
    return $rc
}
finish() {
    # $1 ok, $2 выпуск, $3 сообщение, $4 плохой выпуск (или пусто).
    S_LAST_UTC=$(now) S_LAST_OK=$1 S_LAST_RELEASE=$2 S_LAST_MESSAGE=$3 S_BAD=${4-$(field bad_release)} write_state ""
    log "$3"
}
install_release() {
    check || { S_CHECKED=$(now) S_CHECK_OK=false S_CHECK_ERROR=$check_error write_state installing
               finish false "" "установка не начата: $check_error"; return 1; }
    S_CHECKED=$(now) S_CHECK_OK=true S_CHECK_ERROR=''
    rid=$(latest_id); a=$(arch)
    if [ -z "$rid" ] || [ -z "$a" ]; then
        finish false "$rid" "установка не начата: неизвестен выпуск или арка роутера"; return 1
    fi
    [ "$rid" != "$(current_id)" ] || { finish true "$rid" "выпуск $rid уже установлен"; return 0; }
    if [ "$1" != manual ] && [ "$rid" = "$(field bad_release)" ]; then
        finish false "$rid" "выпуск $rid однажды не прошёл проверку — ночью не ставится, только вручную"; return 1
    fi
    sum=$(latest_sum "$a")
    [ -n "$sum" ] || { finish false "$rid" "в выпуске $rid нет сборки для $a"; return 1; }
    fetch "$DOWNLOAD/$rid/d2k-$a.tar.gz" "$WORK/release.tar.gz" 600 ||
        { finish false "$rid" "не удалось скачать выпуск $rid"; return 1; }
    got=$(openssl dgst -sha256 -r "$WORK/release.tar.gz" | cut -d' ' -f1)
    [ "$got" = "$sum" ] || { finish false "$rid" "архив выпуска $rid не совпал с подписанным хешем"; return 1; }
    rm -rf "$WORK/release"
    if ! mkdir "$WORK/release" || ! tar -xzf "$WORK/release.tar.gz" -C "$WORK/release"; then
        finish false "$rid" "архив выпуска $rid не распаковался"; return 1
    fi

    # Копия того, что заменит установщик, — до первой замены.
    rm -f "$WORK/previous.tar"
    # shellcheck disable=SC2046  # список путей без пробелов, нарочно словами
    tar -cf "$WORK/previous.tar" -C "${ROOT:-/}" $(installed_paths) ||
        { finish false "$rid" "не удалось сохранить текущую версию — установка не начата"; return 1; }
    prev=$(current_id)
    log "ставлю выпуск $rid (был ${prev:-неизвестен})"
    if D2K_LOCAL="$WORK/release" D2K_RELEASE_ID="$rid" D2K_UPDATING=1 \
           sh "$WORK/release/scripts/install.sh" >> "$LOG" 2>&1 && healthy; then
        rm -f "$WORK/previous.tar"
        finish true "$rid" "установлен выпуск $rid" ""
        return 0
    fi
    log "выпуск $rid не прошёл проверку — возвращаю ${prev:-прежнюю версию}"
    "$INIT" stop >> "$LOG" 2>&1 || true
    if tar -xf "$WORK/previous.tar" -C "${ROOT:-/}" && "$INIT" start >> "$LOG" 2>&1; then
        rm -f "$WORK/previous.tar"
        finish false "$rid" "выпуск $rid не прошёл проверку; возвращена прежняя версия" "$rid"
    else
        finish false "$rid" "выпуск $rid не прошёл проверку, и прежняя версия не вернулась; копия: $WORK/previous.tar" "$rid"
    fi
    return 1
}

# Ночной цикл: один раз за сутки в окне 03:00–04:59.
run() {
    trap 'exit 0' INT TERM HUP
    while :; do
        hour=$(date +%H); day=$(date +%Y%m%d)
        if [ "$hour" = 03 ] || [ "$hour" = 04 ]; then
            if [ "$(cat "$WORK/night" 2>/dev/null)" != "$day" ]; then
                mkdir -p "$WORK"; echo "$day" > "$WORK/night"
                if [ "$AUTOUPDATE" = 1 ]; then
                    # Отдельной сессией: установщик останавливает службу,
                    # а с ней и этот цикл.
                    start-stop-daemon -S -b -x "$0" -- install
                else
                    do_check || true
                fi
            fi
        fi
        sleep "$RUN_EVERY" & wait $!
    done
}

set_auto() {
    v=$1
    if grep -q '^AUTOUPDATE=' "$CONF" 2>/dev/null; then
        sed "s/^AUTOUPDATE=.*/AUTOUPDATE=$v/" "$CONF" > "$CONF.new.$$" && mv -f "$CONF.new.$$" "$CONF"
    else
        printf 'AUTOUPDATE=%s\n' "$v" >> "$CONF"
    fi
    AUTOUPDATE=$v; defaults; write_state ""
    log "ночная установка: $([ "$v" = 1 ] && echo включена || echo выключена)"
}

case "${1:-}" in
    check) do_check ;;
    install) do_install "${2:-}" ;;
    run) run ;;
    auto) case "${2:-}" in on) set_auto 1 ;; off) set_auto 0 ;; *) exit 2 ;; esac ;;
    *) echo "usage: $0 {check|install [manual]|run|auto on|off}" >&2; exit 2 ;;
esac
