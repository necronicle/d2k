#!/bin/sh
# Установка d2k на Keenetic.
#
# BusyBox ash. Каждый значимый отказ обрабатывается: установщик, который
# продолжает после неудачной загрузки, оставляет полусобранную систему, а
# человек об этом узнаёт от неработающего интернета.
#
# Что здесь НЕ делается и почему:
#   * ничего не берётся у z2k при неудаче загрузки — подмена артефактов
#     чужого продукта своими это не запасной путь, а сюрприз;
#   * автообновление (d2k-update.sh) ставит только ПОДПИСАННЫЙ выпуск: его
#     архив — это тот же установщик с файлами, запущенный с D2K_LOCAL.
set -eu

REPO=${D2K_REPO:-necronicle/d2k}
REF=${D2K_REF:-main}
BASE=${D2K_BASE:-https://raw.githubusercontent.com/$REPO/$REF}

DIR=/opt/d2k
SBIN=/opt/sbin
INIT=/opt/etc/init.d/S99d2k
OPENWRT_INIT=/etc/init.d/d2k
# Признак OpenWrt — один на весь установщик: хук автозапуска, пакеты, правила.
OPENWRT_RELEASE=${D2K_OPENWRT_RELEASE:-/etc/openwrt_release}
# Штатный менеджер пакетов OpenWrt: apk с 25.12, opkg до неё. Entware-opkg
# для системных пакетов не годится никогда — у него свои пакеты и своя арка.
OPENWRT_APK=${D2K_OPENWRT_APK:-/usr/bin/apk}
OPENWRT_OPKG=${D2K_OPENWRT_OPKG:-/bin/opkg}
OPENWRT_STAGE=
openwrt_check() {
    [ -f "$OPENWRT_RELEASE" ] || return 0
    if [ ! -r /etc/rc.common ] || [ ! -r /lib/functions/procd.sh ]; then
        echo 'd2k: OpenWrt без rc.common/procd — автозапуск недоступен' >&2
        return 0
    fi
    if [ -e "$OPENWRT_INIT" ] || [ -L "$OPENWRT_INIT" ]; then
        if [ -L "$OPENWRT_INIT" ] || [ ! -f "$OPENWRT_INIT" ] ||
           ! grep -qx '# D2K-owned OpenWrt boot bridge v1' "$OPENWRT_INIT"; then
            echo "d2k: чужой $OPENWRT_INIT — не перезаписываю; установка/обновление продолжится без хука" >&2
            return 1
        fi
    fi
}
prepare_openwrt_hook() {
    [ -f "$OPENWRT_RELEASE" ] || return 0
    openwrt_check || return 0
    [ -r /etc/rc.common ] && [ -r /lib/functions/procd.sh ] || return 0
    # Stage on the host filesystem before stopping/replacing the runtime.
    OPENWRT_STAGE=$(mktemp "$OPENWRT_INIT.XXXXXX") || die "не подготовить хук OpenWrt"
    fetch "files/d2k-openwrt-init" "$OPENWRT_STAGE"
    if ! grep -qx '# D2K-owned OpenWrt boot bridge v1' "$OPENWRT_STAGE" ||
       ! sh -n "$OPENWRT_STAGE" || ! chmod 0755 "$OPENWRT_STAGE"; then
        die "неверный хук OpenWrt — прежняя установка сохранена"
    fi
}
install_openwrt_hook() (
    [ -n "$OPENWRT_STAGE" ] || exit 0
    # Recheck ownership in case another service appeared during installation.
    openwrt_check || exit 0
    mv -f "$OPENWRT_STAGE" "$OPENWRT_INIT" || exit 1
    sh /etc/rc.common "$OPENWRT_INIT" enable || exit 1
    echo 'd2k: автозапуск OpenWrt включён (ожидание /opt, затем D2K)'
)
TMP=

say()  { echo "d2k: $*"; }
die()  { echo "d2k: $*" >&2; cleanup; exit 1; }
cleanup() {
    [ -z "$OPENWRT_STAGE" ] || rm -f "$OPENWRT_STAGE"
    [ -z "$TMP" ] || rm -rf "$TMP"
    TMP=
}
trap cleanup EXIT INT TERM

# --- арка ----------------------------------------------------------------
#
# Отказ на неподдерживаемой арке ЯВНЫЙ. Поставить бинарник не той арки значит
# получить «не запускается» без объяснения.

# --- правила: nftables или iptables --------------------------------------
#
# OpenWrt с fw4 (22.03+) — nftables: в 25.12 пакетов iptables нет вовсе, и
# Entware для них не нужен. Keenetic и старый OpenWrt (fw3) — iptables. Тот же
# выбор делает S99d2k; FW_BACKEND=iptables в конфигурации оставляет iptables.
FW=iptables
if [ -f "$OPENWRT_RELEASE" ] && command -v nft >/dev/null 2>&1; then
    cfg_fw=$(sed -n 's/^[[:space:]]*FW_BACKEND=//p' "$DIR/config" 2>/dev/null | tail -n 1 | tr -d "\"'")
    [ "$cfg_fw" = iptables ] || FW=nft
fi

# Штатные пакеты OpenWrt. Ставятся только недостающие.
openwrt_pm() {
    if [ -x "$OPENWRT_APK" ]; then echo apk
    elif [ -x "$OPENWRT_OPKG" ]; then echo opkg
    fi
}
openwrt_has() {
    case "$(openwrt_pm)" in
        apk) "$OPENWRT_APK" info -e "$1" >/dev/null 2>&1 ;;
        opkg) "$OPENWRT_OPKG" list-installed 2>/dev/null | cut -d' ' -f1 | grep -qx "$1" ;;
        *) return 1 ;;
    esac
}
# $* — пакеты словами.
openwrt_add() {
    # shellcheck disable=SC2048,SC2086  # список пакетов, нарочно словами
    case "$(openwrt_pm)" in
        apk) "$OPENWRT_APK" add $* >/dev/null 2>&1 ||
             { "$OPENWRT_APK" update >/dev/null 2>&1 && "$OPENWRT_APK" add $* >/dev/null 2>&1; } ;;
        opkg) "$OPENWRT_OPKG" install $* >/dev/null 2>&1 ||
              { "$OPENWRT_OPKG" update >/dev/null 2>&1 && "$OPENWRT_OPKG" install $* >/dev/null 2>&1; } ;;
        *) return 1 ;;
    esac
}
# Команда для человека: та же установка руками.
openwrt_add_cmd() {
    case "$(openwrt_pm)" in
        apk) echo "apk update && apk add $*" ;;
        *) echo "opkg update && opkg install $*" ;;
    esac
}

# --- что нужно от системы ------------------------------------------------
if [ "$FW" = nft ]; then
    # curl и openssl может ещё не быть: их ставит штатный менеджер ниже, после
    # загрузки (загрузка без curl идёт через wget = uclient-fetch из образа).
    for t in ip nft start-stop-daemon; do
        command -v "$t" >/dev/null 2>&1 || die "нет $t — он есть в обычном образе OpenWrt; проверьте прошивку"
    done
    [ -n "$(openwrt_pm)" ] || die "нет штатного менеджера пакетов OpenWrt ($OPENWRT_APK или $OPENWRT_OPKG)"
else
    for t in curl ip iptables ip6tables start-stop-daemon; do
        command -v "$t" >/dev/null 2>&1 || die "нет $t — поставьте пакет и повторите"
    done
    for t in ipset openssl; do
        command -v "$t" >/dev/null 2>&1 || die "нет $t — нужен для Telegram/Instagram; поставьте зависимости из README"
    done
fi
# Модули netfilter прошивка часто держит файлами, но не загружает: в /proc
# видны только загруженные (Keenetic; Netis N6 04.10 — xt_connbytes ожил от
# modprobe). Установщик загружает их сам тем же способом, что S99d2k при
# старте, и только потом проверяет.
MODULES_DIR=${D2K_MODULES_DIR:-/lib/modules}
load_kmod() {
    modprobe "$1" 2>/dev/null && return 0
    kver=$(uname -r 2>/dev/null)
    ko=
    for d in "$MODULES_DIR/$kver" "$MODULES_DIR"; do
        [ -f "$d/$1.ko" ] && { ko="$d/$1.ko"; break; }
    done
    [ -n "$ko" ] || ko=$(find "$MODULES_DIR" -name "$1.ko" -type f 2>/dev/null | head -1)
    if [ -n "$ko" ]; then insmod "$ko" 2>/dev/null || true; fi
    # Всегда 0: под set -e неудача последней команды в «a || load_kmod»
    # оборвала бы установщик без объяснения; итог проверяется строкой ниже.
    return 0
}
NF_HINT="модуль не найден в прошивке; на Keenetic установите компонент «Модули ядра подсистемы Netfilter»"
# OpenWrt с iptables (fw3 или FW_BACKEND=iptables): модули netfilter —
# отдельные пакеты штатного менеджера, не Entware. Лаборатория 06.10, OpenWrt
# 24.10.8: без них нет NFQUEUE, без kmod-ipt-nat — таблицы nat (MASQUERADE для
# QUIC и перенаправление Telegram). Для nftables пакеты ставятся ниже, после
# загрузки, вместе с curl и openssl.
OPENWRT_KMODS="kmod-nfnetlink-queue kmod-ipt-nfqueue kmod-ipt-conntrack kmod-ipt-conntrack-extra kmod-ipt-ipset kmod-ipt-extra kmod-ip6tables kmod-ipt-nat kmod-ipt-nat6"
if [ "$FW" = iptables ]; then
    if [ -f "$OPENWRT_RELEASE" ]; then
        NF_HINT="модуль не найден; на OpenWrt поставьте пакеты: $(openwrt_add_cmd "$OPENWRT_KMODS")"
        if [ -n "$(openwrt_pm)" ]; then
            kmods_missing=
            for p in $OPENWRT_KMODS; do
                openwrt_has "$p" || kmods_missing="$kmods_missing $p"
            done
            if [ -n "$kmods_missing" ]; then
                say "OpenWrt: ставлю модули ядра:$kmods_missing"
                # shellcheck disable=SC2086  # список пакетов, нарочно словами
                kmods_cmd=$(openwrt_add_cmd $kmods_missing)
                # shellcheck disable=SC2086  # список пакетов, нарочно словами
                openwrt_add $kmods_missing ||
                    say "OpenWrt: модули не поставились — проверьте интернет и место, затем: $kmods_cmd"
            fi
        fi
    fi
    [ -e /proc/net/netfilter/nfnetlink_queue ] || { load_kmod nfnetlink; load_kmod nfnetlink_queue; }
    [ -e /proc/net/netfilter/nfnetlink_queue ] || \
        die "ядро без nfnetlink_queue — $NF_HINT"
    grep -qw NFQUEUE /proc/net/ip_tables_targets 2>/dev/null || load_kmod xt_NFQUEUE
    grep -qw NFQUEUE /proc/net/ip_tables_targets 2>/dev/null || \
        die "в iptables нет цели NFQUEUE — $NF_HINT"
    grep -qw connbytes /proc/net/ip_tables_matches 2>/dev/null || load_kmod xt_connbytes
    grep -qw connbytes /proc/net/ip_tables_matches 2>/dev/null || \
        die "в iptables нет совпадения connbytes — $NF_HINT"
fi

# --- загрузка во временное место -----------------------------------------
#
# Сперва всё скачивается и проверяется, и только потом заменяется. Замена по
# ходу загрузки оставляет систему в состоянии, которого не предусматривал
# никто.
TMP=$(mktemp -d /tmp/d2k-install.XXXXXX) || die "не создать временный каталог"

fetch() {
    # $1 — путь в репозитории, $2 — куда положить.
    #
    # D2K_LOCAL берёт файлы из каталога вместо сети. Нужен для проверки
    # установки С ЧИСТОГО СОСТОЯНИЯ до того, как появятся опубликованные
    # сборки: обещать рабочую установку, ни разу её не пройдя, нельзя (§9).
    if [ -n "${D2K_LOCAL:-}" ]; then
        cp "$D2K_LOCAL/$1" "$2" || die "нет $D2K_LOCAL/$1"
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time 120 -o "$2" "$BASE/$1" || die "не скачать $1"
    else
        # OpenWrt без curl: wget образа (uclient-fetch, HTTPS с ca-bundle);
        # curl поставит ниже штатный менеджер.
        wget -q -T 120 -O "$2" "$BASE/$1" || die "не скачать $1"
    fi
    [ -s "$2" ] || die "$1 оказался пустым"
}

fetch "scripts/architecture.sh" "$TMP/architecture.sh"
fetch "scripts/check-cpu.sh" "$TMP/check-cpu.sh"
SYS_ARCH=$(uname -m)
# ABI пользовательского пространства: на OpenWrt — сама система (DISTRIB_ARCH
# есть и в 24.10, и в 25.12; apk --print-arch даёт лишь «aarch64»), иначе —
# Entware.
ABI_ARCH=
if [ -f "$OPENWRT_RELEASE" ]; then
    ABI_ARCH=$(sed -n "s/^DISTRIB_ARCH=[\"']\{0,1\}\([^\"']*\).*/\1/p" "$OPENWRT_RELEASE" | head -n 1)
fi
if [ -z "$ABI_ARCH" ] && command -v opkg >/dev/null 2>&1; then
    ABI_ARCH=$(opkg print-architecture 2>/dev/null | awk '
        $1 == "arch" && $2 != "all" && $2 != "noarch" {
            if ($3 + 0 >= priority) { priority = $3 + 0; arch = $2 }
        } END { print arch }')
fi
ARCH=$(sh "$TMP/architecture.sh" "$SYS_ARCH" "$ABI_ARCH") || die "неподдерживаемая архитектура"
sh "$TMP/check-cpu.sh" "$ARCH" || die "CPU не соответствует требованиям сборки"
say "архитектура: $SYS_ARCH / ${ABI_ARCH:-ABI не указан} -> $ARCH"
say "загрузка"
fetch "scripts/select-panel-ip.sh" "$TMP/select-panel-ip.sh"
fetch "builds/d2kpanel-linux-$ARCH" "$TMP/d2kpanel"
fetch "builds/d2kc-linux-$ARCH" "$TMP/d2kc"
fetch "builds/d2kd-linux-$ARCH" "$TMP/d2kd"
fetch "builds/d2ktg-linux-$ARCH" "$TMP/d2ktg"
fetch "files/S99d2k"            "$TMP/S99d2k"
fetch "files/config"            "$TMP/config"
fetch "files/d2k-fw-heal.sh"    "$TMP/d2k-fw-heal.sh"
fetch "files/d2k-ppe-deoffload.sh" "$TMP/d2k-ppe-deoffload.sh"
fetch "files/d2k-log-maintenance.sh" "$TMP/d2k-log-maintenance.sh"
fetch "files/d2k-update.sh" "$TMP/d2k-update.sh"
fetch "files/001-d2k.sh"        "$TMP/001-d2k.sh"
fetch "files/d2k-tg-firewall.sh" "$TMP/d2k-tg-firewall.sh"
fetch "files/d2k-tg-watchdog.sh" "$TMP/d2k-tg-watchdog.sh"
fetch "files/d2k-instagram-dns.sh" "$TMP/d2k-instagram-dns.sh"
fetch "files/d2k-instagram-dns-scheduler.sh" "$TMP/d2k-instagram-dns-scheduler.sh"
fetch "files/meta-ranges.txt" "$TMP/meta-ranges.txt"
fetch "files/tg-roots.pem" "$TMP/tg-roots.pem"
fetch "files/fake/stun.bin" "$TMP/stun.bin"
fetch "files/fake/quic_initial_dbankcloud_ru.bin" "$TMP/quic_initial_dbankcloud_ru.bin"
mkdir -p "$TMP/panel"
fetch "internal/web/assets/index.html" "$TMP/panel/index.html"
fetch "internal/web/assets/favicon.svg" "$TMP/panel/favicon.svg"
fetch "internal/web/assets/panel.css"  "$TMP/panel/panel.css"
fetch "internal/web/assets/panel.js"   "$TMP/panel/panel.js"
fetch "internal/web/assets/gsap.js"    "$TMP/panel/gsap.js"
for face in onest jbmono; do
    fetch "internal/web/assets/fonts/$face.woff2" "$TMP/panel/$face.woff2"
    fetch "internal/web/assets/fonts/OFL-$face.txt" "$TMP/panel/OFL-$face.txt"
done

chmod +x "$TMP/d2kpanel" "$TMP/d2kc" "$TMP/d2kd" "$TMP/d2ktg" \
         "$TMP/S99d2k" "$TMP/d2k-fw-heal.sh" "$TMP/d2k-ppe-deoffload.sh" "$TMP/d2k-log-maintenance.sh" "$TMP/d2k-update.sh" "$TMP/001-d2k.sh" \
         "$TMP/d2k-tg-firewall.sh" "$TMP/d2k-tg-watchdog.sh" \
         "$TMP/d2k-instagram-dns.sh" "$TMP/d2k-instagram-dns-scheduler.sh"

# Проверка ДО замены: запускается ли то, что скачалось, и та ли это арка.
PANEL_VERSION=$("$TMP/d2kpanel" --version 2>/dev/null) || die "скачанный d2kpanel не запускается на этой системе"
case "$PANEL_VERSION" in
    *features=telegram-control*) ;;
    *) die "скачанный d2kpanel устарел: в нём нет управления Telegram-туннелем" ;;
esac
"$TMP/d2kd" --help  >/dev/null 2>&1 || die "скачанный d2kd не запускается на этой системе"
TG_VERSION=$("$TMP/d2ktg" --version 2>/dev/null) || die "скачанный d2ktg не запускается на этой системе"
case "$TG_VERSION" in
    *features=per-install-enrollment*) ;;
    *) die "скачанный d2ktg устарел: в нём нет автоматической регистрации установки" ;;
esac
case "$TG_VERSION" in
    *instagram-ip-probe*) ;;
    *) die "скачанный d2ktg устарел: нет проверки доступности Instagram IP" ;;
esac
# The DNS helper pins 18 Instagram/fbcdn/WhatsApp names; an older d2ktg knows
# fewer and would silently reject the rest.
case "$TG_VERSION" in
    *meta-hosts-v3*) ;;
    *) die "скачанный d2ktg устарел: нет проверки сертификатов WhatsApp и fbcdn" ;;
esac
# d2kc без обязательного --control печатает использование и выходит кодом 2 —
# это и есть признак «запускается и та арка». Ноль он здесь вернуть не может.
#
# Код снимается через `|| rc=$?`, а не отдельной строкой: при `set -e` (он
# стоит вверху) команда, вернувшая 2 вне условия, ЗАВЕРШАЕТ установщик молча
# — до всякой проверки. Ровно это и происходило: установка умирала на
# проверке арки, ничего не сказав человеку, и до подмены файлов не доходила
# никогда. Поймано scripts/lab-install.sh на первом же прогоне.
rc=0
"$TMP/d2kc" >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || die "скачанный d2kc не запускается на этой системе (код $rc)"
say "проверено: $("$TMP/d2kpanel" --version | head -1)"

# --- OpenWrt на nftables: место, пакеты, ядро ----------------------------
#
# Всё до остановки прежней версии: отказ здесь оставляет работающую установку.
if [ "$FW" = nft ]; then
    # Место под свои файлы. Без USB /opt — каталог корневой ФС (флеш). Пакеты
    # меряет и отвергает сам менеджер. Нужно: новое минус заменяемое старое
    # плюс самый большой файл (он лежит дважды, пока .new не встал на место).
    opt_fs=/opt; [ -d "$opt_fs" ] || opt_fs=/
    avail_kb=$(df -kP "$opt_fs" 2>/dev/null | awk 'NR == 2 { print $4 }')
    new_kb=$(du -sk "$TMP" | awk '{ print $1 }')
    old_kb=$(du -sk "$SBIN/d2kd" "$SBIN/d2kc" "$SBIN/d2kpanel" "$SBIN/d2ktg" "$DIR/panel" 2>/dev/null |
        awk '{ s += $1 } END { print s + 0 }')
    big_kb=$(du -sk "$TMP/d2ktg" | awk '{ print $1 }')
    need_kb=$((new_kb - old_kb + big_kb))
    case "$avail_kb" in
        ''|*[!0-9]*) say "не узнать свободное место на $opt_fs — продолжаю" ;;
        *) [ "$avail_kb" -ge "$need_kb" ] ||
               die "мало места на $opt_fs: свободно $avail_kb КиБ, нужно $need_kb КиБ — подключите USB-накопитель под /opt" ;;
    esac
    OPENWRT_NEED="kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle"
    command -v curl >/dev/null 2>&1 || OPENWRT_NEED="$OPENWRT_NEED curl"
    command -v openssl >/dev/null 2>&1 || OPENWRT_NEED="$OPENWRT_NEED openssl-util"
    pkgs_missing=
    for p in $OPENWRT_NEED; do
        openwrt_has "$p" || pkgs_missing="$pkgs_missing $p"
    done
    if [ -n "$pkgs_missing" ]; then
        say "OpenWrt: ставлю пакеты:$pkgs_missing"
        # shellcheck disable=SC2086  # список пакетов, нарочно словами
        pkgs_cmd=$(openwrt_add_cmd $pkgs_missing)
        # shellcheck disable=SC2086  # список пакетов, нарочно словами
        openwrt_add $pkgs_missing ||
            die "пакеты не поставились — проверьте интернет и место, затем: $pkgs_cmd"
    fi
    for t in curl openssl; do
        command -v "$t" >/dev/null 2>&1 || die "нет $t и после установки пакетов"
    done
    # Ядро: те же выражения, что в правилах S99d2k, — проверкой без применения.
    {
        echo 'table inet d2k_preflight {'
        echo '	chain c {'
        echo '		type filter hook postrouting priority mangle; policy accept;'
        echo '		meta l4proto tcp ct direction original th dport { 443 } ct original packets 0-8 queue num 65000 bypass'
        echo '		meta nfproto ipv4 fib daddr type broadcast return'
        echo '	}'
        echo '	chain n {'
        echo '		type nat hook postrouting priority srcnat; policy accept;'
        echo '		meta nfproto ipv4 meta l4proto udp meta mark 0x2d masquerade'
        echo '	}'
        echo '}'
    } > "$TMP/preflight.nft"
    nft -c -f "$TMP/preflight.nft" >/dev/null 2>&1 ||
        die "nftables не принимает правила D2K (queue, ct, fib, masquerade) — $(openwrt_add_cmd kmod-nft-queue kmod-nfnetlink-queue kmod-nft-nat kmod-nft-fib)"
    [ -e /proc/net/netfilter/nfnetlink_queue ] || { load_kmod nfnetlink; load_kmod nfnetlink_queue; }
    [ -e /proc/net/netfilter/nfnetlink_queue ] ||
        die "ядро без nfnetlink_queue — $(openwrt_add_cmd kmod-nfnetlink-queue)"
fi
prepare_openwrt_hook

# --- остановка прежней версии --------------------------------------------
if [ -x "$INIT" ]; then
    say "останавливаю прежнюю версию"
    "$INIT" stop || say "прежняя версия остановилась с ошибкой — продолжаю"
fi

# --- атомарная замена ----------------------------------------------------
#
# Переименование в пределах одной ФС атомарно. Копирование поверх работающего
# бинарника — нет: на середине копирования файл уже не тот и ещё не этот.
mkdir -p "$DIR/state" "$DIR/run" "$DIR/log" "$DIR/panel" "$DIR/files/fake" "$SBIN" /opt/etc/init.d

install_atomic() {
    cp "$1" "$2.new" || die "не записать $2.new"
    chmod +x "$2.new"
    mv -f "$2.new" "$2" || die "не подменить $2"
}
install_data_atomic() {
    cp "$1" "$2.new" || die "не записать $2.new"
    chmod 0644 "$2.new"
    mv -f "$2.new" "$2" || die "не подменить $2"
}
install_atomic "$TMP/d2kpanel" "$SBIN/d2kpanel"
install_atomic "$TMP/d2kc"   "$SBIN/d2kc"
install_atomic "$TMP/d2kd"   "$SBIN/d2kd"
# Прокси открытого HTTP (d2khttp) больше не нужен: вставку провайдера в
# HTTP узнаёт d2kd (задача 51). Прежняя версия уже остановлена выше вместе с
# его правилами; бинарник убираем.
rm -f "$SBIN/d2khttp"
install_atomic "$TMP/d2ktg"  "$SBIN/d2ktg"
install_atomic "$TMP/S99d2k" "$INIT"
install_data_atomic "$TMP/panel/index.html" "$DIR/panel/index.html"
install_data_atomic "$TMP/panel/favicon.svg" "$DIR/panel/favicon.svg"
install_data_atomic "$TMP/panel/panel.css"  "$DIR/panel/panel.css"
install_data_atomic "$TMP/panel/panel.js"   "$DIR/panel/panel.js"
install_data_atomic "$TMP/panel/gsap.js"    "$DIR/panel/gsap.js"
mkdir -p "$DIR/panel/fonts"
for face in onest jbmono; do
    install_data_atomic "$TMP/panel/$face.woff2" "$DIR/panel/fonts/$face.woff2"
    install_data_atomic "$TMP/panel/OFL-$face.txt" "$DIR/panel/fonts/OFL-$face.txt"
done
# Файлы прежней панели («Слайдоскоп») новой не нужны: убираем их при обновлении.
for old in slide-left.webp slide-center.webp slide-right.webp slide-holder.webp ground.webp \
           rack.webp family-rack.webp slide-left.webp.json slide-center.webp.json \
           slide-right.webp.json slide-holder.webp.json ground.webp.json rack.webp.json \
           family-rack.webp.json logo-d2k.png mascot-d2k.png mascot.svg \
           fonts/oswald.ttf fonts/OFL-oswald.txt; do
    rm -f "$DIR/panel/$old"
done
install_atomic "$TMP/d2k-fw-heal.sh" "$DIR/d2k-fw-heal.sh"
install_atomic "$TMP/d2k-ppe-deoffload.sh" "$DIR/d2k-ppe-deoffload.sh"
install_atomic "$TMP/d2k-log-maintenance.sh" "$DIR/d2k-log-maintenance.sh"
install_atomic "$TMP/d2k-update.sh" "$DIR/d2k-update.sh"
# Что стоит и под какую арку — для автообновления. Выпуск называет себя сам
# (D2K_RELEASE_ID от d2k-update.sh); ручная установка из main выпуска не знает.
printf '%s\n' "$ARCH" > "$DIR/release-arch.new" && mv -f "$DIR/release-arch.new" "$DIR/release-arch"
printf '%s\n' "${D2K_RELEASE_ID:-}" > "$DIR/release-id.new" && mv -f "$DIR/release-id.new" "$DIR/release-id"
install_atomic "$TMP/d2k-tg-firewall.sh" "$DIR/d2k-tg-firewall.sh"
install_atomic "$TMP/d2k-tg-watchdog.sh" "$DIR/d2k-tg-watchdog.sh"
install_atomic "$TMP/d2k-instagram-dns.sh" "$DIR/d2k-instagram-dns.sh"
install_atomic "$TMP/d2k-instagram-dns-scheduler.sh" "$DIR/d2k-instagram-dns-scheduler.sh"
install_data_atomic "$TMP/meta-ranges.txt" "$DIR/files/meta-ranges.txt"
install_data_atomic "$TMP/tg-roots.pem" "$DIR/files/tg-roots.pem"
install_atomic "$TMP/stun.bin" "$DIR/files/fake/stun.bin"
install_atomic "$TMP/quic_initial_dbankcloud_ru.bin" "$DIR/files/fake/quic_initial_dbankcloud_ru.bin"
# Хук NDM — событийное восстановление правил. Каталог может отсутствовать на
# прошивке без netfilter.d: тогда остаётся периодический сторож, и это
# ухудшение страховки, а не отказ установки.
if [ -d /opt/etc/ndm/netfilter.d ]; then
    install_atomic "$TMP/001-d2k.sh" "/opt/etc/ndm/netfilter.d/001-d2k.sh"
elif [ ! -f "$OPENWRT_RELEASE" ]; then
    # На OpenWrt NDM нет; fw4 своих таблиц D2K не трогает, сторож — страховка.
    say "нет /opt/etc/ndm/netfilter.d — событийного восстановления правил не будет"
fi

# Конфигурация принадлежит человеку: существующую не трогаем.
if [ ! -f "$DIR/config" ]; then
    install_data_atomic "$TMP/config" "$DIR/config"
    say "создана конфигурация $DIR/config"
else
    say "конфигурация уже есть — не трогаю"
fi
# Fresh installs default to loopback in the template. Bind to the primary
# private router address instead, so every LAN device can open the panel
# directly while no public/WAN address is ever selected.
PANEL_LISTEN_CURRENT=$(sed -n 's/^PANEL_LISTEN=//p' "$DIR/config" | tail -n 1)
if [ "$PANEL_LISTEN_CURRENT" = "127.0.0.1:8090" ]; then
    PANEL_LAN_IP=$(ip -4 -o addr show scope global 2>/dev/null | sh "$TMP/select-panel-ip.sh") || \
        die "не удалось определить LAN-адрес роутера для панели"
    [ -n "$PANEL_LAN_IP" ] || die "не найден приватный LAN IPv4-адрес; панель не будет выставлена в интернет"
    sed "s|^PANEL_LISTEN=.*|PANEL_LISTEN=$PANEL_LAN_IP:8090|" "$DIR/config" > "$TMP/config.lan" || \
        die "не настроить LAN-адрес панели"
    install_data_atomic "$TMP/config.lan" "$DIR/config"
    say "панель доступна в LAN: http://$PANEL_LAN_IP:8090/"
fi
# В конфигурации хранится relay secret. Содержимое сохраняем, но ограничиваем
# чтение root даже при обновлении ранее установленного файла с более широкими
# правами.
chmod 0600 "$DIR/config" || die "не защитить права конфигурации"
# Upgrade the old unconfigured Telegram template without changing a user's
# enable/disable choice or custom relay. No fleet credential is installed.
TG_INSTALL_URL=$(sed -n 's/^TG_RELAY_URL=//p' "$DIR/config" | tail -n 1)
if [ -z "$TG_INSTALL_URL" ]; then
    printf '\nTG_RELAY_URL=wss://213.176.74.63.nip.io/ws\n' >> "$DIR/config"
    TG_INSTALL_URL=wss://213.176.74.63.nip.io/ws
fi
if [ "$TG_INSTALL_URL" = wss://213.176.74.63.nip.io/ws ] &&
   ! grep -q '^TG_ENROLL_PORT=' "$DIR/config"; then
    printf 'TG_ENROLL_PORT=9443\n' >> "$DIR/config"
fi
# Instagram/WhatsApp DNS pins come from d2k's own C resolver on the VPS.
# Checking 18 names can wait on silent edges, so the installer does not run it.
# A success younger than a day is kept: a release must not send the whole
# fleet to /resolve at once. An older mark (or one without its time, from an
# older version) is cleared, so the service's scheduler refreshes right after
# start, in the background. A resolver/VPS outage never fails the install.
DNS_MARK="$DIR/state/instagram-dns-last-success"
dns_mark_at=$(sed -n 2p "$DNS_MARK" 2>/dev/null || true)
dns_now=$(date +%s)
case "$dns_mark_at:$dns_now" in
    *[!0-9:]*|:*|*:) dns_mark_at= ;;
esac
if [ -n "$dns_mark_at" ] && [ "$dns_mark_at" -le "$dns_now" ] && [ $((dns_now - dns_mark_at)) -lt 86400 ]; then
    say "DNS Instagram/WhatsApp обновлялся меньше суток назад — следующее обновление по расписанию"
else
    rm -f "$DNS_MARK" /tmp/d2k-instagram-dns-last-attempt
    say "DNS Instagram/WhatsApp обновляется в фоне после запуска: результат в $DIR/log/instagram-dns.log; прежние записи сохраняются"
fi
say "далее — ежедневно в 01:00–04:59 (своя минута у каждой установки), при неудаче повтор с нарастающей паузой"
# Убираем только legacy Go-панельный бинарник прежней установки; новый C
# runtime уже проверен выше и установлен отдельно как d2kpanel.
rm -f "$SBIN/d2k"

# --- запуск и проверка ---------------------------------------------------
say "запуск"
"$INIT" start || die "служба не запустилась"

sleep 2
if ! "$INIT" status | grep -q "датапат: работает"; then
    "$INIT" stop || true
    die "служба запустилась и умерла — смотрите $DIR/log/d2kd.log"
fi

"$INIT" status
if grep -q '^TG_ENABLED=1$' "$DIR/config"; then
    tg_wait=0
    while [ "$tg_wait" -lt 30 ] && [ "$(cat "$DIR/state/telegram.status" 2>/dev/null || true)" != connected ]; do
        sleep 1
        tg_wait=$((tg_wait + 1))
    done
    if [ "$(cat "$DIR/state/telegram.status" 2>/dev/null || true)" = connected ]; then
        say "Telegram: персональная регистрация и подключение к релею подтверждены"
    else
        say "Telegram ещё не подключён; автоматические повторы продолжаются, состояние видно в панели"
    fi
fi
PANEL_LISTEN=$(sed -n 's/^PANEL_LISTEN=//p' "$DIR/config" | tail -n 1)
if [ -n "$PANEL_LISTEN" ]; then
    say "панель слушает: http://$PANEL_LISTEN/"
else
    say "панель отключена (PANEL_LISTEN пуст в $DIR/config)"
fi
# --- автообновление ------------------------------------------------------
if [ "${AUTOUPDATE:-$(sed -n 's/^AUTOUPDATE=//p' "$DIR/config" | tail -n 1)}" = 0 ]; then
    say "автообновление выключено (AUTOUPDATE=0); включается в панели"
else
    say "автообновление: новые подписанные выпуски ставятся ночью 03:00–05:00; кнопка и тумблер — в панели"
fi

install_openwrt_hook || say "предупреждение: автозапуск OpenWrt не включён; установка/обновление завершено, проверьте $OPENWRT_INIT и rc.common"
say "готово"
say "режим по умолчанию — активный обход (MODE=apply). Для наблюдения задайте MODE=observe."
