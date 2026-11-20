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
#   * неподписанный комплект не ставится. И ручная установка, и ночное
#     обновление (d2k-update.sh) берут один архив выпуска и запускают его
#     собственный установщик с D2K_LOCAL.
set -eu

REPO=${D2K_REPO:-necronicle/d2k}
REF=${D2K_REF:-main}
BASE=${D2K_BASE:-https://raw.githubusercontent.com/$REPO/$REF}

# Откуда берётся комплект. Источник ОДИН и тот же у ручной установки и у
# ночного обновления — подписанный выпуск:
#
#   release  выпуск GitHub: latest.json с хешами архивов, подпись Ed25519
#            закреплённым здесь ключом, архив своей арки. По умолчанию.
#   local    уже распакованный комплект ($D2K_LOCAL): так ставит
#            files/d2k-update.sh, лаборатория и сам выпускной путь ниже.
#   ref      файлы ветки по raw.githubusercontent, бинарники из builds/.
#            Путь разработчика: подписи нет, а builds/ в ветке обновляет
#            человек. Ручная установка им НЕ идёт — ровно из-за этого она
#            ставила движок от 12.10 под страницы панели от 13.10.
SOURCE=${D2K_SOURCE:-release}
[ -z "${D2K_LOCAL:-}" ] || SOURCE=local
# Те же адреса и тот же ключ, что у files/d2k-update.sh: выпуск, которому
# верит ночное обновление, и выпуск, который ставит рука, — один файл.
# Совпадение ключа с переменной репозитория сторожит .github/workflows/release.yml.
LATEST=${D2K_UPDATE_LATEST:-https://github.com/$REPO/releases/latest/download}
DOWNLOAD=${D2K_UPDATE_DOWNLOAD:-https://github.com/$REPO/releases/download}
KEY=${D2K_UPDATE_KEY:-MCowBQYDK2VwAyEAqZkq/DsxeFJ1MCEEyFa7yzm80XiWf+cHPR1JsybbMPQ=}

DIR=/opt/d2k
SBIN=/opt/sbin
INIT=/opt/etc/init.d/S99d2k
OPENWRT_INIT=/etc/init.d/d2k
# Признак OpenWrt — один на весь установщик: хук автозапуска, пакеты, правила.
OPENWRT_RELEASE=${D2K_OPENWRT_RELEASE:-/etc/openwrt_release}
# Штатный менеджер пакетов OpenWrt: apk с 25.12, opkg до неё. Entware-opkg
# для системных пакетов не годится никогда — у него свои пакеты и своя арка.
OPENWRT_APK=${D2K_OPENWRT_APK:-/usr/bin/apk}
# ПРОВОДНИК УСТАНОВКИ ЧЕРЕЗ VPS — свой C-сервис D2K (relay-gate/). Каждая
# загрузка сперва идёт через него и только потом напрямую: с части линий
# GitHub, Entware и сервер пакетов OpenWrt не доходят.
#   - GitHub — через CONNECT: TLS остаётся между роутером и GitHub, сервис
#     ответ не видит и подменить не может;
#   - пакеты OpenWrt — штатными зеркалами downloads.openwrt.org по http://
#     через тот же сервис: apk и opkg сами сверяют подписи индексов и
#     пакетов, открытый отрезок их не подменит.
# D2K_GATE= (пусто) — без проводника, только напрямую.
GATE=${D2K_GATE-http://85.192.60.175:9444}
# Где лежат источники пакетов OpenWrt (тесты подставляют свои).
OPENWRT_APK_ETC=${D2K_OPENWRT_APK_ETC:-/etc/apk}
OPENWRT_OPKG_ETC=${D2K_OPENWRT_OPKG_ETC:-/etc}
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
# Сперва через проводник: только зеркала downloads.openwrt.org, переписанные
# на http:// (их индексы и пакеты подписаны). Прочие источники в этой попытке
# не участвуют — их подписи могут и не проверяться. Неудача — 1, и
# openwrt_add идёт напрямую, как прежде.
openwrt_gate_add() {
    [ -n "$GATE" ] || return 1
    gfeeds=$TMP/gate-feeds
    # shellcheck disable=SC2048,SC2086  # список пакетов, нарочно словами
    case "$(openwrt_pm)" in
        apk)
            cat "$OPENWRT_APK_ETC"/repositories.d/*.list "$OPENWRT_APK_ETC"/repositories 2>/dev/null |
                sed -n 's|^https://downloads\.openwrt\.org/|http://downloads.openwrt.org/|p' > "$gfeeds"
            [ -s "$gfeeds" ] || return 1
            http_proxy=$GATE "$OPENWRT_APK" --repositories-file "$gfeeds" update >/dev/null 2>&1 &&
                http_proxy=$GATE "$OPENWRT_APK" --repositories-file "$gfeeds" add $* >/dev/null 2>&1 ;;
        opkg)
            # Свои src идут первыми: штатные https-строки с теми же именами
            # opkg затем пропускает как повтор.
            { grep -v '^src' "$OPENWRT_OPKG_ETC"/opkg.conf 2>/dev/null
              cat "$OPENWRT_OPKG_ETC"/opkg/*.conf 2>/dev/null |
                sed -n 's|^\(src/gz [^ ]*\) https://downloads\.openwrt\.org/|\1 http://downloads.openwrt.org/|p'; } > "$gfeeds"
            grep -q '^src' "$gfeeds" || return 1
            http_proxy=$GATE "$OPENWRT_OPKG" -f "$gfeeds" update >/dev/null 2>&1 &&
                http_proxy=$GATE "$OPENWRT_OPKG" -f "$gfeeds" install $* >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}
# $* — пакеты словами.
openwrt_add() {
    # shellcheck disable=SC2048,SC2086  # список пакетов, нарочно словами
    openwrt_gate_add $* && return 0
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

# Пакеты OpenWrt: модули ядра для правил, ca-bundle, curl и openssl.
#
# Вызывается дважды, делает дело один раз. Установке выпуска openssl нужен
# ДО загрузки — им проверяется подпись, — а установке из каталога или ветки
# он нужен только в конце, и там порядок не менялся: отказ пакетов оставляет
# работающую прежнюю версию.
OPENWRT_PKGS_DONE=
openwrt_packages() {
    [ "$FW" = nft ] || return 0
    [ -z "$OPENWRT_PKGS_DONE" ] || return 0
    OPENWRT_PKGS_DONE=1
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

# Место под саму загрузку — ДО неё. Комплект скачивается целиком в /tmp (на
# роутере это tmpfs, то есть RAM) и только потом раскладывается: не хватило —
# отказ до единого изменения, а не полусобранная система. Прежде установщик
# мерил только /opt, и то ПОСЛЕ загрузки: на 8/16-МиБ роутере обрыв случался
# уже внутри fetch, когда отказываться было поздно.
#
# Перед публикацией размеры всех
# архитектур сверяются с этими лимитами в scripts/test-install-manifest.sh.
TMP_NEED_KB=14336
# При установке выпуска распакованное дерево и раскладка одновременно занимают /tmp.
TMP_RELEASE_NEED_KB=28672
# Оба числа сторожит scripts/test-install-manifest.sh: он измеряет и
# раскладку, и дерево выпуска и отвергает число ниже замера.
need_kb=$TMP_NEED_KB
[ "$SOURCE" != release ] || need_kb=$TMP_RELEASE_NEED_KB
tmp_avail_kb=$(df -kP "$TMP" 2>/dev/null | awk 'NR == 2 { print $4 }')
case "$tmp_avail_kb" in
    ''|*[!0-9]*) say "не узнать свободное место в $TMP — продолжаю" ;;
    *) [ "$tmp_avail_kb" -ge "$need_kb" ] ||
           die "мало места для загрузки в $TMP: свободно $tmp_avail_kb КиБ, нужно $need_kb КиБ" ;;
esac

# $1 — адрес, $2 — куда положить, $3 — предел в секундах.
fetch_url() {
    if command -v curl >/dev/null 2>&1; then
        # Сперва через проводник (CONNECT, TLS сквозной), затем напрямую.
        { [ -n "$GATE" ] &&
            curl -fsSL --proto '=https' --proxy "$GATE" --connect-timeout 8 \
                 --max-time "${3:-120}" -o "$2" "$1"; } ||
            curl -fsSL --proto '=https' --max-time "${3:-120}" -o "$2" "$1" ||
            die "не скачать $1"
    else
        # OpenWrt без curl: wget образа (uclient-fetch, HTTPS с ca-bundle);
        # curl ставит штатный менеджер (openwrt_tools) до первой загрузки.
        # Без проводника: uclient-fetch шлёт прокси «GET https://…» вместо
        # CONNECT, и ответ шёл бы открытым текстом — подменяемо.
        wget -q -T "${3:-120}" -O "$2" "$1" || die "не скачать $1"
    fi
    [ -s "$2" ] || die "$1 оказался пустым"
}
# sha256 файла. На OpenWrt есть sha256sum из busybox, на Keenetic — openssl;
# требовать оба сразу незачем.
sum256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        openssl dgst -sha256 -r "$1" | cut -d' ' -f1
    fi
}
fetch() {
    # $1 — путь в комплекте (он же путь в репозитории), $2 — куда положить.
    #
    # D2K_LOCAL берёт файлы из каталога вместо сети: так идёт установка из
    # архива выпуска и проверка С ЧИСТОГО СОСТОЯНИЯ в лаборатории — обещать
    # рабочую установку, ни разу её не пройдя, нельзя (§9).
    if [ -n "${D2K_LOCAL:-}" ]; then
        cp "$D2K_LOCAL/$1" "$2" || die "нет $D2K_LOCAL/$1"
        [ -s "$2" ] || die "$1 оказался пустым"
    else
        fetch_url "$BASE/$1" "$2"
    fi
}

fetch "scripts/architecture.sh" "$TMP/architecture.sh"
fetch "scripts/check-cpu.sh" "$TMP/check-cpu.sh"
SYS_ARCH=$(uname -m)
# ABI пользовательского пространства: на OpenWrt — сама система (DISTRIB_ARCH
# есть и в 24.10, и в 25.12), иначе — Entware (opkg). На части прошивок пусты
# ОБА: DISTRIB_ARCH в /etc/openwrt_release не прописан, а opkg в OpenWrt 24+
# заменён на apk. Тогда арку называет сам apk, а если и он молчит — заголовок
# ELF любого системного бинарника. Без этой цепочки установка падала на
# «неподдерживаемая архитектура», не сказав, что именно пробовали.
ABI_ARCH=
ABI_TRIED=
ABI_FROM=
abi_source() { ABI_TRIED="${ABI_TRIED:+$ABI_TRIED, }$1"; ABI_FROM=$1; }
if [ -f "$OPENWRT_RELEASE" ]; then
    abi_source "DISTRIB_ARCH в $OPENWRT_RELEASE"
    ABI_ARCH=$(sed -n "s/^DISTRIB_ARCH=[\"']\{0,1\}\([^\"']*\).*/\1/p" "$OPENWRT_RELEASE" | head -n 1)
fi
if [ -z "$ABI_ARCH" ] && command -v opkg >/dev/null 2>&1; then
    abi_source "opkg print-architecture"
    ABI_ARCH=$(opkg print-architecture 2>/dev/null | awk '
        $1 == "arch" && $2 != "all" && $2 != "noarch" {
            if ($3 + 0 >= priority) { priority = $3 + 0; arch = $2 }
        } END { print arch }')
fi
if [ -z "$ABI_ARCH" ]; then
    apk_bin=
    if [ -x "$OPENWRT_APK" ]; then apk_bin=$OPENWRT_APK
    elif command -v apk >/dev/null 2>&1; then apk_bin=apk
    fi
    if [ -n "$apk_bin" ]; then
        abi_source "$apk_bin --print-arch"
        ABI_ARCH=$("$apk_bin" --print-arch 2>/dev/null | head -n 1)
    fi
fi
# Имя без порядка байт сборку не выбирает, а на mips он решает всё: «mips» от
# apk может означать и big-endian ath79, и little-endian ramips. Такое имя
# отбрасывается, и ABI читается из ELF ниже — он про порядок байт не врёт.
case "$ABI_ARCH" in
    mips|mips64) ABI_ARCH= ;;
esac
# Последний источник — сама система. В заголовке ELF нужны три поля:
# e_ident[EI_CLASS] (байт 4: 1 — 32 бита, 2 — 64), e_ident[EI_DATA] (байт 5:
# 1 — little-endian, 2 — big-endian) и e_machine (байты 18-19 в порядке
# EI_DATA; 8 — MIPS, 183 — AArch64, 40 — ARM, 62 — x86-64, 3 — i386,
# 243 — RISC-V, 21 — PPC64). od с -A/-N/-t есть в busybox (им уже пользуется
# files/d2k-instagram-dns-scheduler.sh); xxd там нет.
ABI_ELF_FILES=${D2K_ABI_ELF_FILES:-"/bin/busybox /bin/sh /bin/ash /usr/bin/env"}
if [ -z "$ABI_ARCH" ]; then
    abi_source "заголовок ELF ($ABI_ELF_FILES)"
    for elf_cand in $ABI_ELF_FILES; do
        [ -r "$elf_cand" ] || continue
        elf_hdr=$(od -An -tx1 -N20 "$elf_cand" 2>/dev/null | tr -d ' \n')
        [ "${#elf_hdr}" = 40 ] || continue
        case "$elf_hdr" in 7f454c46*) ;; *) continue ;; esac
        elf_class=$(printf '%s' "$elf_hdr" | cut -c9-10)
        elf_data=$(printf '%s' "$elf_hdr" | cut -c11-12)
        # e_machine приводится к старшему-первым, каким бы ни был EI_DATA.
        case "$elf_data" in
            01) elf_machine=$(printf '%s' "$elf_hdr" | cut -c39-40)$(printf '%s' "$elf_hdr" | cut -c37-38) ;;
            02) elf_machine=$(printf '%s' "$elf_hdr" | cut -c37-38)$(printf '%s' "$elf_hdr" | cut -c39-40) ;;
            *) continue ;;
        esac
        case "$elf_machine:$elf_data:$elf_class" in
            0008:01:01) ABI_ARCH=mipsel ;;
            0008:02:01) ABI_ARCH=mips ;;
            0008:01:02) ABI_ARCH=mips64el ;;
            00b7:01:02) ABI_ARCH=aarch64 ;;
            0028:01:01) ABI_ARCH=arm ;;
            003e:01:02) ABI_ARCH=x86_64 ;;
            0003:01:01) ABI_ARCH=i686 ;;
            00f3:01:02) ABI_ARCH=riscv64 ;;
            0015:02:02) ABI_ARCH=ppc64 ;;
            # big-endian mips64, 32-битный PPC и прочее: сборки нет, и врать
            # про арку хуже, чем отказать внятно.
            *) continue ;;
        esac
        say "ABI из заголовка ELF $elf_cand: $ABI_ARCH"
        break
    done
fi
ARCH=$(sh "$TMP/architecture.sh" "$SYS_ARCH" "$ABI_ARCH") ||
    die "неподдерживаемая архитектура: uname=$SYS_ARCH, ABI=${ABI_ARCH:-не определён} (пробовали: ${ABI_TRIED:-ничего})"
sh "$TMP/check-cpu.sh" "$ARCH" || die "CPU не соответствует требованиям сборки"
say "архитектура: $SYS_ARCH / ${ABI_ARCH:-ABI не указан}${ABI_ARCH:+ (из $ABI_FROM)} -> $ARCH"

# --- выпуск --------------------------------------------------------------
#
# Ручная установка ставит ПОДПИСАННЫЙ выпуск — тот же архив и тем же
# установщиком, что ночное обновление. Раньше она брала бинарники из builds/
# ветки main, а их обновлял человек: 13.10.2026 это давало движок от 12.10
# под страницы панели и службу от 13.10, и проверка версий в самом
# установщике однажды отвергла бы такой комплект целиком.
#
# Проверяется подпись перечня, затем sha256 архива из подписанного перечня.
# Не сошлось — ничего не установлено: прежняя версия остаётся работать.
if [ "$SOURCE" = release ]; then
    # На OpenWrt openssl и curl может не быть вовсе — ставятся до проверки.
    openwrt_packages
    say "выпуск: беру сведения"
    fetch_url "$LATEST/latest.json" "$TMP/latest.json"
    fetch_url "$LATEST/latest.json.sig" "$TMP/latest.json.sig"
    printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$KEY" > "$TMP/key.pem"
    [ "$(wc -c < "$TMP/latest.json.sig" | tr -d ' ')" = 64 ] ||
        die "подпись выпуска не того размера — ничего не установлено"
    openssl pkeyutl -verify -pubin -inkey "$TMP/key.pem" -rawin \
            -in "$TMP/latest.json" -sigfile "$TMP/latest.json.sig" >/dev/null 2>&1 ||
        die "подпись выпуска не сошлась — ничего не установлено"
    # Те же выражения, что в files/d2k-update.sh: один формат, одно чтение.
    rid=$(sed -n 's/.*"release_id":"\([A-Za-z0-9][A-Za-z0-9._-]*\)".*/\1/p' "$TMP/latest.json")
    [ -n "$rid" ] || die "в сведениях о выпуске нет номера"
    want=$(sed -n "s/.*\"$ARCH\":{\"sha256\":\"\([0-9a-f]\{64\}\)\".*/\1/p" "$TMP/latest.json")
    [ -n "$want" ] || die "в выпуске $rid нет сборки для $ARCH"
    say "выпуск $rid: загрузка комплекта $ARCH"
    fetch_url "$DOWNLOAD/$rid/d2k-$ARCH.tar.gz" "$TMP/release.tar.gz" 600
    [ "$(sum256 "$TMP/release.tar.gz")" = "$want" ] ||
        die "архив выпуска $rid не совпал с подписанным хешем — ничего не установлено"
    mkdir "$TMP/release" || die "не создать $TMP/release"
    tar -xzf "$TMP/release.tar.gz" -C "$TMP/release" ||
        die "архив выпуска $rid не распаковался"
    # Архив больше не нужен: в /tmp роутера это RAM, и держать его рядом с
    # распакованным деревом незачем.
    rm -f "$TMP/release.tar.gz"
    [ -s "$TMP/release/scripts/install.sh" ] || die "в архиве выпуска $rid нет установщика"
    say "выпуск $rid: подпись сошлась, ставлю его установщиком"
    # Ставит установщик ИЗ архива: на роутер попадает только подписанное, и
    # комплект раскладывает тот же код, что при ночном обновлении.
    D2K_LOCAL="$TMP/release" D2K_RELEASE_ID="$rid" D2K_SOURCE=local \
        sh "$TMP/release/scripts/install.sh" || exit $?
    exit 0
fi
say "загрузка"
fetch "scripts/select-panel-ip.sh" "$TMP/select-panel-ip.sh"
fetch "builds/d2kpanel-linux-$ARCH" "$TMP/d2kpanel"
fetch "builds/d2kc-linux-$ARCH" "$TMP/d2kc"
fetch "builds/d2kshadow-linux-$ARCH" "$TMP/d2kshadow"
fetch "core/profiles/modern.hex" "$TMP/modern.hex"
fetch "core/profiles/legacy.hex" "$TMP/legacy.hex"
fetch "builds/d2kfetch-linux-$ARCH" "$TMP/d2kfetch"
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
fetch "internal/web/assets/diagnostics.js" "$TMP/panel/diagnostics.js"
fetch "internal/web/assets/gsap.js"    "$TMP/panel/gsap.js"
for face in onest jbmono; do
    fetch "internal/web/assets/fonts/$face.woff2" "$TMP/panel/$face.woff2"
    fetch "internal/web/assets/fonts/OFL-$face.txt" "$TMP/panel/OFL-$face.txt"
done

chmod +x "$TMP/d2kfetch" "$TMP/d2kpanel" "$TMP/d2kc" "$TMP/d2kshadow" "$TMP/d2kd" "$TMP/d2ktg" \
         "$TMP/S99d2k" "$TMP/d2k-fw-heal.sh" "$TMP/d2k-ppe-deoffload.sh" "$TMP/d2k-log-maintenance.sh" "$TMP/d2k-update.sh" "$TMP/001-d2k.sh" \
         "$TMP/d2k-tg-firewall.sh" "$TMP/d2k-tg-watchdog.sh" \
         "$TMP/d2k-instagram-dns.sh" "$TMP/d2k-instagram-dns-scheduler.sh"

FETCH_VERSION=$("$TMP/d2kfetch" --version 2>/dev/null) || die "скачанный d2kfetch не запускается"
if [ -n "${D2K_RELEASE_ID:-}" ]; then
    [ "$FETCH_VERSION" = "d2kfetch $D2K_RELEASE_ID" ] || die "версия прибора не совпадает с выпуском: $FETCH_VERSION"
fi

# Проверка ДО замены: запускается ли то, что скачалось, и та ли это арка.
PANEL_VERSION=$("$TMP/d2kpanel" --version 2>/dev/null) || die "скачанный d2kpanel не запускается на этой системе"
case "$PANEL_VERSION" in
    *features=telegram-control*) ;;
    *) die "скачанный d2kpanel устарел: в нём нет управления Telegram-туннелем" ;;
esac
engine_version() {
    version=$("$TMP/$1" --version 2>/dev/null) || return 1
    case "$version" in "$1 release="*" wire="*) ;; *) return 1 ;; esac
    metadata=${version#"$1 release="}
    release=${metadata% wire=*}
    wire=${metadata##* wire=}
    case "$release" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
    case "$wire" in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$metadata"
}
controller=$(engine_version d2kc) || die "неизвестная версия движка d2kc"
datapath=$(engine_version d2kd) || die "неизвестная версия движка d2kd"
[ "$controller" = "$datapath" ] || die "версии движка расходятся: d2kc $controller, d2kd $datapath"
if [ -n "${D2K_RELEASE_ID:-}" ]; then
    [ "${controller% wire=*}" = "$D2K_RELEASE_ID" ] || die "версия движка расходится с выпуском $D2K_RELEASE_ID: $controller"
fi
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
# Проверка запуска демона без доступа к очереди и сети: ключ справки
# завершает разбор аргументов до инициализации состояния.
rc=0
"$TMP/d2kshadow" --help >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || die "скачанный d2kshadow не запускается на этой системе (код $rc)"
say "проверено: $("$TMP/d2kpanel" --version | head -1)"

# --- OpenWrt на nftables: место, пакеты, ядро ----------------------------
#
# Всё до остановки прежней версии: отказ здесь оставляет работающую установку.
if [ "$FW" = nft ]; then
    openwrt_packages
    # Место под свои файлы — ПОСЛЕ пакетов: без USB /opt — каталог той же
    # корневой ФС (флеш), и пакеты (~7 МБ) берут из того же места (ревью
    # 07.10). Нехватку на сами пакеты отвергает менеджер. Нужно: новое минус
    # заменяемое старое плюс самый большой файл (он лежит дважды, пока .new не
    # встал на место).
    opt_fs=/opt; [ -d "$opt_fs" ] || opt_fs=/
    avail_kb=$(df -kP "$opt_fs" 2>/dev/null | awk 'NR == 2 { print $4 }')
    new_kb=$(du -sk "$TMP" | awk '{ print $1 }')
    old_kb=$(du -sk "$SBIN/d2kd" "$SBIN/d2kc" "$SBIN/d2kshadow" "$SBIN/d2kfetch" "$SBIN/d2kpanel" "$SBIN/d2ktg" "$DIR/panel" 2>/dev/null |
        awk '{ s += $1 } END { print s + 0 }')
    big_kb=$(du -sk "$TMP/d2ktg" | awk '{ print $1 }')
    need_kb=$((new_kb - old_kb + big_kb))
    case "$avail_kb" in
        ''|*[!0-9]*) say "не узнать свободное место на $opt_fs — продолжаю" ;;
        *) [ "$avail_kb" -ge "$need_kb" ] ||
               die "мало места на $opt_fs: свободно $avail_kb КиБ, нужно $need_kb КиБ — подключите USB-накопитель под /opt" ;;
    esac
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
    "$INIT" stop || die "прежняя версия не остановилась — файлы выпуска не заменены"
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
install_atomic "$TMP/d2kshadow" "$SBIN/d2kshadow"
install_data_atomic "$TMP/modern.hex" "$DIR/files/modern.hex"
install_data_atomic "$TMP/legacy.hex" "$DIR/files/legacy.hex"
install_atomic "$TMP/d2kfetch" "$SBIN/d2kfetch"
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
install_data_atomic "$TMP/panel/diagnostics.js" "$DIR/panel/diagnostics.js"
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
# The VPS kept its identity/database but received a new public address.
# Rewrite only exact shipped endpoints (also quoted shell assignments).
# Never evaluate the config or change credentials, custom paths or ports.
awk '
function endpoint(line, key, old, new, value) {
    if (index(line, key "=") != 1) return line
    value = substr(line, length(key) + 2)
    if (value == old || value == "\"" old "\"" || value == sprintf("%c%s%c", 39, old, 39))
        return key "=" new
    return line
}
{
    line = endpoint($0, "TG_RELAY_URL", "wss://213.176.74.63.nip.io/ws", "wss://85.192.60.175.nip.io/ws")
    line = endpoint(line, "D2K_GATE", "http://213.176.74.63:9444", "http://85.192.60.175:9444")
    print endpoint(line, "D2K_RELAY_URL", "https://213.176.74.63.nip.io:9443/resolve", "https://85.192.60.175.nip.io:9443/resolve")
}' "$DIR/config" > "$TMP/config.endpoint" || die "не обновить адрес VPS"
# A private sibling keeps credentials private before and after atomic rename.
(
    umask 077
    endpoint_stage=$(mktemp "$DIR/config.migration.XXXXXX") || exit 1
    trap 'rm -f "$endpoint_stage"' EXIT HUP INT TERM
    cat "$TMP/config.endpoint" > "$endpoint_stage" || exit 1
    chmod 0600 "$endpoint_stage" || exit 1
    mv -f "$endpoint_stage" "$DIR/config"
) || die "не сохранить адрес VPS"
# Upgrade the old unconfigured Telegram template without changing a user's
# enable/disable choice or custom relay. No fleet credential is installed.
TG_INSTALL_URL=$(sed -n 's/^TG_RELAY_URL=//p' "$DIR/config" | tail -n 1)
if [ -z "$TG_INSTALL_URL" ]; then
    printf '\nTG_RELAY_URL=wss://85.192.60.175.nip.io/ws\n' >> "$DIR/config"
    TG_INSTALL_URL=wss://85.192.60.175.nip.io/ws
fi
if [ "$TG_INSTALL_URL" = wss://85.192.60.175.nip.io/ws ] &&
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
