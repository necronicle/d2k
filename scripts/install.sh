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
#   * фонового обновления нет: механизм не проверен, а непроверенное
#     автообновление хуже отсутствующего;
#   * подписи пока нет — это задача версии для общего пользования, и
#     обещать её здесь нельзя.
set -eu

REPO=${D2K_REPO:-necronicle/d2k}
REF=${D2K_REF:-main}
BASE=${D2K_BASE:-https://raw.githubusercontent.com/$REPO/$REF}

DIR=/opt/d2k
SBIN=/opt/sbin
INIT=/opt/etc/init.d/S99d2k
TMP=

say()  { echo "d2k: $*"; }
die()  { echo "d2k: $*" >&2; cleanup; exit 1; }
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; TMP=; }
trap cleanup EXIT INT TERM

# --- арка ----------------------------------------------------------------
#
# Отказ на неподдерживаемой арке ЯВНЫЙ. Поставить бинарник не той арки значит
# получить «не запускается» без объяснения.
case "$(uname -m)" in
    aarch64|arm64) ARCH=arm64 ;;
    armv7l|armv7)  ARCH=arm ;;
    mips)          ARCH=mips ;;
    mipsel)        ARCH=mipsle ;;
    x86_64)        ARCH=amd64 ;;
    *) die "архитектура $(uname -m) не поддерживается" ;;
esac
say "архитектура: $(uname -m) -> $ARCH"

# --- что нужно от системы ------------------------------------------------
for t in curl iptables start-stop-daemon; do
    command -v "$t" >/dev/null 2>&1 || die "нет $t — поставьте пакет и повторите"
done
[ -e /proc/net/netfilter/nfnetlink_queue ] || \
    die "ядро без nfnetlink_queue — d2k работать не сможет"
grep -qw NFQUEUE /proc/net/ip_tables_targets 2>/dev/null || \
    die "в iptables нет цели NFQUEUE"
grep -qw connbytes /proc/net/ip_tables_matches 2>/dev/null || \
    die "в iptables нет совпадения connbytes"

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
    else
        curl -fsSL --max-time 120 -o "$2" "$BASE/$1" || die "не скачать $1"
    fi
    [ -s "$2" ] || die "$1 оказался пустым"
}

say "загрузка"
fetch "builds/d2k-linux-$ARCH"  "$TMP/d2k"
fetch "builds/d2kd-linux-$ARCH" "$TMP/d2kd"
fetch "files/S99d2k"            "$TMP/S99d2k"

chmod +x "$TMP/d2k" "$TMP/d2kd" "$TMP/S99d2k"

# Проверка ДО замены: запускается ли то, что скачалось, и та ли это арка.
"$TMP/d2k" version >/dev/null 2>&1 || die "скачанный d2k не запускается на этой системе"
"$TMP/d2kd" --help  >/dev/null 2>&1 || die "скачанный d2kd не запускается на этой системе"
say "проверено: $("$TMP/d2k" version | head -1)"

# --- остановка прежней версии --------------------------------------------
if [ -x "$INIT" ]; then
    say "останавливаю прежнюю версию"
    "$INIT" stop || say "прежняя версия остановилась с ошибкой — продолжаю"
fi

# --- атомарная замена ----------------------------------------------------
#
# Переименование в пределах одной ФС атомарно. Копирование поверх работающего
# бинарника — нет: на середине копирования файл уже не тот и ещё не этот.
mkdir -p "$DIR/state" "$DIR/run" "$DIR/log" "$SBIN" /opt/etc/init.d

install_atomic() {
    cp "$1" "$2.new" || die "не записать $2.new"
    chmod +x "$2.new"
    mv -f "$2.new" "$2" || die "не подменить $2"
}
install_atomic "$TMP/d2k"    "$SBIN/d2k"
install_atomic "$TMP/d2kd"   "$SBIN/d2kd"
install_atomic "$TMP/S99d2k" "$INIT"

# Конфигурация принадлежит человеку: существующую не трогаем.
if [ ! -f "$DIR/config" ]; then
    "$SBIN/d2k" config -write >/dev/null 2>&1 || true
    say "создана конфигурация $DIR/config"
else
    say "конфигурация уже есть — не трогаю"
fi

# --- запуск и проверка ---------------------------------------------------
say "запуск"
"$INIT" start || die "служба не запустилась"

sleep 2
if ! "$INIT" status | grep -q "датапат: работает"; then
    "$INIT" stop || true
    die "служба запустилась и умерла — смотрите $DIR/log/d2kd.log"
fi

"$INIT" status
say "готово. Панель: http://127.0.0.1:8090/ (адрес меняется в $DIR/config)"
say "режим по умолчанию — наблюдение. Активный обход включается MODE=apply."
