#!/bin/sh
# Удаление d2k с Keenetic.
#
# Убирает ТОЛЬКО своё: свои файлы, свою цепочку firewall, свои процессы.
# Чужого не трогает даже там, где похоже — правило соседа, снятое «на всякий
# случай», ломает соседа молча.
#
# Каталог изученных коробок по умолчанию СОХРАНЯЕТСЯ: он оплачен настоящими
# измерениями на этой линии, и выбрасывать его вместе с программой — потеря,
# которую нечем восполнить. Удалить его можно явно.
set -eu

DIR=/opt/d2k
SBIN=/opt/sbin
INIT=/opt/etc/init.d/S99d2k
KEEP=${D2K_KEEP_STATE:-1}

say() { echo "d2k: $*"; }

if [ -x "$INIT" ]; then
    say "останавливаю"
    "$INIT" stop || say "остановка вернула ошибку — продолжаю удаление"
fi

# Цепочка снимается даже если init-скрипта уже нет: он мог быть удалён руками,
# а правила остаться.
# Старое имя D2K тоже снимается: установка прошлой версии могла оставить его.
for hook in POSTROUTING FORWARD OUTPUT INPUT; do
    for ch in D2K_OUT D2K_IN D2K; do
        while iptables -t mangle -D "$hook" -j "$ch" 2>/dev/null; do :; done
    done
done
for ch in D2K_OUT D2K_IN D2K; do
    if iptables -t mangle -n -L "$ch" >/dev/null 2>&1; then
        iptables -t mangle -F "$ch" 2>/dev/null || true
        iptables -t mangle -X "$ch" 2>/dev/null || true
    fi
done
say "правила сняты"

rm -f "$INIT" "$SBIN/d2k" "$SBIN/d2kd"
rm -rf "$DIR/run" "$DIR/log"

if [ "$KEEP" = "1" ]; then
    say "каталог изученных коробок оставлен в $DIR/state"
    say "чтобы удалить и его: D2K_KEEP_STATE=0 sh $0"
    rm -f "$DIR/config.new"
else
    rm -rf "$DIR"
    say "удалено всё, включая каталог коробок"
fi

left=$(iptables -t mangle -S 2>/dev/null | grep -c -- "-j D2K" || true)
say "готово. Ссылок на цепочки d2k осталось: $left"
