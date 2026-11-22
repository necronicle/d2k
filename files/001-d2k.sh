#!/bin/sh
# Хук NDM: событийное восстановление правил d2k.
# Ставится в /opt/etc/ndm/netfilter.d/001-d2k.sh
#
# Keenetic зовёт скрипты из этого каталога при изменениях netfilter. Сброс
# правил — как раз такое изменение, и хук ловит его СРАЗУ, тогда как
# периодический сторож увидел бы пропажу в среднем через полминуты. Номер 001,
# а не 000: у z2k занят 000, и порядок между ними значения не имеет — оба
# восстанавливают только своё.
#
# Переменные от NDM: $table (filter|nat|mangle|raw), $type (iptables|ip6tables).
# Они приходят из окружения вызывающего, поэтому shellcheck справедливо не
# видит присваивания — отключаем проверку точечно, а не глушим весь файл.
# shellcheck disable=SC2154

HEAL="${HEAL:-/opt/d2k/d2k-fw-heal.sh}"

# Сторож возвращает и разгрузку ускорителя (-j PPE, d2k-ppe-deoffload.sh):
# NDM сносит её вместе с правилами очереди, а без неё ответы снова уходят
# мимо netfilter.
#
# d2k живёт в mangle. nat трогаем тоже: при переподключении Keenetic дёргает
# хук и на нём, а сброс к тому моменту уже случился (та же оговорка, что у
# z2k в 000-zapret2.sh).
if [ "$table" = "mangle" ] || [ "$table" = "nat" ]; then
    [ ! -x "$HEAL" ] || D2K_HEAL_SOURCE=ndm "$HEAL"
fi

# Telegram owns independent nat redirects and IPv6 fast-fail rules. NDM's nat
# rebuild removes them, so ask the existing init service to restore only that
# tunnel's rules; never restart or mutate the D2K strategy engine here.
if [ "$table" = "nat" ]; then
    INIT=/opt/etc/init.d/S99d2k
    [ ! -x "$INIT" ] || "$INIT" telegram-reapply >/dev/null 2>&1 || true
fi
exit 0
