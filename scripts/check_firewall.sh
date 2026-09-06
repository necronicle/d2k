#!/bin/sh
# Проверка правил files/S99d2k НАСТОЯЩИМ iptables, а не чтением текста.
#
# Почему отдельно от scripts/check.sh: единственный способ прогнать iptables
# с машины разработки (Mac, без родного netfilter) — Linux-контейнер, а
# Docker как новая ЖЁСТКАЯ зависимость всего гейта — решение отдельное от
# этой проверки и не принято здесь явочным порядком. Docker в проекте уже
# используется для Linux-специфичной проверки (см. память про
# loopback-буферы: "Linux-проверка через docker+tar") — тот же приём,
# оформленный в отдельный, вызываемый по требованию скрипт.
#
# Нужна затем, что files/S99d2k — самый рискованный файл всей QUIC-вертикали
# (ставит правила firewall на живом роутере Марка, через который ходит вся
# его сеть), а до ревью задачи 4 (круг 2) он не был проверен вообще ничем,
# даже shellcheck'ом. "Прочитали и согласились" проверкой не является:
# здесь fw_up/fw_down исполняются настоящим iptables в изолированном сетевом
# namespace контейнера, и утверждения проверяются по РЕАЛЬНОМУ выводу
# `iptables -S`, а не по тому, что скрипт, как кажется на взгляд, должен
# делать.
#
# Требует Docker (docker info должен отвечать). Ничего не трогает на хосте:
# все правила ставятся и снимаются в СЕТЕВОМ NAMESPACE КОНТЕЙНЕРА, который
# создаётся и уничтожается заново при каждом запуске.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)
S99="$ROOT/files/S99d2k"

if ! docker info >/dev/null 2>&1; then
    echo "check_firewall.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Только определения функций — без хвостового `case "$1" in ... esac`,
# который иначе исполнился бы прямо при source'инге (это `exit`, а не
# управление, — sh на этом действительно выйдет) и сорвал бы проверку раньше
# первого вызова fw_up. Строка отреза — первая строка `case "$1" in`, она
# должна остаться ПОСЛЕДНЕЙ строкой файла, которую видит эта команда: если
# структура S99d2k когда-нибудь изменится и это перестанет быть так, grep
# ниже провалится явно, а не тихо обрежет не там.
#
# $1 в шаблоне ниже — буквальный текст, который ищем В ЧУЖОМ ФАЙЛЕ ($S99), а
# не параметр этого скрипта: раскрывать его нельзя, двойные кавычки были бы
# ошибкой, а не стилем.
# shellcheck disable=SC2016
CASE_LINE=$(grep -n '^case "$1" in' "$S99" | head -1 | cut -d: -f1)
if [ -z "$CASE_LINE" ]; then
    echo "check_firewall.sh: не нашёл 'case \"\$1\" in' в $S99 — разметка файла изменилась" >&2
    exit 1
fi
head -n "$((CASE_LINE - 1))" "$S99" > "$WORK/s99funcs.sh"

cat > "$WORK/driver.sh" <<'DRIVER'
#!/bin/sh
set -e
. /work/s99funcs.sh

fail() { echo "ПРОВАЛ: $*" >&2; exit 1; }

echo "== fw_up =="
fw_up
RULES=$(iptables -t mangle -S)
echo "$RULES"

echo "$RULES" | grep -qE -- '-A D2K_OUT -p udp .*--dports 443.*--queue-bypass' \
    || fail "нет исходящего UDP-правила с --queue-bypass"
echo "$RULES" | grep -qE -- '-A D2K_IN -p udp .*--sports 443.*--queue-bypass' \
    || fail "нет входящего UDP-правила (ответ) с --queue-bypass"
echo "$RULES" | grep -qE -- '-A D2K_OUT -p tcp .*--dports 443.*--queue-bypass' \
    || fail "нет исходящего TCP-правила с --queue-bypass (регресс задачи 3)"
echo "$RULES" | grep -qE -- '-A D2K_IN -p tcp .*--sports 443.*--queue-bypass' \
    || fail "нет входящего TCP-правила (ответ) с --queue-bypass (регресс задачи 3)"

MARK_LINE=$(echo "$RULES" | grep -E -- '-A D2K_OUT -m mark .* -j RETURN' || true)
[ -n "$MARK_LINE" ] || fail "нет правила RETURN по метке в исходящей цепочке"
echo "$MARK_LINE" | grep -q -- '-p ' && fail "правило RETURN по метке сузили протоколом -p — UDP перестанет исключаться"

echo "== fw_up повторно (идемпотентность) =="
fw_up
COUNT_OUT=$(iptables -t mangle -S D2K_OUT | wc -l)
[ "$COUNT_OUT" -eq 4 ] || fail "повторный fw_up размножил правила D2K_OUT (строк: $COUNT_OUT, ждали 4)"

echo "== fw_down =="
fw_down
LEFT=$(iptables -t mangle -S | grep -ic d2k || true)
[ "$LEFT" -eq 0 ] || fail "fw_down оставил $LEFT правил(о) с упоминанием D2K"

echo "ВСЁ ЗЕЛЕНО: правила files/S99d2k проверены настоящим iptables"
DRIVER

docker run --rm --cap-add=NET_ADMIN -v "$WORK:/work" debian:bookworm-slim \
    sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq iptables >/dev/null && sh /work/driver.sh'
