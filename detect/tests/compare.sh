#!/bin/sh
# compare.sh — приёмка ПЕРЕНОСА: эталон и C-порт обязаны дать один и тот же
# вердикт, стратегию и трассу на одной и той же цели.
#
# Запускать НА РОУТЕРЕ: сырые зонды требуют root и живой линии, а весь смысл
# сверки в том, что оба инструмента видят одну и ту же коробку. На маке
# сравнивать нечего — там сырого слоя нет вовсе.
#
# ТРИГГЕР ОБОИМ ОДИН. У эталона приветствие собирает crypto/tls (283 байта), у
# порта — снятый с живого браузера профиль (1534 байта). Это разные байты, и
# коробка на них реагирует по-разному: замер 14.09 на i.ytimg.com дал
# «seqovl-1» на приветствии эталона и «disorder» на браузерном — оба верны, но
# сверять на них АЛГОРИТМ нельзя. Поэтому триггер снимается один раз
# (--dump-trigger) и скармливается обоим шестнадцатеричной строкой.
#
# Из сверки исключено ТОЛЬКО время: оно не вывод. Число зондов сверяется.
#
# И ещё одно, названное поимённо: тексты ошибок берутся у libc, а эталон
# слинкован с glibc (Go), порт — с musl. На одном и том же EMSGSIZE они говорят
# «message too long» и «Message too large». Это разные СТРОКИ одного и того же
# кода ошибки, а не разное поведение, поэтому таблица ниже сводит их к коду —
# поимённо, а не общим sed'ом по слову «too»: общий заглушил бы настоящую
# разницу, если бы она когда-нибудь появилась.
set -e

Z2K=${Z2K:-/opt/sbin/z2k-detect}
D2K=${D2K:-/tmp/d2k-detect}
REPEATS=${REPEATS:-3}
# Каким приветствием снимать общий триггер. legacy (снятый TLS 1.2, 214 байт)
# нужен отдельно: на нём фальшивка шага 1 укладывается в один сегмент, то есть
# сверяется ТОТ ЖЕ путь отправки, что был до починки потолка сегмента. На
# modern (1538 байт) фальшивка уходит несколькими сегментами, и там сверяется
# уже почин­ка, а не эталонный путь.
HELLO=${HELLO:-modern}
OUT=${OUT:-/tmp/d2k-compare}

[ -x "$Z2K" ] || { echo "нет эталона: $Z2K"; exit 1; }
[ -x "$D2K" ] || { echo "нет порта: $D2K"; exit 1; }

mkdir -p "$OUT"
fails=0
total=0

# Время из строки «Зондов: N за ...» вырезаем, остальное сравниваем дословно.
norm() {
	sed -e 's/\(Зондов: *[0-9]*\) за [^ ]*/\1/' \
	    -e 's/message too long/EMSGSIZE/' \
	    -e 's/Message too large/EMSGSIZE/' \
	    -e 's/connection refused/ECONNREFUSED/' \
	    -e 's/Connection refused/ECONNREFUSED/' \
	    "$1"
}

for target in "$@"; do
	total=$((total + 1))
	tag=$(echo "$target-$HELLO" | tr ':/' '__')
	hex="$OUT/$tag.hex"
	"$D2K" classify "$target" --hello "$HELLO" --dump-trigger > "$hex"

	"$Z2K" classify -raw "$(cat "$hex")" -repeats "$REPEATS" "$target" > "$OUT/$tag.z2k" 2>&1 || true
	"$D2K" classify "$target" --raw "$(cat "$hex")" --repeats "$REPEATS" > "$OUT/$tag.d2k" 2>&1 || true

	norm "$OUT/$tag.z2k" > "$OUT/$tag.z2k.n"
	norm "$OUT/$tag.d2k" > "$OUT/$tag.d2k.n"
	if diff -u "$OUT/$tag.z2k.n" "$OUT/$tag.d2k.n" > "$OUT/$tag.diff" 2>&1; then
		echo "СОВПАЛО   $target — $(sed -n 's/^Вердикт: *//p' "$OUT/$tag.d2k")"
	else
		fails=$((fails + 1))
		echo "РАСХОДИТСЯ $target:"
		cat "$OUT/$tag.diff"
	fi
done

echo "---"
if [ "$fails" -eq 0 ]; then
	echo "перенос: совпало $total из $total"
	exit 0
fi
echo "перенос: РАСХОЖДЕНИЙ $fails из $total"
exit 1
