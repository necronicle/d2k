#!/bin/sh
# lab-voice-compare.sh — ПРИЁМКА ПЕРЕНОСА ГОЛОСА: поиск цели у эталона и порта.
#
# Что сверяется и почему только это. Вердикт голосового замера требует
# живого разговора, и общего входа ему у двух инструментов нет. Общий вход
# есть у ПОИСКА ЦЕЛИ: оба читают таблицу соединений ядра и выбирают из неё
# голосовые потоки. Её и сверяем — на двух входах:
#   1. образец detect/tests/voice-conntrack.txt, где собраны все случаи,
#      на которых инструменты могут разойтись;
#   2. живая таблица роутера — то, что есть прямо сейчас.
#
# Эталон — САМ исходный файл оригинала (z2k-detect/internal/voiceprobe/
# target_linux.go), без единой правки: к нему приставляется только main,
# задающий путь таблицы через ConntrackPath (переменная заведена в оригинале
# «ради тестов») и печатающий цели. Порт — d2kvoice --list.
#
# Порт держит ПОТОКИ раздельно (пятёрка), эталон сливает их по адресу
# точки. Для сверки поток порта складывается по точке — ровно так, как это
# делает эталон, — и сравниваются множества точек с их пакетами.
#
# ОБЪЯВЛЕННЫЕ РАСХОЖДЕНИЯ — каждое со своей причиной, и только они:
#   порт 50100   — эталон берёт (его диапазон 50000–50100), порт нет: у
#                  боевого профиля discord_udp и у эталона bol-van граница
#                  50099 (сверка 18.09, docs/field/2026-09-17-voice-port-map.md);
#   IPv6         — эталон берёт, порт нет: датапат d2k сегодня только IPv4;
#   100.64/10    — эталон берёт, порт нет: разделяемое пространство
#                  провайдера (RFC 6598), голосового сервера там не бывает;
#                  у Go IsPrivate его нет.
# Любое другое расхождение — провал.
#
# Роутер только читает таблицу: трафик не трогается, z2k гасить не нужно.
set -eu

ROUTER=${D2K_ROUTER:-192.168.1.1}
SSH_PORT=${D2K_SSH_PORT:-222}
REPO=$(cd "$(dirname "$0")/.." && pwd)
Z2K=${Z2K_DETECT:-/Library/Zapret2/z2k/z2k-detect}
GO=${GO:-$HOME/go/bin/go1.25.12}
SSH="ssh -n -p $SSH_PORT -o IdentitiesOnly=yes -i $HOME/.ssh/id_ed25519 root@$ROUTER"
SSH_IN="ssh -p $SSH_PORT -o IdentitiesOnly=yes -i $HOME/.ssh/id_ed25519 root@$ROUTER"
say() { printf '%s\n' "$*" >&2; }

WORK=$(mktemp -d /tmp/d2kvc.XXXXXX)
TOK="d2kvc$$"
cleanup() { rm -rf "$WORK"; $SSH "rm -f /tmp/$TOK.*" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

say "== эталон: исходный файл оригинала + main =="
mkdir -p "$WORK/ref"
sed 's/^package voiceprobe$/package main/' "$Z2K/internal/voiceprobe/target_linux.go" > "$WORK/ref/target_linux.go"
cat > "$WORK/ref/main.go" <<'EOF'
//go:build linux

package main

import (
	"fmt"
	"os"
)

func main() {
	ConntrackPath = os.Args[1]
	ts, err := FindVoiceTargets()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, t := range ts {
		fmt.Printf("%s %d\n", t.String(), t.Packets)
	}
}
EOF
printf 'module ref\n\ngo 1.25\n' > "$WORK/ref/go.mod"
(cd "$WORK/ref" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$GO" build -o "$WORK/ref-bin" .)
# Файл оригинала обязан войти как есть: отличие только в строке package.
grep -v '^package ' "$Z2K/internal/voiceprobe/target_linux.go" > "$WORK/orig.body"
grep -v '^package ' "$WORK/ref/target_linux.go" > "$WORK/copy.body"
cmp -s "$WORK/orig.body" "$WORK/copy.body" ||
    { say "исходник эталона изменился при копировании"; exit 1; }

say "== порт: d2kvoice =="
make -C "$REPO/core" d2kvoice-linux-arm64 >/dev/null
PORT_BIN="$REPO/builds/d2kvoice-linux-arm64"

say "== доставка =="
$SSH_IN "cat > /tmp/$TOK.ref && chmod +x /tmp/$TOK.ref" < "$WORK/ref-bin"
$SSH_IN "cat > /tmp/$TOK.port && chmod +x /tmp/$TOK.port" < "$PORT_BIN"
$SSH_IN "cat > /tmp/$TOK.ct" < "$REPO/detect/tests/voice-conntrack.txt"

# Порт печатает поток строкой «  ip:порт  <- клиент:порт  пакетов N».
# Складываем по точке и сортируем; эталон печатает «ip:порт N».
norm_port() { awk '$2 == "<-" { p[$1] += $5 } END { for (k in p) print k, p[k] }' | sort; }
norm_ref()  { sort; }

fail=0
compare() {
    label=$1 path=$2
    $SSH "/tmp/$TOK.ref $path" | norm_ref > "$WORK/ref.$label"
    $SSH "/tmp/$TOK.port --list --conntrack $path" | norm_port > "$WORK/port.$label"
    say "--- $label: эталон $(wc -l < "$WORK/ref.$label" | tr -d ' ') точек, порт $(wc -l < "$WORK/port.$label" | tr -d ' ')"
    # Объявленные расхождения: только у эталона, только таких видов.
    only_ref=$(comm -23 "$WORK/ref.$label" "$WORK/port.$label")
    only_port=$(comm -13 "$WORK/ref.$label" "$WORK/port.$label")
    if [ -n "$only_port" ]; then
        say "  ПРОВАЛ: только у порта:"; printf '%s\n' "$only_port" | sed 's/^/    /' >&2
        fail=1
    fi
    printf '%s\n' "$only_ref" | while IFS= read -r l; do
        [ -n "$l" ] || continue
        a=${l%% *}
        case "$a" in
            *:50100)       say "  объявлено: $l — порт 50100 вне профиля" ;;
            \[*)           say "  объявлено: $l — IPv6, датапат d2k только IPv4" ;;
            100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*)
                           say "  объявлено: $l — 100.64/10, разделяемое пространство провайдера" ;;
            *)             say "  ПРОВАЛ: только у эталона: $l"; echo x >> "$WORK/fail" ;;
        esac
    done
    comm -12 "$WORK/ref.$label" "$WORK/port.$label" | sed 's/^/  совпало: /' >&2
}

compare образец "/tmp/$TOK.ct"
# Живую таблицу — ОДНИМ снимком: читай её каждый инструмент сам, он увидел бы
# свой момент, и растущий поток разошёлся бы числом пакетов (первый прогон:
# 82 у эталона против 102 у порта на одной и той же точке).
$SSH "cat /proc/net/nf_conntrack > /tmp/$TOK.live"
compare живая "/tmp/$TOK.live"

[ -f "$WORK/fail" ] && fail=1
if [ "$fail" = 0 ]; then
    say "== СОВПАЛО: поиск цели порта и эталона одинаков, кроме объявленного =="
else
    say "== РАСХОЖДЕНИЕ СВЕРХ ОБЪЯВЛЕННОГО =="
fi
exit "$fail"
