#!/bin/sh
# Полная проверка перед коммитом. Один вход, чтобы её нельзя было прогнать
# наполовину.
#
# Существует потому, что я однажды прогнал make через grep, код возврата
# пришёл от grep, провал сборки одного теста не был замечен, и сломанное
# дерево уехало в коммит. Здесь ничего не фильтруется и каждый шаг проверяется
# по коду возврата.
set -eu

# Отказ ЛЮБОГО шага валит весь скрипт (set -e), и это единственное, на что
# можно опираться. Цепочка вида `sh check.sh; git commit && git push` этот
# отказ не заметит: точка с запятой пропускает код возврата дальше. Звать
# только через && либо проверять $? явно.

GO=${GO:-go}

echo "== формат =="
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
    echo "не отформатировано:"
    echo "$unformatted"
    exit 1
fi

echo "== vet =="
$GO vet ./...

echo "== датапат: сборка и тесты =="
make -C datapath clean
make -C datapath check
make -C datapath planlab ctlprobe

echo "== ядро: сборка и тесты =="
make -C core clean
make -C core check

echo "== датапат: чужой компилятор =="
# Локально всё собирает clang, а CI — gcc. Они расходятся: gcc ловит
# sign-compare там, где clang молчит. Пока этого шага не было, гейт горел
# зелёным при КАЖДОМ красном прогоне CI.
make -C datapath gcc-warn

echo "== ядро: чужой компилятор =="
# Тот же смысл, что и для датапата, и здесь ещё буквальнее: SO_MARK есть
# только на Linux, mipsel-gcc собирает под Linux — только эта проверка (и
# cross ниже) вообще компилирует ветку с меткой. На маке она не строится
# никогда, потому что SO_MARK на маке не определён.
make -C core gcc-warn

echo "== датапат: санитайзеры =="
make -C datapath san

echo "== ядро: санитайзеры =="
make -C core san

echo "== датапат: переносимость =="
make -C datapath cross

echo "== ядро: переносимость =="
make -C core cross

echo "== Go: тесты с детектором гонок =="
D2K_REQUIRE_LAB=1 $GO test -race -count=1 ./...

echo "== скрипты =="
find scripts spike -name '*.sh' -print0 | xargs -0 shellcheck -s sh

echo "ВСЁ ЗЕЛЕНО"
