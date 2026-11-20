#!/bin/sh
# Полная проверка перед коммитом. Один вход, чтобы её нельзя было прогнать
# наполовину.
#
# Существует потому, что я однажды прогнал make через grep, код возврата
# пришёл от grep, провал сборки одного теста не был замечен, и сломанное
# дерево уехало в коммит. Здесь ничего не фильтруется и каждый шаг проверяется
# по коду возврата.
#
# ПАРАЛЛЕЛЬНО, НО НЕ ВСЛЕПУЮ. Прежде всё шло в один поток и занимало 37–47
# минут на десятиядерной машине (замер 12.10.2026). Теперь две фазы:
#
#   1. сборка и тесты — по одному каталогу за раз, с `make -j` ВНУТРИ make:
#      один процесс make сам знает зависимости и параллелит безопасно;
#   2. независимые дорожки — одновременно, каждая со своим журналом и своим
#      кодом возврата. Дорожки не пишут в общие файлы: имена в /tmp у
#      датапата и ядра не пересекаются (проверено), а шарды санитайзеров
#      собирают каждый тест в свой бинарник.
#
# Отказ любой дорожки валит скрипт; её журнал печатается целиком, а не
# обрезанным хвостом. Журналы всех дорожек остаются в каталоге, который
# скрипт называет в конце.
set -eu

# Отказ ЛЮБОГО шага валит весь скрипт (set -e), и это единственное, на что
# можно опираться. Цепочка вида `sh check.sh; git commit && git push` этот
# отказ не заметит: точка с запятой пропускает код возврата дальше. Звать
# только через && либо проверять $? явно.

# ВСЁ ТЕЛО — В ФУНКЦИИ main, ВЫЗОВ — ПОСЛЕДНЕЙ СТРОКОЙ. bash читает скрипт
# по ходу выполнения: правка этого файла посреди прогона сдвигает смещения, и
# дальше он исполняет мешанину. 13.10.2026 так и вышло — дорожка scripts
# провалилась, а скрипт напечатал «ВСЁ ЗЕЛЕНО» с кодом 0: после правки bash
# перескочил проверку отказа. Функцию bash дочитывает целиком до запуска,
# поэтому теперь правка во время прогона его не портит.
main() {
    ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
    cd "$ROOT"
    J=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    LOG=$(mktemp -d "${TMPDIR:-/tmp}/d2k-check.XXXXXX")
    START=$(date +%s)

    # ── Фаза 1: сборка и тесты ──────────────────────────────────────────────────

    echo "== датапат: сборка и тесты (-j$J) =="
    make -C datapath clean
    make -C datapath -j"$J" check planlab ctlprobe

    echo "== модель: общие понятия ТЗ =="
    make -C model clean
    make -C model check

    echo "== ядро: сборка и тесты (-j$J) =="
    make -C core clean
    # d2kc нужен интеграционному тесту рукопожатия контроллера в фазе 2.
    make -C core -j"$J" check d2kc

    # ── Фаза 2: независимые дорожки ─────────────────────────────────────────────

    lane_datapath() {
        # Локально всё собирает clang, а CI — gcc. Они расходятся: gcc ловит
        # sign-compare там, где clang молчит.
        make -C datapath gcc-warn
        make -C datapath san
        make -C datapath cross
    }

    lane_core_tools() {
        # SO_MARK есть только на Linux: чужой компилятор и cross — единственные
        # места, где ветка с меткой вообще компилируется. На маке её нет.
        make -C core gcc-warn
        make -C core cross
        make -C model gcc-warn
        make -C model cross
        # Проводник установки на VPS (relay-gate/): свой C-сервис, без сети в тестах.
        make -C relay-gate test
    }

    # Санитайзеры ядра — шардами по измеренному весу, как в CI
    # (scripts/ci-core-san-shard.sh): одним заходом это 22 минуты.
    lane_san_sched()   { sh scripts/ci-core-san-shard.sh sched; }
    lane_san_compose() { sh scripts/ci-core-san-shard.sh compose; }
    lane_san_rest1()   { sh scripts/ci-core-san-shard.sh rest-1; }
    lane_san_rest2()   { sh scripts/ci-core-san-shard.sh rest-2; }

    lane_scripts() {
        # Шарды обязаны покрывать check и san целиком.
        sh scripts/ci-core-shard.sh verify
        sh scripts/ci-core-san-shard.sh verify
        # Один список с CI (scripts/lint-shell.sh): он же ловит init-скрипты
        # files/ без расширения — S99d2k и остальные, которых глоб *.sh не видит.
        sh scripts/lint-shell.sh
        # Каждый scripts/test-*, а не список руками: список руками отстаёт от
        # дерева (так test-field-controller-return.sh месяцами стоял красным
        # незамеченным). Все запускаются даже после отказа, отказы называются в
        # конце.
        failed=''
        for t in scripts/test-*.sh scripts/test-*.cjs; do
            [ -e "$t" ] || continue
            echo "== $t =="
            case "$t" in
                *.cjs) node "$t" || failed="$failed $t" ;;
                *)     sh "$t"   || failed="$failed $t" ;;
            esac
        done
        if [ -n "$failed" ]; then
            echo "провалились:$failed" >&2
            return 1
        fi
    }

    LANES="datapath core_tools san_sched san_compose san_rest1 san_rest2 scripts"

    echo "== фаза 2: $(echo "$LANES" | wc -w | tr -d ' ') дорожек одновременно, журналы в $LOG =="
    for l in $LANES; do
        ( set -e; "lane_$l" ) > "$LOG/$l.log" 2>&1 &
        echo "$!" > "$LOG/$l.pid"
    done

    failed=''
    for l in $LANES; do
        if wait "$(cat "$LOG/$l.pid")"; then
            echo "  готово: $l"
        else
            echo "  ПРОВАЛ: $l"
            failed="$failed $l"
        fi
    done

    if [ -n "$failed" ]; then
        for l in $failed; do
            echo
            echo "===== журнал дорожки $l ====="
            cat "$LOG/$l.log"
        done
        echo
        echo "ПРОВАЛ:$failed (журналы: $LOG)" >&2
        exit 1
    fi

    # Синтаксис files/S99d2k проверен выше; ПОВЕДЕНИЕ его правил firewall —
    # отдельным scripts/check_firewall.sh настоящим iptables в контейнере. Не
    # вызывается отсюда: Docker — не зависимость остального гейта. Запускать
    # вручную при правке firewall-части S99d2k.

    echo "ВСЁ ЗЕЛЕНО за $(( ($(date +%s) - START) / 60 )) мин $(( ($(date +%s) - START) % 60 )) с (журналы: $LOG)"
}

main "$@"
