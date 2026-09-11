# Ядро d2k. Здесь живёт оракул: то, что отличает «прошло» от «убито», по
# РОВНО тем байтам, что шлёт настоящий клиент — см. шапку include/d2k_meas.h
# про то, чего стоила эта дисциплина 06.09.2026.
#
# -Werror и кросс-проверка — той же причины, что в датапате (см. его
# Makefile): непереносимость обязана ловиться в день, когда её внесли, а не
# на роутере. Для ядра это особенно буквально: SO_MARK есть только на Linux,
# и без цели cross ветка с меткой ни разу не компилируется на машине
# разработки (на маке SO_MARK не определён) — опечатка там доехала бы до
# узла незамеченной.

CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -Iinclude
LDFLAGS ?=
# Стенд в тестах поднимает петлю-мишень в отдельном потоке; самому оракулу
# потоки не нужны, поэтому pthread — только у тестовой линковки.
TEST_LDFLAGS = $(LDFLAGS) -lpthread

# Кросс-компиляторы для проверки переносимости. Пути переопределяются извне.
ZIG        ?= /opt/homebrew/bin/zig
MIPSEL_CC  ?= mipsel-unknown-linux-gnu-gcc

SRC     = meas.c verdict.c crypto.c quic.c quicprobe.c props.c hello.c catalog.c match.c compose.c
HDR     = include/d2k_meas.h include/d2k_verdict.h include/d2k_crypto.h include/d2k_quic.h \
          include/d2k_quicprobe.h include/d2k_hello.h include/d2k_catalog.h include/d2k_compose.h
# Общий стенд тестов (петля-мишень в потоке, режимы 0-4). Один на test_meas и
# test_verdict — второй, отдельный стенд не заводится нигде (см. его шапку).
# test_crypto и test_quic стенда не используют вовсе: криптография и разбор
# QUIC не трогают сеть, вход — байтовые вектора RFC, а не петля-мишень.
# test_quicprobe и test_quic_arms заводят СВОЙ стенд каждый (датаграммный, не
# потоковый — см. их шапки) и в TESTHDR не входят: они не общие ни с кем и
# друг с другом (задача 6 подменяет ДРУГИЕ крючки, чем задача 5). test_hello
# тоже без стенда: вход — снятые байты и встроенные профили, не сеть.
# test_catalog тоже без стенда: вход — файл на диске (testdata/catalog-real.json,
# снимок с роутера) и синтетические JSON-обрывки, которые тест пишет сам, не сеть.
# test_match тоже без стенда: сравнивает уже разобранные d2k_cat_fp (свои,
# сконструированные inline, и настоящие — из того же testdata/catalog-real.json),
# сети и файловой записи не касается вовсе.
# test_compose (задача 3) тоже без стенда и вообще без сети: d2k_compose —
# чистая сборка текста плана из вектора свойств, а d2k_props_ask в этой
# реализации сети не касается вовсе (см. большой комментарий в шапке
# compose.c про то, почему единственный честный ответ здесь — вектор из
# одних D2K_P_UNKNOWN).
TESTHDR = test_stand.h

TESTS   = test_meas test_verdict test_crypto test_quic test_quicprobe test_quic_arms test_hello test_catalog test_match test_compose

.PHONY: all check san gcc-warn cross clean test-meas test-verdict test-crypto test-quic test-quicprobe test-quic-arms test-hello test-catalog test-match test-compose

all: meas.o verdict.o crypto.o quic.o quicprobe.o props.o hello.o catalog.o match.o compose.o

meas.o: meas.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

verdict.o: verdict.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

crypto.o: crypto.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Разбор QUIC зовёт примитивы crypto.c (HKDF, AES-ECB, AES-GCM) — см. шапку
# quic.c: снятие защиты заголовка и расшифровка Initial стоят целиком на них.
quic.o: quic.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Вопросник зовёт d2k_quic_is_initial (quic.c) для согласия в вопросе "это
# вообще Initial" и примитивы crypto.c для серверного направления расшифровки
# (см. шапку quicprobe.c про то, почему это направление не в quic.c).
quicprobe.o: quicprobe.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Задача 6: подбор плеча зовёт d2k_quic_build_pool/d2k_quic_verify_response
# (quicprobe.c, экспортированы задачей 6 — см. их doc-комментарии в
# d2k_quicprobe.h про то, почему не дублируются) и d2k_mark_hook (d2k_meas.h,
# как есть — та же метка, что и у остальных отправителей дерева).
props.o: props.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# core/hello_profiles.inc — приветствия холодного старта, встроенные в
# бинарник (см. шапку hello.c про то, почему не путь к файлу). Собирается
# ИЗ profiles/*.hex МЕХАНИЧЕСКИ: вырезаются комментарии (строки на '#') и все
# пробелы/переводы строк, остаётся чистая шестнадцатеричная строка — эта
# цель не решает, что внутри профиля, только переносит текст в компилируемый
# вид. Сам .inc в git не идёт (core/* в .gitignore, .hex — намеренное
# исключение из него, .inc — нет): это вывод сборки, источник — только .hex.
hello_profiles.inc: profiles/modern.hex profiles/legacy.hex
	@rm -f $@
	@echo "/* Сгенерировано из profiles/ (*.hex) core/Makefile'ом. Правь исходники, не этот файл. */" > $@
	@for name in modern legacy; do \
		hex=$$(grep -v '^#' profiles/$$name.hex | tr -cd '0-9a-fA-F'); \
		len=$${#hex}; \
		if [ $$((len % 2)) -ne 0 ]; then \
			echo "profiles/$$name.hex: нечётное число шестнадцатеричных цифр" >&2; \
			exit 1; \
		fi; \
		printf 'static const char d2k_profile_%s_hex[] = "%s";\n' "$$name" "$$hex" >> $@; \
	done

# hello.c #include'ит hello_profiles.inc напрямую (см. его шапку) — без
# этого правила предыдущей сборки объектник просто не найдёт файл.
hello.o: hello.c $(HDR) hello_profiles.inc
	$(CC) $(CFLAGS) -c -o $@ $<

# Каталог (задача 1): свой разбор JSON поверх файла, который читает и
# Go-панель (см. шапку d2k_catalog.h). Ни от одного другого модуля ядра не
# зависит и ни один не зависит от него — планировщик (задача 5) свяжет его
# с остальными.
catalog.o: catalog.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Узнавание коробки (задача 2): сравнение d2k_cat_fp с допуском поверх типов
# catalog.c (задача 1) — см. шапку match.c и d2k_fp_same/d2k_catalog_match в
# d2k_catalog.h. От catalog.c зависит только по заголовку (типы), не по
# символам, поэтому .o собирается отдельно; связывает их только тест ниже.
match.o: match.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Свойства коробки и вывод плана для TCP (задача 3): d2k_compose зовёт
# d2k_hello_from_profile (hello.c, задача 1) для decoy-приветствия вопросов
# 2/4/5 (см. build_decoy_hello в compose.c про то, почему именно LEGACY-
# профиль, а не MODERN) — отсюда hello.o в связывании тестов ниже. От
# meas.c/verdict.c не зависит по символам вовсе: единственный оракул задачи,
# d2k_meas, недостаточен ни для одного из пяти вопросов, и d2k_props_ask в
# этой реализации честно ничего не измеряет (см. шапку compose.c).
compose.o: compose.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_meas: test_meas.c meas.o $(HDR) $(TESTHDR)
	$(CC) $(CFLAGS) -o $@ test_meas.c meas.o $(TEST_LDFLAGS)

test_verdict: test_verdict.c meas.o verdict.o $(HDR) $(TESTHDR)
	$(CC) $(CFLAGS) -o $@ test_verdict.c meas.o verdict.o $(TEST_LDFLAGS)

test_crypto: test_crypto.c crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_crypto.c crypto.o $(TEST_LDFLAGS)

test_quic: test_quic.c quic.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic.c quic.o crypto.o $(TEST_LDFLAGS)

test_quicprobe: test_quicprobe.c quicprobe.o quic.o crypto.o meas.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quicprobe.c quicprobe.o quic.o crypto.o meas.o $(TEST_LDFLAGS)

test_quic_arms: test_quic_arms.c props.o quicprobe.o quic.o crypto.o meas.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic_arms.c props.o quicprobe.o quic.o crypto.o meas.o $(TEST_LDFLAGS)

test_hello: test_hello.c hello.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_hello.c hello.o $(TEST_LDFLAGS)

test_catalog: test_catalog.c catalog.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_catalog.c catalog.o $(TEST_LDFLAGS)

# Проверка каталога d2k_catalog_load настоящим testdata/catalog-real.json
# (задача 2, шаг "поиск по каталогу находит и не находит") — вот откуда
# catalog.o в этом связывании, а не только match.o.
test_match: test_match.c match.o catalog.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_match.c match.o catalog.o $(TEST_LDFLAGS)

test_compose: test_compose.c compose.o hello.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_compose.c compose.o hello.o $(TEST_LDFLAGS)

test-meas: test_meas
	./test_meas

test-verdict: test_verdict
	./test_verdict

test-crypto: test_crypto
	./test_crypto

test-quic: test_quic
	./test_quic

test-quicprobe: test_quicprobe
	./test_quicprobe

test-quic-arms: test_quic_arms
	./test_quic_arms

test-hello: test_hello
	./test_hello

test-catalog: test_catalog
	./test_catalog

test-match: test_match
	./test_match

test-compose: test_compose
	./test_compose

check: all test-meas test-verdict test-crypto test-quic test-quicprobe test-quic-arms test-hello test-catalog test-match test-compose

# Тот же набор под санитайзерами. «Не упало» и «не читало за буфером» — разные
# утверждения, а оракул держит в руках чужой сокет и чужой ответ на нём.
SANFLAGS = -std=c99 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
           -fno-omit-frame-pointer -Wall -Wextra -Werror -Iinclude
san: hello_profiles.inc
	@set -e; for t in $(TESTS); do \
		echo "== $$t =="; \
		$(CC) $(SANFLAGS) -o /tmp/d2k-core-san-$$t $$t.c \
			$$(echo "$(SRC)" | tr ' ' '\n' | grep -v '^$$') -lpthread ; \
		/tmp/d2k-core-san-$$t; \
	done
	@echo "санитайзеры: все проверки прошли"

# Тот же набор ЧУЖИМ компилятором. Локально собирает clang, CI — gcc, и они
# расходятся в предупреждениях (см. датапат). Компиляция без запуска: тут
# важны предупреждения, а исполняются те же тесты обычной целью check.
GCC ?= mipsel-unknown-linux-gnu-gcc
gcc-warn: hello_profiles.inc
	@for f in $(SRC) $(TESTS:=.c); do \
		$(GCC) $(CFLAGS) -c -o /tmp/d2k-core-gccwarn.o $$f || exit 1; \
	done
	@echo "чужой компилятор: предупреждений нет"

# Переносимость проверяется компиляцией под целевые арки. Обе цели — Linux, и
# только там определён SO_MARK: без этой цели ветка с меткой не компилируется
# нигде на машине разработки. test_meas линкуется ЦЕЛИКОМ под обеими libc по
# той же причине, что d2kd в датапате: раздельная компиляция объектников не
# доказывает, что именно эта комбинация (включая pthread на musl и glibc)
# слинкуется.
cross: hello_profiles.inc
	@for f in $(SRC); do \
		echo "== $$f =="; \
		$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -c -o /tmp/d2k-core-a64.o $$f || exit 1; \
		$(MIPSEL_CC) $(CFLAGS) -c -o /tmp/d2k-core-mipsel.o $$f || exit 1; \
	done
	@echo "== test_meas целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_meas-a64 \
		test_meas.c meas.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_meas-mipsel test_meas.c meas.c -lpthread || exit 1
	@echo "== test_verdict целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_verdict-a64 \
		test_verdict.c meas.c verdict.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_verdict-mipsel \
		test_verdict.c meas.c verdict.c -lpthread || exit 1
	@echo "== test_crypto целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_crypto-a64 \
		test_crypto.c crypto.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_crypto-mipsel \
		test_crypto.c crypto.c -lpthread || exit 1
	@echo "== test_quic целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quic-a64 \
		test_quic.c quic.c crypto.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quic-mipsel \
		test_quic.c quic.c crypto.c -lpthread || exit 1
	@echo "== test_quicprobe целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quicprobe-a64 \
		test_quicprobe.c quicprobe.c quic.c crypto.c meas.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quicprobe-mipsel \
		test_quicprobe.c quicprobe.c quic.c crypto.c meas.c -lpthread || exit 1
	@echo "== test_quic_arms целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quic_arms-a64 \
		test_quic_arms.c props.c quicprobe.c quic.c crypto.c meas.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quic_arms-mipsel \
		test_quic_arms.c props.c quicprobe.c quic.c crypto.c meas.c -lpthread || exit 1
	@echo "== test_hello целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_hello-a64 \
		test_hello.c hello.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_hello-mipsel \
		test_hello.c hello.c -lpthread || exit 1
	@echo "== test_catalog целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_catalog-a64 \
		test_catalog.c catalog.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_catalog-mipsel \
		test_catalog.c catalog.c -lpthread || exit 1
	@echo "== test_match целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_match-a64 \
		test_match.c match.c catalog.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_match-mipsel \
		test_match.c match.c catalog.c -lpthread || exit 1
	@echo "== test_compose целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_compose-a64 \
		test_compose.c compose.c hello.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_compose-mipsel \
		test_compose.c compose.c hello.c -lpthread || exit 1
	@echo "переносимость: aarch64 и mipsel собираются, тесты линкуются"

clean:
	rm -f *.o $(TESTS) hello_profiles.inc
