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

SRC     = meas.c verdict.c crypto.c quic.c quicprobe.c
HDR     = include/d2k_meas.h include/d2k_verdict.h include/d2k_crypto.h include/d2k_quic.h \
          include/d2k_quicprobe.h
# Общий стенд тестов (петля-мишень в потоке, режимы 0-4). Один на test_meas и
# test_verdict — второй, отдельный стенд не заводится нигде (см. его шапку).
# test_crypto и test_quic стенда не используют вовсе: криптография и разбор
# QUIC не трогают сеть, вход — байтовые вектора RFC, а не петля-мишень.
# test_quicprobe заводит СВОЙ стенд (датаграммный, не потоковый — см. его
# шапку) и в TESTHDR не входит: он не общий ни с кем.
TESTHDR = test_stand.h

TESTS   = test_meas test_verdict test_crypto test_quic test_quicprobe

.PHONY: all check san gcc-warn cross clean test-meas test-verdict test-crypto test-quic test-quicprobe

all: meas.o verdict.o crypto.o quic.o quicprobe.o

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

check: all test-meas test-verdict test-crypto test-quic test-quicprobe

# Тот же набор под санитайзерами. «Не упало» и «не читало за буфером» — разные
# утверждения, а оракул держит в руках чужой сокет и чужой ответ на нём.
SANFLAGS = -std=c99 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
           -fno-omit-frame-pointer -Wall -Wextra -Werror -Iinclude
san:
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
gcc-warn:
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
cross:
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
	@echo "переносимость: aarch64 и mipsel собираются, тесты линкуются"

clean:
	rm -f *.o $(TESTS)
