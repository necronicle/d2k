# Датапат d2k. Здесь живёт то, что видит чужие пакеты, и только оно.
#
# -Werror не роскошь: непереносимость обязана ловиться в тот день, когда её
# внесли, а не на роутере. Замер этапа 0 показал, что C даёт ошибки работы с
# памятью там, где Go не даёт, и единственная защита — жёсткие ключи и тесты.

CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -Iinclude
LDFLAGS ?=

# Кросс-компиляторы для проверки переносимости. Пути переопределяются извне.
ZIG        ?= /opt/homebrew/bin/zig
MIPSEL_CC  ?= mipsel-unknown-linux-gnu-gcc

SRC     = plan_parse.c plan_apply.c tls.c wire.c track.c session.c
HDR     = include/d2k_plan.h include/d2k_tls.h include/d2k_wire.h include/d2k_track.h include/d2k_session.h plan_internal.h

.PHONY: all check test-parse test-apply test-tls test-wire test-track test-session cross clean

all: planlab

plan_parse.o: plan_parse.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

plan_apply.o: plan_apply.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_plan_parse: test_plan_parse.c plan_parse.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_plan_parse.c plan_parse.o $(LDFLAGS)

tls.o: tls.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_tls: test_tls.c tls.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_tls.c tls.o $(LDFLAGS)

session.o: session.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_session: test_session.c session.o track.o tls.o wire.o plan_parse.o plan_apply.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_session.c session.o track.o tls.o wire.o plan_parse.o plan_apply.o $(LDFLAGS)

track.o: track.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_track: test_track.c track.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_track.c track.o $(LDFLAGS)

wire.o: wire.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_wire: test_wire.c wire.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_wire.c wire.o $(LDFLAGS)

test_plan_apply: test_plan_apply.c plan_parse.o plan_apply.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_plan_apply.c plan_parse.o plan_apply.o $(LDFLAGS)

planlab: planlab.c plan_parse.o plan_apply.o $(HDR)
	$(CC) $(CFLAGS) -o $@ planlab.c plan_parse.o plan_apply.o $(LDFLAGS)

test-parse: test_plan_parse
	./test_plan_parse

test-apply: test_plan_apply
	./test_plan_apply

test-tls: test_tls
	./test_tls

test-wire: test_wire
	./test_wire

test-track: test_track
	./test_track

test-session: test_session
	./test_session

# Переносимость проверяется компиляцией под целевые арки. Запускать там нечего
# и не нужно: ловим порядок байт, выравнивание и ширину типов.
cross:
	@for f in $(SRC); do \
		echo "== $$f =="; \
		$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -c -o /tmp/d2k-a64.o $$f || exit 1; \
		$(MIPSEL_CC) $(CFLAGS) -c -o /tmp/d2k-mipsel.o $$f || exit 1; \
	done
	@echo "переносимость: aarch64 и mipsel собираются"

# planlab тоже в зависимостях, и это не украшение: он собирается отдельной
# целью, поэтому однажды check остался зелёным при несобирающейся
# лаборатории. Проверка, не собирающая всё, что есть, проверяет не дерево.
check: all test-parse test-apply test-tls test-wire test-track test-session

clean:
	rm -f *.o test_plan_parse test_plan_apply test_tls test_wire test_track test_session planlab
