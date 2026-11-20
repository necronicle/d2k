# Модель D2K: общие понятия ТЗ (D2K_SPEC.md §2, §4, §5.2, §6.1, §14).
# Чистый C99 без сети; журнал «почему» — обычный POSIX-файл. Проверяется на любой машине.

CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -Wshadow -Wconversion -Iinclude
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g

SRC   = codes.c context.c experiment.c fact.c owner.c why.c check.c box.c question.c tls.c program.c synth.c task.c store.c sim.c
HDR   = $(wildcard include/*.h) test.h
TESTS = test_codes test_context test_experiment test_fact test_owner test_why test_check test_box test_question test_tls test_program test_synth test_task test_store test_degradation

all: libd2km.a

libd2km.a: $(SRC:.c=.o)
	$(AR) rcs $@ $^

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c $< -o $@

test_%: test_%.c $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(SANFLAGS) $< $(SRC) -o $@

test_store: test_store.c $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(SANFLAGS) $< $(filter-out store.c,$(SRC)) -o $@

check: $(TESTS)
	@set -e; for t in $(TESTS); do ./$$t; done

# Переносимость: 32-битная big-endian цель роутера (MIPS) без запуска.
ZIG ?= zig
cross:
	$(ZIG) cc -target mips-linux-musleabi -mcpu=mips32+soft_float $(CFLAGS) -c $(SRC)
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -c $(SRC)
	rm -f $(SRC:.c=.o)

# GCC строже clang к знаковости на 32-битной цели: ловит то, что cross не видит.
MIPSEL_CC ?= mipsel-unknown-linux-gnu-gcc
gcc-warn:
	$(MIPSEL_CC) $(CFLAGS) -c $(SRC)
	rm -f $(SRC:.c=.o)

clean:
	rm -f *.o libd2km.a $(TESTS)

.PHONY: all check cross gcc-warn clean
