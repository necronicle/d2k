#!/bin/sh
set -eu

# OpenSSL source is fetched at an immutable upstream commit, then built into a
# static musl archive for the selected router architecture.
OPENSSL_COMMIT=f4dc4d58b48d346a8270183f89acf826d459b0ca
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/build-target.sh"
ZIG=$BUILD_ZIG
JOBS=${JOBS:-4}
SRC_DIR=${OPENSSL_SRC_DIR:-"$ROOT/build/telegram/openssl-src"}
PREFIX=${OPENSSL_PREFIX:-"$ROOT/build/telegram/openssl-$ARCH"}
OBJ_DIR=${OPENSSL_OBJ_DIR:-"$ROOT/build/telegram/obj-$ARCH"}
OUT=${OUT:-"$ROOT/builds"}

command -v "$ZIG" >/dev/null 2>&1 || { echo "zig not found: $ZIG" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required to fetch pinned OpenSSL" >&2; exit 1; }
mkdir -p "$(dirname -- "$SRC_DIR")" "$PREFIX"
mkdir -p "$ROOT/build/telegram" "$OBJ_DIR" "$OUT"

if [ ! -d "$SRC_DIR/.git" ]; then
    git init "$SRC_DIR"
    git -C "$SRC_DIR" remote add origin https://github.com/openssl/openssl.git
fi
actual=$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || true)
if [ "$actual" != "$OPENSSL_COMMIT" ]; then
    git -C "$SRC_DIR" fetch --depth 1 origin "$OPENSSL_COMMIT"
    git -C "$SRC_DIR" checkout --detach "$OPENSSL_COMMIT"
fi
[ "$(git -C "$SRC_DIR" rev-parse HEAD)" = "$OPENSSL_COMMIT" ] || {
    echo "OpenSSL source revision mismatch" >&2
    exit 1
}

cd "$OBJ_DIR"
# Размер d2ktg имеет значение: статический OpenSSL делает его тяжелее всех
# остальных бинарников вместе, а у mips-роутера всего 8 или 16 МиБ флеша.
# -ffunction-sections/-fdata-sections у самого OpenSSL плюс --gc-sections на
# линковке ниже выбрасывают только то, на что никто не ссылается: ни один
# алгоритм не выключен, провайдерские таблицы держат свои функции сами.
# Замер 12.10.2026, big-endian mips: 5 953 012 -> 5 187 940 байт (-12,9 %).
#
# Что НЕ взято и почему (замерено тем же деревом и тем же способом):
#   * -fno-asynchronous-unwind-tables -fno-unwind-tables -> 4 779 780 (-19,7 %);
#   * плюс 33 опции no-* (deprecated, dsa, cms, ct, ocsp, ...) -> 4 064 552
#     (-31,7 %). Обе снимают настоящие возможности, а не мёртвый код, и просят
#     проверки живого рукопожатия, а не только линковки.
#   * плюс снятие нераспределяемой секции .pdr (465 КиБ, на роутере её не
#     читает никто) -> 3 659 800 (-38,5 %). Нужен llvm-objcopy: `zig objcopy`
#     на обратном порядке байт отказывается ("ELF to ELF copying only supports
#     native endian"), а objcopy из binutils выпускающей машины MIPS-целей не
#     знает. Своего инструмента в выпускной цепочке пока нет.
# Проверять изменения размера — scripts/check-router-builds.sh под QEMU
# (openssl-link-smoke достаёт ED25519 из провайдера по умолчанию, то есть ровно
# тот путь, который сборкой секций и можно было бы сломать).
# 15.10.2026 (задача 53): mips-роутерам с 8/16 МиБ флеша d2ktg в 5,1 МБ —
# больше половины комплекта. Сняты возможности, которых d2ktg не вызывает
# (telegram/src: TLS-клиент от 1.2 с проверкой сертификата по имени/IP,
# ED25519, SHA-1, SHA-256, HMAC, RAND) и которых рукопожатие с нашим реле не
# касается. RSA и EC оставлены: на них подписаны цепочки Let's Encrypt.
# Таблицы раскрутки не нужны: d2ktg — C без исключений, musl отменяет потоки
# сигналами, а не раскруткой. Проверка — живое рукопожатие с реле (регистрация
# и подключение d2ktg на роутере) и scripts/check-router-builds.sh под QEMU.
SIZE_CFLAGS='-ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-unwind-tables'
UNUSED_FEATURES='no-dsa no-cms no-ct no-ocsp no-srp no-comp no-engine no-dynamic-engine
    no-dtls no-ssl3 no-idea no-rc2 no-rc4 no-rc5 no-des no-bf no-cast no-camellia no-aria
    no-seed no-sm2 no-sm3 no-sm4 no-gost no-md4 no-mdc2 no-whirlpool no-ts no-rfc3779
    no-cmp no-quic no-nextprotoneg no-srtp no-sctp no-ocb no-siphash no-scrypt'

ASM_FLAGS=no-asm
case "$ARCH" in arm64|amd64) ASM_FLAGS= ;; esac
ATOMIC_FLAGS=
# 32-bit targets may not provide lock-free, unaligned 64-bit atomics. Use OpenSSL's existing
# pthread-lock fallback rather than requiring a router-side libatomic.
case "$ARCH" in mips|mipsel|x86) ATOMIC_FLAGS=-DBROKEN_CLANG_ATOMICS ;; esac
# shellcheck disable=SC2086
CC="$ZIG cc -target $TARGET $TARGET_FLAGS $SIZE_CFLAGS" \
AR="$ZIG ar" RANLIB="$ZIG ranlib" \
    "$SRC_DIR/Configure" "$SSL_TARGET" no-shared no-tests no-apps no-docs no-legacy $UNUSED_FEATURES $ASM_FLAGS $ATOMIC_FLAGS \
    --prefix="$PREFIX" --openssldir=/opt/d2k/certs
make -j "$JOBS" build_libs
make install_sw
[ "${LIBS_ONLY:-0}" != 1 ] || exit 0

SMOKE="$ROOT/telegram/test_openssl_link.c"
LIBDIR="$PREFIX/lib"
[ -d "$LIBDIR" ] || LIBDIR="$PREFIX/lib64"
# TARGET_FLAGS is a controlled compiler option from build-target.sh.
# shellcheck disable=SC2086
"$ZIG" cc -target "$TARGET" $TARGET_FLAGS -static $SIZE_CFLAGS -Wl,--gc-sections \
    -I"$PREFIX/include" -L"$LIBDIR" \
    -o "$ROOT/build/telegram/openssl-link-smoke-$ARCH" "$SMOKE" \
    -lssl -lcrypto -ldl -pthread
file "$ROOT/build/telegram/openssl-link-smoke-$ARCH"

# The router runtime is a single static C executable. Keep all implementation
# sources in the compile command so the package cannot accidentally omit a
# newly added module.
# shellcheck disable=SC2086
"$ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -std=c11 \
    -Wall -Wextra -Werror -pedantic -Wl,-S $SIZE_CFLAGS -Wl,--gc-sections \
    -DD2K_RELEASE_ID="\"${RELEASE_ID:-dev}\"" \
    -I"$ROOT/telegram/include" -I"$PREFIX/include" \
    -o "$OUT/d2ktg-linux-$ARCH" "$ROOT"/telegram/src/*.c \
    -L"$LIBDIR" -lssl -lcrypto -ldl -pthread
file "$OUT/d2ktg-linux-$ARCH"
