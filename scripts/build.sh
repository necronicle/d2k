#!/bin/sh
# Сборка d2k. Единственный источник правды о том, чем и подо что собирается
# обвязка на Go.
#
# Арки и их флаги унаследованы из build-matrix.tsv репозитория z2k, а не
# выбраны заново: они подобраны на живых коробках, и расхождение здесь стоило
# бы того же, чего стоило там — бинарника, который никто ни разу не проверил.
# GOMIPS=softfloat обязателен: на MIPS-роутерах нет сопроцессора.
#
# Датапат на C здесь пока не собирается — его ещё нет. Когда появится, ему
# нужен будет тулчейн Entware/OpenWrt с musl или uclibc: проверено 05-09, что
# у обычного кросс-gcc нет soft-float-варианта glibc и -msoft-float падает.
set -eu

GO=${GO:-go}
OUT=${OUT:-builds}
PKG=./cmd/d2k
LDPKG=github.com/necronicle/d2k/internal/buildinfo

# ARCHES: «GOARCH<таб>доп_переменные». Прочерк — без дополнительных.
ARCHES=${ARCHES:-"
arm64	-
arm	GOARM=5
amd64	-
mips	GOMIPS=softfloat
mipsle	GOMIPS=softfloat
mips64le	GOMIPS64=softfloat
ppc64	-
riscv64	-
386	-
"}

version=${VERSION:-}
if [ -z "$version" ]; then
    version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
fi
commit=$(git rev-parse HEAD 2>/dev/null || echo "")
date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
dirty=0
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    dirty=1
fi

ldflags="-s -w"
ldflags="$ldflags -X $LDPKG.Version=$version"
ldflags="$ldflags -X $LDPKG.Commit=$commit"
ldflags="$ldflags -X $LDPKG.Date=$date"
ldflags="$ldflags -X $LDPKG.Dirty=$dirty"

mkdir -p "$OUT"
echo "версия $version, коммит ${commit:-нет}, правки в дереве: $dirty"

printf '%s\n' "$ARCHES" | while IFS="$(printf '\t')" read -r arch extra; do
    [ -n "$arch" ] || continue
    out="$OUT/d2k-linux-$arch"
    if [ "$extra" = "-" ]; then
        env CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            "$GO" build -trimpath -ldflags "$ldflags" -o "$out" "$PKG"
    else
        # shellcheck disable=SC2086
        env CGO_ENABLED=0 GOOS=linux GOARCH="$arch" $extra \
            "$GO" build -trimpath -ldflags "$ldflags" -o "$out" "$PKG"
    fi
    printf '  %-22s %8s байт\n' "$(basename "$out")" "$(wc -c < "$out" | tr -d ' ')"
done

echo "готово: $OUT"
