#!/bin/sh
# Упаковка выпуска для d2k-update.sh: на каждую арку архив d2k-<арка>.tar.gz с
# тем, что берёт установщик (scripts/install.sh, D2K_LOCAL), и latest.json с
# хешами архивов. Подпись latest.json делает release.yml ключом из секрета.
#
#   RELEASE_ID=d2k-… [NOTES=…] [VERSION=…] sh scripts/package-release.sh BUILDS OUT
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
BUILDS=${1:?каталог сборок}
OUT=${2:?каталог выпуска}
: "${RELEASE_ID:?RELEASE_ID}"
case "$RELEASE_ID" in [A-Za-z0-9]*) ;; *) echo "плохой RELEASE_ID" >&2; exit 1 ;; esac
case "$RELEASE_ID" in *[!A-Za-z0-9._-]*) echo "плохой RELEASE_ID" >&2; exit 1 ;; esac
ARCHES=${ARCHES:-"arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64"}
VERSION=${VERSION:-$RELEASE_ID}
NOTES=${NOTES:-}
mkdir -p "$OUT"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

json() { printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read(), ensure_ascii=False))'; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

assets=
for arch in $ARCHES; do
    tree="$STAGE/$arch"
    mkdir -p "$tree/builds" "$tree/scripts"
    for bin in d2kd d2kc d2kshadow d2kfetch d2kpanel d2ktg; do
        test -s "$BUILDS/$bin-linux-$arch" || { echo "нет $BUILDS/$bin-linux-$arch" >&2; exit 1; }
        cp "$BUILDS/$bin-linux-$arch" "$tree/builds/"
    done
    cp "$ROOT/scripts/install.sh" "$ROOT/scripts/architecture.sh" "$ROOT/scripts/check-cpu.sh" \
       "$ROOT/scripts/select-panel-ip.sh" "$tree/scripts/"
    cp -R "$ROOT/files" "$tree/files"
    mkdir -p "$tree/core/profiles"
    cp "$ROOT/core/profiles/modern.hex" "$ROOT/core/profiles/legacy.hex" "$tree/core/profiles/"
    mkdir -p "$tree/internal/web"
    cp -R "$ROOT/internal/web/assets" "$tree/internal/web/assets"
    cp "$ROOT/LICENSE" "$ROOT/LICENSE-BINARY.md" "$ROOT/THIRD_PARTY_NOTICES.md" "$tree/"
    mkdir -p "$tree/licenses"
    cp "$ROOT/licenses/Apache-2.0.txt" "$tree/licenses/"
    tar -czf "$OUT/d2k-$arch.tar.gz" -C "$tree" builds scripts files internal core \
        LICENSE LICENSE-BINARY.md THIRD_PARTY_NOTICES.md licenses
    sum=$(sha "$OUT/d2k-$arch.tar.gz")
    assets="$assets${assets:+,}\"$arch\":{\"sha256\":\"$sum\"}"
done
# Одна строка: d2k-update.sh читает поля sed'ом и встраивает объект в своё состояние.
printf '{"release_id":"%s","version":%s,"notes":%s,"assets":{%s}}\n' \
    "$RELEASE_ID" "$(json "$VERSION")" "$(json "$NOTES")" "$assets" > "$OUT/latest.json"
echo "выпуск $RELEASE_ID: $(echo "$ARCHES" | wc -w | tr -d ' ') арок, $OUT/latest.json"
