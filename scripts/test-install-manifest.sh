#!/bin/sh
# shellcheck disable=SC2013  # word lists (names, faces), not lines
# Static check that the install chain carries every file the service needs:
#   1. every $DIR/... file and /opt/sbin/d2k* binary named by files/S99d2k or
#      a runtime helper in files/ is installed by scripts/install.sh;
#   2. every repository path install.sh fetches is staged by
#      scripts/lab-install.sh (whose D2K_LOCAL install dies on the first
#      missing file, before it installs anything);
#   3. every helper install.sh puts in $DIR is removed by scripts/uninstall.sh.
# Runtime directories and state written by the service itself are excluded.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
INSTALL=$ROOT/scripts/install.sh
LAB=$ROOT/scripts/lab-install.sh
UNINSTALL=$ROOT/scripts/uninstall.sh
fail() { echo "FAIL: $*" >&2; exit 1; }

# shellcheck disable=SC2016  # literal $DIR as written in the scripts
refs=$(grep -oh '\$DIR/[A-Za-z0-9._/-]*' "$ROOT/files/S99d2k" "$ROOT"/files/*.sh | sort -u |
    grep -vE '^\$DIR/((config|log|run|state|panel|\.update)(/|$)|files$)')
[ -n "$refs" ] || fail "no runtime file references found (layout changed?)"
for ref in $refs; do
    name=${ref#\$DIR/}
    grep -qF "\"\$DIR/$name\"" "$INSTALL" || fail "install.sh does not install $ref (named by the runtime)"
done
for bin in $(grep -oh '/opt/sbin/d2k[a-z]*' "$ROOT/files/S99d2k" "$ROOT"/files/*.sh | sort -u); do
    name=${bin#/opt/sbin/}
    grep -qF "\"\$SBIN/$name\"" "$INSTALL" || fail "install.sh does not install $bin"
done
echo "PASS: install.sh installs every file and binary the service references"

fetched=$(sed -n 's/^fetch "\([^"]*\)".*/\1/p' "$INSTALL")
[ -n "$fetched" ] || fail "no fetch lines in install.sh (layout changed?)"
for path in $fetched; do
    case "$path" in
        builds/*-linux-\$ARCH)
            bin=${path#builds/}; bin=${bin%-linux-\$ARCH}
            grep -qF "\$REL/builds/$bin-linux-\$ARCH" "$LAB" || fail "lab-install.sh does not stage $path" ;;
        *) grep -qF "$path" "$LAB" || fail "lab-install.sh does not stage $path" ;;
    esac
done
# Fonts are fetched in a loop over faces.
for face in $(sed -n 's/^for face in \(.*\); do$/\1/p' "$INSTALL"); do
    grep -qF "fonts/$face.woff2" "$LAB" || fail "lab-install.sh does not stage font $face"
done
grep -q 'install.sh fetch' "$LAB" || fail "lab-install.sh lacks its own staged-file preflight"
echo "PASS: lab-install.sh stages every file install.sh fetches"

# 4. The /tmp preflight must not promise less than install.sh actually downloads.
#    Routers with 8/16 MiB of flash have a small tmpfs, and a number that
#    silently fell behind the binaries would let the download start and then
#    break in the middle — which is exactly what the preflight exists to
#    prevent. Both numbers are measured on the real per-architecture set,
#    which a checkout does not carry: it is in a developer's builds/ or, for
#    the release of record, in the artifacts of the build matrix (release.yml
#    runs this script with D2K_BUILDS before it packages anything). Without a
#    complete set the measurement says so rather than passing quietly.
BUILDS=${D2K_BUILDS:-$ROOT/builds}
need_kb=$(sed -n 's/^TMP_NEED_KB=\([0-9]\{1,\}\)$/\1/p' "$INSTALL")
[ -n "$need_kb" ] || fail "install.sh has no TMP_NEED_KB download preflight"
release_need_kb=$(sed -n 's/^TMP_RELEASE_NEED_KB=\([0-9]\{1,\}\)$/\1/p' "$INSTALL")
[ -n "$release_need_kb" ] || fail "install.sh has no TMP_RELEASE_NEED_KB download preflight"
common_bytes=0
arch_bins=
for path in $fetched; do
    case "$path" in
        builds/*-linux-\$ARCH) bin=${path#builds/}; arch_bins="$arch_bins ${bin%-linux-\$ARCH}" ;;
        *)
            [ -f "$ROOT/$path" ] || fail "install.sh fetches $path, which is not in the tree"
            common_bytes=$((common_bytes + $(wc -c < "$ROOT/$path"))) ;;
    esac
done
# head -n 1: install.sh loops over the same faces twice (download, then install),
# and counting the fonts twice would quietly inflate the measurement.
for face in $(sed -n 's/^for face in \(.*\); do$/\1/p' "$INSTALL" | head -n 1); do
    for path in "internal/web/assets/fonts/$face.woff2" "internal/web/assets/fonts/OFL-$face.txt"; do
        [ -f "$ROOT/$path" ] || fail "install.sh fetches $path, which is not in the tree"
        common_bytes=$((common_bytes + $(wc -c < "$ROOT/$path")))
    done
done
[ -n "$arch_bins" ] || fail "install.sh fetches no per-architecture binary (layout changed?)"
worst_kb=0
worst_arch=
for probe in "$BUILDS"/d2kc-linux-*; do
    arch=${probe##*/d2kc-linux-}
    bytes=$common_bytes
    for bin in $arch_bins; do
        file=$BUILDS/$bin-linux-$arch
        [ -f "$file" ] || { bytes=0; break; }
        bytes=$((bytes + $(wc -c < "$file")))
    done
    [ "$bytes" -gt 0 ] || continue
    kb=$(((bytes + 1023) / 1024))
    [ "$kb" -le "$worst_kb" ] || { worst_kb=$kb; worst_arch=$arch; }
done
if [ "$worst_kb" -eq 0 ]; then
    echo "SKIP: $BUILDS has no complete per-architecture set — the release measures both"
    echo "      preflights on the binaries it is about to publish (D2K_BUILDS)"
else
    [ "$need_kb" -ge "$worst_kb" ] ||
        fail "install.sh TMP_NEED_KB=$need_kb is below the largest download ($worst_arch: $worst_kb KiB)"
    echo "PASS: /tmp preflight ($need_kb KiB) covers the largest download ($worst_arch: $worst_kb KiB)"

    # 5. The same question for the install the user actually gets: the signed
    #    release. It holds more in /tmp than a file-by-file download — the
    #    unpacked tree, and on top of it the set the archive's own installer
    #    stages — so one number could not answer for both. Measured on the
    #    real archive, built by the same script the release workflow runs.
    stage=$(mktemp -d "${TMPDIR:-/tmp}/d2k-manifest.XXXXXX") || fail "no temporary directory"
    trap 'rm -rf "$stage"' EXIT HUP INT TERM
    RELEASE_ID=d2k-manifest-test ARCHES=$worst_arch \
        sh "$ROOT/scripts/package-release.sh" "$BUILDS" "$stage/out" >/dev/null ||
        fail "package-release.sh cannot package $worst_arch"
    mkdir "$stage/tree" || fail "no room to unpack"
    tar -xzf "$stage/out/d2k-$worst_arch.tar.gz" -C "$stage/tree" || fail "release archive does not unpack"
    for notice in LICENSE LICENSE-BINARY.md THIRD_PARTY_NOTICES.md licenses/Apache-2.0.txt; do
        cmp -s "$ROOT/$notice" "$stage/tree/$notice" || fail "release archive is missing or changes $notice"
    done
    tree_kb=$(du -sk "$stage/tree" | awk '{ print $1 }')
    gz_kb=$(du -k "$stage/out/d2k-$worst_arch.tar.gz" | awk '{ print $1 }')
    # Два пика: архив рядом с распакованным деревом, затем дерево рядом с
    # раскладкой (установщик удаляет архив до того, как начнёт раскладывать).
    peak_kb=$((tree_kb + need_kb))
    [ "$peak_kb" -ge $((gz_kb + tree_kb)) ] || peak_kb=$((gz_kb + tree_kb))
    [ "$release_need_kb" -ge "$peak_kb" ] ||
        fail "install.sh TMP_RELEASE_NEED_KB=$release_need_kb is below the release install ($worst_arch: archive $gz_kb KiB, tree $tree_kb KiB, staged $need_kb KiB, peak $peak_kb KiB)"
    echo "PASS: release preflight ($release_need_kb KiB) covers the release install ($worst_arch: peak $peak_kb KiB)"
    rm -rf "$stage"
    trap - EXIT HUP INT TERM
fi

# shellcheck disable=SC2016
for name in $(sed -n 's/^install_atomic "\$TMP\/[^"]*" "\$DIR\/\([^"]*\.sh\)"$/\1/p' "$INSTALL"); do
    grep -qF "\$DIR/$name" "$UNINSTALL" || fail "uninstall.sh does not remove \$DIR/$name"
done
echo "PASS: uninstall.sh removes every installed helper"
echo "install manifest: all checks passed"
