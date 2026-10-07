#!/bin/sh
# Wrong endian/ABI selection must fail before downloading or stopping services.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
check() {
    got=$(sh "$ROOT/scripts/architecture.sh" "$1" "$2")
    [ "$got" = "$3" ] || { echo "$1 / $2: expected $3, got $got" >&2; exit 1; }
}
check aarch64 '' arm64
check armv7l armv7-3.2 arm
check mips mipsel-3.4 mipsel
check mips mips-3.4 mips
check mips64 mipsel-3.4 mipsel
check mips64 mips64el-3.4 mips64el
check mips64el '' mips64el
check x86_64 '' amd64
check x86_64 x64-3.2 amd64
check aarch64 aarch64-3.10_kn arm64
check armv7l armv7-3.2_kn arm
check mips mipsel-3.4_kn mipsel
check x86_64 i686 x86
check i686 '' x86
check ppc64 '' ppc64
check riscv64 '' riscv64
# OpenWrt без Entware: имя архитектуры даёт системный apk/opkg (07.10.2026).
check aarch64 aarch64_generic arm64
check aarch64 aarch64_cortex-a53 arm64
check armv7l arm_cortex-a7_neon-vfpv4 arm
check armv7l arm_cortex-a9_vfpv3-d16 arm
check mips mipsel_24kc mipsel
check mips mips_24kc mips
check mips64 mips64el_mips64r2 mips64el
check x86_64 x86_64 amd64
check i686 i386_pentium4 x86
check riscv64 riscv64_riscv64 riscv64
for arch in armv5tel armv6l armv7b i386 i486 i586 lexra ppc ppc64le mips mips64 sparc unknown; do
    if sh "$ROOT/scripts/architecture.sh" "$arch" '' >/dev/null 2>&1; then
        echo "unsupported $arch accepted" >&2; exit 1
    fi
done
# OpenWrt ARMv5/ARMv6, i586 и 32-битный PPC: сборок нет.
for arch in arm_arm926ej-s arm_arm1176jzf-s_vfp arm_fa526 arm_xscale arm_mpcore i386_pentium-mmx powerpc_464fp mips64_octeonplus; do
    if sh "$ROOT/scripts/architecture.sh" armv7l "$arch" >/dev/null 2>&1; then
        echo "unsupported OpenWrt $arch accepted" >&2; exit 1
    fi
done
if sh "$ROOT/scripts/architecture.sh" mips strange-feed >/dev/null 2>&1; then
    echo 'unknown Entware ABI silently ignored' >&2; exit 1
fi
echo 'architecture selection: PASS'
if printf 'cpu model : MIPS 64Kc V1.0\n' | sh "$ROOT/scripts/check-cpu.sh" mips64el /dev/stdin; then
    echo 'MIPS64 without FPU accepted' >&2; exit 1
fi
printf 'cpu model : MIPS 64Kf V1.0 FPU V1.0\n' | sh "$ROOT/scripts/check-cpu.sh" mips64el /dev/stdin
sh "$ROOT/scripts/check-cpu.sh" mipsel /does-not-exist
if printf 'Features : swp half thumb vfp\n' | sh "$ROOT/scripts/check-cpu.sh" arm /dev/stdin; then
    echo 'ARM without required VFPv3 accepted' >&2; exit 1
fi
printf 'Features : half thumb vfpv3 tls\n' | sh "$ROOT/scripts/check-cpu.sh" arm /dev/stdin
printf 'Features : fp asimd aes\n' | sh "$ROOT/scripts/check-cpu.sh" arm /dev/stdin
echo 'CPU capability gate: PASS'
