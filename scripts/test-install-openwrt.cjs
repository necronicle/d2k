#!/usr/bin/env node
// Installer/uninstaller on OpenWrt without Entware (07.10.2026): stock 25.12
// has nft, apk, wget (uclient-fetch), BusyBox ip and start-stop-daemon, but no
// curl, openssl, iptables or ipset. PATH holds only those commands plus the
// ordinary utilities. No /opt, firewall or package manager is touched.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const engineFixture = require('./test-engine-fixture.cjs');
const root = path.resolve(__dirname, '..');
const tmp = fs.mkdtempSync('/tmp/install-openwrt-test.');
const sh = (body) => `#!/bin/sh\n${body}\n`;
function put(file, contents, mode = 0o755) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents, { mode });
}
try {
  // Ordinary utilities, minus everything a stock OpenWrt image lacks or that a
  // stub below provides.
  const sys = path.join(tmp, 'sys');
  fs.mkdirSync(sys);
  const hidden = new Set(['curl', 'wget', 'openssl', 'iptables', 'ip6tables', 'ipset', 'nft', 'apk', 'opkg',
    'ip', 'start-stop-daemon', 'modprobe', 'insmod', 'df', 'conntrack']);
  for (const dir of ['/bin', '/usr/bin', '/usr/sbin', '/sbin']) {
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const name of names) {
      const target = path.join(sys, name);
      // existsSync follows the link: a name whose first copy is a dangling symlink
      // (new runner image, 22.10.2026: grub-ntldr-img) read as absent and the second
      // directory tried to link it again — EEXIST. The link itself decides.
      if (hidden.has(name)) continue;
      try { fs.symlinkSync(path.join(dir, name), target); }
      catch (e) { if (e.code !== "EEXIST") throw e; }
    }
  }
  const bin = path.join(tmp, 'owrt');
  const log = (name) => path.join(tmp, `${name}.log`);
  put(path.join(bin, 'ip'), sh('exit 0'));
  put(path.join(bin, 'start-stop-daemon'), sh('printf "%s\\n" "$*" >> "$CALLS"'));
  put(path.join(bin, 'nft'), sh(`printf '%s\\n' "$*" >> '${log('nft')}'
case "$1" in
  -c) exit "\${NFT_CHECK_RC:-0}" ;;
  list) [ "\${NFT_TABLES:-0}" = 1 ] || exit 1; exit 0 ;;
esac
exit 0`));
  // apk: installed set in APK_HAVE; add "installs" curl/openssl by dropping stubs.
  put(path.join(bin, 'apk'), sh(`printf '%s\\n' "$*" >> '${log('apk')}'
case "$1" in
  --print-arch) printf '%s\\n' "\${APK_ARCH-x86_64}" ;;
  info) shift; [ "$1" = -e ] && shift
        case " \${APK_HAVE:-} " in *" $1 "*) exit 0 ;; esac; exit 1 ;;
  add) [ "\${APK_ADD_RC:-0}" = 0 ] || exit "$APK_ADD_RC"
       # Packages take room on the same filesystem as /opt.
       [ ! -f '${path.join(tmp, 'df_avail')}' ] || echo $(( $(cat '${path.join(tmp, 'df_avail')}') - 7000 )) > '${path.join(tmp, 'df_avail')}'
       shift
       for p in "$@"; do
         case "$p" in
           curl) cp '${path.join(tmp, 'curl-double')}' '${bin}/curl' ;;
           openssl-util) printf '#!/bin/sh\\nexit 0\\n' > '${bin}/openssl'; chmod +x '${bin}/openssl' ;;
         esac
       done ;;
esac
exit 0`));
  // opkg -f <конфиг>: попытка через проводник на VPS — в свой журнал;
  // GATE_DOWN=1 её роняет, как недоступный VPS.
  put(path.join(tmp, 'opkg'), sh(`if [ "$1" = -f ]; then
  printf '%s %s\\n' "\${http_proxy:-}" "$3" >> '${log('opkg-gate')}'
  cp "$2" '${log('opkg-gate-conf')}'
  [ -z "\${GATE_DOWN:-}" ] || exit 1
  shift 2
fi
printf '%s\\n' "$*" >> '${log('opkg')}'
case "$1" in
  list-installed) for p in \${APK_HAVE:-}; do echo "$p - 1"; done ;;
  install) shift
       for p in "$@"; do
         case "$p" in
           curl) cp '${path.join(tmp, 'curl-double')}' '${bin}/curl' ;;
           openssl-util) printf '#!/bin/sh\\nexit 0\\n' > '${bin}/openssl'; chmod +x '${bin}/openssl' ;;
         esac
       done ;;
esac
exit 0`));
  // wget = uclient-fetch: -O file URL; the URL maps onto the fixture tree.
  put(path.join(bin, 'wget'), sh(`out= url=
while [ $# -gt 0 ]; do case "$1" in -O) out=$2; shift 2 ;; -q) shift ;; -T) shift 2 ;; *) url=$1; shift ;; esac; done
printf '%s\\n' "$url" >> '${log('wget')}'
cp "$SRC/\${url#http://fixture.test/}" "$out"`));
  // The curl a package manager "installs": -o file URL, from the fixture tree.
  put(path.join(tmp, 'curl-double'), sh(`out= url=
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; --max-time|--connect-timeout) shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done
printf '%s\\n' "$url" >> '${log('curl')}'
cp "$SRC/\${url#http://fixture.test/}" "$out"`));
  // Two questions, two answers: the download preflight asks about the
  // installer's own temporary directory (tmpfs on a router), the runtime
  // preflight about /opt. One shared number could not tell them apart.
  put(path.join(bin, 'df'), sh(`echo 'Filesystem 1024-blocks Used Available Capacity Mounted on'
avail=\${DF_AVAIL:-80020}
[ ! -f '${path.join(tmp, 'df_avail')}' ] || avail=$(cat '${path.join(tmp, 'df_avail')}')
case "$*" in *runtime-install.*) avail=\${DF_AVAIL_TMP:-80020} ;; esac
echo "/dev/root 100692 18544 $avail 19% /"`));

  const src = path.join(tmp, 'source');
  const fixture = (name, contents, mode = 0o755) => put(path.join(src, name), contents, mode);
  // Logs what the installer derived, and refuses an unnamed ABI the way the
  // real script does: without $2 a bare uname picks no build on MIPS.
  fixture('scripts/architecture.sh',
    sh('printf "arch %s %s\\n" "$1" "$2" >> "$CALLS"; [ -n "$2" ] || exit 1; printf "amd64\\n"'));
  for (const name of ['check-cpu.sh', 'select-panel-ip.sh']) fixture(`scripts/${name}`, sh('exit 0'));
  fixture('builds/d2kpanel-linux-amd64', sh('echo features=telegram-control'));
  fixture('builds/d2ktg-linux-amd64', sh('echo features=per-install-enrollment,instagram-ip-probe,meta-hosts-v3'));
  fixture('builds/d2kd-linux-amd64', engineFixture('d2kd'));
  fixture('builds/d2kshadow-linux-amd64', sh('exit 2'));
  for (const profile of ['modern', 'legacy']) {
    const file = `core/profiles/${profile}.hex`;
    fixture(file, fs.readFileSync(path.join(root, file)));
  }
  fixture('builds/d2kc-linux-amd64', engineFixture('d2kc'));
  fixture('builds/d2kfetch-linux-amd64', sh('echo d2kfetch dev'));
  fixture('files/S99d2k', sh('printf "service-%s\\n" "$1" >> "$CALLS"\n[ "$1" != status ] || echo "датапат: работает"\nexit 0'));
  fixture('files/config', 'PANEL_LISTEN=192.168.1.1:8090\nTG_ENABLED=0\nTG_RELAY_URL=wss://example.test/ws\n');
  // Sourced by uninstall.sh: definitions only, no exit.
  fixture('files/d2k-ppe-deoffload.sh', sh('d2k_ppe_remove() { :; }'));
  for (const name of ['d2k-fw-heal.sh', '001-d2k.sh', 'd2k-tg-firewall.sh', 'd2k-tg-watchdog.sh',
    'd2k-instagram-dns-scheduler.sh', 'd2k-instagram-dns.sh', 'd2k-log-maintenance.sh', 'd2k-update.sh']) fixture(`files/${name}`, sh('exit 0'));
  fixture('files/d2k-openwrt-init', fs.readFileSync(path.join(root, 'files/d2k-openwrt-init'), 'utf8')
    .replaceAll('/etc/rc.common', path.join(tmp, 'etc/rc.common')));
  for (const name of ['meta-ranges.txt', 'tg-roots.pem', 'fake/stun.bin', 'fake/quic_initial_dbankcloud_ru.bin']) fixture(`files/${name}`, 'fixture\n');
  for (const name of ['index.html', 'favicon.svg', 'panel.css', 'panel.js', 'diagnostics.js', 'gsap.js', 'fonts/onest.woff2',
    'fonts/OFL-onest.txt', 'fonts/jbmono.woff2', 'fonts/OFL-jbmono.txt']) fixture(`internal/web/assets/${name}`, 'fixture\n');

  // A stock image: nfnetlink_queue present, no /proc/net/ip_tables_* at all.
  put(path.join(tmp, 'proc/net/netfilter/nfnetlink_queue'), '', 0o644);
  const release = path.join(tmp, 'etc/openwrt_release');
  put(release, "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='25.12.5'\nDISTRIB_ARCH='aarch64_generic'\n", 0o644);
  put(path.join(tmp, 'lib/functions/procd.sh'), '# fixture\n', 0o644);
  put(path.join(tmp, 'etc/rc.common'), sh('printf "host-%s\\n" "$2" >> "$CALLS"'));
  fs.mkdirSync(path.join(tmp, 'etc/init.d'), { recursive: true });
  const runtime = path.join(tmp, 'runtime');
  for (const name of ['install', 'uninstall']) {
    const script = fs.readFileSync(path.join(root, `scripts/${name}.sh`), 'utf8')
      .replaceAll('/opt', path.join(tmp, 'opt'))
      .replaceAll('/etc/openwrt_release', release)
      .replaceAll('/etc/rc.common', path.join(tmp, 'etc/rc.common'))
      .replaceAll('/etc/init.d/d2k', path.join(tmp, 'etc/init.d/d2k'))
      .replaceAll('/lib/functions/procd.sh', path.join(tmp, 'lib/functions/procd.sh'))
      .replaceAll('/proc/', `${path.join(tmp, 'proc')}/`)
      .replaceAll('/tmp/d2k', runtime);
    fs.writeFileSync(path.join(tmp, `${name}.sh`), script);
  }
  const calls = path.join(tmp, 'calls');
  const env = {
    // Файлы ветки, а не выпуск: здесь проверяется поведение установщика на
    // чистой 25.12, а не канал выпуска (его проверяет test-install-release.cjs).
    D2K_SOURCE: 'ref',
    PATH: `${bin}:${sys}`, HOME: tmp, CALLS: calls, SRC: src, D2K_BASE: 'http://fixture.test',
    D2K_OPENWRT_APK: path.join(bin, 'apk'), D2K_OPENWRT_OPKG: path.join(tmp, 'no-opkg'), D2K_KEEP_STATE: '1',
  };
  const read = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
  const reset = () => { for (const f of [calls, log('apk'), log('opkg'), log('nft'), log('wget'), log('curl'),
    log('opkg-gate'), log('opkg-gate-conf')]) fs.rmSync(f, { force: true }); };
  function run(name, extra = {}) {
    return spawnSync('/bin/sh', [path.join(tmp, `${name}.sh`)], { env: { ...env, ...extra }, encoding: 'utf8', timeout: 20000 });
  }
  const ok = (r) => { assert.equal(r.status, 0, r.stderr || r.stdout); return r.stdout + r.stderr; };
  const d2kd = path.join(tmp, 'opt/sbin/d2kd');

  // 1. Fresh 25.12: nothing installed, no curl — downloads through wget, then
  //    apk adds exactly the missing packages; no iptables anywhere.
  reset();
  const fresh = ok(run('install'));
  assert(read(log('wget')).includes('http://fixture.test/builds/d2kd-linux-amd64'), 'without curl the installer must download through wget');
  assert.match(read(log('apk')), /^add kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle curl openssl-util$/m,
    'apk must add the nft kmods, ca-bundle, curl and openssl-util');
  assert.match(read(log('nft')), /^-c -f .*preflight\.nft$/m, 'kernel support must be checked with nft -c before the switch');
  assert.match(read(calls), /^arch \S+ aarch64_generic$/m, 'architecture must come from DISTRIB_ARCH, not Entware');
  assert(fs.existsSync(d2kd), 'runtime must be installed');
  assert(fs.existsSync(path.join(tmp, 'opt/sbin/d2kfetch')), 'measurement tool must be installed');
  assert(read(calls).includes('service-start'), 'service must be started');
  assert(fs.existsSync(path.join(tmp, 'etc/init.d/d2k')) && read(calls).includes('host-enable'), 'boot bridge must be installed and enabled');
  assert.doesNotMatch(fresh, /Entware/, 'nothing may ask for Entware');
  assert.doesNotMatch(fresh, /ndm/, 'KeeneticOS NDM hook is not an OpenWrt concern');

  // 2. Upgrade with everything in place: no package changes.
  const have = 'kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle curl openssl-util';
  reset();
  ok(run('install', { APK_HAVE: have }));
  assert.doesNotMatch(read(log('apk')), /^add/m, 'installed packages must not be added again');
  assert.equal(read(log('wget')), '', 'with curl present the installer uses curl');

  // 2b. Firmware that names no DISTRIB_ARCH and has no opkg: the ABI comes
  //     from apk, and if apk is silent too, from a system binary's ELF header.
  //     Both were empty on parts of the OpenWrt 24+ field, and the installer
  //     died on "неподдерживаемая архитектура" without saying what it tried.
  const releaseText = read(release);
  put(release, "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='25.12.5'\n", 0o644);
  reset();
  ok(run('install', { APK_HAVE: have, APK_ARCH: 'mipsel_24kc' }));
  assert.match(read(calls), /^arch \S+ mipsel_24kc$/m,
    'without DISTRIB_ARCH the ABI must come from apk --print-arch');

  // ELF headers built here, not taken from this machine: the check must read
  // the same way on any host. Byte 4 is the class, byte 5 the endianness,
  // bytes 18-19 e_machine in that endianness.
  const elfHeader = (machine, data, cls) => {
    const b = Buffer.alloc(64);
    b.write('\x7fELF', 0, 'latin1');
    b[4] = cls; b[5] = data; b[6] = 1;
    if (data === 1) b.writeUInt16LE(machine, 18); else b.writeUInt16BE(machine, 18);
    return b;
  };
  const elfDir = path.join(tmp, 'elf');
  fs.mkdirSync(elfDir, { recursive: true });
  const elfCases = [
    ['mips-be', 8, 2, 1, 'mips'],
    ['mips-le', 8, 1, 1, 'mipsel'],
    ['mips64-le', 8, 1, 2, 'mips64el'],
    ['aarch64', 183, 1, 2, 'aarch64'],
    ['armv7', 40, 1, 1, 'arm'],
    ['x86-64', 62, 1, 2, 'x86_64'],
    ['i386', 3, 1, 1, 'i686'],
    ['riscv64', 243, 1, 2, 'riscv64'],
    ['ppc64', 21, 2, 2, 'ppc64'],
  ];
  for (const [name, machine, data, cls] of elfCases) {
    fs.writeFileSync(path.join(elfDir, name), elfHeader(machine, data, cls), { mode: 0o755 });
  }
  // A shell script is not a system binary: it must be skipped, not guessed at.
  put(path.join(elfDir, 'script'), sh('exit 0'));
  const script = path.join(elfDir, 'script');
  for (const [name, , , , expect] of elfCases) {
    reset();
    ok(run('install', { APK_HAVE: have, APK_ARCH: '', D2K_ABI_ELF_FILES: `${script} ${path.join(elfDir, name)}` }));
    assert.match(read(calls), new RegExp(`^arch \\S+ ${expect}$`, 'm'),
      `${name}: with a silent apk the ABI must be read out of the ELF header`);
  }
  // A bare "mips" names no endianness, and on MIPS that is the whole question:
  // the ELF header must override it rather than pick a build by coin toss.
  reset();
  ok(run('install', { APK_HAVE: have, APK_ARCH: 'mips', D2K_ABI_ELF_FILES: path.join(elfDir, 'mips-be') }));
  assert.match(read(calls), /^arch \S+ mips$/m, 'a bare "mips" must be resolved through the ELF header');
  reset();
  ok(run('install', { APK_HAVE: have, APK_ARCH: 'mips', D2K_ABI_ELF_FILES: path.join(elfDir, 'mips-le') }));
  assert.match(read(calls), /^arch \S+ mipsel$/m, 'a bare "mips" on a little-endian box must become mipsel');
  // Nothing names the ABI: the refusal says which sources were asked.
  reset();
  const blind = run('install', { APK_HAVE: have, APK_ARCH: '', D2K_ABI_ELF_FILES: script });
  assert.notEqual(blind.status, 0, 'with no ABI from any source the installer must refuse');
  assert.match(blind.stdout + blind.stderr, /пробовали:[^\n]*DISTRIB_ARCH[^\n]*--print-arch[^\n]*ELF/,
    `the refusal must name every source tried: ${blind.stdout}${blind.stderr}`);
  put(release, releaseText, 0o644);

  // 3-5. Refusals keep the working install: no stop, no replaced binary.
  const before = fs.readFileSync(d2kd);
  put(path.join(src, 'builds/d2kd-linux-amd64'), engineFixture('d2kd') + '# next release\n');
  const refuse = (extra, pattern, what) => {
    reset();
    const r = run('install', extra);
    assert.notEqual(r.status, 0, `${what}: installer must refuse`);
    assert.match(r.stdout + r.stderr, pattern, `${what}: ${r.stdout}${r.stderr}`);
    assert(!read(calls).includes('service-stop'), `${what}: the running version must not be stopped`);
    assert.deepEqual(fs.readFileSync(d2kd), before, `${what}: binaries must not be replaced`);
  };
  fs.rmSync(path.join(bin, 'openssl'));
  refuse({ APK_HAVE: 'curl', APK_ADD_RC: '1' }, /apk update && apk add kmod-nft-queue .*openssl-util/, 'package failure');
  put(path.join(bin, 'openssl'), sh('exit 0'));
  refuse({ APK_HAVE: have, NFT_CHECK_RC: '1' }, /nftables не принимает правила D2K/, 'kernel without nft queue');
  reset();
  refuse({ APK_HAVE: have, DF_AVAIL: '10' }, /мало места .* USB/, 'no room for the runtime');
  // Room for the DOWNLOAD, in /tmp, before the first byte is fetched: the
  // whole set (~8,3 МиБ) lands there first, and a router with 8/16 MiB of
  // flash has a small tmpfs. Breaking inside fetch is too late to refuse.
  refuse({ APK_HAVE: have, DF_AVAIL_TMP: '100' }, /мало места для загрузки/, 'no room in /tmp');
  assert.equal(read(log('wget')) + read(log('curl')), '',
    'the download preflight must refuse before anything is fetched');
  // Room is measured after the packages took theirs (ревью 07.10): 7005 KiB
  // free, packages take 7000 — the runtime no longer fits.
  reset();
  fs.writeFileSync(path.join(tmp, 'df_avail'), '7005');
  refuse({ APK_HAVE: 'curl openssl-util' }, /мало места .* USB/, 'packages ate the room');
  fs.rmSync(path.join(tmp, 'df_avail'));

  // 6. 24.10: the same through opkg (openssl missing again).
  fs.rmSync(path.join(bin, 'openssl'));
  reset();
  const opkgEnv = { D2K_OPENWRT_APK: path.join(tmp, 'no-apk'), D2K_OPENWRT_OPKG: path.join(tmp, 'opkg'), APK_HAVE: 'curl' };
  ok(run('install', opkgEnv));
  assert.match(read(log('opkg')), /^install kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle openssl-util$/m,
    'opkg must install the missing packages');

  // 6b. 24.10 через проводник на VPS: свой конфиг opkg — строки opkg.conf без
  //     src и штатные зеркала downloads.openwrt.org по http:// (подписи сверяет
  //     opkg); чужой источник в попытку не входит. Проводник лёг — напрямую.
  const opkgEtc = path.join(tmp, 'opkg-etc');
  put(path.join(opkgEtc, 'opkg.conf'), 'dest root /\nlists_dir ext /var/opkg-lists\noption check_signature\n', 0o644);
  put(path.join(opkgEtc, 'opkg/distfeeds.conf'),
    'src/gz openwrt_core https://downloads.openwrt.org/releases/24.10.8/targets/x86/64/packages\n' +
    'src/gz openwrt_base https://downloads.openwrt.org/releases/24.10.8/packages/x86_64/base\n', 0o644);
  put(path.join(opkgEtc, 'opkg/customfeeds.conf'), 'src/gz mine https://example.org/feed\n', 0o644);
  fs.rmSync(path.join(bin, 'openssl'));
  reset();
  ok(run('install', { ...opkgEnv, D2K_OPENWRT_OPKG_ETC: opkgEtc }));
  assert.match(read(log('opkg-gate')), /^http:\/\/85\.192\.60\.175:9444 update$/m, 'opkg list update via the gate');
  assert.match(read(log('opkg-gate')), /^http:\/\/85\.192\.60\.175:9444 install$/m, 'opkg install via the gate');
  assert.equal(read(log('opkg-gate-conf')),
    'dest root /\nlists_dir ext /var/opkg-lists\noption check_signature\n' +
    'src/gz openwrt_core http://downloads.openwrt.org/releases/24.10.8/targets/x86/64/packages\n' +
    'src/gz openwrt_base http://downloads.openwrt.org/releases/24.10.8/packages/x86_64/base\n',
    'gate attempt: opkg.conf without src plus official feeds over http:// only');
  fs.rmSync(path.join(bin, 'openssl'));
  reset();
  ok(run('install', { ...opkgEnv, D2K_OPENWRT_OPKG_ETC: opkgEtc, GATE_DOWN: '1' }));
  assert.match(read(log('opkg-gate')), /update$/m, 'the gate was tried first');
  assert.match(read(log('opkg')), /^install kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle openssl-util$/m,
    'with the gate down opkg installs directly');

  // 7. FW_BACKEND=iptables in the config keeps the iptables path: it needs iptables.
  const config = path.join(tmp, 'opt/d2k/config');
  const configText = read(config);
  fs.appendFileSync(config, 'FW_BACKEND=iptables\n');
  reset();
  const ipt = run('install', { APK_HAVE: have });
  assert.notEqual(ipt.status, 0);
  assert.match(ipt.stdout + ipt.stderr, /нет iptables/, 'explicit iptables backend must require iptables');
  fs.writeFileSync(config, configText);

  // 8. Uninstall removes the three nft tables even without init.
  reset();
  fs.rmSync(path.join(tmp, 'opt/etc/init.d/S99d2k'));
  // Init is gone: the fallback still returns the owner's fw4 flow offloading.
  put(path.join(tmp, 'opt/d2k/run/flow-offloading.saved'), '1\n', 0o644);
  put(path.join(bin, 'uci'), sh(`printf 'uci %s\\n' "$*" >> '${log('nft')}'`));
  put(path.join(bin, 'fw4'), sh(`printf 'fw4 %s\\n' "$*" >> '${log('nft')}'`));
  ok(run('uninstall', { NFT_TABLES: '1' }));
  assert.match(read(log('nft')), /^uci set firewall\.@defaults\[0\]\.flow_offloading=1$/m, 'uninstall must restore flow offloading');
  assert.match(read(log('nft')), /^fw4 reload$/m, 'uninstall must reload fw4 after restoring');
  const nftLog = read(log('nft'));
  for (const t of ['d2k', 'd2k_rst', 'd2k_tg']) assert.match(nftLog, new RegExp(`^delete table inet ${t}$`, 'm'), `uninstall must delete inet ${t}`);
  assert(!fs.existsSync(path.join(tmp, 'etc/init.d/d2k')), 'uninstall must remove the boot bridge');
  // Without Entware /opt was created by D2K: a full uninstall leaves no empty tree.
  reset();
  ok(run('install', { APK_HAVE: have }));
  ok(run('uninstall', { D2K_KEEP_STATE: '0' }));
  assert(!fs.existsSync(path.join(tmp, 'opt')), 'full uninstall must remove the empty /opt tree D2K created');
  // With Entware (/opt/bin/opkg) its directories stay even when empty.
  reset();
  ok(run('install', { APK_HAVE: have }));
  put(path.join(tmp, 'opt/bin/opkg'), sh('exit 0'));
  ok(run('uninstall', { D2K_KEEP_STATE: '0' }));
  assert(fs.existsSync(path.join(tmp, 'opt/etc/init.d')) && fs.existsSync(path.join(tmp, 'opt/sbin')), 'uninstall must not remove Entware directories');
  console.log('OpenWrt without Entware: wget bootstrap, apk/opkg packages, VPS gate, nft preflight, space, uninstall: PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
