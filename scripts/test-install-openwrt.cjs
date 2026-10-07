#!/usr/bin/env node
// Installer/uninstaller on OpenWrt without Entware (07.10.2026): stock 25.12
// has nft, apk, wget (uclient-fetch), BusyBox ip and start-stop-daemon, but no
// curl, openssl, iptables or ipset. PATH holds only those commands plus the
// ordinary utilities. No /opt, firewall or package manager is touched.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
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
      if (!hidden.has(name) && !fs.existsSync(target)) fs.symlinkSync(path.join(dir, name), target);
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
  info) shift; [ "$1" = -e ] && shift
        case " \${APK_HAVE:-} " in *" $1 "*) exit 0 ;; esac; exit 1 ;;
  add) [ "\${APK_ADD_RC:-0}" = 0 ] || exit "$APK_ADD_RC"
       shift
       for p in "$@"; do
         case "$p" in
           curl) cp '${path.join(tmp, 'curl-double')}' '${bin}/curl' ;;
           openssl-util) printf '#!/bin/sh\\nexit 0\\n' > '${bin}/openssl'; chmod +x '${bin}/openssl' ;;
         esac
       done ;;
esac
exit 0`));
  put(path.join(tmp, 'opkg'), sh(`printf '%s\\n' "$*" >> '${log('opkg')}'
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
  put(path.join(bin, 'df'), sh(`echo 'Filesystem 1024-blocks Used Available Capacity Mounted on'
echo "/dev/root 100692 18544 \${DF_AVAIL:-80020} 19% /"`));

  const src = path.join(tmp, 'source');
  const fixture = (name, contents, mode = 0o755) => put(path.join(src, name), contents, mode);
  fixture('scripts/architecture.sh', sh('printf "arch %s %s\\n" "$1" "$2" >> "$CALLS"; printf "amd64\\n"'));
  for (const name of ['check-cpu.sh', 'select-panel-ip.sh']) fixture(`scripts/${name}`, sh('exit 0'));
  fixture('builds/d2kpanel-linux-amd64', sh('echo features=telegram-control'));
  fixture('builds/d2ktg-linux-amd64', sh('echo features=per-install-enrollment,instagram-ip-probe,meta-hosts-v3'));
  fixture('builds/d2kd-linux-amd64', sh('exit 0'));
  fixture('builds/d2kc-linux-amd64', sh('exit 2'));
  fixture('files/S99d2k', sh('printf "service-%s\\n" "$1" >> "$CALLS"\n[ "$1" != status ] || echo "датапат: работает"\nexit 0'));
  fixture('files/config', 'PANEL_LISTEN=192.168.1.1:8090\nTG_ENABLED=0\nTG_RELAY_URL=wss://example.test/ws\n');
  // Sourced by uninstall.sh: definitions only, no exit.
  fixture('files/d2k-ppe-deoffload.sh', sh('d2k_ppe_remove() { :; }'));
  for (const name of ['d2k-fw-heal.sh', '001-d2k.sh', 'd2k-tg-firewall.sh', 'd2k-tg-watchdog.sh',
    'd2k-instagram-dns-scheduler.sh', 'd2k-instagram-dns.sh', 'd2k-log-maintenance.sh', 'd2k-update.sh']) fixture(`files/${name}`, sh('exit 0'));
  fixture('files/d2k-openwrt-init', fs.readFileSync(path.join(root, 'files/d2k-openwrt-init'), 'utf8')
    .replaceAll('/etc/rc.common', path.join(tmp, 'etc/rc.common')));
  for (const name of ['meta-ranges.txt', 'tg-roots.pem', 'fake/stun.bin', 'fake/quic_initial_dbankcloud_ru.bin']) fixture(`files/${name}`, 'fixture\n');
  for (const name of ['index.html', 'favicon.svg', 'panel.css', 'panel.js', 'gsap.js', 'fonts/onest.woff2',
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
    PATH: `${bin}:${sys}`, HOME: tmp, CALLS: calls, SRC: src, D2K_BASE: 'http://fixture.test',
    D2K_OPENWRT_APK: path.join(bin, 'apk'), D2K_OPENWRT_OPKG: path.join(tmp, 'no-opkg'), D2K_KEEP_STATE: '1',
  };
  const read = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
  const reset = () => { for (const f of [calls, log('apk'), log('opkg'), log('nft'), log('wget')]) fs.rmSync(f, { force: true }); };
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

  // 3-5. Refusals keep the working install: no stop, no replaced binary.
  const before = fs.readFileSync(d2kd);
  put(path.join(src, 'builds/d2kd-linux-amd64'), sh('# next release\nexit 0'));
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
  assert.doesNotMatch(read(log('apk')), /^add/m, 'space is checked before packages are added');

  // 6. 24.10: the same through opkg (openssl missing again).
  fs.rmSync(path.join(bin, 'openssl'));
  reset();
  const opkgEnv = { D2K_OPENWRT_APK: path.join(tmp, 'no-apk'), D2K_OPENWRT_OPKG: path.join(tmp, 'opkg'), APK_HAVE: 'curl' };
  ok(run('install', opkgEnv));
  assert.match(read(log('opkg')), /^install kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle openssl-util$/m,
    'opkg must install the missing packages');

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
  ok(run('uninstall', { NFT_TABLES: '1' }));
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
  console.log('OpenWrt without Entware: wget bootstrap, apk/opkg packages, nft preflight, space, uninstall: PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
