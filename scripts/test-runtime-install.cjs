#!/usr/bin/env node
// Full installer/uninstaller in a private filesystem with router boundaries
// replaced by local commands. No /opt, firewall, or router state is touched.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const engineFixture = require('./test-engine-fixture.cjs');
const root = path.resolve(__dirname, '..');
const tmp = fs.mkdtempSync('/tmp/runtime-install-test.');
function fixture(name, contents, mode = 0o755) {
  const target = path.join(tmp, 'source', name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents, { mode });
}
try {
  fs.mkdirSync(path.join(tmp, 'bin'));
  for (const command of ['curl', 'ip', 'ipset', 'openssl']) {
    fs.writeFileSync(path.join(tmp, 'bin', command), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  }
  // iptables doubles: no d2k chains; filter OUTPUT holds RST-drop rules left
  // by a killed d2k process (owner PID gone), a foreign one and a live owner's.
  for (const command of ['iptables', 'ip6tables']) {
    fs.writeFileSync(path.join(tmp, 'bin', command), `#!/bin/sh
printf '${command} %s\\n' "$*" >> "$IPT_CALLS"
case "$*" in
  *"-S OUTPUT"*) [ "\${IPT_RST:-0}" = 1 ] || exit 0
    printf '%s\\n' '-P OUTPUT ACCEPT' \\
      '-A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST -m comment --comment d2k-rst:2147480001 -j DROP' \\
      '-A OUTPUT -p tcp -m tcp --sport 40751 --tcp-flags RST RST -m comment --comment other:2147480001 -j DROP' \\
      '-A OUTPUT -p tcp -m tcp --sport 40752 --tcp-flags RST RST -m comment --comment d2k-rst:${process.pid} -j DROP'
    exit 0 ;;
esac
exit 1
`, { mode: 0o755 });
  }
  fs.writeFileSync(path.join(tmp, 'bin/start-stop-daemon'), '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n', { mode: 0o755 });
  fixture('scripts/architecture.sh', '#!/bin/sh\nprintf "amd64\\n"\n');
  for (const name of ['check-cpu.sh', 'select-panel-ip.sh']) fixture(`scripts/${name}`, '#!/bin/sh\nexit 0\n');
  fixture('builds/d2kpanel-linux-amd64', '#!/bin/sh\necho features=telegram-control\n');
  fixture('builds/d2ktg-linux-amd64', '#!/bin/sh\necho features=per-install-enrollment,instagram-ip-probe,meta-hosts-v3\n');
  fixture('builds/d2kfetch-linux-amd64', '#!/bin/sh\necho d2kfetch ${D2K_RELEASE_ID:-dev}\n');
  fixture('builds/d2kd-linux-amd64', engineFixture('d2kd'));
  fixture('builds/d2kshadow-linux-amd64', '#!/bin/sh\nexit 2\n');
  for (const profile of ['modern', 'legacy']) {
    const file = `core/profiles/${profile}.hex`;
    fixture(file, fs.readFileSync(path.join(root, file)));
  }
  fixture('builds/d2kc-linux-amd64', engineFixture('d2kc'));
  fixture('files/S99d2k', '#!/bin/sh\nprintf "service-%s\\n" "$1" >> "$CALLS"\n[ "$1" != status ] || echo "датапат: работает"\nexit 0\n');
  fixture('files/config', 'PANEL_LISTEN=192.168.1.1:8090\nTG_ENABLED=0\nTG_RELAY_URL=wss://example.test/ws\n');
  for (const name of ['d2k-fw-heal.sh', 'd2k-ppe-deoffload.sh', '001-d2k.sh', 'd2k-tg-firewall.sh', 'd2k-tg-watchdog.sh', 'd2k-instagram-dns-scheduler.sh']) fixture(`files/${name}`, '#!/bin/sh\nexit 0\n');
  fixture('files/d2k-instagram-dns.sh', '#!/bin/sh\nprintf "dns-%s\\n" "$1" >> "$CALLS"\n');
  fixture('files/d2k-log-maintenance.sh', fs.readFileSync(path.join(root, 'files/d2k-log-maintenance.sh')));
  fixture('files/d2k-update.sh', fs.readFileSync(path.join(root, 'files/d2k-update.sh')));
  for (const name of ['meta-ranges.txt', 'tg-roots.pem', 'fake/stun.bin', 'fake/quic_initial_dbankcloud_ru.bin']) fixture(`files/${name}`, 'fixture\n');
  for (const name of ['index.html', 'favicon.svg', 'panel.css', 'panel.js', 'diagnostics.js', 'gsap.js', 'fonts/onest.woff2', 'fonts/OFL-onest.txt', 'fonts/jbmono.woff2', 'fonts/OFL-jbmono.txt']) fixture(`internal/web/assets/${name}`, 'fixture\n');
  fs.mkdirSync(path.join(tmp, 'proc/net/netfilter'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'proc/net/netfilter/nfnetlink_queue'), '');
  fs.writeFileSync(path.join(tmp, 'proc/net/ip_tables_targets'), 'NFQUEUE\n');
  fs.writeFileSync(path.join(tmp, 'proc/net/ip_tables_matches'), 'connbytes\n');
  fs.mkdirSync(path.join(tmp, 'opt/etc/ndm/netfilter.d'), { recursive: true });
  const runtime = path.join(tmp, 'runtime');
  for (const name of ['install', 'uninstall']) {
    const script = fs.readFileSync(name === 'install' && process.env.D2K_INSTALL_FIXTURE_SOURCE ? process.env.D2K_INSTALL_FIXTURE_SOURCE : path.join(root, `scripts/${name}.sh`), 'utf8')
      .replaceAll('/opt', path.join(tmp, 'opt'))
      .replaceAll('/etc/openwrt_release', path.join(tmp, 'etc/openwrt_release'))
      .replaceAll('/etc/rc.common', path.join(tmp, 'etc/rc.common'))
      .replaceAll('/etc/init.d/d2k', path.join(tmp, 'etc/init.d/d2k'))
      .replaceAll('/lib/functions/procd.sh', path.join(tmp, 'lib/functions/procd.sh'))
      .replaceAll('/proc/', `${path.join(tmp, 'proc')}/`)
      .replaceAll('/tmp/d2k', runtime);
    fs.writeFileSync(path.join(tmp, `${name}.sh`), script);
  }
  const iptCalls = path.join(tmp, 'ipt-calls');
  const env = { ...process.env, PATH: `${tmp}/bin:${process.env.PATH}`, D2K_LOCAL: `${tmp}/source`, CALLS: `${tmp}/calls`, IPT_CALLS: iptCalls, D2K_KEEP_STATE: '1' };
  function run(name, extraEnv = {}) {
    const result = spawnSync('/bin/sh', [path.join(tmp, `${name}.sh`)], { env: { ...env, ...extraEnv }, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    return result.stdout;
  }
  const calls = () => { try { return fs.readFileSync(path.join(tmp, 'calls'), 'utf8'); } catch { return ''; } };
  // Upgrade from a release that shipped the port-80 proxy (task 51): its binary goes away.
  fs.mkdirSync(path.join(tmp, 'opt/sbin'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'opt/sbin/d2khttp'), '#!/bin/sh\nexit 2\n', { mode: 0o755 });
  const existingInit = path.join(tmp, 'opt/etc/init.d/S99d2k');
  fs.mkdirSync(path.dirname(existingInit), { recursive: true });
  fs.writeFileSync(existingInit, '#!/bin/sh\n[ "$1" != stop ] || exit 1\n', { mode: 0o755 });
  const beforeStop = fs.readFileSync(path.join(tmp, 'opt/sbin/d2khttp'), 'utf8');
  const stopFailed = spawnSync('/bin/sh', [path.join(tmp, 'install.sh')], { env, encoding: 'utf8', timeout: 10000 });
  assert.notEqual(stopFailed.status, 0, 'failed stop must prevent installation');
  assert.equal(fs.readFileSync(path.join(tmp, 'opt/sbin/d2khttp'), 'utf8'), beforeStop);
  assert(!fs.existsSync(path.join(tmp, 'opt/sbin/d2kd')), 'failed stop must not install binaries');
  fs.unlinkSync(existingInit);
  // Fail the atomic copy after its first bytes reach the destination filesystem.
  const cp = path.join(tmp, 'bin/cp');
  fs.writeFileSync(cp, `#!/bin/sh
case "$2" in "${tmp}"/opt/sbin/*)
    printf partial > "$2"
    case "$INTERRUPT_COPY" in error) exit 1 ;; *) kill -"$INTERRUPT_COPY" "$PPID"; exit 0 ;; esac ;;
esac
exec /bin/cp "$@"
`, { mode: 0o755 });
  const sbin = path.join(tmp, 'opt/sbin');
  const onlyLegacyBinary = () => assert.deepEqual(fs.readdirSync(sbin), ['d2khttp'], 'partial executable must be discarded');
  const workdirs = () => fs.readdirSync(tmp).filter(n => n.startsWith('runtime-install.'));
  for (const interrupt of ['error', 'HUP', 'TERM', 'INT', 'KILL']) {
    const r = spawnSync('/bin/sh', [path.join(tmp, 'install.sh')], {
      env: { ...env, INTERRUPT_COPY: interrupt }, encoding: 'utf8', timeout: 10000,
    });
    if (interrupt === 'KILL') {
      assert.equal(r.signal, 'SIGKILL');
      assert.equal(workdirs().length, 1, 'SIGKILL must leave actual workspace for retry');
      assert.equal(fs.readdirSync(sbin).length, 2, 'SIGKILL must leave an actual partial copy for retry');
    } else {
      assert.equal(r.status, { error: 1, HUP: 129, TERM: 143, INT: 130 }[interrupt], r.stderr);
      onlyLegacyBinary();
      assert.deepEqual(workdirs(), [], 'private installer workspace must be removed on error or signal');
    }
  }
  fs.unlinkSync(cp);
  const live = `runtime-install.${process.pid}.Ab1234`;
  const unmarked = 'runtime-install.2147480001.Ab1234';
  const link = 'runtime-install.2147480001.link01';
  const liveFile = `.d2k-install.${process.pid}.Ab1234`;
  fs.mkdirSync(path.join(tmp, live));
  fs.writeFileSync(path.join(tmp, live, '.d2k-owner'), String(process.pid));
  fs.mkdirSync(path.join(tmp, unmarked));
  fs.symlinkSync(path.join(tmp, 'source'), path.join(tmp, link));
  fs.writeFileSync(path.join(sbin, liveFile), 'active');
  const installOut = run('install');
  assert.deepEqual(workdirs().sort(), [live, unmarked, link].sort(), 'retry must reclaim only its abandoned workspace');
  assert.equal(fs.readFileSync(path.join(sbin, liveFile), 'utf8'), 'active', 'parallel installer stage stays intact');
  fs.unlinkSync(path.join(sbin, liveFile));
  assert.deepEqual(fs.readdirSync(sbin).sort(), ['d2kc', 'd2kd', 'd2kfetch', 'd2kpanel', 'd2kshadow', 'd2ktg'], 'retry must reclaim the abandoned per-file stage');
  assert(fs.existsSync(path.join(tmp, 'opt/sbin/d2kfetch')), 'diagnostic tool must be installed');
  assert(fs.existsSync(path.join(tmp, 'opt/sbin/d2kshadow')), 'shadow daemon must be installed');
  for (const profile of ['modern', 'legacy']) {
    assert.deepEqual(fs.readFileSync(path.join(tmp, `opt/d2k/files/${profile}.hex`)),
      fs.readFileSync(path.join(root, `core/profiles/${profile}.hex`)));
  }
  fs.writeFileSync(path.join(tmp, 'opt/d2k/state/shadow.d2km'), 'shadow knowledge');
  assert(!fs.existsSync(path.join(tmp, 'opt/sbin/d2khttp')), 'upgrade must remove the old d2khttp proxy binary');
  fs.writeFileSync(path.join(tmp, 'bin/mv'), '#!/bin/sh\ncase "$3" in */d2k/config) ls -l "$2" | cut -c1-10 >> "$CALLS.migration-mode";; esac\nexec /bin/mv "$@"\n', { mode: 0o755 });
  const migrationConfig = path.join(tmp, 'opt/d2k/config');
  const identityPath = path.join(tmp, 'opt/d2k/state/tg.identity');
  fs.writeFileSync(identityPath, 'existing-private-identity');
  const oldIP = '213.176.74.63';
  for (const quote of ['', "'", '"']) {
    fs.writeFileSync(migrationConfig, `PANEL_LISTEN=192.168.1.1:8090\nTG_ENABLED=0\nTG_RELAY_URL=${quote}wss://${oldIP}.nip.io/ws${quote}\nD2K_GATE=${quote}http://${oldIP}:9444${quote}\nD2K_RELAY_URL=${quote}https://${oldIP}.nip.io:9443/resolve${quote}\n`);
    run('install');
    const migrated = fs.readFileSync(migrationConfig, 'utf8');
    assert(!migrated.includes(oldIP), 'saved project defaults must migrate');
    assert.equal(fs.statSync(migrationConfig).mode & 0o777, 0o600);
    assert(fs.readFileSync(path.join(tmp, 'calls.migration-mode'), 'utf8').trim().split('\n').every(mode => mode === '-rw-------'), 'staged config is private before rename');
    assert.match(migrated, /TG_RELAY_URL=wss:\/\/85\.192\.60\.175\.nip\.io\/ws/);
    assert.match(migrated, /TG_ENROLL_PORT=9443/);
    assert.match(migrated, /TG_ENABLED=0/);
    assert.equal(fs.readFileSync(identityPath, 'utf8'), 'existing-private-identity');
    run('install');
    assert.equal(fs.readFileSync(migrationConfig, 'utf8'), migrated, 'migration is idempotent');
  }
  const customConfig = `PANEL_LISTEN=192.168.1.1:8090\nTG_ENABLED=0\nTG_RELAY_URL=wss://${oldIP}.nip.io/custom\nTG_ENROLL_PORT=9555\nD2K_GATE=\nD2K_RELAY_URL=https://custom.example/resolve\nTG_RELAY_SECRET=preserved\n`;
  fs.writeFileSync(migrationConfig, customConfig);
  run('install');
  assert.equal(fs.readFileSync(migrationConfig, 'utf8'), customConfig, 'custom endpoints and credentials must survive');
  // The first DNS refresh (15 names, possibly silent edges) must not hold the
  // installer: the service's scheduler runs it in the background with a log.
  assert(!calls().includes('dns-refresh'), 'installer must not run the DNS refresh synchronously');
  assert.match(installOut, /в фоне/, 'installer must say the DNS refresh runs in the background');
  // An upgrade keeps a success younger than a day (no release-day herd on
  // /resolve); an older or time-less mark is cleared, so the scheduler
  // refreshes right away.
  const dnsSuccess = path.join(tmp, 'opt/d2k/state/instagram-dns-last-success');
  const nowSec = Math.floor(Date.now() / 1000);
  fs.writeFileSync(dnsSuccess, `2026-10-02\n${nowSec - 3600}\n`);
  run('install');
  assert(fs.existsSync(dnsSuccess), 'upgrade must keep a DNS success mark younger than 24 h');
  fs.writeFileSync(dnsSuccess, `2026-10-01\n${nowSec - 90000}\n`);
  run('install');
  assert(!fs.existsSync(dnsSuccess), 'upgrade must clear a DNS success mark older than 24 h');
  fs.writeFileSync(dnsSuccess, `2026-10-02\n${nowSec + 7200}\n`);
  run('install');
  assert(!fs.existsSync(dnsSuccess), 'a success mark from the future is not trusted');
  fs.writeFileSync(dnsSuccess, '2026-10-02\n');
  run('install');
  assert(!fs.existsSync(dnsSuccess), 'upgrade must clear an old-format DNS success mark so the scheduler refreshes right away');
  assert(!calls().includes('dns-refresh'), 'upgrade must not run the DNS refresh synchronously');
  // A d2ktg without the 15-name certificate check would silently skip WhatsApp/fbcdn.
  const tgFixture = path.join(tmp, 'source/builds/d2ktg-linux-amd64');
  const tgCurrent = fs.readFileSync(tgFixture);
  fs.writeFileSync(tgFixture, '#!/bin/sh\necho features=per-install-enrollment,instagram-ip-probe,meta-hosts-v2\n');
  const stale = spawnSync('/bin/sh', [path.join(tmp, 'install.sh')], { env, encoding: 'utf8', timeout: 10000 });
  assert.notEqual(stale.status, 0, 'installer must reject a d2ktg without the Meta host list check');
  assert.match(stale.stdout + stale.stderr, /d2ktg устарел/);
  fs.writeFileSync(tgFixture, tgCurrent);
  // Netis N6 (MT7621, field 04.10): xt_connbytes ships as a module file but is
  // not loaded, and /proc/net/ip_tables_matches lists only loaded matches. The
  // installer loads it itself — modprobe first, then insmod of the firmware file.
  const matches = path.join(tmp, 'proc/net/ip_tables_matches');
  const loadStubs = ['modprobe', 'insmod', 'uname'].map((n) => path.join(tmp, 'bin', n));
  fs.writeFileSync(loadStubs[0], `#!/bin/sh\n[ "$1" = xt_connbytes ] && [ "\${MODPROBE_OK:-0}" = 1 ] && { echo connbytes >> '${matches}'; exit 0; }\nexit 1\n`, { mode: 0o755 });
  fs.writeFileSync(loadStubs[1], `#!/bin/sh\ncase "$1" in */xt_connbytes.ko) echo connbytes >> '${matches}'; exit 0 ;; esac\nexit 1\n`, { mode: 0o755 });
  fs.writeFileSync(loadStubs[2], '#!/bin/sh\n[ "$1" = -r ] && { echo 9.9-test; exit 0; }\nexec /usr/bin/uname "$@"\n', { mode: 0o755 });
  fs.writeFileSync(matches, '');
  run('install', { MODPROBE_OK: '1' });
  assert.match(fs.readFileSync(matches, 'utf8'), /connbytes/, 'installer must modprobe an unloaded xt_connbytes');
  const modsDir = path.join(tmp, 'mods');
  fs.mkdirSync(path.join(modsDir, '9.9-test'), { recursive: true });
  fs.writeFileSync(path.join(modsDir, '9.9-test/xt_connbytes.ko'), '');
  fs.writeFileSync(matches, '');
  run('install', { D2K_MODULES_DIR: modsDir });
  assert.match(fs.readFileSync(matches, 'utf8'), /connbytes/, 'installer must insmod xt_connbytes from the firmware tree when modprobe fails');
  fs.rmSync(path.join(modsDir, '9.9-test/xt_connbytes.ko'));
  fs.writeFileSync(matches, '');
  const noModule = spawnSync('/bin/sh', [path.join(tmp, 'install.sh')], { env: { ...env, D2K_MODULES_DIR: modsDir }, encoding: 'utf8', timeout: 10000 });
  assert.notEqual(noModule.status, 0, 'installer must stop when xt_connbytes is absent from the firmware');
  assert.match(noModule.stdout + noModule.stderr, /Модули ядра подсистемы Netfilter/, 'the refusal must name what to install');
  for (const stub of loadStubs) fs.unlinkSync(stub);
  fs.writeFileSync(matches, 'connbytes\n');
  // OpenWrt (лаборатория 06.10, 24.10.8): модули netfilter ставятся штатным
  // opkg, а не Entware; без них отказ называет пакеты OpenWrt, не Keenetic.
  // Это путь iptables (fw3 или FW_BACKEND=iptables) — явно, чтобы nft на
  // машине прогона не уводил на nftables (тот — scripts/test-install-openwrt.cjs).
  fs.appendFileSync(path.join(tmp, 'opt/d2k/config'), 'FW_BACKEND=iptables\n');
  {
    const release = path.join(tmp, 'openwrt_release');
    fs.writeFileSync(release, "DISTRIB_ID='OpenWrt'\n");
    const opkgLog = path.join(tmp, 'opkg.log');
    const opkg = path.join(tmp, 'sysopkg');
    fs.writeFileSync(opkg, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${opkgLog}'\n[ "$1" = list-installed ] && { echo 'kmod-ipt-core - 6.6'; echo 'kmod-nfnetlink-queue - 6.6'; exit 0; }\nexit 0\n`, { mode: 0o755 });
    run('install', { D2K_OPENWRT_RELEASE: release, D2K_OPENWRT_OPKG: opkg, D2K_OPENWRT_APK: path.join(tmp, 'no-apk') });
    const log = fs.readFileSync(opkgLog, 'utf8');
    assert.match(log, /^install kmod-ipt-nfqueue .*kmod-ipt-nat kmod-ipt-nat6$/m, 'OpenWrt: missing kmods must be installed by the system opkg');
    assert.doesNotMatch(log, /install .*kmod-nfnetlink-queue/, 'OpenWrt: installed kmods must not be reinstalled');
    fs.writeFileSync(matches, '');
    const owrtNo = spawnSync('/bin/sh', [path.join(tmp, 'install.sh')], { env: { ...env, D2K_OPENWRT_RELEASE: release, D2K_OPENWRT_OPKG: opkg, D2K_OPENWRT_APK: path.join(tmp, 'no-apk'), D2K_MODULES_DIR: modsDir }, encoding: 'utf8', timeout: 10000 });
    assert.notEqual(owrtNo.status, 0);
    assert.match(owrtNo.stdout + owrtNo.stderr, /на OpenWrt поставьте пакеты: .*kmod-ipt-conntrack-extra/, 'OpenWrt refusal must name OpenWrt packages');
    assert.doesNotMatch(owrtNo.stdout + owrtNo.stderr, /Keenetic/);
    fs.writeFileSync(matches, 'connbytes\n');
  }
  run('install');
  const installed =path.join(tmp, 'opt/d2k/d2k-log-maintenance.sh');
  assert.deepEqual(fs.readFileSync(installed), fs.readFileSync(path.join(root, 'files/d2k-log-maintenance.sh')), 'installer must fetch and install helper');
  assert(fs.statSync(installed).mode & 0o111, 'installed helper must be executable');
  const ppe = path.join(tmp, 'opt/d2k/d2k-ppe-deoffload.sh');
  assert(fs.existsSync(ppe) && (fs.statSync(ppe).mode & 0o111), 'installer must install the PPE de-offload helper executable');
  // Issue #4: OpenWrt does not boot Entware's S99d2k on its own.
  const hostInit = path.join(tmp, 'etc/init.d/d2k');
  assert(!fs.existsSync(hostInit), 'Keenetic install must not create a host OpenWrt service');
  fs.mkdirSync(path.dirname(hostInit), { recursive: true });
  fs.mkdirSync(path.join(tmp, 'lib/functions'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'etc/openwrt_release'), "DISTRIB_ID='OpenWrt'\n");
  fs.writeFileSync(path.join(tmp, 'lib/functions/procd.sh'), '# fixture\n');
  fs.writeFileSync(path.join(tmp, 'etc/rc.common'), '#!/bin/sh\nprintf "host-%s\\n" "$2" >> "$CALLS"\n[ "$2" != enable ] || [ "${HOST_ENABLE_FAIL:-0}" != 1 ]\n', { mode: 0o755 });
  const templatePath = path.join(root, 'files/d2k-openwrt-init');
  if (fs.existsSync(templatePath)) fixture('files/d2k-openwrt-init', fs.readFileSync(templatePath, 'utf8')
    .replaceAll('/etc/rc.common', path.join(tmp, 'etc/rc.common')));
  run('install');
  assert(fs.existsSync(hostInit), 'OpenWrt installer must create /etc/init.d/d2k');
  assert(calls().includes('host-enable'), 'OpenWrt installer must enable its native boot hook');
  run('install');
  assert(fs.existsSync(hostInit), 'OpenWrt upgrade must keep the native boot hook');
  // Missing procd must not turn an otherwise successful update into failure.
  const procd = path.join(tmp, 'lib/functions/procd.sh');
  fs.rmSync(procd);
  run('install');
  fs.writeFileSync(procd, '# fixture\n');
  const ownedHook = fs.readFileSync(hostInit);
  const d2kdSource = path.join(tmp, 'source/builds/d2kd-linux-amd64');
  const d2kdInstalled = path.join(tmp, 'opt/sbin/d2kd');
  fs.writeFileSync(d2kdSource, engineFixture('d2kd') + '# next release\n');
  fs.writeFileSync(hostInit, '#!/bin/sh\n# another service\n');
  const conflict = spawnSync('/bin/sh', [path.join(tmp, 'install.sh')], { env, encoding: 'utf8', timeout: 10000 });
  assert.equal(conflict.status, 0, 'foreign host hook must not block a runtime update');
  assert.match(conflict.stderr, /чужой/);
  assert.match(fs.readFileSync(hostInit, 'utf8'), /another service/);
  assert.deepEqual(fs.readFileSync(d2kdInstalled), fs.readFileSync(d2kdSource), 'runtime update must still complete');
  fs.writeFileSync(hostInit, ownedHook);
  // A bad hook is rejected BEFORE stopping or replacing a working runtime.
  const hookSource = path.join(tmp, 'source/files/d2k-openwrt-init');
  const hookCurrent = fs.readFileSync(hookSource);
  fs.writeFileSync(hookSource, '#!/bin/sh\n# invalid hook\n');
  const beforeCalls = calls(), beforeBinary = fs.readFileSync(d2kdInstalled);
  fs.writeFileSync(d2kdSource, engineFixture('d2kd') + '# staged release\n');
  const badHook = spawnSync('/bin/sh', [path.join(tmp, 'install.sh')], { env, encoding: 'utf8', timeout: 10000 });
  assert.notEqual(badHook.status, 0, 'invalid native hook must fail preflight');
  assert.equal(calls(), beforeCalls, 'invalid hook must not stop or start the runtime');
  assert.deepEqual(fs.readFileSync(d2kdInstalled), beforeBinary, 'invalid hook must not replace binaries');
  assert.deepEqual(fs.readFileSync(hostInit), ownedHook, 'preflight failure must preserve installed hook');
  assert.deepEqual(fs.readdirSync(path.dirname(hostInit)), ['d2k'], 'preflight must clean staged host files');
  fs.writeFileSync(hookSource, hookCurrent);
  // Enable fails after installation: report missing autostart, not a failed release.
  const enableFailure = run('install', { HOST_ENABLE_FAIL: '1' });
  assert.match(enableFailure, /автозапуск OpenWrt не включён/);
  assert.deepEqual(fs.readFileSync(d2kdInstalled), fs.readFileSync(d2kdSource));
  assert.deepEqual(fs.readdirSync(path.dirname(hostInit)), ['d2k']);
  run('install');
  // Uninstall without init must still remove its own tagged -j PPE rules.
  fs.writeFileSync(ppe, '#!/bin/sh\nd2k_ppe_remove() { printf "ppe-remove\\n" >> "$CALLS"; }\n');
  const state = path.join(tmp, 'opt/d2k/state/catalog.json'); fs.writeFileSync(state, '{"learned":true}');
  fs.writeFileSync(path.join(tmp, 'opt/d2k/run/d2k-log-maintenance.pid'), '123');
  // A background DNS refresh must not race the removal of its pins.
  fs.writeFileSync(path.join(tmp, 'opt/d2k/run/d2k-instagram-dns-scheduler.pid'), '999999');
  // Init may already be missing: uninstall still stops its owned helper.
  fs.unlinkSync(path.join(tmp, 'opt/etc/init.d/S99d2k'));
  const diagnosticRuntime = runtime + '-diagnostics';
  fs.mkdirSync(diagnosticRuntime);
  for (const name of ['enabled','report.json','report.new']) fs.writeFileSync(path.join(diagnosticRuntime,name),'stale');
  fs.mkdirSync(runtime); fs.writeFileSync(path.join(runtime, 'live.json'), '{}');
  for (const binary of ['d2kd','d2kc','d2kpanel','d2ktg']) fs.writeFileSync(path.join(runtime, `${binary}.health`), 'stale');
  fs.writeFileSync(path.join(runtime, 'log-tail.ABCDEF'), 'stale');
  for (const name of ['shadow.queue','shadow.queue.seen','shadow.queue.seen.new','shadow.queue.consumer']) fs.writeFileSync(path.join(runtime, name), 'stale');
  fs.writeFileSync(path.join(runtime, 'unrelated'), 'keep');
  const customRuntime = path.join(tmp, 'custom-runtime');
  fs.mkdirSync(customRuntime);
  fs.writeFileSync(path.join(customRuntime, 'live.json'), '{}');
  fs.writeFileSync(path.join(customRuntime, 'log-tail.QRSTUV'), 'stale');
  fs.writeFileSync(path.join(customRuntime, 'unrelated'), 'keep');
  fs.appendFileSync(path.join(tmp, 'opt/d2k/config'), `D2K_RUNTIME_DIR='${customRuntime}'\n`);
  // Init is gone: the fallback still restores the NAT accelerator setting it
  // saved, removes its own MASQUERADE and leftover RST-drop rules, and its /tmp files.
  const fastnat = path.join(tmp, 'proc/sys/net/netfilter/nf_conntrack_fastnat');
  fs.mkdirSync(path.dirname(fastnat), { recursive: true }); fs.writeFileSync(fastnat, '0\n');
  fs.writeFileSync(path.join(tmp, 'opt/d2k/run/fastnat.saved'), '1\n');
  const tmpLeft = [`${runtime}-fw-heal.last`, `${runtime}-instagram-dns-last-attempt`];
  for (const f of tmpLeft) fs.writeFileSync(f, '1');
  for (const d of [`${runtime}-fw-heal.lock`, `${runtime}-fw-operation.lock`]) { fs.mkdirSync(d); fs.writeFileSync(path.join(d, 'pid'), '2147480001'); }
  fs.rmSync(iptCalls, { force: true });
  run('uninstall', { IPT_RST: '1' });
  assert(!fs.existsSync(hostInit), 'keep-state uninstall must remove the native boot hook');
  assert(calls().includes('host-disable') && calls().includes('host-detach'), 'uninstall must disable the hook and cancel its waiting worker');
  assert.equal(fs.readFileSync(fastnat, 'utf8').trim(), '1', 'uninstall fallback must restore the saved fastnat value');
  const ipt = fs.readFileSync(iptCalls, 'utf8');
  for (const tool of ['iptables', 'ip6tables']) {
    assert(ipt.includes(`${tool} -w -D OUTPUT -p tcp --sport 40750 --tcp-flags RST RST -m comment --comment d2k-rst:2147480001 -j DROP`), `${tool}: leftover d2k-rst rule of a dead owner not removed`);
    assert(!ipt.includes(`${tool} -w -D OUTPUT -p tcp --sport 40751`), `${tool}: foreign RST rule touched`);
    assert(!ipt.includes(`${tool} -w -D OUTPUT -p tcp --sport 40752`), `${tool}: RST rule of a live non-d2k process touched`);
  }
  assert(ipt.includes('iptables -t nat -D POSTROUTING -p udp -m mark --mark 0x2d -j MASQUERADE'), 'uninstall fallback must remove its own MASQUERADE');
  for (const f of tmpLeft) assert(!fs.existsSync(f), `uninstall left ${f}`);
  for (const d of [`${runtime}-fw-heal.lock`, `${runtime}-fw-operation.lock`]) assert(!fs.existsSync(d), `uninstall left stale lock ${d}`);
  assert(calls().includes('dns-remove'), 'uninstall must remove the owned DNS pins through the manifest helper');
  const sched = calls().indexOf('d2k-instagram-dns-scheduler.pid');
  assert(sched >= 0 && sched < calls().indexOf('dns-remove'), 'uninstall must stop the DNS scheduler before removing its pins');
  assert(!fs.existsSync(diagnosticRuntime), 'uninstall must remove diagnostic history and opt-in flag');
  assert(!fs.existsSync(installed), 'uninstall must remove helper even when persistent state is kept');
  assert(!fs.existsSync(ppe), 'uninstall must remove the PPE de-offload helper');
  assert(fs.readFileSync(path.join(tmp, 'calls'), 'utf8').includes('ppe-remove'), 'uninstall must remove own PPE rules even without init');
  assert(!fs.existsSync(path.join(runtime, 'live.json')), 'uninstall must remove volatile live snapshot');
  assert(!fs.existsSync(path.join(tmp, 'opt/sbin/d2kfetch')), 'uninstall must remove diagnostic tool');
  assert(!fs.existsSync(path.join(tmp, 'opt/sbin/d2kshadow')), 'uninstall must remove shadow daemon');
  assert(!fs.existsSync(path.join(tmp, 'opt/d2k/files/modern.hex')), 'uninstall removes observed form');
  for (const name of ['shadow.queue','shadow.queue.seen','shadow.queue.seen.new','shadow.queue.consumer']) assert(!fs.existsSync(path.join(runtime, name)), 'uninstall removes owned shadow runtime files');
  assert.equal(fs.readFileSync(path.join(tmp, 'opt/d2k/state/shadow.d2km'), 'utf8'), 'shadow knowledge', 'keep-state preserves independent shadow knowledge');
  for (const binary of ['d2kd','d2kc','d2kpanel','d2ktg']) assert(!fs.existsSync(path.join(runtime, `${binary}.health`)), 'uninstall must remove owned heartbeat');
  assert(!fs.existsSync(path.join(runtime, 'log-tail.ABCDEF')), 'uninstall must remove owned abandoned stage');
  assert.equal(fs.readFileSync(path.join(runtime, 'unrelated'), 'utf8'), 'keep');
  assert(!fs.existsSync(path.join(customRuntime, 'live.json')), 'missing-init uninstall must remove configured custom snapshot');
  assert(!fs.existsSync(path.join(customRuntime, 'log-tail.QRSTUV')), 'missing-init uninstall must remove custom abandoned stage');
  assert.equal(fs.readFileSync(path.join(customRuntime, 'unrelated'), 'utf8'), 'keep');
  assert.equal(fs.readFileSync(state, 'utf8'), '{"learned":true}', 'keep-state must preserve catalog');
  assert(fs.readFileSync(path.join(tmp, 'calls'), 'utf8').includes('d2k-log-maintenance.pid'), 'uninstall fallback must stop owned helper');

  const config = path.join(tmp, 'opt/d2k/config');
  const protectedRuntime = path.join(tmp, 'protected-runtime'); fs.mkdirSync(protectedRuntime);
  fs.writeFileSync(path.join(protectedRuntime, 'live.json'), 'keep');
  const linkedRuntime = path.join(tmp, 'linked-runtime'); fs.symlinkSync(protectedRuntime, linkedRuntime);
  fs.mkdirSync(path.join(protectedRuntime, 'child'));
  for (const value of [linkedRuntime, `${protectedRuntime}/child/..`, `/tmp`, `$(touch ${tmp}/executed)`]) {
    fs.appendFileSync(config, `D2K_RUNTIME_DIR=${value}\n`);
    run('uninstall');
    assert.equal(fs.readFileSync(path.join(protectedRuntime, 'live.json'), 'utf8'), 'keep', 'unsafe custom runtime must be preserved');
    assert(!fs.existsSync(path.join(tmp, 'executed')), 'runtime cleanup must never evaluate configuration');
  }
  const envRuntime = path.join(tmp, 'env-runtime'); fs.mkdirSync(envRuntime);
  fs.writeFileSync(path.join(envRuntime, 'live.json'), '{}');
  run('uninstall', { D2K_RUNTIME_DIR: envRuntime });
  assert(!fs.existsSync(envRuntime), 'explicit valid environment runtime must be cleaned and removed when empty');
  console.log('local installer/helper and keep-state uninstall: PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
