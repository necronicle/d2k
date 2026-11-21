#!/usr/bin/env node
// scripts/install.sh: ручная установка ставит ПОДПИСАННЫЙ выпуск.
//
// До 14.10.2026 она брала бинарники из builds/ ветки main, а их обновлял
// человек: 13.10 ручная установка ставила движок от 12.10 под службу и
// страницы панели от 13.10, и подписи на этом пути не было вовсе. Теперь
// источник один и тот же у руки и у ночного обновления.
//
// Проверяется на самой трудной системе — чистая OpenWrt 25.12, где нет ни
// curl, ни openssl: пакеты обязаны встать ДО проверки подписи, иначе её
// нечем делать. И на Keenetic, где оба уже есть.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');

const engineFixture = require('./test-engine-fixture.cjs');
const root = path.resolve(__dirname, '..');
const tmp = fs.realpathSync(fs.mkdtempSync('/tmp/install-release-test.'));
const sh = (body) => `#!/bin/sh\n${body}\n`;
function put(file, contents, mode = 0o755) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents, { mode });
}
try {
  // OpenSSL 3: pkeyutl -rawin для Ed25519 (у macOS свой LibreSSL без него).
  const openssl = ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl', '/usr/bin/openssl']
    .find(p => fs.existsSync(p) && /OpenSSL 3/.test(execFileSync(p, ['version']).toString()));
  assert(openssl, 'нужен OpenSSL 3');

  // Образ: обычные утилиты, минус всё, что даёт заглушка.
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
  const bin = path.join(tmp, 'bin');
  const log = (name) => path.join(tmp, `${name}.log`);
  const src = path.join(tmp, 'source');
  put(path.join(bin, 'ip'), sh('exit 0'));
  put(path.join(bin, 'start-stop-daemon'), sh('exit 0'));
  put(path.join(bin, 'nft'), sh('exit 0'));
  put(path.join(bin, 'df'), sh(`echo 'Filesystem 1024-blocks Used Available Capacity Mounted on'
echo "/dev/root 100692 18544 \${DF_AVAIL:-80020} 19% /"`));
  // Загрузчик: адрес → файл из source/, как отдал бы GitHub. Пишет в свой
  // журнал, чтобы было видно, чем и в каком порядке шла загрузка.
  // Попытка через проводник (--proxy) пишется в свой журнал «<имя>-gate»;
  // GATE_DOWN=1 роняет её, как недоступный VPS, — тогда следует прямая.
  const fetcher = (name, outFlag) => sh(`out= url= proxy=
while [ $# -gt 0 ]; do case "$1" in ${outFlag}) out=$2; shift 2 ;; --proxy) proxy=$2; shift 2 ;;
  --max-time|--connect-timeout|-T) shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done
if [ -n "$proxy" ]; then
  printf '%s %s\\n' "$proxy" "$url" >> '${log(name + '-gate')}'
  [ -z "\${GATE_DOWN:-}" ] || exit 7
fi
printf '%s\\n' "$url" >> '${log(name)}'
cp "${src}/\${url#http://fixture.test/}" "$out" 2>/dev/null || exit 22`);
  put(path.join(tmp, 'curl-double'), fetcher('curl', '-o'));
  put(path.join(bin, 'wget'), fetcher('wget', '-O'));
  // apk чистой 25.12: ставит ровно то, что просят. curl — заглушка, openssl —
  // настоящий: подпись, которую проверяет пустышка, не проверена никем.
  put(path.join(bin, 'apk'), sh(`if [ "$1" = --repositories-file ]; then
  printf '%s %s\\n' "\${http_proxy:-}" "$3" >> '${log('apk-gate')}'
  cp "$2" '${log('apk-gate-feeds')}'
  [ -z "\${GATE_DOWN:-}" ] || exit 1
  shift 2
fi
printf '%s\\n' "$*" >> '${log('apk')}'
case "$1" in
  --print-arch) printf 'x86_64\\n' ;;
  info) shift; [ "$1" = -e ] && shift
        case " \${APK_HAVE:-} " in *" $1 "*) exit 0 ;; esac; exit 1 ;;
  add) shift
       for p in "$@"; do
         case "$p" in
           curl) cp '${path.join(tmp, 'curl-double')}' '${bin}/curl' ;;
           openssl-util) ln -sf '${openssl}' '${bin}/openssl' ;;
         esac
       done ;;
esac
exit 0`));

  // Комплект выпуска: те же пути, что в scripts/package-release.sh.
  const fixture = (name, contents, mode = 0o755) => put(path.join(src, name), contents, mode);
  fixture('scripts/architecture.sh',
    sh('printf "arch %s %s\\n" "$1" "$2" >> "$CALLS"; printf "amd64\\n"'));
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
  fixture('builds/d2kfetch-linux-amd64', sh('echo d2kfetch ${D2K_RELEASE_ID:-dev}'));
  fixture('files/S99d2k', sh(`printf 'service-%s\\n' "$1" >> "$CALLS"
if [ "$1" = start ]; then
  if [ -n "\${UPDATE_STAGE:-}" ] && [ -e "$UPDATE_STAGE" ]; then echo update-work-at-start >> "$CALLS"; fi
  for w in "$HOME"/runtime-install.*; do
    [ ! -d "$w" ] || echo installer-work-at-start >> "$CALLS"
  done
fi
[ "$1" != status ] || echo "датапат: работает"
exit 0`));
  fixture('files/config', 'PANEL_LISTEN=192.168.1.1:8090\nTG_ENABLED=0\nTG_RELAY_URL=wss://example.test/ws\n');
  fixture('files/d2k-ppe-deoffload.sh', sh('d2k_ppe_remove() { :; }'));
  for (const name of ['d2k-fw-heal.sh', '001-d2k.sh', 'd2k-tg-firewall.sh', 'd2k-tg-watchdog.sh',
    'd2k-instagram-dns-scheduler.sh', 'd2k-instagram-dns.sh', 'd2k-log-maintenance.sh', 'd2k-update.sh']) fixture(`files/${name}`, sh('exit 0'));
  fixture('files/d2k-openwrt-init', fs.readFileSync(path.join(root, 'files/d2k-openwrt-init'), 'utf8')
    .replaceAll('/etc/rc.common', path.join(tmp, 'etc/rc.common')));
  for (const name of ['meta-ranges.txt', 'tg-roots.pem', 'fake/stun.bin', 'fake/quic_initial_dbankcloud_ru.bin']) fixture(`files/${name}`, 'fixture\n');
  for (const name of ['index.html', 'favicon.svg', 'panel.css', 'panel.js', 'diagnostics.js', 'gsap.js', 'fonts/onest.woff2',
    'fonts/OFL-onest.txt', 'fonts/jbmono.woff2', 'fonts/OFL-jbmono.txt']) fixture(`internal/web/assets/${name}`, 'fixture\n');

  // Система: чистый образ 25.12 с nfnetlink_queue и без iptables.
  put(path.join(tmp, 'proc/net/netfilter/nfnetlink_queue'), '', 0o644);
  const release = path.join(tmp, 'etc/openwrt_release');
  put(release, "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='25.12.5'\nDISTRIB_ARCH='x86_64'\n", 0o644);
  put(path.join(tmp, 'lib/functions/procd.sh'), '# fixture\n', 0o644);
  put(path.join(tmp, 'etc/rc.common'), sh('exit 0'));
  fs.mkdirSync(path.join(tmp, 'etc/init.d'), { recursive: true });

  // Установщик под этот корень: тот же код, другие пути.
  const runtime = path.join(tmp, 'runtime');
  const installer = fs.readFileSync(path.join(root, 'scripts/install.sh'), 'utf8')
    .replaceAll('/opt', path.join(tmp, 'opt'))
    .replaceAll('/etc/openwrt_release', release)
    .replaceAll('/etc/rc.common', path.join(tmp, 'etc/rc.common'))
    .replaceAll('/etc/init.d/d2k', path.join(tmp, 'etc/init.d/d2k'))
    .replaceAll('/lib/functions/procd.sh', path.join(tmp, 'lib/functions/procd.sh'))
    .replaceAll('/proc/', `${path.join(tmp, 'proc')}/`)
    .replaceAll('/tmp/d2k', runtime);
  fs.writeFileSync(path.join(tmp, 'install.sh'), installer);
  // В архиве лежит он же: выпуск ставит СВОЙ установщик, не чужой.
  fixture('scripts/install.sh', installer);

  // Выпуск: архив арки, перечень с его sha256 и подпись перечня.
  const keyPem = path.join(tmp, 'key.pem');
  execFileSync(openssl, ['genpkey', '-algorithm', 'ED25519', '-out', keyPem]);
  const pub = execFileSync(openssl, ['pkey', '-in', keyPem, '-pubout']).toString()
    .split('\n').filter(l => l && !l.startsWith('-----')).join('');
  const rid = 'd2k-20261014-0900-abcdef0';
  function publish({ sum, arch = 'amd64', sign = true } = {}) {
    const tar = path.join(src, rid, 'd2k-amd64.tar.gz');
    fs.mkdirSync(path.dirname(tar), { recursive: true });
    execFileSync('tar', ['-czf', tar, '-C', src, 'builds', 'scripts', 'files', 'internal', 'core']);
    const real = execFileSync(openssl, ['dgst', '-sha256', '-r', tar]).toString().split(' ')[0];
    const latest = path.join(src, 'latest/latest.json');
    fs.mkdirSync(path.dirname(latest), { recursive: true });
    fs.writeFileSync(latest, `{"release_id":"${rid}","version":"14.10","notes":"проверка",` +
      `"assets":{"${arch}":{"sha256":"${sum || real}"}}}\n`);
    execFileSync(openssl, ['pkeyutl', '-sign', '-inkey', keyPem, '-rawin', '-in', latest, '-out', latest + '.sig']);
    if (!sign) {
      const bad = fs.readFileSync(latest + '.sig');
      bad[0] ^= 0xff;
      fs.writeFileSync(latest + '.sig', bad);
    }
  }
  publish();

  const calls = path.join(tmp, 'calls');
  const env = {
    PATH: `${bin}:${sys}`, HOME: tmp, CALLS: calls, D2K_KEEP_STATE: '1',
    D2K_BASE: 'http://fixture.test',
    D2K_UPDATE_LATEST: 'http://fixture.test/latest', D2K_UPDATE_DOWNLOAD: 'http://fixture.test',
    D2K_UPDATE_KEY: pub,
    D2K_OPENWRT_APK: path.join(bin, 'apk'), D2K_OPENWRT_OPKG: path.join(tmp, 'no-opkg'),
  };
  const read = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
  const reset = () => { for (const f of [calls, log('apk'), log('wget'), log('curl'), log('curl-gate'),
    log('apk-gate'), log('apk-gate-feeds')]) fs.rmSync(f, { force: true }); };
  const run = (extra = {}) => spawnSync('/bin/sh', [path.join(tmp, 'install.sh')],
    { env: { ...env, ...extra }, encoding: 'utf8', timeout: 30000 });
  const ok = (r) => { assert.equal(r.status, 0, r.stderr || r.stdout); return r.stdout + r.stderr; };
  const d2kd = path.join(tmp, 'opt/sbin/d2kd');
  const releaseId = path.join(tmp, 'opt/d2k/release-id');

  // 1. Чистая 25.12 без curl и openssl: пакеты, затем подписанный выпуск.
  reset();
  const fresh = ok(run());
  assert(!read(calls).includes('installer-work-at-start'), 'signed installer must release downloaded and unpacked copies before service startup');
  assert.match(read(log('apk')), /^add kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle curl openssl-util$/m,
    'пакеты ставятся до проверки подписи: без openssl её нечем делать');
  // Два скрипта определения арки — wget из образа (curl ещё нет), всё
  // остальное — curl, уже из пакетов. Порядок виден по журналам.
  assert.deepEqual(read(log('wget')).trim().split('\n').sort(),
    ['http://fixture.test/scripts/architecture.sh', 'http://fixture.test/scripts/check-cpu.sh'],
    'до пакетов качается только определение арки');
  assert.deepEqual(read(log('curl')).trim().split('\n'),
    ['http://fixture.test/latest/latest.json', 'http://fixture.test/latest/latest.json.sig',
      `http://fixture.test/${rid}/d2k-amd64.tar.gz`],
    'выпуск берётся перечнем, подписью и архивом — в этом порядке');
  // Каждая загрузка выпуска сперва идёт через проводник на VPS (CONNECT).
  const GATE = 'http://85.192.60.175:9444';
  const releaseUrls = ['http://fixture.test/latest/latest.json', 'http://fixture.test/latest/latest.json.sig',
    `http://fixture.test/${rid}/d2k-amd64.tar.gz`];
  assert.deepEqual(read(log('curl-gate')).trim().split('\n'), releaseUrls.map((u) => `${GATE} ${u}`),
    'выпуск сперва качается через проводник на VPS');
  assert.match(fresh, /подпись сошлась/, 'установка должна сказать, что подпись проверена');
  assert(fs.existsSync(d2kd), 'комплект должен встать');
  assert(fs.existsSync(path.join(tmp, 'opt/sbin/d2kfetch')), 'прибор устанавливается вместе с выпуском');
  assert.equal(read(releaseId).trim(), rid,
    'номер выпуска пишется на роутер: иначе ночное обновление поставит то же самое заново');
  assert.equal(read(path.join(tmp, 'opt/d2k/release-arch')).trim(), 'amd64');
  // Комплект раскладывает установщик ИЗ архива, а не этот: арку он считает
  // второй раз, уже файлом из подписанного дерева.
  assert.equal(read(calls).match(/^arch /gm).length, 2,
    'установщик из архива определяет арку сам');
  assert(read(calls).includes('service-start'), 'служба должна запуститься');

  // The updater registered this installer PID against its verified, disposable release.
  const work = path.join(tmp, 'runtime-update');
  const stage = path.join(work, 'release');
  const claim = path.join(work, `lock.${process.pid}`);
  fs.mkdirSync(stage, { recursive: true });
  fs.mkdirSync(claim, { mode: 0o700 });
  fs.symlinkSync(path.basename(claim), path.join(work, 'lock'));
  put(path.join(claim, 'pid'), String(process.pid));
  put(path.join(work, 'previous.tar'), 'rollback copy');
  execFileSync('tar', ['-xzf', path.join(src, rid, 'd2k-amd64.tar.gz'), '-C', stage]);
  function applyUpdate(register) {
    return spawnSync('/bin/sh', ['-c',
      `echo "${register ? '$$' : '1'}" > "$1/installer"; exec sh "$D2K_LOCAL/scripts/install.sh" --verified-update "$PPID"`,
      'sh', claim], { env: { ...env, D2K_LOCAL: stage, D2K_UPDATING: '1', D2K_RELEASE_ID: rid, UPDATE_STAGE: stage },
      encoding: 'utf8', timeout: 30000 });
  }
  assert.notEqual(applyUpdate(false).status, 0, 'refuse to consume a caller bundle without the registered installer PID');
  assert(fs.existsSync(path.join(stage, 'builds/d2kd-linux-amd64')), 'unclaimed local source must remain intact');
  reset();
  const copy = path.join(bin, 'cp');
  put(copy, sh('case "$1" in "$UPDATE_STAGE"/builds/*) exit 1 ;; esac\nexec /bin/cp "$@"'));
  ok(applyUpdate(true));
  fs.unlinkSync(copy);
  assert(!read(calls).includes('update-work-at-start'), 'dispose of the updater release before service start');
  assert(!fs.existsSync(stage));
  assert.equal(read(path.join(work, 'previous.tar')), 'rollback copy');
  assert(fs.existsSync(path.join(work, 'lock')), 'the updater retains its lock');

  // Installed releases before the workspace handoff used a directory lock and
  // kept both archives beside the extracted tree. Unknown parents still own their inputs.
  const legacyLock = path.join(work, 'lock');
  fs.unlinkSync(legacyLock);
  fs.mkdirSync(legacyLock);
  put(path.join(legacyLock, 'pid'), String(process.pid), 0o600);
  fs.mkdirSync(stage);
  const tarball = path.join(work, 'release.tar.gz');
  fs.copyFileSync(path.join(src, rid, 'd2k-amd64.tar.gz'), tarball);
  execFileSync('tar', ['-xzf', tarball, '-C', stage]);
  const legacyProc = path.join(tmp, 'proc', String(process.pid), 'cmdline');
  const oldUpdater = path.join(tmp, 'opt/d2k/d2k-update.sh');
  const runLegacy = () => spawnSync('/bin/sh', [path.join(stage, 'scripts/install.sh')], {
    env: { ...env, D2K_LOCAL: stage, D2K_UPDATING: '1', D2K_RELEASE_ID: rid, UPDATE_STAGE: stage },
    encoding: 'utf8', timeout: 30000,
  });
  put(legacyProc, ['/bin/sh', oldUpdater, 'check', ''].join('\0'), 0o600);
  ok(runLegacy());
  assert(fs.existsSync(path.join(stage, 'builds/d2kd-linux-amd64')) && fs.existsSync(tarball),
    'an unrelated caller must retain its inputs and installation must still succeed');
  put(legacyProc, ['/bin/sh', oldUpdater, 'install', 'manual', ''].join('\0'), 0o600);
  reset();
  ok(runLegacy());
  assert(!read(calls).includes('update-work-at-start'), 'reclaim the legacy updater release before service start');
  assert(!fs.existsSync(tarball) && !fs.existsSync(stage), 'drop both verified legacy copies');
  assert.equal(read(path.join(work, 'previous.tar')), 'rollback copy');
  assert.equal(read(path.join(legacyLock, 'pid')), String(process.pid));

  // A failed legacy install must clean its moved tree even if a retry creates
  // a fresh release/ under the old name before the first child returns.
  fs.mkdirSync(stage);
  fs.copyFileSync(path.join(src, rid, 'd2k-amd64.tar.gz'), tarball);
  execFileSync('tar', ['-xzf', tarball, '-C', stage]);
  fs.rmSync(path.join(stage, 'builds/d2kd-linux-amd64'));
  const move = path.join(bin, 'mv');
  put(move, sh(`if [ "$1" = "$UPDATE_STAGE" ]; then
    /bin/mv "$@" && mkdir "$UPDATE_STAGE" && echo retry > "$UPDATE_STAGE/owner"
    exit $?
  fi
  exec /bin/mv "$@"`));
  assert.notEqual(runLegacy().status, 0);
  fs.unlinkSync(move);
  assert.equal(read(path.join(stage, 'owner')), 'retry\n');
  assert(!fs.readdirSync(work).some(n => n.startsWith('.d2k-install.')), 'failed installer must remove its private stage');
  assert.equal(read(path.join(work, 'previous.tar')), 'rollback copy');

  // 2. Подпись не сошлась: прежняя версия остаётся как была.
  // A mismatched tool must fail before stopping the installed service.
  fixture('builds/d2kfetch-linux-amd64', sh('echo d2kfetch wrong-release'));
  publish(); reset();
  const wrongFetch = run({ GATE_DOWN: '1' });
  assert.notEqual(wrongFetch.status, 0);
  assert.match(wrongFetch.stdout + wrongFetch.stderr, /версия прибора не совпадает/);
  assert(!read(calls).includes('service-stop'), 'отказ версии прибора до остановки службы');
  fixture('builds/d2kfetch-linux-amd64', sh('echo d2kfetch ${D2K_RELEASE_ID:-dev}'));

  const before = fs.readFileSync(d2kd);
  for (const [controller, datapath] of [
    [engineFixture('d2kc', rid), engineFixture('d2kd', 'dev')],
    [engineFixture('d2kc', rid, 32), engineFixture('d2kd', rid, 33)],
    [engineFixture('d2kc', 'dev'), engineFixture('d2kd', 'dev')],
    [engineFixture('d2kc', rid, ''), engineFixture('d2kd', rid, '')],
  ]) {
    fixture('builds/d2kc-linux-amd64', controller);
    fixture('builds/d2kd-linux-amd64', datapath);
    publish();
    reset();
    const mixed = run();
    assert.notEqual(mixed.status, 0, 'несовместимый комплект должен быть отклонён');
    assert.match(mixed.stdout + mixed.stderr, /верси[яи] движка/);
    assert(!read(calls).includes('service-stop'), 'отказ до остановки службы');
    assert.deepEqual(fs.readFileSync(d2kd), before);
  }
  fixture('builds/d2kc-linux-amd64', engineFixture('d2kc'));
  fixture('builds/d2kd-linux-amd64', engineFixture('d2kd'));

  publish({ sign: false });
  reset();
  let bad = run();
  assert.notEqual(bad.status, 0, 'подложная подпись обязана отказать');
  assert.match(bad.stdout + bad.stderr, /подпись выпуска не сошлась/, bad.stdout + bad.stderr);
  assert(!read(calls).includes('service-stop'), 'служба не останавливается');
  assert.deepEqual(fs.readFileSync(d2kd), before, 'бинарники не подменяются');

  // 3. Хеш архива не тот, что в подписанном перечне.
  publish({ sum: 'f'.repeat(64) });
  reset();
  bad = run();
  assert.notEqual(bad.status, 0, 'чужой архив обязан отказать');
  assert.match(bad.stdout + bad.stderr, /не совпал с подписанным хешем/, bad.stdout + bad.stderr);
  assert.deepEqual(fs.readFileSync(d2kd), before, 'бинарники не подменяются');

  // 4. В выпуске нет сборки для этой арки — отказ называет арку.
  publish({ arch: 'riscv64' });
  reset();
  bad = run();
  assert.notEqual(bad.status, 0);
  assert.match(bad.stdout + bad.stderr, /нет сборки для amd64/, bad.stdout + bad.stderr);

  // 5. Места в /tmp хватает на раскладку, но не на выпуск: отказ ДО загрузки.
  //    Установка выпуска держит там распакованное дерево и раскладку поверх
  //    него, то есть вдвое больше, чем установка из каталога.
  publish();
  reset();
  bad = run({ DF_AVAIL: '12000' });
  assert.notEqual(bad.status, 0, 'нехватка места под выпуск обязана отказать');
  assert.match(bad.stdout + bad.stderr, /мало места для загрузки/, bad.stdout + bad.stderr);
  assert.equal(read(log('curl')), '', 'отказ до первого байта выпуска');

  // 6. Система, где curl и openssl уже есть (Keenetic с Entware, OpenWrt с
  //    поставленными пакетами): менеджер пакетов не трогается, подпись
  //    проверяется тем же путём.
  const have = 'kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle curl openssl-util';
  reset();
  ok(run({ APK_HAVE: have }));
  assert.doesNotMatch(read(log('apk')), /^add/m, 'поставленные пакеты не ставятся заново');
  assert.equal(read(releaseId).trim(), rid);

  // 7. Ветка как источник разработчика: подписи нет, бинарники из builds/.
  reset();
  ok(run({ D2K_SOURCE: 'ref', APK_HAVE: have }));
  assert(read(log('curl')).includes('http://fixture.test/builds/d2kd-linux-amd64'),
    'D2K_SOURCE=ref берёт бинарники из builds/ ветки');
  assert.equal(read(releaseId).trim(), '', 'установка из ветки номера выпуска не знает');

  // 8. Проводник недоступен: каждая загрузка повторяется напрямую, установка
  //    не страдает.
  reset();
  ok(run({ GATE_DOWN: '1' }));
  // curl к этому случаю уже «поставлен» прошлым прогоном, поэтому через него
  // идёт и определение арки: проверяется каждая загрузка, а не только выпуск.
  const direct = read(log('curl')).trim().split('\n');
  assert.deepEqual(read(log('curl-gate')).trim().split('\n'), direct.map((u) => `${GATE} ${u}`),
    'каждой прямой загрузке предшествует попытка через проводник');
  for (const u of releaseUrls) assert(direct.includes(u), `после отказа проводника — напрямую: ${u}`);
  assert.equal(read(releaseId).trim(), rid, 'упавший проводник не мешает установке');

  // 9. D2K_GATE= — без проводника: только напрямую.
  reset();
  ok(run({ D2K_GATE: '' }));
  assert.equal(read(log('curl-gate')), '', 'пустой D2K_GATE выключает проводник');
  for (const u of releaseUrls) assert(read(log('curl')).includes(u), `напрямую: ${u}`);

  // 10. Пакеты OpenWrt через проводник: в попытке только штатные зеркала
  //     downloads.openwrt.org, переписанные на http:// (подписи сверяет apk);
  //     чужой источник в неё не попадает.
  const apkEtc = path.join(tmp, 'apk-etc');
  put(path.join(apkEtc, 'repositories.d/distfeeds.list'),
    'https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/packages/packages.adb\n' +
    'https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/base/packages.adb\n', 0o644);
  put(path.join(apkEtc, 'repositories.d/customfeeds.list'),
    '# add your custom package feeds here\nhttps://example.org/feed/packages.adb\n', 0o644);
  reset();
  ok(run({ D2K_OPENWRT_APK_ETC: apkEtc }));
  assert.match(read(log('apk-gate')), new RegExp(`^${GATE} update$`, 'm'), 'индекс — через проводник');
  assert.match(read(log('apk-gate')),
    new RegExp(`^${GATE} add$`, 'm'), 'пакеты — через проводник');
  assert.equal(read(log('apk-gate-feeds')),
    'http://downloads.openwrt.org/releases/25.12.5/targets/x86/64/packages/packages.adb\n' +
    'http://downloads.openwrt.org/releases/25.12.5/packages/x86_64/base/packages.adb\n',
    'в попытке через проводник — только штатные зеркала по http://');
  assert.match(read(log('apk')), /^add kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle/m);
  assert.equal(read(releaseId).trim(), rid);

  // 11. Проводник лёг и для пакетов: apk ставит напрямую, как прежде.
  reset();
  ok(run({ D2K_OPENWRT_APK_ETC: apkEtc, GATE_DOWN: '1' }));
  assert.match(read(log('apk-gate')), new RegExp(`^${GATE} update$`, 'm'), 'попытка через проводник была');
  assert.match(read(log('apk')), /^add kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink ca-bundle/m,
    'после отказа проводника пакеты ставятся напрямую');
  assert.equal(read(releaseId).trim(), rid);

  // Older signed installers expect a caller-owned D2K_LOCAL and return their own status.
  fixture('scripts/install.sh', sh('[ -s "$D2K_LOCAL/builds/d2kd-linux-amd64" ] || exit 1\nexit 37'));
  publish();
  assert.equal(run().status, 37, 'bootstrap must propagate an older installer failure');
  assert(!fs.readdirSync(tmp).some(n => n.startsWith('runtime-install.')), 'bootstrap must reclaim older release staging');

  console.log('install: signed release, bad signature, bad hash, missing arch, /tmp room, Keenetic, ref, VPS gate: PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
