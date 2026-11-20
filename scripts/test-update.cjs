#!/usr/bin/env node
// files/d2k-update.sh: подпись выпуска, установка из архива выпуска,
// проверка служб, возврат прежней версии при отказе.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');

const updater = path.resolve(__dirname, '../files/d2k-update.sh');
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'd2k-update-test.')));
const feed = path.join(tmp, 'feed');
const stub = path.join(tmp, 'stub');
const dir = path.join(tmp, 'opt/d2k');
const sbin = path.join(tmp, 'opt/sbin');
const init = path.join(tmp, 'S99d2k');
const initLog = path.join(tmp, 'init.log');
for (const d of [feed, stub, dir, sbin, path.join(dir, 'state'), path.join(dir, 'run'), path.join(dir, 'panel')]) fs.mkdirSync(d, { recursive: true });

// OpenSSL 3: pkeyutl -rawin для Ed25519 (у macOS свой LibreSSL без него).
const openssl = ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl', '/usr/bin/openssl']
  .find(p => fs.existsSync(p) && /OpenSSL 3/.test(execFileSync(p, ['version']).toString()));
assert(openssl, 'нужен OpenSSL 3');
fs.symlinkSync(openssl, path.join(stub, 'openssl'));
// curl: адрес → файл из feed/, как отдал бы GitHub.
fs.writeFileSync(path.join(stub, 'curl'), `#!/bin/sh
out=; url=; proxy=
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; --proxy) proxy=$2; shift 2 ;; --proto|--max-time|--connect-timeout) shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done
# Попытка через проводник на VPS — в свой журнал; GATE_DOWN=1 её роняет.
if [ -n "$proxy" ]; then echo "$proxy $url" >> "${feed}/../gate.log"; [ -z "\${GATE_DOWN:-}" ] || exit 7; fi
f="${feed}/\${url#https://example.test/}"
[ -f "$f" ] || exit 22
cp "$f" "$out"
`, { mode: 0o755 });
fs.writeFileSync(init, `#!/bin/sh\necho "$1" >> "${initLog}"\n[ "$1" != stop ] || [ "\${FAIL_STOP:-0}" != 1 ]\n`, { mode: 0o755 });

const keyPem = path.join(tmp, 'key.pem');
execFileSync(openssl, ['genpkey', '-algorithm', 'ED25519', '-out', keyPem]);
const pub = execFileSync(openssl, ['pkey', '-in', keyPem, '-pubout']).toString()
  .split('\n').filter(l => l && !l.startsWith('-----')).join('');

// Живой «процесс службы» для проверки после установки.
const live = spawnSync('/bin/sh', ['-c', 'sleep 300 >/dev/null 2>&1 & echo $!'], { encoding: 'utf8' }).stdout.trim();
const liveController = spawnSync('/bin/sh', ['-c', 'sleep 300 >/dev/null 2>&1 & echo $!'], { encoding: 'utf8' }).stdout.trim();
const dead = '999999';

// Выпуск: архив с «установщиком», который заменяет файлы и пишет pid-файлы.
function release(id, { installOk = true, pid = live } = {}) {
  const src = path.join(tmp, 'src-' + id);
  fs.mkdirSync(path.join(src, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(src, 'scripts/install.sh'), `#!/bin/sh
printf '%s\\n' "$0" > "${tmp}/installer-path"
printf '%s\\n' "$D2K_RELEASE_ID" > "${dir}/release-id"
printf 'binary ${id}\\n' > "${sbin}/d2kd"
printf 'controller ${id}\\n' > "${sbin}/d2kc"
printf 'fetch ${id}\\n' > "${sbin}/d2kfetch"
printf 'panel ${id}\\n' > "${dir}/panel/index.html"
echo ${pid} > "${dir}/run/d2kd.pid"; echo ${pid === dead ? dead : liveController} > "${dir}/run/d2k.pid"
exit ${installOk ? 0 : 1}
`);
  fs.mkdirSync(path.join(feed, id), { recursive: true });
  const tar = path.join(feed, id, 'd2k-arm64.tar.gz');
  execFileSync('tar', ['-czf', tar, '-C', src, 'scripts']);
  const sum = execFileSync(openssl, ['dgst', '-sha256', '-r', tar]).toString().split(' ')[0];
  const latest = path.join(feed, 'latest/latest.json');
  fs.mkdirSync(path.dirname(latest), { recursive: true });
  fs.writeFileSync(latest, JSON.stringify({ release_id: id, version: id, notes: 'Новое "в" выпуске', assets: { arm64: { sha256: sum } } }) + '\n');
  execFileSync(openssl, ['pkeyutl', '-sign', '-inkey', keyPem, '-rawin', '-in', latest, '-out', latest + '.sig']);
}

const proc = path.join(tmp, 'proc'), runtime = path.join(tmp, 'runtime');
fs.mkdirSync(path.join(proc, 'sys/kernel/random'), { recursive: true });
fs.mkdirSync(runtime);
fs.writeFileSync(path.join(proc, 'sys/kernel/random/boot_id'), 'test-boot\n');
fs.writeFileSync(path.join(proc, 'uptime'), '100.00 0\n');
const heartbeat = path.join(tmp, 'heartbeat.cjs');
fs.writeFileSync(heartbeat, `
const fs = require('node:fs'), path = require('node:path');
const dir=${JSON.stringify(dir)}, proc=${JSON.stringify(proc)}, runtime=${JSON.stringify(runtime)}, sbin=${JSON.stringify(sbin)};
const mode=process.env.HEALTH_FAULT || '';
const release=fs.readFileSync(path.join(dir,'release-id'),'utf8').trim();
for (const [name,pidfile] of [['d2kd','d2kd.pid'],['d2kc','d2k.pid']]) {
 const pid=fs.readFileSync(path.join(dir,'run',pidfile),'utf8').trim();
 fs.mkdirSync(path.join(proc,pid),{recursive:true});
 fs.writeFileSync(path.join(proc,pid,'stat'),pid+' ('+name+') S '+Array(18).fill('0').join(' ')+' 99\\n');
 const exe=path.join(proc,pid,'exe');try {fs.unlinkSync(exe);} catch {}
 fs.symlinkSync(path.join(sbin,name),exe);
 const file=path.join(runtime,name+'.health');
 let stamp=99000;try {stamp=Math.max(99000,Number(fs.readFileSync(file,'utf8').split(' ')[3])+1);} catch {}
 if(mode==='stalled')stamp=99000;
 if(mode==='stale')stamp=1;
 if(mode==='exe') { fs.unlinkSync(exe); fs.symlinkSync(path.join(dir,'config'),exe); }
 const start=mode==='incarnation'?98:99;
 const peer=mode==='peer'?'wrong':release;
 const rid=mode==='release'?'old':release;
 const boot=mode==='boot'?'old-boot':'test-boot';
 const wire=mode==='wire' && name==='d2kc'?27:28;
 const ready=mode==='ready'?0:1;
 fs.writeFileSync(file,'D2KH1 '+pid+' '+start+' '+stamp+' '+boot+' '+rid+' '+wire+' '+(name==='d2kc'?peer:'-')+' '+(name==='d2kc'?1:0)+' '+ready+' 0\\n');
}
`);
fs.writeFileSync(path.join(stub,'sleep'), '#!/bin/sh\n[ "$1" != 1 ] || exec /bin/sleep "$@"\nexec '+JSON.stringify(process.execPath)+' '+JSON.stringify(heartbeat)+'\n', {mode:0o755});

const env = {
  ...process.env, D2K_PROC_DIR: proc, D2K_RUNTIME_DIR: runtime, D2K_STUB_PATH: stub, D2K_DIR: dir, D2K_SBIN: sbin, D2K_INIT: init,
  D2K_NDM_HOOK: path.join(tmp, 'ndm-hook'), D2K_UPDATE_KEY: pub, D2K_UPDATE_HEALTH_WAIT: '0',
  D2K_UPDATE_LATEST: 'https://example.test/latest', D2K_UPDATE_DOWNLOAD: 'https://example.test',
};
const run = (...args) => spawnSync('/bin/sh', [updater, ...args], { env, encoding: 'utf8' });
const state = () => JSON.parse(fs.readFileSync(path.join(dir, 'state/update.json'), 'utf8'));
const read = p => fs.readFileSync(p, 'utf8');

try {
  fs.writeFileSync(path.join(dir, 'release-arch'), 'arm64\n');
  fs.writeFileSync(path.join(dir, 'release-id'), 'r1\n');
  fs.writeFileSync(path.join(dir, 'config'), 'MODE=apply\nPANEL_LISTEN=\n');
  const knowledge = '{"domain_observations":[{"proof":"keep"}],"boxes":[{"bindings":["keep"]}]}';
  fs.writeFileSync(path.join(dir, 'state/catalog.json'), knowledge);
  fs.writeFileSync(path.join(dir, 'state/dns-cache'), 'preserve-dns');
  fs.writeFileSync(path.join(sbin, 'd2kd'), 'binary r1\n');
  fs.writeFileSync(path.join(sbin, 'd2kc'), 'controller r1\n');
  fs.writeFileSync(path.join(dir, 'panel/index.html'), 'panel r1\n');

  // Проверка: подписанный выпуск виден, поддельный — нет.
  release('r2');
  assert.equal(run('check').status, 0);
  let s = state();
  assert.equal(s.check_ok, true); assert.equal(s.current, 'r1'); assert.equal(s.latest.release_id, 'r2');
  assert.equal(s.latest.notes, 'Новое "в" выпуске');
  fs.appendFileSync(path.join(feed, 'latest/latest.json'), ' ');
  assert.notEqual(run('check').status, 0, 'подделанный latest.json принят');
  s = state();
  assert.equal(s.check_ok, false); assert.match(s.check_error, /подпись/);
  assert.equal(s.latest.release_id, 'r2', 'прежние проверенные сведения потеряны');

  // Успешная установка: стоит новая версия, копии прежней не остаётся.
  release('r2');
  assert.equal(run('install').status, 0, read(path.join(dir, 'log/update.log')));
  s = state();
  assert.equal(s.last_ok, true); assert.equal(s.current, 'r2'); assert.equal(s.busy, '');
  assert.equal(read(path.join(sbin, 'd2kd')), 'binary r2\n');
  assert.equal(read(path.join(sbin, 'd2kfetch')), 'fetch r2\n', 'прибор возвращается вместе с контроллером');
  assert(!fs.existsSync(path.join(dir, '.update/previous.tar')), 'копия прежней версии осталась');
  assert(!fs.existsSync(path.join(dir, '.update/release')), 'распакованный выпуск остался');
  assert.equal(run('install').status, 0, 'повтор того же выпуска не сводится к «уже установлен»');
  assert(read(path.join(tmp, 'installer-path')).startsWith(path.join(dir, '.update') + '/'), 'Keenetic: рабочий каталог — /opt/d2k/.update');


  for (const fault of ['stale', 'stalled', 'incarnation', 'release', 'peer', 'exe', 'boot', 'wire', 'ready']) {
    release('bad-' + fault);
    const outcome = spawnSync('/bin/sh', [updater, 'install'], { env: { ...env, HEALTH_FAULT: fault }, encoding: 'utf8' });
    assert.notEqual(outcome.status, 0, 'unhealthy live PID accepted: ' + fault);
    assert.equal(state().current, 'r2', 'unhealthy release must roll back');
  }

  for (const [label, config] of [
    ['default-panel', 'MODE=apply\n'],
    ['panel', 'MODE=apply\nPANEL_LISTEN=192.168.1.1:8090\n'],
    ['spaced-panel', "MODE=apply\n  PANEL_LISTEN='192.168.1.1:8090' # enabled\n"],
    ['tg', 'MODE=apply\nPANEL_LISTEN=\nTG_ENABLED=1\n'],
    ['spaced-tg', 'MODE=apply\nPANEL_LISTEN=\n  TG_ENABLED=1 # enabled\n']
  ]) {
    fs.writeFileSync(path.join(dir, 'config'), config);
    release('missing-optional-' + label);
    assert.notEqual(run('install').status, 0, 'enabled component without health must prevent promotion: ' + label);
    assert.equal(state().current, 'r2');
    fs.writeFileSync(path.join(dir, 'config'), 'MODE=apply\nPANEL_LISTEN=\n');
  }

  release('bad-stop');
  assert.notEqual(spawnSync('/bin/sh', [updater, 'install'], {
    env: { ...env, HEALTH_FAULT: 'stale', FAIL_STOP: '1' }, encoding: 'utf8'
  }).status, 0);
  assert.equal(read(path.join(sbin, 'd2kd')), 'binary bad-stop\n', 'failed rollback stop must not overwrite running files');
  assert(fs.existsSync(path.join(dir, '.update/previous.tar')), 'failed stop must retain rollback archive');
  release('r2');
  assert.equal(run('install').status, 0);

  // Отказ установщика: прежняя версия возвращается целиком.
  release('r3', { installOk: false });
  fs.writeFileSync(initLog, '');
  assert.notEqual(run('install').status, 0);
  s = state();
  assert.equal(s.last_ok, false); assert.equal(s.bad_release, 'r3'); assert.equal(s.current, 'r2');
  assert.equal(read(path.join(sbin, 'd2kd')), 'binary r2\n');
  assert.equal(read(path.join(sbin, 'd2kfetch')), 'fetch r2\n', 'прибор возвращается вместе с контроллером');
  assert.equal(read(path.join(dir, 'panel/index.html')), 'panel r2\n');
  assert.deepEqual(read(initLog).trim().split('\n'), ['stop', 'start']);
  assert(!fs.existsSync(path.join(dir, '.update/previous.tar')));

  // Служба умерла после установки — тоже возврат.
  release('r4', { pid: dead });
  assert.notEqual(run('install').status, 0);
  assert.equal(state().bad_release, 'r4'); assert.equal(read(path.join(sbin, 'd2kd')), 'binary r2\n');
  assert.equal(read(path.join(sbin, 'd2kfetch')), 'fetch r2\n', 'прибор возвращается вместе с контроллером');

  // Не прошедший проверку выпуск ночью не ставится, вручную — да.
  release('r4');
  assert.notEqual(run('install').status, 0, 'ночная установка повторила плохой выпуск');
  assert.equal(read(path.join(sbin, 'd2kd')), 'binary r2\n');
  assert.equal(read(path.join(sbin, 'd2kfetch')), 'fetch r2\n', 'прибор возвращается вместе с контроллером');
  assert.equal(run('install', 'manual').status, 0);
  assert.equal(state().current, 'r4');

  // Тумблер пишет AUTOUPDATE в config и не трогает прочее.
  assert.equal(run('auto', 'off').status, 0);
  assert.equal(state().auto, false);
  assert.equal(read(path.join(dir, 'config')), 'MODE=apply\nPANEL_LISTEN=\nAUTOUPDATE=0\n');
  assert.equal(run('auto', 'on').status, 0);
  assert.equal(read(path.join(dir, 'config')), 'MODE=apply\nPANEL_LISTEN=\nAUTOUPDATE=1\n');
  assert.equal(state().auto, true);
  // Тумблер выключает ночную установку и у УЖЕ ИДУЩЕГО цикла (поле 10.10.2026):
  // run читал AUTOUPDATE один раз при старте, и «auto off» без перезапуска
  // цикла не мешал ночью поставить выпуск. Час — из файла, запуск установки —
  // запись вызова start-stop-daemon.
  {
    const clock = path.join(tmp, 'clock'); fs.mkdirSync(clock);
    const hour = path.join(tmp, 'hour'); fs.writeFileSync(hour, '12\n');
    const ssd = path.join(tmp, 'ssd.log');
    fs.writeFileSync(path.join(clock, 'date'),
      `#!/bin/sh\n[ "$1" = +%H ] && exec cat "${hour}"\nexec /bin/date "$@"\n`, { mode: 0o755 });
    fs.writeFileSync(path.join(clock, 'start-stop-daemon'),
      `#!/bin/sh\necho "$*" >> "${ssd}"\n`, { mode: 0o755 });
    const nightEnv = { ...env, D2K_STUB_PATH: `${clock}:${stub}`, D2K_UPDATE_TICK: '1' };
    const wait = ms => spawnSync('/bin/sleep', [String(ms / 1000)]);
    const loop = require('node:child_process').spawn('/bin/sh', [updater, 'run'], { env: nightEnv, stdio: 'ignore' });
    try {
      fs.rmSync(path.join(dir, '.update/night'), { force: true });
      wait(1500);
      assert.equal(spawnSync('/bin/sh', [updater, 'auto', 'off'], { env: nightEnv }).status, 0);
      fs.writeFileSync(hour, '03\n');
      for (let i = 0; i < 40 && !fs.existsSync(path.join(dir, '.update/night')); i++) wait(250);
      wait(1500);
      assert(fs.existsSync(path.join(dir, '.update/night')), 'ночной цикл не дошёл до окна 03:00');
      assert(!fs.existsSync(ssd), 'auto off не остановил ночную установку у идущего цикла');
      assert.match(read(path.join(dir, 'log/update.log')), /проверка: последний выпуск/,
        'при выключенной установке цикл не сделал ночную проверку');
    } finally {
      loop.kill('SIGTERM');
    }
    assert.equal(run('auto', 'on').status, 0);
  }
  // OpenWrt без USB (07.10.2026): /opt — флеш корня. Архив, распаковка и
  // копия прежней версии (~20 МБ) — в RAM, а не на флеш.
  {
    const ram = path.join(tmp, 'ram');
    const owrtRelease = path.join(tmp, 'openwrt_release'); fs.writeFileSync(owrtRelease, "DISTRIB_ID='OpenWrt'\n");
    const dfStub = path.join(tmp, 'dfstub'); fs.mkdirSync(dfStub);
    const df = (mnt) => fs.writeFileSync(path.join(dfStub, 'df'), `#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\necho "/dev/root 100 10 90 10% ${mnt}"\n`, { mode: 0o755 });
    const owrt = { ...env, D2K_STUB_PATH: `${dfStub}:${stub}`, D2K_OPENWRT_RELEASE: owrtRelease, D2K_UPDATE_RAM: ram };
    df('/');
    release('r5');
    assert.equal(spawnSync('/bin/sh', [updater, 'install'], { env: owrt, encoding: 'utf8' }).status, 0);
    assert(read(path.join(tmp, 'installer-path')).startsWith(ram + '/'), 'OpenWrt без USB: выпуск должен распаковываться в RAM');
    assert(!fs.existsSync(path.join(ram, 'previous.tar')) && !fs.existsSync(path.join(ram, 'release')), 'в RAM не осталось копий');
    df('/opt');
    release('r6');
    assert.equal(spawnSync('/bin/sh', [updater, 'install'], { env: owrt, encoding: 'utf8' }).status, 0);
    assert(read(path.join(tmp, 'installer-path')).startsWith(path.join(dir, '.update') + '/'), 'OpenWrt с USB под /opt: рабочий каталог на USB');
  }
  // Проводник на VPS: проверка выпуска сперва идёт через него, а когда он
  // недоступен — напрямую, без отказа.
  const gateLog = path.join(feed, '..', 'gate.log');
  fs.rmSync(gateLog, { force: true });
  assert.equal(run('check').status, 0);
  assert.match(read(gateLog), /^http:\/\/85\.192\.60\.175:9444 https:\/\/example\.test\/.*latest\.json$/m,
    'перечень выпуска сперва через проводник');
  fs.rmSync(gateLog, { force: true });
  assert.equal(spawnSync('/bin/sh', [updater, 'check'], { env: { ...env, GATE_DOWN: '1' }, encoding: 'utf8' }).status, 0,
    'упавший проводник не мешает проверке выпуска');
  assert.equal(state().check_ok, true);
  assert.match(read(gateLog), /latest\.json/, 'попытка через проводник была и при его отказе');
  assert.equal(spawnSync('/bin/sh', [updater, 'check'], { env: { ...env, D2K_GATE: '' }, encoding: 'utf8' }).status, 0);
  assert.equal(read(path.join(dir, 'state/catalog.json')), knowledge);
  assert.equal(read(path.join(dir, 'state/dns-cache')), 'preserve-dns');
  console.log('d2k-update: heartbeat identity/progress, stop failure, knowledge retention, signature, install, health rollback, bad release, toggle, VPS gate: PASS');
} finally {
  try { process.kill(Number(live)); } catch (_) {}
  try { process.kill(Number(liveController)); } catch (_) {}
  if (!process.env.KEEP) fs.rmSync(tmp, { recursive: true, force: true }); else console.log(tmp);
}
