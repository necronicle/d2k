#!/usr/bin/env node
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const helper = path.resolve(__dirname, '../files/d2k-log-maintenance.sh');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'd2k-log-test.'));
const log = path.join(tmp, 'log');
const runtime = path.join(tmp, 'runtime');
fs.mkdirSync(log);
const owned = ['service.log', 'shadow.log', 'shadow-daemon.log', 'd2kd.log', 'd2kc.log', 'panel.log', 'telegram.log', 'instagram-dns.log', 'instagram-dns-scheduler.log', 'd2khttp.log'];
const payload = Buffer.concat([Buffer.alloc(3072, 'A'), Buffer.alloc(1024, 'Z')]);
const env = { ...process.env, D2K_DIR: tmp, D2K_RUNTIME_DIR: runtime, LOGMAX: '3072', LOGKEEP: '1024' };
function run(extra = {}) {
  const result = spawnSync('/bin/sh', [helper, 'tick'], { env: { ...env, ...extra }, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
}
try {
  for (const name of [...owned, 'unrelated.log', 'instagram-dns-unrelated.log']) fs.writeFileSync(path.join(log, name), payload);
  const file = path.join(log, 'panel.log');
  const fd = fs.openSync(file, 'a');
  const inode = fs.statSync(file).ino;
  run();
  for (const name of owned) assert.deepEqual(fs.readFileSync(path.join(log, name)), Buffer.alloc(1024, 'Z'), `must retain bounded tail of ${name}`);
  assert.equal(fs.statSync(file).ino, inode, 'must preserve open append inode');
  fs.writeSync(fd, 'AFTER'); fs.closeSync(fd);
  assert(fs.readFileSync(file, 'utf8').endsWith('AFTER'), 'open writer must continue appending to visible log');
  assert.equal(fs.statSync(path.join(log, 'unrelated.log')).size, 4096);
  assert.equal(fs.statSync(path.join(log, 'instagram-dns-unrelated.log')).size, 4096);
  assert.equal(fs.statSync(runtime).mode & 0o777, 0o700);

  // Invalid bounds must use safe defaults, never an empty or enormous tail.
  for (const bounds of [ { LOGMAX: '0', LOGKEEP: '0' }, { LOGMAX: '9999999999999999999', LOGKEEP: '-1' }, { LOGMAX: '1024', LOGKEEP: '4096' } ]) {
    fs.writeFileSync(file, payload); run(bounds);
    assert.deepEqual(fs.readFileSync(file), payload, 'invalid configuration must not destroy log content');
  }

  // Defaults fit a router whose Entware lives on internal flash: a log over
  // 2 MiB keeps its last 1 MiB (field 06.10: 14 MiB per log was too much).
  {
    const big = Buffer.concat([Buffer.alloc(2 * 1048576, 'A'), Buffer.alloc(1048576, 'Z')]);
    fs.writeFileSync(file, big);
    const plain = { ...env }; delete plain.LOGMAX; delete plain.LOGKEEP;
    const result = spawnSync('/bin/sh', [helper, 'tick'], { env: plain, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const kept = fs.readFileSync(file);
    assert.equal(kept.length, 1048576, 'default bound must be 2 MiB, keeping 1 MiB');
    assert(kept.equals(Buffer.alloc(1048576, 'Z')), 'default bound must keep the newest 1 MiB');
  }

  // A failed tail cannot truncate the live file, even if it produced partial output.
  const bin = path.join(tmp, 'bin'); fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'tail'), '#!/bin/sh\nprintf partial\nexit 1\n', { mode: 0o755 });
  fs.writeFileSync(file, payload); run({ PATH: `${bin}:${process.env.PATH}` });
  assert.deepEqual(fs.readFileSync(file), payload, 'failed tail must leave original log intact');
  assert.equal(fs.readdirSync(runtime).filter(x => x.includes('log-tail')).length, 0, 'failed stage must be cleaned');

  // Partial output reported as success is not a valid retained tail either.
  fs.writeFileSync(path.join(bin, 'tail'), '#!/bin/sh\nprintf partial\n', { mode: 0o755 });
  run({ PATH: `${bin}:${process.env.PATH}` });
  assert.deepEqual(fs.readFileSync(file), payload, 'short stage must leave original log intact');
  fs.unlinkSync(path.join(bin, 'tail'));

  // Without stat, check size using only a bounded tail; decimal values with
  // leading zeroes must not cause shell octal errors.
  fs.writeFileSync(path.join(bin, 'stat'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  run({ PATH: `${bin}:${process.env.PATH}`, LOGMAX: '00003072', LOGKEEP: '00001024' });
  assert.deepEqual(fs.readFileSync(file), Buffer.alloc(1024, 'Z'));

  const foreign = path.join(tmp, 'foreign'); fs.writeFileSync(foreign, payload);
  fs.unlinkSync(file); fs.symlinkSync(foreign, file); run();
  assert.deepEqual(fs.readFileSync(foreign), payload, 'owned log symlink must not rotate foreign target');

  // Real periodic worker must keep rotating without an engine process.
  fs.unlinkSync(file); fs.writeFileSync(file, payload);
  const fixture = path.join(tmp, 'payload'); fs.writeFileSync(fixture, payload);
  const periodic = spawnSync('/bin/sh', ['-c', `
    /bin/sh "$HELPER" run & worker=$!
    trap 'kill "$worker" 2>/dev/null; wait "$worker" 2>/dev/null || true' EXIT
    wait_rotation() {
      attempt=0
      while [ "$(wc -c < "$D2K_DIR/log/panel.log")" -ne 1024 ]; do
        attempt=$((attempt + 1)); [ "$attempt" -lt 40 ] || return 1
        sleep 0.1
      done
    }
    wait_rotation || exit 1
    cp "$FIXTURE" "$D2K_DIR/log/panel.log"
    wait_rotation || exit 2
  `], { env: { ...env, HELPER: helper, FIXTURE: fixture, LOG_EVERY: '1' }, encoding: 'utf8', timeout: 7000 });
  assert.equal(periodic.status, 0, 'periodic log worker must rotate again while engine is absent');
  assert.deepEqual(fs.readFileSync(file), Buffer.alloc(1024, 'Z'));
  console.log('owned log bounds, append inode, validation, failed-tail preservation: PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
