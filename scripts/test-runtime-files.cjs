#!/usr/bin/env node
// Executes the init functions with process/firewall boundaries isolated.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'd2k-runtime-test.'));
try {
  const init = fs.readFileSync(path.join(root, 'files/S99d2k'), 'utf8');
  fs.writeFileSync(path.join(tmp, 'init'), init.slice(0, init.lastIndexOf('\ncase "$1" in')));
  fs.mkdirSync(path.join(tmp, 'bin'));
  fs.writeFileSync(path.join(tmp, 'bin/start-stop-daemon'), `#!/bin/sh
printf '%s\\n' "$*" >> "$TEST_DIR/calls"
prev=; for arg in "$@"; do
  [ "$prev" != -p ] || { printf '123\\n' > "$arg"; }
  prev=$arg
done
`, { mode: 0o755 });
  const harness = `
. "$TEST_DIR/init"
PATH=$TEST_DIR/bin:$PATH
DIR=$TEST_DIR/d2k; RUN=$DIR/run; LOG=$DIR/log; STATE_DIR=$DIR/state
RUNTIME_DIR=$TEST_DIR/runtime; LIVE=$RUNTIME_DIR/live.json
CONF=$DIR/config; SOCK=$RUN/socket
DP_PID=$RUN/dp.pid; CT_PID=$RUN/ct.pid; PN_PID=$RUN/panel.pid; SH_PID=$RUN/shadow.pid
HU_PID=$RUN/http.pid; HL_PID=$RUN/heal.pid; LM_PID=$RUN/log-maintenance.pid
TG_PID=$RUN/tg.pid; TG_WD_PID=$RUN/tg-watchdog.pid; DNS_SCHED_PID=$RUN/dns-scheduler.pid
TG_STATUS=$STATE_DIR/telegram.status; TG_FIREWALL=$TEST_DIR/no-tg-firewall
BIN=/bin/sh; DPBIN=/bin/sh; PANELBIN=/bin/sh
HEAL=$TEST_DIR/no-heal; LOG_MAINTENANCE=$TEST_HELPER
FASTNAT=$TEST_DIR/no-fastnat
mkdir -p "$RUN" "$LOG" "$STATE_DIR"
running() { [ -f "$1" ]; }
pid_stamp() { :; }
load_modules() { :; }; fastnat_off() { :; }; flowoffload_off() { :; }
legacy_http_stop() { :; }; late_chains_down() { :; }; rst_rules_down() { :; }
fw_up() { :; }; fw_down() { :; }; fw_installed() { :; }
awk() { printf '123\n'; }
start_engine
start_panel
# Engine-only stop must leave the independent maintenance process intact.
[ -f "$LM_PID" ] || exit 41
stop_pidfile() { rm -f "$1"; }
engine_stop
[ -f "$LM_PID" ] || exit 42
[ -f "$PN_PID" ] || exit 43
printf '{}' > "$LIVE"
stop
[ ! -f "$LM_PID" ] && [ ! -f "$LIVE" ] || exit 44
`;
  fs.writeFileSync(path.join(tmp, 'harness'), harness);
  const result = spawnSync('/bin/sh', [path.join(tmp, 'harness')], {
    env: { ...process.env, TEST_DIR: tmp, TEST_HELPER: path.join(root, 'files/d2k-log-maintenance.sh') }, encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const calls = fs.readFileSync(path.join(tmp, 'calls'), 'utf8').split('\n');
  const controller = calls.find(x => x.includes('--catalog'));
  const panel = calls.find(x => x.includes('--assets'));
  assert(controller.includes(`--live ${tmp}/runtime/live.json`), 'controller must explicitly write runtime live snapshot');
  assert(controller.includes(`--health-file ${tmp}/runtime/d2kc.health`), 'controller heartbeat must use configured private runtime');
  assert(panel.includes(`--health-file ${tmp}/runtime/d2kpanel.health`), 'panel heartbeat must use configured private runtime');
  assert(panel.includes(`--live ${tmp}/runtime/live.json`), 'panel must read same runtime live snapshot');
  assert(controller.includes(`--catalog ${tmp}/d2k/state/catalog.json`), 'persistent catalog location must stay unchanged');
  assert.equal(fs.statSync(path.join(tmp, 'runtime')).mode & 0o777, 0o700, 'runtime directory must be private');
  assert.equal(calls.filter(x => x.includes('-- run')).length, 1, 'maintenance must start once for engine and panel');
  console.log('runtime snapshot paths and engine-stop maintenance: PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
