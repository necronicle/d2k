#!/usr/bin/env node
// Execute only init functions, with all process and network boundaries mocked.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '..');
const tmp = fs.mkdtempSync('/tmp/d2k-shadow-service.');
try {
  const source = fs.readFileSync(path.join(root, 'files/S99d2k'), 'utf8');
  let funcs = '';
  for (const name of ['spawn_shadow', 'shadow_reconcile', 'spawn_controller', 'recover', 'engine_stop']) {
    const match = source.match(new RegExp('^' + name + '\\(\\) \\{[\\s\\S]*?^\\}', 'm'));
    assert(match, `missing ${name}`); funcs += match[0] + '\n';
  }
  fs.writeFileSync(path.join(tmp, 'functions'), funcs);
  const script = `
set -eu
. "$T/functions"
RUN=$T/run; LOG=$T/log; DIR=$T; RUNTIME_DIR=$T/runtime; STATE_DIR=$T/state
mkdir -p "$RUN" "$LOG" "$STATE_DIR" "$RUNTIME_DIR" "$DIR/files"
: > "$DIR/files/modern.hex"
SH_PID=$RUN/shadow.pid; CT_PID=$RUN/controller.pid; DP_PID=$RUN/datapath.pid; HL_PID=$RUN/heal.pid
SHADOWBIN=/bin/sh; SHADOW_QUEUE=$RUNTIME_DIR/shadow.queue; EXP_SOCK=$RUN/exp.sock
BIN=/bin/sh; SOCK=$RUN/control.sock; LIVE=$RUNTIME_DIR/live.json
MEASURE_MARK=0x2f; PROBE_MARK=0x2e; SERVICE_LOG=$LOG/service.log
ENGINE_WANT=$RUN/want; MODE=apply
running() { [ -f "$1" ]; }
spawn_daemon() { printf '%s\\n' "$*" >> "$T/calls"; while [ "$#" -gt 0 ]; do [ "$1" != -p ] || { shift; : > "$1"; }; shift; done; }
wait_running() { running "$1"; }; pid_stamp() { :; }; prepare_runtime() { :; }
svc_log() { printf '%s\\n' "$*" >> "$SERVICE_LOG"; }; say() { :; }
stop_pidfile() { printf 'stop %s\\n' "$1" >> "$T/stop"; rm -f "$1"; }
recover_settle() { :; }; recover_backoff_ok() { :; }
watch_contract_matches() { :; }; fw_installed() { :; }
rst_rules_down() { :; }; spawn_datapath() { : > "$DP_PID"; }
fw_down() { printf 'fw_down\\n' >> "$T/stop"; }; legacy_http_stop() { :; }
fastnat_restore() { :; }; flowoffload_restore() { :; }; late_chains_down() { :; }
# Default: no queue flag and no shadow process.
SHADOW=0; NEWCHAIN=0; SYNTHESIS_ONLY=0; EXP_CONTROL=1
spawn_controller; shadow_reconcile
! grep -q -- --shadow-queue "$T/calls"
[ ! -f "$SH_PID" ]
# Explicit enable requires experimental datapath control.
SHADOW=1; EXP_CONTROL=0
shadow_reconcile
[ ! -f "$SH_PID" ]; grep -q EXP_CONTROL "$SERVICE_LOG"
# Launch arguments and only one instance.
EXP_CONTROL=1
spawn_controller; shadow_reconcile; shadow_reconcile
[ "$(grep -c -- --exp-control "$T/calls")" = 1 ]
grep -q -- "--shadow-queue $SHADOW_QUEUE" "$T/calls"
if grep -q -- '--pass' "$T/calls"; then exit 1; fi
grep -q -- "--store $DIR/state/shadow.d2km" "$T/calls"
# Healthy production engine: recover only the shadow process.
: > "$ENGINE_WANT"; : > "$DP_PID"; rm "$SH_PID"
recover
[ -f "$SH_PID" ]; [ "$(grep -c -- --exp-control "$T/calls")" = 2 ]
[ "$(grep -c -- --catalog "$T/calls")" = 2 ]
# Turning shadow off stops it without touching the working engine.
SHADOW=0; shadow_reconcile; [ ! -f "$SH_PID" ]; [ -f "$DP_PID" ]; [ -f "$CT_PID" ]
# Engine stop must stop the shadow before the datapath/firewall.
SHADOW=1; shadow_reconcile; : > "$T/stop"
engine_stop
[ "$(sed -n '2p' "$T/stop")" = "stop $SH_PID" ]
[ ! -f "$SH_PID" ]
# NEWCHAIN explicitly opts in; no invalid dependency launches a controller.
NEWCHAIN=1; SHADOW=0; EXP_CONTROL=1
if spawn_controller; then exit 1; fi
grep -q 'NEWCHAIN=1' "$SERVICE_LOG"
SHADOW=1; EXP_CONTROL=0
if spawn_controller; then exit 1; fi
EXP_CONTROL=1
spawn_controller
grep -q -- "--newchain-store $DIR/state/shadow.d2km" "$T/calls"
SYNTHESIS_ONLY=1; NEWCHAIN=0
if spawn_controller; then exit 1; fi
NEWCHAIN=1; SHADOW=0
if spawn_controller; then exit 1; fi
SHADOW=1
spawn_controller
grep -q -- '--synthesis-only' "$T/calls"
grep -q -- "--doh-targets $STATE_DIR/doh-targets" "$T/calls"
grep -q -- "--force-targets $STATE_DIR/force-targets" "$T/calls"
`;
  const r = spawnSync('/bin/sh', ['-c', script], {env: {...process.env, T: tmp}, encoding:'utf8'});
  assert.equal(r.status, 0, r.stdout + r.stderr);
  console.log('shadow opt-in, EXP_CONTROL gate, arguments, recovery, stop order: PASS');
} finally { fs.rmSync(tmp, {recursive:true,force:true}); }
