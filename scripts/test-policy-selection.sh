#!/bin/sh
# shellcheck disable=SC1091,SC2329 # dynamic shell fixtures or runtime config
set -eu
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
awk '/^policy_mark\(\)/,/^}/' files/S99d2k > "$task_tmp/functions"
. "$task_tmp/functions"
ndmc() { cat "$task_tmp/input"; }
cat > "$task_tmp/input" <<'FIXTURE'
policy, name = Policy7, description = D2Ktest:
  mark: aa
policy, name = D2Ktest, description = Work:
  mark: bb
FIXTURE
[ "$(policy_mark D2Ktest)" = bb ] || { echo 'ID/description collision selected a different policy' >&2;exit 1; }
[ "$(policy_mark Work)" = bb ]
cat > "$task_tmp/input" <<'FIXTURE'
policy, name = Policy7, description = Shared:
  mark: aa
policy, name = Policy8, description = Shared:
  mark: bb
FIXTURE
[ -z "$(policy_mark Shared)" ] || { echo 'ambiguous description must fail closed' >&2;exit 1; }
[ "$(policy_mark Policy7)" = aa ]
ndmc() { cat "$task_tmp/input"; return 1; }
[ -z "$(policy_mark Policy7)" ] || { echo 'failed ndmc read selected a policy from partial output' >&2;exit 1; }
printf '%s\n' 'policy selection: exact ID wins; unique description retained; ambiguous description is refused'
