#!/bin/sh
# shellcheck disable=SC1091,SC2329,SC2034 # dynamic shell fixtures or runtime config
set -eu
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
# The service initialises this path before dispatch. Start on a Keenetic fixture.
OPENWRT_RELEASE=$task_tmp/openwrt_release
awk '/^(policy_mark|policy_args|openwrt_selector|openwrt_mark_number|openwrt_firewall_policy)\(\)/,/^}/' files/S99d2k > "$task_tmp/functions"
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

touch "$OPENWRT_RELEASE"
# Exercise the native MARK reader with the same field accessors used by UCI.
config_get_bool() { enabled=1; }
config_get() {
    case "$3" in
        target) target=MARK ;;
        set_mark) value=65536/0xff0000 ;;
    esac
}
openwrt_policies() {
    openwrt_firewall_policy lan_clients
    printf 'route.pbr_wan\tpbr_wan\t20000/0xff0000\n'
}
KEENETIC_POLICY=mark.10000.ff0000
[ "$(policy_args)" = '--only-mark 0x10000/0xff0000' ]
KEENETIC_POLICY=route.pbr_wan
[ "$(policy_args)" = '--only-mark 0x20000/0xff0000' ]
KEENETIC_POLICY=route.removed
[ "$(policy_args)" = '--only-mark none' ]
printf '%s\n' 'OpenWrt: native group and routing-table masks preserved; missing selection serves no clients'
