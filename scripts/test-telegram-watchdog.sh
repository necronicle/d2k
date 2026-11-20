#!/bin/sh
# shellcheck disable=SC2016 # fixture strings are expanded by the child shell
set -eu
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/bin" "$root/state" "$root/log"
export root
sed -e 's@^PATH=.*@PATH=$root/bin:/usr/bin:/bin@' -e 's@^DIR=.*@DIR=$root@' \
    -e 's@^INIT=.*@INIT=$root/bin/restart@' files/d2k-tg-watchdog.sh > "$root/watch"
printf '%s\n' '#!/bin/sh' 'echo restart >> "$root/calls"' > "$root/bin/restart"
printf '%s\n' '#!/bin/sh' 'exit "$PROBE_RC"' > "$root/bin/curl"
# End after three passes without sleeping.
sed -i.bak 's/^    sleep 60$/    rounds=$((${rounds:-0}+1)); [ "$rounds" -lt 3 ] || exit 0/' "$root/watch"
chmod +x "$root/bin/"*
for rc in 127 126 60 0 28; do
    : > "$root/calls"
    PROBE_RC=$rc sh "$root/watch"
    if [ "$rc" = 28 ]; then [ "$(wc -l < "$root/calls")" -eq 1 ]; else [ ! -s "$root/calls" ]; fi
done
echo 'Telegram watchdog: unavailable probe leaves the tunnel up; three timeouts trigger recovery'
