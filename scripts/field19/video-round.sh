#!/bin/sh
set -eu
LABEL=${1:?usage: video-round.sh LABEL PRIVATE_URL_JSON [60]}
INPUT=${2:?private URL JSON required}
DURATION=${3:-60}
[ "$DURATION" = 60 ] || { echo 'video playback duration must be 60 seconds' >&2; exit 2; }
case "$LABEL" in *[!A-Za-z0-9_.-]*|'') echo 'unsafe label' >&2; exit 2;; esac
[ -r "$INPUT" ] || { echo 'private URL JSON is not readable' >&2; exit 2; }
RUNS=${D2K_FIELD_RUNS:?D2K_FIELD_RUNS is required}
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
OUT="$RUNS/$LABEL/video"
PROFILE="$RUNS/chrome-profiles/$LABEL-video-$$"
PORT=${PORT:-9333}
mkdir -p "$RUNS/$LABEL" "$RUNS/chrome-profiles"
if [ -e "$OUT" ]; then
    PREVIOUS="$OUT.previous-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mv "$OUT" "$PREVIOUS"
    echo "previous-video-evidence-preserved $PREVIOUS"
fi
mkdir -p "$OUT" "$PROFILE"
stop() {
    for pid in $(pgrep -f "Google Chrome --user-data-dir=$PROFILE" 2>/dev/null || true); do kill "$pid" 2>/dev/null || true; done
    rm -rf "$PROFILE"
}
trap stop EXIT HUP INT TERM
open -na "Google Chrome" --args "--user-data-dir=$PROFILE" "--remote-debugging-port=$PORT" \
    --no-first-run --no-default-browser-check --hide-crash-restore-bubble \
    --disable-features=Translate,TranslateUI --window-size=1300,900 about:blank
set +e
node "$HERE/videoobserve.mjs" "$PORT" "$OUT" "$INPUT" "$DURATION"
RC=$?
set -e
stop
trap - EXIT HUP INT TERM
exit "$RC"
