#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
node --test "$ROOT/scripts/field19/test-video-metrics.mjs" \
    "$ROOT/scripts/field19/test-video-observer.mjs" \
    "$ROOT/scripts/field19/test-video-comparison-recovery.mjs" \
    "$ROOT/scripts/field19/test-video-arm.mjs"
node --check "$ROOT/scripts/field19/video-metrics.mjs"
node --check "$ROOT/scripts/field19/videoobserve.mjs"
sh -n "$ROOT/scripts/field19/video-round.sh"
