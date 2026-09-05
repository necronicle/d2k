#!/bin/sh
exec /opt/homebrew/bin/zig cc -target aarch64-linux-musl "$@"
