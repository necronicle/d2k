#!/bin/sh
# Host-only compilation database for clangd/Serena. Does not build or run tests.
# Requires compiledb (uv tool install compiledb) and jq.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
index_tmp=$(mktemp -d "${TMPDIR:-/tmp}/d2k-code-index.XXXXXX")
trap 'rm -f "$index_tmp/core.json" "$index_tmp/datapath.json" "$index_tmp/detect.json" "$index_tmp/merged.json"; rmdir "$index_tmp"' EXIT HUP INT TERM
for component in core datapath detect; do
    # Run inside the component: make -C is not reliably tracked by compiledb
    # with the macOS make output. -n prevents recipe execution, -B lists all.
    (cd "$repo_dir/$component" && compiledb -n -f -o "$index_tmp/$component.json" make -B all check)
done
jq -s 'add | unique_by(.directory + "/" + .file)' \
    "$index_tmp/core.json" "$index_tmp/datapath.json" "$index_tmp/detect.json" > "$index_tmp/merged.json"
jq -e 'length > 0 and any(.[]; .file == "sched.c") and any(.[]; .file == "session.c") and any(.[]; .file == "classify.c")' "$index_tmp/merged.json" > /dev/null
mv "$index_tmp/merged.json" "$repo_dir/compile_commands.json"
jq 'group_by(.directory) | map({directory: .[0].directory, files: length})' "$repo_dir/compile_commands.json"
