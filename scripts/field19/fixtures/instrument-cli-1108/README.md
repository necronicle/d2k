# Synthetic CLI write-out fixtures (12b, 2026-11-08)
These are offline constructed records, not a field capture. portal.tsv represents
main 200 then same-origin stylesheet portal on local_port 41000, num_connects=0.
reconnect.tsv differs only in local_port; it must yield unknown, not a verdict.
Columns: url_effective, http_code, size_download, num_connects, local_port,
remote_ip, http_version, exitcode, remote_port. fake-cli.py writes bodies/headers
and these records without sockets. Its HTTP/3 failure is synthetic too.

12c: export.bundle and cli-export.bundle are synthetic recorded byte streams
produced offline by the unchanged d2kfetch-export.sh. They are not router captures.
export.bundle contains probe.b0 (all 256 byte values, then newline/DONE and a
header-like sequence), probe.h0 (CRLF headers), and empty probe.empty-_.09.
cli-export.bundle contains one binary response plus headers/writeout/stderr.
Reproduce: write those test payloads to a temporary directory and run
`sh scripts/field19/d2kfetch-export.sh DIR > BUNDLE`. Expected contents are
asserted in test-site-cli.py; no network is involved.
