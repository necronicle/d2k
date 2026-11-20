# Site instrument (task 12, 08.11.2026)

`router-round.sh` retains the old 22 diagnostic targets and all input rows.
Its additional site stage visits the 19 document targets (`/`, `/ru/`).
The other three paths are standalone CDN diagnostics, not extra sites.
`site-round.py` tries a full h3 visit for scheduled h3 targets, then records
TCP Chrome/Safari visits separately. A failed h3 attempt cannot fail a site
whose TCP visit completes. A complete visit in one input makes the site work;
input-specific failures remain visible. Historical successful HTTP responses,
including weak/challenge responses, are only an upper bound, not full-page proof.
The h3 denominator is the scheduled target set (14 in saved A/A2/B3), not a
fresh assertion that all these servers currently advertise HTTP/3.

HTML supplies stylesheets, scripts, images, frames, preload and embedded styles;
CSS supplies imports and URLs recursively. Fragments/data URLs are ignored;
redirects, cookies, Referer, complete libcurl responses, HTTP status, portals and
optional expected decoded sizes are checked. The serial TCP client negotiates
HTTP/2 over TLS with HTTP/1.1 fallback. The measured CLI process (or optional
worker) retains its connection cache for the origin. Plain HTTP uses persistent HTTP/1.1.
Same-origin requests must reuse the connection (no new connects and identical
IP/ports). Different origins necessarily have separate TCP connections.
A server-initiated close/new connection is reported as unverified keep-alive,
not a successful reproduction of the required persistent experiment.

Every response body is retained under `site-bodies/<sha256>`; `site.jsonl`
contains request URL, protocol, status, endpoints, new-connection count,
headers, byte count, body hash/path and the resulting visit verdict.
The existing `d2kfetch-record.sh` and raw QUIC export stay unchanged: their
stream counts are distinct from decoded HTTP bodies and cannot prove resources.

## Default: CLI two-pass visit (task 12b)

No shared library or worker installation is needed for the default `cli` backend.
Discovery downloads the main document and recursively expands HTML/CSS and
redirects using the existing parser on the Mac. These preliminary requests can
use separate processes; their bodies and metadata are retained under `discovery`
and do not establish a site verdict.

The measured pass groups discovered URLs by origin, main document first. Each
origin gets ONE sequential curl process with all its URLs. `--next` separates
per-URL body/header paths and Referer; common options are repeated after it.
The process owns the connection cache and cookie engine; other origins get
separate invocations. Cookies start fresh for the measured pass. Discovery
cookies/connections are never confused with measurement evidence.

For every transfer the CLI emits `url_effective`, `http_code`, `size_download`,
`num_connects`, `local_port`, `remote_ip`, `http_version`, `exitcode` and
`remote_port`. These raw rows are retained alongside headers, body paths and
batch identity. `size_download` is encoded wire size; `size` and reference sizes
are decoded body bytes. The latter are never compared to compressed wire size.
The final curl process exit status alone cannot describe earlier transfers.

Bodies, headers and write-out/stderr use the existing `d2kfetch-export.sh`
stream over SSH: `NAME SIZE\n`, exactly SIZE bytes, ending with `DONE\n`.
CLI files use `probe.*` names; the Mac reuses `d2kfetch-import.py` and checks
that all expected files arrived. Binary bodies need no escaping or base64.
The exporter source is embedded in the shell sent over SSH, so it needs no
separate router installation. Keep both helper files beside `site-round.py`.
Remote requirements: POSIX sh, curl-impersonate, `mktemp -d /tmp/d2k-site.XXXXXX`,
`touch`, `rm -rf`, `wc -c` and `cat`; `cd`, `test`, `printf`, `trap` are shell
builtins. `mktemp` already serves d2kfetch-record.sh (explicit XXXXXX template);
`wc -c`/`cat` are the working exporter itself. BusyBox mktemp supports `-d`.
No tar, stat, head -c, remote Python or remote hash command is used by the
standalone site CLI. `router-round.sh` retains its existing BusyBox `sha256sum`
for instrument hashes; host-side hashing uses Python/shasum. Remote temporary
files are removed by POSIX `trap ... 0`, including trapped HUP/INT/TERM exits.
Only the measured pass feeds the site verdict. Every same-origin repeat must
have zero new connections and the same IP/ports within that batch. A changed
port/new connection, even on a portal response, yields “keep-alive не сохранён”
and no site verdict; the observed portal remains in `observed_failures`.
All scheduled transfers remain in `transfers`, including ones not traversed
when redirects/resources change. A newly discovered dependency in pass two expands its origin's batch. The
whole prefix is replayed with the new URL in one process, and verdict traversal
restarts using the final batch. Earlier measurements remain in
`measurement_history`; they cannot supply a final verdict for that origin.
This repeats to graph closure without an arbitrary request limit. A site that
continually generates new static URLs may not converge; interrupt such a run
and retain its observations rather than call it a measured visit.

Router paths (defaults):

```text
SITE_BACKEND=cli
SITE_CURL=/opt/d2k-tools/curl-impersonate
SITE_CA=/opt/d2k-tools/cacert.pem
SITE_REFERENCES=/local/path/to/expected-sizes.json   # optional
```

`site-round.py RUN --router --cacert /opt/d2k-tools/cacert.pem` selects this
backend by default. CLI profiles are chrome150 and safari2601. H3 uses
`--http3-only`; scheduled TCP inputs follow it as independent fallback visits.
`--check-only` checks CLI version/profile options and CA readability without
URLs. The shell wrappers run it before clearing/training, and hash the selected
CLI plus controller into `instrument.txt`.

For `lan-round.sh`, `SITE_CURL` defaults to its local `$CI` and `SITE_CA` to
`/Library/Zapret2/d2k-field-runs/tools/cacert.pem`; set matching local paths as
needed. Both round scripts affect the real network when run. They were not run
against the router in this task.

## Optional shared-library worker

Select `SITE_BACKEND=worker` and set `SITE_WORKER`, `SITE_CURL_LIB`, `SITE_CA`
(paths on router for router-round, local for lan-round). Direct controller use:
`--backend worker --worker PATH --library PATH --cacert PATH`.
The existing C worker requires a shared libcurl-impersonate exporting
`curl_easy_impersonate` (chrome150/safari260); ordinary Entware libcurl is
rejected. No shared library is installed or required for CLI mode.

```sh
cc -std=c99 -O2 -Wall -Wextra -Werror scripts/field19/site-fetch.c -o /tmp/field19-site-fetch
# On Linux append -ldl. Cross-build with target curl headers and router ABI.
```

Expected-size JSON is `{ "http://host/resource.css": 106050 }`, keyed by full
URL, with **decoded** body bytes. Supply only an independently established
reference; the collector does not turn its candidate response into a baseline.
No reference file was supplied for this task. Content-Length truncation is
still detected by libcurl without one.

## Offline verification

```sh
python3 -I scripts/field19/test-router-round.py
python3 -I scripts/field19/test-site-cli.py
python3 -I scripts/field19/router-round-report.py scripts/field19/fixtures/instrument-1108/B3-cand-1108
```

Tests use saved/synthetic write-out records, fake CLI/SSH/preflight stubs and
a socket-free fake shared library. They do not contact the router or public network.

Saved B3 has 19/19 single-document TCP responses after h3 fallback, and 4/14
h3 stream responses. It contains no main HTML or persistent subrequests, so
fast-torrent's real keep-alive portal and a full-page 18/19 cannot be recovered.
The test separately demonstrates synthetic full visits yielding 18/19, with
only fast-torrent failing, and exercises a portal on its dynamically discovered
same-connection CSS request. Synthetic results are not field evidence.

## Limits of the static visit

This is an HTTP instrument, not a JavaScript browser engine. It does not execute
scripts, answer browser challenges, reproduce viewport/media/lazy-load choices,
or prove login/video/all site functions. It traverses statically declared
resources (including srcset candidates), so the requested set can differ from
an actual browser. Recognized challenges have the distinct `server_replied_challenge` outcome:
the server answered, but a full visit cannot be measured statically. They count
as neither failed nor working nor an instrument error.
The real fast-torrent reproduction, CLI connection reuse on the router, Linux wire
behavior and comparison with the accepted release remain for an owner-run field
experiment. Unit tests/cross compilation do not close those requirements.


## Field1 corrections and offline replay (12d)

A complete response from the server with ANY HTTP status is transport evidence;
404/500 do not establish blocking. Statuses remain on every recorded transfer.
Curl transfer errors still detect timeout, TLS refusal, RST and incomplete
Content-Length/chunked/TLS bodies; optional independent decoded-size references
still detect a mismatch. Without an independent reference the instrument cannot
exclude all content substitution. Empty complete responses (e.g. 204) are valid.
Redirect cycles/malformed redirects are inconclusive, not proof of blocking.

Third-party subresources (host differs from document hosts) are reported under
`third_party`, separately from first-party failures/unknowns. A document redirect
to another host remains part of the document visit. A missing/failed third-party
image cannot fail an otherwise measured first-party site. A failed external
CLI envelope/parser is also isolated; `measurement_errors` retains its diagnostic. Browser challenges
remain a limit on static measurement, including a challenge encountered on an
external resource. Portal redirect detection uses known host boundaries rather
than substrings such as `rkn` in a legitimate Imgur filename. Body portal
evidence requires a frame, form action or meta refresh pointing to a known
provider portal; an article link alone is insufficient. Unknown portals and
other unrecognized substitution need independent content evidence.

`web_url` rejects non-string and empty values; literal `src='False'` is a real
URL supplied by the saved fast-torrent HTML. It is deliberately retained.
Its 500 reply is not a network-blocking verdict.

CLI parsing accepts failed-transfer port -1 sentinels, preserves failure rc and
HTTP version 0, and recognizes numeric 2.0/3.0 spellings. Successful rows cannot
use negative ports. Raw write-out is retained intact (not the last header line),
including in parser-error diagnostics. Historical field1 errors discarded the
raw values, so their exact causes cannot be proved from site.jsonl alone.

Reports automatically re-evaluate saved CLI transfers when site-bodies exists,
checking each decoded body against its recorded SHA-256, filename and size.
They never promote discovery or combine browser inputs. Missing data stay
unknown; failure to verify a body is a data error. Standalone derived JSONL:

```sh
python3 -I scripts/field19/site-replay.py RUN --output /tmp/replayed-site.jsonl
python3 -I scripts/field19/router-round-report.py RUN
D2K_FIELD1_RUN=/path/to/site-check-B3-1108b python3 -I scripts/field19/test-site-field1.py
```

The replay commands read local files only and do not alter the original run.
The output must be outside the resolved original run directory (including symlinks). Independently supplied size
references are not silently reconstructed: a saved run with a reference file is
marked inconclusive until its reference evidence is reviewed.

B3-1108b reclassification: 12 static first-party visits completed, 5 server
browser-check responses, mailsuite timed out in both TCP inputs, enimerosi has no
recoverable measured rows. This does not establish the human report of only
fast-torrent failing: that saved HTTP experiment shows no provider portal for
fast-torrent; real browser/JS behavior remains outside its evidence.

## Independent video playback instrument (19.11.2026)

`video-round.sh LABEL PRIVATE_URL_JSON 60` drives one dedicated field Chrome through CDP. The private JSON contains one stable non-secret `id` and the temporary signed `url`; URLs and response/request details are written only to `network.private.json` and `playback.private.json`. `summary.json` and `manifest.json` contain no URL, query, signature, or authorization header.

The observer enables Network before navigation, disables cache, starts the visible video once with a CDP user gesture, samples actual video progress every 250 ms, and records waiting/stalled transitions. A standalone run passes only after 60 seconds of progressing playback and at least two completed media/range responses. Missing Chrome/video observations and failed loads do not pass. Startup and rebuffering are compared only between identical video IDs, instrument version, and duration via `compareRuns` in `video-metrics.mjs`; there is no separate absolute startup threshold.

Offline verification (no browser or network):

```sh
sh scripts/test-field-video-instrument.sh
```

The wrapper preserves earlier evidence and uses a disposable Chrome profile. It does not switch router services or disable QUIC; baseline/candidate service orchestration remains part of a separately authorized field window.
