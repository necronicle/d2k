# QUIC Run: original versus C on real loopback sockets

```sh
D2K_REF_GO=/Users/mark/go/bin/go1.25.12 sh scripts/check-quic-run-parity.sh
# The same oracle and C classifier on Linux ARM64 (existing gcc:14 + Zig):
D2K_REF_GO=/Users/mark/go/bin/go1.25.12 sh scripts/check-quic-run-parity.sh --linux
# Exact raw fragments on isolated container loopback (CAP_NET_RAW only):
D2K_REF_GO=/Users/mark/go/bin/go1.25.12 sh scripts/check-quic-run-parity.sh --linux-raw
# Same raw tests with real conntrack enabled (d2k-fragment-test image):
D2K_REF_GO=/Users/mark/go/bin/go1.25.12 sh scripts/check-quic-run-parity.sh --linux-raw-conntrack
```

The runner copies the unchanged donor `internal/quicprobe` package, checked
against `e9a391347671cbb07663d2bee5b3d92f016c789e`, into a temporary module.
It compiles the current C classifier and executes the actual Go `Run` and C
classifier against equivalent local UDP scenarios. No router, external target,
donor modification or Go runtime dependency is introduced into D2K.

The donor uses `AllowLoopback` and an explicit address; the C test entry point
uses its equivalent test switch and disables supplementary DNS resolution.
Test-only overrides shorten timeouts. Linux mode cross-compiles both programs
and runs in a read-only, unprivileged container with `--network none` and a
read-only temporary artifact mount. It does not pull an image.

| Scenario | Original verdict | Sent probes |
| --- | --- | --- |
| Closed UDP port / ICMP | no_quic | 3 |
| Silent listener, including version negotiation | address | 6 |
| Version negotiation only | no_quic | 6 |
| Control and target answer | clear | 6 |
| Only one control response, all target responses | clear | 6 |
| All control responses, only one target response | flaky | 6 |

Expected donor results are checked before comparing C. This prevents a broken
fixture from making both implementations agree for the wrong reason.
The responder sends authenticated synthetic Initial/CRYPTO data, using donor
key derivation and encryption. This exercises the instrument's protocol oracle;
it is deliberately **not** an HTTP/3 server or proof of application access.

Before the fix, C returned inconclusive for the first two cases, sent nine
probes instead of six for VN-only, eight instead of six for direct success,
and stopped with flaky after a partial positive control.

Additional independent checks execute unchanged `askArms` and `blobBytes`:

- All five internal fake hypotheses match byte-for-byte (three pinned 1200-byte
  files plus the generated 620-byte default and 16 zero bytes).
- On a one-IP target without residual blocking, the original and C select
  `quic5`, 6 copies, TTL 3 in the same order with the same trace/counts.
- The responder expires fake state after 40 ms. The old C transport's invented
  60 ms pause fails this test; the original sends back-to-back and passes.
- Full `Run` with residual blocking and no spare IP retains `content`, skips
  unavailable questions, and sends only the nine baseline probes.
- Partial positive residual control keeps the pinned IP available; original
  and C both find the same fake/copies/TTL. This case compares diagnosis and
  arm result, **not** all subsequent property questions or total probe counts.

`D2K_QUIC_TESTS` optionally narrows the Go test regex for reproductions; omit
it for acceptance. The runner copies pinned donor fake files to the temporary
module too, without depending on a router installation.

The original fragment builder is also compared byte-for-byte on 96 combinations
of sizes and plans (including short inputs, alignment, overlap clamping and
reverse order). `--linux-raw` runs a separate privileged-to-open-raw-sockets
test, still inside `--network none` with only CAP_NET_RAW and a read-only root:

- Actual Go `measure/exchangeFragmented` and C send all four original shapes.
- A packet socket captures the real C wire; full IPv4/UDP bytes and ordering
  are compared to original `buildFragments` using the observed input and ID.
- Three attempts must have different ports, CIDs and nonzero IP IDs.
- Both two-fragment orders reassemble and obtain authenticated QUIC answers.
  Overlap success/failure must match the original on this kernel, not an
  invented universal outcome for every receiver.
- Failed marks on either receiving or raw socket must yield unsent/untrusted
  results, and packet capture must show no transmitted fragment.
- Failed NODEFRAG setup yields unsent results and no wire, without falling back
  to a normal raw socket.

`--linux-raw-conntrack` reproduces a limitation in the unchanged donor: conntrack
reorders reverse fragments and locally drops overlap groups. The C measurement
sender now uses mandatory IP_NODEFRAG, preserving the original builder's actual
bytes/order through conntrack. The test asserts the donor limitation first,
then verifies the corrected C wire against the original pure builder. This mode
is therefore **not** a claim of identical donor/C transport outcomes under that
kernel setup. The question tree and fragment shapes are unchanged.

Scope is still not complete Run/wire parity. Fragment Plan execution is covered
separately by `scripts/check-fragment-plan-linux.sh` (including NFQUEUE/NAT);
per-attempt TLS input/control freshness, options/deadline semantics and remaining
property questions are open. Fragment survival is `not measured` in the
capability-free lab, never a claim that fragments cannot traverse a real
network. No test here proves application access or router/NAT execution.
