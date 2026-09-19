# QUIC Run: original versus C on real loopback sockets

```sh
D2K_REF_GO=/Users/mark/go/bin/go1.25.12 sh scripts/check-quic-run-parity.sh
# The same oracle and C classifier on Linux ARM64 (existing gcc:14 + Zig):
D2K_REF_GO=/Users/mark/go/bin/go1.25.12 sh scripts/check-quic-run-parity.sh --linux
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

Scope: these are terminal baseline branches, not the complete Run. The content
branch, residual blocking, shared address pool, arm/property ordering and
wire freshness still need independent parity coverage. C's protection against
local send failure and lost bypass marks remains separately tested by the C
suite; it is not established by these six network scenarios.
