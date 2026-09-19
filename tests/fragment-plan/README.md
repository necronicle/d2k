# Original QUIC fragment Plan, Linux sender and NAT

Run from the repository root:

```sh
docker build -t d2k-fragment-test -f tests/fragment-plan/Dockerfile tests/fragment-plan
sh scripts/check-fragment-plan-linux.sh
```

The first command fetches test packages into a local image. The runner itself
has no outside network and no router access. It creates an ephemeral veth/server
namespace and SNAT rule; capabilities are scoped to that disposable container.
SYS_ADMIN is needed for `ip netns`, not host administration.

`compose.c` constructs a measured-arm fixture through the real C Plan producer;
`raw.c` loads/applies it and uses the real sender. AF_PACKET compares all four
fragment shapes, with and without fake, to the shared builder (separately
verified by the original Go's 96 vectors). It checks the actual number/order
of fake packets, their client NAT mapping, fragment bytes and source ports,
and a return echo on the original client socket. No actual domain-search run,
HTTP/3 application or NFQUEUE original is present in this test.

Conntrack is explicitly active. Without NODEFRAG the reverse-order/overlap
cases fail even though the pure builder tests pass. Test-only syscall failure
injection covers NODEFRAG/mark setup and prohibits ordinary-socket fallback.
The procfs lookup is replaced with the mapping confirmed by the echo; actual
SNAT and reply routing are NOT mocked. Unsupported overlap reassembly on the
server is reported, not converted into an application success.

For remaining work and acceptance boundaries see
[handoff](../../docs/field/2026-09-19-quic-fragment-plan.md).
