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
HTTP/3 application is present in this part of the test.

Conntrack is explicitly active. Without NODEFRAG the reverse-order/overlap
cases fail even though the pure builder tests pass. Test-only syscall failure
injection covers NODEFRAG/mark setup and prohibits ordinary-socket fallback.
The actual procfs conntrack lookup, SNAT and reply routing are NOT mocked.
Unsupported overlap reassembly on the
server is reported, not converted into an application success.

The runner then executes `nfq.sh`: an ordinary UDP client sends a real QUIC
Initial through NFQUEUE and the actual `d2kd` loop. All eight combinations must
match the expected wire, remove the queued original and record execution DONE.
The server is still a UDP echo, not an HTTP/3 implementation; DONE is deliberately
allowed with no echo for unsupported overlap reassembly.

Three failure cases use fake + reverse fragments:

- Declared interface MTU 1100: no fake/fragment sent, original accepted, no DONE.
  A dummy interface supplies the explicit sender limit while the actual route
  stays at 1500. This is not a PMTU-change test.
- NODEFRAG setup fails: same clean original pass, with no ordinary-socket fallback.
- Second fragment send fails: first fragment and two fakes are on wire, original
  is dropped, execution is damaged and not DONE. No application reply is expected.

`daemon_faults.c` substitutes syscalls only in the test daemon's raw object;
production has no environment-driven fault hook. Client/server, queue verdicts,
procfs NAT lookup, raw sender and veth capture remain real. A small non-QUIC seed
establishes conntrack/SNAT before each Initial; first-ever unconfirmed NAT and
router-specific procfs availability are outside this fixture.

For remaining work and acceptance boundaries see
[handoff](../../docs/field/2026-09-19-quic-fragment-plan.md).
