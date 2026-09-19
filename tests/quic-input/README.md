# QUIC measurement input: independent donor oracle

Run from the repository root:

```sh
D2K_REF_GO=/Users/mark/go/bin/go1.25.12 sh scripts/check-quic-input-parity.sh
```

`D2K_REF_ROOT` optionally locates the z2k checkout (not its `z2k-detect`
subdirectory). The runner checks the two original source files against
`e9a391347671cbb07663d2bee5b3d92f016c789e`, copies them unmodified into a fresh
temporary directory with this test, and invokes Go 1.25.12. It does not modify
the donor, contact targets, change router services or add Go to D2K runtime.
The build tag keeps this helper out of ordinary project Go builds.

The C constructor produces an actual encrypted Initial. The donor's key
derivation and AEAD open it; the donor's `Initial.Marshal` must reproduce the
entire packet byte-for-byte with identical inputs. The test checks PN=0,
PNLen=4, v1, 8-byte CID lengths, 1200-byte datagram, one CRYPTO frame followed
by PADDING, a complete ClientHello, and matching header/transport SCID.

For three different SNI lengths, its ClientHello must match the original
`ClientHello` outside random, X25519 public key and SCID. Everything else,
including extension order, transport parameter values and encodings, cipher
suites and signature algorithms, remains in the comparison. Random fields
must not be left zero. The C suite separately checks freshness and limits.

`--export-profile` explicitly regenerates `core/profiles/quic_probe.h` from
the original, then rebuilds and checks. It is an internal measurement profile,
not an imported strategy or target list. The generator refuses a different Go
version or non-AES cipher ordering instead of silently relabelling it.

## Scope still open

This pins the AES-capable donor ClientHello shape. Go selects a different
cipher order without hardware AES; that alternate profile and selection have
not yet been ported. Cross-compilation alone does not establish donor shape
parity on MIPS. Likewise this oracle does not cover renamed/split questions,
random neutral control naming, multi-datagram client capture, response verdicts
or actual application access. Those remain separate acceptance items.
