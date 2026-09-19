//go:build d2k_donor

// Test-only oracle: copy beside the UNMODIFIED pinned donor hello.go and
// initial.go. No Go dependency is added to the D2K product runtime.
package quicprobe

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

type randomField struct {
	name      string
	off, size int
}

// Ignore ONLY per-connection randomness. Retain all lengths, extension order,
// cipher suites, algorithms, transport parameters and their wire encodings.
func normalized(t *testing.T, src []byte) ([]byte, []randomField) {
	t.Helper()
	b := append([]byte(nil), src...)
	need := func(at, n int) {
		if at < 0 || n < 0 || at+n > len(b) {
			t.Fatalf("truncated ClientHello at %d+%d/%d", at, n, len(b))
		}
	}
	need(0, 39)
	if b[0] != 1 || int(b[1])<<16|int(b[2])<<8|int(b[3]) != len(b)-4 {
		t.Fatal("not a complete ClientHello")
	}
	fields := []randomField{{"random", 6, 32}}
	p := 38
	if b[p] != 0 {
		t.Fatal("QUIC session ID is not empty")
	}
	p++
	need(p, 2)
	n := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	need(p, n)
	p += n
	need(p, 1)
	n = int(b[p])
	p++
	need(p, n)
	p += n
	need(p, 2)
	n = int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if p+n != len(b) {
		t.Fatal("extension length mismatch")
	}
	for p < len(b) {
		need(p, 4)
		typ := binary.BigEndian.Uint16(b[p:])
		n = int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		need(p, n)
		switch typ {
		case 0x33:
			if n != 38 || binary.BigEndian.Uint16(b[p:]) != 36 || binary.BigEndian.Uint16(b[p+2:]) != 29 || binary.BigEndian.Uint16(b[p+4:]) != 32 {
				t.Fatal("expected one X25519 key share")
			}
			fields = append(fields, randomField{"key_share", p + 6, 32})
		case 0x39:
			q, end := p, p+n
			for q < end {
				id, w := readVarint(b[q:end])
				if w == 0 {
					t.Fatal("bad TP id")
				}
				q += w
				l, w := readVarint(b[q:end])
				if w == 0 || l > uint64(end-q-w) {
					t.Fatal("bad TP length")
				}
				q += w
				if id == 0x0f {
					if l != 8 {
						t.Fatal("SCID is not eight bytes")
					}
					fields = append(fields, randomField{"scid", q, 8})
				}
				q += int(l)
			}
		}
		p += n
	}
	if len(fields) != 3 {
		t.Fatalf("random fields: %v", fields)
	}
	for _, f := range fields {
		clear(b[f.off : f.off+f.size])
	}
	return b, fields
}

// Open the C packet with the DONOR keys/AEAD implementation. Fixed dimensions
// here are the donor buildInitial contract, not assumptions about arbitrary QUIC.
func openProbe(t *testing.T, packet []byte) ([]byte, []byte) {
	t.Helper()
	if len(packet) != 1200 || packet[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(packet[1:]) != uint32(V1) || packet[5] != 8 || packet[14] != 8 {
		t.Fatal("Initial dimensions/version/CIDs differ from buildInitial")
	}
	scid := append([]byte(nil), packet[15:23]...)
	client, _, err := deriveKeys(packet[6:14], V1)
	if err != nil {
		t.Fatal(err)
	}
	q := 23
	token, w := readVarint(packet[q:])
	if w == 0 || token != 0 {
		t.Fatal("unexpected token")
	}
	q += w
	n, w := readVarint(packet[q:])
	if w == 0 {
		t.Fatal("bad length")
	}
	q += w
	if q+int(n) != len(packet) {
		t.Fatal("Initial length mismatch")
	}
	p := append([]byte(nil), packet...)
	if err := applyHeaderProtection(p, client.hp, q, 4, true); err != nil {
		t.Fatal(err)
	}
	if p[0]&3 != 3 || binary.BigEndian.Uint32(p[q:]) != 0 {
		t.Fatal("buildInitial requires PNLen=4, PN=0")
	}
	body, err := open(client, p[q+4:], p[:q+4], 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 4 || body[0] != 6 {
		t.Fatal("first frame is not CRYPTO")
	}
	q = 1
	off, w := readVarint(body[q:])
	if w == 0 || off != 0 {
		t.Fatal("CRYPTO offset is not zero")
	}
	q += w
	n, w = readVarint(body[q:])
	if w == 0 || n > uint64(len(body)-q-w) {
		t.Fatal("bad CRYPTO length")
	}
	q += w
	hello := body[q : q+int(n)]
	for _, v := range body[q+int(n):] {
		if v != 0 {
			t.Fatal("not one CRYPTO followed by PADDING")
		}
	}
	rebuilt, err := (Initial{Version: V1, DCID: packet[6:14], SCID: scid,
		PacketNumber: 0, PNLen: 4, Crypto: []CryptoFrame{{Offset: 0, Data: hello}}, DatagramLen: 1200}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, rebuilt) {
		t.Fatal("C Initial differs byte-for-byte from donor Marshal with identical inputs")
	}
	_, fields := normalized(t, hello)
	for _, f := range fields {
		if bytes.Equal(hello[f.off:f.off+f.size], make([]byte, f.size)) {
			t.Fatalf("%s was not randomized", f.name)
		}
		if f.name == "scid" && !bytes.Equal(hello[f.off:f.off+f.size], scid) {
			t.Fatal("transport SCID differs from packet SCID")
		}
	}
	return hello, scid
}

func TestD2KProbeHelloParity(t *testing.T) {
	bin := os.Getenv("D2K_QUIC_INPUT_BIN")
	if bin == "" {
		t.Fatal("D2K_QUIC_INPUT_BIN is required")
	}
	for _, name := range []string{"profile.example", "a.example", "longer-target-name.example.com"} {
		t.Run(name, func(t *testing.T) {
			want, err := ClientHello(name, []byte{1, 2, 3, 4, 5, 6, 7, 8})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := exec.Command(bin, "--dump-probe", name).Output()
			if err != nil {
				t.Fatal(err)
			}
			got, err := hex.DecodeString(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			got, _ = openProbe(t, got)
			want, _ = normalized(t, want)
			got, _ = normalized(t, got)
			if !bytes.Equal(want, got) {
				t.Fatalf("C probe differs from donor outside randomness:\nwant %x\n got %x", want, got)
			}
		})
	}
}

// Generate a normalized internal instrument profile from the ORIGINAL code,
// never a user's learned strategy pool. Run explicitly; ordinary tests do not
// modify the repository. Random fields are filled anew by C, before SNI rename.
func TestExportD2KProbeProfile(t *testing.T) {
	path := os.Getenv("D2K_QUIC_PROFILE_OUT")
	if path == "" {
		t.Skip("explicit export only")
	}
	b, err := ClientHello("profile.example", []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}
	b, fields := normalized(t, b)
	if runtime.Version() != "go1.25.12" || !bytes.Equal(b[39:47], []byte{0, 6, 0x13, 1, 0x13, 2, 0x13, 3}) {
		t.Fatal("export requires pinned Go 1.25.12 AES-capable profile; do not overwrite with another shape")
	}
	var out strings.Builder
	fmt.Fprintln(&out, "/* Generated by tests/quic-input from pinned z2k quicprobe.ClientHello.")
	fmt.Fprintln(&out, " * Donor e9a391347671cbb07663d2bee5b3d92f016c789e, hello.go/initial.go.")
	fmt.Fprintln(&out, " * Go 1.25.12, AES-capable profile; only random/key_share/SCID zeroed.")
	fmt.Fprintln(&out, " * Regenerate and verify with the independent donor oracle. */")
	fmt.Fprintln(&out, "static const uint8_t d2k_quic_probe_profile[] = {")
	for i, v := range b {
		if i%12 == 0 {
			fmt.Fprint(&out, "    ")
		}
		fmt.Fprintf(&out, "0x%02x,", v)
		if i%12 == 11 || i == len(b)-1 {
			fmt.Fprintln(&out)
		} else {
			fmt.Fprint(&out, " ")
		}
	}
	fmt.Fprintln(&out, "};")
	for _, f := range fields {
		fmt.Fprintf(&out, "#define D2K_QUIC_PROFILE_%s_OFF %d\n", strings.ToUpper(f.name), f.off)
	}
	if err := os.WriteFile(path, []byte(out.String()), 0644); err != nil {
		t.Fatal(err)
	}
}
