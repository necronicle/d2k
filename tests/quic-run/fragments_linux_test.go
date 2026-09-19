//go:build d2k_donor && linux

package quicprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func packetCapture(t *testing.T) (int, func() map[uint16][][]byte) {
	t.Helper()
	proto := int((unix.ETH_P_IP<<8)&0xffff | unix.ETH_P_IP>>8)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, proto)
	if err != nil {
		t.Fatalf("raw lab requires CAP_NET_RAW: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	intf, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: intf.Index}); err != nil {
		t.Fatal(err)
	}
	drain := func() map[uint16][][]byte {
		groups := map[uint16][][]byte{}
		for {
			b := make([]byte, 65535)
			n, from, e := unix.Recvfrom(fd, b, 0)
			if errors.Is(e, unix.EAGAIN) {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			ll, ok := from.(*unix.SockaddrLinklayer)
			if !ok || ll.Pkttype != unix.PACKET_HOST || n < 20 {
				continue
			}
			b = b[:n]
			if b[0] != 0x45 || b[9] != 17 || binary.BigEndian.Uint16(b[6:])&0x3fff == 0 {
				continue
			}
			id := binary.BigEndian.Uint16(b[4:])
			groups[id] = append(groups[id], b)
		}
		return groups
	}
	return fd, drain
}

func TestD2KRawFragments(t *testing.T) {
	// There are no public endpoints here. The only network is container loopback.
	plans := []fragPlan{{pos1: 8}, {pos1: 8, disorder: true},
		{three: true, pos1: 8, pos2: 32, ov12: 8, ov23: 8, disorder: true},
		{three: true, pos1: 16, pos2: 48, ov12: 8, ov23: 8, disorder: true}}
	for i, p := range plans {
		t.Run(fmt.Sprint(i+1), func(t *testing.T) {
			server := startScenario(t, "clear")
			defer server.stop()
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: server.port}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, originalDrain := packetCapture(t)
			ref := measure(ctx, addr, Options{Repeats: 3, Parallel: 3}, func(int) probeSpec {
				s := buildInitial("blocked.example", V1, 1200, 0)
				s.frag = &p
				return s
			}, 40*time.Millisecond)
			if ref.NotBuilt != 0 {
				t.Fatalf("original raw path unavailable: %+v", ref)
			}
			if i < 2 && ref.Answered != 3 {
				t.Fatalf("original two-fragment path must reassemble: %+v", ref)
			}
			originalGroups := originalDrain()
			if os.Getenv("D2K_CONNTRACK") == "1" {
				// Original source stays unchanged. Its raw socket lacks NODEFRAG:
				// distinguish a local rewrite/drop from the server's DPI behavior.
				t.Logf("unchanged Go with conntrack: groups=%d answered=%d sent=%d", len(originalGroups), ref.Answered, ref.Sent)
				if i == 1 {
					if len(originalGroups) != 3 {
						t.Fatalf("expected three reordered donor groups, got %d", len(originalGroups))
					}
					for _, frames := range originalGroups {
						if binary.BigEndian.Uint16(frames[0][6:])&8191 != 0 {
							t.Fatal("donor limitation was not reproduced: reverse order survived conntrack")
						}
					}
				}
				if i >= 2 && len(originalGroups) != 0 {
					t.Fatal("donor limitation was not reproduced: overlapping fragments survived local defrag")
				}
			}
			_, drain := packetCapture(t)
			out, err := exec.Command(os.Getenv("D2K_QUIC_RUN_BIN"), strconv.Itoa(server.port), "fragment", strconv.Itoa(i+1)).CombinedOutput()
			if err != nil {
				t.Fatalf("C: %v %s", err, out)
			}
			expected := fmt.Sprintf("%d %d 0 1 3\n", ref.Answered, 3-ref.Answered)
			if string(out) != expected {
				t.Fatalf("C %s; original %+v", out, ref)
			}
			t.Logf("original answered=%d sent=%d not-built=%d; C %s", ref.Answered, ref.Sent, ref.NotBuilt, strings.TrimSpace(string(out)))
			groups := drain()
			if len(groups) != 3 {
				t.Fatalf("each attempt needs distinct nonzero IP ID, got %d groups", len(groups))
			}
			ports, dcids := map[uint16]bool{}, map[string]bool{}
			for id, frames := range groups {
				if id == 0 {
					t.Fatal("zero IP ID")
				}
				total := 0
				for _, f := range frames {
					end := int(binary.BigEndian.Uint16(f[6:])&8191)*8 + len(f) - 20
					if end > total {
						total = end
					}
				}
				l4 := make([]byte, total)
				for _, f := range frames {
					off := int(binary.BigEndian.Uint16(f[6:])&8191) * 8
					copy(l4[off:], f[20:])
				}
				if len(l4) < 32 {
					t.Fatal("short reassembled datagram")
				}
				port := binary.BigEndian.Uint16(l4)
				if ports[port] {
					t.Fatal("reused receive socket/port")
				}
				ports[port] = true
				// Original input has an 8-byte destination CID. Require independence.
				dcid := string(l4[14:22])
				if dcids[dcid] {
					t.Fatal("reused DCID")
				}
				dcids[dcid] = true
				want, e := buildFragments(net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), port, uint16(server.port), l4[8:], p, id)
				if e != nil || len(want) != len(frames) {
					t.Fatalf("fragment count: C %d Go %d err %v", len(frames), len(want), e)
				}
				for k := range want {
					if !bytes.Equal(want[k], frames[k]) {
						t.Fatalf("actual wire/order differs from original, fragment %d", k)
					}
				}
			}
		})
	}
	for _, where := range []string{"mark-rx", "mark-raw", "nodefrag"} {
		t.Run(where, func(t *testing.T) {
			server := startScenario(t, "clear")
			defer server.stop()
			_, drain := packetCapture(t)
			out, err := exec.Command(os.Getenv("D2K_QUIC_RUN_BIN"), strconv.Itoa(server.port), "fragment", "1", where).CombinedOutput()
			if err != nil {
				t.Fatalf("C: %v %s", err, out)
			}
			want := "0 3 3 0 0"
			if where == "nodefrag" {
				want = "0 3 3 1 0"
			}
			if strings.TrimSpace(string(out)) != want {
				t.Fatalf("failed socket setup must remain unsent (mark failure also untrusted): %s", out)
			}
			if len(drain()) != 0 {
				t.Fatal("unisolated fragments reached the wire")
			}
		})
	}
}
