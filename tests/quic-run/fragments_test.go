//go:build d2k_donor

package quicprobe

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestD2KFragmentsParity(t *testing.T) {
	plans := []fragPlan{
		{pos1: 8}, {pos1: 8, disorder: true},
		{three: true, pos1: 8, pos2: 32, ov12: 8, ov23: 8, disorder: true},
		{three: true, pos1: 16, pos2: 48, ov12: 8, ov23: 8, disorder: true},
		{pos1: 30}, {three: true, pos1: 8},
		{three: true, pos1: 16, pos2: 9, ov12: 65535, ov23: 65535},
		{three: true, pos1: 24, pos2: 65535, ov12: 3, ov23: 7},
	}
	for pi, p := range plans {
		for _, n := range []int{0, 1, 8, 16, 17, 24, 25, 31, 32, 33, 1200, 1499} {
			payload := make([]byte, n)
			for i := range payload {
				payload[i] = byte(i)
			}
			want, err := buildFragments(net.IPv4(10, 0, 0, 1), net.IPv4(93, 184, 216, 34), 51234, 443, payload, p, 0x1234)
			expected := "ERR\n"
			if err == nil {
				var b strings.Builder
				for _, f := range want {
					fmt.Fprintf(&b, "%x\n", f)
				}
				expected = b.String()
			}
			three, reverse := 0, 0
			if p.three {
				three = 1
			}
			if p.disorder {
				reverse = 1
			}
			args := []string{"--fragments"}
			for _, v := range []int{n, three, p.pos1, p.pos2, p.ov12, p.ov23, reverse} {
				args = append(args, strconv.Itoa(v))
			}
			out, e := exec.Command(os.Getenv("D2K_QUIC_RUN_BIN"), args...).CombinedOutput()
			if e != nil {
				t.Fatalf("C plan %d len %d: %v %s", pi, n, e, out)
			}
			if string(out) != expected {
				t.Fatalf("wire differs: plan %d len %d\nC: %s\nGo: %s", pi, n, out, expected)
			}
		}
	}
}
