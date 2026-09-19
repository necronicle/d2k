//go:build d2k_donor

package quicprobe

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func donorBlobs(t *testing.T) {
	t.Helper()
	old := blobDir
	blobDir = os.Getenv("D2K_QUIC_BLOBS")
	if blobDir == "" {
		t.Fatal("D2K_QUIC_BLOBS required")
	}
	t.Cleanup(func() { blobDir = old })
}

func TestD2KBlobParity(t *testing.T) {
	donorBlobs(t)
	out, err := exec.Command(os.Getenv("D2K_QUIC_RUN_BIN"), "--blobs").CombinedOutput()
	if err != nil {
		t.Fatalf("C: %v %s", err, out)
	}
	var want strings.Builder
	for _, b := range blobs {
		body := blobBytes(b.name, b.file)
		if body == nil {
			t.Fatalf("missing original data %s", b.name)
		}
		fmt.Fprintf(&want, "%s %x\n", b.name, body)
	}
	if string(out) != want.String() {
		t.Fatal("C embedded bytes differ from original blobBytes")
	}
}

// This oracle requires an EXACT original fake on the same UDP socket before
// the authenticated Initial. It tests measurement, not an HTTP/3 application.
func startArmScenario(t *testing.T, residual string) localScenario {
	t.Helper()
	fake := blobBytes("quic5", "quic_5.bin")
	if len(fake) != 1200 {
		t.Fatal("missing quic5 fixture")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		seen := map[string]time.Time{}
		controls := 0
		for {
			b := make([]byte, 2048)
			n, a, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			b = b[:n]
			if bytes.Equal(b, fake) {
				seen[a.String()] = time.Now()
				continue
			}
			target, reply, e := initialAnswer(b)
			if e != nil {
				continue
			}
			// A bounded fake state exposes an invented 60 ms pause in C's
			// old transport. Original sends the fake and Initial back-to-back.
			at, prefixed := seen[a.String()]
			allow := target && prefixed && time.Since(at) < 40*time.Millisecond
			if !target && residual != "" {
				controls++
				allow = controls <= 3 || (residual == "partial" && controls == 4)
			}
			if allow {
				_, _ = c.WriteToUDP(reply, a)
			}
			delete(seen, a.String())
		}
	}()
	return localScenario{c.LocalAddr().(*net.UDPAddr).Port, func() { c.Close(); <-done }}
}

func TestD2KArmsParity(t *testing.T) {
	donorBlobs(t)
	ref := startArmScenario(t, "")
	pool := addrPool{pinned: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ref.port}}
	opt := Options{Port: ref.port, Repeats: 3, Parallel: 3, Timeout: 40 * time.Millisecond}
	var want Result
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	askArms(ctx, &pool, "blocked.example", opt, opt.Timeout, &want)
	cancel()
	ref.stop()
	// Raw fragments are not available in this unprivileged parity lab. A raw
	// capability must not silently turn this into a different acceptance test.
	if want.Props.FakeAhead != "quic5" || want.Props.FakeRepeats != 6 || want.Props.FakeTTL != 3 ||
		want.Probes != 9 || len(want.Trace) != 4 || want.Trace[3].NotBuilt != 3 {
		t.Fatalf("unexpected donor result: %+v trace=%+v", want.Props, want.Trace)
	}
	local := startArmScenario(t, "")
	defer local.stop()
	out, err := exec.Command(os.Getenv("D2K_QUIC_RUN_BIN"), strconv.Itoa(local.port), "arms").CombinedOutput()
	if err != nil {
		t.Fatalf("C: %v %s", err, out)
	}
	var expected strings.Builder
	fmt.Fprintf(&expected, "%s %d %d %d\n", want.Props.FakeAhead, want.Props.FakeRepeats, want.Props.FakeTTL, want.Probes)
	for _, s := range want.Trace {
		notMeasured := 0
		if s.NotBuilt > 0 {
			notMeasured = 3
		}
		fmt.Fprintf(&expected, "%s|%d|%d|%d\n", s.Name, s.Sent-s.NotBuilt, s.Answered, notMeasured)
	}
	if string(out) != expected.String() {
		t.Fatalf("C:\n%s\ndonor:\n%s", out, expected.String())
	}
}

func TestD2KResidualParity(t *testing.T) {
	donorBlobs(t)
	for _, mode := range []string{"blocked", "partial"} {
		t.Run(mode, func(t *testing.T) {
			ref := startArmScenario(t, mode)
			opt := Options{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(ref.port)), AllowLoopback: true,
				Port: ref.port, Repeats: 3, Timeout: 40 * time.Millisecond}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			want := Run(ctx, "blocked.example", opt)
			cancel()
			ref.stop()
			residual := mode == "blocked"
			if want.Verdict != VerdictContent || want.Props.ResidualBlocking == nil ||
				*want.Props.ResidualBlocking != residual {
				t.Fatalf("unexpected donor: %+v", want)
			}
			if residual && want.Probes != 9 {
				t.Fatalf("fresh pool should be exhausted: %+v", want)
			}
			if !residual && (want.Props.FakeAhead != "quic5" || want.Props.FakeRepeats != 6 || want.Props.FakeTTL != 3) {
				t.Fatalf("partial residual control must allow pinned arm search: %+v", want)
			}
			local := startArmScenario(t, mode)
			defer local.stop()
			out, err := exec.Command(os.Getenv("D2K_QUIC_RUN_BIN"), strconv.Itoa(local.port), "content").CombinedOutput()
			if err != nil {
				t.Fatalf("C: %v %s", err, out)
			}
			residualValue := 1
			if residual {
				residualValue = 2
			}
			expected := fmt.Sprintf("%s %d %s %d %d\n", want.Verdict, residualValue,
				want.Props.FakeAhead, want.Props.FakeRepeats, want.Props.FakeTTL)
			if string(out) != expected {
				t.Fatalf("C: %s donor: %s", out, expected)
			}
		})
	}
}
