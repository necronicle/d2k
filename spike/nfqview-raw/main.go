// nfqview-raw — Go без netlink-библиотеки, на голых системных вызовах.
// Инструмент замера этапа 0 d2k, НЕ продуктовый код.
//
// Зачем существует. Замер 05-09 показал: Go через mdlayher/netlink стоит
// ~110 мкс CPU на пакет, C на сыром netlink — ~14 мкс. Разница восьмикратная,
// и по двум реализациям нельзя сказать, чья это цена: языка или библиотеки.
// Эта версия повторяет C построчно — тот же цикл, тот же разбор, тот же
// предвыделенный буфер, никаких каналов и колбэков — и потому отвечает
// именно на этот вопрос.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	netlinkNetfilter = 12
	nfnlSubsysQueue  = 3

	nfqnlMsgPacket       = 0
	nfqnlMsgVerdict      = 1
	nfqnlMsgConfig       = 2
	nfqnlMsgVerdictBatch = 3

	nfqaCfgCmd         = 1
	nfqaCfgParams      = 2
	nfqaCfgQueueMaxLen = 3
	nfqaCfgMask        = 4
	nfqaCfgFlags       = 5

	nfqnlCfgCmdBind = 1

	nfqnlCopyMeta   = 1
	nfqnlCopyPacket = 2

	nfqaCfgFFailOpen = 1 << 0
	nfqaCfgFGSO      = 1 << 2

	// Значения из enum nfqnl_attr_type ядра. VERDICT_HDR = 2, а НЕ 1:
	// единицу занимает PACKET_HDR. С единицей ядро не находит заголовок
	// вердикта среди разобранных атрибутов и отвечает EINVAL, а sendto при
	// этом возвращает успех — пакеты молча копятся в очереди.
	nfqaPacketHdr  = 1
	nfqaVerdictHdr = 2
	nfqaPayload    = 10

	nfAccept = 1

	// SOL_NETLINK и NETLINK_NO_ENOBUFS в пакете syscall не объявлены.
	solNetlink       = 270
	netlinkNoENOBUFS = 5

	nlmsgHdrLen = 16
	nlaHdrLen   = 4
	nfgenMsgLen = 4

	recvBuf       = 256 * 1024
	maxSeqSamples = 96
)

func align4(n int) int { return (n + 3) &^ 3 }

type flowKey struct {
	proto            uint8
	localIP, remote  netip.Addr
	localPt, remotePt uint16
}

type flowStat struct {
	first, last, lastIn, lastOut float64

	outPkts, inPkts   uint64
	outBytes, inBytes uint64

	sawSYN, sawSYNACK, rstIn, rstOut, finIn, finOut bool
	clientHello, serverHello, lastInFIN, lastInRST  bool

	inBase, outBase uint32
	inSet, outSet   bool
	inMax, outMax   uint32

	inSamples, outSamples []uint32
}

var (
	fQueue   = flag.Int("q", 200, "номер NFQUEUE")
	fCopyLen = flag.Int("copylen", 128, "байт пакета в юзерспейс, 0 — только метаданные")
	fQLen    = flag.Int("qlen", 8192, "глубина очереди в ядре")
	fDur     = flag.Duration("dur", 60*time.Second, "длительность замера")
	fTick    = flag.Duration("tick", 10*time.Second, "интервал отчёта")
	fLAN     = flag.String("lan", "192.168.1.0/24", "локальная подсеть")
	fOut     = flag.String("out", "/tmp/nfqview-raw", "префикс файлов результата")
	fBatch   = flag.Bool("batch", false, "групповой вердикт")
	fGSO     = flag.Bool("gso", false, "просить ядро не резать объединённые сегменты")
)

var (
	fd       int
	seqNum   uint32
	flows    = make(map[flowKey]*flowStat)
	lanPfx   netip.Prefix
	stPkts   uint64
	stBytes  uint64
	stParse  uint64
	stVerdct uint64
	stRecv   uint64
	errShown int
	dumpLeft = 0
)

func nowSec() float64 {
	var ts syscall.Timespec
	// CLOCK_MONOTONIC = 1
	_, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0)
	if e != 0 {
		return float64(time.Now().UnixNano()) / 1e9
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}

// msgInit собирает заголовок netlink-сообщения в переданный буфер и
// возвращает его текущую длину. Буфер переиспользуется — выделений на пакет
// быть не должно, в этом весь смысл этой версии.
func msgInit(b []byte, typ uint16, flags uint16, queue uint16) int {
	for i := 0; i < nlmsgHdrLen+nfgenMsgLen; i++ {
		b[i] = 0
	}
	binary.LittleEndian.PutUint32(b[0:4], uint32(nlmsgHdrLen+nfgenMsgLen))
	binary.LittleEndian.PutUint16(b[4:6], typ)
	binary.LittleEndian.PutUint16(b[6:8], flags)
	seqNum++
	binary.LittleEndian.PutUint32(b[8:12], seqNum)
	b[nlmsgHdrLen] = syscall.AF_UNSPEC // nfgen_family
	b[nlmsgHdrLen+1] = 0               // version
	binary.BigEndian.PutUint16(b[nlmsgHdrLen+2:], queue)
	return nlmsgHdrLen + nfgenMsgLen
}

func putAttr(b []byte, l int, typ uint16, data []byte) int {
	l = align4(l)
	binary.LittleEndian.PutUint16(b[l:], uint16(nlaHdrLen+len(data)))
	binary.LittleEndian.PutUint16(b[l+2:], typ)
	copy(b[l+nlaHdrLen:], data)
	l += nlaHdrLen + len(data)
	binary.LittleEndian.PutUint32(b[0:4], uint32(align4(l)))
	return align4(l)
}

var sa = &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}

func send(b []byte, l int) error { return syscall.Sendto(fd, b[:l], 0, sa) }

func queueConfig() error {
	b := make([]byte, 512)

	cmd := make([]byte, 4)
	cmd[0] = nfqnlCfgCmdBind
	binary.BigEndian.PutUint16(cmd[2:], syscall.AF_INET)
	l := msgInit(b, nfnlSubsysQueue<<8|nfqnlMsgConfig, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, uint16(*fQueue))
	l = putAttr(b, l, nfqaCfgCmd, cmd)
	if err := send(b, l); err != nil {
		return fmt.Errorf("bind очереди: %w", err)
	}

	// struct nfqnl_msg_config_params упакована: be32 copy_range + u8 copy_mode.
	params := make([]byte, 5)
	binary.BigEndian.PutUint32(params[0:], uint32(*fCopyLen))
	if *fCopyLen > 0 {
		params[4] = nfqnlCopyPacket
	} else {
		params[4] = nfqnlCopyMeta
	}
	maxlen := make([]byte, 4)
	binary.BigEndian.PutUint32(maxlen, uint32(*fQLen))
	fl := uint32(nfqaCfgFFailOpen)
	if *fGSO {
		fl |= nfqaCfgFGSO
	}
	flags := make([]byte, 4)
	binary.BigEndian.PutUint32(flags, fl)
	mask := make([]byte, 4)
	binary.BigEndian.PutUint32(mask, nfqaCfgFFailOpen|nfqaCfgFGSO)

	l = msgInit(b, nfnlSubsysQueue<<8|nfqnlMsgConfig, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, uint16(*fQueue))
	l = putAttr(b, l, nfqaCfgParams, params)
	l = putAttr(b, l, nfqaCfgQueueMaxLen, maxlen)
	l = putAttr(b, l, nfqaCfgFlags, flags)
	l = putAttr(b, l, nfqaCfgMask, mask)
	if err := send(b, l); err != nil {
		return fmt.Errorf("параметры очереди: %w", err)
	}
	return nil
}

var vbuf = make([]byte, 128)
var vhdr = make([]byte, 8)

func sendVerdict(id uint32, batch bool) error {
	typ := uint16(nfnlSubsysQueue<<8 | nfqnlMsgVerdict)
	if batch {
		typ = nfnlSubsysQueue<<8 | nfqnlMsgVerdictBatch
	}
	binary.BigEndian.PutUint32(vhdr[0:], nfAccept)
	binary.BigEndian.PutUint32(vhdr[4:], id)
	l := msgInit(vbuf, typ, syscall.NLM_F_REQUEST, uint16(*fQueue))
	l = putAttr(vbuf, l, nfqaVerdictHdr, vhdr)
	if dumpLeft > 0 {
		dumpLeft--
		fmt.Fprintf(os.Stderr, "[вердикт] %d байт: % x\n", l, vbuf[:l])
	}
	return send(vbuf, l)
}

func account(p []byte, t float64) {
	if len(p) < 20 {
		stParse++
		return
	}
	var src, dst netip.Addr
	var proto uint8
	var total uint64
	var l4 []byte

	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			stParse++
			return
		}
		total = uint64(binary.BigEndian.Uint16(p[2:4]))
		proto = p[9]
		src, _ = netip.AddrFromSlice(p[12:16])
		dst, _ = netip.AddrFromSlice(p[16:20])
		if binary.BigEndian.Uint16(p[6:8])&0x1fff == 0 {
			l4 = p[ihl:]
		}
	case 6:
		if len(p) < 40 {
			stParse++
			return
		}
		total = uint64(binary.BigEndian.Uint16(p[4:6])) + 40
		proto = p[6]
		src, _ = netip.AddrFromSlice(p[8:24])
		dst, _ = netip.AddrFromSlice(p[24:40])
		l4 = p[40:]
	default:
		stParse++
		return
	}
	if !src.IsValid() || !dst.IsValid() {
		stParse++
		return
	}

	outbound := true
	if lanPfx.Contains(src) {
		outbound = true
	} else if lanPfx.Contains(dst) {
		outbound = false
	}

	var sport, dport uint16
	if (proto == 6 || proto == 17) && len(l4) >= 4 {
		sport = binary.BigEndian.Uint16(l4[0:2])
		dport = binary.BigEndian.Uint16(l4[2:4])
	}

	k := flowKey{proto: proto}
	if outbound {
		k.localIP, k.remote, k.localPt, k.remotePt = src, dst, sport, dport
	} else {
		k.localIP, k.remote, k.localPt, k.remotePt = dst, src, dport, sport
	}

	f := flows[k]
	if f == nil {
		f = &flowStat{first: t}
		flows[k] = f
	}
	f.last = t

	var fin, syn, rst, ack, ch, sh bool
	var seq uint32
	if proto == 6 && len(l4) >= 20 {
		seq = binary.BigEndian.Uint32(l4[4:8])
		fl := l4[13]
		fin, syn, rst, ack = fl&0x01 != 0, fl&0x02 != 0, fl&0x04 != 0, fl&0x10 != 0
		doff := int(l4[12]>>4) * 4
		if doff >= 20 && len(l4) > doff {
			pay := l4[doff:]
			if len(pay) >= 6 && pay[0] == 0x16 && pay[1] == 0x03 {
				ch = pay[5] == 0x01
				sh = pay[5] == 0x02
			}
		}
	}

	if outbound {
		f.outPkts++
		f.outBytes += total
		f.lastOut = t
		if syn && !ack {
			f.sawSYN = true
		}
		f.rstOut = f.rstOut || rst
		f.finOut = f.finOut || fin
		f.clientHello = f.clientHello || ch
		if proto == 6 {
			if !f.outSet {
				f.outBase, f.outSet = seq, true
			}
			if d := seq - f.outBase; d < 1<<31 {
				if d > f.outMax {
					f.outMax = d
				}
				if len(f.outSamples) < maxSeqSamples {
					f.outSamples = append(f.outSamples, d)
				}
			}
		}
	} else {
		f.inPkts++
		f.inBytes += total
		f.lastIn = t
		if syn && ack {
			f.sawSYNACK = true
		}
		f.rstIn = f.rstIn || rst
		f.finIn = f.finIn || fin
		f.serverHello = f.serverHello || sh
		f.lastInFIN, f.lastInRST = fin, rst
		if proto == 6 {
			if !f.inSet {
				f.inBase, f.inSet = seq, true
			}
			if d := seq - f.inBase; d < 1<<31 {
				if d > f.inMax {
					f.inMax = d
				}
				if len(f.inSamples) < maxSeqSamples {
					f.inSamples = append(f.inSamples, d)
				}
			}
		}
	}
}

type qStat struct{ depth, copyMode, copyRange, dropped, userDropped, idSeq uint64 }

func readQStat() qStat {
	var s qStat
	fh, err := os.Open("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return s
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		if n, err := strconv.Atoi(f[0]); err != nil || n != *fQueue {
			continue
		}
		u := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		s.depth, s.copyMode, s.copyRange = u(2), u(3), u(4)
		s.dropped, s.userDropped, s.idSeq = u(5), u(6), u(7)
		return s
	}
	return s
}

func readSelfCPU() float64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(data)[i+1:])
	if len(f) < 13 {
		return 0
	}
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	return float64(ut+st) / 100.0
}

func readSelfRSS() uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(f[1], 10, 64)
	return v * uint64(os.Getpagesize())
}

func main() {
	flag.Parse()

	var err error
	lanPfx, err = netip.ParsePrefix(*fLAN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "плохая подсеть -lan: %v\n", err)
		os.Exit(2)
	}

	fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkNetfilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket netlink: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, solNetlink, netlinkNoENOBUFS, 1); err != nil {
		fmt.Fprintf(os.Stderr, "предупреждение: NO_ENOBUFS: %v\n", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024); err != nil {
		fmt.Fprintf(os.Stderr, "предупреждение: SO_RCVBUF: %v\n", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		fmt.Fprintf(os.Stderr, "bind: %v\n", err)
		os.Exit(1)
	}
	if err := queueConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	stopped := false
	go func() { <-stop; stopped = true }()

	// Таймаут на чтение нужен, чтобы тик отчёта и выход по времени случались
	// и в полной тишине на линии.
	// 20 мс, а не 200: в групповом режиме этим таймаутом добирается остаток
	// пачки, и при 200 мс хвост каждой группы застревал на пятую долю секунды.
	// Из-за этого go-raw-batch показывал 6,4 МБ/с при самом низком CPU — цена
	// была моя, не механизма.
	tv := syscall.Timeval{Sec: 0, Usec: 20000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	buf := make([]byte, recvBuf)
	q0 := readQStat()
	qLast := q0
	t0, cpu0 := nowSec(), readSelfCPU()
	nextTick := t0 + fTick.Seconds()

	var batchID uint32
	batchN := 0
	const batchSize = 16

	for !stopped {
		t := nowSec()
		if t-t0 >= fDur.Seconds() {
			break
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				if *fBatch && batchN > 0 {
					_ = sendVerdict(batchID, true)
					batchN = 0
				}
			} else {
				stRecv++
			}
		} else {
			t = nowSec()
			// Границы считаются явно, без вычитания выровненной длины из
			// остатка: у последнего атрибута хвоста выравнивания может не быть.
			left, pos := n, 0
			for left >= nlmsgHdrLen {
				mlen := int(binary.LittleEndian.Uint32(buf[pos:]))
				mtype := binary.LittleEndian.Uint16(buf[pos+4:])
				if mlen < nlmsgHdrLen || mlen > left {
					break
				}
				// Ядро отвечает NLMSG_ERROR на кривой запрос. Без этой ветки
				// ошибка вердикта выглядит как «отправлено успешно»: sendto
				// возвращает nil, а пакеты копятся в очереди.
				if mtype == syscall.NLMSG_ERROR && errShown < 3 {
					code := int32(binary.LittleEndian.Uint32(buf[pos+nlmsgHdrLen:]))
					badType := binary.LittleEndian.Uint16(buf[pos+nlmsgHdrLen+4+4:])
					fmt.Fprintf(os.Stderr, "[ядро] ошибка %d (%s) на сообщение type=0x%04x\n",
						code, syscall.Errno(-code), badType)
					errShown++
				}
				if mtype&0xff == nfqnlMsgPacket && mtype != syscall.NLMSG_ERROR && mtype != syscall.NLMSG_DONE {
					var id uint32
					var haveID bool
					var payload []byte

					aleft := mlen - nlmsgHdrLen - nfgenMsgLen
					ap := pos + nlmsgHdrLen + nfgenMsgLen
					for aleft >= nlaHdrLen {
						alen := int(binary.LittleEndian.Uint16(buf[ap:]))
						atype := binary.LittleEndian.Uint16(buf[ap+2:]) & 0x3fff
						if alen < nlaHdrLen || alen > aleft {
							break
						}
						switch {
						case atype == nfqaPacketHdr && alen-nlaHdrLen >= 7:
							id = binary.BigEndian.Uint32(buf[ap+nlaHdrLen:])
							haveID = true
						case atype == nfqaPayload:
							payload = buf[ap+nlaHdrLen : ap+alen]
						}
						step := align4(alen)
						if step > aleft {
							break
						}
						ap += step
						aleft -= step
					}

					if haveID {
						if *fBatch {
							if id > batchID {
								batchID = id
							}
							batchN++
							if batchN >= batchSize {
								if sendVerdict(batchID, true) != nil {
									stVerdct++
								}
								batchN = 0
							}
						} else if sendVerdict(id, false) != nil {
							stVerdct++
						}
						stPkts++
						if payload != nil {
							stBytes += uint64(len(payload))
							account(payload, t)
						}
					}
				}
				step := align4(mlen)
				if step > left {
					break
				}
				pos += step
				left -= step
			}
		}

		t = nowSec()
		if t >= nextTick {
			q := readQStat()
			if q.idSeq != 0 || q.dropped != 0 || q.userDropped != 0 {
				qLast = q
			}
			el := t - t0
			cpu := readSelfCPU() - cpu0
			fmt.Printf("[%4.0fс] пакетов=%d (%.0f/с) байт=%d потоков=%d | ядро: выдано=%d глубина=%d дроп-очереди=%d дроп-юзера=%d | cpu=%.1f%% rss=%dКиБ\n",
				el, stPkts, float64(stPkts)/el, stBytes, len(flows), q.idSeq, q.depth, q.dropped, q.userDropped,
				100*cpu/el, readSelfRSS()/1024)
			nextTick = t + fTick.Seconds()
		}
	}

	if *fBatch && batchN > 0 {
		_ = sendVerdict(batchID, true)
	}

	elapsed := nowSec() - t0
	cpu := readSelfCPU() - cpu0
	if q := readQStat(); q.idSeq != 0 || q.dropped != 0 || q.userDropped != 0 {
		qLast = q
	}

	summary := fmt.Sprintf(`{
  "impl": "go-raw",
  "queue": %d,
  "copylen": %d,
  "qlen": %d,
  "gso": %v,
  "batch_verdict": %v,
  "duration_s": %.3f,
  "packets": %d,
  "packets_per_s": %.1f,
  "bytes_copied": %d,
  "flows": %d,
  "parse_fail": %d,
  "verdict_fail": %d,
  "recv_errors": %d,
  "cpu_seconds": %.2f,
  "cpu_percent": %.2f,
  "rss_kib": %d,
  "kernel_queue_start": {"queue_depth_now": %d, "copy_mode": %d, "copy_range": %d, "queue_dropped": %d, "user_dropped": %d, "id_sequence": %d},
  "kernel_queue_last": {"queue_depth_now": %d, "copy_mode": %d, "copy_range": %d, "queue_dropped": %d, "user_dropped": %d, "id_sequence": %d}
}
`, *fQueue, *fCopyLen, *fQLen, *fGSO, *fBatch, elapsed, stPkts, float64(stPkts)/elapsed, stBytes,
		len(flows), stParse, stVerdct, stRecv, cpu, 100*cpu/elapsed, readSelfRSS()/1024,
		q0.depth, q0.copyMode, q0.copyRange, q0.dropped, q0.userDropped, q0.idSeq,
		qLast.depth, qLast.copyMode, qLast.copyRange, qLast.dropped, qLast.userDropped, qLast.idSeq)
	_ = os.WriteFile(*fOut+".summary.json", []byte(summary), 0o644)
	fmt.Print(summary)

	writeFlows(*fOut+".flows.tsv")
	writeSeq(*fOut + ".seq.tsv")
	fmt.Fprintf(os.Stderr, "потоки записаны: %s.flows.tsv (%d)\n", *fOut, len(flows))
}

func b(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func writeFlows(path string) {
	fh, err := os.Create(path)
	if err != nil {
		return
	}
	defer fh.Close()
	w := bufio.NewWriter(fh)
	defer w.Flush()
	fmt.Fprintln(w, "proto\tlocal\tlport\tremote\trport\tout_pkts\tin_pkts\tout_bytes\tin_bytes\t"+
		"seen_out_span\tseen_in_span\tsyn\tsynack\trst_in\trst_out\tfin_in\tfin_out\t"+
		"client_hello\tserver_hello\tlast_in_fin\tlast_in_rst\tlife_s\tlast_in_after_s\tlast_out_after_s")
	for k, f := range flows {
		li, lo := -1.0, -1.0
		if f.lastIn > 0 {
			li = f.lastIn - f.first
		}
		if f.lastOut > 0 {
			lo = f.lastOut - f.first
		}
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f\t%.2f\t%.2f\n",
			k.proto, k.localIP, k.localPt, k.remote, k.remotePt,
			f.outPkts, f.inPkts, f.outBytes, f.inBytes, f.outMax, f.inMax,
			b(f.sawSYN), b(f.sawSYNACK), b(f.rstIn), b(f.rstOut), b(f.finIn), b(f.finOut),
			b(f.clientHello), b(f.serverHello), b(f.lastInFIN), b(f.lastInRST),
			f.last-f.first, li, lo)
	}
}

func writeSeq(path string) {
	fh, err := os.Create(path)
	if err != nil {
		return
	}
	defer fh.Close()
	w := bufio.NewWriter(fh)
	defer w.Flush()
	fmt.Fprintln(w, "dir\tlocal\tlport\tremote\trport\tspan\tn_seen\toffsets")
	for k, f := range flows {
		if k.proto != 6 {
			continue
		}
		emit := func(dir string, span uint32, s []uint32) {
			if len(s) == 0 {
				return
			}
			parts := make([]string, len(s))
			for i, v := range s {
				parts[i] = strconv.FormatUint(uint64(v), 10)
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%d\t%d\t%d\t%s\n",
				dir, k.localIP, k.localPt, k.remote, k.remotePt, span, len(s), strings.Join(parts, ","))
		}
		emit("in", f.inMax, f.inSamples)
		emit("out", f.outMax, f.outSamples)
	}
}
