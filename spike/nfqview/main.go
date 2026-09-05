// nfqview — измерительный инструмент этапа 0 d2k. НЕ продуктовый код.
//
// Читает пакеты из NFQUEUE, НИЧЕГО с ними не делает и сразу отпускает
// (NF_ACCEPT). Задача одна: узнать, что датапат вообще способен увидеть на
// живом Keenetic, и во что это обходится.
//
// Почему так, а не tcpdump: tcpdump на роутере висит на netdev и его так же
// слепит аппаратный offload, то есть он ответит на вопрос про себя, а не про
// NFQUEUE. Нужен именно тот источник данных, на котором потом будет стоять
// d2k.
//
// Считается по каждому потоку: сколько пакетов увидела очередь в каждую
// сторону, до какого места ответного потока дошла видимость, какие флаги и
// какие маркеры TLS попались. Это сопоставляется с conntrack и с захватом на
// клиенте — сама очередь про свою слепоту сказать не может.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
)

type flowKey struct {
	proto    uint8
	localIP  netip.Addr
	remoteIP netip.Addr
	localPt  uint16
	remotePt uint16
}

type flowStat struct {
	first, last time.Time
	lastOut     time.Time
	lastIn      time.Time

	outPkts, inPkts   uint64
	outBytes, inBytes uint64

	sawSYN, sawSYNACK bool
	rstIn, rstOut     bool
	finIn, finOut     bool

	clientHello bool
	serverHello bool

	// Куда дотянулась видимость ответного потока: максимальный сдвиг
	// относительно первого увиденного seq сервера. Именно это число, а не
	// счётчик пакетов, отвечает на вопрос «увидим ли обрыв на 300-м килобайте».
	inSeqBase uint32
	inSeqSet  bool
	inSeqMax  uint32

	outSeqBase uint32
	outSeqSet  bool
	outSeqMax  uint32

	// Сумма и максимум не отличают «видели первые N пакетов» от «видели
	// начало и конец, а середину нет». Отличает только распределение,
	// поэтому храним сами сдвиги — ограниченно, чтобы поток не рос без края.
	inSeqSamples  []uint32
	outSeqSamples []uint32

	lastInFIN bool
	lastInRST bool
}

const maxSeqSamples = 96

// qStat — строка ядра про нашу очередь. Порядок полей взят из
// nfnetlink_queue.c (seq_show): queue_num, peer_portid, queue_total,
// copy_mode, copy_range, queue_dropped, queue_user_dropped, id_sequence, 1.
//
// queue_total — это ТЕКУЩАЯ глубина очереди, а не накопленный счётчик;
// накопленное число выданных пакетов показывает id_sequence.
type qStat struct {
	QueueDepth   uint64 `json:"queue_depth_now"`
	CopyMode     uint64 `json:"copy_mode"`
	CopyRange    uint64 `json:"copy_range"`
	QueueDropped uint64 `json:"queue_dropped"`
	UserDropped  uint64 `json:"user_dropped"`
	IDSequence   uint64 `json:"id_sequence"`
}

var (
	fQueue   = flag.Int("q", 200, "номер NFQUEUE")
	fCopyLen = flag.Int("copylen", 128, "сколько байт пакета копировать в userspace")
	fQLen    = flag.Int("qlen", 8192, "глубина очереди в ядре")
	fDur     = flag.Duration("dur", 60*time.Second, "длительность замера")
	fTick    = flag.Duration("tick", 10*time.Second, "интервал промежуточного отчёта")
	fLAN     = flag.String("lan", "192.168.1.0/24", "локальная подсеть: по ней определяется направление")
	fOut     = flag.String("out", "/tmp/nfqview", "префикс файлов результата")
	fBatch   = flag.Bool("batch", false, "групповой вердикт вместо попакетного")
)

func main() {
	flag.Parse()

	lanPrefix, err := netip.ParsePrefix(*fLAN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "плохая подсеть -lan: %v\n", err)
		os.Exit(2)
	}

	var (
		mu    sync.Mutex
		flows = make(map[flowKey]*flowStat)

		pkts, bytesTotal uint64
		parseFail        uint64
		verdictFail      uint64
		nlErrors         uint64

		batchID uint32
		batchN  int
	)
	const batchSize = 16

	cfg := nfqueue.Config{
		NfQueue:      uint16(*fQueue),
		MaxPacketLen: uint32(*fCopyLen),
		MaxQueueLen:  uint32(*fQLen),
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
		// FAIL_OPEN: переполненная очередь пропускает пакет, а не роняет его.
		// Замер идёт на живом домашнем роутере, и цена ошибки инструмента не
		// должна ложиться на пользователя. Сколько прошло мимо — видно по
		// счётчикам ядра, так что честность числа это не портит.
		Flags: nfqueue.NfQaCfgFlagFailOpen,
	}

	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "открыть очередь %d не вышло: %v\n", *fQueue, err)
		os.Exit(1)
	}
	defer nf.Close()

	// ENOBUFS уронил бы чтение при всплеске; нам важнее продолжать считать и
	// узнать про потерю из статистики ядра, чем упасть на первом же всплеске.
	if err := nf.Con.SetOption(netlink.NoENOBUFS, true); err != nil {
		fmt.Fprintf(os.Stderr, "предупреждение: NoENOBUFS не установлен: %v\n", err)
	}
	if err := nf.Con.SetReadBuffer(4 * 1024 * 1024); err != nil {
		fmt.Fprintf(os.Stderr, "предупреждение: буфер чтения не увеличен: %v\n", err)
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *fDur)
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	hook := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID

		// Вердикт первым делом: любая ошибка разбора ниже не должна
		// превращаться в задержанный или потерянный пользовательский пакет.
		if *fBatch {
			// Групповой вердикт накрывает все пакеты вплоть до указанного id.
			// Копить его по остатку от деления нельзя: хвост очереди повиснет
			// до таймаута ядра, то есть замер начнёт тормозить пользователя.
			// Поэтому считаем накопленное и добиваем остаток по таймеру ниже.
			mu.Lock()
			if id > batchID {
				batchID = id
			}
			batchN++
			bid, flush := batchID, batchN >= batchSize
			if flush {
				batchN = 0
			}
			mu.Unlock()
			if flush {
				if err := nf.SetVerdictBatch(bid, nfqueue.NfAccept); err != nil {
					mu.Lock()
					verdictFail++
					mu.Unlock()
				}
			}
		} else if err := nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
			mu.Lock()
			verdictFail++
			mu.Unlock()
		}

		if a.Payload == nil {
			return 0
		}
		p := *a.Payload
		now := time.Now()

		k, st, ok := parse(p, lanPrefix)
		mu.Lock()
		pkts++
		bytesTotal += uint64(len(p))
		if !ok {
			parseFail++
			mu.Unlock()
			return 0
		}
		f := flows[k]
		if f == nil {
			f = &flowStat{first: now}
			flows[k] = f
		}
		f.last = now
		merge(f, st, now)
		mu.Unlock()
		return 0
	}

	var firstNLErr string
	errFn := func(e error) int {
		mu.Lock()
		nlErrors++
		if firstNLErr == "" && e != nil {
			firstNLErr = e.Error()
		}
		mu.Unlock()
		return 0
	}

	if err := nf.RegisterWithErrorFunc(ctx, hook, errFn); err != nil {
		fmt.Fprintf(os.Stderr, "подписка на очередь не удалась: %v\n", err)
		os.Exit(1)
	}

	if *fBatch {
		go func() {
			t := time.NewTicker(20 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					mu.Lock()
					bid, n := batchID, batchN
					batchN = 0
					mu.Unlock()
					if n > 0 {
						_ = nf.SetVerdictBatch(bid, nfqueue.NfAccept)
					}
				}
			}
		}()
	}

	qs0 := readQueueStat(*fQueue)
	cpu0, _ := readSelfCPU()

	// Строка очереди в /proc обнуляется, как только подписка снята, поэтому
	// итоговые счётчики нельзя читать после выхода из цикла. Держим последний
	// непустой снимок: в первой версии итог показывал нули при живых тиках.
	var qsLast qStat
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				q := readQueueStat(*fQueue)
				if q.IDSequence == 0 && q.QueueDropped == 0 && q.UserDropped == 0 {
					continue
				}
				mu.Lock()
				qsLast = q
				mu.Unlock()
			}
		}
	}()

	ticker := time.NewTicker(*fTick)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-ticker.C:
			mu.Lock()
			n, b, nf_ := pkts, bytesTotal, len(flows)
			mu.Unlock()
			qs := readQueueStat(*fQueue)
			el := time.Since(started).Seconds()
			cpu, _ := readSelfCPU()
			rss := readSelfRSS()
			fmt.Printf("[%4.0fс] пакетов=%d (%.0f/с) байт=%d потоков=%d | ядро: выдано=%d глубина=%d дроп-очереди=%d дроп-юзера=%d | cpu=%.1f%% rss=%dКиБ\n",
				el, n, float64(n)/el, b, nf_, qs.IDSequence, qs.QueueDepth, qs.QueueDropped, qs.UserDropped,
				100*(cpu-cpu0)/el, rss/1024)
		}
	}

	cpu1, _ := readSelfCPU()
	elapsed := time.Since(started).Seconds()

	mu.Lock()
	defer mu.Unlock()

	summary := map[string]any{
		"queue":              *fQueue,
		"copylen":            *fCopyLen,
		"qlen":               *fQLen,
		"batch_verdict":      *fBatch,
		"duration_s":         elapsed,
		"packets":            pkts,
		"packets_per_s":      float64(pkts) / elapsed,
		"bytes_copied":       bytesTotal,
		"flows":              len(flows),
		"parse_fail":         parseFail,
		"verdict_fail":       verdictFail,
		"netlink_errors":     nlErrors,
		"netlink_first_error": firstNLErr,
		"kernel_queue_start": qs0,
		"kernel_queue_last":  qsLast,
		"cpu_seconds":        cpu1 - cpu0,
		"cpu_percent":        100 * (cpu1 - cpu0) / elapsed,
		"rss_kib":            readSelfRSS() / 1024,
	}
	js, _ := json.MarshalIndent(summary, "", "  ")
	_ = os.WriteFile(*fOut+".summary.json", append(js, '\n'), 0o644)
	fmt.Println(string(js))

	writeFlows(*fOut+".flows.tsv", flows)
	writeSeqSamples(*fOut+".seq.tsv", flows)
	fmt.Printf("потоки записаны: %s.flows.tsv, выборка seq: %s.seq.tsv (%d потоков)\n", *fOut, *fOut, len(flows))
}

type pktStat struct {
	key      flowKey
	outbound bool
	length   uint64

	syn, ack, rst, fin bool
	seq                uint32
	ch, sh             bool
}

func parse(p []byte, lan netip.Prefix) (flowKey, pktStat, bool) {
	var st pktStat
	if len(p) < 20 {
		return st.key, st, false
	}

	var (
		src, dst netip.Addr
		proto    uint8
		l4       []byte
		total    uint64
	)

	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return st.key, st, false
		}
		total = uint64(binary.BigEndian.Uint16(p[2:4]))
		proto = p[9]
		src, _ = netip.AddrFromSlice(p[12:16])
		dst, _ = netip.AddrFromSlice(p[16:20])
		l4 = p[ihl:]
		// Фрагмент без нулевого смещения не несёт заголовка L4.
		if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
			l4 = nil
		}
	case 6:
		if len(p) < 40 {
			return st.key, st, false
		}
		total = uint64(binary.BigEndian.Uint16(p[4:6])) + 40
		proto = p[6]
		src, _ = netip.AddrFromSlice(p[8:24])
		dst, _ = netip.AddrFromSlice(p[24:40])
		l4 = p[40:]
	default:
		return st.key, st, false
	}
	if !src.IsValid() || !dst.IsValid() {
		return st.key, st, false
	}

	outbound := lan.Contains(src)
	if !outbound && !lan.Contains(dst) {
		// Ни одна сторона не локальная: транзит не наш, направление
		// определить нечем. Не выдумываем — считаем исходящим по факту
		// прихода, но помечаем поток отдельным ключом через remote-адрес.
		outbound = true
	}

	var sport, dport uint16
	if (proto == 6 || proto == 17) && len(l4) >= 4 {
		sport = binary.BigEndian.Uint16(l4[0:2])
		dport = binary.BigEndian.Uint16(l4[2:4])
	}

	k := flowKey{proto: proto}
	if outbound {
		k.localIP, k.remoteIP, k.localPt, k.remotePt = src, dst, sport, dport
	} else {
		k.localIP, k.remoteIP, k.localPt, k.remotePt = dst, src, dport, sport
	}

	st.key = k
	st.outbound = outbound
	st.length = total

	if proto == 6 && len(l4) >= 20 {
		st.seq = binary.BigEndian.Uint32(l4[4:8])
		flags := l4[13]
		st.fin = flags&0x01 != 0
		st.syn = flags&0x02 != 0
		st.rst = flags&0x04 != 0
		st.ack = flags&0x10 != 0
		doff := int(l4[12]>>4) * 4
		if doff >= 20 && len(l4) > doff {
			pay := l4[doff:]
			// Заголовок TLS-записи: тип 0x16 (handshake), версия 0x03xx,
			// затем длина и тип рукопожатия. Хватает первых шести байт.
			if len(pay) >= 6 && pay[0] == 0x16 && pay[1] == 0x03 {
				switch pay[5] {
				case 0x01:
					st.ch = true
				case 0x02:
					st.sh = true
				}
			}
		}
	}
	return k, st, true
}

func merge(f *flowStat, st pktStat, now time.Time) {
	if st.outbound {
		f.outPkts++
		f.outBytes += st.length
		f.lastOut = now
		if st.syn && !st.ack {
			f.sawSYN = true
		}
		if st.rst {
			f.rstOut = true
		}
		if st.fin {
			f.finOut = true
		}
		if st.ch {
			f.clientHello = true
		}
		if st.key.proto == 6 {
			if !f.outSeqSet {
				f.outSeqBase, f.outSeqSet = st.seq, true
			}
			d := st.seq - f.outSeqBase
			if d < 1<<31 {
				if d > f.outSeqMax {
					f.outSeqMax = d
				}
				if len(f.outSeqSamples) < maxSeqSamples {
					f.outSeqSamples = append(f.outSeqSamples, d)
				}
			}
		}
	} else {
		f.inPkts++
		f.inBytes += st.length
		f.lastIn = now
		if st.syn && st.ack {
			f.sawSYNACK = true
		}
		if st.rst {
			f.rstIn = true
		}
		if st.fin {
			f.finIn = true
		}
		if st.sh {
			f.serverHello = true
		}
		f.lastInFIN, f.lastInRST = st.fin, st.rst
		if st.key.proto == 6 {
			if !f.inSeqSet {
				f.inSeqBase, f.inSeqSet = st.seq, true
			}
			d := st.seq - f.inSeqBase
			if d < 1<<31 {
				if d > f.inSeqMax {
					f.inSeqMax = d
				}
				if len(f.inSeqSamples) < maxSeqSamples {
					f.inSeqSamples = append(f.inSeqSamples, d)
				}
			}
		}
	}
}

func writeFlows(path string, flows map[flowKey]*flowStat) {
	type row struct {
		k flowKey
		f *flowStat
	}
	rows := make([]row, 0, len(flows))
	for k, f := range flows {
		rows = append(rows, row{k, f})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].f.inSeqMax > rows[j].f.inSeqMax
	})

	fh, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "не записать потоки: %v\n", err)
		return
	}
	defer fh.Close()
	w := bufio.NewWriter(fh)
	defer w.Flush()

	fmt.Fprintln(w, strings.Join([]string{
		"proto", "local", "lport", "remote", "rport",
		"out_pkts", "in_pkts", "out_bytes", "in_bytes",
		"seen_out_span", "seen_in_span",
		"syn", "synack", "rst_in", "rst_out", "fin_in", "fin_out",
		"client_hello", "server_hello", "last_in_fin", "last_in_rst",
		"life_s", "last_in_after_s", "last_out_after_s",
	}, "\t"))

	for _, r := range rows {
		f := r.f
		lastIn, lastOut := -1.0, -1.0
		if !f.lastIn.IsZero() {
			lastIn = f.lastIn.Sub(f.first).Seconds()
		}
		if !f.lastOut.IsZero() {
			lastOut = f.lastOut.Sub(f.first).Seconds()
		}
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f\t%.2f\t%.2f\n",
			r.k.proto, r.k.localIP, r.k.localPt, r.k.remoteIP, r.k.remotePt,
			f.outPkts, f.inPkts, f.outBytes, f.inBytes,
			f.outSeqMax, f.inSeqMax,
			b(f.sawSYN), b(f.sawSYNACK), b(f.rstIn), b(f.rstOut), b(f.finIn), b(f.finOut),
			b(f.clientHello), b(f.serverHello), b(f.lastInFIN), b(f.lastInRST),
			f.last.Sub(f.first).Seconds(), lastIn, lastOut)
	}
}

// writeSeqSamples — сдвиги seq тех пакетов, что реально дошли до очереди.
// Отвечает на вопрос, который сумма не отвечает: видим ли мы середину потока
// или только его начало и конец.
func writeSeqSamples(path string, flows map[flowKey]*flowStat) {
	fh, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "не записать выборку seq: %v\n", err)
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
				dir, k.localIP, k.localPt, k.remoteIP, k.remotePt, span, len(s), strings.Join(parts, ","))
		}
		emit("in", f.inSeqMax, f.inSeqSamples)
		emit("out", f.outSeqMax, f.outSeqSamples)
	}
}

func b(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// readQueueStat — счётчики самого ядра по нашей очереди. Единственный
// источник правды о том, сколько пакетов ядро в очередь положило и сколько
// выбросило, не дождавшись вердикта.
func readQueueStat(q int) qStat {
	var s qStat
	fh, err := os.Open("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return s
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 9 {
			continue
		}
		if n, err := strconv.Atoi(fields[0]); err != nil || n != q {
			continue
		}
		s.QueueDepth = mustU(fields[2])
		s.CopyMode = mustU(fields[3])
		s.CopyRange = mustU(fields[4])
		s.QueueDropped = mustU(fields[5])
		s.UserDropped = mustU(fields[6])
		s.IDSequence = mustU(fields[7])
		return s
	}
	return s
}

func mustU(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func readSelfCPU() (float64, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	// После имени процесса в скобках поля идут по порядку; utime — 14-е.
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 {
		return 0, fmt.Errorf("нераспознанный /proc/self/stat")
	}
	fields := strings.Fields(string(data)[i+1:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("мало полей в /proc/self/stat")
	}
	ut := mustU(fields[11])
	stt := mustU(fields[12])
	return float64(ut+stt) / 100.0, nil
}

func readSelfRSS() uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	return mustU(fields[1]) * uint64(os.Getpagesize())
}

