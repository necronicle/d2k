package volume

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// stand — мишень для проб: считает принятые байты и рвёт соединение, когда их
// набралось больше порога. Без стенда правила пробы пришлось бы проверять на
// живой линии, то есть мерить чужую политику вместо своего кода.
type stand struct {
	// cutAt — сколько байт принять, прежде чем оборвать. Ноль — не рвать.
	cutAt int
	// body — длина тела в ответе на GET.
	body int
	// noLen — не объявлять длину тела: случай, в котором обрыв неотличим от
	// конца документа.
	noLen bool
}

func (s stand) start(t *testing.T) Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return Target{IP: "127.0.0.1", Port: addr.Port, Plain: true}
}

func (s stand) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	got := 0
	for {
		head := false
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			got += len(line)
			if s.cutAt > 0 && got > s.cutAt {
				return // обрыв: столько мы принимать не подписывались
			}
			if strings.HasPrefix(line, "HEAD ") {
				head = true
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		if head || s.body == 0 {
			if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); err != nil {
				return
			}
			continue
		}
		hdr := "HTTP/1.1 200 OK\r\n"
		if !s.noLen {
			hdr += fmt.Sprintf("Content-Length: %d\r\n", s.body)
		}
		if _, err := c.Write([]byte(hdr + "\r\n" + strings.Repeat("x", s.body))); err != nil {
			return
		}
		if s.noLen {
			return // без длины иначе не показать конец тела
		}
	}
}

func probeStand(t *testing.T, s stand, pump Pump) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Probe(ctx, s.start(t), "", pump)
}

func TestЖиваяМишеньПроходитЛестницуЦеликом(t *testing.T) {
	r := probeStand(t, stand{}, PumpOut)
	if r.Verdict != VerdictPassed {
		t.Fatalf("вердикт %v (%s), ожидалось «объём прошёл»", r.Verdict, r.Err)
	}
	if r.AtKB != ChunkCount*ChunkSize/1024 {
		t.Errorf("объём %d КБ, ожидалось %d", r.AtKB, ChunkCount*ChunkSize/1024)
	}
}

func TestОбрывЗаПорогомЭтоНашКласс(t *testing.T) {
	r := probeStand(t, stand{cutAt: 20000}, PumpOut)
	if r.Verdict != VerdictCut {
		t.Fatalf("вердикт %v (%s), ожидался обрыв по объёму", r.Verdict, r.Err)
	}
	if r.AtKB < MinDetectKB {
		t.Errorf("обрыв записан на %d КБ — это ниже порога, вердикта быть не должно", r.AtKB)
	}
}

func TestОбрывДоПорогаВердиктаНеДаёт(t *testing.T) {
	// Соединения рвутся по десятку обычных причин. Приписывать такой обрыв
	// блокировке — выдумывать её.
	r := probeStand(t, stand{cutAt: 5000}, PumpOut)
	if r.Verdict == VerdictCut {
		t.Fatalf("обрыв на %d КБ объявлен блокировкой, а порог %d КБ", r.AtKB, MinDetectKB)
	}
	if r.Verdict != VerdictShort {
		t.Errorf("вердикт %v, ожидалось «объём не набран»", r.Verdict)
	}
}

func TestСмертьНаПервомЗапросеЭтоНедоступность(t *testing.T) {
	r := probeStand(t, stand{cutAt: 10}, PumpOut)
	if r.Verdict != VerdictUnreachable {
		t.Fatalf("вердикт %v, ожидалась недоступность мишени", r.Verdict)
	}
	if r.Detected() {
		t.Error("недоступная мишень записана как найденный блок")
	}
}

func TestВходящаяНакачкаНаборуОбъёмаРавнаПрохождению(t *testing.T) {
	want := ChunkCount * ChunkSize
	r := probeStand(t, stand{body: want + 1024}, PumpIn)
	if r.Verdict != VerdictPassed {
		t.Fatalf("вердикт %v (%s), ожидалось «объём прошёл»", r.Verdict, r.Err)
	}
}

func TestКороткийДокументНеЗначитОтсутствиеБлока(t *testing.T) {
	// Мишень отдала всё, что у неё было, и объёма не хватило. Это «мерить
	// нечем», а не «блока нет».
	r := probeStand(t, stand{body: 8 * 1024}, PumpIn)
	if r.Verdict != VerdictShort {
		t.Fatalf("вердикт %v, ожидалось «объём не набран»", r.Verdict)
	}
}

func TestБезОбъявленнойДлиныВердиктаНет(t *testing.T) {
	// Конец тела и обрыв выглядят одинаково, если длина не объявлена.
	r := probeStand(t, stand{body: 40 * 1024, noLen: true}, PumpIn)
	if r.Verdict == VerdictCut {
		t.Fatal("конец тела без объявленной длины объявлен обрывом")
	}
}

func TestДлинаТелаЧитаетсяБезОглядкиНаРегистр(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh: 4096\r\n\r\n"))
	n, err := readHead(br)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4096 {
		t.Errorf("длина %d, ожидалось 4096", n)
	}
}
