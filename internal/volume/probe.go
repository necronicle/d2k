// Package volume — активная проба на блокировку по объёму соединения.
//
// Класс блокировки: коробка пропускает рукопожатие и первые килобайты, а потом
// рвёт установленный поток, набравший пару десятков килобайт. Разрезом
// ClientHello он не лечится вовсе — режется не рукопожатие.
//
// Почему проба, а не наблюдение за чужим трафиком. Наблюдение отвечает на
// вопрос «этот хост сейчас режут?» и ошибается в обе стороны: горизонт
// видимости датапата — первые пакеты соединения, и здоровая крупная загрузка
// выглядит оттуда ровно как обрыв. Проба отвечает на другой вопрос — «есть ли
// этот блок на ЭТОЙ линии к ЭТОЙ сети» — за секунды, на своей мишени, своим
// объёмом и не трогая пользовательский трафик.
//
// Зачем проба идёт ПЕРВОЙ. Пока ответ неизвестен, вопрос «блокируют по имени
// или по адресу» ЛЖЁТ: при блоке по объёму рукопожатие проходит с любым именем,
// поток умирает и там и там, и ответ всегда получается «по адресу». Проба не
// дополняет тот вопрос, а снимает его ложный ответ.
//
// Унаследовано, а не измерено здесь: способ накачки исходящим объёмом и порог,
// ниже которого обрыв этому классу не приписывается — из замера на этой же
// линии (z2k, 31.08.2026, метод runnin4ik/dpi-detector). Всё прочее меряется
// заново, включая то, за каким направлением коробка вообще следит.
package volume

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// Ступень лестницы объёма и число ступеней: накопленный объём растёт
	// 4, 8, 12 … 40 КБ и покрывает весь наблюдавшийся разброс обрыва.
	ChunkSize  = 4000
	ChunkCount = 10

	// Ниже этого объёма обрыв нашим классом не считается. До двенадцати
	// килобайт соединения рвутся по десятку обычных причин, и вердикт был бы
	// шумом, а не измерением.
	MinDetectKB = 12

	connectTimeout   = 8 * time.Second
	handshakeTimeout = 8 * time.Second

	// Пауза между запросами. Без неё десять запросов уходят одной очередью, и
	// коробка видит поток иначе, чем видит его браузер: вердикт плывёт.
	chunkDelay = 50 * time.Millisecond

	// Ожидание ответа считается от ИЗМЕРЕННОГО RTT, а не берётся с потолка.
	// Живой ответ приходит за один RTT; «нет ответа» — это неподходящее имя,
	// на котором коробка молчит, и с фиксированным потолком каждый мимо-
	// кандидат стоил бы полные секунды. Нижняя граница защищает от слишком
	// оптимистичного замера на первом пакете, верхняя — от линии с большим RTT.
	readTimeoutMin = 1500 * time.Millisecond
	readTimeoutMax = 12 * time.Second
)

// Pump — чьим объёмом качаем соединение.
//
// Ось существует потому, что от ответа зависит устройство пассивного
// наблюдателя: он считает либо наши байты, либо чужие, и выбрать наугад нельзя.
type Pump int

const (
	// PumpOut — объём создаём мы: запросы с мусорным заголовком по одному
	// keep-alive соединению. Не зависит от того, что отдаёт мишень.
	PumpOut Pump = iota
	// PumpIn — объём создаёт мишень: один запрос и чтение тела.
	PumpIn
)

func (p Pump) String() string {
	if p == PumpIn {
		return "входящий"
	}
	return "исходящий"
}

// Verdict — исход одной пробы.
type Verdict int

const (
	// VerdictUnreachable — мишень не ответила вовсе. Про линию не сказано
	// ничего: это не «блока нет».
	VerdictUnreachable Verdict = iota
	// VerdictCut — соединение умерло за порогом. Это наш класс.
	VerdictCut
	// VerdictPassed — лестница пройдена целиком, соединение живо.
	VerdictPassed
	// VerdictShort — объём до порога не дорос: документ кончился раньше или
	// обрыв случился слишком рано. Вердикта НЕТ, и выдавать это за «блока нет»
	// нельзя.
	VerdictShort
)

func (v Verdict) String() string {
	switch v {
	case VerdictCut:
		return "обрыв по объёму"
	case VerdictPassed:
		return "объём прошёл"
	case VerdictShort:
		return "объём не набран — вердикта нет"
	default:
		return "мишень не ответила"
	}
}

// Target — куда идём.
type Target struct {
	// ASN — номер сети, к которой мишень принадлежит. Ответ пробы относится
	// к сети, а не к хосту: одно имя на все сети не подходит.
	ASN  string
	Name string
	IP   string
	Port int
	// SNI — имя, которое предъявляем. Пустое — идём по адресу.
	SNI string
	// Plain — открытый HTTP, без рукопожатия. Отдельным полем, а не выводом
	// из номера порта: связь «порт 80 значит без TLS» верна для курируемого
	// списка и неверна вообще, а прятать её в проверке порта — прятать
	// решение там, где его не видно.
	Plain bool
}

func (t Target) addr() string { return net.JoinHostPort(t.IP, strconv.Itoa(t.Port)) }

// Result — что проба узнала.
type Result struct {
	Target  Target
	SNI     string
	Pump    Pump
	Verdict Verdict
	// AtKB — накопленный объём, на котором всё кончилось.
	AtKB int
	// Err — человеческая причина, если соединение оборвалось.
	Err string
	RTT time.Duration
}

// Detected — короткий вопрос к результату: это наш класс?
func (r Result) Detected() bool { return r.Verdict == VerdictCut }

var padPool = func() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, ChunkSize*2)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}()

// Probe гоняет одну пробу. sni пустой — идём по адресу.
func Probe(ctx context.Context, t Target, sni string, pump Pump) Result {
	res := Result{Target: t, SNI: sni, Pump: pump}

	d := net.Dialer{Timeout: connectTimeout}
	start := time.Now()
	raw, err := d.DialContext(ctx, "tcp", t.addr())
	if err != nil {
		res.Err = "нет TCP: " + errShort(err)
		return res
	}
	defer raw.Close()

	conn := net.Conn(raw)
	if !t.Plain {
		// Дедлайн обязателен: на неподходящем имени коробка не отвечает вовсе,
		// и рукопожатие висит без ограничения по времени — перебор кандидатов
		// встанет намертво на первом же таком имени.
		if err := raw.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			res.Err = "дедлайн: " + errShort(err)
			return res
		}
		// Сертификат не проверяем: идём по адресу и подставляем имя сами —
		// измеряется реакция коробки, а не подлинность сервера.
		tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec
		if err := tc.HandshakeContext(ctx); err != nil {
			res.Err = "нет TLS: " + errShort(err)
			return res
		}
		conn = tc
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		res.Err = "дедлайн: " + errShort(err)
		return res
	}
	res.RTT = time.Since(start)

	host := t.IP
	if sni != "" {
		host = sni
	}
	if pump == PumpIn {
		return pumpIn(conn, res, host)
	}
	return pumpOut(conn, res, host)
}

// pumpOut — лестница исходящего объёма: десять запросов по одному соединению,
// со второго — с мусорным заголовком. Мусор в заголовке остаётся единственным
// способом накачать соединение своим объёмом, не завися от мишени.
func pumpOut(conn net.Conn, res Result, host string) Result {
	br := bufio.NewReader(conn)
	readTimeout := readTimeoutMax // пока RTT не измерен — ждём по потолку

	for i := 0; i < ChunkCount; i++ {
		var sb strings.Builder
		sb.WriteString("HEAD / HTTP/1.1\r\nHost: ")
		sb.WriteString(host)
		sb.WriteString("\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n")
		if i > 0 {
			off := rand.Intn(len(padPool) - ChunkSize)
			sb.WriteString("X-Pad: ")
			sb.WriteString(padPool[off : off+ChunkSize])
			sb.WriteString("\r\n")
		}
		sb.WriteString("\r\n")

		sentKB := i * ChunkSize / 1024
		if err := conn.SetDeadline(time.Now().Add(readTimeout)); err != nil {
			return died(res, i, sentKB, err)
		}
		reqStart := time.Now()
		if _, err := conn.Write([]byte(sb.String())); err != nil {
			return died(res, i, sentKB, err)
		}
		if err := drainHead(br); err != nil {
			return died(res, i, sentKB, err)
		}
		if i == 0 {
			// RTT известен — дальше ждём втрое дольше него, в разумных
			// границах: «нет ответа» распознаётся втрое быстрее прежнего.
			readTimeout = clamp(time.Since(reqStart)*3, readTimeoutMin, readTimeoutMax)
		}
		time.Sleep(chunkDelay)
	}
	res.Verdict = VerdictPassed
	res.AtKB = ChunkCount * ChunkSize / 1024
	return res
}

// pumpIn — объём создаёт мишень: один запрос и чтение тела.
//
// Обрыв здесь отличается от честно кончившегося документа только объявленной
// длиной. Нет Content-Length — вердикта нет: молчаливо принять конец тела за
// обрыв значило бы выдумать блокировку.
func pumpIn(conn net.Conn, res Result, host string) Result {
	want := ChunkCount * ChunkSize
	req := "GET / HTTP/1.1\r\nHost: " + host +
		"\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n"

	if err := conn.SetDeadline(time.Now().Add(readTimeoutMax)); err != nil {
		res.Err = errShort(err)
		return res
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		res.Err = "запрос не ушёл: " + errShort(err)
		return res
	}
	br := bufio.NewReader(conn)
	length, err := readHead(br)
	if err != nil {
		res.Err = "нет ответа: " + errShort(err)
		return res
	}

	buf := make([]byte, 16*1024)
	got := 0
	for got < want {
		if err := conn.SetDeadline(time.Now().Add(readTimeoutMax)); err != nil {
			break
		}
		n, rerr := br.Read(buf)
		got += n
		if rerr == nil {
			// Документ кончился ровно там, где обещан. Ждать дальше нечего:
			// мишень своё отдала, и молчание после этого — не обрыв.
			if length >= 0 && got >= length {
				break
			}
			continue
		}
		// Тело кончилось ровно там, где обещано, — это здоровый конец, а не
		// обрыв, сколько бы килобайт в нём ни было.
		if length >= 0 && got >= length {
			break
		}
		res.Err = errShort(rerr)
		return dieIn(res, got, length)
	}
	res.AtKB = got / 1024
	if got >= want {
		res.Verdict = VerdictPassed
		return res
	}
	// Дочитали до конца документа, а объёма не набрали: мишень мала для этой
	// пробы. Это не «блока нет».
	res.Verdict = VerdictShort
	if length < 0 {
		res.Err = "мишень не объявила длину тела"
	}
	return res
}

func dieIn(res Result, got, length int) Result {
	res.AtKB = got / 1024
	switch {
	case length < 0:
		// Без объявленной длины обрыв неотличим от конца документа.
		res.Verdict = VerdictShort
	case res.AtKB >= MinDetectKB:
		res.Verdict = VerdictCut
	default:
		res.Verdict = VerdictShort
	}
	return res
}

// died превращает обрыв на ступени i в вердикт с учётом порога.
func died(res Result, i, sentKB int, err error) Result {
	res.Err = errShort(err)
	res.AtKB = sentKB
	if i == 0 {
		// Умерли на первом же запросе — мишень недоступна, а не блок.
		res.Verdict = VerdictUnreachable
		return res
	}
	if sentKB >= MinDetectKB {
		res.Verdict = VerdictCut
	} else {
		res.Verdict = VerdictShort
	}
	return res
}

// drainHead читает ответ на HEAD: заголовки до пустой строки, тела нет.
func drainHead(br *bufio.Reader) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

// readHead читает заголовки ответа и возвращает объявленную длину тела; -1 —
// длина не объявлена.
func readHead(br *bufio.Reader) (int, error) {
	length := -1
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return length, err
		}
		if line == "\r\n" || line == "\n" {
			return length, nil
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "content-length") {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n >= 0 {
			length = n
		}
	}
}

func clamp(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

func errShort(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, io.EOF) {
		return "соединение закрыто"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 40 {
		s = s[i+2:]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// String — строка для журнала: что мерили и что вышло.
func (r Result) String() string {
	s := fmt.Sprintf("%s %s: %s на %d КБ", r.Target.IP, r.Pump, r.Verdict, r.AtKB)
	if r.SNI != "" {
		s = r.SNI + " → " + s
	}
	if r.Err != "" {
		s += " (" + r.Err + ")"
	}
	return s
}
