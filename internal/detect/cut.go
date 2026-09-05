// Package detect — прямые вопросы к коробке о том, КАК она читает поток.
//
// Не подбор стратегии, а поиск расхождения: обход существует ровно там, где
// разбор коробки и разбор сервера расходятся. Каждый опыт здесь меняет ОДНУ
// вещь и отвечает на один вопрос.
package detect

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Outcome — чем кончился опыт.
type Outcome int

const (
	// OutcomeSilence — ответа не было. Коробка проглотила приветствие.
	OutcomeSilence Outcome = iota
	// OutcomeReset — соединение сброшено.
	OutcomeReset
	// OutcomeAnswer — сервер ответил. Разбор коробки и сервера разошлись.
	OutcomeAnswer
	// OutcomeNoConnect — не встал даже транспорт.
	OutcomeNoConnect
)

func (o Outcome) String() string {
	switch o {
	case OutcomeReset:
		return "сброс"
	case OutcomeAnswer:
		return "сервер ответил"
	case OutcomeNoConnect:
		return "нет транспорта"
	default:
		return "молчание"
	}
}

// Result — исход одного опыта.
type Result struct {
	// What — что именно делали. Для журнала: «пробую опыт 3» ничего не значит.
	What    string
	Outcome Outcome
	Bytes   int
	// First — первый байт ответа. 0x16 значит рукопожатие сервера.
	First byte
	Took  time.Duration
	Err   string
}

func (r Result) String() string {
	s := fmt.Sprintf("%-34s %-14s %5d байт", r.What, r.Outcome, r.Bytes)
	if r.Outcome == OutcomeAnswer {
		s += fmt.Sprintf(", первый байт %#02x", r.First)
	}
	s += fmt.Sprintf(", %s", r.Took.Round(time.Millisecond))
	if r.Err != "" {
		s += " (" + r.Err + ")"
	}
	return s
}

// Options — как ставить опыт.
type Options struct {
	// Splits — где резать приветствие. Пусто — послать одним куском.
	Splits []int
	// Gap — пауза между кусками. Ноль — без паузы: куски уйдут подряд, но
	// разными сегментами, потому что каждый кусок это свой Write.
	Gap time.Duration
	// Wait — сколько ждать ответа. Ноль — три секунды.
	Wait time.Duration
	// What — как назвать опыт в отчёте.
	What string
}

// Send шлёт приветствие so-как-задано и смотрит, что вернётся.
//
// Своё соединение и свои байты: никакой библиотеки TLS. Библиотека шлёт
// приветствие одним куском и не даёт разрезать его там, где нам надо, — а
// вопрос как раз про место разреза.
func Send(ctx context.Context, addr string, hello []byte, opt Options) Result {
	res := Result{What: opt.What}
	if res.What == "" {
		res.What = describe(opt.Splits)
	}
	wait := opt.Wait
	if wait == 0 {
		wait = 3 * time.Second
	}

	start := time.Now()
	d := net.Dialer{Timeout: 8 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Outcome = OutcomeNoConnect
		res.Err = short(err)
		res.Took = time.Since(start)
		return res
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		// Без этого куски склеятся в один сегмент, и опыт про место разреза
		// перестанет быть опытом про место разреза.
		_ = tc.SetNoDelay(true)
	}

	for _, part := range parts(hello, opt.Splits) {
		if _, err := c.Write(part); err != nil {
			res.Outcome = OutcomeReset
			res.Err = short(err)
			res.Took = time.Since(start)
			return res
		}
		if opt.Gap > 0 {
			time.Sleep(opt.Gap)
		}
	}

	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 4096)
	n, rerr := c.Read(buf)
	res.Bytes = n
	res.Took = time.Since(start)
	if n > 0 {
		res.First = buf[0]
		res.Outcome = OutcomeAnswer
		return res
	}
	if rerr != nil {
		if isTimeout(rerr) {
			res.Outcome = OutcomeSilence
		} else {
			res.Outcome = OutcomeReset
			res.Err = short(rerr)
		}
	}
	return res
}

// parts режет приветствие в заданных местах.
func parts(hello []byte, splits []int) [][]byte {
	if len(splits) == 0 {
		return [][]byte{hello}
	}
	var out [][]byte
	prev := 0
	for _, at := range splits {
		if at <= prev || at >= len(hello) {
			continue
		}
		out = append(out, hello[prev:at])
		prev = at
	}
	out = append(out, hello[prev:])
	return out
}

func describe(splits []int) string {
	if len(splits) == 0 {
		return "целиком"
	}
	var b strings.Builder
	b.WriteString("разрез на ")
	for i, at := range splits {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d", at)
	}
	return b.String()
}

// SNIAt — где в приветствии лежит имя. -1, если не нашлось.
func SNIAt(hello []byte, sni string) int {
	i := strings.Index(string(hello), sni)
	return i
}

func isTimeout(err error) bool {
	var ne net.Error
	if e, ok := err.(net.Error); ok {
		ne = e
	}
	return ne != nil && ne.Timeout()
}

func short(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 40 {
		s = s[i+2:]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}
