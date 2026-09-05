package classify

import (
	"context"
	"net"
	"time"
)

// tally — сколько попыток прошло, сколько нет.
//
// Считаем повторами, а не одной попыткой: линия шумит, и вывод из одного
// замера — это вывод из шума. Невоспроизводимость сама по себе вердикт
// (VerdictFlaky), а не повод округлить в удобную сторону.
type tally struct {
	pass int
	fail int
	err  error
}

// once шлёт триггер один раз, разрезав его в заданных местах.
//
// Своё соединение и свои байты: библиотека TLS шлёт приветствие одним куском и
// не даёт разрезать его там, где надо, — а вопрос как раз про место разреза.
func once(ctx context.Context, addr string, tr Trigger, cuts []int, gap, wait time.Duration) (bool, error) {
	d := net.Dialer{Timeout: 8 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		// Без этого куски склеятся в один сегмент, и опыт про место разреза
		// перестанет быть опытом про место разреза.
		_ = tc.SetNoDelay(true)
	}
	_ = c.SetDeadline(time.Now().Add(wait + 8*time.Second))

	for _, part := range spans(tr.Payload, cuts) {
		if _, err := c.Write(part); err != nil {
			return false, nil // сброс на записи — это «убито», а не ошибка опыта
		}
		if gap > 0 {
			time.Sleep(gap)
		}
	}

	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 512)
	n, rerr := c.Read(buf)
	if n > 0 {
		// §6.2 п.3: начало ServerHello НЕ доказывает завершённый сеанс. Здесь
		// это и не утверждается — оракул отвечает лишь на вопрос «коробка
		// пропустила байты или убила соединение».
		return true, nil
	}
	_ = rerr
	return false, nil
}

// measure повторяет опыт и считает исходы.
func measure(ctx context.Context, addr string, tr Trigger, cuts []int, gap time.Duration, repeats int, wait time.Duration) tally {
	var t tally
	for i := 0; i < repeats; i++ {
		if ctx.Err() != nil {
			break
		}
		ok, err := once(ctx, addr, tr, cuts, gap, wait)
		if err != nil {
			t.err = err
			t.fail++
			continue
		}
		if ok {
			t.pass++
		} else {
			t.fail++
		}
	}
	return t
}

// spans режет нагрузку в заданных местах.
func spans(payload []byte, cuts []int) [][]byte {
	if len(cuts) == 0 {
		return [][]byte{payload}
	}
	var out [][]byte
	prev := 0
	for _, at := range cuts {
		if at <= prev || at >= len(payload) {
			continue
		}
		out = append(out, payload[prev:at])
		prev = at
	}
	return append(out, payload[prev:])
}
