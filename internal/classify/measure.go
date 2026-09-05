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
	// rtt — RTT последнего УСПЕШНОГО Dial в этой серии; ноль, если ни один
	// Dial не удался. RTT — свойство ЛИНИИ, а не отдельного вопроса дерева,
	// и дереву он нужен СНАРУЖИ этой функции: Run сужает по нему ожидание
	// для СЛЕДУЮЩЕГО вопроса (см. classify.go). Внутри одной серии значение
	// не используется — measure ждёт одно и то же wait все repeats попыток.
	rtt time.Duration
}

// connectTimeout — потолок ожидания TCP-соединения.
//
// Унаследовано, а не измерено здесь: то же число уже стоит в
// internal/volume/probe.go как connectTimeout и handshakeTimeout, а туда
// пришло из пробы донора z2k-detect/internal/tcp16, где задано замером на
// этой линии.
const connectTimeout = 8 * time.Second

// transportCeiling — сколько сверх wait можно занимать транспорту (сама
// запись всех кусков плюс паузы между ними), прежде чем дедлайн соединения
// сработает принудительно.
//
// Это потолок ожидания ТРАНСПОРТА, а не ответа: ответ ждёт сам wait, и его
// значение задаёт вызывающий. Число то же, что у connectTimeout, и того же
// происхождения: internal/volume/probe.go, а туда — из пробы донора
// z2k-detect/internal/tcp16.
const transportCeiling = 8 * time.Second

// once шлёт триггер один раз, разрезав его в заданных местах, и возвращает
// RTT — длительность самого Dial.
//
// Своё соединение и свои байты: библиотека TLS шлёт приветствие одним куском и
// не даёт разрезать его там, где надо, — а вопрос как раз про место разреза.
//
// RTT берём из Dial, а не измеряем отдельным пакетом: соединение и так
// устанавливается, и отдельный замер был бы лишним раундом сверх бюджета.
// Значение возвращается наружу для дерева (см. Run в classify.go) — само
// once() и measure() его не используют, они лишь передают его дальше.
func once(ctx context.Context, addr string, tr Trigger, cuts []int, gap, wait time.Duration) (bool, time.Duration, error) {
	d := net.Dialer{Timeout: connectTimeout}
	dialStart := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	rtt := time.Since(dialStart)
	if err != nil {
		return false, rtt, err
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		// Без этого куски склеятся в один сегмент, и опыт про место разреза
		// перестанет быть опытом про место разреза.
		_ = tc.SetNoDelay(true)
	}
	_ = c.SetDeadline(time.Now().Add(wait + transportCeiling))

	for _, part := range spans(tr.Payload, cuts) {
		if _, err := c.Write(part); err != nil {
			return false, rtt, nil // сброс на записи — это «убито», а не ошибка опыта
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
		return true, rtt, nil
	}
	_ = rerr
	return false, rtt, nil
}

// measure повторяет опыт и считает исходы.
//
// wait используется БЕЗ ИЗМЕНЕНИЙ для каждой из repeats попыток этого
// вызова — сужение ожидания по RTT происходит МЕЖДУ вопросами дерева, а не
// внутри одной серии повторов (решение по ревью Task 3: RTT — свойство
// линии, и её вопрос задаётся Run один раз на весь прогон в classify.go, а
// не заново на каждый measure()). Здесь только исполнение и отчёт: сколько
// прошло, сколько нет, и какой RTT показал последний удавшийся Dial —
// вызывающий сам решает, что с ним делать дальше.
func measure(ctx context.Context, addr string, tr Trigger, cuts []int, gap time.Duration, repeats int, wait time.Duration) tally {
	var t tally
	for i := 0; i < repeats; i++ {
		if ctx.Err() != nil {
			break
		}
		ok, rtt, err := once(ctx, addr, tr, cuts, gap, wait)
		if err != nil {
			t.err = err
			t.fail++
			continue
		}
		// Dial удался независимо от исхода чтения — RTT валиден и тогда,
		// когда коробка дальше пропала (заблокировала).
		t.rtt = rtt
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
