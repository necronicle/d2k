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
	// markOK — подтвердила ли постановка метки SO_MARK КАЖДЫЙ из repeats
	// дозвонов этой серии. true, если метку не просили (mark==0) — тогда
	// подтверждать нечего, см. once(). §5.5: провал метки не должен путаться
	// с решением коробки, поэтому это отдельное поле, а не часть err/pass.
	markOK bool
}

// markFunc — как метить исходящий сокет зонда (SO_MARK). Платформенная
// реализация по умолчанию — mark_linux.go (настоящая разметка) или
// mark_other.go (SO_MARK недоступен физически, метка молча игнорируется).
// Package-переменная, а не прямой вызов markControl: тесту «помеченный clear
// остаётся clear» (classify_test.go) нужно подтверждение метки, а получить
// его настоящим SO_MARK можно только под Linux и с CAP_NET_ADMIN — тест
// подменяет markFunc, чтобы проверить ПОЛИТИКУ вердикта отдельно от
// доступности привилегии на машине, где идёт проверка.
var markFunc = markControl

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
//
// mark — метка SO_MARK, которой обязан идти зонд (§5.5: исключение из
// собственного преобразования; files/S99d2k, `-m mark --mark "$MARK" -j
// RETURN`). Ноль значит «не метить» — законно для разового ручного вызова,
// где плана на цели ещё нет. Провал постановки метки НЕ прерывает Dial и не
// становится ошибкой опыта (err) — это отдельное наблюдение о достоверности,
// возвращаемое отдельным булем и обрабатываемое в Run (см. Result.Marked):
// сетевая ошибка и недоказанное исключение зонда — разные вещи, и путать их
// значило бы снова смешивать наблюдение с диагнозом (§2.4).
func once(ctx context.Context, addr string, tr Trigger, cuts []int, gap, wait time.Duration, mark uint32) (bool, time.Duration, bool, error) {
	d := net.Dialer{Timeout: connectTimeout}
	markOK := mark == 0
	if mark != 0 {
		d.Control = markFunc(mark, &markOK)
	}
	dialStart := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	rtt := time.Since(dialStart)
	if err != nil {
		return false, rtt, markOK, err
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
			return false, rtt, markOK, nil // сброс на записи — это «убито», а не ошибка опыта
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
		return true, rtt, markOK, nil
	}
	_ = rerr
	return false, rtt, markOK, nil
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
func measure(ctx context.Context, addr string, tr Trigger, cuts []int, gap time.Duration, repeats int, wait time.Duration, mark uint32) tally {
	t := tally{markOK: true}
	for i := 0; i < repeats; i++ {
		if ctx.Err() != nil {
			break
		}
		ok, rtt, markOK, err := once(ctx, addr, tr, cuts, gap, wait, mark)
		if !markOK {
			// АНД по всей серии: если хоть один дозвон не подтвердил метку,
			// про серию в целом нельзя сказать, что зонд был исключён из
			// собственного обхода (§5.5) — а именно это утверждает markOK.
			t.markOK = false
		}
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
