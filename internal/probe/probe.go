package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"
)

// Outcome — чем кончился зонд. Это НАБЛЮДЕНИЕ, а не диагноз: §2.4 запрещает
// выводить из промаха устройство механизма.
type Outcome int

const (
	// OutcomeExchange — с той стороны пришла нагрузка.
	OutcomeExchange Outcome = iota
	// OutcomeReset — соединение сброшено после приветствия.
	OutcomeReset
	// OutcomeSilence — приветствие ушло, ответа нет до срока. Это НЕ
	// доказательство блокировки адреса (§2.4).
	OutcomeSilence
	// OutcomeNoConnect — не установился даже транспорт.
	OutcomeNoConnect
)

func (o Outcome) String() string {
	switch o {
	case OutcomeExchange:
		return "обмен"
	case OutcomeReset:
		return "сброс"
	case OutcomeSilence:
		return "молчание"
	default:
		return "нет соединения"
	}
}

// Result — что зонд увидел.
type Result struct {
	Outcome Outcome
	// Байты нагрузки с той стороны и типы встреченных TLS-записей — те же
	// величины, что датапат считает для пользовательского трафика, чтобы
	// уровень доказательства определялся одинаково (§4.2).
	Bytes     int
	SeenTypes uint8
	Elapsed   time.Duration
	// LocalPort — по нему вызывающий отличает свой поток от чужого.
	LocalPort uint16
	Err       error
}

// Prober открывает соединение к цели и посылает приветствие ЗАДАННОЙ формы.
//
// Не crypto/tls: библиотека послала бы своё приветствие, а нам нужно то, что
// шлёт клиент пользователя. Форма — это то, что коробка разглядывает.
type Prober struct {
	// Timeout — сколько ждём ответа. Это и есть «ждём ВРЕМЯ, а не повторы».
	Timeout time.Duration
	// Dialer позволяет задать локальный адрес и метку. Подменяется тестами.
	Dialer *net.Dialer
}

// New делает зонд с разумными сроками.
func New() *Prober {
	return &Prober{
		Timeout: 4 * time.Second,
		Dialer:  &net.Dialer{Timeout: 3 * time.Second},
	}
}

// Do шлёт приветствие и слушает ответ.
//
// Прикладного запроса зонд НЕ посылает: §2.6 запрещает копировать и повторять
// запросы с возможными побочными эффектами. Рукопожатие побочных эффектов не
// имеет, а данные после него — уже могут.
func (p *Prober) Do(ctx context.Context, addr string, port int, hello []byte) Result {
	start := time.Now()
	res := Result{Outcome: OutcomeNoConnect}

	d := p.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: 3 * time.Second}
	}
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		res.Err = err
		res.Elapsed = time.Since(start)
		return res
	}
	defer conn.Close()

	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		res.LocalPort = uint16(la.Port)
	}

	deadline := time.Now().Add(p.Timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(hello); err != nil {
		res.Err = err
		res.Outcome = classify(err)
		res.Elapsed = time.Since(start)
		return res
	}

	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if n > 0 {
			if res.Bytes == 0 {
				// Тип записи запоминается как есть; толковать его здесь
				// нельзя — уровень доказательства определяет вызывающий
				// (§4.2), ровно как и для пользовательского трафика.
				if t := buf[0]; t >= 20 && t <= 23 {
					res.SeenTypes |= 1 << (t - 20)
				}
			} else if t := buf[0]; t >= 20 && t <= 23 {
				res.SeenTypes |= 1 << (t - 20)
			}
			res.Bytes += n
			res.Outcome = OutcomeExchange
			// Одного ServerHello мало (§4.2). Читаем дальше, пока идёт.
			if res.SeenTypes&(1<<(23-20)) != 0 {
				break
			}
			continue
		}
		if err != nil {
			if res.Bytes > 0 && errors.Is(err, io.EOF) {
				break
			}
			if res.Bytes == 0 {
				res.Outcome = classify(err)
				res.Err = err
			}
			break
		}
	}
	if res.Bytes == 0 && res.Outcome == OutcomeNoConnect {
		res.Outcome = OutcomeSilence
	}
	res.Elapsed = time.Since(start)
	return res
}

// HasAppData — дошло ли до прикладных данных. Тот же признак, по которому
// уровень 3 отличается от уровня 2 у пользовательского трафика.
func (r Result) HasAppData() bool { return r.SeenTypes&(1<<(23-20)) != 0 }

func classify(err error) Outcome {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return OutcomeReset
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return OutcomeSilence
	}
	if errors.Is(err, io.EOF) {
		// Закрытие без данных: тот же по смыслу исход, что и сброс, —
		// соединение оборвали, не ответив.
		return OutcomeReset
	}
	return OutcomeSilence
}

// Describe — короткая строка для журнала решений.
func (r Result) Describe() string {
	return fmt.Sprintf("%s, %d байт, %s", r.Outcome, r.Bytes, r.Elapsed.Round(time.Millisecond))
}
