package classify

import (
	"context"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

// opts — набор параметров для тестов дерева. Правки решения 1 из задачи:
//
// Gap ставим в loopbackGap (та же константа, что уже определена в
// measure_test.go), а не оставляем нулём. На петле два Write подряд без
// паузы попадают в один Read() стенда, и опыт про разрез перестаёт быть
// опытом про разрез — замер (measure_test.go) показал 10 разделений из 40
// при gap=0 и 40 из 40 при gap=50мкс. Это дефект СТЕНДА (на петле пакетов
// нет вовсе), а не боевого пути, поэтому Options.Gap по умолчанию в самом
// classify.go остаётся нулём — правится только здесь, в тестовом помощнике.
func opts(ctl Trigger) Options {
	return Options{Repeats: 3, Wait: 700 * time.Millisecond, Gap: loopbackGap, LongGap: 400 * time.Millisecond, Control: ctl}
}

func TestЧистаяЛинияНеТребуетОбхода(t *testing.T) {
	tr, _ := TLSTrigger("любое.example")
	ctl, _ := Control("контроль.example")
	r := Run(context.Background(), stand(t, "clear", tr.Payload[:8]), tr, opts(ctl))
	if r.Verdict != VerdictClear {
		t.Fatalf("вердикт %q, ожидался clear: %s", r.Verdict, r.Reason)
	}
}

func TestПрефиксныйМатчерИЕгоГраница(t *testing.T) {
	// Стенд молчит, если первый сегмент начинается с первых 8 байт триггера.
	// Значит граница сигнатуры ровно 8, и двоичный поиск обязан её назвать.
	//
	// Diagnose включаем явно и только здесь: по умолчанию граница не ищется
	// вовсе («Бюджет времени» плана) — этот тест единственный, кому граница
	// нужна по существу проверки.
	tr, _ := TLSTrigger("заблокировано.example")
	ctl, _ := Control("контроль.example")
	o := opts(ctl)
	o.Diagnose = true
	r := Run(context.Background(), stand(t, "prefix", tr.Payload[:8]), tr, o)
	if r.Verdict != VerdictPrefix {
		t.Fatalf("вердикт %q, ожидался prefix: %s", r.Verdict, r.Reason)
	}
	if r.Boundary != 8 {
		t.Fatalf("граница %d, а сигнатура кончается на 8", r.Boundary)
	}
	if r.SplitPos != 1 {
		t.Fatalf("предложен разрез на %d, а левее границы годится любой", r.SplitPos)
	}
}

func TestПересборкаЭтоНеПрефикс(t *testing.T) {
	tr, _ := TLSTrigger("заблокировано.example")
	ctl, _ := Control("контроль.example")
	r := Run(context.Background(), stand(t, "reasm", tr.Payload[:8]), tr, opts(ctl))
	if r.Verdict != VerdictOpaque {
		t.Fatalf("вердикт %q, ожидался opaque: %s", r.Verdict, r.Reason)
	}
}

func TestБезКонтроляВердиктНеУтверждаетЛишнего(t *testing.T) {
	// Контроль молчит вместе с триггером: отличить «режут наши байты» от
	// «режут всё подряд» нечем, и вердикт обязан это сказать, а не выбрать
	// удобное. §2.3 запрещает d2k утверждать блокировку по адресу.
	tr, _ := TLSTrigger("заблокировано.example")
	addr := stand(t, "reasm", []byte{0x16}) // молчит на что угодно, начинающееся с 0x16
	ctl, _ := Control("контроль.example")
	r := Run(context.Background(), addr, tr, opts(ctl))
	if r.Verdict != VerdictInconclusive {
		t.Fatalf("вердикт %q, ожидался inconclusive: %s", r.Verdict, r.Reason)
	}
	if r.Reason == "" {
		t.Fatal("вердикт без причины: человеку нечего читать")
	}
}

// TestСужениеОжиданияЗажатоВГраницах — clampWait не покрывался вообще
// (ревью Task 3, п.5).
func TestСужениеОжиданияЗажатоВГраницах(t *testing.T) {
	cases := []struct{ in, want time.Duration }{
		{0, waitFloor},
		{waitFloor - time.Millisecond, waitFloor},
		{waitFloor, waitFloor},
		{2 * time.Second, 2 * time.Second},
		{waitCeiling, waitCeiling},
		{waitCeiling + time.Second, waitCeiling},
	}
	for _, c := range cases {
		if got := clampWait(c.in); got != c.want {
			t.Errorf("clampWait(%s) = %s, хочу %s", c.in, got, c.want)
		}
	}
}

func TestОжиданиеСужаетсяПослеПервогоОтвета(t *testing.T) {
	// Первый вопрос прогона ждёт по потолку (RTT неоткуда взять) — стенд
	// отвечает через 2с: дольше пола (1с), но заведомо меньше потолка (5с), и
	// первый вопрос обязан его дождаться. Второй вопрос (подтверждение
	// clear) уже знает RTT первого Dial — на петле это единицы-десятки
	// микросекунд, ×8 меньше пола, и ожидание зажимается им (1с) — тот же
	// ответ через 2с он уже не поймает. Расхождение доказывает: сужение
	// произошло МЕЖДУ вопросами (дефект ревью, п.3), а не потерялось.
	tr, _ := TLSTrigger("любое.example")
	addr := stand(t, "delay", nil, 2*time.Second)
	// Options{} нарочно НЕ через opts(): там Wait задан явно (700мс) и
	// автоматический режим по RTT вообще не включится. Повтор ставим ОДИН
	// явно: проверяется сужение ожидания между вопросами, а не умолчание в
	// три повтора — с тремя первый вопрос ответил бы трижды, и различие
	// между вопросами утонуло бы в подсчёте.
	r := Run(context.Background(), addr, tr, Options{Gap: loopbackGap, Repeats: 1})

	if len(r.Trace) < 2 {
		t.Fatalf("трасса короче двух вопросов: %+v", r.Trace)
	}
	if r.Trace[0].What != "триггер целиком" || r.Trace[0].Pass != 1 {
		t.Fatalf("первый вопрос не дождался ответа по потолку: %+v", r.Trace[0])
	}
	if r.Trace[1].What != "триггер целиком (подтверждение)" || r.Trace[1].Pass != 0 {
		t.Fatalf("второй вопрос не сузил ожидание по измеренному RTT: %+v", r.Trace[1])
	}
	if r.Verdict != VerdictFlaky {
		t.Fatalf("вердикт %q, ожидался flaky (база прошла, подтверждение — нет): %s", r.Verdict, r.Reason)
	}
}

func TestЯвноеОжиданиеОтменяетСужение(t *testing.T) {
	// Wait=200мс задан явно и короче задержки стенда (500мс). И первый, и
	// второй вопрос обязаны провалиться ОДИНАКОВО: ни потолок (5с), ни пол
	// сужения по RTT (1с — здесь БОЛЬШЕ заданных явно 200мс) не имеют права
	// подменить значение, заданное вызывающим.
	tr, _ := TLSTrigger("любое.example")
	addr := stand(t, "delay", nil, 500*time.Millisecond)
	r := Run(context.Background(), addr, tr, Options{Gap: loopbackGap, Wait: 200 * time.Millisecond})

	if len(r.Trace) < 2 {
		t.Fatalf("трасса короче двух вопросов: %+v", r.Trace)
	}
	if r.Trace[0].Pass != 0 {
		t.Fatalf("первый вопрос (%s) дождался ответа при явном Wait=200мс короче задержки 500мс", r.Trace[0].What)
	}
	if r.Trace[1].Pass != 0 {
		t.Fatalf("второй вопрос (%s) дождался ответа при явном Wait=200мс короче задержки 500мс — сужение по RTT его не должно было отменить", r.Trace[1].What)
	}
	if r.Verdict != VerdictInconclusive {
		t.Fatalf("вердикт %q, ожидался inconclusive (контроль не задан): %s", r.Verdict, r.Reason)
	}
}

// TestОшибкаОпытаНеПутаетсяСБлокировкой — дефект из ревью (п.2): tally.err
// проверялся только у базового вопроса, у остальных читался лишь pass, и
// обрыв транспорта был неотличим от «коробка не пропустила байты» (§2.4).
// Стенд принимает РОВНО одно соединение и перестаёт слушать: база проходит,
// а следующему вопросу дозвониться уже некуда — connection refused, а не
// решение коробки.
func TestОшибкаОпытаНеПутаетсяСБлокировкой(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go func() {
		c, aerr := ln.Accept()
		_ = ln.Close() // второй попытке дозвониться уже некуда
		if aerr != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8192)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00}) // база проходит
	}()

	tr, _ := TLSTrigger("любое.example")
	r := Run(context.Background(), addr, tr, Options{Gap: loopbackGap, Wait: 300 * time.Millisecond})
	if r.Verdict != VerdictFlaky {
		t.Fatalf("вердикт %q, ожидался flaky (отказ транспорта, не решение коробки): %s", r.Verdict, r.Reason)
	}
	if r.Reason == "" {
		t.Fatal("вердикт без причины")
	}
}

// withMarkFunc подменяет markFunc на симулятор с фиксированным исходом и
// возвращает функцию отмены. Настоящий SO_MARK проверить можно только под
// Linux и с CAP_NET_ADMIN (обоих на машине, где идёт этот тест, может не
// быть) — здесь проверяется ПОЛИТИКА вердикта (§5.5: непомеченный clear не
// проходит, помеченный — проходит), а не доступность привилегии.
func withMarkFunc(t *testing.T, ok bool) {
	t.Helper()
	old := markFunc
	markFunc = func(_ uint32, gotOK *bool) func(string, string, syscall.RawConn) error {
		return func(string, string, syscall.RawConn) error {
			*gotOK = ok
			return nil
		}
	}
	t.Cleanup(func() { markFunc = old })
}

// TestНепомеченныйClearСтановитсяInconclusive — §5.5 дословно: «ошибка
// установки метки — явное снижение достоверности, если исключение обхода не
// гарантировано». Непомеченный clear самоподтверждается: зонд мог получить
// «отпущено» потому, что уже стоящий план пропустил его как обычный трафик,
// а не потому, что цель и правда чиста, — доверять такому «обходить нечего»
// нельзя.
func TestНепомеченныйClearСтановитсяInconclusive(t *testing.T) {
	withMarkFunc(t, false)
	tr, _ := TLSTrigger("любое.example")
	ctl, _ := Control("контроль.example")
	o := opts(ctl)
	o.Mark = 0x2d
	r := Run(context.Background(), stand(t, "clear", tr.Payload[:8]), tr, o)
	if r.Verdict != VerdictInconclusive {
		t.Fatalf("вердикт %q, ожидался inconclusive (метка не подтвердилась): %s", r.Verdict, r.Reason)
	}
	if r.Marked {
		t.Fatal("Marked=true, хотя markFunc сообщил о провале постановки")
	}
	if !strings.Contains(r.Reason, "БЕЗ подтверждённой метки") {
		t.Fatalf("причина не называет отсутствие метки: %s", r.Reason)
	}
}

// TestНольНеТребуетМетки — законный путь разового ручного вызова (`d2k
// classify` без плана на цели, см. Options.Mark): Mark=0 не требует
// подтверждения, и clear остаётся clear.
func TestНольНеТребуетМетки(t *testing.T) {
	tr, _ := TLSTrigger("любое.example")
	ctl, _ := Control("контроль.example")
	r := Run(context.Background(), stand(t, "clear", tr.Payload[:8]), tr, opts(ctl)) // Mark не задан — 0
	if r.Verdict != VerdictClear {
		t.Fatalf("вердикт %q, ожидался clear (метку не просили): %s", r.Verdict, r.Reason)
	}
	if r.Marked {
		t.Fatal("Marked=true при Options.Mark=0 — подтверждать было нечего")
	}
}

// TestПомеченныйClearОстаётсяClear — когда метка ПОДТВЕРЖДЕНА, понижать
// вердикт не за что.
func TestПомеченныйClearОстаётсяClear(t *testing.T) {
	withMarkFunc(t, true)
	tr, _ := TLSTrigger("любое.example")
	ctl, _ := Control("контроль.example")
	o := opts(ctl)
	o.Mark = 0x2d
	r := Run(context.Background(), stand(t, "clear", tr.Payload[:8]), tr, o)
	if r.Verdict != VerdictClear {
		t.Fatalf("вердикт %q, ожидался clear (метка подтверждена): %s", r.Verdict, r.Reason)
	}
	if !r.Marked {
		t.Fatal("Marked=false, хотя markFunc подтвердил метку на каждом дозвоне")
	}
}
