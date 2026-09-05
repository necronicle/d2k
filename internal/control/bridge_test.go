package control_test

// Мост между двумя реализациями одного формата: Go-клиент против настоящего
// C-сервера (datapath/ctlprobe, где живут тот же разбор команд и та же
// сессия, что в d2kd).
//
// Проверять это сравнением исходников на глаз бесполезно — расходятся они
// молча и находятся в поле. Здесь расхождение падает набором.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/necronicle/d2k/internal/control"
	"github.com/necronicle/d2k/internal/plan"
)

type probe struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Scanner
}

// say отправляет стенду команду и возвращает его ответ.
func (p *probe) say(t *testing.T, line string) string {
	t.Helper()
	if _, err := fmt.Fprintln(p.in, line); err != nil {
		t.Fatalf("команда %q стенду: %v", line, err)
	}
	if !p.out.Scan() {
		t.Fatalf("стенд молчит после %q", line)
	}
	return p.out.Text()
}

func start(t *testing.T) (*probe, string) {
	t.Helper()
	bin, err := filepath.Abs("../../datapath/ctlprobe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		// Стенд собирается целью `make -C datapath ctlprobe`, и она входит в
		// scripts/check.sh. Отсутствие — не повод молча пропустить проверку:
		// молча пропущенная проверка ничем не отличается от отсутствующей.
		t.Fatalf("стенд не собран (%v); нужен `make -C datapath ctlprobe`", err)
	}

	// Путь сокета короткий: sockaddr_un ограничен ~104 байтами, а TMPDIR на
	// маке длинный.
	sock := fmt.Sprintf("/tmp/d2k-bridge-%d.sock", os.Getpid())
	_ = os.Remove(sock)

	cmd := exec.Command(bin, sock)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(outPipe)
	if !sc.Scan() || sc.Text() != "готов" {
		t.Fatalf("стенд не поздоровался: %q", sc.Text())
	}
	p := &probe{cmd: cmd, in: in, out: sc}
	t.Cleanup(func() {
		_, _ = fmt.Fprintln(in, "quit")
		_ = in.Close()
		_ = cmd.Wait()
		_ = os.Remove(sock)
	})
	return p, sock
}

func dial(t *testing.T, sock string) *control.Conn {
	t.Helper()
	var c *control.Conn
	var err error
	// Стенд поднимает сокет до «готов», но принимает подключение в своём
	// цикле — небольшая гонка тут законна.
	for i := 0; i < 50; i++ {
		c, err = control.Dial(sock)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("не подключиться к стенду: %v", err)
	}
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestСобытиеПриветствияДоезжает(t *testing.T) {
	p, sock := start(t)
	c := dial(t, sock)

	p.say(t, "hello linkedin.com")

	ev, err := c.Next()
	if err != nil {
		t.Fatalf("событие не прочиталось: %v", err)
	}
	if ev.Type != control.EvHello {
		t.Fatalf("тип события %#04x, а ждали приветствие", ev.Type)
	}
	if ev.Name != "linkedin.com" {
		t.Fatalf("имя цели %q, а ждали linkedin.com", ev.Name)
	}
	// Ключ канонизирован: 93.184.216.34 против 192.168.1.67 — низким концом
	// идёт тот, чьи шесть байт «адрес+порт» меньше.
	if ev.Key.LowIP != [4]byte{93, 184, 216, 34} {
		t.Fatalf("низкий конец ключа %v, а ждали 93.184.216.34", ev.Key.LowIP)
	}
	if ev.Key.LowPort != 443 {
		t.Fatalf("порт низкого конца %d, а ждали 443", ev.Key.LowPort)
	}
}

func TestПодозрениеПриходитКодом(t *testing.T) {
	p, sock := start(t)
	c := dial(t, sock)

	// Приветствие, затем сброс с чужим TTL. Без плана защита не назначена,
	// поэтому сброс не снимается, но подозрение отмечается.
	p.say(t, "hello discord.com")
	p.say(t, "rst")

	var codes []uint8
	for i := 0; i < 4; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("событие %d: %v", i, err)
		}
		if ev.Type == control.EvSuspect {
			codes = append(codes, ev.Code)
			break
		}
	}
	if len(codes) == 0 {
		t.Fatal("подозрение не доехало")
	}
	if codes[0] != control.SuspectRST {
		t.Fatalf("код подозрения %d (%s), а ждали сброс в ответ на приветствие",
			codes[0], control.SuspectText(codes[0]))
	}
}

func TestПланСтавитсяПоИмениИПрименяется(t *testing.T) {
	p, sock := start(t)
	c := dial(t, sock)

	src, err := os.ReadFile("../plan/testdata/rzd_arm.plan")
	if err != nil {
		t.Fatal(err)
	}
	pl, err := plan.ParseText(string(src))
	if err != nil {
		t.Fatal(err)
	}
	tlv, err := pl.MarshalTLV()
	if err != nil {
		t.Fatal(err)
	}

	if err := c.SetPlanName("linkedin.com", tlv); err != nil {
		t.Fatalf("план не отправился: %v", err)
	}

	// Даём стенду прокрутить цикл: команда приходит асинхронно.
	var line string
	for i := 0; i < 50; i++ {
		line = p.say(t, "plans")
		if strings.Contains(line, "planов 1") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(line, "planов 1") {
		t.Fatalf("план не встал в таблицу: %q", line)
	}
	if !strings.Contains(line, "отвергнуто 0") {
		t.Fatalf("команда отвергнута: %q", line)
	}

	// Теперь та же цель обязана получить план, а другая — нет.
	got := p.say(t, "hello linkedin.com")
	if !strings.Contains(got, "посылок 2") {
		t.Fatalf("план по имени не применился: %q", got)
	}
	got = p.say(t, "hello example.org")
	if !strings.Contains(got, "посылок 0") {
		t.Fatalf("план применился к чужой цели: %q", got)
	}
}

func TestПланСНеисполнимойПорчейОтвергается(t *testing.T) {
	p, sock := start(t)
	c := dial(t, sock)

	// ipid_zero сырым сокетом неисполним: ядро подставит свой идентификатор.
	// §2.5 запрещает молча приближать операцию другой — значит отказ.
	pl := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 6, Proto: 1,
		Payloads: []plan.Payload{{ID: 1, Bytes: []byte{0xDE, 0xAD}}},
		Poisons:  []plan.Poison{{ID: 1, Flags: plan.PoisonIPIDZero}},
		Fakes:    []plan.Fake{{PayloadID: 1, PoisonID: 1, Repeats: 1}},
	}
	tlv, err := pl.MarshalTLV()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetPlanName("bad.example", tlv); err != nil {
		t.Fatal(err)
	}

	var line string
	for i := 0; i < 50; i++ {
		line = p.say(t, "plans")
		if strings.Contains(line, "отвергнуто 1") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(line, "отвергнуто 1") {
		t.Fatalf("неисполнимый план не отвергнут: %q", line)
	}
	if !strings.Contains(line, "planов 0") {
		t.Fatalf("неисполнимый план всё-таки встал в таблицу: %q", line)
	}
}

func TestВторойКонтроллерОтвергается(t *testing.T) {
	_, sock := start(t)
	first := dial(t, sock)
	_ = first

	second, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("второе подключение не открылось: %v", err)
	}
	defer second.Close()
	if err := second.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Датапат обслуживает одного хозяина: двое поставили бы противоречащие
	// планы, не зная друг о друге.
	buf := make([]byte, 4)
	n, err := second.Read(buf)
	if err != io.EOF || n != 0 {
		t.Fatalf("второй контроллер не отвергнут: прочитано %d, ошибка %v", n, err)
	}
}

func TestСвидетельствоОбменаДоезжает(t *testing.T) {
	p, sock := start(t)
	c := dial(t, sock)

	p.say(t, "hello example.net")
	p.say(t, "reply 22") // 22 — рукопожатие TLS

	var ex *control.Event
	for i := 0; i < 6; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("событие %d: %v", i, err)
		}
		if ev.Type == control.EvExchange {
			ex = &ev
			break
		}
	}
	if ex == nil {
		t.Fatal("свидетельство обмена не доехало")
	}
	if ex.RecordType != control.TLSHandshake {
		t.Fatalf("тип записи %d, а ждали рукопожатие (%d)",
			ex.RecordType, control.TLSHandshake)
	}
	if ex.Bytes == 0 {
		t.Fatal("байты обмена нулевые")
	}
}

func TestПредупреждениеTLSНеПутаетсяСРукопожатием(t *testing.T) {
	// §4.2: уровень 2 не выдавать за уровень 4. Датапат сообщает ТИП записи,
	// а не вывод «работает»; вывод делает контроллер. Проверка на то, что тип
	// доезжает неискажённым.
	p, sock := start(t)
	c := dial(t, sock)

	p.say(t, "hello alert.example")
	p.say(t, "reply 21") // 21 — предупреждение TLS

	for i := 0; i < 6; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("событие %d: %v", i, err)
		}
		if ev.Type == control.EvExchange {
			if ev.RecordType != control.TLSAlert {
				t.Fatalf("тип записи %d, а ждали предупреждение (%d)",
					ev.RecordType, control.TLSAlert)
			}
			return
		}
	}
	t.Fatal("свидетельство обмена не доехало")
}

func TestОтпечатокСбросаДоезжает(t *testing.T) {
	// Отпечаток коробки складывается из того, ЧЕМ подделка отличалась от
	// ответов сервера в том же потоке. Без этих полей в каталоге лежал бы
	// факт «был сброс», по которому одну коробку от другой не отличить.
	p, sock := start(t)
	c := dial(t, sock)

	p.say(t, "hello fingerprint.example")
	p.say(t, "rst")

	for i := 0; i < 6; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("событие %d: %v", i, err)
		}
		if ev.Type != control.EvSuspect {
			continue
		}
		if ev.Code != control.SuspectRST {
			t.Fatalf("код %d, а ждали сброс в ответ на приветствие", ev.Code)
		}
		// Стенд шлёт сброс с TTL 127, а SYN-ACK был с TTL 124.
		if ev.TTL != 127 {
			t.Fatalf("TTL подозрительного пакета %d, а ждали 127", ev.TTL)
		}
		if ev.RefTTL != 124 {
			t.Fatalf("ориентир TTL %d, а ждали 124", ev.RefTTL)
		}
		return
	}
	t.Fatal("подозрение с отпечатком не доехало")
}
