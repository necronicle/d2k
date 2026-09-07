package control_test

// Мост между двумя реализациями одного формата: Go-клиент против настоящего
// C-сервера (datapath/ctlprobe, где живут тот же разбор команд и та же
// сессия, что в d2kd).
//
// Проверять это сравнением исходников на глаз бесполезно — расходятся они
// молча и находятся в поле. Здесь расхождение падает набором.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// nextHello читает события до ближайшего EvHello, пропуская мимо EvRefused:
// сценарии этого файла в основном не ставят план перед "hello"/"quic", а
// значит, по ревью п.3, следом за приветствием честно идёт «плана для этой
// цели нет» (D2K_JRN_PLAN_REFUSED -> EvRefused, session.c) — раньше это
// событие вообще не доезжало до провода, и тесты, писавшие
// `ev, _ := c.Next()` сразу после "hello", могли рассчитывать, что
// приветствие — единственное, что придёт. Три попытки — с запасом: между
// двумя "hello" здесь ложится не больше одной такой пары.
func nextHello(t *testing.T, c *control.Conn) control.Event {
	t.Helper()
	for i := 0; i < 3; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("событие приветствия не прочиталось: %v", err)
		}
		if ev.Type == control.EvHello {
			return ev
		}
	}
	t.Fatal("приветствие не пришло")
	return control.Event{}
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
	if ev.Key.Proto != 6 {
		t.Fatalf("транспорт в ключе %d, а ждали 6 (TCP)", ev.Key.Proto)
	}
}

func TestTCPИQUICСОдинаковымАдресомИПортомДаютРазныеКлючи(t *testing.T) {
	// По ревью задачи 4 QUIC-вертикали: TCP и UDP — независимые пространства
	// портов, поэтому браузер, гоняющий QUIC и TCP к одному адресу
	// наперегонки, вполне может свести их к одинаковой паре адрес+порт.
	// Контроллер держит состояние ПО КЛЮЧУ, и без транспорта в ключе эти два
	// потока делили бы и перетирали друг другу состояние. Проверяется через
	// настоящий C-стенд (ctlprobe), а не через представление о нём: команда
	// "quic" в ctlprobe нарочно переиспользует порт последнего hello, чтобы
	// получить ИМЕННО такое совпадение.
	p, sock := start(t)
	c := dial(t, sock)

	p.say(t, "hello example.com")
	tcpEv := nextHello(t, c)

	p.say(t, "quic")
	quicEv := nextHello(t, c)

	// Оба приветствия — от одного и того же имени (ctlprobe шлёт QUIC Initial
	// с example.com внутри, см. шапку ctlprobe.c) и с одного и того же адреса
	// и порта — иначе сама проверка ничего не доказывала бы.
	if tcpEv.Name != "example.com" || quicEv.Name != "example.com" {
		t.Fatalf("имена разошлись: TCP %q, QUIC %q", tcpEv.Name, quicEv.Name)
	}
	if tcpEv.Key.LowIP != quicEv.Key.LowIP || tcpEv.Key.HighIP != quicEv.Key.HighIP ||
		tcpEv.Key.LowPort != quicEv.Key.LowPort || tcpEv.Key.HighPort != quicEv.Key.HighPort {
		t.Fatalf("адрес+порт разошлись, проверка не про то: TCP %v, QUIC %v",
			tcpEv.Key, quicEv.Key)
	}

	if tcpEv.Key.Proto != 6 {
		t.Fatalf("транспорт TCP-ключа %d, а ждали 6", tcpEv.Key.Proto)
	}
	if quicEv.Key.Proto != 17 {
		t.Fatalf("транспорт QUIC-ключа %d, а ждали 17", quicEv.Key.Proto)
	}
	if tcpEv.Key == quicEv.Key {
		t.Fatalf("TCP- и QUIC-ключ совпали целиком при одинаковом адресе и порте: %v", tcpEv.Key)
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

// TestПланПоИмениПрименяетсяИКQUIC — задача 4 научила handle_udp искать план
// по извлечённому из QUIC Initial имени тем же способом, что и TCP; здесь это
// проверяется на том же проводе, которым ставит план настоящий контроллер
// (control.Conn.SetPlanName), а не только изнутри d2k_session_packet
// (test_quic_session.c). Имя "example.com" не выбор теста — это фиксированное
// имя ФИКСИРОВАННОГО вектора v1_initial, зашитого в команду "quic" (см.
// ctlprobe.c и core/test_quic.c), подменить нельзя.
func TestПланПоИмениПрименяетсяИКQUIC(t *testing.T) {
	p, sock := start(t)
	c := dial(t, sock)

	// Без порчи (PoisonID: 0): rzd_arm.plan портит TCP-контрольную сумму
	// (badsum), а её UDP-сборка исполнять не умеет и честно отказывает
	// (wire_udp.c) — это отдельное, отдельно проверенное свойство отказа, а
	// не то, что здесь проверяется. Здесь важно, что САМ поиск плана по имени
	// у QUIC-потока работает, а для этого годится и порча="ничего".
	pl := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 17, Proto: 1,
		Payloads: []plan.Payload{{ID: 1, Bytes: []byte{0xDE, 0xAD}}},
		Fakes:    []plan.Fake{{PayloadID: 1, PoisonID: 0, Repeats: 1}},
	}
	tlv, err := pl.MarshalTLV()
	if err != nil {
		t.Fatal(err)
	}

	if err := c.SetPlanName("example.com", tlv); err != nil {
		t.Fatalf("план не отправился: %v", err)
	}
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

	got := p.say(t, "quic")
	if strings.Contains(got, "посылок 0") {
		t.Fatal("план по имени не применился к QUIC-потоку: " + got)
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

func TestПрикладныеДанныеОтличаютсяОтРукопожатия(t *testing.T) {
	// §4.2: «проверка только первых байтов ServerHello недостаточна». Первый
	// тип записи всегда 22, поэтому уровень доказательства по нему не
	// поднять. Набор встреченных типов — то, чем уровень 3 отличается от 2.
	p, sock := start(t)
	c := dial(t, sock)

	p.say(t, "hello levels.example")
	p.say(t, "reply 22") // ServerHello
	p.say(t, "reply 23") // прикладные данные

	sawHandshakeOnly, sawAppData := false, false
	for i := 0; i < 8; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("событие %d: %v", i, err)
		}
		if ev.Type != control.EvExchange {
			continue
		}
		if !ev.HasAppData() {
			sawHandshakeOnly = true
			continue
		}
		sawAppData = true
		break
	}
	if !sawHandshakeOnly {
		t.Fatal("сообщение об обмене на уровне рукопожатия не пришло")
	}
	if !sawAppData {
		t.Fatal("появление прикладных данных не сообщено: уровень навсегда остался бы вторым")
	}
}

func TestПриманкуGoУзнаётРазборщикC(t *testing.T) {
	// Приманку строит Go, а узнаёт её на проводе разборщик на C. Сверять две
	// реализации на глаз бессмысленно: расходятся они молча. Здесь
	// собранное Go приветствие проходит через ТОТ ЖЕ протокольный модуль,
	// что стоит на пакетном пути.
	p, sock := start(t)
	c := dial(t, sock)

	hello, err := plan.Hello("disk.rzd.ru", 0)
	if err != nil {
		t.Fatal(err)
	}
	p.say(t, "raw "+hex.EncodeToString(hello))

	for i := 0; i < 4; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("событие %d: %v", i, err)
		}
		if ev.Type != control.EvHello {
			continue
		}
		if ev.Name != "disk.rzd.ru" {
			t.Fatalf("разборщик на C увидел имя %q, а Go клал disk.rzd.ru", ev.Name)
		}
		return
	}
	t.Fatal("разборщик на C не узнал приветствие, собранное на Go")
}

func TestФормаПриветствияЛовитсяПоЗапросу(t *testing.T) {
	// Зонд обязан повторять форму пользовательского приветствия. Значит
	// датапат должен уметь её отдать — по запросу, а не с каждым
	// соединением: полкилобайта на каждое приветствие роутера ради того, что
	// нужно раз в жизни цели.
	p, sock := start(t)
	c := dial(t, sock)

	// До взведения ловушки формы нет.
	p.say(t, "hello before.example")
	if got := p.say(t, "shape"); !strings.Contains(got, "shape: 0 байт") {
		t.Fatalf("форма поймана без запроса: %q", got)
	}

	if err := c.WantShape("youtube.com"); err != nil {
		t.Fatal(err)
	}
	// Даём стенду прокрутить цикл и разобрать команду.
	for i := 0; i < 50; i++ {
		p.say(t, "hello other.example")
		if strings.Contains(p.say(t, "shape"), "shape: 0 байт") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Чужая цель ловушку не тратит.
	if got := p.say(t, "shape"); !strings.Contains(got, "shape: 0 байт") {
		t.Fatalf("ловушка сработала на чужой цели: %q", got)
	}

	p.say(t, "hello youtube.com")
	got := p.say(t, "shape")
	if strings.Contains(got, "shape: 0 байт") {
		t.Fatalf("форма не поймана на своей цели: %q", got)
	}

	// И она обязана доехать до контроллера целиком.
	//
	// Бюджет попыток — 130, не 12: по ревью п.3 у КАЖДОГО "hello" без
	// плана (а плана здесь ни у одной цели нет) следом идёт ещё и EvRefused
	// (session.c, refuse()) — раньше это событие на провод не выходило
	// вовсе. Цикл ожидания ловушки формы выше повторяет "hello
	// other.example" до 50 раз, то есть в очереди перед EvShape может
	// накопиться до 50×2 таких пар плюс горстка от "before.example" и
	// подтверждения самой команды ARM_SHAPE — с запасом это чуть больше
	// сотни, не дюжина.
	var shape []byte
	for i := 0; i < 130; i++ {
		ev, err := c.Next()
		if err != nil {
			break
		}
		if ev.Type == control.EvShape {
			shape = ev.Shape
			break
		}
	}
	if len(shape) == 0 {
		t.Fatal("форма приветствия не доехала до контроллера")
	}
	if shape[0] != 0x16 {
		t.Fatalf("пойманное не похоже на запись рукопожатия: %#02x", shape[0])
	}
	if !bytes.Contains(shape, []byte("youtube.com")) {
		t.Fatal("в пойманной форме нет имени цели")
	}
}

func TestКомандаПодтверждается(t *testing.T) {
	// Без подтверждения зонд пришлось бы пускать «через паузу на всякий
	// случай», а пауза наугад — гонка, которую не видно, пока она не
	// проявится на медленной коробке.
	p, sock := start(t)
	_ = p
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
		t.Fatal(err)
	}

	for i := 0; i < 6; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("подтверждение не пришло: %v", err)
		}
		if ev.Type != control.EvAck {
			continue
		}
		if ev.AckOf != control.CmdSetName {
			t.Fatalf("подтверждена команда %#04x, а слали %#04x", ev.AckOf, control.CmdSetName)
		}
		if !ev.AckOK {
			t.Fatal("годная команда отвергнута")
		}
		if ev.AckReason != control.AckOK {
			t.Fatalf("у успеха причина отказа %d, а не control.AckOK", ev.AckReason)
		}
		return
	}
	t.Fatal("подтверждение не пришло")
}

func TestНегоднаяКомандаПодтверждаетсяОтказом(t *testing.T) {
	p, sock := start(t)
	_ = p
	c := dial(t, sock)

	// План, который датапат обязан отвергнуть: ipid_zero сырым сокетом
	// неисполним.
	pl := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1, Transport: 6, Proto: 1,
		Payloads: []plan.Payload{{ID: 1, Bytes: []byte{0xDE, 0xAD}}},
		Poisons:  []plan.Poison{{ID: 1, Flags: plan.PoisonIPIDZero}},
		Fakes:    []plan.Fake{{PayloadID: 1, PoisonID: 1, Repeats: 1}},
	}
	tlv, _ := pl.MarshalTLV()
	if err := c.SetPlanName("bad.example", tlv); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("подтверждение не пришло: %v", err)
		}
		if ev.Type != control.EvAck {
			continue
		}
		if ev.AckOK {
			t.Fatal("неисполнимый план подтверждён как принятый")
		}
		// Причина обязана быть «план негоден», а не «нет места» — до
		// разделения причин (см. onAck, internal/controller/controller.go)
		// контроллер не мог отличить одно от другого и жёг кандидата даже
		// тогда, когда виновата была нехватка места, а не сам план.
		if ev.AckReason != control.AckBadPlan {
			t.Fatalf("причина отказа неисполнимого плана %d, а не control.AckBadPlan", ev.AckReason)
		}
		return
	}
	t.Fatal("отказ не подтверждён")
}

// waitAckReason читает события до EvAck на команду cmd и возвращает код
// причины (AckReason). Общий хвост TestКомандаПодтверждается и
// TestНегоднаяКомандаПодтверждаетсяОтказом выше, вынесенный сюда для новой
// проверки ниже — им самим трогать незачем.
func waitAckReason(t *testing.T, c *control.Conn, cmd uint16) uint8 {
	t.Helper()
	for i := 0; i < 8; i++ {
		ev, err := c.Next()
		if err != nil {
			t.Fatalf("подтверждение не пришло: %v", err)
		}
		if ev.Type == control.EvAck && ev.AckOf == cmd {
			return ev.AckReason
		}
	}
	t.Fatal("подтверждение на нужную команду не пришло")
	return 0
}

// sendRawGetAckReason открывает СЫРОЕ соединение (без обёртки control.Conn —
// нужно для кадра, который легальный клиент собрать не может, см. ниже),
// шлёт body как кадр типа typ и возвращает код причины из ответного
// D2K_EV_ACK. Раскладка кадра — [длина payload u32 BE][тип u16 BE][ключ
// потока 13 байт, нулевой у подтверждения][тип команды u16 BE][признак
// успеха u8][код причины u8] — та же, что разбирает control.Conn.Next()
// изнутри (control.go, случай EvAck), развёрнутая тут вручную: у сырого
// соединения нет обёртки, которая сделала бы это сама.
//
// Тело функции — ОДНА попытка, без ретраев: повтор на переподключение решается
// снаружи, в вызывающем коде, потому что там же виден весь бюджет попыток и
// его исчерпание можно честно завалить тестом с понятной причиной, а не
// прятать за t.Fatal внутри хелпера.
func sendRawGetAckReason(sock string, typ uint16, body []byte) (uint8, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return 0, fmt.Errorf("подключение: %w", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return 0, err
	}
	frame := make([]byte, 6+len(body))
	binary.BigEndian.PutUint32(frame[0:4], uint32(2+len(body)))
	binary.BigEndian.PutUint16(frame[4:6], typ)
	copy(frame[6:], body)
	if _, err := c.Write(frame); err != nil {
		// Гонка принятия: старое соединение могло ещё не отвалиться со
		// стороны сервера, когда мы дозвонились до нового, — accept()
		// ctlprobe увидит наше как «второго контроллера» и закроет его,
		// пока d2k_ctl_poll в основном цикле (poll(200), ctlprobe.c) не
		// заметил уход прежнего. Гонка не гипотетическая: без ретраев на
		// вызывающей стороне именно это ловится как "write: broken pipe"
		// на прогоне полного набора тестов пакета (не при одиночном
		// запуске — там сервер обычно успевает).
		return 0, fmt.Errorf("запись: %w", err)
	}
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return 0, fmt.Errorf("заголовок ответа: %w", err)
	}
	plen := binary.BigEndian.Uint32(hdr[0:4])
	rtyp := binary.BigEndian.Uint16(hdr[4:6])
	if rtyp != control.EvAck {
		return 0, fmt.Errorf("тип кадра %#04x, а ждали подтверждение (%#04x)", rtyp, control.EvAck)
	}
	if plen < 2 {
		return 0, fmt.Errorf("кадр подтверждения короче собственного заголовка: %d", plen)
	}
	rbody := make([]byte, plen-2)
	if _, err := io.ReadFull(c, rbody); err != nil {
		return 0, fmt.Errorf("тело ответа: %w", err)
	}
	// 13 — ширина ключа потока НА ПРОВОДЕ (D2K_KEY_WIRE_LEN,
	// datapath/include/d2k_ctlsrv.h); control.go держит то же число под
	// именем keyLen, непубличным, поэтому здесь оно повторено, а не
	// импортировано — сверяет их bridge-тест в целом, не эта строка.
	const keyWireLen = 13
	if len(rbody) < keyWireLen+4 {
		return 0, fmt.Errorf("тело подтверждения короче ожидаемого (ключ+тип+успех+причина): %d байт", len(rbody))
	}
	return rbody[keyWireLen+3], nil
}

// TestКодыПодтвержденияСовпадаютУGoИC — сверка констант D2K_ACK_* (C,
// datapath/include/d2k_ctl.h) и control.Ack* (Go, control.go) по образцу
// TestКодыЗаписейСовпадаютУGoИC (internal/plan/lab_test.go): расхождение
// здесь — та же по цене ошибка, что и там (обе стороны собираются, тесты
// каждой стороны проходят по отдельности, а смысл байта на проводе разный),
// и до этой проверки её не было вовсе — только комментарий «обязаны
// совпадать» по обе стороны, который сам себя не проверяет.
//
// D2K_ACK_NO_ROOM сюда осознанно не входит и не может: вместимость таблицы
// планов после округления round_pow2 (datapath/track.c) не бывает меньше 16,
// а с вытеснением по давности (datapath/plans.c) полная таблица вытесняет
// самую давнюю запись вместо отказа — этот код больше не проезжает по
// проводу ни при какой настоящей команде (см. большой комментарий у
// D2K_ACK_NO_ROOM, d2k_ctl.h). Он остаётся непроверенным здесь честно, а не
// по недосмотру: сводить его сюда значило бы либо ломать инвариант нарочно
// ради теста, либо звать внутренности datapath, которых у Go нет и не будет.
func TestКодыПодтвержденияСовпадаютУGoИC(t *testing.T) {
	p, sock := start(t)
	_ = p
	c := dial(t, sock)

	src, err := os.ReadFile("../plan/testdata/rzd_arm.plan")
	if err != nil {
		t.Fatal(err)
	}
	goodPlan, err := plan.ParseText(string(src))
	if err != nil {
		t.Fatal(err)
	}
	goodTLV, err := goodPlan.MarshalTLV()
	if err != nil {
		t.Fatal(err)
	}

	// OK: годная команда с исполнимым планом.
	if err := c.SetPlanName("ack-ok.example", goodTLV); err != nil {
		t.Fatalf("годная команда не отправилась: %v", err)
	}
	if reason := waitAckReason(t, c, control.CmdSetName); reason != control.AckOK {
		t.Fatalf("код подтверждения годной команды %d, а ждали control.AckOK (%d)",
			reason, control.AckOK)
	}

	// BAD_PLAN: план, неисполнимый содержательно — ipid_zero сырым сокетом
	// не распорядиться, ядро подставит свой (см. TestНегоднаяКомандаПодтверждаетсяОтказом).
	badPlan := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1, Transport: 6, Proto: 1,
		Payloads: []plan.Payload{{ID: 1, Bytes: []byte{0xDE, 0xAD}}},
		Poisons:  []plan.Poison{{ID: 1, Flags: plan.PoisonIPIDZero}},
		Fakes:    []plan.Fake{{PayloadID: 1, PoisonID: 1, Repeats: 1}},
	}
	badTLV, err := badPlan.MarshalTLV()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetPlanName("ack-badplan.example", badTLV); err != nil {
		t.Fatalf("неисполнимый план не отправился: %v", err)
	}
	if reason := waitAckReason(t, c, control.CmdSetName); reason != control.AckBadPlan {
		t.Fatalf("код подтверждения неисполнимого плана %d, а ждали control.AckBadPlan (%d)",
			reason, control.AckBadPlan)
	}

	// BAD_ARGS: незнакомый тип команды — d2k_ctlsrv_command бьёт по ветке
	// default отказом именно с этой причиной, какая бы команда ни пришла
	// (см. ctlsrv.c). control.Conn такую не собрать: все экспортированные
	// Set*/Del* проверяют аргументы на СВОЕЙ стороне раньше, чем дошло бы
	// до провода, — и это не случайно, просто не про эту причину отказа.
	// Кадр собран в обход клиента на ОТДЕЛЬНОМ соединении: старое закрыто,
	// а не разделяет сокет с новым — второй ОДНОВРЕМЕННЫЙ контроллер
	// отвергается самим протоколом (см. TestВторойКонтроллерОтвергается).
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	var reason uint8
	var lastErr error
	for i := 0; i < 50; i++ {
		reason, lastErr = sendRawGetAckReason(sock, 0x00FE, nil) // тип вне D2K_CMD_*/D2K_EV_*
		if lastErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("незнакомая команда не прошла за 50 попыток: %v", lastErr)
	}
	if reason != control.AckBadArgs {
		t.Fatalf("код подтверждения незнакомой команды %d, а ждали control.AckBadArgs (%d)",
			reason, control.AckBadArgs)
	}
}
