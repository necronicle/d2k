package controller_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/necronicle/d2k/internal/controller"
	"github.com/necronicle/d2k/internal/probe"
	"github.com/necronicle/d2k/internal/volume"
)

// probeServerIP — адрес «сервера» у стенда датапата. Совпадение обязательно:
// наблюдение за объёмом привязано к адресу цели, и таблица про другой адрес
// ничего не скажет.
const probeServerIP = "93.184.216.34"

// ctLine собирает строку таблицы ядра — ту самую раскладку, что печатает
// роутер: по два src/dst/packets/bytes, прямое направление и обратное.
func ctLine(dstIP string, srcPort int, inBytes int64) string {
	return fmt.Sprintf("ipv4     2 tcp      6 431999 ESTABLISHED "+
		"src=192.168.1.67 dst=%s sport=%d dport=443 packets=11 bytes=1400 "+
		"src=%s dst=88.87.93.11 sport=443 dport=%d packets=22 bytes=%d "+
		"[ASSURED] mark=0 use=1", dstIP, srcPort, dstIP, srcPort, inBytes)
}

func writeCT(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestОбрывПоОбъёмуНаходитсяПоПовторяемости(t *testing.T) {
	// Порог не назначается числом. «16 килобайт» — чужой замер на чужой линии.
	// Признак — ПОВТОРЯЕМОСТЬ: потоки к одной цели кончаются почти на одном
	// объёме. Здоровая отдача так себя не ведёт: она кончается там, где
	// кончился документ, и у разных страниц разный размер.
	r := newRig(t)
	// Проба меряет 19 КБ там, где наблюдение видело 15: числа намеренно
	// разные, чтобы было видно, ЧЬЁ измерение становится приметой коробки.
	r.vol.set(volume.ScanFound, "проходящее.example", 19)
	ct := filepath.Join(t.TempDir(), "ct")
	r.ctrl.SetConntrackPath(ct)

	// Цель попадает под наблюдение, как только узнали её имя.
	writeCT(t, ct)
	r.say("hello hetzner.example")
	r.pump(3)

	// Три потока, каждый кончается около одного и того же объёма.
	for i, n := range []int64{15994, 16104, 15870} {
		writeCT(t, ct, ctLine(probeServerIP, 50000+i, n))
		r.pump(2)
		writeCT(t, ct) // поток исчез — значит завершился
		r.pump(2)
	}

	logs := r.log.String()
	if !strings.Contains(logs, "раз подряд — спрашиваю пробой") {
		t.Fatalf("повторяющийся объём не замечен:\n%s", logs)
	}
	if strings.Contains(logs, "примета: обрыв по объёму около 15 КиБ") {
		t.Fatalf("приметой стало наблюдение, а не измерение пробы:\n%s", logs)
	}
	if !strings.Contains(logs, "примета: обрыв по объёму около 19 КиБ") {
		t.Fatalf("измерение пробы не записано приметой:\n%s", logs)
	}
}

func TestРазныеОбъёмыНеСчитаютсяОбрывом(t *testing.T) {
	// Обычная отдача: страницы разного размера. Объявлять это обрывом —
	// значит выдумывать блокировку там, где её нет.
	r := newRig(t)
	ct := filepath.Join(t.TempDir(), "ct")
	r.ctrl.SetConntrackPath(ct)
	writeCT(t, ct)
	r.say("hello normal.example")
	r.pump(3)

	for i, n := range []int64{5000, 40000, 180000, 9000} {
		writeCT(t, ct, ctLine(probeServerIP, 50000+i, n))
		r.pump(2)
		writeCT(t, ct)
		r.pump(2)
	}
	if strings.Contains(r.log.String(), "обрыв по объёму") {
		t.Fatalf("разные объёмы объявлены обрывом:\n%s", r.log)
	}
}

func TestИмяБерётсяИзПробыАНеИзПеребора(t *testing.T) {
	// Наблюдение за счётчиками ядра — повод спросить, а не ответ. Имя находит
	// активная проба на самой цели, и найденное ставится ОДНИМ кандидатом:
	// ставить вслед за подтверждённым измерением ещё пятнадцать — не доверять
	// собственному прибору и тратить время человека.
	r := newRig(t)
	r.vol.set(volume.ScanFound, "проходящее.example", 19)
	ct := filepath.Join(t.TempDir(), "ct")
	r.ctrl.SetConntrackPath(ct)
	writeCT(t, ct)
	r.say("hello volume.example")
	r.pump(3)

	for i, n := range []int64{15994, 16000, 15900} {
		writeCT(t, ct, ctLine(probeServerIP, 50000+i, n))
		r.pump(2)
		writeCT(t, ct)
		r.pump(2)
	}
	before := r.probe.count()
	r.pump(4)

	logs := r.log.String()
	if !strings.Contains(logs, "имя проходящее.example проводит объём") {
		t.Fatalf("проба не спрошена или её ответ не истолкован:\n%s", logs)
	}
	if !strings.Contains(logs, "(имя проходящее.example)") {
		t.Fatalf("поставлено не найденное пробой имя:\n%s", logs)
	}
	if n := strings.Count(logs, "пробую"); n != 1 {
		t.Fatalf("кандидатов поставлено %d, а имя уже подобрано пробой:\n%s", n, logs)
	}
	if r.probe.count() != before {
		t.Fatal("для цели с обрывом по объёму пущен пакетный зонд, который тут ничего не мерит")
	}

	// Проверка идёт сама и немедленно: ждать, пока человек прокачает через
	// цель двадцать килобайт, — это те самые «повторы вместо времени».
	r.pump(3)
	if r.vol.probeCount() == 0 {
		t.Fatalf("поставленный план никто не проверил:\n%s", r.log)
	}
	if r.vol.probeSNI != "volume.example" {
		t.Fatalf("проверка пошла с именем %q, а датапат ищет план по имени цели", r.vol.probeSNI)
	}
	if !strings.Contains(r.log.String(), "провёл 39 КБ там, где рвалось на 19 КБ") {
		t.Fatalf("прохождение объёма не засчитано:\n%s", r.log)
	}
	_, bind, _ := r.store.Catalog().Lookup("volume.example", "")
	if bind == nil {
		t.Fatalf("решение не записано:\n%s", r.log)
	}
	// Уровень 4: прикладной обмен в ПРОВЕРЯЕМОМ объёме — мы знаем, сколько
	// отдавалось раньше, и знаем, сколько теперь.
	if bind.Level != 4 {
		t.Fatalf("уровень %d, а обмен проверен по объёму", bind.Level)
	}
}

func TestНаблюдениеБезПодтвержденияПробойИменНеПеребирает(t *testing.T) {
	// Ровно тот случай, на котором прежний детектор ошибся: одна и та же
	// страница ошибки, отданная трижды, выглядит как обрыв. Проба говорит
	// «блока нет» — и никакой оси имён не возникает.
	r := newRig(t)
	r.vol.set(volume.ScanNoBlock, "", 0)
	ct := filepath.Join(t.TempDir(), "ct")
	r.ctrl.SetConntrackPath(ct)
	writeCT(t, ct)
	r.say("hello samepage.example")
	r.pump(3)

	for i, n := range []int64{15994, 16000, 15900} {
		writeCT(t, ct, ctLine(probeServerIP, 50000+i, n))
		r.pump(2)
		writeCT(t, ct)
		r.pump(2)
	}
	r.pump(4)

	logs := r.log.String()
	if !strings.Contains(logs, "блока по объёму здесь нет") {
		t.Fatalf("ответ пробы не истолкован:\n%s", logs)
	}
	if strings.Contains(logs, "(имя ") {
		t.Fatalf("перебор имён начат там, где проба блока не нашла:\n%s", logs)
	}
	if strings.Contains(logs, "примета: обрыв по объёму") {
		t.Fatalf("заведена примета коробки по одному лишь наблюдению:\n%s", logs)
	}
}

func TestПробаНаОбъёмСпрашиваетсяРаньшеВопросовПроРазрез(t *testing.T) {
	// Порядок несущий: при блокировке по объёму рукопожатие проходит с любым
	// именем, и вопросы про разбор приветствия отвечают мимо. Спросить их
	// раньше — получить уверенный неверный ответ.
	r := newRig(t)
	r.probe.script = []probe.Result{{Outcome: probe.OutcomeExchange}}
	r.say("hello order.example")
	r.say("rst")
	r.pump(10)

	logs := r.log.String()
	iv := strings.Index(logs, "режут ли поток по объёму")
	ih := strings.Index(logs, "первое приветствие или последнее")
	if iv < 0 {
		t.Fatalf("про объём не спросили вовсе:\n%s", logs)
	}
	if ih >= 0 && ih < iv {
		t.Fatalf("про разрез приветствия спросили раньше, чем про объём:\n%s", logs)
	}
}

func TestБезТаблицыЯдраМолчанияНеБывает(t *testing.T) {
	// «Обрывов не видели» и «не смотрели» — разные утверждения.
	r := newRig(t)
	r.ctrl.SetConntrackPath(filepath.Join(t.TempDir(), "нет-такого"))
	r.say("hello any.example")
	r.pump(3)
	if !strings.Contains(r.log.String(), "обрывы по объёму не наблюдаются") {
		t.Fatalf("недоступность счётчиков не объявлена:\n%s", r.log)
	}
	_ = time.Now
}

func TestПанельНазываетЗаданныйВопрос(t *testing.T) {
	// Подбор имени по объёму занимает до полутора минут. Всё это время писать
	// «распознаём поведение» — молчать о том, чем занят прибор.
	r := newRig(t)
	r.vol.set(volume.ScanFound, "проходящее.example", 19)
	hold := make(chan struct{})
	r.vol.hold = hold
	r.say("hello asking.example")
	r.say("rst")
	for i := 0; i < 10 && r.vol.count() == 0; i++ {
		r.pump(1)
	}
	defer close(hold)

	var phase string
	for _, s := range r.ctrl.Knowledge().Searches {
		if s.Target == "asking.example" {
			phase = s.Phase
		}
	}
	if !strings.Contains(phase, "спрашиваем") {
		t.Fatalf("панель показывает фазу %q, а идёт вопрос:\n%s", phase, r.log)
	}
}

func TestПорядокИмёнСогреваетсяИзКаталога(t *testing.T) {
	// После перезагрузки роутера подбор не должен начинать с нуля: имя,
	// однажды открывшее дорогу, записано внутри сработавшего плана, и порядок
	// кандидатов обязан это учитывать.
	r := newRig(t)
	// Имя латиницей намеренно: согревание достаёт его из приманки внутри
	// плана, а разбор приветствия читает только печатный ASCII — как и все
	// настоящие имена узлов.
	r.vol.set(volume.ScanFound, "passing.example", 19)
	ct := filepath.Join(t.TempDir(), "ct")
	r.ctrl.SetConntrackPath(ct)
	writeCT(t, ct)
	r.say("hello first.example")
	r.pump(3)
	for i, n := range []int64{15994, 16000, 15900} {
		writeCT(t, ct, ctLine(probeServerIP, 50000+i, n))
		r.pump(2)
		writeCT(t, ct)
		r.pump(2)
	}
	r.pump(4)
	writeCT(t, ct, ctLine(probeServerIP, 60000, 163654))
	r.pump(3)
	if _, bind, _ := r.store.Catalog().Lookup("first.example", ""); bind == nil {
		t.Fatalf("решение не записано, согревать нечем:\n%s", r.log)
	}

	// Новый контроллер на том же каталоге — как после перезагрузки.
	fresh := controller.New(r.conn, r.store, r.log)
	if got := fresh.VolumeNames(); len(got) == 0 || got[0] != "passing.example" {
		head := got
		if len(head) > 3 {
			head = head[:3]
		}
		t.Fatalf("порядок кандидатов начинается с %v, а сработавшее имя известно", head)
	}
}

func TestНеПрошедшийПланУступаетМестоСледующему(t *testing.T) {
	// Цель бывает закрыта сразу двумя способами: объём режется, и вдобавок имя
	// в настоящем приветствии не пропускают. Остановиться на подстановке имени
	// значило бы бросить такую цель на полпути.
	r := newRig(t)
	r.vol.set(volume.ScanFound, "passing.example", 19)
	r.vol.verifyVerdict = volume.VerdictCut
	ct := filepath.Join(t.TempDir(), "ct")
	r.ctrl.SetConntrackPath(ct)
	writeCT(t, ct)
	r.say("hello both.example")
	r.pump(3)
	for i, n := range []int64{15994, 16000, 15900} {
		writeCT(t, ct, ctLine(probeServerIP, 50000+i, n))
		r.pump(2)
		writeCT(t, ct)
		r.pump(2)
	}
	r.pump(12)

	logs := r.log.String()
	if !strings.Contains(logs, "объём не провёл") {
		t.Fatalf("неудача проверки не записана:\n%s", logs)
	}
	if n := strings.Count(logs, "пробую"); n < 2 {
		t.Fatalf("поставлен %d кандидат: после неудачи имени поиск не продолжен:\n%s", n, logs)
	}
	if !strings.Contains(logs, "(поиск)") {
		t.Fatalf("после оси имени не пробовалась ось разреза:\n%s", logs)
	}
}
