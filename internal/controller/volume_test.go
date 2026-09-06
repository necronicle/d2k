package controller_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/necronicle/d2k/internal/classify"
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
	r.vol.set(volume.ScanFound, "passing.example", 19)
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
	r.vol.set(volume.ScanFound, "passing.example", 19)
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
	if !strings.Contains(logs, "имя passing.example проводит объём") {
		t.Fatalf("проба не спрошена или её ответ не истолкован:\n%s", logs)
	}
	if !strings.Contains(logs, "(имя passing.example)") {
		t.Fatalf("поставлено не найденное пробой имя:\n%s", logs)
	}
	if n := strings.Count(logs, "(имя passing.example)"); n != 1 {
		t.Fatalf("имя поставлено %d раз, а проба подобрала его один раз:\n%s", n, logs)
	}
	// Подобранное имя обязано ПЕРЕБИТЬ лестницу, а не встать в её конец.
	if strings.LastIndex(logs, "(поиск)") > strings.LastIndex(logs, "(имя passing.example)") {
		t.Fatalf("после подобранного имени лестница продолжила своим порядком:\n%s", logs)
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

func TestИзмерениеОбъёмаНеЗадерживаетЛестницу(t *testing.T) {
	// Полевой прогон 06.09.2026: обе цели простояли две минуты с заданным
	// вопросом про объём и без единого поставленного плана. Измерение идёт до
	// полутора минут, а первый кандидат встаёт за секунду — держать человека
	// ради вопроса, который на большинстве целей ответит «блока нет», нельзя.
	r := newRig(t)
	r.vol.set(volume.ScanFound, "passing.example", 19)
	hold := make(chan struct{})
	r.vol.hold = hold
	r.probe.script = []probe.Result{{Outcome: probe.OutcomeSilence}}

	r.say("hello nowait.example")
	r.say("rst")
	for i := 0; i < 12 && r.vol.count() == 0; i++ {
		r.pump(1)
	}
	r.pump(4)

	logs := r.log.String()
	if !strings.Contains(logs, "заодно меряю объём") {
		close(hold)
		t.Fatalf("объём не меряется вовсе:\n%s", logs)
	}
	if !strings.Contains(logs, "пробую") {
		close(hold)
		t.Fatalf("пока идёт измерение объёма, ни один кандидат не поставлен:\n%s", logs)
	}
	close(hold)
}

func TestПоискНеЗакрываетсяПокаИдётИзмерение(t *testing.T) {
	// Лестница может кончиться раньше измерения. Закрыть поиск в этот момент
	// значит выбросить ответ, за который уже заплачено временем человека, —
	// и именно он единственный, который при блоке по объёму помогает.
	r := newRig(t)
	r.vol.set(volume.ScanFound, "passing.example", 19)
	hold := make(chan struct{})
	r.vol.hold = hold
	r.probe.script = []probe.Result{{Outcome: probe.OutcomeSilence}}

	r.say("hello late.example")
	r.say("rst")
	r.pump(20)

	if strings.Contains(r.log.String(), "решения не нашлось") {
		close(hold)
		t.Fatalf("поиск закрыт, пока измерение объёма ещё шло:\n%s", r.log)
	}
	close(hold)
	r.pump(6)
	if !strings.Contains(r.log.String(), "(имя passing.example)") {
		t.Fatalf("дождавшийся ответ не поставлен:\n%s", r.log)
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
	// Цель бывает закрыта сразу двумя способами: объём режется, и вдобавок
	// матчер требует разрез. Остановиться на подстановке имени значило бы
	// бросить такую цель на полпути.
	//
	// До задачи 5 вторая ось была лестницей generate() «на всякий случай»:
	// после неудачи имени та просто перебирала ещё несколько НЕизмеренных
	// комбинаций (§3.5 это и запрещает). Здесь вторая ось — вердикт
	// classify.Run, измеренный НЕЗАВИСИМО от объёма и своим каналом. Порядок
	// между осями в жизни — гонка двух фоновых измерений (см. комментарий у
	// fakeClassify.hold); здесь он зафиксирован намеренно — classify держится,
	// пока не провалится подстановка имени, — чтобы проверить ИМЕННО «после
	// неудачи одной оси подхватывается другая», а не то, какая из двух горутин
	// в этом прогоне оказалась быстрее.
	r := newRig(t)
	r.vol.set(volume.ScanFound, "passing.example", 19)
	r.vol.verifyVerdict = volume.VerdictCut
	r.classify.set(classify.VerdictPrefix, 4)
	hold := make(chan struct{})
	r.classify.hold = hold
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
		close(hold)
		t.Fatalf("неудача проверки имени не записана:\n%s", logs)
	}
	if strings.Contains(candidateLines(logs), "разрез") {
		close(hold)
		t.Fatalf("ось разреза подхвачена раньше своего вердикта:\n%s", logs)
	}

	// Классификация отвечает ПОСЛЕ того, как имя от объёма уже провалилось.
	close(hold)
	r.pump(6)

	logs = r.log.String()
	if n := strings.Count(candidateLines(logs), "пробую"); n < 2 {
		t.Fatalf("поставлен %d кандидат: после неудачи имени поиск не продолжен:\n%s", n, logs)
	}
	if !strings.Contains(candidateLines(logs), "разрез") {
		t.Fatalf("после оси имени не пробовалась ось разреза, измеренная classify.Run:\n%s", logs)
	}
}
