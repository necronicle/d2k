package controller_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if !strings.Contains(logs, "похоже на обрыв по объёму") {
		t.Fatalf("повторяющийся объём не замечен:\n%s", logs)
	}
	if !strings.Contains(logs, "примета: обрыв по объёму около 15 КиБ") {
		t.Fatalf("объём не записан приметой:\n%s", logs)
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

func TestПодборИмениПроверяетсяОбъёмомАНеЗондом(t *testing.T) {
	// Чтобы перевалить за обрыв, нужен полный сеанс TLS и прикладной запрос —
	// §2.6 запрещает подмешивать такое. Проверяем тем же прибором, которым
	// обнаружили: счётчиком ядра на трафике самого человека.
	r := newRig(t)
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
	if !strings.Contains(logs, "пробую") {
		t.Fatalf("после обрыва по объёму кандидат не поставлен:\n%s", logs)
	}
	if !strings.Contains(logs, "(имя ") {
		t.Fatalf("перебирается не имя:\n%s", logs)
	}
	if r.probe.count() != before {
		t.Fatal("для цели с обрывом по объёму пущен зонд, который тут ничего не мерит")
	}

	// Поток перевалил за обрыв вдвое — вот это доказательство.
	writeCT(t, ct, ctLine(probeServerIP, 60000, 163654))
	r.pump(3)

	if !strings.Contains(r.log.String(), "обрыв по объёму снят") {
		t.Fatalf("превышение объёма не засчитано:\n%s", r.log)
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
