package plan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runLab гоняет ТОТ ЖЕ исполнитель, что пойдёт в датапат. Отдельной
// реализации преобразований на Go нет и быть не должно: §2.5 документа
// запрещает две реализации, потому что они разойдутся, и измеренное перестанет
// соответствовать исполняемому.
//
// План берётся текстом, кодируется в каноническую форму этим же пакетом и
// скармливается planlab — так проверяется вся цепочка, а не только её концы.
func runLab(t *testing.T, planText, scenario string) string {
	t.Helper()
	lab := filepath.Join("..", "..", "datapath", "planlab")
	if _, err := os.Stat(lab); err != nil {
		// Пропущенный тест выглядит как пройденный. Локально пропуск терпим,
		// в CI — нет: там переменная выставлена, и отсутствие бинарника валит
		// прогон.
		if os.Getenv("D2K_REQUIRE_LAB") != "" {
			t.Fatalf("planlab не собран, а D2K_REQUIRE_LAB выставлена: %v", err)
		}
		t.Skip("planlab не собран: cd datapath && make planlab")
	}

	p, err := ParseText(planText)
	if err != nil {
		t.Fatalf("разбор плана: %v", err)
	}
	raw, err := p.MarshalTLV()
	if err != nil {
		t.Fatalf("кодирование плана: %v", err)
	}

	dir := t.TempDir()
	pf := filepath.Join(dir, "p.tlv")
	sf := filepath.Join(dir, "s.txt")
	if err := os.WriteFile(pf, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sf, []byte(scenario), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(lab, pf, sf).CombinedOutput()
	if err != nil {
		t.Fatalf("planlab: %v\n%s", err, out)
	}
	return string(out)
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const сценарийОдинПакет = "pkt 1000 10 8 " +
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"

func TestЭталонФальшивкаПередКусками(t *testing.T) {
	got := runLab(t, readFixture(t, "fake_before.plan"), сценарийОдинПакет)
	want := readFixture(t, "fake_before.golden")
	if got != want {
		t.Errorf("вывод разошёлся с эталоном:\n--- эталон ---\n%s--- получено ---\n%s", want, got)
	}
}

// Расхождение кодов записей между Go и C — самая дорогая ошибка этой связки:
// обе стороны собираются, тесты каждой проходят, а план исполняется не тот.
// Ловится только сквозным прогоном.
func TestКодыЗаписейСовпадаютУGoИC(t *testing.T) {
	out := runLab(t, readFixture(t, "fake_before.plan"), сценарийОдинПакет)
	if strings.HasPrefix(out, "reject") {
		t.Fatalf("исполнитель отверг план, порождённый Go: %s", out)
	}
	if !strings.Contains(out, "emit ") {
		t.Errorf("исполнитель не выпустил ни одной посылки: %s", out)
	}
}

// Невычислимый якорь обязан давать отказ и в лаборатории тоже: если бы
// planlab печатал пустой список вместо refuse, эталон «нет действий» стал бы
// неотличим от «план неприменим».
func TestНевычислимыйЯкорьВидноВЛаборатории(t *testing.T) {
	src := readFixture(t, "split_sni.plan")
	out := runLab(t, src, "pkt 1000 none 0 aabbccddeeff0011\n")
	if !strings.Contains(out, "refuse") {
		t.Errorf("ожидался отказ при отсутствии SNI, получено:\n%s", out)
	}
}
