package catalog_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
)

func filled(t *testing.T, path string) *catalog.Store {
	t.Helper()
	s, err := catalog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.MinInterval = 0
	if _, _, err := s.Catalog().Confirm(fp(3, 54321, 0x88), armPlan("p1"),
		"name", "a.example", catalog.LevelHandshake, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.Touch()
	if ok, err := s.FlushNow(time.Now()); err != nil || !ok {
		t.Fatalf("запись не состоялась: ok=%v err=%v", ok, err)
	}
	return s
}

func TestЗаписьИЧтениеПереживаютПерезапуск(t *testing.T) {
	// Этап D: запись состояния и перезапуск не теряют подтверждённую привязку.
	path := filepath.Join(t.TempDir(), "catalog.json")
	filled(t, path)

	s2, err := catalog.Open(path)
	if err != nil {
		t.Fatalf("после перезапуска каталог не открылся: %v", err)
	}
	box, bind, pl := s2.Catalog().Lookup("a.example", "")
	if box == nil || bind == nil || pl == nil {
		t.Fatal("подтверждённая привязка потерялась при перезапуске")
	}
	if _, err := pl.Compile(); err != nil {
		t.Fatalf("прочитанный план не переводится в каноническую форму: %v", err)
	}
}

func TestЗаписьАтомарнаИХранитПрежнюю(t *testing.T) {
	// §5.6: атомарная фиксация и сохранность последней исправной версии.
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	s := filled(t, path)

	// Вторая запись обязана оставить прежнюю версию рядом.
	if _, _, err := s.Catalog().Confirm(fp(3, 54321, 0x88), armPlan("p1"),
		"name", "b.example", catalog.LevelHandshake, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.Touch()
	if _, err := s.FlushNow(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".prev"); err != nil {
		t.Fatalf("прежняя версия не сохранена: %v", err)
	}

	// Временных файлов после успешной записи остаться не должно.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("после записи остался временный файл %s", e.Name())
		}
	}
}

func TestБитыйКаталогОткатываетсяНаПрежний(t *testing.T) {
	// Молча подсунуть вчерашнее знание вместо сегодняшнего нельзя: решения
	// принимаются по нему. Откат обязан быть виден.
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	s := filled(t, path)
	if _, _, err := s.Catalog().Confirm(fp(3, 54321, 0x88), armPlan("p1"),
		"name", "b.example", catalog.LevelHandshake, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.Touch()
	if _, err := s.FlushNow(time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("{ это не json"), 0o644); err != nil {
		t.Fatal(err)
	}
	s2, err := catalog.Open(path)
	if err == nil {
		t.Fatal("откат на прежнюю версию случился молча")
	}
	if s2 == nil {
		t.Fatal("после отката работать нечем")
	}
	if box, _, _ := s2.Catalog().Lookup("a.example", ""); box == nil {
		t.Fatal("прежняя версия не восстановилась")
	}
}

func TestЧастотаЗаписиОграничена(t *testing.T) {
	// §5.6: накопитель роутера — флешка, беречь её требуется прямо.
	path := filepath.Join(t.TempDir(), "catalog.json")
	s, err := catalog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.MinInterval = time.Hour
	now := time.Now()

	if _, _, err := s.Catalog().Confirm(fp(3, 54321, 0x88), armPlan("p1"),
		"name", "a.example", catalog.LevelHandshake, now); err != nil {
		t.Fatal(err)
	}
	s.Touch()
	if ok, err := s.Flush(now); err != nil || !ok {
		t.Fatalf("первая запись не состоялась: %v", err)
	}

	s.Touch()
	if ok, err := s.Flush(now.Add(time.Minute)); err != nil || ok {
		t.Fatal("вторая запись прошла раньше срока")
	}
	if !s.Pending() {
		t.Fatal("накопленное изменение потерялось при отказе писать")
	}
	// А на остановке — обязана пройти невзирая на срок.
	if ok, err := s.FlushNow(now.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("запись на остановке не прошла: %v", err)
	}
	if s.Pending() {
		t.Fatal("после записи остались незаписанные изменения")
	}
}

func TestБитыйКаталогНеЗаписывается(t *testing.T) {
	// Писать заведомо битое нельзя: оно вытеснит исправное.
	path := filepath.Join(t.TempDir(), "catalog.json")
	s := filled(t, path)
	s.Catalog().Boxes[0].Bindings[0].PlanID = "нет такого"
	s.Touch()
	if _, err := s.FlushNow(time.Now()); err == nil {
		t.Fatal("битый каталог записался")
	}
	// На диске обязано остаться исправное.
	s2, err := catalog.Open(path)
	if err != nil {
		t.Fatalf("исправный каталог на диске испорчен: %v", err)
	}
	if box, _, _ := s2.Catalog().Lookup("a.example", ""); box == nil {
		t.Fatal("исправная запись потерялась")
	}
}
