package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestОтсутствующийФайлНеОшибка(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "нет-такого"))
	if err != nil {
		t.Fatalf("первый запуск не должен падать: %v", err)
	}
	if c.Existed {
		t.Error("Existed должен быть false, иначе не отличить пустой файл от отсутствующего")
	}
	if c.Mode != ModeObserve {
		t.Errorf("режим по умолчанию = %q, ожидался observe", c.Mode)
	}
}

func TestОпечаткаВЗначенииЭтоОшибка(t *testing.T) {
	// Молча взять умолчание здесь нельзя: пользователь увидит «настройка не
	// сработала» вместо «вы ошиблись в значении».
	_, err := Load(write(t, "MODE=obsrve\n"))
	if err == nil {
		t.Fatal("неизвестный режим должен быть ошибкой")
	}
	if !strings.Contains(err.Error(), "obsrve") {
		t.Errorf("в ошибке нет самого значения: %v", err)
	}
}

func TestНеизвестныйКлючСохраняется(t *testing.T) {
	// Выбросить его — значит потерять настройку новой версии при откате.
	c, err := Load(write(t, "MODE=off\nБУДУЩИЙ_КЛЮЧ=42\n"))
	if err != nil {
		t.Fatalf("неизвестный ключ не должен ронять разбор: %v", err)
	}
	if c.Unknown["БУДУЩИЙ_КЛЮЧ"] != "42" {
		t.Errorf("ключ не сохранён: %#v", c.Unknown)
	}
	if !strings.Contains(c.Render(), "БУДУЩИЙ_КЛЮЧ=42") {
		t.Error("ключ потерян при обратной записи")
	}
}

func TestСхемаИзБудущегоОтвергается(t *testing.T) {
	_, err := Load(write(t, "SCHEMA=99\n"))
	if err == nil {
		t.Fatal("схема новее текущей должна быть ошибкой, а не поводом гадать")
	}
}

func TestОтносительныйStateDirОтвергается(t *testing.T) {
	// Относительный путь означал бы, что состояние окажется там, откуда
	// запустили службу, — то есть в разных местах при запуске руками и из init.
	if _, err := Load(write(t, "STATE_DIR=state\n")); err == nil {
		t.Fatal("относительный STATE_DIR должен быть ошибкой")
	}
}

func TestГраницыНомераОчереди(t *testing.T) {
	for _, v := range []string{"-1", "65536", "нет"} {
		if _, err := Load(write(t, "QUEUE_NUM="+v+"\n")); err == nil {
			t.Errorf("QUEUE_NUM=%s принят, хотя не должен", v)
		}
	}
	c, err := Load(write(t, "QUEUE_NUM=2001\n"))
	if err != nil || c.QueueNum != 2001 {
		t.Errorf("нормальное значение не прочитано: %v %d", err, c.QueueNum)
	}
}

func TestОбратнаяЗаписьЧитаетсяОбратно(t *testing.T) {
	c1, err := Load(write(t, "MODE=off\nQUEUE_NUM=2005\nЧУЖОЙ=да\n"))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Load(write(t, c1.Render()))
	if err != nil {
		t.Fatalf("собственный вывод не читается: %v", err)
	}
	if c2.Mode != c1.Mode || c2.QueueNum != c1.QueueNum || c2.Unknown["ЧУЖОЙ"] != "да" {
		t.Errorf("круг не сошёлся: %+v против %+v", c2, c1)
	}
}
