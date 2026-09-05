package plan_test

import (
	"bytes"
	"testing"

	"github.com/necronicle/d2k/internal/plan"
)

func TestПриманкаЭтоЦелоеПриветствие(t *testing.T) {
	// Огрызок вместо приветствия не работает: коробка отбрасывает битую
	// запись целиком и своего имени в ней не ищет. Значит собранное обязано
	// быть согласованным по всем трём длинам сразу.
	b, err := plan.Hello("disk.rzd.ru", 0)
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != 0x16 {
		t.Fatalf("тип записи %#02x, а ждали рукопожатие", b[0])
	}
	recLen := int(b[3])<<8 | int(b[4])
	if len(b) != 5+recLen {
		t.Fatalf("длина записи %d не сходится с фактическими %d", recLen, len(b)-5)
	}
	if b[5] != 0x01 {
		t.Fatalf("тип рукопожатия %#02x, а ждали ClientHello", b[5])
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	if recLen != 4+hsLen {
		t.Fatalf("длина рукопожатия %d не сходится с записью %d", hsLen, recLen)
	}
	if !bytes.Contains(b, []byte("disk.rzd.ru")) {
		t.Fatal("имени приманки нет в собранном приветствии")
	}
}

func TestПриманкаВоспроизводима(t *testing.T) {
	// §5.4: случайность представлена явно. Один и тот же план обязан давать
	// одни и те же байты на проводе, иначе измерения не с чем сравнивать.
	a, _ := plan.Hello("example.com", 0)
	b, _ := plan.Hello("example.com", 0)
	if !bytes.Equal(a, b) {
		t.Fatal("две сборки одной приманки дали разные байты")
	}
	c, _ := plan.Hello("example.com", 7)
	if bytes.Equal(a, c) {
		t.Fatal("заданный байт заполнения ни на что не влияет")
	}
}

func TestПриманкаРазбираетсяИсполнителем(t *testing.T) {
	// Настоящая проверка: собранное приветствие должен узнать тот же
	// протокольный модуль, что стоит на пакетном пути. Здесь — его
	// Go-двойника нет, поэтому сверяем то, что модуль ищет: смещение имени.
	b, err := plan.Hello("linkedin.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(b, []byte("linkedin.com"))
	if i < 0 {
		t.Fatal("имени нет")
	}
	// Перед именем обязаны стоять его длина и тип «имя хоста».
	if b[i-1] != byte(len("linkedin.com")) || b[i-3] != 0x00 {
		t.Fatalf("раскладка расширения server_name не та: %x", b[i-5:i])
	}
}

func TestПустоеИСлишкомДлинноеИмяОтвергаются(t *testing.T) {
	if _, err := plan.Hello("", 0); err == nil {
		t.Fatal("приманка без имени собралась")
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := plan.Hello(string(long), 0); err == nil {
		t.Fatal("слишком длинное имя принято")
	}
}
