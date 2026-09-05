package probe_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/necronicle/d2k/internal/plan"
	"github.com/necronicle/d2k/internal/probe"
)

// withExt вставляет расширение в собранное приветствие — чтобы проверить, что
// выбрасывается именно то, что должно.
func withExt(t *testing.T, base []byte, typ uint16, body []byte) []byte {
	t.Helper()
	// Находим блок расширений: он последний, и его длина — последние два
	// байта перед содержимым.
	recLen := int(binary.BigEndian.Uint16(base[3:5]))
	hs := base[5 : 5+recLen]
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	b := hs[4 : 4+hsLen]

	// Проходим до блока расширений тем же путём, что и Reshape.
	p := 2 + 32
	p += 1 + int(b[p])
	p += 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	p += 1 + int(b[p])
	extLen := int(binary.BigEndian.Uint16(b[p : p+2]))

	add := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(add[0:2], typ)
	binary.BigEndian.PutUint16(add[2:4], uint16(len(body)))
	copy(add[4:], body)

	nb := append([]byte(nil), b[:p]...)
	var el [2]byte
	binary.BigEndian.PutUint16(el[:], uint16(extLen+len(add)))
	nb = append(nb, el[:]...)
	nb = append(nb, b[p+2:]...)
	nb = append(nb, add...)

	outHS := []byte{0x01, byte(len(nb) >> 16), byte(len(nb) >> 8), byte(len(nb))}
	outHS = append(outHS, nb...)
	out := []byte{0x16, base[1], base[2], byte(len(outHS) >> 8), byte(len(outHS))}
	return append(out, outHS...)
}

func TestКопияСохраняетФормуИМеняетСлучайное(t *testing.T) {
	orig, err := plan.Hello("youtube.com", 0x11)
	if err != nil {
		t.Fatal(err)
	}
	copy1, dropped, err := probe.Reshape(orig, 0x55)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 0 {
		t.Fatalf("выброшено лишнее: %v", dropped)
	}
	// Имя цели — то, ради чего всё затевалось.
	if !bytes.Contains(copy1, []byte("youtube.com")) {
		t.Fatal("в копии нет имени цели")
	}
	// Форма: длина совпадает байт в байт, потому что ничего не выброшено.
	if len(copy1) != len(orig) {
		t.Fatalf("длина копии %d против исходных %d", len(copy1), len(orig))
	}
	// А случайное поле заменено.
	if bytes.Equal(copy1[11:11+32], orig[11:11+32]) {
		t.Fatal("случайное поле скопировано буквально")
	}
	// Наборы шифров сохранены: они начинаются после случайного поля и
	// идентификатора сессии.
	if !bytes.Contains(copy1, []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03}) {
		t.Fatal("наборы шифров не сохранились")
	}
}

func TestКопияВоспроизводима(t *testing.T) {
	// §5.4: один и тот же зонд обязан давать одни и те же байты, иначе
	// измерения не с чем сравнивать.
	orig, _ := plan.Hello("example.com", 0)
	a, _, _ := probe.Reshape(orig, 0x55)
	b, _, _ := probe.Reshape(orig, 0x55)
	if !bytes.Equal(a, b) {
		t.Fatal("две копии одного приветствия разошлись")
	}
}

func TestБилетВозобновленияНеКопируется(t *testing.T) {
	// §2.6: не копировать и не повторять пользовательские запросы. Билет —
	// учётные данные сессии, посылать их от себя нельзя.
	orig, _ := plan.Hello("example.com", 0)
	ticket := []byte("СЕКРЕТНЫЙ-БИЛЕТ-ПОЛЬЗОВАТЕЛЯ")
	withTicket := withExt(t, orig, 35, ticket)

	out, dropped, err := probe.Reshape(withTicket, 0x55)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, ticket) {
		t.Fatal("билет возобновления уехал в копию")
	}
	if len(dropped) != 1 || dropped[0] != 35 {
		t.Fatalf("выброшенное не отмечено: %v", dropped)
	}
	// Имя при этом обязано остаться: выбрасываем билет, а не форму.
	if !bytes.Contains(out, []byte("example.com")) {
		t.Fatal("вместе с билетом потерялось имя цели")
	}
}

func TestОбрезанноеПриветствиеОтвергается(t *testing.T) {
	orig, _ := plan.Hello("example.com", 0)
	for _, n := range []int{0, 4, 10, len(orig) / 2, len(orig) - 1} {
		if _, _, err := probe.Reshape(orig[:n], 0); err == nil {
			t.Fatalf("обрезанное до %d байт приветствие принято", n)
		}
	}
	if _, _, err := probe.Reshape([]byte{0x17, 0x03, 0x03, 0, 0}, 0); err == nil {
		t.Fatal("не-рукопожатие принято за приветствие")
	}
}
