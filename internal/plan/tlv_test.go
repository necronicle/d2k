package plan

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestКругТекстTLVТекст(t *testing.T) {
	// Две формы плана могут разойтись, и этот круг — единственное, что ловит
	// расхождение до того, как оно доедет до исполнителя.
	p1, err := ParseText(образец)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p1.MarshalTLV()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := UnmarshalTLV(raw)
	if err != nil {
		t.Fatalf("своя же каноническая форма не читается: %v", err)
	}
	if p1.Text() != p2.Text() {
		t.Errorf("круг не сошёлся:\n--- было ---\n%s\n--- стало ---\n%s", p1.Text(), p2.Text())
	}
}

func TestЗаголовокTLV(t *testing.T) {
	p, _ := ParseText(образец)
	raw, _ := p.MarshalTLV()
	if !bytes.HasPrefix(raw, []byte("D2KP")) {
		t.Fatalf("нет магии: %s", hex.EncodeToString(raw[:8]))
	}
	if raw[4] != 0 || raw[5] != 1 {
		t.Errorf("схема в заголовке не 1: %x", raw[4:6])
	}
	if raw[8] != 0 || raw[9] != 0 {
		t.Errorf("флаги обязаны быть нулевыми: %x", raw[8:10])
	}
}

func TestОбрезаннаяЗаписьОтвергается(t *testing.T) {
	p, _ := ParseText(образец)
	raw, _ := p.MarshalTLV()
	if _, err := UnmarshalTLV(raw[:len(raw)-3]); err == nil {
		t.Fatal("обрезанный план принят")
	}
}

func TestНеизвестныйТипЗаписиОтвергается(t *testing.T) {
	p, _ := ParseText(образец)
	raw, _ := p.MarshalTLV()
	// Портим тип первой записи: пропустить её молча значило бы исполнить не
	// тот план, который измеряли.
	raw[headerLen] = 0x77
	if _, err := UnmarshalTLV(raw); err == nil {
		t.Fatal("неизвестный тип записи пропущен молча")
	}
}

func TestВисячаяСсылкаОтвергается(t *testing.T) {
	// План, часть которого не существует, — это не «план без порчи», а план,
	// отличный от записанного.
	src := "d2k-plan 1 1\nid " + hex.EncodeToString(make([]byte, 16)) + "\n" +
		"proto tcp tls\npayload 1 aabb\n" +
		"fake payload=1 poison=9 repeats=1 gap_us=0 place=before\norder forward\n"
	p, err := ParseText(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.MarshalTLV(); err == nil {
		t.Fatal("план с висячей ссылкой на порчу закодирован")
	}
}

func TestСсылкаНольЭтоОтсутствие(t *testing.T) {
	// Фальшивка без порчи законна: ноль означает «ничего», а не «запись 0».
	src := "d2k-plan 1 1\nid " + hex.EncodeToString(make([]byte, 16)) + "\n" +
		"proto tcp tls\npayload 1 aabb\n" +
		"fake payload=1 poison=0 repeats=1 gap_us=0 place=before\norder forward\n"
	p, err := ParseText(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.MarshalTLV(); err != nil {
		t.Fatalf("фальшивка без порчи отвергнута: %v", err)
	}
}
