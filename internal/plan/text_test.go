package plan

import "testing"

const образец = `d2k-plan 1 1
id 0102030405060708090a0b0c0d0e0f10
proto tcp tls
payload 1 160301
poison 1 ttl=3 badsum seqshift=-10000
split sni_start +0
fake payload=1 poison=1 repeats=2 gap_us=78000 place=before
order forward
`

func TestКругТекстПланТекст(t *testing.T) {
	p, err := ParseText(образец)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if got := p.Text(); got != образец {
		t.Errorf("круг не сошёлся:\n--- было ---\n%s\n--- стало ---\n%s", образец, got)
	}
}

func TestНеизвестнаяСтрокаЭтоОшибка(t *testing.T) {
	// Молча пропустить строку значило бы исполнить не тот план, который
	// записан. Спека запрещает это на уровне TLV, и текст обязан вести себя
	// так же — иначе расхождение появится в человеческой форме.
	if _, err := ParseText("d2k-plan 1 1\nчегототакое 5\n"); err == nil {
		t.Fatal("неизвестная директива должна быть ошибкой")
	}
}
