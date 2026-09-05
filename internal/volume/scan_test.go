package volume

import (
	"context"
	"testing"
)

// answers — заранее заданные ответы пробы по именам. Подбор — это правила, а
// не сеть: проверяем правила.
type answers struct {
	base   Verdict
	byName map[string][]Verdict
	seen   []string
}

func (a *answers) probe() func(context.Context, Target, string, Pump) Result {
	return func(_ context.Context, t Target, sni string, p Pump) Result {
		if sni == "" {
			return Result{Target: t, Pump: p, Verdict: a.base, AtKB: 19}
		}
		a.seen = append(a.seen, sni)
		v := a.byName[sni]
		if len(v) == 0 {
			return Result{Target: t, SNI: sni, Pump: p, Verdict: VerdictCut, AtKB: 19}
		}
		out := v[0]
		if len(v) > 1 {
			a.byName[sni] = v[1:]
		}
		return Result{Target: t, SNI: sni, Pump: p, Verdict: out, AtKB: 19}
	}
}

func scanWith(a *answers, names []string, opt ScanOptions) ScanResult {
	opt.probe = a.probe()
	return Scan(context.Background(), Target{IP: "203.0.113.1", Port: 443}, names, opt)
}

func TestБезБлокаИмяНеПриписывается(t *testing.T) {
	// Объём проходит и так. Записать сюда имя значило бы выдумать
	// зависимость, которой нет, и потом «чинить» ею работающее.
	a := &answers{base: VerdictPassed}
	r := scanWith(a, []string{"a.example", "b.example"}, ScanOptions{})
	if r.Verdict != ScanNoBlock {
		t.Fatalf("вердикт %v, ожидалось «блока нет»", r.Verdict)
	}
	if r.Name != "" {
		t.Errorf("приписано имя %q там, где блока нет", r.Name)
	}
	if len(a.seen) != 0 {
		t.Errorf("проверено %d имён впустую: %v", len(a.seen), a.seen)
	}
}

func TestНедоступнаяМишеньНеПоводДляПодбора(t *testing.T) {
	a := &answers{base: VerdictUnreachable}
	r := scanWith(a, []string{"a.example"}, ScanOptions{})
	if r.Verdict != ScanUnusable {
		t.Fatalf("вердикт %v, ожидалось «мерить нечем»", r.Verdict)
	}
	if r.Tried != 0 {
		t.Errorf("проверено %d имён на мишени, которая не отвечает", r.Tried)
	}
}

func TestУбившееРукопожатиеИмяОтбраковано(t *testing.T) {
	// Замер 06.09.2026, Gcore AS199524: без имени поток жил до 19 КБ, а с
	// неподходящим именем рукопожатие не встало вовсе. Такое имя вредно, а не
	// бесполезно, и в план попасть не должно никогда.
	a := &answers{base: VerdictCut, byName: map[string][]Verdict{
		"вредное.example": {VerdictUnreachable},
		"годное.example":  {VerdictPassed},
	}}
	r := scanWith(a, []string{"вредное.example", "годное.example"}, ScanOptions{})
	if r.Name != "годное.example" {
		t.Fatalf("выбрано имя %q", r.Name)
	}
	if len(r.Killed) != 1 || r.Killed[0] != "вредное.example" {
		t.Errorf("вредное имя не записано в отбракованные: %v", r.Killed)
	}
}

func TestПодборБерётПервоеПрошедшееИЗдесьЖеОстанавливается(t *testing.T) {
	a := &answers{base: VerdictCut, byName: map[string][]Verdict{
		"первое.example": {VerdictPassed},
		"второе.example": {VerdictPassed},
	}}
	r := scanWith(a, []string{"первое.example", "второе.example"}, ScanOptions{})
	if r.Name != "первое.example" {
		t.Fatalf("выбрано %q, а порядок кандидатов задан вызывающим", r.Name)
	}
	if len(a.seen) != 1 {
		t.Errorf("после удачи проверено ещё %d имён: %v", len(a.seen)-1, a.seen[1:])
	}
}

func TestПотолокИмёнСоблюдается(t *testing.T) {
	a := &answers{base: VerdictCut, byName: map[string][]Verdict{
		"третье.example": {VerdictPassed},
	}}
	names := []string{"первое.example", "второе.example", "третье.example"}
	r := scanWith(a, names, ScanOptions{MaxNames: 2})
	if r.Verdict != ScanExhausted {
		t.Fatalf("вердикт %v, ожидалось «имя не найдено»: потолок два имени", r.Verdict)
	}
	if r.Tried != 2 {
		t.Errorf("проверено %d имён при потолке 2", r.Tried)
	}
}

func TestПодтверждениеОтсеиваетСлучайноеПрохождение(t *testing.T) {
	// Коробка не обязана рвать каждый поток. Одно прохождение — не имя.
	a := &answers{base: VerdictCut, byName: map[string][]Verdict{
		"случайное.example": {VerdictPassed, VerdictCut},
		"настоящее.example": {VerdictPassed, VerdictPassed},
	}}
	names := []string{"случайное.example", "настоящее.example"}
	r := scanWith(a, names, ScanOptions{Confirm: true})
	if r.Name != "настоящее.example" {
		t.Fatalf("выбрано %q — подтверждение не отсеяло случайное прохождение", r.Name)
	}
}

func TestОбрывБезИмениЗапоминаетсяКакИзмерение(t *testing.T) {
	a := &answers{base: VerdictCut}
	r := scanWith(a, nil, ScanOptions{})
	if r.CutAtKB != 19 {
		t.Errorf("объём обрыва %d КБ, а проба показала 19", r.CutAtKB)
	}
}
