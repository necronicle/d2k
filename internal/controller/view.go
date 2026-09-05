package controller

import (
	"fmt"
	"sort"
	"strings"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/plan"
	"github.com/necronicle/d2k/internal/status"
)

// Knowledge собирает то, что панель показывает про узнанное.
//
// Живёт здесь, а не в панели: панель не должна знать ни устройства каталога,
// ни того, чем «проверяем готовое» отличается от «ищем новое». Её дело —
// показать, а не решить, что показывать.
func (c *Controller) Knowledge() status.Knowledge {
	k := status.Knowledge{
		Linked:     true,
		CatalogAt:  c.store.Path(),
		Confirms:   c.Confirms,
		ProbesUsed: c.probesUsed,
	}
	cat := c.store.Catalog()
	for i := range cat.Boxes {
		k.Boxes = append(k.Boxes, boxView(&cat.Boxes[i]))
		k.Targets += len(cat.Boxes[i].Bindings)
	}
	sort.Slice(k.Boxes, func(i, j int) bool { return k.Boxes[i].ID < k.Boxes[j].ID })

	for _, t := range c.Tasks() {
		v := status.SearchView{
			Target:   t.Target,
			Since:    t.Started,
			Attempts: t.Attempts,
			Probes:   t.Probes,
			Phase:    "распознаём поведение",
		}
		if t.Current != nil {
			v.Candidate = t.Current.Plan.ID
			v.Source = t.Current.Source
			// §8 требует различать «проверяем готовую стратегию коробки X» и
			// «ищем новое решение». Различие берётся из того, откуда взялся
			// кандидат, а не додумывается.
			if t.Current.BoxID != "" {
				v.Phase = "проверяем готовый план коробки " + t.Current.BoxID
			} else {
				v.Phase = "ищем новое решение"
			}
		}
		k.Searches = append(k.Searches, v)
	}
	return k
}

func boxView(b *catalog.Box) status.BoxView {
	v := status.BoxView{ID: b.ID, Created: b.Created, Updated: b.Updated}
	for _, s := range b.Fingerprint.Signals {
		v.Signals = append(v.Signals, status.SignalView{
			Kind:  s.Kind,
			Human: humanSignal(s),
			Seen:  s.Seen,
		})
	}
	for _, p := range b.Plans {
		v.Plans = append(v.Plans, status.PlanView{
			ID: p.ID, Proto: p.Proto, Successes: p.Successes,
			Enabled: p.Enabled, Human: humanPlan(p.Text), Text: p.Text,
		})
	}
	for _, bd := range b.Bindings {
		v.Bindings = append(v.Bindings, status.BindingView{
			Target: bd.Target, Kind: bd.Kind, Level: bd.Level,
			LevelName: status.LevelName(bd.Level),
			Successes: bd.Successes, Confirmed: bd.Confirmed, Enabled: bd.Enabled,
		})
	}
	return v
}

// humanSignal — примета словами.
//
// Собирается здесь, а не в шаблоне: шаблон не должен знать, что 0x88 это ToS,
// а 54321 — идентификатор IP. И не должен решать, что из этого важно.
func humanSignal(s catalog.Signal) string {
	switch s.Kind {
	case "rst":
		var b strings.Builder
		b.WriteString("сброс приходит не от сервера")
		if s.TTL != 0 {
			fmt.Fprintf(&b, ": TTL %d", s.TTL)
		}
		if s.IPID != 0 {
			fmt.Fprintf(&b, ", постоянный идентификатор IP %d", s.IPID)
		}
		if s.ToS != 0 {
			fmt.Fprintf(&b, ", ToS %#02x", s.ToS)
		}
		return b.String()
	case "repeat":
		return "приветствие приходится повторять: ответа нет"
	case "silent":
		return "на приветствие не отвечают вовсе"
	default:
		return s.Kind
	}
}

// humanPlan — что план делает, словами.
//
// §8: «понятное описание действий и техническое представление по раскрытию».
// Описание строится из РАЗОБРАННОГО плана, а не из его текста: пересказывать
// строку значит однажды пересказать не то, что исполнится.
func humanPlan(text string) string {
	p, err := plan.ParseText(text)
	if err != nil {
		return "план не разбирается — показывать нечего"
	}
	var parts []string
	for _, f := range p.Fakes {
		n := int(f.Repeats)
		if n == 0 {
			n = 1
		}
		what := fmt.Sprintf("перед нагрузкой уходит %d приманк%s", n, ending(n))
		if pl := findPayload(p, f.PayloadID); pl != nil {
			if sni := sniOf(pl.Bytes); sni != "" {
				what += fmt.Sprintf(" с чужим именем %s", sni)
			}
		}
		if po := findPoison(p, f.PoisonID); po != nil {
			var how []string
			if po.TTL != 0 {
				how = append(how, fmt.Sprintf("TTL %d — умрёт по дороге", po.TTL))
			}
			if po.Flags&plan.PoisonBadSum != 0 {
				how = append(how, "неверная сумма — сервер отбросит")
			}
			if len(how) > 0 {
				what += " (" + strings.Join(how, ", ") + ")"
			}
		}
		if f.GapUS > 0 && n > 1 {
			what += fmt.Sprintf(", пауза %d мс", f.GapUS/1000)
		}
		parts = append(parts, what)
	}
	if len(p.Splits) > 0 {
		parts = append(parts, fmt.Sprintf("нагрузка режется на %d части", len(p.Splits)+1))
	}
	if p.Guards&plan.GuardRSTAlien != 0 {
		parts = append(parts, "входящий сброс от чужого отправителя снимается")
	}
	if len(parts) == 0 {
		return "план ничего не меняет"
	}
	return strings.Join(parts, "; ")
}

func ending(n int) string {
	if n == 1 {
		return "а"
	}
	return "и"
}

func findPayload(p plan.Plan, id uint16) *plan.Payload {
	for i := range p.Payloads {
		if p.Payloads[i].ID == id {
			return &p.Payloads[i]
		}
	}
	return nil
}

func findPoison(p plan.Plan, id uint16) *plan.Poison {
	for i := range p.Poisons {
		if p.Poisons[i].ID == id {
			return &p.Poisons[i]
		}
	}
	return nil
}

// sniOf вытаскивает имя из приманки, чтобы показать его человеку. Разбор
// нарочно поверхностный: если не нашлось — покажем без имени, а не соврём.
func sniOf(hello []byte) string {
	i := 0
	for i+4 < len(hello) {
		if hello[i] == 0x00 && hello[i+1] == 0x00 && hello[i+2] == 0x00 {
			// Похоже на начало server_name: тип 0, длина списка, тип имени 0.
			break
		}
		i++
	}
	// Ищем печатное имя после разметки расширения.
	for j := i; j+1 < len(hello); j++ {
		n := int(hello[j])
		if n < 4 || j+1+n > len(hello) {
			continue
		}
		s := hello[j+1 : j+1+n]
		printable := true
		dot := false
		for _, ch := range s {
			if ch == '.' {
				dot = true
			}
			if ch < 0x20 || ch > 0x7e {
				printable = false
				break
			}
		}
		if printable && dot {
			return string(s)
		}
	}
	return ""
}
