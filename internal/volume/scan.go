package volume

import (
	"context"
	"time"
)

// Подбор имени, с которым объём проходит.
//
// Ось здесь — имя, а не разрез: режется установленный поток, и никакая нарезка
// рукопожатия на него не действует. Замер 06.09.2026 на этой линии, мишень
// 91.98.156.82: без имени обрыв на 23 КБ дважды подряд, с disk.rzd.ru — 39 КБ
// пройдено дважды подряд. Одна и та же мишень, одна минута, разница только в
// имени.
//
// Неподходящее имя ХУЖЕ отсутствия имени. Там же: hcaptcha.com и ya.ru не дали
// даже встать рукопожатию, тогда как без имени поток жил до 23 КБ. Поэтому
// кандидат, убивший рукопожатие, отбраковывается сразу и никогда не попадает в
// план — иначе обход своими руками ломал бы то, что работало.
//
// Порядок проверки задан этим же: сперва БЕЗ имени. Если объём проходит и так,
// блока здесь нет, и приписывать сети имя нельзя — это была бы выдуманная
// зависимость.

// ScanVerdict — чем кончился подбор.
type ScanVerdict int

const (
	// ScanNoBlock — объём проходит и без имени: блока на этом направлении нет.
	ScanNoBlock ScanVerdict = iota
	// ScanFound — имя найдено.
	ScanFound
	// ScanExhausted — блок есть, но ни одно имя из списка не подошло.
	ScanExhausted
	// ScanUnusable — мишень не отвечает даже без имени: мерить нечем.
	ScanUnusable
)

func (v ScanVerdict) String() string {
	switch v {
	case ScanFound:
		return "имя найдено"
	case ScanExhausted:
		return "блок есть, имя не найдено"
	case ScanUnusable:
		return "мишень не отвечает — мерить нечем"
	default:
		return "блока по объёму нет"
	}
}

// ScanResult — что дал подбор.
type ScanResult struct {
	Target  Target
	Verdict ScanVerdict
	// Name — найденное имя. Пусто во всех прочих исходах.
	Name string
	// CutAtKB — объём, на котором рвётся без имени. Ноль, если не рвётся.
	CutAtKB int
	// Tried — сколько имён проверено, включая отбракованные.
	Tried int
	// Killed — имена, убившие рукопожатие. Хранятся, чтобы не предлагать их
	// снова и чтобы было видно, что список кандидатов не бесплатен.
	Killed []string
	// Baseline — проба без имени, целиком.
	Baseline Result
}

// ScanOptions — ограничители подбора. Без них перебор двухсот имён на мишени,
// где каждое неподходящее стоит рукопожатия, занимает минуты.
type ScanOptions struct {
	// MaxNames — сколько имён разрешено проверить. Ноль — все.
	MaxNames int
	// Budget — общий потолок времени. Ноль — без потолка.
	Budget time.Duration
	// Confirm — повторить удачное имя ещё раз перед объявлением. Одно
	// прохождение может быть случайным: коробка не обязана рвать каждый поток.
	Confirm bool

	// probe — подменяемая проба. Нужна тестам: правила подбора («без имени
	// сперва», «убившее рукопожатие — отбраковать») проверяются логикой, а не
	// живой сетью, иначе тест меряет чужую линию.
	probe func(context.Context, Target, string, Pump) Result
}

func (o ScanOptions) prober() func(context.Context, Target, string, Pump) Result {
	if o.probe != nil {
		return o.probe
	}
	return Probe
}

// Scan ищет имя, с которым объём на этой мишени проходит.
func Scan(ctx context.Context, t Target, names []string, opt ScanOptions) ScanResult {
	res := ScanResult{Target: t}
	probe := opt.prober()

	base := probe(ctx, t, t.SNI, PumpOut)
	res.Baseline = base
	switch base.Verdict {
	case VerdictPassed:
		res.Verdict = ScanNoBlock
		return res
	case VerdictCut:
		res.CutAtKB = base.AtKB
	default:
		// Мишень не ответила или объём не набран: вердикта о линии нет, и
		// подбирать имя не к чему.
		res.Verdict = ScanUnusable
		return res
	}

	deadline := time.Time{}
	if opt.Budget > 0 {
		deadline = time.Now().Add(opt.Budget)
	}

	for _, name := range names {
		if opt.MaxNames > 0 && res.Tried >= opt.MaxNames {
			break
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}
		if ctx.Err() != nil {
			break
		}
		res.Tried++

		r := probe(ctx, t, name, PumpOut)
		switch r.Verdict {
		case VerdictUnreachable:
			// Рукопожатие не встало: с этим именем коробка глушит соединение
			// целиком. Кандидат вредный, не просто бесполезный.
			res.Killed = append(res.Killed, name)
		case VerdictPassed:
			if opt.Confirm {
				if again := probe(ctx, t, name, PumpOut); again.Verdict != VerdictPassed {
					continue
				}
			}
			res.Verdict = ScanFound
			res.Name = name
			return res
		}
	}

	res.Verdict = ScanExhausted
	return res
}
