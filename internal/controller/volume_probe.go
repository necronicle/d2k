package controller

import (
	"context"
	"sort"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/plan"

	"github.com/necronicle/d2k/internal/volume"
)

// Активная проба на блок по объёму соединения.
//
// Ось отдельная от разреза, и она про ИМЯ. Замер 06.09.2026 на этой линии,
// мишень 91.98.156.82: без имени поток рвётся на 23 КБ дважды подряд, с
// disk.rzd.ru проходит 39 КБ дважды подряд — одна мишень, одна минута, разница
// только в имени. Никакая нарезка приветствия на это не влияет: режется уже
// установленный поток.
//
// Почему проба, а не наблюдение за трафиком человека. Наблюдение отвечает на
// вопрос «этот хост сейчас режут?» и ошибается: окно видимости датапата —
// первые пакеты, а обрыв случается на двадцатом килобайте.
//
// Качаем ИСХОДЯЩИМ объёмом, потому что его задаём мы сами и не зависим от
// того, что и как отдаёт мишень. Одного этого хватает: в пробе входящих меньше
// двух килобайт за весь сеанс, а поток всё равно рвётся. Что коробка считает
// суммарный объём или любой из двух — не измерено и здесь не утверждается.
//
// Одного имени на все сети не бывает — это измерено, а не предположено. Прогон
// по 35 сетям 06.09.2026: disk.rzd.ru проходит 12 из них и не проходит 21.
// Хуже: на Gcore AS199524 без имени поток жил до 19 КБ, а с этим именем
// рукопожатие не встало вовсе. Неподходящее имя вредно, а не бесполезно,
// поэтому оно отбраковывается пробой и в план не попадает.
//
// Имя держится на всех адресах одного оператора (Hetzner 91.98.156.82 и
// 46.62.154.37 — разные /8, обе прошли), но таблицы «сеть → имя» здесь нет
// намеренно: она стареет и требует внешнего источника. Вместо неё порядок
// кандидатов — имена, уже сработавшие на этой линии, идут первыми, и для
// второй цели того же оператора подбор кончается на первой же пробе.

// questionVolume — имя вопроса в журнале решений.
const questionVolume = "режут ли поток по объёму"

const (
	// Сколько имён разрешено проверить за один поиск. Каждое неподходящее имя
	// стоит рукопожатия, а иное — полного его таймаута.
	maxVolumeNames = 12
	// Потолок времени на подбор. Человек ждёт.
	volumeScanBudget = 90 * time.Second
)

// VolumeProber — чем задаётся вопрос про объём. Интерфейс, чтобы проверки не
// ходили в сеть.
type VolumeProber interface {
	Scan(ctx context.Context, t volume.Target, names []string, opt volume.ScanOptions) volume.ScanResult
	Probe(ctx context.Context, t volume.Target, sni string, pump volume.Pump) volume.Result
}

type liveVolumeProber struct{}

func (liveVolumeProber) Scan(ctx context.Context, t volume.Target, names []string, opt volume.ScanOptions) volume.ScanResult {
	return volume.Scan(ctx, t, names, opt)
}

func (liveVolumeProber) Probe(ctx context.Context, t volume.Target, sni string, pump volume.Pump) volume.Result {
	return volume.Probe(ctx, t, sni, pump)
}

// SetVolumeProber подменяет пробу на объём.
func (c *Controller) SetVolumeProber(p VolumeProber) { c.volProber = p }

type volumeScanDone struct {
	target string
	res    volume.ScanResult
}

type volumeVerifyDone struct {
	target string
	res    volume.Result
}

// verifyVolume проверяет поставленный план тем же прибором, которым нашли
// обрыв.
//
// Раньше здесь стояло ожидание: план ставился, и поиск ждал, пока человек сам
// прокачает через цель достаточно объёма. Это ровно те «повторы вместо
// времени», от которых мы уходили: устройство, которое ходит на сервер раз в
// сутки, не подтвердило бы решение никогда.
//
// Зонд идёт с НАСТОЯЩИМ именем цели: датапат ищет план по имени, и только так
// поставленная приманка вообще вступает в дело. Проверяется, стало быть, не
// «проходит ли имя», а «работает ли поставленный план» — это разные вопросы, и
// первый уже отвечен подбором.
func (c *Controller) verifyVolume(t *Task) {
	if c.volProber == nil || t.ServerIP == "" || t.scanning {
		return
	}
	t.scanning = true
	target := t.Target
	tgt := volume.Target{IP: t.ServerIP, Port: t.ServerPort, Plain: t.ServerPort == 80}
	c.sayf("по %s проверяю поставленный план объёмом: %s:%d", target, t.ServerIP, t.ServerPort)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c.volVerify <- volumeVerifyDone{target: target, res: c.volProber.Probe(ctx, tgt, target, volume.PumpOut)}
	}()
}

// onVolumeVerify — проверка ответила.
func (c *Controller) onVolumeVerify(d volumeVerifyDone) error {
	t := c.tasks[d.target]
	if t == nil {
		return nil
	}
	t.scanning = false
	if t.Current == nil {
		return nil
	}

	if d.res.Verdict != volume.VerdictPassed {
		c.sayf("по %s план %s объём не провёл: %s", t.Target, t.Current.Plan.ID, d.res.Verdict)
		t.Current = nil
		return c.advance(t)
	}

	// Уровень 4 по §4.2: прикладной обмен в ПРОВЕРЯЕМОМ объёме — известно,
	// на чём рвалось раньше, и известно, сколько прошло теперь.
	c.sayf("по %s план %s провёл %d КБ там, где рвалось на %d КБ",
		t.Target, t.Current.Plan.ID, d.res.AtKB, t.VolumeCutAt/1024)
	box, created, err := c.store.Catalog().Confirm(
		t.Fingerprint, t.Current.Plan, t.Kind, t.Target, catalog.LevelApplication, c.now())
	if err != nil {
		c.sayf("по %s объём прошёл, но записать нечего: %v", t.Target, err)
		return nil
	}
	c.store.Touch()
	c.Confirms++
	what := "коробка " + box.ID
	if created {
		what = "заведена коробка " + box.ID
	}
	if t.Current.Decoy != "" {
		c.sayf("по %s подошло имя %s: %s, план %s",
			t.Target, t.Current.Decoy, what, t.Current.Plan.ID)
	}
	delete(c.tasks, t.Target)
	if w := c.volume[t.Target]; w != nil {
		w.told = false
		w.samples = nil
	}
	if _, err := c.store.Flush(c.now()); err != nil {
		c.sayf("каталог не записался: %v", err)
	}
	return nil
}

// askVolume запускает измерение объёма и НЕ ЖДЁТ его.
//
// Ожидание здесь стоило полевого прогона: обе цели простояли две минуты с
// заданным вопросом и без единого поставленного плана. Измерение идёт до
// полутора минут, а первый кандидат встаёт за секунду — держать человека всё
// это время ради вопроса, который на большинстве целей ответит «блока нет»,
// нельзя.
//
// Поэтому лестница кандидатов идёт своим ходом, а ответ про объём, когда
// придёт, ПЕРЕБИВАЕТ её: подстановка имени — единственное, что при этом блоке
// вообще действует, и ждать своей очереди ей незачем.
func (c *Controller) askVolume(t *Task) {
	if t.ServerIP == "" || c.volProber == nil || t.scanning {
		// Спросить нечем. «Не спрашивали» — не «нет» (§2.4).
		t.Traits.VolumeAsked = true
		return
	}
	if t.Probes >= maxProbesPerTask {
		c.sayf("по %s бюджет зондов исчерпан (%d) — про объём не спрашиваю", t.Target, t.Probes)
		t.Traits.VolumeAsked = true
		return
	}

	t.scanning = true
	t.Traits.VolumeAsked = true
	t.Probes++
	c.probesUsed++
	c.sayf("по %s заодно меряю объём (%s), не останавливая поиск",
		t.Target, "если режут по объёму, дело в имени, а не в разрезе")

	target := t.Target
	tgt := volume.Target{IP: t.ServerIP, Port: t.ServerPort, Plain: t.ServerPort == 80}
	names := c.volumeNames()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), volumeScanBudget+30*time.Second)
		defer cancel()
		res := c.volProber.Scan(ctx, tgt, names, volume.ScanOptions{
			MaxNames: maxVolumeNames,
			Budget:   volumeScanBudget,
			Confirm:  true,
		})
		c.volResults <- volumeScanDone{target: target, res: res}
	}()
}

// seedNameHits согревает порядок кандидатов из каталога.
//
// Имена, уже открывавшие дорогу, записаны внутри подтверждённых планов — в
// приманке. Доставать их оттуда, а не заводить отдельное поле, значит держать
// один источник правды: план, который сработал, и есть доказательство, что имя
// работает. Перезагрузка роутера после этого не стоит человеку лишних проб.
func (c *Controller) seedNameHits() {
	cat := c.store.Catalog()
	for i := range cat.Boxes {
		for _, pl := range cat.Boxes[i].Plans {
			if pl.Successes == 0 {
				continue
			}
			parsed, err := plan.ParseText(pl.Text)
			if err != nil {
				continue
			}
			for _, f := range parsed.Fakes {
				pay := findPayload(parsed, f.PayloadID)
				if pay == nil {
					continue
				}
				if sni := sniOf(pay.Bytes); sni != "" {
					c.nameHits[sni] += pl.Successes
				}
			}
		}
	}
}

// volumeNames — порядок проверки имён: сперва те, что уже открывали дорогу на
// этой линии. Замена таблице «сеть → имя»: она стареет, а порядок сам
// подстраивается под то, что здесь работает.
// Scanning — идёт ли измерение объёма. Наружу ради панели: оно идёт рядом с
// лестницей, а не вместо неё, и человеку это надо видеть.
func (t *Task) Scanning() bool { return t.scanning }

// VolumeNames — порядок проверки имён. Наружу ради проверок: согрет ли он
// прошлым знанием, видно только отсюда.
func (c *Controller) VolumeNames() []string { return c.volumeNames() }

func (c *Controller) volumeNames() []string {
	all := decoyNames()
	if len(c.nameHits) == 0 {
		return all
	}
	// Сработавшее имя может не значиться в списке кандидатов вовсе: список —
	// заготовка, а знание приходит из замера. Выбросить такое имя значило бы
	// забыть единственное, что здесь точно работало.
	known := make(map[string]bool, len(all))
	out := make([]string, 0, len(all)+len(c.nameHits))
	for _, n := range all {
		known[n] = true
	}
	for n := range c.nameHits {
		if !known[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out) // порядок среди равных не должен зависеть от обхода карты
	out = append(out, all...)
	sort.SliceStable(out, func(i, j int) bool { return c.nameHits[out[i]] > c.nameHits[out[j]] })
	return out
}

// onVolumeScan толкует ответ. Единственное место, где проба превращается в
// свойство, и потому здесь важнее всего не сказать лишнего (§2.4).
func (c *Controller) onVolumeScan(d volumeScanDone) error {
	t := c.tasks[d.target]
	if t == nil {
		return nil
	}
	t.scanning = false
	r := d.res

	switch r.Verdict {
	case volume.ScanNoBlock:
		c.sayf("по %s ответ: объём проходит и без имени — блока по объёму здесь нет", t.Target)
		if t.Current == nil && t.Asking.Name == "" {
			// Лестница успела кончиться, пока мы мерили. Теперь ответ есть, и
			// закрывать поиск можно честно.
			return c.step(t)
		}
		return nil

	case volume.ScanFound:
		t.Traits.VolumeCut = true
		t.Traits.PassingName = r.Name
		t.VolumeCutAt = int64(r.CutAtKB) * 1024
		c.nameHits[r.Name]++
		c.sayf("по %s ответ: поток рвётся на %d КБ, имя %s проводит объём (проверено имён %d)",
			t.Target, r.CutAtKB, r.Name, r.Tried)
		t.Fingerprint = c.volumeSignal(t, r.CutAtKB)
		if len(r.Killed) > 0 {
			c.sayf("по %s имена, убившие рукопожатие, отброшены: %v", t.Target, r.Killed)
		}
		// Перебиваем лестницу: при этом блоке ничто, кроме имени, не поможет,
		// а очередь была построена без знания о нём.
		t.Current = nil
		t.Queue = nil
		return c.advance(t)

	case volume.ScanExhausted:
		t.Traits.VolumeCut = true
		t.VolumeCutAt = int64(r.CutAtKB) * 1024
		c.sayf("по %s ответ: поток рвётся на %d КБ, но ни одно из %d имён его не провело",
			t.Target, r.CutAtKB, r.Tried)
		t.Fingerprint = c.volumeSignal(t, r.CutAtKB)
		if t.Current == nil && t.Asking.Name == "" {
			return c.step(t)
		}
		return nil

	default:
		c.sayf("по %s про объём ответа нет: %s (%s)", t.Target, r.Verdict, r.Baseline.Err)
		if t.Current == nil && t.Asking.Name == "" {
			return c.step(t)
		}
	}
	return nil
}

// volumeSignal заводит примету коробки по измеренному обрыву.
//
// Примета берётся из ПРОБЫ, а не из наблюдения за чужим потоком: наблюдение
// путает здоровую крупную загрузку с обрывом, и коробка, заведённая по такой
// примете, была бы выдумкой.
func (c *Controller) volumeSignal(t *Task, atKB int) catalog.Fingerprint {
	c.sayf("  примета: обрыв по объёму около %d КиБ", atKB)
	return addSignal(t.Fingerprint, catalog.Signal{
		Kind: "volume", Seen: 1, Volume: atKB,
	})
}
