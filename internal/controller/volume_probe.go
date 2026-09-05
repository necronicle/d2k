package controller

import (
	"context"
	"sort"
	"time"

	"github.com/necronicle/d2k/internal/catalog"

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
}

type liveVolumeProber struct{}

func (liveVolumeProber) Scan(ctx context.Context, t volume.Target, names []string, opt volume.ScanOptions) volume.ScanResult {
	return volume.Scan(ctx, t, names, opt)
}

// SetVolumeProber подменяет пробу на объём.
func (c *Controller) SetVolumeProber(p VolumeProber) { c.volProber = p }

type volumeScanDone struct {
	target string
	res    volume.ScanResult
}

// askVolume запускает подбор. Он долгий, поэтому уходит в сторону, а ответ
// возвращается тем же путём, что и ответ обычного зонда.
func (c *Controller) askVolume(t *Task) error {
	if t.ServerIP == "" || c.volProber == nil || t.scanning {
		// Спросить нечем. «Не спрашивали» — не «нет» (§2.4): ставим отказ от
		// вопроса и идём дальше.
		t.Traits.VolumeAsked = true
		return c.step(t)
	}
	if t.Probes >= maxProbesPerTask {
		c.sayf("по %s бюджет зондов исчерпан (%d) — про объём не спрашиваю", t.Target, t.Probes)
		t.Traits.VolumeAsked = true
		return c.step(t)
	}

	t.scanning = true
	t.Probes++
	c.probesUsed++
	t.Asking = Question{Name: questionVolume, Why: "если режут по объёму, дело в имени, а не в разрезе"}
	c.sayf("по %s спрашиваю: %s (%s), накачка исходящим объёмом",
		t.Target, t.Asking.Name, t.Asking.Why)

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
	return nil
}

// volumeNames — порядок проверки имён: сперва те, что уже открывали дорогу на
// этой линии. Замена таблице «сеть → имя»: она стареет, а порядок сам
// подстраивается под то, что здесь работает.
func (c *Controller) volumeNames() []string {
	all := decoyNames()
	if len(c.nameHits) == 0 {
		return all
	}
	out := append([]string(nil), all...)
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
	t.Asking = Question{}
	t.Traits.VolumeAsked = true
	r := d.res

	switch r.Verdict {
	case volume.ScanNoBlock:
		c.sayf("по %s ответ: объём проходит и без имени — блока по объёму здесь нет", t.Target)

	case volume.ScanFound:
		t.Traits.VolumeCut = true
		t.Traits.PassingName = r.Name
		t.VolumeCutAt = int64(r.CutAtKB) * 1024
		t.Fingerprint = c.volumeSignal(t, r.CutAtKB)
		c.nameHits[r.Name]++
		c.sayf("по %s ответ: поток рвётся на %d КБ, имя %s проводит объём (проверено имён %d)",
			t.Target, r.CutAtKB, r.Name, r.Tried)
		if len(r.Killed) > 0 {
			c.sayf("по %s имена, убившие рукопожатие, отброшены: %v", t.Target, r.Killed)
		}

	case volume.ScanExhausted:
		t.Traits.VolumeCut = true
		t.VolumeCutAt = int64(r.CutAtKB) * 1024
		t.Fingerprint = c.volumeSignal(t, r.CutAtKB)
		c.sayf("по %s ответ: поток рвётся на %d КБ, но ни одно из %d имён его не провело",
			t.Target, r.CutAtKB, r.Tried)

	default:
		c.sayf("по %s про объём ответа нет: %s (%s)", t.Target, r.Verdict, r.Baseline.Err)
	}
	return c.step(t)
}

// volumeSignal заводит примету коробки по измеренному обрыву.
//
// Примета берётся из ПРОБЫ, а не из наблюдения за чужим потоком: наблюдение
// путает здоровую крупную загрузку с обрывом, и коробка, заведённая по такой
// примете, была бы выдумкой.
func (c *Controller) volumeSignal(t *Task, atKB int) catalog.Fingerprint {
	c.sayf("  примета: обрыв по объёму около %d КиБ", atKB)
	return addSignal(t.Fingerprint, catalog.Signal{
		Kind: "volume", Seen: 1,
		// Объём кладём в поле идентификатора: он и есть примета этой коробки
		// на этом направлении, и по нему две коробки различаются.
		IPID: uint16(atKB),
	})
}
