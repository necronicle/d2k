package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/necronicle/d2k/internal/classify"
)

// Активная классификация функции решения коробки.
//
// §3.5 запрещает лестницу «попробуем это, потом то» — вместо неё вывод из
// измеренного. classify.Run — тот самый замер: он задаёт вопросы триггером
// на ФАКТИЧЕСКОЙ цели и возвращает вердикт, из которого buildQueue
// (controller.go, verdictCandidates) выводит очередь. Сам замер уходит в
// сеть и стоит секунд — по образцу объёма (volume_probe.go, askVolume/
// onVolumeScan): фоном, не задерживая лестницу кандидатов, а ответ, когда
// придёт, её перебивает.
//
// Бюджет — минута на весь прогон, ЦЕЛЬ пятнадцать секунд (docs/superpowers/
// plans/2026-09-06-classify-core.md, «Бюджет времени»; то же число уже
// зашито в cmd/d2k/classify.go как жёсткий предел контекста). Здесь это тот
// же предел на тот же вызов, а не отдельное число «на глаз».

// questionClassify — имя вопроса в журнале и в панели. Та же формулировка,
// что и в помощи команды `classify` (cmd/d2k/main.go): один и тот же вопрос
// не должен называться по-разному в двух местах продукта.
const questionClassify = "чем именно режут"

// classifyBudget — жёсткий предел на один прогон classify.Run.
const classifyBudget = 60 * time.Second

// DefaultMark — метка SO_MARK по умолчанию, если её не переопределит
// SetMark. Совпадает с MARK=0x2d в files/S99d2k: firewall-цепочка отпускает
// пакет с этой меткой мимо очереди нетронутым (§5.5) — расхождение здесь
// значило бы, что зонд метится числом, которое правило не узнаёт.
const DefaultMark uint32 = 0x2d

// Classifier — чем контроллер измеряет функцию решения коробки. Интерфейс, а
// не прямой вызов classify.Run, чтобы проверки не ходили в сеть.
type Classifier interface {
	Run(ctx context.Context, addr string, tr classify.Trigger, opt classify.Options) classify.Result
}

type liveClassifier struct{}

func (liveClassifier) Run(ctx context.Context, addr string, tr classify.Trigger, opt classify.Options) classify.Result {
	return classify.Run(ctx, addr, tr, opt)
}

// SetClassifier подменяет способ измерять функцию решения. Нужен проверкам:
// они не должны ходить в сеть.
func (c *Controller) SetClassifier(cl Classifier) { c.classifier = cl }

type classifyDone struct {
	target string
	res    classify.Result
}

// Classifying — идёт ли измерение функции решения. Наружу ради панели: оно
// идёт рядом с лестницей, а не вместо неё, и человеку это надо видеть — тем
// же способом, что и Task.Scanning() для объёма.
func (t *Task) Classifying() bool { return t.classifying }

// controlName — имя для контроля classify.Run: другое, заведомо не связанное
// с целью имя на ТОМ ЖЕ адресе. Без него дерево не отличит «решение по нашим
// байтам» от «молчит вообще всё» и на любом непройденном разрезе выдаст
// inconclusive, ни разу не дойдя до opaque (см. classify.Run, шаг
// «контроль»).
//
// Измеренное имя (Traits.PassingName) точнее заготовки: оно уже подтверждено
// пробой объёма НА ЭТОЙ линии, а не взято алфавитом инструмента — то же
// правило, что и decoyFor в candidates.go. Совпадение с самой целью
// (redundant control) отбрасывается: контролем нельзя ставить то же имя, что
// и триггером, иначе вопрос теряет смысл.
func controlName(t *Task, decoy string) string {
	name := decoyFor(t, decoy)
	if name == t.Target {
		return ""
	}
	return name
}

// askClassify запускает измерение функции решения и НЕ ЖДЁТ его — по образцу
// askVolume: первый кандидат обязан встать сразу, не дожидаясь замера,
// который может занять до минуты.
func (c *Controller) askClassify(t *Task) {
	if t.Kind != "name" || t.ServerIP == "" || c.classifier == nil || t.classifying {
		// Спросить нечем: цель без имени (t.Kind == "addr") измерять нечем —
		// classify.Trigger строится вокруг SNI, а не вокруг адреса. «Не
		// спрашивали» — не «нет» (§2.4), поэтому дальше просто не спрашиваем
		// снова, вектор остаётся пуст.
		t.classifyAsked = true
		return
	}
	tr, err := classify.TLSTrigger(t.Target)
	if err != nil {
		t.classifyAsked = true
		return
	}
	if t.Probes >= maxProbesPerTask {
		// Бюджет зондов общий на задачу (§5): классификация не исключение.
		c.sayf("по %s бюджет зондов исчерпан (%d) — функцию решения не измеряю",
			t.Target, t.Probes)
		t.classifyAsked = true
		return
	}

	// Mark — §5.5: активный поиск обязан метить зонд, иначе датапат (или уже
	// поставленный, ещё не проверенный план) может обработать его как
	// обычный трафик, и вердикт (особенно clear) окажется недостоверным
	// (см. classify.Run — Options.Mark, Result.Marked).
	opt := classify.Options{Mark: c.mark}
	if name := controlName(t, c.decoy); name != "" {
		if ctl, err := classify.Control(name); err == nil {
			opt.Control = ctl
		}
		// Ошибку контроля молча проглатываем: пустой Control — легальное
		// значение (Run сам за него отвечает вердиктом inconclusive, если до
		// контроля дойдёт дело), а не повод останавливать всё измерение.
	}

	t.classifying = true
	t.classifyAsked = true
	t.Probes++
	c.probesUsed++
	c.sayf("по %s заодно измеряю: %s, не останавливая поиск", t.Target, questionClassify)

	target := t.Target
	addr := fmt.Sprintf("%s:%d", t.ServerIP, t.ServerPort)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), classifyBudget)
		defer cancel()
		res := c.classifier.Run(ctx, addr, tr, opt)
		c.classifyResults <- classifyDone{target: target, res: res}
	}()
}

// onClassify — измерение функции решения ответило.
//
// Единственное место, где вердикт превращается в очередь кандидатов, и
// потому здесь так же, как в onVolumeScan, важнее всего не сказать лишнего
// (§2.4) и не сохранить отрицательный результат (§2.3): clear,
// inconclusive, flaky и unreachable не значат «изучили и записали», они
// значат «мерить больше нечем» — задача закрывается БЕЗ записи, причина
// уходит в журнал словами Result.Reason (он уже человеческий, см.
// classify.go).
func (c *Controller) onClassify(d classifyDone) error {
	t := c.tasks[d.target]
	if t == nil {
		return nil
	}
	t.classifying = false
	res := d.res

	switch res.Verdict {
	case classify.VerdictClear:
		// Триггер проходит как есть — обходить нечего. Это не отказ и не
		// решение, а честный «чинить нечего»: поиск закрывается без записи
		// (§2.3), как и любой другой случай, где сохранять нечего.
		c.sayf("по %s классификация: %s — поиск закрыт, обходить нечего",
			t.Target, res.Reason)
		c.cooldown[t.Target] = c.now().Add(cooldownAfterFail)
		if err := c.clear(t.Kind, t.Target); err != nil {
			return err
		}
		delete(c.tasks, t.Target)
		return nil

	case classify.VerdictPrefix, classify.VerdictWholePacket, classify.VerdictOpaque:
		// Оба «разрез работает» (Prefix/WholePacket) и «нужны вопросы о
		// свойствах» (Opaque) объявляются одной строкой: РАЗНИЦУ между ними
		// verdictCandidates уже читает из t.Classified.Verdict, а здесь
		// достаточно сказать человеку, что измерение закончилось и что оно
		// показало (Reason уже человеческий, см. classify.go).
		c.sayf("по %s классификация: %s", t.Target, res.Reason)

	default:
		// VerdictInconclusive, VerdictFlaky, VerdictUnreachable — и пустой
		// Verdict стенда, который эту цель ещё не сконфигурировал (реальный
		// classify.Run пустого вердикта не возвращает никогда: каждый путь
		// Run проставляет его явно). Пустой вердикт — не решение и не отказ,
		// это отсутствие сигнала: очередь идёт своим ходом, как будто
		// классификации не было вовсе.
		if res.Verdict == "" {
			if t.Current == nil && t.Asking.Name == "" {
				return c.step(t)
			}
			return nil
		}
		// А вот определённый отрицательный вердикт — решение о том, что
		// решения нет: не сохраняем ничего, поиск закрывается, причина —
		// словами измерения.
		c.sayf("по %s классификация не даёт вердикта (%s): %s — не сохранено ничего",
			t.Target, res.Verdict, res.Reason)
		c.cooldown[t.Target] = c.now().Add(cooldownAfterFail)
		if err := c.clear(t.Kind, t.Target); err != nil {
			return err
		}
		delete(c.tasks, t.Target)
		return nil
	}

	t.Classified = res
	// Ответ перебивает очередь — тем же образом, что и объём (onVolumeScan,
	// ScanFound): пока измеряли, лестница могла уйти по кандидату, ничего не
	// знающему о вердикте, и держать его в очереди незачем.
	t.Current = nil
	t.Queue = nil
	return c.advance(t)
}
