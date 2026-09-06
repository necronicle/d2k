// Слой вопросов о свойствах коробки-«отравителя» буфера пересборки.
//
// Вердикт VerdictOpaque говорит: разрез бесполезен, решение принимается по
// содержимому, а поток при этом пересобирается — иначе разрез бы сработал.
// Разрез такую коробку не берёт; берёт её отравление буфера пересборки. Пять
// вопросов ниже — про то, ЧЕМ именно можно это отравление вызвать:
// перекрытием слева, порядком сегментов, контрольной суммой, разбором
// протокола, счётом дубликатов.
//
// Каждый вопрос двойного назначения: план, которым спрашиваем, и есть план,
// которым обходим, если вопрос пройдёт. Второй реализации нет и не будет
// (§2.5) — измеренное не может разойтись с исполняемым, потому что это один
// и тот же байтовый план.
package classify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/plan"
)

// Properties — вектор ответов на пять вопросов, а не диагноз устройства
// (§6.2 п.10): первый прошедший вопрос не восстанавливает модель коробки
// целиком, он отвечает ровно на СВОЙ вопрос и ни на какой другой. nil значит
// «не спрашивали или спросили безрезультатно» — не «нет» (§2.4: наблюдение
// не превращается в диагноз, отсутствие ответа не превращается в ответ).
type Properties struct {
	// ToleratesLeftOverlap — держит ли коробка сегмент, начинающийся левее
	// настоящих данных. false записывается ТОЛЬКО по проходу вопроса
	// «перекрытие слева»: коробка приняла отравленный перекрытием поток.
	ToleratesLeftOverlap *bool
	// ToleratesReorder — держит ли коробка сегменты не по порядку прихода.
	ToleratesReorder *bool
	// ValidatesChecksum — сверяет ли коробка контрольную сумму TCP.
	ValidatesChecksum *bool
	// ParsesL7 — разбирает ли коробка TLS (а не просто смотрит на байты).
	ParsesL7 *bool
	// CountsDuplicates — считает ли коробка разнесённые во времени копии
	// как одно и то же, или временное окно счётчика у неё уже.
	CountsDuplicates *bool
}

// PropProbe — один вопрос двойного назначения.
//
// Plan строит план, которым задаётся вопрос; тот же план, если пройдёт,
// является уже готовой стратегией обхода — второго плана для той же цели
// нет. Set читает исход ОДНОГО прохода этого плана и обязан игнорировать
// промах (§6.2 п.2): каждая реализация Set начинается с `if !passed {
// return }`, потому что промах объясняется разбором L7, шумом линии и чем
// угодно ещё, а не только измеряемым свойством.
type PropProbe struct {
	Name string
	Plan func(decoy string) (catalog.Plan, error)
	Set  func(*Properties, bool)
}

// PropProbes строит пять вопросов о свойствах коробки.
//
// Порядок задан замером (task-4-plans.md, «Порядок вопросов»), а не вкусом.
// Неудачный вопрос ждёт весь таймаут, удачный отвечает сразу и обрывает
// перебор — поэтому первым стоит перекрытие слева, единственный из пяти
// приём, что уже брал живые коробки (тот же multisplit:pos=1:seqovl=1,
// которым z2k обходит instagram на этой линии; замер 06.09.2026 на
// 57.144.248.34 показал, что разрез там не помогает вовсе, а коробка
// пересобирает поток). Дальше — разнесённые дубликаты, порядок, сумма,
// разбор протокола.
func PropProbes() []PropProbe {
	return []PropProbe{
		{
			Name: "перекрытие слева",
			Plan: overlapPlan,
			Set: func(pr *Properties, passed bool) {
				if !passed {
					return
				}
				no := false
				pr.ToleratesLeftOverlap = &no
			},
		},
		{
			Name: "счёт дубликатов",
			Plan: duplicatesPlan,
			Set: func(pr *Properties, passed bool) {
				if !passed {
					return
				}
				yes := true
				pr.CountsDuplicates = &yes
			},
		},
		{
			Name: "порядок сегментов",
			Plan: reorderPlan,
			Set: func(pr *Properties, passed bool) {
				if !passed {
					return
				}
				no := false
				pr.ToleratesReorder = &no
			},
		},
		{
			Name: "контрольная сумма",
			Plan: checksumPlan,
			Set: func(pr *Properties, passed bool) {
				if !passed {
					return
				}
				no := false
				pr.ValidatesChecksum = &no
			},
		},
		{
			Name: "разбор протокола",
			Plan: parseProtocolPlan,
			Set: func(pr *Properties, passed bool) {
				if !passed {
					return
				}
				// Оба поля пишутся из ЭТОГО прохода и ничего не читают из
				// pr — не предусловие «сумму уже проверили», выведенное из
				// чужого промаха. Это и есть ловушка донора наоборот
				// (task-4-plans.md, «Разбор протокола»): у него отчёт
				// печатал «разбирает протокол: да» рядом с ложным «сумму
				// проверяет: да», выведенным из ПРОМАХА вопроса о сумме —
				// тавтология с перевёрнутым знаком. Здесь оба вывода стоят
				// на одном и том же факте: коробка разобрала приманку как
				// TLS (иначе не на чем было бы её опознать) И проглотила
				// сегмент с битой суммой (иначе приманка не дошла бы до
				// разбора вовсе).
				yesParses := true
				pr.ParsesL7 = &yesParses
				noChecksum := false
				pr.ValidatesChecksum = &noChecksum
			},
		},
	}
}

// Compose собирает кандидатов ИЗ ИЗМЕРЕННОГО, а не берёт из списка.
//
// Правило записи здесь одно: каждый признак попадает в сборку только если
// измерение его ПОДДЕРЖИВАЕТ. Неизмеренное свойство не превращается ни в
// «да», ни в «нет» (§2.4) — оно просто не участвует.
//
// Каждый добавленный кандидат — БУКВАЛЬНО тот же план, которым был задан
// соответствующий вопрос (см. PropProbes): раз вопрос прошёл, спрашивать
// заново нечего, стратегия уже на руках.
func Compose(pr Properties, decoy string) ([]catalog.Plan, error) {
	yes := func(b *bool) bool { return b != nil && *b }
	no := func(b *bool) bool { return b != nil && !*b }

	var out []catalog.Plan
	add := func(p catalog.Plan, err error) error {
		if err != nil {
			return err
		}
		out = append(out, p)
		return nil
	}

	// Порядок — из task-4-brief.md, Step 4: «сперва то, что прямо следует из
	// измеренного (перекрытие, порядок, серия)». Этот порядок СВОЙ, отличный
	// от порядка опроса в PropProbes — там он подчинён цене таймаута, а не
	// приоритету готового кандидата.
	if no(pr.ToleratesLeftOverlap) {
		if err := add(overlapPlan(decoy)); err != nil {
			return nil, err
		}
	}
	if no(pr.ToleratesReorder) {
		if err := add(reorderPlan(decoy)); err != nil {
			return nil, err
		}
	}
	if yes(pr.CountsDuplicates) {
		if err := add(duplicatesPlan(decoy)); err != nil {
			return nil, err
		}
	}
	// Сумма и разбор протокола продолжают тот же список: обе — про приманку
	// с битой суммой перед нагрузкой, и порядок вопросов в plans.md их
	// относительно друг друга и первой тройки не фиксирует.
	//
	// checksumPlan добавляется, только если ValidatesChecksum=false пришло
	// НЕ вместе с ParsesL7=true. Вопрос «разбор протокола» пишет оба поля из
	// ОДНОГО факта (см. PropProbes) — если он прошёл, мы знаем, что реально
	// сработал ИМЕННО parseProtocolPlan (приманка — целое приветствие), а не
	// checksumPlan (приманка — голая набивка). У Properties нет памяти о
	// происхождении значения, и когда оба поля стоят одновременно, откуда
	// взялось ValidatesChecksum=false — от собственного прохода вопроса
	// «контрольная сумма» или от побочного эффекта вопроса «разбор
	// протокола» — неотличимо. checksumPlan сам в этом случае мог никогда не
	// проходить, а по модели task-4-plans.md (п.3) на коробке, что
	// РАЗБИРАЕТ TLS, набивка заведомо не сработает: коробка проигнорирует
	// мусор и продолжит ждать настоящее приветствие. Предлагать его тогда —
	// тратить заход на план, который никогда сам не проходил, да ещё и
	// впереди уже подтверждённого parseProtocolPlan.
	if no(pr.ValidatesChecksum) && !yes(pr.ParsesL7) {
		if err := add(checksumPlan(decoy)); err != nil {
			return nil, err
		}
	}
	if yes(pr.ParsesL7) {
		if err := add(parseProtocolPlan(decoy)); err != nil {
			return nil, err
		}
	}

	if len(out) == 0 {
		// Вектор пуст: ни один вопрос ничего не подтвердил (или их ещё не
		// задавали). Собрать нечего, кроме одного честного кандидата «всё
		// сразу» — см. everythingPlan.
		if err := add(everythingPlan(decoy)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// overlapByte — приставка перекрытия слева. Один байт: сама приставка и есть
// приём, которым z2k обходит instagram на этой линии
// (multisplit:pos=1:seqovl=1) — не число длины, длина перекрытия равна длине
// приманки (plan.Seqovl).
var overlapByte = []byte{0x41}

// overlapPlan — вопрос 1 и, если пройдёт, готовая стратегия «перекрытие
// слева» (task-4-plans.md, п.1). decoy не используется: приём не про имя, а
// про склейку потока, и параметр здесь только ради общего вида PropProbe.Plan.
func overlapPlan(string) (catalog.Plan, error) {
	p := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 6, Proto: 1,
		Payloads: []plan.Payload{{ID: 1, Bytes: overlapByte}},
		Seqovls:  []plan.Seqovl{{PayloadID: 1}},
	}
	return build(p, "tls")
}

// reorderPlan — вопрос 3 (task-4-plans.md, п.2, «Порядок сегментов»): разрез
// посередине приветствия, куски уходят хвостом вперёд. decoy не используется
// по той же причине, что и в overlapPlan.
func reorderPlan(string) (catalog.Plan, error) {
	p := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 6, Proto: 1,
		Splits: []plan.Position{{Anchor: plan.AnchorHelloMiddle}},
		Order:  plan.OrderReverse,
	}
	return build(p, "tls")
}

// checksumFiller — 64 байта набивки для вопроса о контрольной сумме, не
// приветствие (task-4-plans.md, п.3: «набивка, а не приветствие — намеренно»)
// — коробка, которая РАЗБИРАЕТ TLS, мусор проигнорирует и продолжит ждать
// настоящее приветствие, и различие с вопросом о разборе протокола именно в
// этом, не косметическое. 64 байта повтора 0x41 — буквально пример из
// документа задачи.
var checksumFiller = bytes.Repeat([]byte{0x41}, 64)

// checksumPlan — вопрос 4 (task-4-plans.md, п.3, «Контрольная сумма»).
func checksumPlan(string) (catalog.Plan, error) {
	return badsumFakePlan(checksumFiller, 1, 0)
}

// parseProtocolPlan — вопрос 5 (task-4-plans.md, п.4, «Разбор протокола»):
// приманка та же форма, что и в checksumPlan, но приманка — целое
// правдоподобное приветствие с безобидным именем, а не набивка.
func parseProtocolPlan(decoy string) (catalog.Plan, error) {
	hello, err := plan.Hello(decoy, 0)
	if err != nil {
		return catalog.Plan{}, err
	}
	return badsumFakePlan(hello, 1, 0)
}

// duplicatesPlan — вопрос 2 (task-4-plans.md, п.5, «Счёт дубликатов»): две
// копии с паузой 20000мкс. Число и пауза наследованы из замера донора:
// боевое плечо обходится ДВУМЯ копиями с разрывом, а плотной очереди нужно
// семь (см. также комментарий у plan.Fake) — если у счётчика коробки есть
// временное окно, плотная очередь и разнесённая пара для него не одно и то
// же.
func duplicatesPlan(decoy string) (catalog.Plan, error) {
	hello, err := plan.Hello(decoy, 0)
	if err != nil {
		return catalog.Plan{}, err
	}
	return badsumFakePlan(hello, 2, 20000)
}

// badsumFakePlan — общая форма вопросов 2, 4 и 5: приманка с испорченной
// суммой перед нагрузкой, БЕЗ TTL. В controller.fakePlan TTL нужен боевому
// плечу как страховка (приманка обязана умереть по дороге, даже если сумма
// её не остановит) — а здесь вопрос именно про сумму и про разбор, и
// подмешивать вторую порчу значило бы спрашивать не то, что названо
// (task-4-plans.md приводит точные формы без ttl=).
func badsumFakePlan(payload []byte, repeats uint8, gapUS uint32) (catalog.Plan, error) {
	p := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 6, Proto: 1,
		Payloads: []plan.Payload{{ID: 1, Bytes: payload}},
		Poisons:  []plan.Poison{{ID: 1, Flags: plan.PoisonBadSum}},
		Fakes: []plan.Fake{{
			PayloadID: 1, PoisonID: 1,
			Repeats: repeats, GapUS: gapUS, Placement: plan.PlaceBefore,
		}},
	}
	return build(p, "tls")
}

// everythingPlan — единственный честный кандидат при пустом векторе свойств
// (Compose): ничего не измерено, и вместо угадывания ОДНОГО приёма здесь
// собраны все три приёма, у которых есть готовая форма без измерения, —
// перекрытие слева, разнесённая пара дублей и порядок сегментов — одним
// планом.
//
// До коммита 898ea00 порядок сегментов сюда намеренно не входил: переворот
// в datapath/plan_apply.c искал границу кусков сравнением v[i].bytes с
// in->payload — указателями из РАЗНЫХ выделений памяти (буфер плана и буфер
// пакета), а сравнение таких указателей оператором `<` не определено языком
// Си и «работало» только при удачной раскладке кучи; для связки «фальшивка
// ПЕРЕД нагрузкой + обратный порядок» это воспроизводимо ломало результат.
// 898ea00 переписал переворот на сравнение по полю kind
// (D2K_EMIT_PAYLOAD/D2K_EMIT_FAKE, определено всегда) и добавил в
// datapath/test_plan_apply.c четыре теста, которые покрывают ровно нужную
// здесь связку — фальшивку перед нагрузкой вместе с разрезом и обратным
// порядком, и отдельно перекрытие без разреза вместе с обратным порядком.
// Комбинация всех трёх сразу («seqovl + split + fake + reverse») проверена
// дополнительно вручную через planlab перед тем, как её здесь закрепить, и
// закреплена тестом на связку целиком
// (TestЛабораторияВсёСразуИсполняетТриПриёмаВместе, properties_test.go):
// фальшивки уходят первыми, не тронутые переворотом, затем хвост, затем
// голова с приставкой перекрытия и сдвинутым назад номером.
func everythingPlan(decoy string) (catalog.Plan, error) {
	hello, err := plan.Hello(decoy, 0)
	if err != nil {
		return catalog.Plan{}, err
	}
	p := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 6, Proto: 1,
		Payloads: []plan.Payload{
			{ID: 1, Bytes: hello},
			{ID: 2, Bytes: overlapByte},
		},
		Poisons: []plan.Poison{{ID: 1, Flags: plan.PoisonBadSum}},
		Fakes: []plan.Fake{{
			PayloadID: 1, PoisonID: 1,
			Repeats: 2, GapUS: 20000, Placement: plan.PlaceBefore,
		}},
		Seqovls: []plan.Seqovl{{PayloadID: 2}},
		Splits:  []plan.Position{{Anchor: plan.AnchorHelloMiddle}},
		Order:   plan.OrderReverse,
	}
	return build(p, "tls")
}

// planID делает имя плана из его текста. Копия controller.planID: тот же
// метод обязан давать то же имя одинаковому плану, а импортировать controller
// отсюда нельзя — это создало бы цикл, потому что задача 5 будет
// импортировать classify из controller (см. бриф задачи 4).
func planID(text string) string {
	h := sha256.Sum256([]byte(text))
	return "plan-" + hex.EncodeToString(h[:4])
}

// build — минимальный сборщик по образцу controller.wrap (см. бриф задачи
// 4): проверяет сборку плана в каноническую форму и заворачивает его в
// catalog.Plan. Кандидат, который не переводится в каноническую форму, не
// должен доехать до датапата и быть отвергнутым там — там уже идёт чужое
// соединение, и поздно (тот же довод записан в controller.wrap).
func build(p plan.Plan, proto string) (catalog.Plan, error) {
	if _, err := p.MarshalTLV(); err != nil {
		return catalog.Plan{}, fmt.Errorf("кандидат не собирается: %w", err)
	}
	text := p.Text()
	return catalog.Plan{ID: planID(text), Proto: proto, Text: text}, nil
}
