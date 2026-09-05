package classify

import (
	"context"
	"fmt"
	"net"
	"time"
)

// waitFloor, waitCeiling, waitRTTFactor — как сужать ожидание ответа между
// вопросами дерева, когда вызывающий не задал Wait явно.
//
// Числа не новые: floor=1с, ceiling=5с и множитель ×8 — это буквально
// datapath/session.c:silence_deadline (floor_ns, ceil_ns, `f->rtt_ns * 8`).
// Не путать с одним нюансом: там же для ПОТОКА, чей RTT никогда не измерялся
// (перехвачен на середине обмена), возвращается плоские 2с — не потолок. Это
// другой случай: тот код подхватывает чужой уже идущий обмен и никогда не
// видел его начала, а здесь КАЖДЫЙ вопрос сам инициирует Dial и RTT для него
// в принципе получить неоткуда лишь у первого вопроса всего прогона. Именно
// для этого одного вопроса выбор — ждать по потолку (ниже, в Run) — уже
// решение задачи, не позаимствованное из session.c.
const (
	waitFloor     = 1 * time.Second
	waitCeiling   = 5 * time.Second
	waitRTTFactor = 8
)

// clampWait зажимает d между waitFloor и waitCeiling.
func clampWait(d time.Duration) time.Duration {
	if d < waitFloor {
		return waitFloor
	}
	if d > waitCeiling {
		return waitCeiling
	}
	return d
}

// Options — как спрашивать.
type Options struct {
	// Repeats — сколько раз повторять КАЖДЫЙ вопрос дерева, кроме одного
	// особого случая. Умолчание — один: дороги именно НЕпрошедшие вопросы
	// (каждый несёт полное ожидание ответа), и утраивать их с самого начала —
	// сжечь весь бюджет на первых двух непройденных.
	//
	// Исключение — подтверждение перед clear (см. Run): там повторов ВСЕГДА
	// на clearConfirmRepeats больше, чем здесь, независимо от этого значения,
	// потому что ложный clear — худшая из ошибок дерева.
	Repeats int
	// Wait — сколько ждать ответа. Ноль (умолчание) — вывести из измеренного
	// RTT: первый вопрос всего прогона ждёт по waitCeiling (RTT ещё неоткуда
	// взять), каждый следующий — waitRTTFactor оборотов RTT, измеренного на
	// Dial предыдущего вопроса, в границах [waitFloor, waitCeiling]. RTT
	// живёт ПОПЕРЁК дерева (в Run), а не внутри одной серии повторов — при
	// умолчании Repeats=1 «следующая попытка той же серии» часто не
	// наступает вовсе, и сужение внутри одного measure() было бы мертвым
	// кодом. Заданное здесь явно значение это правило отменяет полностью и
	// держится неизменным на весь прогон.
	Wait time.Duration
	// Gap — пауза между кусками в обычных вопросах. Умолчание — ноль: на
	// настоящем пути два Write с TCP_NODELAY уходят двумя IP-пакетами и без
	// паузы, а слипание в один пакет — свойство петли в тестах (там нет ни
	// одного провода между Write и Read), а не свойство обхода. Платить
	// временем человека за артефакт стенда незачем — стенд лечится своей
	// собственной паузой (loopbackGap в measure_test.go), боевой путь трогать
	// не нужно.
	Gap time.Duration
	// LongGap — пауза для вопроса о буфере пересборки. Должна быть заведомо
	// больше Gap, иначе вопрос «есть ли буфер» неотличим от вопроса «где
	// разрез». Значение по умолчанию — из брифа задачи; отдельно не
	// переизмерялось, но это больше не стоит на пути по умолчанию (см.
	// Diagnose) — обоснуется, когда данные Reassembles кто-то станет
	// потреблять.
	LongGap time.Duration
	// Control — другое имя на ту же цель.
	Control Trigger
	// Diagnose — искать ли границу сигнатуры и спрашивать про буфер
	// пересборки. По умолчанию НЕТ: для обхода ни то ни другое не нужно
	// (разрез на 1 годится при любой границе правее, и рекомендация не
	// меняется от того, есть у коробки буфер или нет) — а двоичный поиск
	// границы это ещё ~log2(длина) вопросов подряд, каждый непрошедший из
	// которых стоит целого ожидания. «Бюджет времени» плана: это единственная
	// ветка дерева, которая одна способна съесть весь бюджет, поэтому она
	// диагностика под флагом, а не всегда исполняемый шаг.
	Diagnose bool
}

// clearConfirmRepeats — сколько ДОПОЛНИТЕЛЬНЫХ повторов задать базовому
// вопросу, прежде чем выносить clear, независимо от Options.Repeats.
//
// Ложный clear — худшая из ошибок дерева: человек остаётся заблокирован, а
// инструмент говорит, что всё в порядке. Это единственное место, где цена
// лишних повторов оправдана, — сама база уже прошла, и здесь дорог не
// НЕпрошедший вопрос, а недостаточно проверенный положительный.
const clearConfirmRepeats = 2

func (o *Options) withDefaults() {
	if o.Repeats <= 0 {
		o.Repeats = 1
	}
	// Wait <= 0 остаётся сигналом «вывести из RTT» (см. Run). Здесь
	// специально нет строки вида "o.Wait = 3*time.Second": фиксированный
	// потолок на любую линию и был тем, что решение 3 задачи заменяет.
	if o.LongGap <= 0 {
		o.LongGap = 600 * time.Millisecond
	}
}

// Result — что показал прогон.
type Result struct {
	Verdict Verdict
	Reason  string
	// Boundary — на каком байте кончается сигнатура. Ноль, если границу не
	// искали (Diagnose=false, до VerdictPrefix не дошли, или граница не
	// существует вовсе — VerdictWholePacket).
	Boundary int
	// SplitPos — где резать по итогам замера. Ноль, если разрез не помогает.
	SplitPos int
	// Reassembles — есть ли у коробки буфер пересборки. nil — не спрашивали
	// (Diagnose=false или до VerdictPrefix не дошли).
	Reassembles *bool
	Probes      int
	Trace       []Step
}

// stopOnErr — если у опыта t есть ошибка транспорта (не решение коробки, а
// отказ Dial), помечает res как flaky и говорит вызывающему остановиться.
//
// §2.4: наблюдение не превращается в диагноз. До этой правки причина
// проверялась только у базового вопроса (unreachable), а у остальных читался
// лишь pass — сетевой сбой или отмена контекста были неотличимы от «коробка
// не пропустила байты», и это портило не только вердикт, но и любое число,
// вычисленное после (Boundary, SplitPos). Молчаливый pass==0 при непустой
// ошибке отныне запрещён на каждом вопросе дерева, кроме самого первого —
// там своя, более точная причина (VerdictUnreachable, см. Run).
func (res *Result) stopOnErr(what string, t tally) bool {
	if t.err == nil {
		return false
	}
	res.Verdict = VerdictFlaky
	res.Reason = fmt.Sprintf("%s: ошибка опыта, а не решение коробки: %v", what, t.err)
	return true
}

// Run задаёт вопросы по порядку и выносит вердикт.
//
// Порядок несущий, и каждый шаг отсекает половину: база → помогает ли резать
// вообще → контроль → (по запросу) граница двоичным поиском. Каждый вопрос
// меняет ТОЛЬКО способ записи одного и того же триггера — из формы отклика
// читается структура матчера.
func Run(ctx context.Context, addr string, tr Trigger, opt Options) Result {
	opt.withDefaults()
	var res Result

	if h, p, err := net.SplitHostPort(addr); err != nil || h == "" || p == "" {
		res.Verdict = VerdictFlaky
		res.Reason = "адрес не разобран, ожидается host:port"
		return res
	}
	if len(tr.Payload) < 2 {
		res.Verdict = VerdictFlaky
		res.Reason = "триггер короче двух байт — резать нечего"
		return res
	}

	// knownRTT — RTT линии, уточняется от вопроса к вопросу; ноль — ещё не
	// измерен ни одним удавшимся Dial. Живёт на весь Run, а не на один
	// measure(): при Repeats=1 «следующая попытка ТОЙ ЖЕ серии» — редкость,
	// а вот «следующий ВОПРОС» есть почти всегда, и именно туда сужение
	// обязано долетать (см. Options.Wait).
	var knownRTT time.Duration

	ask := func(what string, trig Trigger, cuts []int, gap time.Duration, repeats int) tally {
		wait := opt.Wait
		if wait <= 0 { // автоматический режим — вызывающий Wait не задавал
			if knownRTT > 0 {
				wait = clampWait(knownRTT * waitRTTFactor)
			} else {
				wait = waitCeiling // самый первый вопрос прогона — RTT неоткуда взять
			}
		}
		t := measure(ctx, addr, trig, cuts, gap, repeats, wait)
		if opt.Wait <= 0 && t.rtt > 0 {
			knownRTT = t.rtt
		}
		res.Probes += repeats
		res.Trace = append(res.Trace, Step{What: what, Pass: t.pass, Fail: t.fail})
		return t
	}

	// 1. БАЗА. Триггер целиком. Проходит — блокировки по содержимому нет.
	base := ask("триггер целиком", tr, nil, opt.Gap, opt.Repeats)
	switch {
	case base.pass == 0 && base.err != nil:
		res.Verdict = VerdictUnreachable
		res.Reason = "нет TCP до цели: " + base.err.Error()
		return res
	case base.pass == opt.Repeats:
		// ПОДТВЕРЖДЕНИЕ. Единственное место дерева с усиленным числом
		// повторов — см. clearConfirmRepeats.
		confirm := ask("триггер целиком (подтверждение)", tr, nil, opt.Gap, clearConfirmRepeats)
		if res.stopOnErr("триггер целиком (подтверждение)", confirm) {
			return res
		}
		totalPass := base.pass + confirm.pass
		totalRepeats := opt.Repeats + clearConfirmRepeats
		if totalPass != totalRepeats {
			res.Verdict = VerdictFlaky
			res.Reason = fmt.Sprintf("база не подтвердилась: итого %d из %d — ложный clear дороже честного flaky", totalPass, totalRepeats)
			return res
		}
		res.Verdict = VerdictClear
		res.Reason = fmt.Sprintf("триггер проходит как есть — обходить нечего (%d/%d подряд)", totalPass, totalRepeats)
		return res
	case base.pass > 0:
		res.Verdict = VerdictFlaky
		res.Reason = fmt.Sprintf("база не воспроизводится: %d из %d", base.pass, opt.Repeats)
		return res
	}

	// 2. ПОМОГАЕТ ЛИ РЕЗАТЬ ВООБЩЕ. Разрез после первого байта — самый
	// агрессивный: в первом сегменте остаётся один байт. Не прошёл он — не
	// пройдёт ни один правее, и границу искать незачем.
	one := ask("разрез на 1", tr, []int{1}, opt.Gap, opt.Repeats)
	if res.stopOnErr("разрез на 1", one) {
		return res
	}
	if one.pass == 0 {
		// 2а. КОНТРОЛЬ. Прежде чем говорить «пересборка», исключаем, что
		// содержимое вообще ни при чём (§2.3: d2k не утверждает блокировку по
		// адресу — соответствующий случай называется inconclusive).
		ctlPass := 0
		if len(opt.Control.Payload) > 0 {
			c := ask("контроль другим именем", opt.Control, nil, opt.Gap, opt.Repeats)
			if res.stopOnErr("контроль другим именем", c) {
				return res
			}
			ctlPass = c.pass
		}
		if ctlPass == 0 {
			res.Verdict = VerdictInconclusive
			res.Reason = "молчит и контроль на другом имени: отличить «режут наши байты» от «молчит всё» нечем"
			return res
		}
		res.Verdict = VerdictOpaque
		res.Reason = "разрез не помогает, контроль проходит — решение по содержимому, поток пересобирается"
		return res
	}
	if one.pass != opt.Repeats {
		res.Verdict = VerdictFlaky
		res.Reason = fmt.Sprintf("разрез на 1 не воспроизводится: %d из %d", one.pass, opt.Repeats)
		return res
	}

	// Разрез на 1 прошёл — стратегия уже известна: split на 1 годится при
	// любой границе сигнатуры правее и независимо от буфера пересборки.
	// Вердикт и разрез выносятся ЗДЕСЬ, до диагностики — «Бюджет времени»
	// плана прямо требует, чтобы дальнейшие шаги не были на пути по
	// умолчанию (см. Options.Diagnose).
	res.Verdict = VerdictPrefix
	res.SplitPos = 1
	res.Reason = "разрез на 1 проходит — матчер читает начало и пересборкой его не спасает"
	if !opt.Diagnose {
		return res
	}

	// 3. ЕСТЬ ЛИ БУФЕР ПЕРЕСБОРКИ (диагностика, по запросу). Тот же разрез,
	// но с паузой. Коробка без буфера ведёт себя так же; коробка с буфером
	// успевает склеить и снова опознать сигнатуру.
	long := ask("разрез на 1 с паузой", tr, []int{1}, opt.LongGap, opt.Repeats)
	if res.stopOnErr("разрез на 1 с паузой", long) {
		return res
	}
	reass := long.pass == 0
	res.Reassembles = &reass
	if reass {
		res.Reason += "; при паузе " + opt.LongGap.String() + " блок возвращается — у коробки есть буфер пересборки"
	}

	// 4. ГРАНИЦА СИГНАТУРЫ двоичным поиском (диагностика, по запросу).
	// Разрез у самого конца — если проходит даже он, границы нет вообще:
	// матчеру нужен пакет целиком.
	last := ask("разрез у самого конца", tr, []int{len(tr.Payload) - 1}, opt.Gap, opt.Repeats)
	if res.stopOnErr("разрез у самого конца", last) {
		return res
	}
	if last.pass == opt.Repeats {
		res.Verdict = VerdictWholePacket
		res.Reason = "проходит любой разрез — матчер требует пакет целиком"
		res.SplitPos = 1
		return res
	}
	lo, hi := 1, len(tr.Payload)-1
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		what := fmt.Sprintf("разрез на %d", mid)
		m := ask(what, tr, []int{mid}, opt.Gap, opt.Repeats)
		if res.stopOnErr(what, m) {
			return res
		}
		switch {
		case m.pass == opt.Repeats:
			lo = mid
		case m.pass == 0:
			hi = mid
		default:
			res.Verdict = VerdictFlaky
			res.Reason = fmt.Sprintf("разрез на %d не воспроизводится: %d из %d", mid, m.pass, opt.Repeats)
			return res
		}
	}
	res.Boundary = hi
	res.Reason = fmt.Sprintf("префиксный матчер: сигнатура кончается на байте %d, разрез левее её ломает", hi)
	return res
}
