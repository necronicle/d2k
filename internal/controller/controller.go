// Package controller — связь наблюдения, обучения, проверки и активации.
//
// Живёт отдельным процессом от датапата (§7.1): падение планировщика не должно
// ронять разбор пакетов. Разговаривают через управляющий сокет.
//
// Что здесь происходит и чего не происходит:
//
//	происходит  подозрение → задача на цель → проверка готового плана
//	            узнанной коробки → и только при нехватке знания синтез;
//	НЕ происходит  сохранение отрицательного результата. Неудачный кандидат
//	            живёт в памяти задачи и исчезает вместе с ней (§2.3).
package controller

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/control"
)

// Пределы. §5.2 требует их на всё, и «столько, сколько придёт» пределом не
// является.
const (
	maxTasks     = 64  // одновременных поисков
	maxNames     = 512 // потоков, чьё имя цели мы помним
	taskLifetime = 10 * time.Minute
	// Сколько раз кандидат должен доехать до соединения, не дав обмена,
	// чтобы считаться неподошедшим.
	//
	// Одного раза мало: наблюдение «снят чужой сброс» говорит, что защита
	// сработала, но не говорит, дошло ли дело до обмена, — и по нему
	// кандидата отбрасывать нельзя. Без этого предела кандидат, который
	// исправно снимает подделку и не приводит к обмену, залипал бы до
	// истечения задачи, то есть на десять минут.
	//
	// Два, а не три: каждое применение без обмена — это ожидание у человека,
	// и порог здесь считается в его секундах, а не в наших попытках.
	maxSilentTries = 2
)

// Task — один согласованный поиск по одной цели.
//
// §4.1: для каждой цели одна задача, параллельные открытия браузера
// присоединяются к ней. Десяток вкладок не должен порождать десяток поисков.
type Task struct {
	Target      string
	Kind        string // "name" | "addr"
	Started     time.Time
	Fingerprint catalog.Fingerprint

	Queue   []Candidate
	Current *Candidate
	// Сколько потоков реально получили текущего кандидата. Подозрение,
	// пришедшее ДО применения, ничего о кандидате не говорит.
	AppliedCount int
	Attempts     int
	// Уже пробованные в этом поиске. Только в памяти и только на время
	// задачи: §2.3 запрещает персистить отказ, а повторять один и тот же
	// кандидат дважды подряд бессмысленно.
	tried map[string]bool
}

// Controller связывает датапат и каталог.
type Controller struct {
	conn  *control.Conn
	store *catalog.Store
	out   io.Writer
	now   func() time.Time
	decoy string

	tasks map[string]*Task
	// Ключ потока → цель. Подозрение и обмен несут только ключ, имя приходит
	// раньше отдельным событием.
	names    map[control.Key]string
	nameSeq  []control.Key // порядок появления, для вытеснения старых
	dropped  int
	Applied  int // сколько раз кандидат доехал до соединения
	Confirms int
}

// New создаёт контроллер.
func New(conn *control.Conn, store *catalog.Store, out io.Writer) *Controller {
	return &Controller{
		conn:  conn,
		store: store,
		out:   out,
		now:   time.Now,
		decoy: DecoySNI,
		tasks: map[string]*Task{},
		names: map[control.Key]string{},
	}
}

// SetClock нужен тестам: время в решениях не должно зависеть от настенных
// часов машины, где идёт проверка.
func (c *Controller) SetClock(f func() time.Time) { c.now = f }

// SetDecoy меняет имя приманки. Имя, работающее на одной линии, не обязано
// работать на другой — это часть поиска, а не константа.
func (c *Controller) SetDecoy(s string) { c.decoy = s }

func (c *Controller) sayf(format string, a ...any) {
	if c.out != nil {
		fmt.Fprintf(c.out, format+"\n", a...)
	}
}

// Sync ставит датапату планы всех подтверждённых привязок.
//
// Зовётся при запуске и после каждого подтверждения: датапат состояния между
// запусками не хранит, знание живёт в каталоге.
func (c *Controller) Sync() error {
	cat := c.store.Catalog()
	n := 0
	for i := range cat.Boxes {
		box := &cat.Boxes[i]
		for _, bd := range box.Bindings {
			if !bd.Enabled {
				continue
			}
			p := box.PlanByID(bd.PlanID)
			if p == nil || !p.Enabled {
				continue
			}
			tlv, err := p.Compile()
			if err != nil {
				// Битую запись нашли при загрузке; сюда она дойти не должна.
				// Если дошла — молчать нельзя.
				c.sayf("каталог: план %s коробки %s не собирается: %v",
					p.ID, box.ID, err)
				continue
			}
			if err := c.push(bd.Kind, bd.Target, tlv); err != nil {
				return err
			}
			n++
		}
	}
	if n > 0 {
		c.sayf("каталог: поставлено планов по подтверждённым привязкам: %d", n)
	}
	return nil
}

func (c *Controller) push(kind, target string, tlv []byte) error {
	switch kind {
	case "name":
		return c.conn.SetPlanName(target, tlv)
	case "addr":
		var ip [4]byte
		if err := parseIP4(target, &ip); err != nil {
			return err
		}
		return c.conn.SetPlanAddr(ip, tlv)
	}
	return fmt.Errorf("привязка вида %q не ставится", kind)
}

func parseIP4(s string, out *[4]byte) error {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return fmt.Errorf("адрес %q не IPv4", s)
	}
	for i, p := range parts {
		v := 0
		if p == "" || len(p) > 3 {
			return fmt.Errorf("адрес %q не IPv4", s)
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return fmt.Errorf("адрес %q не IPv4", s)
			}
			v = v*10 + int(ch-'0')
		}
		if v > 255 {
			return fmt.Errorf("адрес %q не IPv4", s)
		}
		out[i] = byte(v)
	}
	return nil
}

// Run читает события, пока датапат не закроется.
func (c *Controller) Run() error {
	for {
		ev, err := c.conn.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := c.Handle(ev); err != nil {
			return err
		}
	}
}

// Handle обрабатывает одно событие. Вынесено наружу ради проверок.
func (c *Controller) Handle(ev control.Event) error {
	now := c.now()
	c.expire(now)

	switch ev.Type {
	case control.EvHello:
		c.remember(ev.Key, ev.Name)

	case control.EvApplied:
		if t := c.taskForKey(ev.Key); t != nil && t.Current != nil {
			t.AppliedCount++
			c.Applied++
		}

	case control.EvSuspect:
		return c.onSuspect(ev, now)

	case control.EvExchange:
		return c.onExchange(ev, now)
	}
	return nil
}

// target возвращает цель потока: имя, если оно было, иначе адрес высокого
// конца пары. §5.3: отсутствие имени — нормальное состояние модели, и цель
// без имени обязана обслуживаться, а не пропускаться.
func (c *Controller) target(k control.Key) (string, string) {
	if n, ok := c.names[k]; ok && n != "" {
		return "name", n
	}
	// Сервер — тот конец, у которого порт 443. Если ни у кого, берём высокий:
	// выдумывать тут нечего, а ключ канонизирован.
	if k.LowPort == 443 {
		return "addr", fmt.Sprintf("%d.%d.%d.%d", k.LowIP[0], k.LowIP[1], k.LowIP[2], k.LowIP[3])
	}
	return "addr", fmt.Sprintf("%d.%d.%d.%d", k.HighIP[0], k.HighIP[1], k.HighIP[2], k.HighIP[3])
}

func (c *Controller) remember(k control.Key, name string) {
	if name == "" {
		return
	}
	if _, ok := c.names[k]; !ok {
		if len(c.nameSeq) >= maxNames {
			delete(c.names, c.nameSeq[0])
			c.nameSeq = c.nameSeq[1:]
		}
		c.nameSeq = append(c.nameSeq, k)
	}
	c.names[k] = name
}

func (c *Controller) taskForKey(k control.Key) *Task {
	_, target := c.target(k)
	return c.tasks[target]
}

func (c *Controller) expire(now time.Time) {
	for k, t := range c.tasks {
		if now.Sub(t.Started) > taskLifetime {
			// Задача закрылась ничем. Ничего не сохраняется: §2.3.
			c.sayf("поиск по %s закрыт по времени, попыток %d — не сохранено ничего",
				t.Target, t.Attempts)
			delete(c.tasks, k)
		}
	}
}

// failsCandidate — говорит ли наблюдение о том, что текущий кандидат НЕ
// помог.
//
// «Снят чужой сброс» не говорит: это защита сработала, то есть план делает
// ровно то, ради чего поставлен. Первый полевой прогон споткнулся именно
// здесь — контроллер записал «кандидат не помог» в ту же секунду, когда
// датапат писал «обмен пошёл», и отбросил сработавший план.
//
// Успехом это наблюдение тоже не является: подделку сняли, а дошло ли дело до
// обмена — отдельный вопрос. Правильный ответ — не считать его ни тем, ни
// другим и ждать либо обмена, либо другого подозрения.
func failsCandidate(code uint8) bool {
	switch code {
	case control.SuspectRSTCut:
		return false
	default:
		return true
	}
}

func signalOf(ev control.Event) catalog.Signal {
	s := catalog.Signal{Seen: 1}
	switch ev.Code {
	case control.SuspectRST, control.SuspectRSTCut:
		// Один и тот же вид: подделанный сброс. Различие между ними — наша
		// РЕАКЦИЯ (сняли или пропустили), а отпечаток описывает поведение
		// КОРОБКИ. Разведи их — и одна коробка попала бы в базу дважды, что
		// и случилось на первом прогоне с этой проверкой.
		s.Kind = "rst"
	case control.SuspectRepeat:
		s.Kind = "repeat"
	case control.SuspectSilent:
		s.Kind = "silent"
	default:
		s.Kind = fmt.Sprintf("код-%d", ev.Code)
	}
	if s.Kind == "rst" || s.Kind == "rst_cut" {
		// Разность, а не абсолютный TTL: ориентир взят из того же потока,
		// поэтому разность переносима, а абсолютное значение нет.
		s.TTLDelta = int(ev.TTL) - int(ev.RefTTL)
		s.ToS = ev.ToS
		s.IPID = ev.IPID
	}
	return s
}

func (c *Controller) onSuspect(ev control.Event, now time.Time) error {
	kind, target := c.target(ev.Key)
	sig := signalOf(ev)

	t := c.tasks[target]
	if t == nil {
		if ev.Code == control.SuspectRSTCut {
			// Снятый сброс бывает только там, где план УЖЕ стоит: снимает его
			// защита из плана. Начинать по нему поиск значит искать решение
			// для цели, у которой решение уже работает.
			return nil
		}
		if len(c.tasks) >= maxTasks {
			// Отказ, а не безграничный рост. §5.2.
			c.dropped++
			return nil
		}
		t = &Task{
			Target:  target,
			Kind:    kind,
			Started: now,
			Fingerprint: catalog.Fingerprint{
				Method: catalog.FingerprintMethod,
			},
			tried: map[string]bool{},
		}
		c.tasks[target] = t
		c.sayf("подозрение по %s (%s): начат поиск", target, control.SuspectText(ev.Code))
	} else if t.Current != nil && t.AppliedCount >= maxSilentTries {
		c.sayf("по %s кандидат %s применён %d раз без обмена, беру следующий",
			target, t.Current.Plan.ID, t.AppliedCount)
		t.Current = nil
		t.AppliedCount = 0
	} else if t.Current != nil && t.AppliedCount > 0 && failsCandidate(ev.Code) {
		// Кандидат доехал до соединения и не помог. Это НЕ доказательство
		// свойств коробки (§2.4) и никуда не записывается — просто следующий.
		c.sayf("по %s кандидат %s не помог (%s), беру следующий",
			target, t.Current.Plan.ID, control.SuspectText(ev.Code))
		t.Current = nil
		t.AppliedCount = 0
	} else if t.Current != nil {
		// Подозрение пришло раньше, чем кандидат доехал хоть до одного
		// соединения: о кандидате оно не говорит ничего.
		return nil
	}

	t.Fingerprint = addSignal(t.Fingerprint, sig)
	if t.Current != nil {
		return nil
	}
	return c.advance(t)
}

func addSignal(fp catalog.Fingerprint, s catalog.Signal) catalog.Fingerprint {
	for i := range fp.Signals {
		x := &fp.Signals[i]
		if x.Kind == s.Kind && x.TTLDelta == s.TTLDelta && x.IPID == s.IPID && x.ToS == s.ToS {
			x.Seen += s.Seen
			return fp
		}
	}
	fp.Signals = append(fp.Signals, s)
	return fp
}

// advance выбирает следующего кандидата и ставит его датапату.
func (c *Controller) advance(t *Task) error {
	if len(t.Queue) == 0 {
		q, err := c.buildQueue(t)
		if err != nil {
			return err
		}
		t.Queue = q
	}
	for len(t.Queue) > 0 {
		cand := t.Queue[0]
		t.Queue = t.Queue[1:]
		if t.tried[cand.Plan.ID] {
			continue
		}
		t.tried[cand.Plan.ID] = true

		tlv, err := cand.Plan.Compile()
		if err != nil {
			c.sayf("кандидат %s не собирается: %v", cand.Plan.ID, err)
			continue
		}
		if err := c.push(t.Kind, t.Target, tlv); err != nil {
			return err
		}
		t.Current = &cand
		t.AppliedCount = 0
		t.Attempts++
		c.sayf("по %s пробую %s (%s), попытка %d",
			t.Target, cand.Plan.ID, cand.Source, t.Attempts)
		return nil
	}

	// Кандидаты кончились. Ничего не сохраняется и ничего не остаётся: §2.3.
	// Снимаем поставленный план, чтобы цель вернулась к прямому проходу.
	c.sayf("по %s решения не нашлось, попыток %d — не сохранено ничего",
		t.Target, t.Attempts)
	if err := c.clear(t.Kind, t.Target); err != nil {
		return err
	}
	delete(c.tasks, t.Target)
	return nil
}

func (c *Controller) clear(kind, target string) error {
	switch kind {
	case "name":
		return c.conn.DelPlanName(target)
	case "addr":
		var ip [4]byte
		if err := parseIP4(target, &ip); err != nil {
			return err
		}
		return c.conn.DelPlanAddr(ip)
	}
	return nil
}

// buildQueue собирает очередь проверки в порядке §3.4:
// сперва готовые планы узнанных коробок, и только потом синтез.
func (c *Controller) buildQueue(t *Task) ([]Candidate, error) {
	var out []Candidate
	cat := c.store.Catalog()

	for _, box := range cat.Candidates(t.Fingerprint) {
		plans := append([]catalog.Plan(nil), box.Plans...)
		// Порядок опирается на подтверждённые успехи (§3.4).
		sort.SliceStable(plans, func(i, j int) bool {
			return plans[i].Successes > plans[j].Successes
		})
		for _, p := range plans {
			if !p.Enabled {
				continue
			}
			out = append(out, Candidate{
				Source: "коробка " + box.ID,
				BoxID:  box.ID,
				Plan:   p,
			})
		}
	}
	known := len(out)

	gen, err := generate(t.Fingerprint, c.decoy)
	if err != nil {
		return nil, err
	}
	out = append(out, gen...)

	if known > 0 {
		c.sayf("по %s: готовых планов узнанных коробок %d, затем синтез %d",
			t.Target, known, len(gen))
	}
	return out, nil
}

func (c *Controller) onExchange(ev control.Event, now time.Time) error {
	kind, target := c.target(ev.Key)
	t := c.tasks[target]
	if t == nil || t.Current == nil || t.AppliedCount == 0 {
		// Поиска нет. Но если по этой цели уже есть подтверждённая привязка,
		// а обмен дошёл до прикладных данных, — уровень доказательства обязан
		// подняться. Уровень 2 записывается тогда, когда больше ничего не
		// видно; оставить его навсегда значит хранить заниженное знание.
		if ev.HasAppData() {
			c.raiseLevel(kind, target, now)
		}
		// В остальном это обычный трафик, и он ничего не подтверждает.
		return nil
	}

	// §4.2: уровень 2 нельзя ПОКАЗЫВАТЬ ИЛИ СОХРАНЯТЬ как уровень 4. Здесь он
	// и сохраняется как 2 — ровно тот, что измерен.
	//
	// Не подтверждать вовсе до появления прикладных данных нельзя: без
	// снятия аппаратной разгрузки обратного направления их почти не видно, а
	// снятие стоит 66 % ядра (замер этапа 0, решение 0003). Первый полевой
	// прогон на этом и встал: обмен шёл, а записать было нечего.
	//
	// Уровень поднимется сам, когда прикладные данные всё-таки попадут в
	// окно: датапат сообщает об их появлении отдельно, а Confirm повышает
	// уровень привязки и не понижает.
	level := catalog.LevelProtocol
	if ev.HasAppData() {
		level = catalog.LevelHandshake
	}

	box, created, err := c.store.Catalog().Confirm(
		t.Fingerprint, t.Current.Plan, t.Kind, t.Target, level, now)
	if err != nil {
		c.sayf("по %s обмен пошёл, но записать нечего: %v", t.Target, err)
		return nil
	}
	c.store.Touch()
	c.Confirms++

	what := "коробка " + box.ID
	if created {
		what = "заведена коробка " + box.ID
	} else if t.Current.BoxID != "" {
		what = "повторное использование плана коробки " + box.ID
	}
	c.sayf("по %s обмен пошёл (%d байт, уровень %d): %s, план %s",
		t.Target, ev.Bytes, level, what, t.Current.Plan.ID)

	delete(c.tasks, t.Target)
	if _, err := c.store.Flush(now); err != nil {
		c.sayf("каталог не записался: %v", err)
	}
	return nil
}

// raiseLevel поднимает уровень доказательства подтверждённой привязки, когда
// в обмене появились прикладные данные. Понизить уровень отсюда нельзя: он
// отражает лучшее, что было измерено.
func (c *Controller) raiseLevel(kind, target string, now time.Time) {
	cat := c.store.Catalog()
	for i := range cat.Boxes {
		bd := cat.Boxes[i].BindingFor(kind, target)
		if bd == nil || !bd.Enabled || bd.Level >= catalog.LevelHandshake {
			continue
		}
		bd.Level = catalog.LevelHandshake
		bd.Confirmed = now
		c.store.Touch()
		c.sayf("по %s уровень доказательства поднят до %d: пошли прикладные данные",
			target, bd.Level)
		if _, err := c.store.Flush(now); err != nil {
			c.sayf("каталог не записался: %v", err)
		}
		return
	}
}

// Tasks — живое состояние поисков. §8 вид «Сейчас в работе»: это состояние
// процесса, а не история. Закрытый неудачей поиск исчезает.
func (c *Controller) Tasks() []*Task {
	out := make([]*Task, 0, len(c.tasks))
	for _, t := range c.tasks {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// Dropped — сколько подозрений не породили задачу из-за предела. Считать
// обязательно: «поисков нет» и «поиски не заводятся» — разные состояния.
func (c *Controller) Dropped() int { return c.dropped }
