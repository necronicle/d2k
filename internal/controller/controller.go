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
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/conntrack"
	"github.com/necronicle/d2k/internal/control"
	"github.com/necronicle/d2k/internal/plan"
	"github.com/necronicle/d2k/internal/probe"
)

// Пределы. §5.2 требует их на всё, и «столько, сколько придёт» пределом не
// является.
const (
	maxTasks     = 64  // одновременных поисков
	maxNames     = 512 // потоков, чьё имя цели мы помним
	taskLifetime = 10 * time.Minute
	// Сколько цель отдыхает после безуспешного поиска. Только в памяти и
	// только на этот срок (§2.3): вчерашний отказ завтра не значит ничего, а
	// десять вкладок, стучащихся в мёртвый хост, не должны запускать десять
	// поисков подряд.
	cooldownAfterFail = 2 * time.Minute
	// Сколько зондов позволено одной цели за поиск. §5: у измерений есть
	// бюджет, и «сколько получится» бюджетом не является.
	maxProbesPerTask = 8
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

	// Адрес цели: по нему стучится зонд. Берётся из ключа потока — той
	// стороны, у которой порт 443.
	ServerIP   string
	ServerPort int

	// Форма приветствия, которую шлёт клиент. Зонд обязан повторять её, а не
	// слать своё: коробка может по-разному относиться к приветствию браузера
	// и к приветствию нашей библиотеки (§3.1, §5.5).
	Shape []byte
	// Что известно о разборе у коробки. Из этого выводится план — а не
	// берётся готовым из чужого набора.
	Traits Traits
	// Заданный сейчас вопрос. Пустое имя означает, что в полёте не вопрос, а
	// проверка кандидата.
	Asking Question
	// Порт зонда в полёте: по нему наблюдения датапата привязываются к
	// НАШЕМУ соединению, а не к чужому.
	probePort uint16
	// Датапат отметил подделанный сброс по зонду. Это и отличает вмешательство
	// коробки от закрытия сервером: у подделки чужой TTL.
	probeForgedRST bool

	// Зонд в полёте либо вот-вот уйдёт (ждём подтверждения команды).
	//
	// Пока он не ответил, подозрения клиента НИЧЕГО не решают: человек может
	// судорожно обновлять страницу, и каждое обновление — это подозрение.
	// Позволь им двигать кандидата — и лестница сгорит за пять нажатий F5,
	// не проверив толком ни одного.
	probing  bool
	awaiting bool
	// scanning — идёт подбор имени по объёму. Он долгий, и второй такой же
	// поверх первого только удвоил бы нагрузку на линию.
	scanning bool
	// Сколько раз зондировали. §10 требует считать стоимость зондов на цель.
	Probes int
	// Объём, на котором потоки к этой цели кончаются раз за разом. Ноль —
	// не наблюдали.
	VolumeCutAt int64
}

// Prober — то, чем контроллер стучится в цель. Интерфейс, а не структура,
// чтобы проверки не ходили в сеть.
type Prober interface {
	Do(ctx context.Context, addr string, port int, hello []byte) probe.Result
}

type probeDone struct {
	target string
	res    probe.Result
}

// Controller связывает датапат и каталог.
type Controller struct {
	conn   *control.Conn
	store  *catalog.Store
	out    io.Writer
	now    func() time.Time
	decoy  string
	prober Prober

	// Подтверждения приходят без имени цели: датапат отвечает в том порядке,
	// в каком получил, поэтому очередь ожидающих — обычная FIFO.
	pendingAcks []string
	results     chan probeDone

	// Подбор имени по объёму: своя проба, свой канал ответов.
	volProber  VolumeProber
	volResults chan volumeScanDone
	volVerify  chan volumeVerifyDone
	// nameHits — сколько раз имя уже проводило объём на этой линии. Только в
	// памяти: это ускоритель порядка перебора, а не знание о цели.
	nameHits map[string]int

	// Наблюдение за объёмом: обрыв, который не виден в окне первых пакетов.
	volume   map[string]*volumeWatch
	ctPath   string
	ctWarned bool

	// Цели, по которым поиск недавно закончился ничем. Только в памяти и
	// только на короткий срок: §2.3 запрещает персистить отказ, но десять
	// вкладок, стучащихся в мёртвый хост, не должны запускать десять поисков
	// подряд. Документ это допущение прямо описывает.
	cooldown map[string]time.Time

	tasks map[string]*Task
	// Ключ потока → цель. Подозрение и обмен несут только ключ, имя приходит
	// раньше отдельным событием.
	names    map[control.Key]string
	nameSeq  []control.Key // порядок появления, для вытеснения старых
	dropped  int
	Applied  int // сколько раз кандидат доехал до соединения
	Confirms int

	// probesUsed — всего зондов за сеанс. §10 требует считать стоимость
	// зондов на новую цель.
	probesUsed int
}

// New создаёт контроллер.
func New(conn *control.Conn, store *catalog.Store, out io.Writer) *Controller {
	c := &Controller{
		conn:     conn,
		store:    store,
		out:      out,
		now:      time.Now,
		decoy:    DecoySNI,
		prober:   probe.New(),
		tasks:    map[string]*Task{},
		names:    map[control.Key]string{},
		results:  make(chan probeDone, 32),
		cooldown: map[string]time.Time{},
		volume:   map[string]*volumeWatch{},
		ctPath:   conntrack.DefaultPath,

		volProber:  liveVolumeProber{},
		volResults: make(chan volumeScanDone, 8),
		volVerify:  make(chan volumeVerifyDone, 8),
		nameHits:   map[string]int{},
	}
	c.seedNameHits()
	return c
}

// SetConntrackPath подменяет источник счётчиков ядра. Для проверок: они не
// должны зависеть от того, что творится в таблице этой машины.
func (c *Controller) SetConntrackPath(p string) { c.ctPath = p }

// SetProber подменяет способ стучаться в цель. Нужен проверкам: они не должны
// ходить в сеть.
func (c *Controller) SetProber(p Prober) { c.prober = p }

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

// Run читает события и разбирает результаты зондов, пока датапат не закроется.
//
// Два источника, а не один: зонд уходит в сеть и отвечает секундами позже, а
// цикл событий останавливать на это время нельзя — датапат за секунду
// присылает сотни наблюдений.
func (c *Controller) Run() error {
	events := make(chan control.Event, 64)
	fail := make(chan error, 1)
	go func() {
		for {
			ev, err := c.conn.Next()
			if err != nil {
				fail <- err
				return
			}
			events <- ev
		}
	}()

	// Счётчики ядра опрашиваются по часам, а не по событиям: обрыв по объёму
	// случается ПОСЛЕ того, как окно наблюдения датапата давно закрылось, и
	// никакого события про него не придёт.
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()

	for {
		select {
		case ev := <-events:
			if err := c.Handle(ev); err != nil {
				return err
			}
		case r := <-c.results:
			if err := c.onProbe(r); err != nil {
				return err
			}
		case r := <-c.volResults:
			if err := c.onVolumeScan(r); err != nil {
				return err
			}
		case r := <-c.volVerify:
			if err := c.onVolumeVerify(r); err != nil {
				return err
			}
		case <-tick.C:
			c.pollVolume(c.now())
		case err := <-fail:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// Pump разбирает готовые результаты зондов, не блокируя. Для проверок,
// которые зовут Handle напрямую.
func (c *Controller) Pump() error {
	c.pollVolume(c.now())
	for {
		select {
		case r := <-c.results:
			if err := c.onProbe(r); err != nil {
				return err
			}
		case r := <-c.volResults:
			if err := c.onVolumeScan(r); err != nil {
				return err
			}
		case r := <-c.volVerify:
			if err := c.onVolumeVerify(r); err != nil {
				return err
			}
		default:
			return nil
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
		if ev.Name != "" {
			// Под наблюдение по объёму ставим сразу: обрыв случится позже,
			// когда окно датапата уже закроется, и начинать смотреть в тот
			// момент будет поздно.
			ip, _ := serverOf(ev.Key)
			c.watchVolume(ev.Name, ip)
		}

	case control.EvAck:
		return c.onAck(ev, now)

	case control.EvShape:
		c.onShape(ev)

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
	// Отдыхающие цели чистятся здесь же: карта без чистки растёт без
	// предела, а §5.2 требует пределов на всё.
	for k, until := range c.cooldown {
		if now.After(until) {
			delete(c.cooldown, k)
		}
	}
	for k, t := range c.tasks {
		if t.scanning {
			// Незавершённое измерение нельзя выбрасывать по часам: ответ уже
			// оплачен временем человека.
			continue
		}
		if now.Sub(t.Started) > taskLifetime {
			// Задача закрылась ничем. Ничего не сохраняется: §2.3.
			c.sayf("поиск по %s закрыт по времени, попыток %d — не сохранено ничего",
				t.Target, t.Attempts)
			c.cooldown[t.Target] = now.Add(cooldownAfterFail)
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
	if s.Kind == "rst" {
		// TTL самой подделки — примета коробки: она стоит на фиксированном
		// расстоянии от нас. Разность с TTL сервера сохраняется как
		// наблюдение, но приметой не является: серверы стоят на разном
		// расстоянии, и на четырёх целях одной линии разности были 3, 38, 40
		// и 74 при одном и том же TTL подделки 127.
		s.TTL = ev.TTL
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
	if t != nil && t.probePort != 0 && keyHasPort(ev.Key, t.probePort) {
		// Это наблюдение по НАШЕМУ зонду. Подделанный сброс здесь — улика о
		// том, что коробка вмешалась; закрытие сервером такой приметы не
		// имеет. Различить их иначе нельзя: зонд видит сокет, а не заголовки.
		if ev.Code == control.SuspectRST || ev.Code == control.SuspectRSTCut {
			t.probeForgedRST = true
		}
		t.Fingerprint = addSignal(t.Fingerprint, sig)
		return nil
	}
	if t != nil && t.awaiting {
		// Кандидат проверяется нашим зондом. Подозрения клиента сейчас
		// ничего не решают: они только уточняют отпечаток. Именно здесь
		// судорожное обновление страницы перестаёт жечь лестницу кандидатов.
		t.Fingerprint = addSignal(t.Fingerprint, sig)
		return nil
	}
	if t == nil {
		if until, ok := c.cooldown[target]; ok && now.Before(until) {
			// Поиск по этой цели только что кончился ничем. Начинать заново
			// на каждое обновление страницы значит гонять одну и ту же
			// лестницу по кругу и мешать самим себе.
			return nil
		}
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
		ip, port := serverOf(ev.Key)
		t = &Task{
			Target:  target,
			Kind:    kind,
			Started: now,
			Fingerprint: catalog.Fingerprint{
				Method: catalog.FingerprintMethod,
			},
			tried:      map[string]bool{},
			ServerIP:   ip,
			ServerPort: port,
		}
		c.tasks[target] = t
		c.sayf("подозрение по %s (%s): начат поиск", target, control.SuspectText(ev.Code))
		if sig.TTL != 0 || sig.IPID != 0 {
			// Примета печатается целиком: без неё «узнавание не сработало»
			// приходится угадывать по последствиям.
			c.sayf("  примета: %s ttl=%d (сервер %d) tos=%#02x ipid=%d",
				sig.Kind, sig.TTL, ev.RefTTL, sig.ToS, sig.IPID)
		}
		// Просим форму приветствия: зонд обязан повторять то, что шлёт
		// клиент, а не своё. Если не успеет прийти — соберём похожее сами и
		// скажем об этом.
		if kind == "name" {
			if err := c.conn.WantShape(target); err != nil {
				return err
			}
			c.pendingAcks = append(c.pendingAcks, "")
		}
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
	if t.Current != nil || t.Asking.Name != "" {
		return nil
	}
	return c.step(t)
}

// step делает следующий шаг поиска: либо задаёт вопрос, ответ на который
// изменит выбор, либо, когда спрашивать больше нечего, проверяет кандидата.
//
// Вопрос ПЕРЕД кандидатом не порядок ради порядка. Сегодня отсутствие первого
// же вопроса стоило трёх зондов на цель, которую невозможно пробить в
// принципе: коробка там решает по адресу, и никакая работа с именем не
// помогла бы никогда.
func (c *Controller) step(t *Task) error {
	if t.Current != nil {
		// Кандидат уже стоит и проверяется. Запоздавший ответ на прежний
		// вопрос его не отменяет: иначе только что поставленный план
		// сменялся бы следующим, не успев быть проверенным.
		//
		// Ровно это и происходило, когда измерение объёма перебивало
		// лестницу: подобранное имя вставало, а пришедший следом ответ на
		// вопрос про приветствие двигал очередь дальше, и проверялся уже
		// не тот план.
		return nil
	}
	// Объём меряется фоном, как только стало ясно, что транспорт встаёт.
	// Прибор для него другой, и очередь кандидатов он не занимает.
	if !t.Traits.VolumeAsked && t.Traits.ByName == TraitYes {
		c.askVolume(t)
	}
	if q, ok := nextQuestion(t.Traits); ok {
		return c.ask(t, q)
	}
	if t.Traits.ByName == TraitNo {
		// Транспорт не встаёт: работать нечем. Ничего не сохраняется (§2.3) —
		// ни как «непробиваемая», ни как отметка на цели.
		c.sayf("по %s транспорт не встаёт — искать нечем, не сохранено ничего",
			t.Target)
		c.cooldown[t.Target] = c.now().Add(cooldownAfterFail)
		delete(c.tasks, t.Target)
		return c.clear(t.Kind, t.Target)
	}
	return c.advance(t)
}

// ask задаёт вопрос коробке. Плана при этом НЕ ставится: вопрос меряет саму
// линию, а не наше воздействие на неё.
func (c *Controller) ask(t *Task, q Question) error {
	if t.ServerIP == "" || c.prober == nil {
		// Спросить нечем — идём к кандидатам, отметив, что не спрашивали.
		return c.advance(t)
	}
	hello, how, err := c.questionHello(t, q)
	if err != nil {
		c.sayf("по %s вопрос «%s» не собрать: %v", t.Target, q.Name, err)
		t.Traits = answerUnknown(t.Traits, q)
		return c.step(t)
	}
	t.Asking = q
	t.probeForgedRST = false
	c.sayf("по %s спрашиваю: %s (%s), %s", t.Target, q.Name, q.Why, how)
	c.fire(t, hello)
	return nil
}

// questionHello строит сообщение, которым задаётся вопрос.
func (c *Controller) questionHello(t *Task, q Question) ([]byte, string, error) {
	switch q.Name {
	case "встаёт ли транспорт":
		// Любое имя годится: вопрос про транспорт, а не про имя.
		h, err := c.clientHello(t)
		return h, "форма клиента", err
	default:
		h, err := c.clientHello(t)
		return h, "форма клиента", err
	}
}

func answerUnknown(tr Traits, q Question) Traits {
	// Не спросили — значит не знаем. Превращать «не спрашивали» в «нет»
	// запрещено (§2.4), поэтому здесь ставится именно отказ от вопроса.
	switch q.Name {
	case "встаёт ли транспорт":
		tr.ByName = TraitYes // не смогли спросить — работаем как обычно
	case "первое приветствие или последнее":
		tr.ReadsFirstHello = TraitNo
	case "собирает ли сегменты":
		tr.Reassembles = TraitYes
	}
	return tr
}

func addSignal(fp catalog.Fingerprint, s catalog.Signal) catalog.Fingerprint {
	for i := range fp.Signals {
		x := &fp.Signals[i]
		if x.Kind == "volume" && s.Kind == "volume" {
			// У обрыва по объёму нет ни TTL, ни идентификатора: сравнивать
			// нечего, кроме самого объёма, и допуск тот же, что в каталоге —
			// иначе задача накопит приметы, которые каталог сочтёт одной.
			d := x.Volume - s.Volume
			if d < 0 {
				d = -d
			}
			if d <= catalog.VolumeSlack {
				x.Seen += s.Seen
				return fp
			}
			continue
		}
		// Допуск по TTL тот же, что в каталоге: иначе задача накопит приметы,
		// которые каталог потом сочтёт одной.
		d := int(x.TTL) - int(s.TTL)
		if d < 0 {
			d = -d
		}
		if x.Kind == s.Kind && d <= 2 && x.IPID == s.IPID && x.ToS == s.ToS {
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
		// Ждём подтверждения и только потом стучимся. Пускать зонд «через
		// паузу на всякий случай» — гонка, которую не видно, пока она не
		// проявится на медленной коробке.
		c.pendingAcks = append(c.pendingAcks, t.Target)
		t.Current = &cand
		t.AppliedCount = 0
		// Для обрыва по объёму пакетный зонд не годится: чтобы перевалить за
		// порог, нужен полный сеанс TLS и прикладной запрос. Такую цель
		// проверяет накачка объёма — тем же прибором, которым обнаружили.
		t.awaiting = c.prober != nil && t.ServerIP != "" && t.VolumeCutAt == 0
		t.Attempts++
		c.sayf("по %s пробую %s (%s), попытка %d",
			t.Target, cand.Plan.ID, cand.Source, t.Attempts)
		return nil
	}

	if t.scanning {
		// Измерение объёма ещё идёт. Закрыть поиск сейчас значит выбросить
		// ответ, за который уже заплачено временем: при блоке по объёму
		// подстановка имени — единственное, что поможет, а лестница до него
		// добраться и не могла.
		c.sayf("по %s кандидаты кончились, но измерение объёма ещё идёт — жду его",
			t.Target)
		t.Current = nil
		return nil
	}

	// Кандидаты кончились. Ничего не сохраняется и ничего не остаётся: §2.3.
	// Снимаем поставленный план, чтобы цель вернулась к прямому проходу.
	c.sayf("по %s решения не нашлось, попыток %d, зондов %d — не сохранено ничего",
		t.Target, t.Attempts, t.Probes)
	c.cooldown[t.Target] = c.now().Add(cooldownAfterFail)
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

	gen, err := generate(t.Fingerprint, c.decoy, t.Traits.PassingName)
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

// serverOf — какая сторона пары сервер. Та, у которой порт 443; если ни у
// кого, берём высокий конец: ключ канонизирован, выдумывать тут нечего.
func serverOf(k control.Key) (string, int) {
	if k.LowPort == 443 {
		return fmt.Sprintf("%d.%d.%d.%d", k.LowIP[0], k.LowIP[1], k.LowIP[2], k.LowIP[3]), 443
	}
	return fmt.Sprintf("%d.%d.%d.%d", k.HighIP[0], k.HighIP[1], k.HighIP[2], k.HighIP[3]),
		int(k.HighPort)
}

func (c *Controller) onShape(ev control.Event) {
	if len(ev.Shape) == 0 {
		return
	}
	// Форма ловится по одной цели за раз, и задача, её заказавшая, — та, у
	// которой формы ещё нет.
	for _, t := range c.tasks {
		if t.Shape == nil {
			t.Shape = append([]byte(nil), ev.Shape...)
			c.sayf("по %s поймана форма приветствия: %d байт", t.Target, len(ev.Shape))
			return
		}
	}
}

// onAck: план встал — можно стучаться.
func (c *Controller) onAck(ev control.Event, now time.Time) error {
	if len(c.pendingAcks) == 0 {
		return nil
	}
	target := c.pendingAcks[0]
	c.pendingAcks = c.pendingAcks[1:]
	if target == "" {
		return nil // подтверждение на заказ формы
	}
	t := c.tasks[target]
	if t == nil || t.Current == nil {
		return nil
	}
	if !ev.AckOK {
		// Датапат отверг план. Это не наблюдение о коробке — это наш
		// негодный кандидат, и следующий берём немедленно.
		c.sayf("по %s датапат отверг %s, беру следующий", target, t.Current.Plan.ID)
		t.Current = nil
		return c.advance(t)
	}
	if t.VolumeCutAt > 0 {
		// Цель с обрывом по объёму проверяется накачкой объёма, а не пакетным
		// зондом: тот до порога не доберётся, ему для этого нужен полный сеанс.
		c.verifyVolume(t)
		return nil
	}
	c.startProbe(t, now)
	return nil
}

// startProbe стучится в цель НЕ ДОЖИДАЯСЬ клиента.
//
// Это и есть ответ на «ждать надо время, а не повторы»: устройство, которое
// не перезапрашивает — телевизор, приставка, часть IoT, — иначе не
// обслуживалось бы вовсе, а срок ожидания задавали бы чужие привычки.
// clientHello — приветствие ТОЙ ЖЕ формы, что шлёт клиент. Коробка может
// по-разному относиться к приветствию браузера и к нашему (§3.1, §5.5).
func (c *Controller) clientHello(t *Task) ([]byte, error) {
	if len(t.Shape) == 0 {
		return plan.Hello(t.Target, 0x30)
	}
	reshaped, dropped, err := probe.Reshape(t.Shape, 0x55)
	if err != nil {
		return plan.Hello(t.Target, 0x30)
	}
	if len(dropped) > 0 {
		c.sayf("по %s из формы клиента убраны расширения %v: билеты возобновления не копируем",
			t.Target, dropped)
	}
	return reshaped, nil
}

// fire отправляет зонд. Не решает, ЧТО спрашивать, — только отправляет.
func (c *Controller) fire(t *Task, hello []byte) {
	if t.probing || t.ServerIP == "" || c.prober == nil {
		t.awaiting = false
		return
	}
	if t.Probes >= maxProbesPerTask {
		// Бюджет кончился. Это не свойство цели и никуда не пишется — просто
		// столько мы за один поиск себе позволяем (§5).
		c.sayf("по %s бюджет зондов исчерпан (%d)", t.Target, t.Probes)
		t.awaiting = false
		t.Asking = Question{}
		return
	}
	t.probing = true
	t.Probes++
	c.probesUsed++
	target, ip, port := t.Target, t.ServerIP, t.ServerPort
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res := c.prober.Do(ctx, ip, port, hello)
		c.results <- probeDone{target: target, res: res}
	}()
}

func (c *Controller) startProbe(t *Task, now time.Time) {
	hello, err := c.clientHello(t)
	if err != nil {
		c.sayf("по %s приветствие для зонда не собралось: %v", t.Target, err)
		t.awaiting = false
		return
	}
	c.sayf("по %s стучусь сам: %s:%d", t.Target, t.ServerIP, t.ServerPort)
	c.fire(t, hello)
}

// onProbe — зонд ответил. Ответ толкуется по тому, ЧТО спрашивали.
func (c *Controller) onProbe(d probeDone) error {
	t := c.tasks[d.target]
	if t == nil {
		return nil
	}
	t.probing = false
	t.awaiting = false
	t.probePort = d.res.LocalPort

	if t.Asking.Name != "" {
		return c.onAnswer(t, d)
	}
	if t.Current == nil {
		return nil
	}
	c.sayf("по %s зонд: %s", d.target, d.res.Describe())

	if d.res.Outcome != probe.OutcomeExchange {
		// Кандидат не подошёл. Это НЕ доказательство свойств коробки (§2.4) и
		// никуда не записывается.
		t.Current = nil
		return c.advance(t)
	}

	level := catalog.LevelProtocol
	if d.res.HasAppData() {
		level = catalog.LevelHandshake
	}
	box, created, err := c.store.Catalog().Confirm(
		t.Fingerprint, t.Current.Plan, t.Kind, t.Target, level, c.now())
	if err != nil {
		c.sayf("по %s зонд прошёл, но записать нечего: %v", t.Target, err)
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
	c.sayf("по %s решение найдено за %d зонд(ов), уровень %d: %s, план %s",
		t.Target, t.Probes, level, what, t.Current.Plan.ID)

	delete(c.tasks, t.Target)
	if _, err := c.store.Flush(c.now()); err != nil {
		c.sayf("каталог не записался: %v", err)
	}
	return nil
}

// keyHasPort — участвует ли этот порт в паре ключа. Ключ канонизирован, и
// наш порт может оказаться любым из двух концов.
func keyHasPort(k control.Key, port uint16) bool {
	return k.LowPort == port || k.HighPort == port
}

// onAnswer толкует ответ на заданный вопрос.
//
// Толкование — единственное место, где наблюдение превращается в свойство
// коробки, и потому здесь важнее всего не сказать лишнего. Каждый исход
// сопоставляется ровно с тем, что он доказывает, и ни с чем сверх (§2.4).
func (c *Controller) onAnswer(t *Task, d probeDone) error {
	q := t.Asking
	t.Asking = Question{}

	switch q.Name {
	case "встаёт ли транспорт":
		if d.res.Outcome == probe.OutcomeNoConnect {
			// Не встал даже транспорт. Это ниже TLS, и работать с именем
			// бессмысленно — но утверждать «блокировка по адресу» всё равно
			// нельзя: сервер мог просто лежать (§2.4). Записываем ровно то,
			// что видно, и не сохраняем ничего (§2.3).
			c.sayf("по %s ответ: транспорт не встаёт вовсе (%s) — это ниже TLS",
				t.Target, d.res.Describe())
			t.Traits.ByName = TraitNo
		} else {
			c.sayf("по %s ответ: транспорт встаёт — дело выше него", t.Target)
			t.Traits.ByName = TraitYes
		}
	default:
		t.Traits = answerUnknown(t.Traits, q)
	}
	return c.step(t)
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
