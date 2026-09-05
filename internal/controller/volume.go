package controller

import (
	"fmt"
	"sort"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/conntrack"
)

// Обнаружение обрыва по объёму — того класса блокировки, где рукопожатие
// проходит, обмен идёт, а поток встаёт на десятке-другом килобайт.
//
// Окно наблюдения датапата — первые пакеты соединения, и обрыв на шестнадцатом
// килобайте за ним по построению. §5.2 требует проектировать обнаружение
// поздних обрывов отдельно; вот оно, и строится оно на счётчиках ядра, которые
// аппаратной разгрузкой не ослеплены (замер этапа 0).
//
// Порог НЕ назначается числом. «Обрыв на 16 килобайтах» — это чужой замер на
// чужой линии; здесь признаком служит ПОВТОРЯЕМОСТЬ: несколько потоков к одной
// цели кончились почти на одном и том же объёме. Здоровая отдача так себя не
// ведёт — она кончается там, где кончился документ, и у разных страниц разный
// размер. Донор наблюдал ровно это: hetzner.com отдавал 15994 байта раз за
// разом.

const (
	// Полоса, в которой обрыв по объёму вообще имеет смысл искать. Ниже —
	// обычные короткие ответы, выше — уже нормальная отдача.
	volumeBandLow  int64 = 4 * 1024
	volumeBandHigh int64 = 512 * 1024
	// Насколько два измерения считаются «одним и тем же объёмом». Отдача
	// одного и того же документа гуляет на заголовках; обрыв по счётчику —
	// почти нет.
	volumeSpreadNum = 6
	volumeSpreadDen = 100
	// Сколько согласных измерений нужно, чтобы говорить об обрыве. Одно —
	// это просто короткая страница.
	volumeSamplesNeeded = 3
	// Сколько измерений держим на цель. §5.2: предел нужен на всё.
	volumeSamplesKept = 8
)

// flowKey — поток глазами наблюдателя: адрес цели и порт клиента.
type flowKey struct {
	dstIP   string
	srcPort int
}

// seenFlow — что известно о живом потоке.
type seenFlow struct {
	inBytes int64
	// state — последнее состояние, в котором ядро его видело. Именно оно
	// отличает обрыв от честно отданного документа.
	state string
}

// volumeWatch — наблюдение за объёмом по одной цели.
type volumeWatch struct {
	target  string
	dstIP   string
	live    map[flowKey]seenFlow
	samples []int64 // объёмы ОБОРВАВШИХСЯ потоков
	// closed — сколько потоков закончилось честно. Нужно для сводки: «обрывов
	// не было» и «мы ничего не видели» — разные утверждения.
	closed int
	told   bool
}

// watchVolume ставит цель под наблюдение. Дешёвая операция: наблюдение
// стоит одного чтения таблицы ядра на всех.
func (c *Controller) watchVolume(target, dstIP string) {
	if dstIP == "" {
		return
	}
	if c.volume == nil {
		c.volume = map[string]*volumeWatch{}
	}
	if _, ok := c.volume[target]; ok {
		return
	}
	if len(c.volume) >= maxTasks {
		return
	}
	c.volume[target] = &volumeWatch{
		target: target, dstIP: dstIP, live: map[flowKey]seenFlow{},
	}
}

// pollVolume снимает счётчики ядра и копит измерения.
//
// Поток, исчезнувший из таблицы, считается завершившимся: сколько он успел
// отдать, столько и отдал. Это единственный момент, когда объём известен
// окончательно.
func (c *Controller) pollVolume(now time.Time) {
	if len(c.volume) == 0 {
		return
	}
	seen := map[string]map[flowKey]seenFlow{}
	for target, w := range c.volume {
		flows, err := conntrack.Read(c.ctPath, conntrack.Match{DstIP: w.dstIP, DstPort: 443})
		if err != nil {
			// Таблицы нет — наблюдать нечем. Молчать об этом нельзя: иначе
			// «обрывов не видели» будет означать «не смотрели».
			if !c.ctWarned {
				c.ctWarned = true
				c.sayf("счётчики потоков недоступны (%v): обрывы по объёму не наблюдаются", err)
			}
			return
		}
		m := map[flowKey]seenFlow{}
		for _, f := range flows {
			m[flowKey{dstIP: f.DstIP, srcPort: f.SrcPort}] = seenFlow{
				inBytes: f.InBytes, state: f.State,
			}
		}
		seen[target] = m
	}

	for target, w := range c.volume {
		m := seen[target]
		// Исчезнувшие потоки — завершившиеся. Но КАК завершившиеся, вот
		// вопрос.
		//
		// Повторяющегося объёма МАЛО. Сервер, отдающий одну и ту же страницу,
		// выглядит точно так же: три запроса — три одинаковых числа. Мой
		// собственный замер на несуществующем имени дал ровно это, и детектор
		// объявил обрывом честную страницу ошибки.
		//
		// Отличает одно от другого то, КАК умер поток. Отданный до конца
		// документ закрывается по-человечески: сервер шлёт FIN, ядро уводит
		// запись в FIN_WAIT, TIME_WAIT, CLOSE. Оборванный поток остаётся в
		// ESTABLISHED и просто протухает по таймауту — закрывать его некому.
		// Донор ловит то же самое иначе: «обрыв посреди TLS-записи».
		for k, last := range w.live {
			if _, still := m[k]; still {
				continue
			}
			delete(w.live, k)
			if last.state != "ESTABLISHED" {
				// Закрылся честно — это не обрыв, сколько бы байт ни было.
				w.closed++
				continue
			}
			if last.inBytes < volumeBandLow || last.inBytes > volumeBandHigh {
				continue
			}
			w.samples = append(w.samples, last.inBytes)
			if len(w.samples) > volumeSamplesKept {
				w.samples = w.samples[len(w.samples)-volumeSamplesKept:]
			}
		}
		for k, v := range m {
			w.live[k] = v
		}
		if at, n, ok := w.cut(); ok && !w.told {
			w.told = true
			c.onVolumeCut(target, at, n, now)
		}

		// Проверка кандидата по объёму: поток, заметно переваливший за
		// измеренный обрыв, и есть доказательство. Зонда тут нет и быть не
		// может — счётчик ядра видит то, чего не видит окно наблюдения.
		if t := c.tasks[target]; t != nil && t.Current != nil && t.VolumeCutAt > 0 {
			for _, f := range w.live {
				if f.inBytes > t.VolumeCutAt*2 {
					c.onVolumePassed(t, f.inBytes, now)
					break
				}
			}
		}
	}
}

// cut — есть ли повторяющийся объём, на котором потоки кончаются.
// Возвращает сам объём и число согласных измерений.
func (w *volumeWatch) cut() (int64, int, bool) {
	if len(w.samples) < volumeSamplesNeeded {
		return 0, 0, false
	}
	s := append([]int64(nil), w.samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	// Ищем самую плотную группу: значения, отличающиеся не больше чем на
	// заданную долю от меньшего.
	best, bestAt := 0, int64(0)
	for i := range s {
		n := 0
		for j := i; j < len(s); j++ {
			if s[j]-s[i] > s[i]*volumeSpreadNum/volumeSpreadDen {
				break
			}
			n++
		}
		if n > best {
			best, bestAt = n, s[i]
		}
	}
	return bestAt, best, best >= volumeSamplesNeeded
}

// onVolumeCut — измерение состоялось: потоки к цели раз за разом кончаются на
// одном объёме.
//
// Это НАБЛЮДЕНИЕ, а не приговор (§2.4): сайт мог просто отдавать документ
// одного размера. Отличать одно от другого будет проверка — подстановка
// проходящего имени и сравнение объёма с измеренным.
func (c *Controller) onVolumeCut(target string, at int64, n int, now time.Time) {
	c.sayf("по %s потоки кончаются на %d байтах, %d раз подряд — похоже на обрыв по объёму",
		target, at, n)
	t := c.tasks[target]
	if t == nil {
		if until, ok := c.cooldown[target]; ok && now.Before(until) {
			return
		}
		if len(c.tasks) >= maxTasks {
			c.dropped++
			return
		}
		w := c.volume[target]
		t = &Task{
			Target:      target,
			Kind:        "name",
			Started:     now,
			Fingerprint: catalog.Fingerprint{Method: catalog.FingerprintMethod},
			tried:       map[string]bool{},
			ServerIP:    w.dstIP,
			ServerPort:  443,
		}
		c.tasks[target] = t
		if err := c.conn.WantShape(target); err == nil {
			c.pendingAcks = append(c.pendingAcks, "")
		}
	}
	t.VolumeCutAt = at
	// Раз через поток прошло полтора десятка килобайт, транспорт очевидно
	// встаёт и рукопожатие проходит. Спрашивать об этом зондом — тратить
	// попытку человека на то, что уже измерено. §3.5: следующий вопрос
	// задаётся, когда его ответ способен изменить выбор; этот не способен.
	t.Traits.ByName = TraitYes
	t.Traits.VolumeCut = true
	t.Fingerprint = addSignal(t.Fingerprint, catalog.Signal{
		Kind: "volume", TTL: 0, Seen: 1,
		// Объём кладём в поле идентификатора: он и есть примета этой коробки
		// на этой линии, и по нему две коробки различаются.
		IPID: uint16(at / 1024),
	})
	c.sayf("  примета: обрыв по объёму около %d КиБ", at/1024)
	if t.Current == nil && t.Asking.Name == "" {
		if err := c.step(t); err != nil {
			c.sayf("по %s шаг поиска не удался: %v", target, err)
		}
	}
}

// volumeReport — что видно про объёмы. Для панели и журнала.
func (c *Controller) volumeReport() []string {
	out := make([]string, 0, len(c.volume))
	for target, w := range c.volume {
		at, n, ok := w.cut()
		if !ok {
			continue
		}
		out = append(out, fmt.Sprintf("%s: обрыв около %d байт (%d измерений)", target, at, n))
	}
	sort.Strings(out)
	return out
}

// onVolumePassed — поток к цели перевалил за измеренный обрыв.
//
// Порог «вдвое больше обрыва» выбран не из красоты: отдача, кончившаяся ровно
// там же, где кончалась всегда, ничего не доказывает, а вдвое большая уже не
// объясняется прежним поведением. Само число обрыва при этом ИЗМЕРЕНО на этой
// линии, а не взято из чужого замера.
func (c *Controller) onVolumePassed(t *Task, got int64, now time.Time) {
	c.sayf("по %s поток отдал %d байт против прежних %d — обрыв по объёму снят",
		t.Target, got, t.VolumeCutAt)

	// Уровень 4 по §4.2: прикладной обмен в проверяемом объёме. Именно
	// проверяемом — мы знаем, сколько отдавалось раньше, и знаем, сколько
	// отдаётся теперь.
	box, created, err := c.store.Catalog().Confirm(
		t.Fingerprint, t.Current.Plan, t.Kind, t.Target, catalog.LevelApplication, now)
	if err != nil {
		c.sayf("по %s объём вырос, но записать нечего: %v", t.Target, err)
		return
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
	if _, err := c.store.Flush(now); err != nil {
		c.sayf("каталог не записался: %v", err)
	}
}
