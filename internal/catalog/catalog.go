// Package catalog — каталог изученных DPI-коробок.
//
// Основная сущность базы знаний (§3): модель поведения блокирующей коробки,
// проверенные для неё планы и подтверждённые привязки целей. Домены здесь
// индекс подтверждённых встреч, а не способ группировки.
//
// ЧЕГО ЗДЕСЬ НЕТ И НЕ БУДЕТ — таблицы отказов. §2.3: неудачный подбор не
// сохраняется вообще, ни как список нерешённых, ни как отметка на цели.
// Линия, маршрут и сам DPI меняются; вчерашний отказ завтра не значит ничего,
// а сохранённый будет мешать честной повторной попытке. Поэтому у Box нет
// поля Failures, и добавлять его нельзя.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/necronicle/d2k/internal/plan"
)

// SchemaVersion — версия раскладки файла. Продукт станет общим (§1.1), и
// миграция должна быть возможна с самого начала.
const SchemaVersion = 1

// FingerprintMethod — версия способа получения отпечатка. Её смена делает
// записи кандидатами на перепроверку (§3.4), а не мусором: выбрасывать
// подтверждённое из-за смены алгоритма значит терять работу, которая была
// оплачена настоящими измерениями.
//
// Версия 2: приметой коробки стал АБСОЛЮТНЫЙ TTL подделанного пакета вместо
// его разности с TTL сервера. Замер 2026-09-05 показал, почему: пять целей
// на одной линии дали пять «разных» коробок с одинаковыми ToS 0x88 и
// идентификатором IP 54321 — различались только разности, потому что серверы
// стоят на разном расстоянии, а коробка на одном и том же. Обратный счёт дал
// TTL 127 у всех четырёх. Разность отвечает на вопрос «подделка ли это», а не
// «чья она».
const FingerprintMethod = 2

// Уровни доказательства успеха по §4.2. Уровень 2 нельзя показывать или
// сохранять как уровень 4, поэтому он записывается числом, а не словом
// «работает».
const (
	LevelTransport   = 1 // транспорт установился
	LevelProtocol    = 2 // протокольный ответ распознан
	LevelHandshake   = 3 // рукопожатие завершилось
	LevelApplication = 4 // прикладной обмен в проверяемом объёме
	LevelRepeated    = 5 // последующие реальные соединения подтвердили
)

// Signal — одно наблюдавшееся отличие в поведении линии.
//
// Для сброса примета коробки — TTL самого подделанного пакета, а не его
// разность с TTL сервера. Коробка стоит на фиксированном расстоянии от нас,
// серверы — на разном; разность поэтому гуляет от цели к цели, а абсолютное
// значение держится. Замер 2026-09-05: четыре цели, разности 3, 38, 40 и 74,
// TTL подделки у всех 127.
//
// TTLDelta сохраняется как наблюдение — он отвечает на вопрос «подделка ли
// это», — но в сравнении отпечатков не участвует: он про пару «коробка и
// сервер», а не про коробку.
type Signal struct {
	Kind     string `json:"kind"`
	TTL      uint8  `json:"ttl,omitempty"`
	TTLDelta int    `json:"ttl_delta,omitempty"`
	ToS      uint8  `json:"tos,omitempty"`
	IPID     uint16 `json:"ipid,omitempty"`
	// Volume — объём в килобайтах, на котором рвётся поток. Только для
	// приметы вида «volume».
	//
	// Отдельным полем, а не в чужом: объём — ИЗМЕРЕНИЕ с известной
	// погрешностью, а не идентификатор, и сравнивать его надо с допуском.
	// Пока он лежал в поле идентификатора IP и сравнивался точно, одна и та
	// же коробка попадала в базу пять раз: на роутере 06.09.2026 нашлись пять
	// «коробок по объёму» с пересекающимися целями.
	Volume int `json:"volume,omitempty"`
	Seen   int `json:"seen"`
}

// Fingerprint — отпечаток поведения коробки.
type Fingerprint struct {
	Method  int      `json:"method"`
	Signals []Signal `json:"signals"`
}

// ttlSlack — на сколько TTL приметы может гулять и всё ещё считаться той же.
//
// Не вкус: полевой прогон 2026-09-05 дал у одной и той же подделки TTL 126 и
// 127 в пределах одного часа. Маршрут меняется на хоп, и число прыжков вместе
// с ним. Сравнивай точно — и каждое дрожание маршрута плодило бы примету, а
// потом и коробку.
//
// Два, а не больше: соседний хоп это ±1, запас на второй. Шире — и два
// РАЗНЫХ механизма на соседних узлах слились бы в один. Что они при этом
// одинаково себя ведут, ещё не делает их одним устройством (§3), но модель
// поведения у них была бы одна, а каталог хранит именно модели.
const ttlSlack = 2

// volumeSlack — на сколько может гулять измеренный объём обрыва.
//
// Не вкус: проба качает лестницей по 4000 байт, и меньше одной ступени она
// различить не может по построению. Замер 06.09.2026 на одной и той же сети
// дал 19 и 23 КБ на двух адресах — это одно поведение, разнесённое
// погрешностью прибора. Допуск равен ступени.
const volumeSlack = 4

// VolumeSlack — тот же допуск наружу: задача копит приметы до того, как они
// попадут в каталог, и складывать их обязана по тому же правилу.
const VolumeSlack = volumeSlack

// sameEvidence — одна ли это примета.
//
// Разность TTL сюда НЕ входит: она про пару «коробка и сервер», а не про
// коробку, и на разных целях разная. TTL сравнивается с допуском, всё
// остальное — точно: постоянный идентификатор IP и ToS не дрожат.
func sameEvidence(a, b Signal) bool {
	if a.Kind == "volume" {
		// У обрыва по объёму нет ни TTL, ни идентификатора: коробка ничего не
		// присылает, она просто перестаёт пропускать. Сравнивать нечего, кроме
		// объёма, и сравнивать его надо с допуском прибора.
		d := a.Volume - b.Volume
		if d < 0 {
			d = -d
		}
		return d <= volumeSlack
	}
	d := int(a.TTL) - int(b.TTL)
	if d < 0 {
		d = -d
	}
	return d <= ttlSlack && a.IPID == b.IPID && a.ToS == b.ToS
}

// migrate чинит записи, сделанные прежней раскладкой.
//
// Объём обрыва раньше лежал в поле идентификатора IP и сравнивался точно —
// оттого одна коробка попадала в базу по нескольку раз. Перекладываем в своё
// поле, где он сравнивается с допуском прибора. Записи не выбрасываются:
// они оплачены настоящими измерениями (§3.4).
func (c *Catalog) migrate() {
	for i := range c.Boxes {
		sigs := c.Boxes[i].Fingerprint.Signals
		for j := range sigs {
			s := &sigs[j]
			if s.Kind == "volume" && s.Volume == 0 && s.IPID != 0 {
				s.Volume = int(s.IPID)
				s.IPID = 0
			}
		}
	}
}

// Compatible — можно ли считать, что два отпечатка сняты с одного поведения.
//
// Правило: ни один общий вид сигнала не должен ПРОТИВОРЕЧИТЬ. Отсутствие
// сигнала противоречием не является — за одну встречу видно не всё: коробка
// шлёт сброс не на каждую цель, а молчание в одном опыте не отменяет сброса в
// другом. А вот сброс с другим TTL и другим идентификатором IP — это уже
// другое поведение, и складывать их в одну модель нельзя.
//
// Совместимость НЕ доказывает тождество механизмов (§2.4). Она лишь означает,
// что наблюдения не спорят между собой.
func (f Fingerprint) Compatible(other Fingerprint) bool {
	if f.Method != other.Method {
		return false
	}
	common := 0
	for _, s := range other.Signals {
		seen, agreed := false, false
		for _, t := range f.Signals {
			if t.Kind != s.Kind {
				continue
			}
			seen = true
			if sameEvidence(t, s) {
				agreed = true
				break
			}
		}
		if !seen {
			continue
		}
		if !agreed {
			// Примета того же вида, но с другими уликами — это противоречие,
			// а не «пока не встречали».
			return false
		}
		common++
	}
	// Совсем без общих сигналов говорить о совместимости не о чем: два
	// отпечатка, не пересекающиеся ни в чём, — это два разных наблюдения, а
	// не одно, увиденное дважды.
	return common > 0
}

// Match — насколько отпечаток f похож на отпечаток other: доля сигналов
// other, найденных в f, от 0 до 1.
//
// Совпадение НЕ создаёт подтверждённую запись (§2.4): оно лишь основание
// проверить готовый план этой коробки на фактической цели.
func (f Fingerprint) Match(other Fingerprint) float64 {
	if f.Method != other.Method || len(other.Signals) == 0 {
		return 0
	}
	hit := 0
	for _, s := range other.Signals {
		// Просматриваются ВСЕ приметы того же вида, а не первая попавшаяся.
		// Ранняя редакция обрывалась на первой: у коробки лежали приметы с
		// TTL 127 и 126, наблюдали 126 — и совпадение не находилось, хотя
		// оно было вторым по списку.
		for _, t := range f.Signals {
			if t.Kind != s.Kind {
				continue
			}
			// Приметы, у которых есть улики, обязаны совпасть по ним. Для
			// сброса это TTL и идентификатор, для обрыва — объём. Считать
			// совпадением одно лишь совпадение ВИДА значило бы объявить
			// коробку с обрывом на 19 КБ и коробку с обрывом на 200 одной.
			if (s.Kind == "rst" || s.Kind == "volume") && !sameEvidence(t, s) {
				continue
			}
			hit++
			break
		}
	}
	return float64(hit) / float64(len(other.Signals))
}

// Plan — проверенный план коробки.
//
// Хранится человеческая форма, а не байты TLV: она читаема, её можно
// сравнить глазами при разборе полёта, и она переживает смену раскладки TLV.
// Каноническую форму порождает internal/plan из этого текста.
type Plan struct {
	ID        string    `json:"id"`
	Proto     string    `json:"proto"`
	Text      string    `json:"text"`
	Added     time.Time `json:"added"`
	Successes int       `json:"successes"`
	Enabled   bool      `json:"enabled"`
}

// Compile переводит план в каноническую форму для исполнителя.
func (p Plan) Compile() ([]byte, error) {
	pl, err := plan.ParseText(p.Text)
	if err != nil {
		return nil, fmt.Errorf("план %s не разбирается: %w", p.ID, err)
	}
	return pl.MarshalTLV()
}

// Binding — подтверждённая привязка цели к плану.
//
// Enabled отдельно от Plan.Enabled намеренно: §5.6 требует независимого
// отключения плана и привязки. Выключить план для одной цели и оставить для
// остальных — обычное дело при разборе жалобы.
type Binding struct {
	Kind      string    `json:"kind"` // "name" | "addr"
	Target    string    `json:"target"`
	PlanID    string    `json:"plan_id"`
	Level     int       `json:"level"`
	Confirmed time.Time `json:"confirmed"`
	Successes int       `json:"successes"`
	Enabled   bool      `json:"enabled"`
}

// Box — изученная модель поведения DPI-коробки.
//
// ID обозначает модель поведения, не серийный номер и не доказанную
// топологию провайдера (§3): совпавшее поведение может принадлежать
// нескольким физическим устройствам, а в цепочке может действовать несколько
// механизмов.
type Box struct {
	ID          string      `json:"id"`
	Created     time.Time   `json:"created"`
	Updated     time.Time   `json:"updated"`
	Fingerprint Fingerprint `json:"fingerprint"`
	Plans       []Plan      `json:"plans"`
	Bindings    []Binding   `json:"bindings"`
}

// PlanByID возвращает план коробки.
func (b *Box) PlanByID(id string) *Plan {
	for i := range b.Plans {
		if b.Plans[i].ID == id {
			return &b.Plans[i]
		}
	}
	return nil
}

// BindingFor возвращает привязку цели.
func (b *Box) BindingFor(kind, target string) *Binding {
	for i := range b.Bindings {
		if b.Bindings[i].Kind == kind && strings.EqualFold(b.Bindings[i].Target, target) {
			return &b.Bindings[i]
		}
	}
	return nil
}

// Catalog — весь каталог.
type Catalog struct {
	Schema  int       `json:"schema"`
	Updated time.Time `json:"updated"`
	Boxes   []Box     `json:"boxes"`
}

// New создаёт пустой каталог. Пустая база при первом запуске — это норма
// (§2.2), а не состояние ошибки.
func New() *Catalog {
	return &Catalog{Schema: SchemaVersion}
}

// BoxByID возвращает коробку.
func (c *Catalog) BoxByID(id string) *Box {
	for i := range c.Boxes {
		if c.Boxes[i].ID == id {
			return &c.Boxes[i]
		}
	}
	return nil
}

// Lookup ищет подтверждённую привязку цели по имени, затем по адресу.
// Имя точнее адреса: за одним адресом CDN стоят сотни имён (§3.2).
func (c *Catalog) Lookup(name, addr string) (*Box, *Binding, *Plan) {
	for _, kind := range []string{"name", "addr"} {
		want := name
		if kind == "addr" {
			want = addr
		}
		if want == "" {
			continue
		}
		for i := range c.Boxes {
			b := c.Boxes[i].BindingFor(kind, want)
			if b == nil || !b.Enabled {
				continue
			}
			p := c.Boxes[i].PlanByID(b.PlanID)
			if p == nil || !p.Enabled {
				continue
			}
			return &c.Boxes[i], b, p
		}
	}
	return nil, nil, nil
}

// Candidates возвращает коробки, чей отпечаток похож на наблюдаемый,
// от самой похожей к менее похожей.
//
// Совпадение отпечатка НЕ создаёт привязку (§2.4, §10): это лишь порядок, в
// котором стоит проверять готовые планы на фактической цели.
func (c *Catalog) Candidates(fp Fingerprint) []*Box {
	type scored struct {
		box   *Box
		score float64
	}
	var list []scored
	for i := range c.Boxes {
		s := c.Boxes[i].Fingerprint.Match(fp)
		if s > 0 {
			list = append(list, scored{&c.Boxes[i], s})
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].score > list[j].score })
	out := make([]*Box, 0, len(list))
	for _, s := range list {
		out = append(out, s.box)
	}
	return out
}

// Validate проверяет каталог целиком. §5.6 требует проверки состояния при
// загрузке: запись, которую нельзя исполнить, обязана быть найдена здесь, а
// не в момент, когда она понадобится.
func (c *Catalog) Validate() error {
	if c.Schema != SchemaVersion {
		return fmt.Errorf("схема каталога %d, а эта сборка знает %d",
			c.Schema, SchemaVersion)
	}
	seenBox := map[string]bool{}
	for i := range c.Boxes {
		b := &c.Boxes[i]
		if b.ID == "" {
			return fmt.Errorf("коробка %d без идентификатора", i)
		}
		if seenBox[b.ID] {
			return fmt.Errorf("коробка %s встречается дважды", b.ID)
		}
		seenBox[b.ID] = true

		seenPlan := map[string]bool{}
		for _, p := range b.Plans {
			if p.ID == "" {
				return fmt.Errorf("коробка %s: план без идентификатора", b.ID)
			}
			if seenPlan[p.ID] {
				return fmt.Errorf("коробка %s: план %s встречается дважды", b.ID, p.ID)
			}
			seenPlan[p.ID] = true
			// План, который не разбирается, — битая запись. Найти её надо
			// сейчас, а не когда она понадобится посреди соединения.
			if _, err := plan.ParseText(p.Text); err != nil {
				return fmt.Errorf("коробка %s, план %s: %w", b.ID, p.ID, err)
			}
		}
		for _, bd := range b.Bindings {
			if bd.Kind != "name" && bd.Kind != "addr" {
				return fmt.Errorf("коробка %s: привязка вида %q", b.ID, bd.Kind)
			}
			if bd.Target == "" {
				return fmt.Errorf("коробка %s: привязка без цели", b.ID)
			}
			if !seenPlan[bd.PlanID] {
				return fmt.Errorf("коробка %s: привязка %s ссылается на несуществующий план %s",
					b.ID, bd.Target, bd.PlanID)
			}
			if bd.Level < LevelTransport || bd.Level > LevelRepeated {
				return fmt.Errorf("коробка %s: привязка %s с уровнем доказательства %d",
					b.ID, bd.Target, bd.Level)
			}
		}
	}
	return nil
}

var errNoConfirmation = errors.New(
	"привязка без подтверждённого обмена не сохраняется: §2.3")

// Recognise ищет коробку, чьё изученное поведение не противоречит
// наблюдаемому. НИЧЕГО НЕ СОЗДАЁТ и ничего не записывает.
//
// Возвращает лучшую по числу совпавших сигналов и то, была ли она
// единственной совместимой. Неоднозначность — это факт для решающего: §3.4
// говорит, что при неоднозначном распознавании выбирают различающий вопрос
// или проверяют наиболее вероятный готовый план, но НЕ запускают полный
// подбор только из-за неоднозначности.
func (c *Catalog) Recognise(fp Fingerprint) (box *Box, unambiguous bool) {
	var best *Box
	bestScore := -1.0
	n := 0
	for i := range c.Boxes {
		if !c.Boxes[i].Fingerprint.Compatible(fp) {
			continue
		}
		n++
		if s := c.Boxes[i].Fingerprint.Match(fp); s > bestScore {
			bestScore, best = s, &c.Boxes[i]
		}
	}
	return best, n == 1
}

// boxID делает стабильное локальное имя из отпечатка, которым коробка была
// заведена. Локальное (§3.3): это не серийный номер и не глобальный
// регистр — имя нужно, чтобы ссылаться на модель внутри этой базы.
//
// Считается ОДИН раз при заведении и дальше не меняется: отпечаток
// уточняется по мере встреч, и имя, пересчитываемое из него, менялось бы
// вместе с ним, ломая все ссылки.
func boxID(fp Fingerprint, now time.Time) string {
	sig := make([]string, 0, len(fp.Signals))
	for _, s := range fp.Signals {
		sig = append(sig, fmt.Sprintf("%s/%d/%d/%d", s.Kind, s.TTL, s.IPID, s.ToS))
	}
	sort.Strings(sig)
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s", fp.Method, strings.Join(sig, ";"))))
	return "box-" + hex.EncodeToString(h[:4])
}

// Confirm записывает подтверждённый успех: коробка, план и привязка цели.
//
// Единственная точка, через которую в каталог попадает новое знание. Без
// подтверждённого обмена не записывается ничего — ни коробка, ни план, ни
// привязка. Неудачное исследование не создаёт пустую коробку и не оставляет
// записи «решения нет» (§2.3, §3.4).
//
// КОРОБКУ ОПРЕДЕЛЯЕТ ОТПЕЧАТОК, а не вызывающий. Имени коробки в аргументах
// нет намеренно: выбирай её тот, кто зовёт, — одно и то же поведение попало
// бы в базу дважды под разными именами, а разное поведение слилось бы в одно.
// Заранее известных коробок не существует: первая появляется здесь, из
// измерения, и только вместе с подтверждённым решением.
//
// Возвращает коробку и признак того, что она заведена сейчас.
func (c *Catalog) Confirm(fp Fingerprint, p Plan,
	bindKind, target string, level int, now time.Time) (*Box, bool, error) {

	if level < LevelProtocol {
		// Транспорт установился — это ещё не обмен. Записывать такое значит
		// заполнять базу тем, что не подтверждено.
		return nil, false, errNoConfirmation
	}
	if len(fp.Signals) == 0 {
		// Коробка без единого наблюдения — это не модель поведения, а пустая
		// запись. §3.4: неудачное исследование не создаёт пустую коробку.
		return nil, false, errors.New("отпечаток пуст: коробку заводить не из чего")
	}

	b, _ := c.Recognise(fp)
	created := false
	if b == nil {
		// Имя выводится из отпечатка, значит два одинаковых отпечатка дадут
		// одно имя. Если узнавание почему-то не сработало, а имя уже занято —
		// это ТА ЖЕ коробка, и заводить вторую с тем же именем нельзя:
		// каталог с двумя одноимёнными записями не проходит проверку и не
		// записывается вовсе, то есть теряется всё подтверждённое за сеанс.
		//
		// Проверка стоит здесь, а не только в Validate, потому что Validate
		// ловит уже случившееся, а тут ещё можно поступить правильно.
		id := boxID(fp, now)
		if ex := c.BoxByID(id); ex != nil {
			b = ex
		} else {
			c.Boxes = append(c.Boxes, Box{
				ID:          id,
				Created:     now,
				Fingerprint: fp,
			})
			b = &c.Boxes[len(c.Boxes)-1]
			created = true
		}
	}
	if !created {
		// Уточняем отпечаток: новые сигналы добавляются, счётчик виденного
		// растёт. Старые не выбрасываются — они были измерены.
		b.Fingerprint = mergeFingerprint(b.Fingerprint, fp)
	}
	b.Updated = now

	if ex := b.PlanByID(p.ID); ex != nil {
		ex.Successes++
		ex.Enabled = true
	} else {
		p.Added = now
		p.Successes = 1
		p.Enabled = true
		b.Plans = append(b.Plans, p)
	}

	if bd := b.BindingFor(bindKind, target); bd != nil {
		bd.Successes++
		bd.Confirmed = now
		bd.Enabled = true
		if level > bd.Level {
			bd.Level = level
		}
		bd.PlanID = p.ID
	} else {
		b.Bindings = append(b.Bindings, Binding{
			Kind:      bindKind,
			Target:    target,
			PlanID:    p.ID,
			Level:     level,
			Confirmed: now,
			Successes: 1,
			Enabled:   true,
		})
	}
	c.Updated = now
	return b, created, nil
}

func mergeFingerprint(a, b Fingerprint) Fingerprint {
	if a.Method != b.Method {
		// Способ сменился: старый отпечаток не выбрасывается, но и не
		// смешивается с новым — смешанный не соответствовал бы ни одному
		// способу. Записи становятся кандидатами на перепроверку (§3.4).
		return b
	}
	out := a
	for _, s := range b.Signals {
		found := false
		for i := range out.Signals {
			t := &out.Signals[i]
			if t.Kind == s.Kind && sameEvidence(*t, s) {
				t.Seen += s.Seen
				found = true
				break
			}
		}
		if !found {
			out.Signals = append(out.Signals, s)
		}
	}
	return out
}
