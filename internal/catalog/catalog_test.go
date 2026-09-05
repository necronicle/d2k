package catalog_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
)

const armText = `d2k-plan 1 1
id 00000000000000000000000000000042
proto tcp tls
payload 1 deadbe
poison 1 ttl=3 badsum
fake payload=1 poison=1 repeats=2 gap_us=78000 place=before
order forward
`

// fp — отпечаток с одной приметой сброса. Первый аргумент — TTL самой
// подделки: именно он примета коробки, а не разность с TTL сервера.
func fp(ttl uint8, ipid uint16, tos uint8) catalog.Fingerprint {
	return catalog.Fingerprint{
		Method: catalog.FingerprintMethod,
		Signals: []catalog.Signal{
			{Kind: "rst", TTL: ttl, IPID: ipid, ToS: tos, Seen: 1},
		},
	}
}

func armPlan(id string) catalog.Plan {
	return catalog.Plan{ID: id, Proto: "tls", Text: armText}
}

func TestПустойКаталогЭтоНорма(t *testing.T) {
	// §2.2: пустая база при первом запуске — норма, а не состояние ошибки.
	dir := t.TempDir()
	s, err := catalog.Open(filepath.Join(dir, "catalog.json"))
	if err != nil {
		t.Fatalf("пустой каталог не открылся: %v", err)
	}
	if len(s.Catalog().Boxes) != 0 {
		t.Fatal("новый каталог не пуст")
	}
	if err := s.Catalog().Validate(); err != nil {
		t.Fatalf("пустой каталог не проходит проверку: %v", err)
	}
}

func TestБезПодтверждённогоОбменаНеЗаписываетсяНичего(t *testing.T) {
	// §2.3 — главное правило продукта. Уровень 1 (транспорт установился) не
	// является подтверждением обмена.
	c := catalog.New()
	_, _, err := c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "linkedin.com", catalog.LevelTransport, time.Now())
	if err == nil {
		t.Fatal("привязка записалась по одному установленному транспорту")
	}
	if len(c.Boxes) != 0 {
		t.Fatalf("в каталоге появилось %d коробок при отказе", len(c.Boxes))
	}
}

func TestПодтверждениеСоздаётКоробкуПланИПривязку(t *testing.T) {
	c := catalog.New()
	now := time.Now()
	if _, _, err := c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "linkedin.com", catalog.LevelHandshake, now); err != nil {
		t.Fatal(err)
	}
	if len(c.Boxes) != 1 {
		t.Fatalf("коробок %d, а ждали одну", len(c.Boxes))
	}
	box, bind, pl := c.Lookup("linkedin.com", "")
	if box == nil || bind == nil || pl == nil {
		t.Fatal("подтверждённая привязка не находится")
	}
	if bind.Level != catalog.LevelHandshake {
		t.Fatalf("уровень доказательства %d, а записывали %d",
			bind.Level, catalog.LevelHandshake)
	}
	if bind.Successes != 1 || pl.Successes != 1 {
		t.Fatal("счётчики подтверждённых успехов не заведены")
	}
	if _, err := pl.Compile(); err != nil {
		t.Fatalf("сохранённый план не переводится в каноническую форму: %v", err)
	}
}

func TestПовторноеПодтверждениеНеПлодитДубликаты(t *testing.T) {
	// §3.4: успех готового плана сохраняет новую привязку без создания
	// дубликата модели и без нового синтеза.
	c := catalog.New()
	now := time.Now()
	for i := 0; i < 3; i++ {
		if _, _, err := c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
			"name", "linkedin.com", catalog.LevelHandshake, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.Boxes) != 1 || len(c.Boxes[0].Plans) != 1 || len(c.Boxes[0].Bindings) != 1 {
		t.Fatalf("дубликаты: коробок %d, планов %d, привязок %d",
			len(c.Boxes), len(c.Boxes[0].Plans), len(c.Boxes[0].Bindings))
	}
	if c.Boxes[0].Bindings[0].Successes != 3 {
		t.Fatalf("подтверждений %d, а было три", c.Boxes[0].Bindings[0].Successes)
	}
	// Отпечаток тоже не должен раздуваться от одинаковых наблюдений.
	if n := len(c.Boxes[0].Fingerprint.Signals); n != 1 {
		t.Fatalf("сигналов в отпечатке %d, а наблюдение было одно и то же", n)
	}
	if c.Boxes[0].Fingerprint.Signals[0].Seen != 3 {
		t.Fatal("счётчик наблюдений сигнала не растёт")
	}
}

func TestНоваяЦельПривязываетсяКТойЖеКоробке(t *testing.T) {
	// §3.4 и этап E: успех готового плана на новом домене не создаёт дубликат
	// модели.
	c := catalog.New()
	now := time.Now()
	_, _, _ = c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "linkedin.com", catalog.LevelHandshake, now)
	_, _, _ = c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "instagram.com", catalog.LevelHandshake, now)

	if len(c.Boxes) != 1 {
		t.Fatalf("вторая цель создала дубликат коробки: %d", len(c.Boxes))
	}
	if len(c.Boxes[0].Bindings) != 2 {
		t.Fatalf("привязок %d, а целей две", len(c.Boxes[0].Bindings))
	}
	if len(c.Boxes[0].Plans) != 1 {
		t.Fatal("вторая цель создала дубликат плана")
	}
}

func TestИмяИщетсяРаньшеАдреса(t *testing.T) {
	// §3.2: за одним адресом CDN стоят сотни имён, приписывать по нему домен
	// нельзя.
	c := catalog.New()
	now := time.Now()
	byName, _, _ := c.Confirm(fp(127, 54321, 0x88), armPlan("pn"),
		"name", "discord.com", catalog.LevelHandshake, now)
	byAddr, _, _ := c.Confirm(fp(64, 111, 0x10), armPlan("pa"),
		"addr", "162.159.135.232", catalog.LevelHandshake, now)
	if byName == nil || byAddr == nil {
		t.Fatal("подтверждение не создало коробок")
	}
	if byName.ID == byAddr.ID {
		t.Fatal("разное поведение слилось в одну коробку")
	}

	box, _, _ := c.Lookup("discord.com", "162.159.135.232")
	if box == nil || box.ID != byName.ID {
		t.Fatal("адрес перебил имя")
	}
	// Чужое имя на том же адресе законно падает на адресную привязку.
	box, _, _ = c.Lookup("other.example", "162.159.135.232")
	if box == nil || box.ID != byAddr.ID {
		t.Fatal("запасной поиск по адресу не сработал")
	}
}

func TestОтключениеПланаИПривязкиНезависимы(t *testing.T) {
	// §5.6 требует именно независимого отключения.
	c := catalog.New()
	now := time.Now()
	_, _, _ = c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "a.example", catalog.LevelHandshake, now)
	_, _, _ = c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "b.example", catalog.LevelHandshake, now)

	c.Boxes[0].BindingFor("name", "a.example").Enabled = false
	if box, _, _ := c.Lookup("a.example", ""); box != nil {
		t.Fatal("выключенная привязка всё ещё находится")
	}
	if box, _, _ := c.Lookup("b.example", ""); box == nil {
		t.Fatal("выключение одной привязки задело другую")
	}

	c.Boxes[0].PlanByID("p1").Enabled = false
	if box, _, _ := c.Lookup("b.example", ""); box != nil {
		t.Fatal("выключенный план всё ещё применяется")
	}
}

func TestСовпадениеОтпечаткаТолькоПорядокПроверки(t *testing.T) {
	// §2.4 и §10: совпадение отпечатков без успешной проверки не создаёт
	// подтверждённую привязку. Candidates даёт ПОРЯДОК, а не решение.
	c := catalog.New()
	now := time.Now()
	first, _, _ := c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "a.example", catalog.LevelHandshake, now)
	_, _, _ = c.Confirm(fp(200, 7, 0x00), armPlan("p2"),
		"name", "b.example", catalog.LevelHandshake, now)

	got := c.Candidates(fp(127, 54321, 0x88))
	if len(got) == 0 || got[0].ID != first.ID {
		t.Fatalf("похожая коробка не первая: %v", got)
	}
	// Отпечаток, не похожий ни на что, кандидатов не даёт.
	if n := len(c.Candidates(fp(1, 1, 1))); n != 0 {
		t.Fatalf("непохожий отпечаток дал %d кандидатов", n)
	}
	// И никаких привязок при этом не создалось.
	if box, _, _ := c.Lookup("c.example", ""); box != nil {
		t.Fatal("подбор кандидатов создал привязку")
	}
}

func TestУКоробкиНетТаблицыОтказов(t *testing.T) {
	// §2.3: отрицательный результат не персистится вообще. Проверка на то,
	// что в JSON не появилось поля, куда его можно было бы положить.
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	s, _ := catalog.Open(path)
	s.MinInterval = 0
	_, _, _ = s.Catalog().Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "a.example", catalog.LevelHandshake, time.Now())
	s.Touch()
	if _, err := s.FlushNow(time.Now()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"failure", "failed", "отказ", "unreachable", "blocked"} {
		if strings.Contains(strings.ToLower(string(b)), bad) {
			t.Fatalf("в каталоге на диске встретилось %q — отрицательный результат не сохраняется (§2.3)", bad)
		}
	}
}

func TestПроверкаЛовитБитыеЗаписи(t *testing.T) {
	c := catalog.New()
	now := time.Now()
	_, _, _ = c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "a.example", catalog.LevelHandshake, now)

	// Привязка в никуда.
	c.Boxes[0].Bindings[0].PlanID = "нет такого"
	if err := c.Validate(); err == nil {
		t.Fatal("привязка на несуществующий план прошла проверку")
	}
	c.Boxes[0].Bindings[0].PlanID = "p1"

	// План, который не разбирается. Найти его надо при загрузке, а не когда
	// он понадобится посреди соединения.
	c.Boxes[0].Plans[0].Text = "это не план"
	if err := c.Validate(); err == nil {
		t.Fatal("неразбираемый план прошёл проверку")
	}
}

func TestКоробкуОпределяетИзмерениеАНеВызывающий(t *testing.T) {
	// Заранее известных коробок нет. Первая появляется из измерения, и имени
	// ей никто не даёт: оно выводится из отпечатка, которым она заведена.
	c := catalog.New()
	now := time.Now()

	// Одно и то же поведение на двух целях — ОДНА коробка.
	b1, created1, err := c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "linkedin.com", catalog.LevelHandshake, now)
	if err != nil || !created1 {
		t.Fatalf("первая коробка не заведена: %v", err)
	}
	b2, created2, err := c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "instagram.com", catalog.LevelHandshake, now)
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Fatal("то же поведение завело вторую коробку")
	}
	if b1.ID != b2.ID {
		t.Fatalf("одно поведение получило два имени: %s и %s", b1.ID, b2.ID)
	}

	// Другое поведение — другая коробка, даже на той же линии.
	b3, created3, err := c.Confirm(fp(200, 7, 0x00), armPlan("p2"),
		"name", "other.example", catalog.LevelHandshake, now)
	if err != nil || !created3 {
		t.Fatalf("другое поведение не завело коробку: %v", err)
	}
	if b3.ID == b1.ID {
		t.Fatal("разное поведение попало в одну коробку")
	}
	if len(c.Boxes) != 2 {
		t.Fatalf("коробок %d, а поведений было два", len(c.Boxes))
	}
}

func TestПротиворечиеРазводитКоробки(t *testing.T) {
	// Отсутствие сигнала — не противоречие: за одну встречу видно не всё.
	// А сброс с другим TTL и другим идентификатором — уже другое поведение.
	rst := fp(127, 54321, 0x88)
	other := fp(64, 111, 0x10)
	quiet := catalog.Fingerprint{
		Method: catalog.FingerprintMethod,
		Signals: []catalog.Signal{
			{Kind: "rst", TTL: 127, IPID: 54321, ToS: 0x88, Seen: 1},
			{Kind: "silent", Seen: 1},
		},
	}
	if !rst.Compatible(quiet) {
		t.Fatal("лишний сигнал в новом наблюдении объявлен противоречием")
	}
	if !quiet.Compatible(rst) {
		t.Fatal("недостающий сигнал объявлен противоречием")
	}
	if rst.Compatible(other) {
		t.Fatal("сброс с другими уликами объявлен тем же поведением")
	}
	// Ни одного общего сигнала — говорить о совместимости не о чем.
	onlySilent := catalog.Fingerprint{
		Method:  catalog.FingerprintMethod,
		Signals: []catalog.Signal{{Kind: "silent", Seen: 1}},
	}
	if rst.Compatible(onlySilent) {
		t.Fatal("непересекающиеся наблюдения объявлены одним поведением")
	}
}

func TestПустойОтпечатокНеЗаводитКоробку(t *testing.T) {
	// §3.4: неудачное исследование не создаёт пустую коробку.
	c := catalog.New()
	_, _, err := c.Confirm(catalog.Fingerprint{Method: catalog.FingerprintMethod},
		armPlan("p1"), "name", "a.example", catalog.LevelHandshake, time.Now())
	if err == nil {
		t.Fatal("коробка заведена из пустого отпечатка")
	}
	if len(c.Boxes) != 0 {
		t.Fatal("в каталоге появилась пустая коробка")
	}
}

func TestИмяКоробкиНеМеняетсяПриУточненииОтпечатка(t *testing.T) {
	// Отпечаток уточняется по мере встреч. Имя, пересчитываемое из него,
	// менялось бы вместе с ним и ломало все ссылки.
	c := catalog.New()
	now := time.Now()
	b1, _, _ := c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
		"name", "a.example", catalog.LevelHandshake, now)
	id := b1.ID

	richer := catalog.Fingerprint{
		Method: catalog.FingerprintMethod,
		Signals: []catalog.Signal{
			{Kind: "rst", TTL: 127, IPID: 54321, ToS: 0x88, Seen: 1},
			{Kind: "repeat", Seen: 1},
		},
	}
	b2, created, err := c.Confirm(richer, armPlan("p1"),
		"name", "b.example", catalog.LevelHandshake, now)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("уточнение отпечатка завело новую коробку")
	}
	if b2.ID != id {
		t.Fatalf("имя коробки изменилось: было %s, стало %s", id, b2.ID)
	}
	if len(b2.Fingerprint.Signals) != 2 {
		t.Fatal("отпечаток не уточнился")
	}
}

func TestРазноеРасстояниеДоСервераНеПлодитКоробки(t *testing.T) {
	// Полевой замер 2026-09-05: пять целей на одной линии дали пять «разных»
	// коробок. Все четыре сброса имели ToS 0x88 и идентификатор IP 54321,
	// различались только разности TTL — потому что серверы стоят на разном
	// расстоянии, а коробка на одном и том же.
	//
	// Приметой коробки должен быть TTL самой подделки. Здесь это и
	// закреплено: четыре цели, четыре разных сервера, одна коробка.
	c := catalog.New()
	now := time.Now()

	targets := []string{"linkedin.com", "instagram.com", "www.torproject.org", "facebook.com"}
	var ids []string
	for _, tgt := range targets {
		// TTL подделки один и тот же, потому что коробка одна.
		box, _, err := c.Confirm(fp(127, 54321, 0x88), armPlan("p1"),
			"name", tgt, catalog.LevelProtocol, now)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, box.ID)
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("цель %s попала в другую коробку: %s против %s",
				targets[i], id, ids[0])
		}
	}
	if len(c.Boxes) != 1 {
		t.Fatalf("коробок %d, а цензор один", len(c.Boxes))
	}
	if len(c.Boxes[0].Bindings) != 4 {
		t.Fatalf("привязок %d, а целей четыре", len(c.Boxes[0].Bindings))
	}

	// А другой TTL подделки — уже другая коробка: это другое расстояние, то
	// есть другое место в сети.
	other, created, err := c.Confirm(fp(64, 54321, 0x88), armPlan("p2"),
		"name", "elsewhere.example", catalog.LevelProtocol, now)
	if err != nil {
		t.Fatal(err)
	}
	if !created || other.ID == ids[0] {
		t.Fatal("подделка с другого расстояния слилась с прежней коробкой")
	}
}
