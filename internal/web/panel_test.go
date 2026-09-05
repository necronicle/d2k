package web

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/necronicle/d2k/internal/config"
	"github.com/necronicle/d2k/internal/status"
)

func newPanel(t *testing.T) http.Handler {
	t.Helper()
	c := config.Default()
	c.Path = "/несуществующий/config"
	p, err := New(c, time.Now().Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return p.Handler()
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

func TestПанельНеВыдаётНеработающееЗаРаботающее(t *testing.T) {
	// Это главное требование к панели на этом этапе. Если она когда-нибудь
	// начнёт молчать об отсутствии датапата, тест обязан упасть.
	body := get(t, newPanel(t), "/").Body.String()
	for _, must := range []string{
		"не смотрит на трафик",
		"Датапат ещё не написан",
		"построено 2 из 6",
	} {
		if !strings.Contains(body, must) {
			t.Errorf("на странице нет %q", must)
		}
	}
	if strings.Contains(body, "всё в порядке") || strings.Contains(body, "работает нормально") {
		t.Error("панель успокаивает, хотя обхода нет")
	}
}

func TestОтсутствующиеПоказанияНеПоказаныНулями(t *testing.T) {
	// «0 обойдённых целей» и «мы ничего не считаем» — разные утверждения.
	body := get(t, newPanel(t), "/").Body.String()
	if !strings.Contains(body, "Чего панель не показывает и почему") {
		t.Fatal("нет раздела об отсутствующих показаниях")
	}
	if !strings.Contains(body, "Обойдённые цели") {
		t.Error("обойдённые цели не перечислены среди отсутствующих показаний")
	}
}

func TestПолитикаЗапрещаетВнешниеИсточники(t *testing.T) {
	// Правило «панель работает без интернета» проверяется здесь, а не
	// обещанием в документации.
	csp := get(t, newPanel(t), "/").Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("нет Content-Security-Policy")
	}
	for _, must := range []string{"default-src 'none'", "script-src 'none'"} {
		if !strings.Contains(csp, must) {
			t.Errorf("в политике нет %q: %s", must, csp)
		}
	}
}

func TestРазметкаНеСодержитВнешнихСсылок(t *testing.T) {
	body := get(t, newPanel(t), "/").Body.String()
	for _, bad := range []string{"http://", "https://", "//fonts.", "cdn."} {
		if strings.Contains(body, bad) {
			t.Errorf("в разметке есть внешняя ссылка %q", bad)
		}
	}
}

func TestApiОтдаётТотЖеСнимок(t *testing.T) {
	rr := get(t, newPanel(t), "/api/status")
	var s status.Snapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &s); err != nil {
		t.Fatalf("снимок не разбирается: %v", err)
	}
	if s.Working() {
		t.Error("снимок утверждает, что d2k работает, хотя датапата нет")
	}
	built, total := s.BuiltCount()
	if built != 2 || total != 6 {
		t.Errorf("построено %d из %d, ожидалось 2 из 6", built, total)
	}
	if len(s.Absent) == 0 {
		t.Error("список отсутствующих показаний пуст — значит панель молчит о том, чего не знает")
	}
}

func TestЧужиеПутиНеОтдаются(t *testing.T) {
	if code := get(t, newPanel(t), "/чего-нет").Code; code != http.StatusNotFound {
		t.Errorf("на неизвестный путь код %d, ожидался 404", code)
	}
}

func TestРаспознаваниеПетли(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8090": true,
		"[::1]:8090":     true,
		"localhost:8090": true,
		"0.0.0.0:8090":   false,
		"192.168.1.1:80": false,
		"мусор":          false,
	} {
		if got := LoopbackOnly(addr); got != want {
			t.Errorf("LoopbackOnly(%q) = %v, ожидалось %v", addr, got, want)
		}
	}
}

// fakeKnowledge — узнанное для проверки разметки. Настоящий контроллер сюда
// не тащим: панель обязана работать от данных, а не от связки.
type fakeKnowledge struct{ k status.Knowledge }

func (f fakeKnowledge) Knowledge() status.Knowledge { return f.k }

func renderWith(t *testing.T, k status.Knowledge) string {
	t.Helper()
	p, err := New(config.Default(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.SetKnowledge(fakeKnowledge{k})
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("код %d", rec.Code)
	}
	return rec.Body.String()
}

func TestУровеньДваНеЧитаетсяКакГотово(t *testing.T) {
	// §4.2: уровень 2 нельзя показывать как уровень 4. Линейка залита ровно
	// на измеренное, а слова названы так, чтобы «сервер ответил» нельзя было
	// принять за «обмен прошёл».
	body := renderWith(t, status.Knowledge{
		Linked: true,
		Boxes: []status.BoxView{{
			ID:      "box-test",
			Signals: []status.SignalView{{Kind: "rst", Human: "сброс не от сервера", Seen: 3}},
			Bindings: []status.BindingView{
				{Target: "a.example", Level: 2, LevelName: status.LevelName(2), Successes: 1, Enabled: true},
				{Target: "b.example", Level: 3, LevelName: status.LevelName(3), Successes: 4, Enabled: true},
			},
		}},
	})

	if !strings.Contains(body, status.LevelName(2)) {
		t.Fatal("уровень не назван словами")
	}
	// Ни один уровень не называется словом, которое можно прочитать как
	// «всё в порядке»: измеряется не исправность, а глубина доказательства.
	for n := 1; n <= 5; n++ {
		if strings.Contains(status.LevelName(n), "работает") {
			t.Fatalf("уровень %d назван словом «работает» — оно ничего не измеряет", n)
		}
	}
	// Линейка залита ровно на измеренное: две клетки за уровень 2 и три за
	// уровень 3.
	if n := strings.Count(body, `class="on"`); n != 5 {
		t.Fatalf("залитых клеток %d, а ждали 2+3=5", n)
	}
	if !strings.Contains(body, "доказательство: 2 из 5") {
		t.Fatal("для незрячего уровень не назван")
	}
}

func TestКарточкаКоробкиНеВыдумываетУстройство(t *testing.T) {
	// §8 запрещает показывать недоказанные производителя, физический адрес
	// или экземпляр оборудования. Карточка обозначает МОДЕЛЬ ПОВЕДЕНИЯ.
	body := renderWith(t, status.Knowledge{
		Linked: true,
		Boxes: []status.BoxView{{
			ID:      "box-test",
			Signals: []status.SignalView{{Kind: "rst", Human: "сброс не от сервера: TTL 126", Seen: 4}},
		}},
	})
	for _, forbidden := range []string{"производитель", "модель оборудования", "устройство "} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("карточка утверждает про железо: %q", forbidden)
		}
	}
	if !strings.Contains(body, "TTL 126") {
		t.Fatal("измеренная примета не показана")
	}
}

func TestПустаяБазаНеВыглядитПоломкой(t *testing.T) {
	body := renderWith(t, status.Knowledge{Linked: true})
	if !strings.Contains(body, "Это не сбой") {
		t.Fatal("пустая база не объяснена — читается как поломка")
	}
	if !strings.Contains(body, "Ничего не ищется") {
		t.Fatal("отсутствие поисков не объяснено")
	}
}

func TestБезКонтроллераПанельНеВыдаётПрошлоеЗаНастоящее(t *testing.T) {
	p, err := New(config.Default(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "не подключён к датапату") {
		t.Fatal("панель молчит о том, что происходящего не видит")
	}
}

func TestИдущийПоискПоказанКакЖивоеСостояние(t *testing.T) {
	// §2.3 и §8: закрытый неудачей поиск исчезает бесследно, и панель обязана
	// сказать об этом, а не делать вид, что ведёт историю.
	body := renderWith(t, status.Knowledge{
		Linked: true,
		Searches: []status.SearchView{{
			Target: "linkedin.com", Phase: "проверяем готовый план коробки box-4c",
			Attempts: 2, Probes: 2, Candidate: "plan-b0",
		}},
	})
	if !strings.Contains(body, "linkedin.com") || !strings.Contains(body, "готовый план коробки") {
		t.Fatal("идущий поиск не показан")
	}
	// Проверяем по фразе, а не по куску строки: перенос в шаблоне не должен
	// ломать вердикт проверки.
	if !strings.Contains(body, "Поиск не записывается") {
		t.Fatal("панель не говорит, что неудачный поиск не записывается")
	}
}

func TestКороткийКоммитНеОбрываетСтраницу(t *testing.T) {
	// Срез `slice .Commit 0 12` на коротком коммите обрывает исполнение
	// шаблона. Поймано на роутере 06.09.2026: сборка со штампом в семь
	// символов рендерилась до слова «коммит» и обрывалась, а код был 200.
	// Пустой коммит бага не показывал — он уходил в другую ветку условия.
	p, err := New(config.Default(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, commit := range []string{"", "030b7d6", "0123456789abcdef0123"} {
		var buf bytes.Buffer
		data := struct {
			S       status.Snapshot
			K       status.Knowledge
			Built   int
			Total   int
			Working bool
		}{S: status.Snapshot{Commit: commit}, Total: 6}
		if err := p.tmpl.Execute(&buf, data); err != nil {
			t.Fatalf("коммит %q длиной %d: шаблон не исполнился: %v", commit, len(commit), err)
		}
		if !strings.Contains(buf.String(), "</html>") {
			t.Fatalf("коммит %q: страница оборвана на %d байтах", commit, buf.Len())
		}
	}
}

func TestОшибкаШаблонаНеВыдаётсяЗаСтраницу(t *testing.T) {
	// «200 и половина разметки» — это сломанное, притворившееся рабочим.
	p, err := New(config.Default(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.tmpl = template.Must(template.New("panel.html").Parse(
		`<p>начало</p>{{slice .S.Commit 0 12}}<p>конец</p>`))
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("сломанный шаблон отдан как успех, %d байт: %s", rec.Body.Len(), rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("код %d, ожидался 500", rec.Code)
	}
}
