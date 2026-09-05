package web

import (
	"encoding/json"
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
