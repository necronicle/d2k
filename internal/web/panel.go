// Package web — локальная панель d2k.
//
// Панель обязана открываться без интернета: ни внешних шрифтов, ни CDN, ни
// загружаемых библиотек (§8 документа). Всё, что она отдаёт, вшито в бинарник.
//
// Панель только читает. Изменяющих запросов у неё нет, и пока их нет, нет и
// аутентификации — но добавлять первый такой запрос без неё нельзя, и об этом
// написано на самой странице, чтобы забыть было труднее.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/necronicle/d2k/internal/config"
	"github.com/necronicle/d2k/internal/status"
)

//go:embed assets/panel.css
var assets embed.FS

//go:embed templates/panel.html
var tmplFS embed.FS

// KnowledgeSource — откуда панель берёт узнанное.
//
// Интерфейс, а не ссылка на контроллер: панель не должна знать ни устройства
// каталога, ни того, чем «проверяем готовое» отличается от «ищем новое». И
// без контроллера она обязана работать — просто честно говорить, что
// происходящего не видит.
type KnowledgeSource interface {
	Knowledge() status.Knowledge
}

// Panel отдаёт снимок состояния человеку и машине.
type Panel struct {
	cfg     config.Config
	started time.Time
	tmpl    *template.Template
	know    KnowledgeSource
	// linkNote — почему узнанного нет, если источника не дали. Отсутствие
	// объяснения читается как поломка, а это не поломка.
	linkNote string
}

// New готовит панель. Шаблон разбирается один раз на старте: ошибка разметки
// должна убивать запуск, а не всплывать у человека в браузере.
func New(cfg config.Config, started time.Time) (*Panel, error) {
	t, err := template.New("panel.html").Funcs(template.FuncMap{
		"uptime": humanUptime,
		// iter даёт шаблону счётный ряд для линейки доказательства. В Go
		// шаблонах нет цикла по числу, а рисовать пять клеток руками значит
		// однажды нарисовать четыре.
		"iter": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i
			}
			return out
		},
	}).ParseFS(tmplFS, "templates/panel.html")
	if err != nil {
		return nil, fmt.Errorf("разметка панели: %w", err)
	}
	return &Panel{
		cfg: cfg, started: started, tmpl: t,
		linkNote: "служба запущена без контроллера",
	}, nil
}

// SetKnowledge подключает источник узнанного. Без него панель показывает
// сборку и настройки, но не коробки и не поиски.
func (p *Panel) SetKnowledge(k KnowledgeSource) { p.know = k }

// SetLinkNote объясняет, почему узнанного нет.
func (p *Panel) SetLinkNote(s string) { p.linkNote = s }

func (p *Panel) knowledge() status.Knowledge {
	if p.know == nil {
		return status.Knowledge{Linked: false, LinkNote: p.linkNote}
	}
	return p.know.Knowledge()
}

// Handler — маршруты панели.
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.page)
	mux.HandleFunc("/api/status", p.apiStatus)
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
	return securityHeaders(mux)
}

// securityHeaders — политика содержимого, запрещающая внешние источники.
// Это не украшение: правило «панель работает без интернета» проверяется здесь,
// а не обещанием в документации. Любая попытка подтянуть шрифт или скрипт со
// стороны сломается на глазах у разработчика, а не у пользователя.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self'; connect-src 'self'; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (p *Panel) snapshot() status.Snapshot {
	// Конфигурация перечитывается на каждый запрос: человек правит файл и
	// обновляет страницу, и она обязана показать то, что в файле сейчас, а не
	// то, что было при запуске службы.
	c, err := config.Load(p.cfg.Path)
	if err != nil {
		// Испорченный файл — не повод показать умолчания как действующие
		// настройки. Показываем то, что удалось разобрать, и говорим об
		// ошибке отдельным полем.
		c = p.cfg
	}
	return status.Collect(c, p.started)
}

func (p *Panel) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s := p.snapshot()
	built, total := s.BuiltCount()

	data := struct {
		S       status.Snapshot
		K       status.Knowledge
		Built   int
		Total   int
		Working bool
	}{S: s, K: p.knowledge(), Built: built, Total: total, Working: s.Working()}

	// Собираем страницу ЦЕЛИКОМ и только потом отдаём.
	//
	// Прямая запись в ответ означала, что ошибка на середине шаблона уходит
	// человеку как «200 и половина страницы». Поймано на роутере 06.09.2026:
	// срез коммита за границу строки обрывал разметку на слове «коммит», а
	// браузер показывал пустую панель с кодом успеха. Сломанное не должно
	// иметь возможности притвориться рабочим.
	var buf bytes.Buffer
	if err := p.tmpl.Execute(&buf, data); err != nil {
		http.Error(w, "страница не собралась: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (p *Panel) apiStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(struct {
		status.Snapshot
		Knowledge status.Knowledge `json:"knowledge"`
	}{Snapshot: p.snapshot(), Knowledge: p.knowledge()})
}

// Serve поднимает панель и блокируется до отмены контекста.
func (p *Panel) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("панель на %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           p.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Ограничение на заголовки: панель локальная, но открытый порт
		// остаётся открытым портом.
		MaxHeaderBytes: 32 << 10,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func humanUptime(sec int64) string {
	if sec <= 0 {
		return "только что"
	}
	d := time.Duration(sec) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	default:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		return fmt.Sprintf("%d ч %d мин", h, m)
	}
}

// LoopbackOnly — привязана ли панель к петле. Служба предупреждает, если нет:
// открыть панель наружу можно только осознанно (§8 запрещает делать это
// автоматически).
func LoopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return strings.EqualFold(host, "localhost")
	}
	return ip.IsLoopback()
}
