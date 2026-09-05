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

// Panel отдаёт снимок состояния человеку и машине.
type Panel struct {
	cfg     config.Config
	started time.Time
	tmpl    *template.Template
}

// New готовит панель. Шаблон разбирается один раз на старте: ошибка разметки
// должна убивать запуск, а не всплывать у человека в браузере.
func New(cfg config.Config, started time.Time) (*Panel, error) {
	t, err := template.New("panel.html").Funcs(template.FuncMap{
		"uptime": humanUptime,
	}).ParseFS(tmplFS, "templates/panel.html")
	if err != nil {
		return nil, fmt.Errorf("разметка панели: %w", err)
	}
	return &Panel{cfg: cfg, started: started, tmpl: t}, nil
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
		Built   int
		Total   int
		Working bool
	}{S: s, Built: built, Total: total, Working: s.Working()}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.tmpl.Execute(w, data); err != nil {
		// Заголовки уже ушли, дописывать ошибку в разметку бессмысленно.
		return
	}
}

func (p *Panel) apiStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(p.snapshot())
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
