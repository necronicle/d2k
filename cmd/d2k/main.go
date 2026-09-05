// Команда d2k — CLI и служба.
//
// На этапе A здесь нет ни перехвата пакетов, ни обхода. Это намеренно: по §11
// документа «готово» и «есть дизайн» — разные вещи, и программа обязана
// говорить о себе правду. Поэтому `status` прямо пишет, что датапат не
// реализован, вместо того чтобы показывать зелёный прочерк.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/necronicle/d2k/internal/buildinfo"
	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/config"
	"github.com/necronicle/d2k/internal/control"
	"github.com/necronicle/d2k/internal/controller"
	"github.com/necronicle/d2k/internal/status"
	"github.com/necronicle/d2k/internal/web"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w *os.File) {
	fmt.Fprintf(w, `%s

Использование: d2k <команда> [флаги]

  version              что за сборка запущена
  config [-write]      показать конфигурацию; -write создать файл с умолчаниями
  status               что программа делает прямо сейчас
  plan <подкоманда>    перевод плана между текстовой и канонической формой
  control              контроллер: связь датапата и каталога коробок
  serve [-log FILE]    запустить службу и локальную панель

Путь к конфигурации: переменная D2K_CONFIG, иначе %s
`, buildinfo.Short(), config.DefaultPath())
}

func run(args []string, out, errOut *os.File) int {
	if len(args) == 0 {
		usage(errOut)
		return 2
	}

	switch args[0] {
	case "version", "-v", "--version":
		fmt.Fprint(out, buildinfo.Full())
		return 0

	case "config":
		fs := flag.NewFlagSet("config", flag.ContinueOnError)
		fs.SetOutput(errOut)
		write := fs.Bool("write", false, "создать файл конфигурации с умолчаниями, если его нет")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		return cmdConfig(*write, out, errOut)

	case "status":
		return cmdStatus(out, errOut)

	case "plan":
		return cmdPlan(args[1:], out, errOut)

	case "control":
		return cmdControl(args[1:], out, errOut)

	case "serve":
		return cmdServe(args[1:], out, errOut)

	case "help", "-h", "--help":
		usage(out)
		return 0

	default:
		fmt.Fprintf(errOut, "неизвестная команда %q\n", args[0])
		usage(errOut)
		return 2
	}
}

func loadConfig(errOut *os.File) (config.Config, bool) {
	c, err := config.Load(config.DefaultPath())
	if err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return c, false
	}
	return c, true
}

func cmdConfig(write bool, out, errOut *os.File) int {
	c, ok := loadConfig(errOut)
	if !ok {
		return 1
	}

	if write {
		if c.Existed {
			fmt.Fprintf(errOut, "файл %s уже есть — не перезаписываю\n", c.Path)
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
			fmt.Fprintf(errOut, "не создать каталог: %v\n", err)
			return 1
		}
		if err := os.WriteFile(c.Path, []byte(c.Render()), 0o644); err != nil {
			fmt.Fprintf(errOut, "не записать конфигурацию: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "создан %s\n", c.Path)
		return 0
	}

	if !c.Existed {
		fmt.Fprintf(out, "# файла %s нет — показаны умолчания\n", c.Path)
	}
	fmt.Fprint(out, c.Render())
	if n := len(c.Unknown); n > 0 {
		fmt.Fprintf(errOut, "\nвнимание: %d ключ(ей) эта сборка не знает: %v\n", n, c.UnknownKeys())
	}
	return 0
}

func cmdStatus(out, errOut *os.File) int {
	c, ok := loadConfig(errOut)
	if !ok {
		return 1
	}
	// Тот же снимок, что показывает панель. Два источника разошлись бы, и
	// человек получил бы два разных ответа на один вопрос.
	s := status.Collect(c, time.Time{})

	fmt.Fprintf(out, "%s\n\n", buildinfo.Short())

	src := s.ConfigPath
	if !s.ConfigExists {
		src += " (файла нет, действуют умолчания)"
	}
	fmt.Fprintf(out, "конфигурация:  %s\n", src)
	fmt.Fprintf(out, "режим:         %s\n", s.Mode)
	fmt.Fprintf(out, "каталог:       %s (%s)\n", s.StateDir, s.StateDirNote)
	if s.PanelListen == "" {
		fmt.Fprintf(out, "панель:        выключена\n")
	} else {
		fmt.Fprintf(out, "панель:        %s\n", s.PanelListen)
	}
	fmt.Fprintf(out, "очередь:       %d\n", s.QueueNum)

	built, total := s.BuiltCount()
	fmt.Fprintf(out, "\nобработка (построено %d из %d):\n", built, total)
	for _, st := range s.Stages {
		mark := "нет"
		if st.Built {
			mark = "есть"
		}
		fmt.Fprintf(out, "  %-4s %-20s %s\n", mark, st.Title, st.Detail)
	}

	fmt.Fprintf(out, "\nпоказаний нет:\n")
	for _, a := range s.Absent {
		fmt.Fprintf(out, "  %-22s %s\n", a.Title, a.Detail)
	}

	if len(s.UnknownKeys) > 0 {
		fmt.Fprintf(out, "\nнепонятые ключи конфигурации: %v\n", s.UnknownKeys)
	}
	return 0
}

func cmdServe(args []string, out, errOut *os.File) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	logPath := fs.String("log", "", "писать вывод сюда вместо stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *logPath != "" {
		// Служба уходит в фон через start-stop-daemon, который потоки
		// потомка не перенаправляет. Раз файл нужен нам, открываем его сами
		// — до первой печати, иначе стартовые строки уйдут в никуда, и
		// диагностировать станет нечем. Ровно это и случилось на первой
		// установке.
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintf(errOut, "не открыть журнал %s: %v\n", *logPath, err)
			return 1
		}
		out, errOut = f, f
	}

	c, ok := loadConfig(errOut)
	if !ok {
		return 1
	}
	if c.PanelListen == "" && c.ControlSocket == "" {
		// Без панели и без датапата служба не делает ничего наблюдаемого.
		// Запускать её в таком виде — значит оставить человеку процесс,
		// который выглядит работающим обходом.
		fmt.Fprintf(errOut, "PANEL_LISTEN и CONTROL_SOCKET пусты — запускать нечего.\n")
		return 3
	}

	started := time.Now()
	panel, err := web.New(c, started)
	if err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 1
	}

	// Каталог и контроллер. Панель работает и без них — просто честно
	// говорит, что происходящего не видит: показывать прошлое знание за
	// настоящее нельзя.
	var stopCtl func()
	if store, err := catalog.Open(c.CatalogPath()); err != nil && store == nil {
		panel.SetLinkNote(fmt.Sprintf("каталог %s не читается: %v", c.CatalogPath(), err))
	} else {
		if err != nil {
			// Откат на предыдущую версию каталога. Работать можно, но знать
			// об этом обязательно.
			fmt.Fprintf(errOut, "внимание: %v\n", err)
		}
		conn, derr := control.Dial(c.ControlSocket)
		if derr != nil {
			panel.SetLinkNote(fmt.Sprintf("датапат на %s не отвечает", c.ControlSocket))
		} else {
			ctrl := controller.New(conn, store, out)
			ctrl.SetDecoy(c.DecoySNI)
			if err := ctrl.Sync(); err != nil {
				fmt.Fprintf(errOut, "не поставить планы подтверждённых привязок: %v\n", err)
			}
			panel.SetKnowledge(ctrl)
			go func() {
				if err := ctrl.Run(); err != nil {
					fmt.Fprintf(errOut, "контроллер остановлен: %v\n", err)
				}
			}()
			stopCtl = func() {
				_ = conn.Close()
				// §5.5: у остановки должен быть описанный путь, и
				// «накопленное потерялось» им не является.
				if wrote, err := store.FlushNow(time.Now()); err != nil {
					fmt.Fprintf(errOut, "каталог не записан при остановке: %v\n", err)
				} else if wrote {
					fmt.Fprintf(out, "каталог записан при остановке.\n")
				}
			}
		}
	}
	if stopCtl != nil {
		defer stopCtl()
	}

	fmt.Fprintf(out, "%s\n", buildinfo.Short())
	fmt.Fprintf(out, "панель: http://%s/\n", c.PanelListen)
	// Говорим это при каждом запуске, а не только в панели: человек, поднявший
	// службу из консоли, должен узнать правду до того, как решит, что обход
	// заработал.
	if stopCtl == nil {
		// Говорим это при каждом запуске, а не только в панели: человек,
		// поднявший службу из консоли, должен узнать правду до того, как
		// решит, что обход заработал.
		fmt.Fprintf(out, "контроллер не подключён к датапату — обход не подбирается.\n")
	}
	if !web.LoopbackOnly(c.PanelListen) {
		fmt.Fprintf(errOut, "внимание: панель слушает не на петле (%s) и доступна из сети. Аутентификации у неё нет.\n", c.PanelListen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := panel.Serve(ctx, c.PanelListen); err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 1
	}
	fmt.Fprintf(out, "остановлено\n")
	return 0
}
