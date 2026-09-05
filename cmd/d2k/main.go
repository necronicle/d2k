// Команда d2k — CLI и служба.
//
// На этапе A здесь нет ни перехвата пакетов, ни обхода. Это намеренно: по §11
// документа «готово» и «есть дизайн» — разные вещи, и программа обязана
// говорить о себе правду. Поэтому `status` прямо пишет, что датапат не
// реализован, вместо того чтобы показывать зелёный прочерк.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/necronicle/d2k/internal/buildinfo"
	"github.com/necronicle/d2k/internal/config"
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
  serve                запустить службу

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

	case "serve":
		return cmdServe(out, errOut)

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

	fmt.Fprintf(out, "%s\n\n", buildinfo.Short())

	src := c.Path
	if !c.Existed {
		src += " (файла нет, действуют умолчания)"
	}
	fmt.Fprintf(out, "конфигурация:  %s\n", src)
	fmt.Fprintf(out, "режим:         %s\n", c.Mode)
	fmt.Fprintf(out, "каталог:       %s%s\n", c.StateDir, dirNote(c.StateDir))
	if c.PanelListen == "" {
		fmt.Fprintf(out, "панель:        выключена\n")
	} else {
		fmt.Fprintf(out, "панель:        %s\n", c.PanelListen)
	}
	fmt.Fprintf(out, "очередь:       %d\n", c.QueueNum)

	// Пока датапата нет, писать что-либо про наблюдение трафика нельзя: это
	// ровно тот случай, когда «неизвестное показывается как исправное».
	fmt.Fprintf(out, "\nдатапат:       НЕ РЕАЛИЗОВАН (этап A)\n")
	fmt.Fprintf(out, "наблюдение:    нет — пакеты не читаются\n")
	fmt.Fprintf(out, "обход:         нет — ни один план не исполняется\n")
	fmt.Fprintf(out, "каталог коробок: пуст — хранилище ещё не реализовано\n")

	if len(c.Unknown) > 0 {
		fmt.Fprintf(out, "\nнепонятые ключи конфигурации: %v\n", c.UnknownKeys())
	}
	return 0
}

func dirNote(p string) string {
	if p == "" {
		return " (не задан)"
	}
	st, err := os.Stat(p)
	switch {
	case os.IsNotExist(err):
		return " (не создан)"
	case err != nil:
		return fmt.Sprintf(" (недоступен: %v)", err)
	case !st.IsDir():
		return " (существует, но это не каталог)"
	default:
		return ""
	}
}

func cmdServe(out, errOut *os.File) int {
	c, ok := loadConfig(errOut)
	if !ok {
		return 1
	}
	// Отказ, а не тихий запуск пустой службы: запущенный d2k, который ничего
	// не делает, выглядит для человека как работающий обход. §2.3 документа
	// запрещает показывать неизвестное исправным, и это тот же случай.
	fmt.Fprintf(errOut, "%s\n", buildinfo.Short())
	fmt.Fprintf(errOut, "serve пока не реализован: датапат отсутствует, режим %q исполнять нечем.\n", c.Mode)
	fmt.Fprintf(errOut, "Запущенная служба без датапата выглядела бы работающей, поэтому запуск отклонён.\n")
	_ = out
	return 3
}
