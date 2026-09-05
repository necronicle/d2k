// Подкоманда control — контроллер: связь датапата и каталога.
//
// Отдельный процесс от датапата намеренно (§7.1): падение планировщика не
// должно ронять разбор пакетов. Если этот процесс умрёт, датапат продолжит
// исполнять уже поставленные планы и наблюдать, а трафик не встанет.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/control"
	"github.com/necronicle/d2k/internal/controller"
)

func cmdControl(args []string, out, errOut *os.File) int {
	fs := flag.NewFlagSet("control", flag.ContinueOnError)
	fs.SetOutput(errOut)
	sock := fs.String("socket", "", "управляющий сокет датапата (умолчание из конфигурации)")
	catPath := fs.String("catalog", "", "файл каталога (умолчание из конфигурации)")
	decoy := fs.String("decoy", "", "имя в приманке (умолчание из конфигурации)")
	once := fs.Bool("once", false, "выйти, когда датапат закроет соединение")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	c, ok := loadConfig(errOut)
	if !ok {
		return 1
	}
	if *sock == "" {
		*sock = c.ControlSocket
	}
	if *catPath == "" {
		*catPath = c.CatalogPath()
	}
	if *decoy == "" {
		*decoy = c.DecoySNI
	}
	if *sock == "" || *catPath == "" {
		fmt.Fprintf(errOut, "не заданы ни сокет, ни каталог\n")
		return 2
	}

	store, err := catalog.Open(*catPath)
	if err != nil {
		// Открытие вернуло каталог и ошибку одновременно — это откат на
		// предыдущую версию. Работать можно, но человек обязан знать: решения
		// принимаются по этому знанию.
		if store == nil {
			fmt.Fprintf(errOut, "каталог: %v\n", err)
			return 1
		}
		fmt.Fprintf(errOut, "внимание: %v\n", err)
	}

	conn, err := control.Dial(*sock)
	if err != nil {
		fmt.Fprintf(errOut, "датапат на %s не отвечает: %v\n", *sock, err)
		return 1
	}
	defer conn.Close()

	ctrl := controller.New(conn, store, out)
	ctrl.SetDecoy(*decoy)

	boxes := len(store.Catalog().Boxes)
	fmt.Fprintf(out, "контроллер: каталог %s, изученных коробок %d\n", *catPath, boxes)
	if boxes == 0 {
		// Пустая база при первом запуске — норма (§2.2), и говорить об этом
		// надо прямо: иначе человек решит, что что-то не загрузилось.
		fmt.Fprintf(out, "база пуста — это первый запуск, а не сбой.\n")
	}
	if err := ctrl.Sync(); err != nil {
		fmt.Fprintf(errOut, "не поставить планы подтверждённых привязок: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// Разрываем чтение, чтобы Run вернулся.
		_ = conn.Close()
	}()

	runErr := ctrl.Run()

	// §5.5 требует описанного пути на SIGTERM, и «накопленное потерялось»
	// таким путём не является.
	if wrote, err := store.FlushNow(time.Now()); err != nil {
		fmt.Fprintf(errOut, "каталог не записан при остановке: %v\n", err)
		return 1
	} else if wrote {
		fmt.Fprintf(out, "каталог записан при остановке.\n")
	}

	if runErr != nil && !errors.Is(runErr, io.EOF) && ctx.Err() == nil {
		fmt.Fprintf(errOut, "контроллер остановлен: %v\n", runErr)
		if !*once {
			return 1
		}
	}
	return 0
}
