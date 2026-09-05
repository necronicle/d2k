package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/necronicle/d2k/internal/detect"
	"github.com/necronicle/d2k/internal/plan"
)

// cmdCut — где резать приветствие, чтобы разбор коробки разошёлся с разбором
// сервера.
//
// Отдельный прибор, а не режим контроллера: он отвечает на вопрос о КОРОБКЕ и
// должен работать до того, как у нас есть хоть один план.
func cmdCut(args []string, out, errOut *os.File) int {
	fs := flag.NewFlagSet("cut", flag.ContinueOnError)
	fs.SetOutput(errOut)
	target := fs.String("target", "", "мишень host:port (обязательно)")
	name := fs.String("sni", "", "имя в приветствии (обязательно)")
	at := fs.Int("at", -1, "резать в этом месте; не задано — перебрать осмысленные")
	gapMS := fs.Int("gap", 0, "пауза между кусками, мс")
	repeat := fs.Int("repeat", 1, "сколько раз повторить каждый опыт")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *name == "" {
		fmt.Fprintln(errOut, "нужны -target host:port и -sni имя")
		return 2
	}

	hello, err := plan.Hello(*name, 0x30)
	if err != nil {
		fmt.Fprintf(errOut, "приветствие не собралось: %v\n", err)
		return 2
	}
	sniAt := detect.SNIAt(hello, *name)

	// Места разреза выведены из устройства приветствия, а не выбраны на вкус.
	// Каждое отвечает на свой вопрос о том, где коробка теряет разбор.
	type probe struct {
		what   string
		splits []int
	}
	var probes []probe
	if *at >= 0 {
		probes = []probe{{fmt.Sprintf("разрез на %d", *at), []int{*at}}}
	} else {
		probes = []probe{
			{"целиком (как есть)", nil},
			{"после первого байта записи", []int{1}},
			{"после заголовка записи", []int{5}},
			{"перед именем", []int{sniAt}},
			{"посреди имени", []int{sniAt + len(*name)/2}},
			{"после имени", []int{sniAt + len(*name)}},
			{"первый байт и середина имени", []int{1, sniAt + len(*name)/2}},
		}
	}

	fmt.Fprintf(out, "мишень %s, имя %s, приветствие %d байт, имя со смещения %d\n\n",
		*target, *name, len(hello), sniAt)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	for _, p := range probes {
		if sniAt < 0 && p.splits != nil {
			continue
		}
		for i := 0; i < *repeat; i++ {
			r := detect.Send(ctx, *target, hello, detect.Options{
				What:   p.what,
				Splits: p.splits,
				Gap:    time.Duration(*gapMS) * time.Millisecond,
			})
			fmt.Fprintln(out, r)
		}
	}
	return 0
}
