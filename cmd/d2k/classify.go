package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/necronicle/d2k/internal/classify"
)

// cmdClassify — дерево вердиктов: чем именно режут и что из этого следует.
//
// Отдельная команда, а не режим cut: cut перебирает точки разреза и печатает
// все исходы разом, оставляя вывод человеку. classify задаёт вопросы ПО
// ПОРЯДКУ, останавливается, как только на них есть ответ, и сам называет
// вердикт — база → помогает ли резать вообще → контроль → граница.
func cmdClassify(args []string, out, errOut *os.File) int {
	fs := flag.NewFlagSet("classify", flag.ContinueOnError)
	fs.SetOutput(errOut)
	target := fs.String("target", "", "мишень host:port (обязательно)")
	name := fs.String("sni", "", "имя в приветствии (обязательно)")
	control := fs.String("control", "", "другое имя на ту же цель для контроля; пусто — без контроля")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *name == "" {
		fmt.Fprintln(errOut, "нужны -target host:port и -sni имя")
		return 2
	}

	tr, err := classify.TLSTrigger(*name)
	if err != nil {
		fmt.Fprintf(errOut, "триггер не собрался: %v\n", err)
		return 2
	}

	var opt classify.Options
	if *control != "" {
		ctl, err := classify.Control(*control)
		if err != nil {
			fmt.Fprintf(errOut, "контроль не собрался: %v\n", err)
			return 2
		}
		opt.Control = ctl
	}

	// Шестьдесят секунд — жёсткий предел плана (docs/superpowers/plans/
	// 2026-09-06-classify-core.md, «Бюджет времени»: «Стратегия обязана быть
	// готова за минуту, цель — пятнадцать секунд»), не число «на глаз».
	// Более мягкий потолок здесь прятал бы нарушение бюджета вместо того,
	// чтобы его показать: дерево обязано уложиться само, а не досидеть до
	// того, что ему великодушно разрешили.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r := classify.Run(ctx, *target, tr, opt)

	fmt.Fprintf(out, "вердикт: %s\n", r.Verdict)
	fmt.Fprintf(out, "причина: %s\n", r.Reason)
	if r.Boundary > 0 {
		fmt.Fprintf(out, "граница сигнатуры: байт %d\n", r.Boundary)
	}
	if r.SplitPos > 0 {
		fmt.Fprintf(out, "разрез: байт %d\n", r.SplitPos)
	}
	if r.Reassembles != nil {
		state := "нет"
		if *r.Reassembles {
			state = "есть"
		}
		fmt.Fprintf(out, "буфер пересборки: %s\n", state)
	}
	fmt.Fprintf(out, "проб отправлено: %d\n", r.Probes)

	fmt.Fprintln(out, "\nтрасса:")
	for _, s := range r.Trace {
		fmt.Fprintf(out, "  %-32s %d/%d\n", s.What, s.Pass, s.Pass+s.Fail)
	}
	return 0
}
