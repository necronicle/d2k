// Подкоманда plan — перевод между двумя формами одного плана.
//
// Каноническую форму TLV порождает ТОЛЬКО эта сторона: исполнитель на C её
// читает и не умеет писать, а разборщика текста в нём нет вовсе. Причина в
// §2.5 и в том, где живёт риск: текстовый разборщик — лишняя поверхность для
// ошибок в компоненте, чей вход приходит из сети, а падение кладёт весь
// транзитный трафик.
package main

import (
	"fmt"
	"os"

	"github.com/necronicle/d2k/internal/plan"
)

func cmdPlan(args []string, out, errOut *os.File) int {
	if len(args) == 0 {
		fmt.Fprint(errOut, `Использование: d2k plan <подкоманда>

  compile <текст> [вывод]   текст -> каноническая форма TLV (без вывода — в stdout)
  show <файл>               показать план: TLV или текст, по содержимому

Форм две, план один. Текстовая — для человека и для правки, каноническая —
для исполнителя. Перевод обратим побайтово, и это проверяется тестом.
`)
		return 2
	}

	switch args[0] {
	case "compile":
		if len(args) < 2 {
			fmt.Fprint(errOut, "compile: не задан файл с текстом плана\n")
			return 2
		}
		src, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintf(errOut, "%v\n", err)
			return 1
		}
		p, err := plan.ParseText(string(src))
		if err != nil {
			fmt.Fprintf(errOut, "план не разобран: %v\n", err)
			return 1
		}
		b, err := p.MarshalTLV()
		if err != nil {
			// Ссылка в никуда ловится здесь, а не у исполнителя: план, который
			// нельзя исполнить, не должен доехать до устройства.
			fmt.Fprintf(errOut, "план не собирается: %v\n", err)
			return 1
		}
		if len(args) >= 3 {
			if err := os.WriteFile(args[2], b, 0o644); err != nil {
				fmt.Fprintf(errOut, "%v\n", err)
				return 1
			}
			fmt.Fprintf(out, "%s: %d байт\n", args[2], len(b))
			return 0
		}
		if _, err := out.Write(b); err != nil {
			fmt.Fprintf(errOut, "%v\n", err)
			return 1
		}
		return 0

	case "show":
		if len(args) < 2 {
			fmt.Fprint(errOut, "show: не задан файл\n")
			return 2
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintf(errOut, "%v\n", err)
			return 1
		}
		// Форма определяется по содержимому, а не по расширению: расширение
		// врёт ровно тогда, когда файл скопировали не туда.
		var p plan.Plan
		if len(b) >= 4 && string(b[:4]) == "D2KP" {
			p, err = plan.UnmarshalTLV(b)
		} else {
			p, err = plan.ParseText(string(b))
		}
		if err != nil {
			fmt.Fprintf(errOut, "план не разобран: %v\n", err)
			return 1
		}
		fmt.Fprint(out, p.Text())
		return 0

	default:
		fmt.Fprintf(errOut, "неизвестная подкоманда plan %q\n", args[0])
		return 2
	}
}
