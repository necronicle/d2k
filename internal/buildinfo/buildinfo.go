// Package buildinfo — что именно за сборка сейчас работает.
//
// Значения подставляются линкером на сборке (см. scripts/build.sh). Без них
// программа обязана честно сказать «неизвестно», а не выдумать номер: по
// требованию §7.3 документа установщик и панель показывают канал, версию и
// commit, и показанное должно соответствовать тому, что реально запущено.
package buildinfo

import (
	"fmt"
	"runtime"
)

var (
	// Version — тег или «dev», если собрано вне релиза.
	Version = "dev"
	// Commit — полный хеш коммита; пустой, если сборка не из дерева git.
	Commit = ""
	// Date — время сборки в RFC3339, UTC.
	Date = ""
	// Dirty — «1», если в дереве были незакоммиченные правки.
	Dirty = ""
)

// Short — одна строка для логов и заголовков.
func Short() string {
	c := Commit
	if len(c) > 12 {
		c = c[:12]
	}
	if c == "" {
		c = "неизвестен"
	}
	s := fmt.Sprintf("d2k %s (%s)", Version, c)
	if Dirty == "1" {
		s += " с правками"
	}
	return s
}

// Full — многострочный вывод для `d2k version`.
func Full() string {
	c := Commit
	if c == "" {
		c = "неизвестен"
	}
	d := Date
	if d == "" {
		d = "неизвестно"
	}
	dirty := "нет"
	if Dirty == "1" {
		dirty = "ДА — сборка не воспроизводима из тега"
	}
	return fmt.Sprintf(""+
		"версия:        %s\n"+
		"коммит:        %s\n"+
		"собрано:       %s\n"+
		"правки в дереве: %s\n"+
		"платформа:     %s/%s\n"+
		"тулчейн:       %s\n",
		Version, c, d, dirty, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
