// Package config — собственная конфигурация d2k.
//
// Своя, а не унаследованная от z2k: там конфигурация генерируется целиком из
// шаблона на каждой пересборке, и пользовательские правки в ней живут только
// потому, что их отдельно вычитывают и вписывают обратно. Здесь наоборот —
// файл принадлежит пользователю, а программа лишь читает его и заполняет
// умолчаниями то, чего нет.
//
// Три правила, которые задают всё остальное:
//
//  1. Непонятая строка — ошибка, а не повод молча взять умолчание. Опечатка в
//     имени ключа не должна выглядеть как «настройка не сработала».
//  2. Неизвестный ключ сохраняется и показывается, а не выбрасывается. Иначе
//     откат на старую версию потеряет настройки новой.
//  3. У схемы есть номер. Формат состояния и формат конфигурации будут
//     меняться, и миграция должна опираться на объявленную версию, а не на
//     угадывание по содержимому.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// SchemaCurrent — версия формата, которую понимает этот код.
const SchemaCurrent = 1

// Mode — что d2k делает с трафиком.
type Mode string

const (
	// ModeOff — служба запущена, но в трафик не вмешивается и не наблюдает.
	ModeOff Mode = "off"
	// ModeObserve — только наблюдение: очередь читается, вердикт всегда
	// «пропустить». Это режим этапов A–C; активного обхода в нём нет.
	ModeObserve Mode = "observe"
)

// Config — разобранная конфигурация. Поля заполнены всегда: либо из файла,
// либо умолчанием.
type Config struct {
	Schema int
	Mode   Mode

	// PanelListen — адрес локальной панели. Пустая строка выключает её.
	PanelListen string

	// StateDir — где живут каталог коробок и журнал решений.
	StateDir string

	// QueueNum — номер NFQUEUE для датапата.
	QueueNum int

	// Unknown — ключи, которых этот код не знает. Сохраняются, чтобы откат на
	// предыдущую версию не терял настройки следующей.
	Unknown map[string]string

	// Path — откуда прочитано; пустая строка, если файла не было.
	Path string
	// Existed — был ли файл. Отличать «файл отсутствует» от «файл пуст».
	Existed bool
}

// Default — конфигурация до чтения файла.
func Default() Config {
	return Config{
		Schema:      SchemaCurrent,
		Mode:        ModeObserve,
		PanelListen: "127.0.0.1:8090",
		StateDir:    "/opt/d2k/state",
		QueueNum:    2000,
		Unknown:     map[string]string{},
	}
}

// DefaultPath — путь к файлу конфигурации. Переопределяется переменной
// окружения, чтобы стенд и роутер не мешали друг другу.
func DefaultPath() string {
	if p := os.Getenv("D2K_CONFIG"); p != "" {
		return p
	}
	return "/opt/d2k/config"
}

// Load читает конфигурацию. Отсутствие файла — не ошибка: это первый запуск,
// и умолчания заведомо рабочие. Ошибка разбора — ошибка.
func Load(path string) (Config, error) {
	c := Default()
	c.Path = path

	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, fmt.Errorf("конфигурация %s: %w", path, err)
	}
	defer fh.Close()
	c.Existed = true

	sc := bufio.NewScanner(fh)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		key, val, ok := strings.Cut(t, "=")
		if !ok {
			return c, fmt.Errorf("%s:%d: строка без «=»: %q", path, line, t)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"`)

		switch key {
		case "SCHEMA":
			n, err := strconv.Atoi(val)
			if err != nil {
				return c, fmt.Errorf("%s:%d: SCHEMA должно быть числом, а не %q", path, line, val)
			}
			c.Schema = n
		case "MODE":
			switch Mode(val) {
			case ModeOff, ModeObserve:
				c.Mode = Mode(val)
			default:
				return c, fmt.Errorf("%s:%d: MODE=%q, допустимы off и observe", path, line, val)
			}
		case "PANEL_LISTEN":
			c.PanelListen = val
		case "STATE_DIR":
			if val != "" && !filepath.IsAbs(val) {
				return c, fmt.Errorf("%s:%d: STATE_DIR должен быть абсолютным путём, а не %q", path, line, val)
			}
			c.StateDir = val
		case "QUEUE_NUM":
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 || n > 65535 {
				return c, fmt.Errorf("%s:%d: QUEUE_NUM=%q, нужно число 0..65535", path, line, val)
			}
			c.QueueNum = n
		default:
			c.Unknown[key] = val
		}
	}
	if err := sc.Err(); err != nil {
		return c, fmt.Errorf("конфигурация %s: %w", path, err)
	}

	if c.Schema > SchemaCurrent {
		return c, fmt.Errorf("%s: SCHEMA=%d новее, чем понимает эта сборка (%d) — обновите d2k, а не правьте файл",
			path, c.Schema, SchemaCurrent)
	}
	return c, nil
}

// UnknownKeys — отсортированный список непонятых ключей, чтобы вывод был
// одинаковым от запуска к запуску.
func (c Config) UnknownKeys() []string {
	keys := make([]string, 0, len(c.Unknown))
	for k := range c.Unknown {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Render — конфигурация в том виде, в каком её можно записать обратно.
// Неизвестные ключи сохраняются.
func (c Config) Render() string {
	var b strings.Builder
	b.WriteString("# Конфигурация d2k. Файл принадлежит вам: программа его читает,\n")
	b.WriteString("# но не переписывает при обновлении.\n")
	fmt.Fprintf(&b, "SCHEMA=%d\n\n", c.Schema)
	b.WriteString("# off — служба запущена, но трафик не трогает и не наблюдает.\n")
	b.WriteString("# observe — только наблюдение, вердикт всегда «пропустить».\n")
	fmt.Fprintf(&b, "MODE=%s\n\n", c.Mode)
	b.WriteString("# Локальная панель. Пустое значение выключает её.\n")
	fmt.Fprintf(&b, "PANEL_LISTEN=%s\n\n", c.PanelListen)
	b.WriteString("# Каталог коробок и журнал решений.\n")
	fmt.Fprintf(&b, "STATE_DIR=%s\n\n", c.StateDir)
	b.WriteString("# Номер очереди NFQUEUE для датапата.\n")
	fmt.Fprintf(&b, "QUEUE_NUM=%d\n", c.QueueNum)
	if len(c.Unknown) > 0 {
		b.WriteString("\n# Ключи, которых эта сборка не знает. Сохранены намеренно:\n")
		b.WriteString("# откат на предыдущую версию не должен терять настройки следующей.\n")
		for _, k := range c.UnknownKeys() {
			fmt.Fprintf(&b, "%s=%s\n", k, c.Unknown[k])
		}
	}
	return b.String()
}
