// Package status — единственный источник правды о том, что d2k делает сейчас.
//
// Один снимок и для `d2k status`, и для панели. Если бы их было два, они бы
// разошлись, и человек получил бы два разных ответа на один вопрос — а
// вопрос здесь ровно один и довольно неприятный: работает обход или нет.
//
// Главное свойство снимка: он описывает возможности через то, ПОСТРОЕНЫ ли
// они, а не через то, здоровы ли они. Ненаписанная возможность не бывает
// «в порядке», и показывать её зелёной нельзя (§2.3 документа).
package status

import (
	"fmt"
	"os"
	"time"

	"github.com/necronicle/d2k/internal/buildinfo"
	"github.com/necronicle/d2k/internal/config"
)

// Stage — звено обработки. Из них складывается цепочка, которую показывает
// панель: от чтения пакета до применения плана.
type Stage struct {
	// Key — устойчивый идентификатор для разметки и тестов.
	Key string `json:"key"`
	// Title — как звено называется для человека.
	Title string `json:"title"`
	// Built — существует ли оно вообще. Не «здорово», а именно «написано».
	Built bool `json:"built"`
	// Detail — что именно есть или чего нет. Заполняется всегда: «нет» без
	// объяснения читается как поломка, а это не поломка.
	Detail string `json:"detail"`
}

// Snapshot — состояние на момент запроса.
type Snapshot struct {
	Taken time.Time `json:"taken"`

	Version string `json:"version"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
	Dirty   bool   `json:"dirty"`

	ConfigPath    string    `json:"config_path"`
	ConfigExists  bool      `json:"config_exists"`
	Mode          string    `json:"mode"`
	PanelListen   string    `json:"panel_listen"`
	StateDir      string    `json:"state_dir"`
	StateDirNote  string    `json:"state_dir_note"`
	QueueNum      int       `json:"queue_num"`
	UnknownKeys   []string  `json:"unknown_keys"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`

	Stages []Stage `json:"stages"`

	// Absent — показания, которых у панели нет, и причина. Существует ради
	// того, чтобы отсутствующее не выглядело нулём: «0 обойдённых целей» и
	// «мы ничего не считаем» — разные утверждения.
	Absent []Stage `json:"absent"`
}

// Collect собирает снимок. startedAt — момент запуска службы; нулевое время
// означает, что снимок берётся из CLI, а не из работающей службы.
func Collect(c config.Config, startedAt time.Time) Snapshot {
	now := time.Now()
	s := Snapshot{
		Taken:        now,
		Version:      buildinfo.Version,
		Commit:       buildinfo.Commit,
		Built:        buildinfo.Date,
		Dirty:        buildinfo.Dirty == "1",
		ConfigPath:   c.Path,
		ConfigExists: c.Existed,
		Mode:         string(c.Mode),
		PanelListen:  c.PanelListen,
		StateDir:     c.StateDir,
		StateDirNote: describeDir(c.StateDir),
		QueueNum:     c.QueueNum,
		UnknownKeys:  c.UnknownKeys(),
		StartedAt:    startedAt,
	}
	if !startedAt.IsZero() {
		s.UptimeSeconds = int64(now.Sub(startedAt).Seconds())
	}

	// Порядок звеньев — порядок обработки, а не важности. Панель рисует их
	// слева направо, и обрыв цепочки виден там, где он есть на самом деле.
	//
	// Звенья датапата ставятся ЗАГЛУШКАМИ и уточняются в ApplyChain по живому
	// состоянию. Раньше они были зашиты в «не написано» навсегда — и панель
	// показывала «датапат не написан, построено 2 из 6» при работающей
	// очереди, применяющихся планах и заполняющемся каталоге. Прибор, который
	// врёт о самом себе, отравляет всё, что через него смотрят.
	s.Stages = []Stage{
		{Key: "config", Title: "Конфигурация", Built: true,
			Detail: configDetail(c)},
		{Key: "capture", Title: "Чтение пакетов", Built: false,
			Detail: "Контроллер не подключён к датапату — сказать, читаются ли пакеты, нечем."},
		{Key: "flow", Title: "Состояние потоков", Built: false,
			Detail: "Контроллер не подключён к датапату."},
		{Key: "plan", Title: "Исполнение планов", Built: false,
			Detail: "Контроллер не подключён к датапату: применяется ли обход, отсюда не видно."},
		{Key: "boxes", Title: "Каталог коробок", Built: false,
			Detail: "Каталог не открыт."},
		{Key: "panel", Title: "Панель", Built: true,
			Detail: "Показывает этот снимок."},
	}

	s.Absent = []Stage{
		{Key: "outages", Title: "Здоровье наблюдения",
			Detail: "Нечем: сколько пакетов не дошло до очереди, снаружи не измеряется."},
	}
	return s
}

// ApplyChain приводит звенья обработки в соответствие с ЖИВЫМ состоянием.
//
// Отдельным шагом, а не в New, потому что знание приходит от контроллера, а
// снимок собирается и без него — и тогда честный ответ «не подключён», а не
// «не написано».
func (s *Snapshot) ApplyChain(k Knowledge) {
	for i := range s.Stages {
		st := &s.Stages[i]
		switch st.Key {
		case "capture":
			if k.Linked {
				st.Built = true
				st.Detail = "Очередь ядра открыта, пакеты читаются: контроллер получает события датапата."
			}
		case "flow":
			if k.Linked {
				st.Built = true
				st.Detail = "Датапат ведёт учёт соединений и сообщает о подозрениях."
			}
		case "plan":
			if k.Linked {
				st.Built = true
				st.Detail = "Планы ставятся датапату и исполняются на живых соединениях."
			}
		case "boxes":
			if k.CatalogAt != "" {
				st.Built = true
				st.Detail = fmt.Sprintf("Каталог %s: изученных коробок %d, целей %d.",
					k.CatalogAt, len(k.Boxes), k.Targets)
			}
		}
	}
	if !k.Linked {
		s.Absent = append(s.Absent, Stage{Key: "traffic", Title: "Наблюдаемый трафик",
			Detail: "Нечем: контроллер не подключён к датапату. Это не «ноль соединений», а отсутствие измерения."})
	}
}

func configDetail(c config.Config) string {
	if !c.Existed {
		return "Файла " + c.Path + " нет, действуют умолчания."
	}
	if len(c.Unknown) > 0 {
		return "Прочитана из " + c.Path + "; есть ключи, которых эта сборка не знает."
	}
	return "Прочитана из " + c.Path + "."
}

func describeDir(p string) string {
	if p == "" {
		return "не задан"
	}
	st, err := os.Stat(p)
	switch {
	case os.IsNotExist(err):
		return "не создан"
	case err != nil:
		return "недоступен: " + err.Error()
	case !st.IsDir():
		return "существует, но это не каталог"
	default:
		return "есть"
	}
}

// BuiltCount — сколько звеньев цепочки существует. Панель показывает это
// числом рядом с цепочкой, чтобы «две из шести» читалось до разглядывания
// картинки.
func (s Snapshot) BuiltCount() (built, total int) {
	for _, st := range s.Stages {
		if st.Built {
			built++
		}
	}
	return built, len(s.Stages)
}

// Working — делает ли d2k хоть что-нибудь с трафиком. Отдельный метод, а не
// вычисление в шаблоне: это тот ответ, ради которого панель открывают.
func (s Snapshot) Working() bool {
	for _, st := range s.Stages {
		if st.Key == "capture" && st.Built {
			return true
		}
	}
	return false
}
