package status

import "time"

// Здесь — то, что d2k УЗНАЛ, в виде, годном для показа. Отдельно от Snapshot
// намеренно: снимок отвечает на вопрос «что за сборка и что в ней написано», а
// это — на вопрос «что она выучила на этой линии».
//
// §8 требует различать три вещи, которые легко слить в одну: «распознаём
// коробку», «проверяем готовую стратегию» и «ищем новое решение». Поэтому у
// поиска есть Source кандидата, а у привязки — уровень доказательства.

// SignalView — одна примета коробки, как её показывают человеку.
type SignalView struct {
	Kind string `json:"kind"`
	// Human — примета словами. Собирается здесь, а не в шаблоне: шаблон не
	// должен знать, что 0x88 это ToS, а 54321 — идентификатор IP.
	Human string `json:"human"`
	Seen  int    `json:"seen"`
}

// BindingView — подтверждённая привязка цели.
type BindingView struct {
	Target string `json:"target"`
	Kind   string `json:"kind"`
	// Level — уровень доказательства по §4.2. Числом, а не словом «работает»:
	// уровень 2 нельзя показывать как уровень 4.
	Level     int       `json:"level"`
	LevelName string    `json:"level_name"`
	Successes int       `json:"successes"`
	Confirmed time.Time `json:"confirmed"`
	Enabled   bool      `json:"enabled"`
}

// PlanView — проверенный план коробки.
type PlanView struct {
	ID        string `json:"id"`
	Proto     string `json:"proto"`
	Successes int    `json:"successes"`
	Enabled   bool   `json:"enabled"`
	// Human — что план делает, словами. Техническое представление
	// раскрывается отдельно (§8, вид «Планы»).
	Human string `json:"human"`
	Text  string `json:"text"`
}

// BoxView — изученная модель поведения DPI-коробки.
//
// Карточка обозначает МОДЕЛЬ ПОВЕДЕНИЯ. Ни производителя, ни физического
// адреса, ни экземпляра оборудования здесь нет и быть не может: §8 это прямо
// запрещает, а §3 объясняет почему — совпавшее поведение может принадлежать
// нескольким устройствам.
type BoxView struct {
	ID       string        `json:"id"`
	Created  time.Time     `json:"created"`
	Updated  time.Time     `json:"updated"`
	Signals  []SignalView  `json:"signals"`
	Plans    []PlanView    `json:"plans"`
	Bindings []BindingView `json:"bindings"`
}

// SearchView — идущий поиск. Это ЖИВОЕ состояние процесса, а не история:
// закрытый неудачей поиск исчезает и никуда не записывается (§2.3, §8).
type SearchView struct {
	Target string `json:"target"`
	// Phase — что именно сейчас происходит. §8 требует различать
	// «распознаём», «проверяем готовое» и «ищем новое».
	Phase    string    `json:"phase"`
	Since    time.Time `json:"since"`
	Attempts int       `json:"attempts"`
	Probes   int       `json:"probes"`
	// Candidate — что проверяется прямо сейчас, и откуда он взялся.
	Candidate string `json:"candidate"`
	Source    string `json:"source"`
}

// Knowledge — всё, что панель показывает про узнанное.
type Knowledge struct {
	// Linked — подключён ли контроллер к датапату. Без него панель показывает
	// прошлое знание и НЕ показывает происходящее; путать это нельзя.
	Linked     bool         `json:"linked"`
	LinkNote   string       `json:"link_note"`
	CatalogAt  string       `json:"catalog_at"`
	Boxes      []BoxView    `json:"boxes"`
	Searches   []SearchView `json:"searches"`
	Targets    int          `json:"targets"`
	Confirms   int          `json:"confirms"`
	ProbesUsed int          `json:"probes_used"`
}

// LevelName — уровень доказательства словами (§4.2).
//
// Слова подобраны так, чтобы уровень 2 нельзя было прочитать как уровень 4:
// «сервер ответил» и «обмен прошёл» — разные утверждения, и разница между
// ними здесь единственное, что важно.
func LevelName(n int) string {
	switch n {
	case 1:
		return "транспорт установился"
	case 2:
		return "сервер ответил"
	case 3:
		return "обмен прошёл"
	case 4:
		return "прикладной обмен в проверенном объёме"
	case 5:
		return "подтверждён последующими соединениями"
	default:
		return "уровень не определён"
	}
}
