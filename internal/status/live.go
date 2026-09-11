package status

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// LiveSource — узнанное, прочитанное из файла, который пишет движок.
//
// ПОЧЕМУ ФАЙЛ, А НЕ ВТОРОЙ ЧИТАТЕЛЬ КАТАЛОГА. До 11.09.2026 панель брала
// узнанное у Go-контроллера, и он же вёл поиски. Контроллер переписан на C
// (core/sched.c) и удалён отсюда; собрать тот же вид в Go заново значило бы
// завести ВТОРОГО читателя каталога и второе представление о том, что такое
// «идущий поиск». Первый разошёлся бы со вторым в первый же день, и панель
// начала бы показывать не то, что делает движок. Вид собирает тот, кто
// единственный знает и каталог, и живые поиски, — сам движок
// (d2k_sched_write_live); здесь он только читается.
//
// Формат — ровно эта же структура Knowledge в JSON, поле в поле по её тегам.
//
// Файл читается на КАЖДЫЙ запрос панели, а не кэшируется надолго: показывать
// прошлое состояние за настоящее — ровно то, что §8 запрещает. Кэш на секунду
// защищает только от шквала запросов одной страницы.
type LiveSource struct {
	path string

	mu   sync.Mutex
	at   time.Time
	last Knowledge
}

// NewLiveSource заводит читателя файла вида. Существование файла НЕ
// проверяется: движок мог ещё не запуститься, и это законное состояние —
// панель скажет о нём честно, а не откажется подниматься.
func NewLiveSource(path string) *LiveSource { return &LiveSource{path: path} }

// Knowledge читает файл и отдаёт то, что в нём. Ошибка чтения — это НЕ пустое
// знание: панель обязана отличать «движок молчит» от «движок ничего не нашёл»,
// поэтому причина едет в LinkNote, а Linked остаётся ложью.
func (l *LiveSource) Knowledge() Knowledge {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.at) < time.Second {
		return l.last
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		l.last = Knowledge{
			Linked:   false,
			LinkNote: fmt.Sprintf("движок не отдаёт состояние (%s): %v", l.path, err),
		}
		l.at = time.Now()
		return l.last
	}
	var k Knowledge
	if err := json.Unmarshal(b, &k); err != nil {
		l.last = Knowledge{
			Linked:   false,
			LinkNote: fmt.Sprintf("состояние движка не разбирается (%s): %v", l.path, err),
		}
		l.at = time.Now()
		return l.last
	}
	l.last = k
	l.at = time.Now()
	return l.last
}
