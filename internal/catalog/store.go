package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store — хранение каталога на диске.
//
// Требования §5.6, и каждое здесь исполнено, а не упомянуто:
//
//	атомарная фиксация      — запись во временный файл, fsync, rename;
//	проверка ошибок записи  — проверяется каждая, включая Close и Sync;
//	сохранность последней исправной версии — прежний файл переезжает в .prev
//	                          ДО подмены, и загрузка умеет к нему откатиться;
//	ограничение частоты     — пишем не чаще MinInterval, копя изменения;
//	проверка при загрузке   — Validate на всём каталоге.
//
// Ограничение частоты не роскошь: накопитель роутера — флешка, и §5.6
// требует беречь её прямо. База при этом содержит только подтверждённое
// (§2.3), поэтому неудачные поиски дисковых операций не порождают вовсе.
type Store struct {
	path string
	// Не чаще этого интервала. Ноль означает «писать сразу» и годится тестам.
	MinInterval time.Duration

	mu        sync.Mutex
	cat       *Catalog
	dirty     bool
	lastWrite time.Time
}

// Open читает каталог. Отсутствие файла — не ошибка: пустая база при первом
// запуске это норма (§2.2).
//
// Если основной файл битый, берётся .prev и об этом сообщается: молча
// подсунуть вчерашнее знание вместо сегодняшнего нельзя, потому что решения
// принимаются по нему.
func Open(path string) (*Store, error) {
	s := &Store{path: path, MinInterval: 30 * time.Second}

	cat, err := readFile(path)
	switch {
	case err == nil:
		s.cat = cat
		return s, nil
	case os.IsNotExist(err):
		s.cat = New()
		return s, nil
	}

	prev, perr := readFile(path + ".prev")
	if perr != nil {
		return nil, fmt.Errorf("каталог %s не читается (%w), и запасной тоже (%v)",
			path, err, perr)
	}
	s.cat = prev
	// Каталог откатился на предыдущую версию — это факт для того, кто решает,
	// а не мелочь. Возвращается вместе с рабочим Store: работать можно, но
	// знать об этом обязательно.
	return s, fmt.Errorf("каталог %s повреждён (%w), взята предыдущая версия", path, err)
}

func readFile(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("разбор: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.migrate()
	return &c, nil
}

// Catalog отдаёт каталог под замком вызывающего. Изменивший обязан позвать
// Touch, иначе изменение не доедет до диска.
func (s *Store) Catalog() *Catalog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cat
}

// Touch отмечает, что каталог изменился.
func (s *Store) Touch() {
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()
}

// Flush пишет каталог, если он изменился и прошло достаточно времени.
// Возвращает true, если запись состоялась.
func (s *Store) Flush(now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return false, nil
	}
	if !s.lastWrite.IsZero() && now.Sub(s.lastWrite) < s.MinInterval {
		return false, nil
	}
	return s.writeLocked(now)
}

// FlushNow пишет немедленно, невзирая на интервал. Для остановки службы:
// §5.5 требует описанного пути на SIGTERM, и «накопленное потерялось» таким
// путём не является.
func (s *Store) FlushNow(now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return false, nil
	}
	return s.writeLocked(now)
}

func (s *Store) writeLocked(now time.Time) (bool, error) {
	if err := s.cat.Validate(); err != nil {
		// Писать заведомо битое нельзя: оно вытеснит исправное.
		return false, fmt.Errorf("каталог не прошёл проверку перед записью: %w", err)
	}
	s.cat.Updated = now

	b, err := json.MarshalIndent(s.cat, "", "  ")
	if err != nil {
		return false, err
	}
	b = append(b, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, ".catalog-*.tmp")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	// Дальше любая ошибка обязана убрать за собой временный файл: иначе
	// каталог обрастёт мусором, который никто не удалит.
	fail := func(e error) (bool, error) {
		tmp.Close()
		os.Remove(tmpName)
		return false, e
	}
	if _, err := tmp.Write(b); err != nil {
		return fail(err)
	}
	// Проверяется КАЖДАЯ ошибка, включая эти две. Незамеченный сбой Sync
	// означает файл, который выглядит записанным и не переживёт отключения
	// питания, — а отключения питания у роутера случаются.
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return false, err
	}

	// Прежняя версия сохраняется ДО подмены. Если сюда не дойдёт, .prev
	// останется от прошлого раза — тоже исправный.
	if _, err := os.Stat(s.path); err == nil {
		if err := os.Rename(s.path, s.path+".prev"); err != nil {
			os.Remove(tmpName)
			return false, err
		}
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return false, err
	}

	s.dirty = false
	s.lastWrite = now
	return true, nil
}

// Path — где лежит каталог.
func (s *Store) Path() string { return s.path }

// Pending говорит, есть ли незаписанные изменения. Нужно сводке: «всё
// записано» и «ещё не время писать» — разные состояния.
func (s *Store) Pending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dirty
}
