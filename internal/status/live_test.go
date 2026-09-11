package status_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/necronicle/d2k/internal/status"
)

func TestЖивойВидЧитаетсяПолеВПоле(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "live.json")
	// Ровно тот вид, который пишет движок (core/sched.c,
	// d2k_sched_write_live). Файл здесь — эталон формата, а не выдумка теста:
	// разойдись он с писателем, панель показала бы пустоту вместо знания.
	body := `{
  "linked": true,
  "link_note": "",
  "catalog_at": "/opt/d2k/state/catalog.json",
  "boxes": [
    {"id": "box-abc", "created": "2026-09-11T10:00:00Z", "updated": "2026-09-11T11:00:00Z",
     "signals": [{"kind": "rst", "human": "подделанный сброс, TTL 127", "seen": 3}],
     "plans": [{"id": "plan-1", "proto": "tls", "successes": 52, "enabled": true, "human": "", "text": "d2k-plan 1 1\n"}],
     "bindings": [{"target": "rutracker.org", "kind": "name", "level": 3,
                   "level_name": "обмен прошёл", "successes": 1,
                   "confirmed": "2026-09-11T11:00:00Z", "enabled": true}]}
  ],
  "searches": [
    {"target": "accounts.youtube.com", "phase": "спрашиваем коробку о свойствах",
     "since": "2026-09-11T11:05:00Z", "attempts": 0, "probes": 5,
     "candidate": "", "source": "выведен из замера"}
  ],
  "targets": 1,
  "confirms": 1,
  "probes_used": 8
}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	k := status.NewLiveSource(p).Knowledge()
	if !k.Linked {
		t.Fatalf("вид прочитан, а связь не отмечена: %q", k.LinkNote)
	}
	if len(k.Boxes) != 1 || k.Boxes[0].ID != "box-abc" {
		t.Fatalf("коробки не прочитались: %+v", k.Boxes)
	}
	if len(k.Boxes[0].Bindings) != 1 || k.Boxes[0].Bindings[0].Target != "rutracker.org" {
		t.Fatalf("привязки не прочитались: %+v", k.Boxes[0].Bindings)
	}
	if len(k.Searches) != 1 || k.Searches[0].Probes != 5 {
		t.Fatalf("идущие поиски не прочитались: %+v", k.Searches)
	}
	if k.Targets != 1 || k.Confirms != 1 || k.ProbesUsed != 8 {
		t.Fatalf("счётчики не прочитались: %d %d %d", k.Targets, k.Confirms, k.ProbesUsed)
	}
}

func TestМолчаниеДвижкаНеПустоеЗнание(t *testing.T) {
	// §8: «движок молчит» и «движок ничего не нашёл» — разные вещи, и
	// показывать первое как второе нельзя.
	k := status.NewLiveSource(filepath.Join(t.TempDir(), "нет.json")).Knowledge()
	if k.Linked {
		t.Fatal("файла нет, а связь отмечена")
	}
	if !strings.Contains(k.LinkNote, "не отдаёт состояние") {
		t.Fatalf("причина не названа: %q", k.LinkNote)
	}
}
