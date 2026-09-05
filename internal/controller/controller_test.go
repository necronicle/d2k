package controller_test

// Сценарий этапа D целиком, на настоящем датапате.
//
// Стенд управляющего сокета (datapath/ctlprobe) гоняет ТОТ ЖЕ разбор команд и
// ту же сессию, что и служба на роутере. Контроллер разговаривает с ним по
// настоящему сокету. Проверяется не «функция вернула что ожидалось», а то,
// что пустая база превращается в изученную коробку от измерения — и что
// неудача не оставляет следов.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/control"
	"github.com/necronicle/d2k/internal/controller"
)

type rig struct {
	t     *testing.T
	cmd   *exec.Cmd
	in    io.WriteCloser
	out   *bufio.Scanner
	conn  *control.Conn
	ctrl  *controller.Controller
	store *catalog.Store
	log   *bytes.Buffer
	clock time.Time
	path  string
}

func (r *rig) say(line string) string {
	r.t.Helper()
	if _, err := fmt.Fprintln(r.in, line); err != nil {
		r.t.Fatalf("команда %q стенду: %v", line, err)
	}
	if !r.out.Scan() {
		r.t.Fatalf("стенд молчит после %q", line)
	}
	return r.out.Text()
}

// pump вычитывает события и скармливает их контроллеру, пока они есть.
func (r *rig) pump(n int) {
	r.t.Helper()
	for i := 0; i < n; i++ {
		// Срок короткий: события местные и приходят мгновенно, а ждать
		// несуществующее по три четверти секунды на каждом вызове —
		// двадцать секунд прогона на ровном месте.
		if err := r.conn.SetDeadline(time.Now().Add(120 * time.Millisecond)); err != nil {
			r.t.Fatal(err)
		}
		ev, err := r.conn.Next()
		if err != nil {
			return // событий больше нет
		}
		if err := r.ctrl.Handle(ev); err != nil {
			r.t.Fatalf("контроллер не переварил событие: %v", err)
		}
	}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	bin, err := filepath.Abs("../../datapath/ctlprobe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("стенд не собран (%v); нужен `make -C datapath ctlprobe`", err)
	}
	sock := fmt.Sprintf("/tmp/d2k-ctrl-%d.sock", os.Getpid())
	_ = os.Remove(sock)

	cmd := exec.Command(bin, sock)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(outPipe)
	if !sc.Scan() || sc.Text() != "готов" {
		t.Fatalf("стенд не поздоровался: %q", sc.Text())
	}

	var conn *control.Conn
	for i := 0; i < 50; i++ {
		conn, err = control.Dial(sock)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("не подключиться: %v", err)
	}

	path := filepath.Join(t.TempDir(), "catalog.json")
	store, err := catalog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	store.MinInterval = 0

	log := &bytes.Buffer{}
	r := &rig{
		t: t, cmd: cmd, in: in, out: sc, conn: conn,
		store: store, log: log, path: path,
		clock: time.Date(2026, 9, 5, 21, 0, 0, 0, time.UTC),
	}
	r.ctrl = controller.New(conn, store, log)
	r.ctrl.SetClock(func() time.Time { return r.clock })

	t.Cleanup(func() {
		_ = conn.Close()
		_, _ = fmt.Fprintln(in, "quit")
		_ = in.Close()
		_ = cmd.Wait()
		_ = os.Remove(sock)
		if t.Failed() {
			t.Logf("журнал контроллера:\n%s", log.String())
		}
	})
	return r
}

func TestПустаяБазаПревращаетсяВИзученнуюКоробку(t *testing.T) {
	// Полный сценарий этапа D: пустая база → сбой → поиск → проверка →
	// сохранение коробки, плана и привязки → применение на следующем
	// соединении.
	r := newRig(t)

	if len(r.store.Catalog().Boxes) != 0 {
		t.Fatal("база не пуста при старте")
	}

	// Соединение с блокировкой: приветствие, затем подделанный сброс.
	r.say("hello linkedin.com")
	r.say("rst")
	r.pump(8)

	if len(r.ctrl.Tasks()) != 1 {
		t.Fatalf("поисков %d, а подозрение было одно", len(r.ctrl.Tasks()))
	}
	// Коробки пока НЕТ: подозрение само по себе ничего не подтверждает.
	if len(r.store.Catalog().Boxes) != 0 {
		t.Fatal("подозрение создало коробку без подтверждённого решения")
	}

	// Кандидат доехал до соединения, и обмен пошёл с прикладными данными.
	r.say("hello linkedin.com")
	r.pump(4)
	r.say("reply 22")
	r.say("reply 23")
	r.pump(8)

	cat := r.store.Catalog()
	if len(cat.Boxes) != 1 {
		t.Fatalf("коробок %d, а ждали одну; журнал:\n%s", len(cat.Boxes), r.log)
	}
	box, bind, pl := cat.Lookup("linkedin.com", "")
	if box == nil || bind == nil || pl == nil {
		t.Fatalf("привязка не сохранена; журнал:\n%s", r.log)
	}
	if bind.Level < catalog.LevelHandshake {
		t.Fatalf("уровень доказательства %d, а прикладные данные были", bind.Level)
	}
	if len(box.Fingerprint.Signals) == 0 {
		t.Fatal("у коробки нет ни одного признака распознавания")
	}
	// Поиск закрыт: он живое состояние, а не история.
	if len(r.ctrl.Tasks()) != 0 {
		t.Fatal("после подтверждения поиск остался открытым")
	}

	// И запись пережила перезапуск.
	s2, err := catalog.Open(r.path)
	if err != nil {
		t.Fatalf("после перезапуска каталог не открылся: %v", err)
	}
	if box, _, _ := s2.Catalog().Lookup("linkedin.com", ""); box == nil {
		t.Fatal("подтверждённая привязка не пережила перезапуск")
	}
}

func TestНеудачныйПоискНеОставляетСледов(t *testing.T) {
	// §2.3 — главное правило. Кандидаты кончились, решения нет: на диске не
	// должно остаться ничего, ни коробки, ни отметки на цели.
	r := newRig(t)

	for i := 0; i < 8; i++ {
		r.say("hello rutracker.org")
		r.pump(4)
		r.say("rst")
		r.pump(6)
	}

	if n := len(r.store.Catalog().Boxes); n != 0 {
		t.Fatalf("после безуспешного поиска в базе %d коробок; журнал:\n%s", n, r.log)
	}
	if _, err := r.store.FlushNow(r.clock); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(r.path); err == nil {
		if strings.Contains(string(b), "rutracker") {
			t.Fatalf("цель безуспешного поиска попала на диск:\n%s", b)
		}
	}
	if !strings.Contains(r.log.String(), "не сохранено ничего") {
		t.Fatalf("исчерпание кандидатов не отмечено в журнале:\n%s", r.log)
	}
}

func TestУзнаннаяКоробкаНеЗапускаетНовыйПодбор(t *testing.T) {
	// Этап E: успех готового плана на новой цели не вызывает генератор и не
	// создаёт дубликат модели.
	r := newRig(t)

	// Первая цель — учимся.
	r.say("hello linkedin.com")
	r.say("rst")
	r.pump(8)
	r.say("hello linkedin.com")
	r.pump(4)
	r.say("reply 22")
	r.say("reply 23")
	r.pump(8)
	if len(r.store.Catalog().Boxes) != 1 {
		t.Fatalf("первая цель не изучена; журнал:\n%s", r.log)
	}

	// Вторая цель с ТЕМ ЖЕ поведением.
	r.log.Reset()
	r.say("hello instagram.com")
	r.say("rst")
	r.pump(8)

	logs := r.log.String()
	if !strings.Contains(logs, "готовых планов узнанных коробок") {
		t.Fatalf("готовый план узнанной коробки не предложен первым:\n%s", logs)
	}
	if !strings.Contains(logs, "(коробка ") {
		t.Fatalf("первым кандидатом пошёл не план коробки:\n%s", logs)
	}

	r.say("hello instagram.com")
	r.pump(4)
	r.say("reply 22")
	r.say("reply 23")
	r.pump(8)

	cat := r.store.Catalog()
	if len(cat.Boxes) != 1 {
		t.Fatalf("вторая цель создала дубликат коробки: %d", len(cat.Boxes))
	}
	if len(cat.Boxes[0].Bindings) != 2 {
		t.Fatalf("привязок %d, а целей было две", len(cat.Boxes[0].Bindings))
	}
	if len(cat.Boxes[0].Plans) != 1 {
		t.Fatalf("планов %d, а приём был один и тот же", len(cat.Boxes[0].Plans))
	}
	if !strings.Contains(r.log.String(), "повторное использование плана коробки") {
		t.Fatalf("повторное использование не отмечено как повторное:\n%s", r.log)
	}
}

func TestОдинПоискНаЦельАНеДесять(t *testing.T) {
	// §4.1: параллельные открытия браузера присоединяются к одной задаче.
	r := newRig(t)
	for i := 0; i < 5; i++ {
		r.say("hello discord.com")
		r.say("rst")
	}
	r.pump(30)
	if n := len(r.ctrl.Tasks()); n != 1 {
		t.Fatalf("поисков по одной цели %d, а должен быть один", n)
	}
}

func TestОбменБезПоискаНичегоНеПодтверждает(t *testing.T) {
	// Обычный трафик идёт всё время. Он не должен ничего записывать.
	r := newRig(t)
	r.say("hello ya.ru")
	r.say("reply 22")
	r.say("reply 23")
	r.pump(8)
	if n := len(r.store.Catalog().Boxes); n != 0 {
		t.Fatalf("обычный трафик записал %d коробок", n)
	}
}
