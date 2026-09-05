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
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/control"
	"github.com/necronicle/d2k/internal/controller"
	"github.com/necronicle/d2k/internal/plan"
	"github.com/necronicle/d2k/internal/probe"
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
	probe *fakeProber
}

// fakeProber отвечает на зонды по сценарию. В сеть проверки не ходят: вердикт
// теста не должен зависеть от того, что творится на линии.
type fakeProber struct {
	mu sync.Mutex
	// Ответы по очереди; последний повторяется.
	script []probe.Result
	calls  int
	hellos [][]byte
}

func (f *fakeProber) Do(_ context.Context, _ string, _ int, hello []byte) probe.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.hellos = append(f.hellos, append([]byte(nil), hello...))
	if len(f.script) == 0 {
		return probe.Result{Outcome: probe.OutcomeSilence}
	}
	if f.calls-1 < len(f.script) {
		return f.script[f.calls-1]
	}
	return f.script[len(f.script)-1]
}

func (f *fakeProber) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeProber) lastHello() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hellos) == 0 {
		return nil
	}
	return f.hellos[len(f.hellos)-1]
}

// ok — зонд прошёл с прикладными данными.
func ok() probe.Result {
	return probe.Result{
		Outcome:   probe.OutcomeExchange,
		Bytes:     4096,
		SeenTypes: 1<<(22-20) | 1<<(23-20),
	}
}

// blocked — зонд получил сброс.
func blocked() probe.Result { return probe.Result{Outcome: probe.OutcomeReset} }

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

// pump вычитывает события, скармливает их контроллеру и разбирает ответы
// зондов, пока не станет тихо.
//
// Тихо — это когда и событий нет, и зонды в полёте кончились. Ранняя редакция
// выходила по первому же отсутствию события и пропускала разбор зонда,
// который к тому моменту ещё летел.
func (r *rig) pump(rounds int) {
	r.t.Helper()
	for i := 0; i < rounds; i++ {
		progressed := false
		for j := 0; j < 32; j++ {
			if err := r.conn.SetReadDeadline(time.Now().Add(60 * time.Millisecond)); err != nil {
				r.t.Fatal(err)
			}
			ev, err := r.conn.Next()
			if err != nil {
				break
			}
			progressed = true
			if err := r.ctrl.Handle(ev); err != nil {
				r.t.Fatalf("контроллер не переварил событие: %v", err)
			}
		}
		// Зонды отвечают из своей горутины: даём им долететь и разбираем.
		time.Sleep(20 * time.Millisecond)
		before := len(r.ctrl.Tasks())
		if err := r.ctrl.Pump(); err != nil {
			r.t.Fatalf("контроллер не переварил зонд: %v", err)
		}
		if len(r.ctrl.Tasks()) != before {
			progressed = true
		}
		if !progressed && r.probe.count() > 0 && len(r.ctrl.Tasks()) == 0 {
			return
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
	r.probe = &fakeProber{}
	r.ctrl = controller.New(conn, store, log)
	r.ctrl.SetClock(func() time.Time { return r.clock })
	r.ctrl.SetProber(r.probe)

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

func TestРешениеНаходитсяБезЕдиногоПовтораКлиента(t *testing.T) {
	// Главное свойство активного поиска. Клиент сходил ОДИН раз и больше не
	// возвращался — так ведут себя телевизор, приставка и часть IoT. Пассивный
	// поиск на них не работал бы вовсе, потому что ждал бы повтора, которого
	// не будет.
	r := newRig(t)
	r.probe.script = []probe.Result{blocked(), ok()}

	r.say("hello linkedin.com")
	r.say("rst")
	r.pump(10)

	if r.probe.count() == 0 {
		t.Fatalf("контроллер не постучался сам; журнал:\n%s", r.log)
	}
	box, bind, pl := r.store.Catalog().Lookup("linkedin.com", "")
	if box == nil || bind == nil || pl == nil {
		t.Fatalf("решение не найдено после %d зондов; журнал:\n%s",
			r.probe.count(), r.log)
	}
	if len(r.ctrl.Tasks()) != 0 {
		t.Fatal("после решения поиск остался открытым")
	}
	if !strings.Contains(r.log.String(), "стучусь сам") {
		t.Fatalf("в журнале нет следа активного зонда:\n%s", r.log)
	}

	// И запись пережила перезапуск.
	if _, err := r.store.FlushNow(r.clock); err != nil {
		t.Fatal(err)
	}
	s2, err := catalog.Open(r.path)
	if err != nil {
		t.Fatalf("после перезапуска каталог не открылся: %v", err)
	}
	if b, _, _ := s2.Catalog().Lookup("linkedin.com", ""); b == nil {
		t.Fatal("подтверждённая привязка не пережила перезапуск")
	}
}

func TestЗондПовторяетФормуКлиентскогоПриветствия(t *testing.T) {
	// §3.1 и §5.5: зонд обязан проверять тот же трафик, что у пользователя.
	// Синтетическое приветствие коробка может разглядывать иначе.
	r := newRig(t)
	r.probe.script = []probe.Result{ok()}

	// Приветствие с приметным набором шифров: если зонд соберёт своё, набора
	// в нём не будет.
	hello, err := plan.Hello("marked.example", 0x77)
	if err != nil {
		t.Fatal(err)
	}
	r.say("raw " + hex.EncodeToString(hello))
	r.say("rst")
	r.pump(10)

	sent := r.probe.lastHello()
	if len(sent) == 0 {
		t.Fatalf("зонд не пускался; журнал:\n%s", r.log)
	}
	if !bytes.Contains(sent, []byte("marked.example")) {
		t.Fatal("в приветствии зонда нет имени цели")
	}
	if !strings.Contains(r.log.String(), "форма клиента") {
		t.Fatalf("зонд пошёл не с формой клиента:\n%s", r.log)
	}
	// Случайное поле обязано отличаться от клиентского: копия не должна быть
	// буквальным повтором чужого сообщения (§2.6).
	if bytes.Equal(sent[11:11+32], hello[11:11+32]) {
		t.Fatal("случайное поле клиента скопировано буквально")
	}
}

func TestНеудачныйПоискНеОставляетСледов(t *testing.T) {
	// §2.3 — главное правило. Все кандидаты отвергнуты: на диске не должно
	// остаться ничего, ни коробки, ни отметки на цели.
	r := newRig(t)
	r.probe.script = []probe.Result{blocked()}

	r.say("hello rutracker.org")
	r.say("rst")
	r.pump(30)

	if n := len(r.store.Catalog().Boxes); n != 0 {
		t.Fatalf("после безуспешного поиска в базе %d коробок; журнал:\n%s", n, r.log)
	}
	if _, err := r.store.FlushNow(r.clock); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(r.path); err == nil && strings.Contains(string(b), "rutracker") {
		t.Fatalf("цель безуспешного поиска попала на диск:\n%s", b)
	}
	if !strings.Contains(r.log.String(), "не сохранено ничего") {
		t.Fatalf("исчерпание кандидатов не отмечено в журнале:\n%s", r.log)
	}
	if r.probe.count() < 2 {
		t.Fatalf("кандидаты перебирались не зондами: зондов %d", r.probe.count())
	}
}

func TestУзнаннаяКоробкаНеЗапускаетНовыйПодбор(t *testing.T) {
	// Этап E: успех готового плана на новой цели не вызывает генератор и не
	// создаёт дубликат модели.
	r := newRig(t)
	r.probe.script = []probe.Result{ok()}

	r.say("hello linkedin.com")
	r.say("rst")
	r.pump(10)
	if len(r.store.Catalog().Boxes) != 1 {
		t.Fatalf("первая цель не изучена; журнал:\n%s", r.log)
	}

	r.log.Reset()
	r.say("hello instagram.com")
	r.say("rst")
	r.pump(10)

	logs := r.log.String()
	if !strings.Contains(logs, "готовых планов узнанных коробок") {
		t.Fatalf("готовый план узнанной коробки не предложен первым:\n%s", logs)
	}
	if !strings.Contains(logs, "(коробка ") {
		t.Fatalf("первым кандидатом пошёл не план коробки:\n%s", logs)
	}

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
	if !strings.Contains(logs, "повторное использование плана коробки") {
		t.Fatalf("повторное использование не отмечено как повторное:\n%s", logs)
	}
}

func TestУровеньДоказательстваЧестен(t *testing.T) {
	// §4.2: одного ServerHello мало для уровня 3. Зонд, увидевший только
	// рукопожатие, обязан дать уровень 2, а не 3.
	r := newRig(t)
	r.probe.script = []probe.Result{{
		Outcome:   probe.OutcomeExchange,
		Bytes:     1400,
		SeenTypes: 1 << (22 - 20), // только рукопожатие
	}}

	r.say("hello linkedin.com")
	r.say("rst")
	r.pump(10)

	_, bind, _ := r.store.Catalog().Lookup("linkedin.com", "")
	if bind == nil {
		t.Fatalf("обмен на уровне 2 не подтверждён вовсе; журнал:\n%s", r.log)
	}
	if bind.Level != catalog.LevelProtocol {
		t.Fatalf("уровень записан как %d, а измерен был 2", bind.Level)
	}
}

func TestОдинПоискНаЦельАНеДесять(t *testing.T) {
	// §4.1: параллельные открытия браузера присоединяются к одной задаче.
	// Считаем НАЧАТЫЕ поиски, а не живые задачи: при активном зонде задача
	// закрывается сама, и «ноль живых» ничего не говорит.
	r := newRig(t)
	r.probe.script = []probe.Result{blocked()}

	for i := 0; i < 5; i++ {
		r.say("hello discord.com")
		r.say("rst")
	}
	r.pump(30)

	if n := strings.Count(r.log.String(), "начат поиск"); n != 1 {
		t.Fatalf("поисков начато %d, а цель одна; журнал:\n%s", n, r.log)
	}
}

// slowProber отвечает не сразу: пока он думает, изображаем судорожное
// обновление страницы.
type slowProber struct {
	release chan struct{}
	res     probe.Result
	calls   int
	mu      sync.Mutex
}

func (s *slowProber) Do(_ context.Context, _ string, _ int, _ []byte) probe.Result {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	<-s.release
	return s.res
}

func (s *slowProber) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestСудорожноеОбновлениеНеЖжётКандидатов(t *testing.T) {
	// Человек жмёт F5 подряд. Каждое нажатие — новое соединение и новое
	// подозрение. Пока наш зонд проверяет кандидата, эти подозрения не имеют
	// права ни двигать лестницу, ни начинать второй поиск.
	r := newRig(t)
	slow := &slowProber{release: make(chan struct{}), res: ok()}
	r.ctrl.SetProber(slow)

	r.say("hello linkedin.com")
	r.say("rst")
	r.pump(3)

	tasks := r.ctrl.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("поисков %d; журнал:\n%s", len(tasks), r.log)
	}
	attempts := tasks[0].Attempts

	// Судорожное обновление, пока зонд в полёте.
	for i := 0; i < 10; i++ {
		r.say("hello linkedin.com")
		r.say("rst")
	}
	r.pump(6)

	tasks = r.ctrl.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("обновления развели %d поисков; журнал:\n%s", len(tasks), r.log)
	}
	if tasks[0].Attempts != attempts {
		t.Fatalf("обновления сожгли лестницу: попыток было %d, стало %d;\nжурнал:\n%s",
			attempts, tasks[0].Attempts, r.log)
	}
	if n := slow.count(); n != 1 {
		t.Fatalf("зондов запущено %d, а должен быть один; журнал:\n%s", n, r.log)
	}
	if n := strings.Count(r.log.String(), "начат поиск"); n != 1 {
		t.Fatalf("поисков начато %d; журнал:\n%s", n, r.log)
	}

	// Отпускаем зонд: решение обязано найтись.
	close(slow.release)
	r.pump(6)
	if box, _, _ := r.store.Catalog().Lookup("linkedin.com", ""); box == nil {
		t.Fatalf("после отпущенного зонда решение не найдено; журнал:\n%s", r.log)
	}
}

func TestПослеБезуспешногоПоискаЦельОтдыхает(t *testing.T) {
	// §2.3 разрешает короткий отказ ТОЛЬКО в памяти: десять вкладок,
	// стучащихся в мёртвый хост, не должны запускать десять поисков подряд.
	r := newRig(t)
	r.probe.script = []probe.Result{blocked()}

	r.say("hello rutracker.org")
	r.say("rst")
	r.pump(30)

	if !strings.Contains(r.log.String(), "не сохранено ничего") {
		t.Fatalf("поиск не закончился исчерпанием; журнал:\n%s", r.log)
	}
	started := strings.Count(r.log.String(), "начат поиск")

	// Ещё обращения сразу же — нового поиска быть не должно.
	for i := 0; i < 5; i++ {
		r.say("hello rutracker.org")
		r.say("rst")
	}
	r.pump(10)
	if n := strings.Count(r.log.String(), "начат поиск"); n != started {
		t.Fatalf("отдыхающая цель перезапустила поиск: было %d, стало %d;\nжурнал:\n%s",
			started, n, r.log)
	}

	// А когда отдых кончился — можно снова.
	r.clock = r.clock.Add(5 * time.Minute)
	r.say("hello rutracker.org")
	r.say("rst")
	r.pump(10)
	if n := strings.Count(r.log.String(), "начат поиск"); n <= started {
		t.Fatalf("после отдыха поиск не возобновился; журнал:\n%s", r.log)
	}
	// И на диске по-прежнему пусто.
	if n := len(r.store.Catalog().Boxes); n != 0 {
		t.Fatalf("безуспешные поиски записали %d коробок", n)
	}
}

func TestБюджетЗондовОграничен(t *testing.T) {
	// §5: у измерений есть бюджет, и «сколько получится» бюджетом не является.
	r := newRig(t)
	r.probe.script = []probe.Result{blocked()}

	r.say("hello budget.example")
	r.say("rst")
	r.pump(40)

	if n := r.probe.count(); n > 8 {
		t.Fatalf("зондов %d, а бюджет восемь; журнал:\n%s", n, r.log)
	}
}
