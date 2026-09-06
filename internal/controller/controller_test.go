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
	"github.com/necronicle/d2k/internal/classify"
	"github.com/necronicle/d2k/internal/control"
	"github.com/necronicle/d2k/internal/controller"
	"github.com/necronicle/d2k/internal/plan"
	"github.com/necronicle/d2k/internal/probe"
	"github.com/necronicle/d2k/internal/volume"
)

type rig struct {
	t        *testing.T
	cmd      *exec.Cmd
	in       io.WriteCloser
	out      *bufio.Scanner
	conn     *control.Conn
	ctrl     *controller.Controller
	store    *catalog.Store
	log      *bytes.Buffer
	clock    time.Time
	path     string
	probe    *fakeProber
	vol      *fakeVolume
	classify *fakeClassify
}

// fakeClassify — измерение функции решения коробки по сценарию. Настоящее
// classify.Run уходит в сеть и занимает секунды; проверять здесь надо то,
// что очередь кандидатов зависит от вердикта, а не чужую линию.
//
// Зеркало fakeVolume: нулевое значение (verdict == "") — стенд для теста, ещё
// не заданный сценарием, а не измерение с ответом «вердикта нет». Настоящий
// classify.Run пустой Verdict не возвращает никогда — это следует не
// повторять как боевое поведение, а держать возможным ТОЛЬКО в стенде: см.
// комментарий у этого случая в onClassify (classify_probe.go).
type fakeClassify struct {
	mu       sync.Mutex
	verdict  classify.Verdict
	splitPos int
	calls    int
	// lastMark — метка (Options.Mark), с которой пришёл ПОСЛЕДНИЙ вызов
	// Run. §5.5 требует, чтобы зонд активного поиска шёл помеченным, —
	// проверить это можно, только увидев, что реально долетело до
	// classify.Options, а не подразумевая это.
	lastMark uint32
	// hold — задержать ответ. Классификация и подбор по объёму меряются
	// независимо и параллельно (обе — фоном, см. askVolume/askClassify), и
	// который из двух ответит раньше — гонка двух горутин без единого
	// внешнего замедления. Там, где тесту важен порядок между осями, а не
	// сам факт «обе работают», гонку разрешает это поле — по образцу
	// fakeVolume.hold.
	hold chan struct{}
}

func (f *fakeClassify) Run(_ context.Context, _ string, _ classify.Trigger, opt classify.Options) classify.Result {
	f.mu.Lock()
	hold := f.hold
	f.calls++
	f.lastMark = opt.Mark
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return classify.Result{
		Verdict:  f.verdict,
		SplitPos: f.splitPos,
		Reason:   "стенд: вердикт задан сценарием теста",
	}
}

func (f *fakeClassify) mark() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastMark
}

// set задаёт вердикт следующего (и любого дальнейшего) вызова Run. boundary
// — позиция разреза: она же ложится в Result.SplitPos, ровно то поле, из
// которого verdictCandidates строит план (см. controller.go) — Result.
// Boundary в дереве classify отдельный и диагностический (граница сигнатуры,
// а не место разреза), здесь он не нужен.
func (f *fakeClassify) set(v classify.Verdict, boundary int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verdict, f.splitPos = v, boundary
}

func (f *fakeClassify) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeVolume — проба на объём по сценарию. Настоящая уходит в сеть на десятки
// секунд, а проверять надо правила, а не чужую линию.
type fakeVolume struct {
	mu      sync.Mutex
	verdict volume.ScanVerdict
	name    string
	cutKB   int
	tried   int
	calls   int
	names   []string
	// hold — задержать ответ. Подбор в жизни идёт до полутора минут, и
	// проверить, что видно человеку ВО ВРЕМЯ него, иначе нечем.
	hold chan struct{}

	// Проверка поставленного плана.
	probes        int
	probeSNI      string
	verifyVerdict volume.Verdict
}

func (f *fakeVolume) Scan(_ context.Context, t volume.Target, names []string, _ volume.ScanOptions) volume.ScanResult {
	f.mu.Lock()
	hold := f.hold
	f.calls++
	f.names = names
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return volume.ScanResult{
		Target: t, Verdict: f.verdict, Name: f.name, CutAtKB: f.cutKB, Tried: f.tried,
	}
}

// Probe — проверка поставленного плана. Отдельный сценарий: подбор и проверка
// отвечают на разные вопросы, и путать их в стенде нельзя.
func (f *fakeVolume) Probe(_ context.Context, t volume.Target, sni string, p volume.Pump) volume.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	f.probeSNI = sni
	return volume.Result{Target: t, SNI: sni, Pump: p, Verdict: f.verifyVerdict, AtKB: 39}
}

func (f *fakeVolume) probeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probes
}

func (f *fakeVolume) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeVolume) set(v volume.ScanVerdict, name string, cutKB int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verdict, f.name, f.cutKB = v, name, cutKB
}

// fakeProber отвечает на зонды по сценарию. В сеть проверки не ходят: вердикт
// теста не должен зависеть от того, что творится на линии.
type fakeProber struct {
	mu sync.Mutex
	// Ответы по очереди; последний повторяется.
	script []probe.Result
	calls  int
	hellos [][]byte
	// hold — задержать ответ. По образцу fakeVolume.hold/fakeClassify.hold:
	// без него зонд на подтверждение кандидата (advance -> awaiting) отвечает
	// в своей горутине настолько быстро, что второй Pump() внутри того же
	// вызова может утащить и его результат тоже — порядок между «отпустить
	// один зонд» и «получить именно этот ответ, не следующий» тогда решает
	// планировщик, а не тест. Нужен там, где важно поймать задачу МЕЖДУ
	// зондами, а не после того, как вся лестница домоталась до конца.
	hold chan struct{}
}

func (f *fakeProber) Do(_ context.Context, _ string, _ int, hello []byte) probe.Result {
	f.mu.Lock()
	hold := f.hold
	f.calls++
	f.hellos = append(f.hellos, append([]byte(nil), hello...))
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
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
	r.vol = &fakeVolume{verdict: volume.ScanNoBlock, verifyVerdict: volume.VerdictPassed}
	// Нулевое значение: вердикта нет, пока сценарий теста явно не задаст его
	// через r.classify.set(...) — см. комментарий у fakeClassify. Тесты, для
	// которых вердикт не важен, ничего не задают, и очередь идёт так, как
	// будто классификации не было вовсе (onClassify, случай пустого Verdict).
	r.classify = &fakeClassify{}
	r.ctrl = controller.New(conn, store, log)
	r.ctrl.SetClock(func() time.Time { return r.clock })
	r.ctrl.SetProber(r.probe)
	// Проба на объём по умолчанию говорит «блока нет»: проверка не должна
	// ходить в сеть и не должна зависеть от политики чужой линии.
	r.ctrl.SetVolumeProber(r.vol)
	r.ctrl.SetClassifier(r.classify)

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

func TestНеВстающийТранспортНеТратитЗондыНаИмя(t *testing.T) {
	// Первый вопрос отсекает больше всего: встаёт ли транспорт вообще. Если
	// нет — дело ниже TLS, и перебирать плечи бессмысленно. Сегодня его
	// отсутствие стоило трёх зондов на www.instagram.com, куда не приходит
	// даже SYN-ACK.
	//
	// Чего этот ответ НЕ утверждает: что цель заблокирована по адресу. Сервер
	// мог лежать, а проходящего имени для проверки у нас ещё нет (§2.4).
	r := newRig(t)
	r.probe.script = []probe.Result{{Outcome: probe.OutcomeNoConnect}}

	r.say("hello www.instagram.com")
	r.say("rst")
	r.pump(20)

	if n := r.probe.count(); n != 1 {
		t.Fatalf("зондов %d, а хватало одного вопроса; журнал:\n%s", n, r.log)
	}
	if !strings.Contains(r.log.String(), "спрашиваю: встаёт ли транспорт") {
		t.Fatalf("вопрос не задан:\n%s", r.log)
	}
	if !strings.Contains(r.log.String(), "ниже TLS") {
		t.Fatalf("ответ не истолкован:\n%s", r.log)
	}
	// И ни слова про блокировку по адресу: этого мы не измеряли.
	if strings.Contains(r.log.String(), "решает адрес") {
		t.Fatalf("утверждение про адрес сделано без измерения:\n%s", r.log)
	}
	if n := len(r.store.Catalog().Boxes); n != 0 {
		t.Fatalf("непробиваемая цель записана: коробок %d", n)
	}
}

func TestВопросПредшествуетКандидатам(t *testing.T) {
	// Вопрос задаётся ДО того, как тратить попытки: его ответ меняет выбор.
	// Ответ «решает имя» открывает дорогу кандидатам.
	r := newRig(t)
	r.probe.script = []probe.Result{
		{Outcome: probe.OutcomeExchange, Bytes: 200, SeenTypes: 1 << (21 - 20)}, // ответ на вопрос
		ok(), // проверка кандидата
	}

	r.say("hello linkedin.com")
	r.say("rst")
	r.pump(20)

	logs := r.log.String()
	qi := strings.Index(logs, "спрашиваю: встаёт ли транспорт")
	ci := strings.Index(logs, "пробую plan-")
	if qi < 0 {
		t.Fatalf("вопрос не задан:\n%s", logs)
	}
	if ci < 0 {
		t.Fatalf("до кандидатов дело не дошло:\n%s", logs)
	}
	if qi > ci {
		t.Fatalf("кандидат пошёл раньше вопроса:\n%s", logs)
	}
	if !strings.Contains(logs, "транспорт встаёт") {
		t.Fatalf("ответ про транспорт не записан:\n%s", logs)
	}
	if box, _, _ := r.store.Catalog().Lookup("linkedin.com", ""); box == nil {
		t.Fatalf("после верного ответа решение не найдено:\n%s", logs)
	}
}

// readAndHandle читает события с сокета по одному и сразу отдаёт их в
// Handle — как в бою, где каждое событие обрабатывается по прибытии, — пока
// не встретит событие типа want (тоже передав его в Handle) или не кончится
// лимит попыток. Pump() здесь НЕ зовётся ни разу: это то, ради чего функция
// вообще нужна отдельно от r.pump() — обычный pump() в каждом раунде
// вычитывает ответы зондов из фонового канала, а этому тесту важно самому
// решать, когда зонду разрешено ответить (см. rig.probe.hold ниже).
func readAndHandle(t *testing.T, r *rig, want uint16) control.Event {
	t.Helper()
	for i := 0; i < 8; i++ {
		if err := r.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		ev, err := r.conn.Next()
		if err != nil {
			t.Fatalf("событие (ждали тип %d): %v; журнал:\n%s", want, err, r.log)
		}
		if err := r.ctrl.Handle(ev); err != nil {
			t.Fatalf("контроллер не переварил событие типа %d: %v", ev.Type, err)
		}
		if ev.Type == want {
			return ev
		}
	}
	t.Fatalf("тип события %d не пришёл за отведённые попытки; журнал:\n%s", want, r.log)
	return control.Event{}
}

func TestQUICПрименениеНеПортитСчётчикTCPКандидата(t *testing.T) {
	// Находка 6 ревью задачи 4 (круг 2): taskForKey резолвит цель по ИМЕНИ
	// (c.target читает c.names[ключ], а задачи лежат в c.tasks[имя]), а не по
	// ключу с транспортом, — так что TCP-поток и QUIC-поток к одному имени
	// делят один *Task и один AppliedCount. Правило ротации (maxSilentTries,
	// см. onSuspect) верно только тогда, когда обмен (EvExchange) в принципе
	// МОГ прийти в ответ на применение, а датапат считает обмен и молчаливый
	// сброс ТОЛЬКО по TCP-таблице потоков (session.c: handle_udp возвращается
	// раньше общего хвоста d2k_session_packet, где копятся exchanges и
	// rst_dropped; d2k_session_sweep обходит только s->flows). Задача 4
	// научила датапат применять план и к QUIC-потокам, так что EvApplied
	// реально приходит и с Proto==17 — без разбора протокола в Handle() такое
	// применение молча накручивало бы AppliedCount TCP-кандидата и могло бы
	// вызвать ротацию рабочего плана по молчанию потоков, для которых обмен
	// структурно ненаблюдаем (задачи 5/6 QUIC-вертикали ещё не существуют).
	r := newRig(t)
	// hold блокирует ответ зонда, пока тест сам не решит его отпустить: без
	// этого зонд на подтверждение первого кандидата (запущенный ВНУТРИ
	// обработки ответа на вопрос «встаёт ли транспорт») мог бы успеть
	// ответить и уйти в advance() ДО того, как тест успеет прочитать
	// состояние задачи — гонка двух горутин без точки синхронизации. Здесь
	// синхронизация — сам канал: он отпускает ровно столько ответов, сколько
	// тест явно передал ему через `<-`.
	r.probe.hold = make(chan struct{})

	r.say("hello example.com")
	readAndHandle(t, r, control.EvHello)
	r.say("rst")
	readAndHandle(t, r, control.EvSuspect)

	// Отпускаем ровно ОДИН ответ зонда — на вопрос «встаёт ли транспорт»,
	// первый и обязательный для любой свежей задачи (nextQuestion). Зонд на
	// подтверждение кандидата, запущенный дальше внутри advance(), тоже
	// вызовет Do() и тоже встанет на этот же hold, но получить свой ответ
	// сможет только вторым `<-hold`, которого этот тест никогда не пошлёт —
	// он и не должен: до сравнения счётчика дело дойти не обязано.
	r.probe.hold <- struct{}{}

	var tasks []*controller.Task
	for i := 0; i < 100; i++ {
		if err := r.ctrl.Pump(); err != nil {
			t.Fatalf("Pump: %v", err)
		}
		tasks = r.ctrl.Tasks()
		if len(tasks) == 1 && tasks[0].Current != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(tasks) != 1 || tasks[0].Current == nil {
		t.Fatalf("ожидал ровно одну задачу с кандидатом после ответа на вопрос; задачи: %+v; журнал:\n%s",
			tasks, r.log)
	}
	if tasks[0].AppliedCount != 0 {
		t.Fatalf("AppliedCount %d до всякого применения — ожидал 0", tasks[0].AppliedCount)
	}

	// Кандидат уже отправлен в ctlprobe (advance -> push), но команда идёт по
	// сокету асинхронно — тот же приём ожидания, что и в
	// TestПланСтавитсяПоИмениИПрименяется.
	var line string
	for i := 0; i < 50; i++ {
		line = r.say("plans")
		if strings.Contains(line, "planов 1") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(line, "planов 1") {
		t.Fatalf("план кандидата не встал в таблицу: %q; журнал:\n%s", line, r.log)
	}
	var plansN, okBefore, badN uint64
	if _, err := fmt.Sscanf(line, "planов %d, команд принято %d, отвергнуто %d",
		&plansN, &okBefore, &badN); err != nil {
		t.Fatalf("не разобрать ответ %q: %v", line, err)
	}

	// Кандидат, который в самом деле выбрал advance() (запасной, everythingPlan
	// из classify.Compose на пустом векторе свойств), портит TCP-контрольную
	// сумму (plan.PoisonBadSum) — а её UDP-сборка исполнять не умеет и честно
	// отказывает (wire_udp.c, см. TestПланПоИмениПрименяетсяИКQUIC в
	// internal/control/bridge_test.go, где это же проверено отдельно). Для
	// НАХОДКИ 6 это не имеет значения: она про то, что делает Handle() с
	// EvApplied, а не про то, какую конкретно порчу выбрал сегодняшний
	// синтез кандидатов (тот, что умеет и TCP, и UDP, — работа задач 5/6, не
	// этой). Меняем план цели на порто-нейтральный (без порчи вовсе, чтобы
	// UDP-сборка ничего не отвергла) — таблица планов ctlprobe одна на имя, и
	// его прямая перестановка не трогает t.Current/AppliedCount на стороне
	// Go: Handle() смотрит только на факт события EvApplied и на его Proto,
	// а не на байты применённого плана.
	udpOK := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 17, Proto: 1,
		Payloads: []plan.Payload{{ID: 1, Bytes: []byte{0xDE, 0xAD}}},
		Fakes:    []plan.Fake{{PayloadID: 1, PoisonID: 0, Repeats: 1}},
	}
	tlv, err := udpOK.MarshalTLV()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.conn.SetPlanName("example.com", tlv); err != nil {
		t.Fatalf("замена плана цели не отправилась: %v", err)
	}
	for i := 0; i < 50; i++ {
		line = r.say("plans")
		var p2, ok2, b2 uint64
		if _, err := fmt.Sscanf(line, "planов %d, команд принято %d, отвергнуто %d", &p2, &ok2, &b2); err == nil {
			if ok2 > okBefore {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(line, "planов 1") {
		t.Fatalf("замена плана цели не встала: %q; журнал:\n%s", line, r.log)
	}

	// QUIC-поток к ТОЙ ЖЕ цели: "quic" переиспользует порт последнего
	// hello/rst — тот самый случай гонки TCP/QUIC браузера к одному имени,
	// см. TestTCPИQUICСОдинаковымАдресомИПортомДаютРазныеКлючи в
	// internal/control/bridge_test.go. От одной датаграммы приходит два
	// события: сперва hello (имя узнано по QUIC-ключу — без него
	// c.names[quic-ключ] не был бы известен, и taskForKey не нашёл бы
	// задачу), затем applied (план сработал) — handle_udp делает и то, и
	// другое в одном вызове, и журналирует их в этом порядке.
	r.say("quic")
	quicHello := readAndHandle(t, r, control.EvHello)
	if quicHello.Key.Proto != 17 {
		t.Fatalf("QUIC-хелло с транспортом %d, ждали UDP(17)", quicHello.Key.Proto)
	}
	quicApplied := readAndHandle(t, r, control.EvApplied)
	if quicApplied.Key.Proto != 17 {
		t.Fatalf("EvApplied с транспортом %d, ждали UDP(17)", quicApplied.Key.Proto)
	}

	tasks = r.ctrl.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("задача пропала после QUIC-применения: %+v; журнал:\n%s", tasks, r.log)
	}
	if tasks[0].AppliedCount != 0 {
		t.Fatalf("QUIC-применение (Proto=17) увеличило AppliedCount TCP-кандидата: %d",
			tasks[0].AppliedCount)
	}

	// Контрольная проверка, без которой предыдущая ничего не доказывает:
	// то же самое применение, но по-настоящему TCP, ОБЯЗАНО посчитаться —
	// иначе тест мог бы проходить просто потому, что ветка вообще ничего не
	// считает. Новый "hello" — свежий порт, тот же адрес и имя: обычная
	// вторая вкладка браузера к той же цели.
	r.say("hello example.com")
	tcpHello := readAndHandle(t, r, control.EvHello)
	if tcpHello.Key.Proto != 6 {
		t.Fatalf("второе TCP-хелло с транспортом %d, ждали TCP(6)", tcpHello.Key.Proto)
	}
	tcpApplied := readAndHandle(t, r, control.EvApplied)
	if tcpApplied.Key.Proto != 6 {
		t.Fatalf("EvApplied с транспортом %d, ждали TCP(6)", tcpApplied.Key.Proto)
	}

	tasks = r.ctrl.Tasks()
	if len(tasks) != 1 || tasks[0].AppliedCount != 1 {
		t.Fatalf("TCP-применение (Proto=6) обязано было увеличить AppliedCount до 1, получили задачи: %+v",
			tasks)
	}
}
