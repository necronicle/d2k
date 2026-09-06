package controller_test

// §3.5 запрещает лестницу «попробуем это, потом то»: набор гипотез без
// замера. Эти проверки — про то, что такой функции в пакете больше нет и что
// очередь кандидатов выводится из вердикта classify.Run, а не угадывается.

import (
	"os"
	"strings"
	"testing"

	"github.com/necronicle/d2k/internal/classify"
	"github.com/necronicle/d2k/internal/controller"
)

// TestКандидатыНеБерутсяИзСписка — защита от возврата лестницы.
//
// Проверка на архитектуру, а не на поведение: пока в пакете есть функция,
// порождающая набор гипотез из наблюдения и без единого зонда, — это ровно
// generate(), удалённая этой задачей, — проект нарушает §3.5. Проверяем
// исходный текст, а не факт существования какого-то отдельного файла: имени
// «лестница жила в своём файле» не было даже до правки — она жила прямо в
// candidates.go, и повторное её появление скорее всего произойдёт там же.
func TestКандидатыНеБерутсяИзСписка(t *testing.T) {
	for _, path := range []string{"candidates.go", "controller.go"} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "func generate(") {
			t.Fatalf("функция generate (лестница кандидатов без замера) вернулась в %s", path)
		}
	}
}

// candidateLines — строки журнала, где кандидат ПРЕДЛОЖЕН («пробую plan-
// ...», см. advance() в controller.go), а не любая строка, где слово
// встретилось по соседству. Нужно ровно из-за одной такой соседней строки:
// askVolume (volume_probe.go, ось объёма, трогать которую эта задача не
// должна) объясняет СВОЙ вопрос словами «...дело в имени, а не в разрезе» —
// это предложение про то, что объём НЕ про разрез, и оно есть в журнале
// КАЖДОЙ задачи, как только транспорт встал, независимо от вердикта
// classify.Run. Голый strings.Contains(log, "разрез") цеплял бы её всегда и
// не отличал бы вердикты вовсе — проверять нужно именно строку применения
// кандидата.
func candidateLines(log string) string {
	var out []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "пробую plan-") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// TestОчередьЗависитОтВердикта — главная проверка задачи: очередь кандидатов
// СЛЕДУЕТ ИЗ ВЕРДИКТА classify.Run, а не одинакова для любой коробки.
func TestОчередьЗависитОтВердикта(t *testing.T) {
	r := newRig(t)
	r.classify.set(classify.VerdictPrefix, 8)
	r.say("hello prefix.example")
	r.say("rst")
	r.pump(10)
	if !strings.Contains(candidateLines(r.log.String()), "разрез") {
		t.Fatalf("для префиксного матчера не предложен разрез:\n%s", r.log)
	}

	r2 := newRig(t)
	r2.classify.set(classify.VerdictOpaque, 0)
	r2.say("hello opaque.example")
	r2.say("rst")
	r2.pump(10)
	if strings.Contains(candidateLines(r2.log.String()), "разрез") {
		t.Fatalf("для пересобирающей коробки предложен разрез, который её не берёт:\n%s", r2.log)
	}
}

// TestПересобирающаяКоробкаПолучаетВопросыВПорядкеОпроса проверяет очередь
// пересобирающей коробки не только «от противного» (нет слова «разрез»), но
// и по существу: первым кандидатом идёт ПЕРВЫЙ вопрос classify.PropProbes —
// тот порядок задан ценой таймаута (перекрытие слева отвечает быстрее
// прочих, см. её же комментарий), а не порядком classify.Compose, который
// собирает уже измеренное и здесь неприменим.
func TestПересобирающаяКоробкаПолучаетВопросыВПорядкеОпроса(t *testing.T) {
	r := newRig(t)
	r.classify.set(classify.VerdictOpaque, 0)

	r.say("hello opaque2.example")
	r.say("rst")
	r.pump(15)

	first := classify.PropProbes()[0].Name
	logs := r.log.String()
	if !strings.Contains(logs, "«"+first+"»") {
		t.Fatalf("первым кандидатом пересобирающей коробки не пошёл вопрос %q:\n%s", first, logs)
	}
}

// TestВердиктClearЗакрываетПоискБезЗаписи — §2.3 применительно к classify:
// «обходить нечего» не отказ и не решение, а честный конец поиска, и на
// диске от него не должно остаться ничего.
func TestВердиктClearЗакрываетПоискБезЗаписи(t *testing.T) {
	r := newRig(t)
	r.classify.set(classify.VerdictClear, 0)

	r.say("hello clear.example")
	r.say("rst")
	r.pump(10)

	if len(r.ctrl.Tasks()) != 0 {
		t.Fatalf("поиск остался открытым после вердикта clear:\n%s", r.log)
	}
	if n := len(r.store.Catalog().Boxes); n != 0 {
		t.Fatalf("вердикт clear записал %d коробок — обходить было нечего", n)
	}
	if !strings.Contains(r.log.String(), "обходить нечего") {
		t.Fatalf("вердикт clear не отмечен в журнале:\n%s", r.log)
	}
}

// TestНеопределённыйВердиктЗакрываетПоискСловамиПричины — inconclusive,
// flaky и unreachable вердикта не дают (§2.4): ничего не сохраняется, поиск
// закрывается, а причина уходит в журнал словами измерения (Result.Reason
// уже человеческий — см. classify.go).
func TestНеопределённыйВердиктЗакрываетПоискСловамиПричины(t *testing.T) {
	r := newRig(t)
	r.classify.set(classify.VerdictFlaky, 0)

	r.say("hello flaky.example")
	r.say("rst")
	r.pump(10)

	logs := r.log.String()
	if len(r.ctrl.Tasks()) != 0 {
		t.Fatalf("поиск остался открытым после неопределённого вердикта:\n%s", logs)
	}
	if n := len(r.store.Catalog().Boxes); n != 0 {
		t.Fatalf("неопределённый вердикт записал %d коробок", n)
	}
	if !strings.Contains(logs, "стенд: вердикт задан сценарием теста") {
		t.Fatalf("причина измерения не попала в журнал словами:\n%s", logs)
	}
	if !strings.Contains(logs, "не сохранено ничего") {
		t.Fatalf("неопределённый вердикт не отмечен как закрытие без записи:\n%s", logs)
	}
}

// TestКлассификацияЗапрашиваетсяОдинРаз — судорожное обновление страницы не
// должно запускать classify.Run заново на каждое подозрение: он уже стоит
// одним из пяти зондов на бюджет задачи (§5), и повторный запуск на F5 сжёг
// бы этот бюджет за пару нажатий.
func TestКлассификацияЗапрашиваетсяОдинРаз(t *testing.T) {
	r := newRig(t)
	r.classify.set(classify.VerdictOpaque, 0)

	for i := 0; i < 5; i++ {
		r.say("hello repeat.example")
		r.say("rst")
	}
	r.pump(20)

	if n := r.classify.count(); n != 1 {
		t.Fatalf("classify.Run вызван %d раз, а задача одна:\n%s", n, r.log)
	}
}

// TestЗондКлассификацииИдётСМеткой — §5.5: активный поиск обязан метить
// зонд классификации SO_MARK'ом (иначе датапат может преобразовать его как
// обычный трафик, и вердикт, особенно clear, окажется недостоверным — см.
// classify.Options.Mark, Result.Marked, onClassify). Проверяем то, что
// РЕАЛЬНО дошло до classify.Options, а не то, что должно было дойти.
func TestЗондКлассификацииИдётСМеткой(t *testing.T) {
	r := newRig(t)
	r.classify.set(classify.VerdictOpaque, 0)

	r.say("hello marked.example")
	r.say("rst")
	r.pump(10)

	if got := r.classify.mark(); got != controller.DefaultMark {
		t.Fatalf("зонд классификации ушёл с меткой %#x, а умолчание — %#x", got, controller.DefaultMark)
	}

	// SetMark переопределяет умолчание — из конфигурации (cmd/d2k), не
	// константа контроллера.
	r2 := newRig(t)
	r2.classify.set(classify.VerdictOpaque, 0)
	r2.ctrl.SetMark(0x99)

	r2.say("hello marked2.example")
	r2.say("rst")
	r2.pump(10)

	if got := r2.classify.mark(); got != 0x99 {
		t.Fatalf("SetMark(0x99) не дошёл до зонда: получено %#x", got)
	}
}

// TestЗапасногоПланаБезВердиктаОжидаетсяЯвно — путь «вердикта ещё нет →
// единственный кандидат из classify.Compose на пустом векторе свойств»
// исполняется почти в каждом тесте этого файла как побочный эффект гонки
// между classify и постановкой первого кандидата, но ни один тест не
// утверждает этого явно. classify.hold держит вердикт бесконечно, пока
// тест не отпустит его сам, — единственная кандидатура, доступная
// контроллеру всё это время, обязана быть ИМЕННО тем планом, который
// строит classify.Compose(classify.Properties{}, decoy).
func TestЗапасногоПланаБезВердиктаОжидаетсяЯвно(t *testing.T) {
	r := newRig(t)
	hold := make(chan struct{})
	r.classify.hold = hold
	t.Cleanup(func() { close(hold) })

	r.say("hello fallback.example")
	r.say("rst")
	r.pump(5)

	logs := r.log.String()
	if !strings.Contains(candidateLines(logs), "запасной план") {
		t.Fatalf("без вердикта не предложен запасной план:\n%s", logs)
	}

	want, err := classify.Compose(classify.Properties{}, controller.DecoySNI)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 1 {
		t.Fatalf("classify.Compose на пустом векторе дал %d планов, ожидался один", len(want))
	}
	if !strings.Contains(candidateLines(logs), want[0].ID) {
		t.Fatalf("предложенный план не совпадает с classify.Compose(Properties{}, decoy) (%s):\n%s",
			want[0].ID, logs)
	}
}
