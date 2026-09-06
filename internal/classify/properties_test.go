package classify

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/plan"
)

// Три проверки ниже — из брифа задачи 4 дословно (Step 1). Они фиксируют
// главное правило (§6.2 п.2) прежде, чем в файле появится хоть одна строка
// реализации.

func TestИзПромахаСвойствоНеВыводится(t *testing.T) {
	// §6.2 п.2 — прямой запрет. Промах объясняется разбором L7, шумом линии и
	// чем угодно ещё; записать из него «коробка сумму проверяет» значит
	// выдумать механизм.
	var pr Properties
	for _, p := range PropProbes() {
		p.Set(&pr, false)
	}
	if pr.ValidatesChecksum != nil {
		t.Error("из промаха выведена проверка суммы")
	}
	if pr.ParsesL7 != nil {
		t.Error("из промаха выведен разбор протокола")
	}
	if pr.CountsDuplicates != nil {
		t.Error("из промаха выведен счёт дубликатов")
	}
}

func TestПроходЗаписываетСвойствоОднозначно(t *testing.T) {
	var pr Properties
	setByName(t, PropProbes(), &pr, "контрольная сумма", true)
	if pr.ValidatesChecksum == nil || *pr.ValidatesChecksum {
		t.Fatal("проглоченная битая сумма обязана означать «сумму не сверяет»")
	}
}

// setByName находит вопрос по имени и передаёт ему passed. По ревью:
// тест с фильтром по имени, который ни разу не совпал, проходит вхолостую
// (pr остаётся нулевым) — имена вопросов ничем не типизированы, и опечатка
// или переименование не должны тихо проглатываться пустым циклом. Все тесты
// ниже, что раньше фильтровали PropProbes() по Name внутри собственного
// цикла, переведены на этот помощник.
func setByName(t *testing.T, probes []PropProbe, pr *Properties, name string, passed bool) {
	t.Helper()
	for _, p := range probes {
		if p.Name == name {
			p.Set(pr, passed)
			return
		}
	}
	t.Fatalf("вопрос %q не найден среди PropProbes — фильтр по имени разошёлся с реализацией", name)
}

func TestСборкаИдётИзВектораАНеИзСписка(t *testing.T) {
	// Свойств нет вовсе — собрать нечего, кроме одного честного «всё сразу».
	empty, err := Compose(Properties{}, "отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 1 {
		t.Fatalf("без свойств собрано %d кандидатов, ожидался один", len(empty))
	}

	// Измерено, что перекрытие слева коробка не терпит — сборка обязана его
	// использовать, и результат обязан отличаться от случая без свойств.
	no := false
	got, err := Compose(Properties{ToleratesLeftOverlap: &no}, "отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("измеренное свойство не дало ни одного кандидата")
	}
	if got[0].Text == empty[0].Text {
		t.Fatal("сборка не зависит от вектора свойств — это список, а не вывод")
	}
}

// TestПорядокВопросовЗаданЗамером — task-4-plans.md, раздел «Порядок
// вопросов»: первым перекрытие слева (единственный приём из пяти, что уже
// брал живые коробки, и его провал стоит целого таймаута), дальше разнесённые
// дубликаты, порядок, сумма, разбор протокола. Порядок в таблице брифа
// (Step 3) другой — но задачу явно просили соблюсти порядок из plans.md, а не
// из таблицы.
func TestПорядокВопросовЗаданЗамером(t *testing.T) {
	want := []string{
		"перекрытие слева",
		"счёт дубликатов",
		"порядок сегментов",
		"контрольная сумма",
		"разбор протокола",
	}
	probes := PropProbes()
	if len(probes) != len(want) {
		t.Fatalf("вопросов %d, ожидалось %d", len(probes), len(want))
	}
	for i, name := range want {
		if probes[i].Name != name {
			t.Errorf("вопрос %d: имя %q, ожидалось %q", i, probes[i].Name, name)
		}
	}
}

// TestРазборПротоколаНеЗависитОтИсходаВопросаОСумме — ловушка донора наоборот
// (task-4-plans.md, «Разбор протокола»): вопрос о сумме («контрольная сумма»)
// здесь НИ РАЗУ не задавался — даже с промахом. Проход одного лишь вопроса о
// разборе протокола обязан сам по себе, без единого чужого предусловия,
// записать оба факта. Если бы Set читал pr.ValidatesChecksum как
// предусловие, этот тест остался бы зелёным по совпадению (поле nil), но
// реализация ниже вообще не читает pr — только пишет, что делает ловушку
// структурно невозможной, а не случайно избегнутой.
func TestРазборПротоколаНеЗависитОтИсходаВопросаОСумме(t *testing.T) {
	var pr Properties
	setByName(t, PropProbes(), &pr, "разбор протокола", true)
	if pr.ParsesL7 == nil || !*pr.ParsesL7 {
		t.Fatal("проход вопроса о разборе протокола обязан записать ParsesL7=true")
	}
	if pr.ValidatesChecksum == nil || *pr.ValidatesChecksum {
		t.Fatal("тот же проход обязан записать ValidatesChecksum=false — коробка проглотила биту сумму")
	}
}

// TestКонтрольнаяСуммаНеОбъявляетРазборПротокола — обратная сторона той же
// ловушки: филлер (мусор, не приветствие) не доказывает разбор протокола
// вообще ничем, и проход вопроса о сумме не имеет права трогать ParsesL7.
func TestКонтрольнаяСуммаНеОбъявляетРазборПротокола(t *testing.T) {
	var pr Properties
	setByName(t, PropProbes(), &pr, "контрольная сумма", true)
	if pr.ParsesL7 != nil {
		t.Fatal("проход вопроса о сумме (мусор, не приветствие) не доказывает разбор протокола")
	}
}

// TestРазборПротоколаНеТянетНепройденныйПланСуммы — ревью: «разбор протокола»
// пишет ОБА поля (ParsesL7, ValidatesChecksum) из одного прохода (см. выше).
// Compose не имеет права читать ValidatesChecksum=false как «checksumPlan
// тоже проходил» — сам checksumPlan (голая набивка) здесь ни разу не
// запускался, а по модели task-4-plans.md (п.3) на коробке, что РАЗБИРАЕТ
// TLS, набивка заведомо не сработает. Единственный кандидат обязан быть
// parseProtocolPlan — планом, который реально прошёл.
func TestРазборПротоколаНеТянетНепройденныйПланСуммы(t *testing.T) {
	var pr Properties
	setByName(t, PropProbes(), &pr, "разбор протокола", true)

	got, err := Compose(pr, "x")
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseProtocolPlan("x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("кандидатов %d, ожидался ровно один (parseProtocolPlan): %+v", len(got), got)
	}
	if got[0].Text != want.Text {
		t.Fatal("единственный кандидат обязан быть parseProtocolPlan — планом, который реально прошёл")
	}
}

// TestКонтрольнаяСуммаОднаДобавляетСвойПлан — обратная сторона предыдущего
// теста: когда ValidatesChecksum=false пришёл САМ ПО СЕБЕ (вопрос «разбор
// протокола» вовсе не задавался, ParsesL7 == nil), новый гейт не имеет права
// выбросить план заодно с ложноположительным случаем выше.
func TestКонтрольнаяСуммаОднаДобавляетСвойПлан(t *testing.T) {
	var pr Properties
	setByName(t, PropProbes(), &pr, "контрольная сумма", true)

	got, err := Compose(pr, "x")
	if err != nil {
		t.Fatal(err)
	}
	want, err := checksumPlan("x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Text != want.Text {
		t.Fatalf("вопрос о сумме прошёл сам по себе — Compose обязан предложить checksumPlan: %+v", got)
	}
}

// TestПорядокКандидатовПерекрытиеПорядокСерия — Compose, Step 4 брифа:
// «сперва то, что прямо следует из измеренного (перекрытие, порядок,
// серия)». Порядок здесь СВОЙ, отличный от порядка опроса (там он подчинён
// цене таймаута, а не приоритету кандидата).
func TestПорядокКандидатовПерекрытиеПорядокСерия(t *testing.T) {
	no := false
	yes := true
	pr := Properties{
		ToleratesLeftOverlap: &no,
		ToleratesReorder:     &no,
		CountsDuplicates:     &yes,
	}
	got, err := Compose(pr, "отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("кандидатов %d, ожидалось 3: %+v", len(got), got)
	}
	overlap, err := overlapPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	reorder, err := reorderPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	dup, err := duplicatesPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Text != overlap.Text {
		t.Errorf("первым обязан идти кандидат перекрытия")
	}
	if got[1].Text != reorder.Text {
		t.Errorf("вторым обязан идти кандидат порядка")
	}
	if got[2].Text != dup.Text {
		t.Errorf("третьим обязана идти серия дубликатов")
	}
}

// TestКаждыйПланПереводитсяВКаноническуюФорму — сверх брифа: кандидат,
// который не переводится в каноническую форму, не должен доехать до
// датапата и быть отвергнутым ТАМ — там уже идёт чужое соединение, и поздно
// (тот же довод — в controller.wrap). Проверяется весь круг «текст → план →
// TLV», а не только то, что build() однажды не вернул ошибку при сборке.
func TestКаждыйПланПереводитсяВКаноническуюФорму(t *testing.T) {
	plans := map[string]catalog.Plan{}
	for _, p := range PropProbes() {
		cp, err := p.Plan("отвод.example")
		if err != nil {
			t.Fatalf("вопрос %q: план не построился: %v", p.Name, err)
		}
		plans[p.Name] = cp
	}
	all, err := Compose(Properties{}, "отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	plans["всё сразу"] = all[0]

	for name, cp := range plans {
		if cp.Proto != "tls" {
			t.Errorf("%s: proto %q, ожидался tls", name, cp.Proto)
		}
		pp, err := plan.ParseText(cp.Text)
		if err != nil {
			t.Fatalf("%s: текст плана не разобрался обратно: %v\n%s", name, err, cp.Text)
		}
		if _, err := pp.MarshalTLV(); err != nil {
			t.Fatalf("%s: план не собирается в TLV: %v", name, err)
		}
	}
}

// runPlanLab гоняет ТОТ ЖЕ исполнитель, что пойдёт в датапат (по образцу
// internal/plan.runLab — тот неэкспортирован, поэтому здесь свой,
// минимальный). Второй реализации преобразований не появляется: план берётся
// текстом, кодируется этим же пакетом plan и скармливается planlab.
func runPlanLab(t *testing.T, planText, scenario string) string {
	t.Helper()
	lab := filepath.Join("..", "..", "datapath", "planlab")
	if _, err := os.Stat(lab); err != nil {
		// Пропущенный тест выглядит как пройденный. Локально пропуск терпим,
		// в CI (scripts/check.sh выставляет D2K_REQUIRE_LAB) — нет.
		if os.Getenv("D2K_REQUIRE_LAB") != "" {
			t.Fatalf("planlab не собран, а D2K_REQUIRE_LAB выставлена: %v", err)
		}
		t.Skip("planlab не собран: cd datapath && make planlab")
	}

	p, err := plan.ParseText(planText)
	if err != nil {
		t.Fatalf("разбор плана: %v", err)
	}
	raw, err := p.MarshalTLV()
	if err != nil {
		t.Fatalf("кодирование плана: %v", err)
	}

	dir := t.TempDir()
	pf := filepath.Join(dir, "p.tlv")
	sf := filepath.Join(dir, "s.txt")
	if err := os.WriteFile(pf, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sf, []byte(scenario), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(lab, pf, sf).CombinedOutput()
	if err != nil {
		t.Fatalf("planlab: %v\n%s", err, out)
	}
	return string(out)
}

// TestЛабораторияПерекрытиеСдвигаетНомерИНесётПриставку — заявленное в задаче
// поведение: «перекрытие даёт номер 999 вместо 1000 и приставку впереди».
func TestЛабораторияПерекрытиеСдвигаетНомерИНесётПриставку(t *testing.T) {
	cp, err := overlapPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	out := runPlanLab(t, cp.Text, "pkt 1000 none 0 aabbccddeeff00112233\n")
	if strings.HasPrefix(out, "reject") {
		t.Fatalf("план перекрытия отвергнут: %s", out)
	}
	fields := strings.Fields(out)
	// emit payload <delay> <seq> ttl=.. poison=.. <pre+payload hex>
	if len(fields) < 7 || fields[0] != "emit" || fields[1] != "payload" {
		t.Fatalf("не одна посылка нагрузки: %s", out)
	}
	if fields[3] != "999" {
		t.Errorf("номер %s, ожидался 999 (1000 минус байт приставки)", fields[3])
	}
	if !strings.HasPrefix(fields[6], "41") {
		t.Errorf("приставка не найдена впереди: %s", fields[6])
	}
}

// TestЛабораторияПорядокШлётХвостРаньшеГоловы — заявленное поведение:
// «порядок шлёт хвост раньше головы».
func TestЛабораторияПорядокШлётХвостРаньшеГоловы(t *testing.T) {
	cp, err := reorderPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	out := runPlanLab(t, cp.Text, "pkt 2000 none 0 000102030405060708090a0b0c0d0e0f1011121314\n")
	if strings.HasPrefix(out, "reject") || strings.Contains(out, "refuse") {
		t.Fatalf("план порядка отвергнут либо неприменим: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var payloadLines [][]string
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) > 1 && f[0] == "emit" && f[1] == "payload" {
			payloadLines = append(payloadLines, f)
		}
	}
	if len(payloadLines) != 2 {
		t.Fatalf("кусков нагрузки %d, ожидалось 2: %s", len(payloadLines), out)
	}
	// Хвост (более поздний номер) обязан уйти ПЕРВОЙ строкой.
	if payloadLines[0][3] <= payloadLines[1][3] {
		t.Errorf("первым уходит не хвост: номера %s затем %s", payloadLines[0][3], payloadLines[1][3])
	}
}

// TestЛабораторияПовторыДаютВторуюКопиюСПаузой — заявленное поведение:
// «повторы дают вторую копию с паузой 20000 мкс».
func TestЛабораторияПовторыДаютВторуюКопиюСПаузой(t *testing.T) {
	cp, err := duplicatesPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	out := runPlanLab(t, cp.Text, "pkt 1000 none 0 aabb\n")
	if strings.HasPrefix(out, "reject") {
		t.Fatalf("план дубликатов отвергнут: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var fakeLines [][]string
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) > 1 && f[0] == "emit" && f[1] == "fake" {
			fakeLines = append(fakeLines, f)
		}
	}
	if len(fakeLines) != 2 {
		t.Fatalf("копий фальшивки %d, ожидалось 2: %s", len(fakeLines), out)
	}
	if fakeLines[0][2] != "0" {
		t.Errorf("первая копия с задержкой %s, ожидался 0", fakeLines[0][2])
	}
	if fakeLines[1][2] != "20000" {
		t.Errorf("вторая копия с задержкой %s, ожидалось 20000мкс", fakeLines[1][2])
	}
	// Обе копии несут испорченную сумму — сервер их выбросит, коробка (если
	// не сверяет сумму) — нет.
	for i, f := range fakeLines {
		if f[5] != "poison=01" {
			t.Errorf("копия %d: %s, ожидалась испорченная сумма poison=01", i, f[5])
		}
	}
}

// TestЛабораторияПриманкиНеОтвергаютсяИРазличаютсяСодержимым — вопросы 3 и 4
// (сумма и разбор протокола) отличаются РОВНО содержимым приманки: набивка
// против целого приветствия. Само различие — не косметика (task-4-plans.md,
// п.3), и здесь оно проверяется по факту, а не по описанию.
func TestЛабораторияПриманкиНеОтвергаютсяИРазличаютсяСодержимым(t *testing.T) {
	sumPlan, err := checksumPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	parsePlan, err := parseProtocolPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	if sumPlan.Text == parsePlan.Text {
		t.Fatal("план суммы и план разбора протокола совпали — вопросы неразличимы")
	}

	scenario := "pkt 1000 none 0 aabb\n"
	sumOut := runPlanLab(t, sumPlan.Text, scenario)
	parseOut := runPlanLab(t, parsePlan.Text, scenario)
	for name, out := range map[string]string{"сумма": sumOut, "разбор протокола": parseOut} {
		if strings.HasPrefix(out, "reject") {
			t.Fatalf("план %q отвергнут: %s", name, out)
		}
		if !strings.Contains(out, "emit fake ") {
			t.Fatalf("план %q не выпустил фальшивку: %s", name, out)
		}
	}
	f := strings.Fields(strings.Split(sumOut, "\n")[0])
	if !strings.HasPrefix(f[6], "4141") {
		t.Errorf("приманка суммы не похожа на набивку: %s", f[6])
	}
	fp := strings.Fields(strings.Split(parseOut, "\n")[0])
	if !strings.HasPrefix(fp[6], "160301") {
		t.Errorf("приманка разбора протокола не похожа на TLS-приветствие: %s", fp[6])
	}
}

// TestЛабораторияВсёСразуИсполняетТриПриёмаВместе — everythingPlan едет по
// умолчанию при КАЖДОМ первом контакте с незнакомой коробкой (пустой вектор
// свойств) и был единственным из шести планов без поведенческой проверки
// через planlab (по ревью). Комбинация «seqovl + split + fake + reverse»
// стала возможной только с коммитом 898ea00 (переворот по kind, а не по
// сравнению указателей из разных выделений памяти) — до него эта же
// проверка была бы недостоверна: план собрался бы, но исполнитель мог
// увести фальшивку в перевёрнутый диапазон вместе с кусками.
func TestЛабораторияВсёСразуИсполняетТриПриёмаВместе(t *testing.T) {
	cp, err := everythingPlan("отвод.example")
	if err != nil {
		t.Fatal(err)
	}
	// Тот же 20-байтовый сценарий, что и у остальных лабораторных тестов:
	// середина на байте 10 даёт хвост длиной 10 (сдвиг +10) и голову длиной
	// 10 (сдвиг -1 из-за приставки перекрытия) — числа проверены planlab'ом
	// вручную перед тем, как их здесь закрепить.
	out := runPlanLab(t, cp.Text, "pkt 1000 none 0 aabbccddeeff00112233445566778899aabbccdd\n")
	if strings.HasPrefix(out, "reject") {
		t.Fatalf("план «всё сразу» отвергнут: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 5 { // 2 фальшивки + хвост + голова + fate
		t.Fatalf("строк %d, ожидалось 5 (2 фальшивки, 2 куска, fate): %s", len(lines), out)
	}

	fake0, fake1 := strings.Fields(lines[0]), strings.Fields(lines[1])
	tail, head := strings.Fields(lines[2]), strings.Fields(lines[3])

	if fake0[1] != "fake" || fake1[1] != "fake" {
		t.Fatalf("первыми обязаны идти две фальшивки: %v / %v", fake0, fake1)
	}
	if fake0[2] != "0" || fake1[2] != "20000" {
		t.Errorf("задержки фальшивок %s/%s, ожидались 0/20000 (разнесённая пара)", fake0[2], fake1[2])
	}
	if fake0[5] != "poison=01" || fake1[5] != "poison=01" {
		t.Errorf("фальшивки без битой суммы: %s / %s", fake0[5], fake1[5])
	}

	if tail[1] != "payload" || head[1] != "payload" {
		t.Fatalf("после фальшивок ожидались куски нагрузки: %v / %v", tail, head)
	}
	// Обратный порядок: хвост уходит ПЕРВЫМ, без приставки перекрытия — она
	// стоит на куске, что при построении был первым (см. head ниже), а
	// переворот меняет местами ОТПРАВКУ, а не то, к какому куску приставлена
	// приставка.
	if tail[3] != "1010" {
		t.Errorf("хвост с номером %s, ожидался 1010 (1000+10, середина 20-байтового сценария)", tail[3])
	}
	// Голова уходит ВТОРОЙ и несёт приставку перекрытия — номер сдвинут
	// назад на длину приставки (1 байт).
	if head[3] != "999" {
		t.Errorf("голова с номером %s, ожидался 999 (1000 минус байт приставки)", head[3])
	}
	if !strings.HasPrefix(head[6], "41") {
		t.Errorf("приставка перекрытия не найдена впереди головы: %s", head[6])
	}
	if lines[4] != "fate drop" {
		t.Errorf("fate %q, ожидался drop — нагрузку выпустили сами", lines[4])
	}
}
