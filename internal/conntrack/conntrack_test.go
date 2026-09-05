package conntrack_test

import (
	"path/filepath"
	"testing"

	"github.com/necronicle/d2k/internal/conntrack"
)

// Образец снят с роутера владельца: разбирать надо то, что ядро печатает на
// самом деле, а не то, что написано в документации к формату.
func TestРазборНастоящейТаблицыРоутера(t *testing.T) {
	flows, err := conntrack.Read(filepath.Join("testdata", "router.txt"),
		conntrack.Match{DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) == 0 {
		t.Fatal("в образце с роутера не нашлось ни одного потока на 443")
	}
	for _, f := range flows {
		if f.DstPort != 443 {
			t.Fatalf("фильтр пропустил поток на порт %d", f.DstPort)
		}
		if f.SrcIP == "" || f.DstIP == "" {
			t.Fatalf("адреса не разобраны: %+v", f)
		}
		// Счётчики ОБОИХ направлений: ради них всё и затевалось. Одинаковые
		// ключи в строке встречаются дважды, и взять первый packets= за общее
		// число — самая естественная и самая неверная ошибка разбора.
		if f.OutBytes <= 0 {
			t.Fatalf("байты прямого направления не разобраны: %+v", f)
		}
	}
}

func TestОбратноеНаправлениеЭтоВтороеВхождение(t *testing.T) {
	// Строка ядра содержит по два src=, dst=, packets=, bytes= — сперва
	// прямое направление, потом обратное. Разбор, берущий первое вхождение
	// для всего, молча считает обратные байты прямыми.
	line := "ipv4     2 tcp      6 431999 ESTABLISHED " +
		"src=192.168.1.67 dst=1.2.3.4 sport=50000 dport=443 packets=11 bytes=1400 " +
		"src=1.2.3.4 dst=88.87.93.11 sport=443 dport=50000 packets=22 bytes=15994 " +
		"[ASSURED] mark=0 use=1"
	dir := t.TempDir()
	p := filepath.Join(dir, "ct")
	if err := writeFile(p, line+"\n"); err != nil {
		t.Fatal(err)
	}
	flows, err := conntrack.Read(p, conntrack.Match{})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("потоков %d", len(flows))
	}
	f := flows[0]
	if f.OutBytes != 1400 {
		t.Fatalf("прямые байты %d, а в строке 1400", f.OutBytes)
	}
	if f.InBytes != 15994 {
		t.Fatalf("обратные байты %d, а в строке 15994", f.InBytes)
	}
	if f.InPkts != 22 || f.OutPkts != 11 {
		t.Fatalf("пакеты перепутаны: прямых %d, обратных %d", f.OutPkts, f.InPkts)
	}
	if !f.Assured {
		t.Fatal("признак обмена в обе стороны потерян")
	}
	if f.State != "ESTABLISHED" {
		t.Fatalf("состояние %q", f.State)
	}
}

func TestIPv6НеПодмешивается(t *testing.T) {
	// У d2k пока только IPv4, и делать вид, что иначе, нельзя.
	line := "ipv6     10 tcp      6 431999 ESTABLISHED src=2a03::1 dst=2a03::2 " +
		"sport=50000 dport=443 packets=1 bytes=100 src=2a03::2 dst=2a03::1 " +
		"sport=443 dport=50000 packets=1 bytes=100 mark=0 use=1"
	dir := t.TempDir()
	p := filepath.Join(dir, "ct")
	if err := writeFile(p, line+"\n"); err != nil {
		t.Fatal(err)
	}
	flows, _ := conntrack.Read(p, conntrack.Match{})
	if len(flows) != 0 {
		t.Fatalf("IPv6 просочился в разбор: %+v", flows)
	}
}

func TestОтсутствиеТаблицыЭтоОшибкаАНеПустота(t *testing.T) {
	// Ядро без conntrack и «потоков нет» — разные утверждения.
	if _, err := conntrack.Read(filepath.Join(t.TempDir(), "нет"), conntrack.Match{}); err == nil {
		t.Fatal("отсутствие таблицы прошло как пустая таблица")
	}
}

func TestНеотвеченныйПотокРазбирается(t *testing.T) {
	// Поток без ответа — это [UNREPLIED], и обратные счётчики у него нулевые.
	// Ровно так выглядит блокировка ниже TLS: SYN уходит, ответа нет.
	// Разбор обязан отличать это от «мы не посмотрели».
	flows, err := conntrack.Read(filepath.Join("testdata", "router.txt"),
		conntrack.Match{DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	var unreplied int
	for _, f := range flows {
		if f.State == "SYN_SENT" && f.InPkts == 0 {
			unreplied++
			if f.OutPkts == 0 {
				t.Fatalf("у неотвеченного потока нет и прямых пакетов: %+v", f)
			}
		}
	}
	// Образец снят с живого роутера в момент, когда часть целей не отвечала;
	// если таких потоков не окажется — проверка не про что, и это надо знать.
	if unreplied == 0 {
		t.Skip("в образце нет неотвеченных потоков — проверять нечего")
	}
}
