// Package conntrack — счётчики потоков от ядра.
//
// Нужен ради одного класса блокировки, который иначе не виден вовсе:
// рукопожатие проходит, обмен идёт, и поток встаёт на десятке-другом
// килобайт. Окно наблюдения d2k — первые пакеты соединения, и обрыв на
// шестнадцатом килобайте за ним по построению (§5.2 требует проектировать
// обнаружение поздних обрывов отдельно — вот оно).
//
// Почему conntrack, а не контрольные мишени. Донор меряет этот класс
// отдельной пробой по курируемым адресам, но §2.3 запрещает d2k контрольные
// цели и фиксированные адреса: часть из них заблокирована и мимо линии, и
// ориентиром они не работают. Conntrack даёт то же знание из своего же
// трафика — и, что важно, замер этапа 0 показал, что его счётчики НЕ
// ослеплены аппаратной разгрузкой, в отличие от очереди.
package conntrack

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultPath — где ядро показывает таблицу.
const DefaultPath = "/proc/net/nf_conntrack"

// Flow — один поток глазами ядра.
type Flow struct {
	Proto    string
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	State    string
	OutPkts  int64
	OutBytes int64
	InPkts   int64
	InBytes  int64
	// Assured — ядро видело обмен в обе стороны.
	Assured bool
}

// Match — какие потоки интересны. Пустое поле означает «любой».
type Match struct {
	DstIP   string
	DstPort int
}

func (m Match) fits(f Flow) bool {
	if m.DstIP != "" && f.DstIP != m.DstIP {
		return false
	}
	if m.DstPort != 0 && f.DstPort != m.DstPort {
		return false
	}
	return true
}

// Read возвращает потоки, подходящие под match.
//
// Читается весь файл, но наружу отдаётся только нужное: на роутере таблица
// бывает в тысячи записей, и держать их все в памяти контроллера незачем.
// Фильтр обязателен по той же причине — §5.2 требует пределов на всё.
func Read(path string, match Match) ([]Flow, error) {
	if path == "" {
		path = DefaultPath
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("таблица потоков %s: %w", path, err)
	}
	defer fh.Close()

	var out []Flow
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f, ok := parseLine(sc.Text())
		if !ok || !match.fits(f) {
			continue
		}
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseLine разбирает строку таблицы.
//
// Формат позиционный только в начале; дальше идут пары ключ=значение, причём
// ОДИНАКОВЫЕ ключи встречаются дважды — сперва для прямого направления, потом
// для обратного. Именно поэтому разбор считает вхождения, а не ищет первое:
// взять первое src= и назвать его источником можно, а вот первое packets=
// назвать общим числом пакетов — уже нельзя.
func parseLine(s string) (Flow, bool) {
	var f Flow
	fields := strings.Fields(s)
	if len(fields) < 6 {
		return f, false
	}
	if fields[0] != "ipv4" {
		// IPv6 сюда не подмешиваем: у d2k пока только IPv4, и делать вид, что
		// иначе, нельзя.
		return f, false
	}
	f.Proto = fields[2]
	if f.Proto != "tcp" && f.Proto != "udp" {
		return f, false
	}
	/* Состояние берётся ПО МЕСТУ, а не по виду слова.
	   Раскладка начала строки: семейство, номер семейства, протокол, номер
	   протокола, таймаут, [состояние]. Догадка «слово из заглавных букв — это
	   состояние» ловила таймаут, потому что цифры тоже «в верхнем регистре».
	   У UDP состояния нет вовсе, и выдумывать его не надо. */
	if f.Proto == "tcp" && len(fields) > 5 && !strings.Contains(fields[5], "=") {
		f.State = fields[5]
	}

	seen := map[string]int{}
	for _, kv := range fields {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			if kv == "[ASSURED]" {
				f.Assured = true
			}
			continue
		}
		n := seen[k]
		seen[k] = n + 1
		switch {
		case k == "src" && n == 0:
			f.SrcIP = v
		case k == "dst" && n == 0:
			f.DstIP = v
		case k == "sport" && n == 0:
			f.SrcPort = atoi(v)
		case k == "dport" && n == 0:
			f.DstPort = atoi(v)
		case k == "packets" && n == 0:
			f.OutPkts = atoi64(v)
		case k == "bytes" && n == 0:
			f.OutBytes = atoi64(v)
		case k == "packets" && n == 1:
			f.InPkts = atoi64(v)
		case k == "bytes" && n == 1:
			f.InBytes = atoi64(v)
		}
	}
	return f, f.SrcIP != "" && f.DstIP != ""
}

func atoi(s string) int     { n, _ := strconv.Atoi(s); return n }
func atoi64(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }
