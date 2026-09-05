package plan

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var anchorNames = map[Anchor]string{
	AnchorPayloadStart: "payload_start",
	AnchorSNIStart:     "sni_start",
	AnchorSNIEnd:       "sni_end",
	AnchorHelloMiddle:  "hello_middle",
	AnchorRecordEnd:    "record_end",
}

func anchorByName(s string) (Anchor, bool) {
	for a, n := range anchorNames {
		if n == s {
			return a, true
		}
	}
	return 0, false
}

var transportNames = map[uint8]string{6: "tcp", 17: "udp"}
var protoNames = map[uint8]string{0: "unknown", 1: "tls", 2: "quic"}

func byName(m map[uint8]string, s string) (uint8, bool) {
	for v, n := range m {
		if n == s {
			return v, true
		}
	}
	return 0, false
}

// Text — человеческая форма плана.
//
// Порядок строк фиксирован, а приманки и порча сортируются по номеру: круг
// «текст → план → текст» обязан сходиться побайтово, а diff в git — показывать
// изменение плана, а не перестановку записей.
func (p Plan) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "d2k-plan %d %d\n", p.Schema, p.MinExec)
	fmt.Fprintf(&b, "id %s\n", hex.EncodeToString(p.ID[:]))
	fmt.Fprintf(&b, "proto %s %s\n", transportNames[p.Transport], protoNames[p.Proto])

	pl := append([]Payload(nil), p.Payloads...)
	sort.Slice(pl, func(i, j int) bool { return pl[i].ID < pl[j].ID })
	for _, v := range pl {
		fmt.Fprintf(&b, "payload %d %s\n", v.ID, hex.EncodeToString(v.Bytes))
	}

	po := append([]Poison(nil), p.Poisons...)
	sort.Slice(po, func(i, j int) bool { return po[i].ID < po[j].ID })
	for _, v := range po {
		fmt.Fprintf(&b, "poison %d", v.ID)
		if v.TTL != 0 {
			fmt.Fprintf(&b, " ttl=%d", v.TTL)
		}
		if v.Flags&PoisonBadSum != 0 {
			b.WriteString(" badsum")
		}
		if v.Flags&PoisonTCPTSBack != 0 {
			b.WriteString(" tcpts")
		}
		if v.Flags&PoisonIPIDZero != 0 {
			b.WriteString(" ipidzero")
		}
		if v.SeqShift != 0 {
			fmt.Fprintf(&b, " seqshift=%d", v.SeqShift)
		}
		b.WriteString("\n")
	}

	for _, s := range p.Splits {
		fmt.Fprintf(&b, "split %s %+d\n", anchorNames[s.Anchor], s.Offset)
	}
	for _, f := range p.Fakes {
		place := "before"
		if f.Placement == PlaceBetween {
			place = "between"
		}
		fmt.Fprintf(&b, "fake payload=%d poison=%d repeats=%d gap_us=%d place=%s\n",
			f.PayloadID, f.PoisonID, f.Repeats, f.GapUS, place)
	}
	for _, s := range p.Seqovls {
		fmt.Fprintf(&b, "seqovl payload=%d poison=%d\n", s.PayloadID, s.PoisonID)
	}
	ord := "forward"
	if p.Order == OrderReverse {
		ord = "reverse"
	}
	fmt.Fprintf(&b, "order %s\n", ord)
	return b.String()
}

// ParseText разбирает человеческую форму.
//
// Неизвестная директива — ОШИБКА, а не повод пропустить строку. Молчаливый
// пропуск дал бы план, отличный от записанного, а §2.5 документа требует,
// чтобы измеренное совпадало с исполняемым: предупреждение о потерянном
// параметре не делает изменённую стратегию проверенной.
func ParseText(s string) (Plan, error) {
	var p Plan
	sc := bufio.NewScanner(strings.NewReader(s))
	line := 0
	seenHeader := false

	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)

		switch f[0] {
		case "d2k-plan":
			if len(f) != 3 {
				return p, fmt.Errorf("строка %d: заголовку нужны схема и версия исполнителя", line)
			}
			v, err := parseU16(f[1])
			if err != nil {
				return p, fmt.Errorf("строка %d: схема: %w", line, err)
			}
			p.Schema = v
			if v, err = parseU16(f[2]); err != nil {
				return p, fmt.Errorf("строка %d: версия исполнителя: %w", line, err)
			}
			p.MinExec = v
			seenHeader = true

		case "id":
			if len(f) != 2 {
				return p, fmt.Errorf("строка %d: id <32 hex-символа>", line)
			}
			raw, err := hex.DecodeString(f[1])
			if err != nil || len(raw) != 16 {
				return p, fmt.Errorf("строка %d: id — 16 байт в hex", line)
			}
			copy(p.ID[:], raw)

		case "proto":
			if len(f) != 3 {
				return p, fmt.Errorf("строка %d: proto <транспорт> <протокол>", line)
			}
			tr, ok := byName(transportNames, f[1])
			if !ok {
				return p, fmt.Errorf("строка %d: неизвестный транспорт %q", line, f[1])
			}
			pr, ok := byName(protoNames, f[2])
			if !ok {
				return p, fmt.Errorf("строка %d: неизвестный протокол %q", line, f[2])
			}
			p.Transport, p.Proto = tr, pr

		case "payload":
			if len(f) != 3 {
				return p, fmt.Errorf("строка %d: payload <номер> <hex>", line)
			}
			id, err := parseU16(f[1])
			if err != nil {
				return p, fmt.Errorf("строка %d: номер приманки: %w", line, err)
			}
			if id == 0 {
				return p, fmt.Errorf("строка %d: номер приманки 0 занят под «ничего»", line)
			}
			raw, err := hex.DecodeString(f[2])
			if err != nil {
				return p, fmt.Errorf("строка %d: байты приманки не hex", line)
			}
			p.Payloads = append(p.Payloads, Payload{ID: id, Bytes: raw})

		case "poison":
			if len(f) < 2 {
				return p, fmt.Errorf("строка %d: poison <номер> [признаки]", line)
			}
			id, err := parseU16(f[1])
			if err != nil {
				return p, fmt.Errorf("строка %d: номер порчи: %w", line, err)
			}
			if id == 0 {
				return p, fmt.Errorf("строка %d: номер порчи 0 занят под «ничего»", line)
			}
			po := Poison{ID: id}
			for _, a := range f[2:] {
				switch {
				case a == "badsum":
					po.Flags |= PoisonBadSum
				case a == "tcpts":
					po.Flags |= PoisonTCPTSBack
				case a == "ipidzero":
					po.Flags |= PoisonIPIDZero
				case strings.HasPrefix(a, "ttl="):
					n, err := strconv.ParseUint(a[4:], 10, 8)
					if err != nil {
						return p, fmt.Errorf("строка %d: ttl: %w", line, err)
					}
					po.TTL = uint8(n)
				case strings.HasPrefix(a, "seqshift="):
					n, err := strconv.ParseInt(a[9:], 10, 32)
					if err != nil {
						return p, fmt.Errorf("строка %d: seqshift: %w", line, err)
					}
					po.SeqShift = int32(n)
				default:
					return p, fmt.Errorf("строка %d: неизвестный признак порчи %q", line, a)
				}
			}
			p.Poisons = append(p.Poisons, po)

		case "split":
			if len(f) != 3 {
				return p, fmt.Errorf("строка %d: split <якорь> <смещение>", line)
			}
			a, ok := anchorByName(f[1])
			if !ok {
				return p, fmt.Errorf("строка %d: неизвестный якорь %q", line, f[1])
			}
			off, err := strconv.ParseInt(f[2], 10, 17)
			if err != nil || off < -32768 || off > 32767 {
				return p, fmt.Errorf("строка %d: смещение вне диапазона: %q", line, f[2])
			}
			p.Splits = append(p.Splits, Position{Anchor: a, Offset: int16(off)})

		case "fake":
			fk := Fake{}
			for _, a := range f[1:] {
				k, v, ok := strings.Cut(a, "=")
				if !ok {
					return p, fmt.Errorf("строка %d: %q без «=»", line, a)
				}
				switch k {
				case "payload":
					n, err := parseU16(v)
					if err != nil {
						return p, fmt.Errorf("строка %d: payload: %w", line, err)
					}
					fk.PayloadID = n
				case "poison":
					n, err := parseU16(v)
					if err != nil {
						return p, fmt.Errorf("строка %d: poison: %w", line, err)
					}
					fk.PoisonID = n
				case "repeats":
					n, err := strconv.ParseUint(v, 10, 8)
					if err != nil {
						return p, fmt.Errorf("строка %d: repeats: %w", line, err)
					}
					fk.Repeats = uint8(n)
				case "gap_us":
					n, err := strconv.ParseUint(v, 10, 32)
					if err != nil {
						return p, fmt.Errorf("строка %d: gap_us: %w", line, err)
					}
					fk.GapUS = uint32(n)
				case "place":
					switch v {
					case "before":
						fk.Placement = PlaceBefore
					case "between":
						fk.Placement = PlaceBetween
					default:
						return p, fmt.Errorf("строка %d: неизвестное размещение %q", line, v)
					}
				default:
					return p, fmt.Errorf("строка %d: неизвестное поле фальшивки %q", line, k)
				}
			}
			p.Fakes = append(p.Fakes, fk)

		case "seqovl":
			sq := Seqovl{}
			for _, a := range f[1:] {
				k, v, ok := strings.Cut(a, "=")
				if !ok {
					return p, fmt.Errorf("строка %d: %q без «=»", line, a)
				}
				n, err := parseU16(v)
				if err != nil {
					return p, fmt.Errorf("строка %d: %s: %w", line, k, err)
				}
				switch k {
				case "payload":
					sq.PayloadID = n
				case "poison":
					sq.PoisonID = n
				default:
					return p, fmt.Errorf("строка %d: неизвестное поле перекрытия %q", line, k)
				}
			}
			p.Seqovls = append(p.Seqovls, sq)

		case "order":
			if len(f) != 2 {
				return p, fmt.Errorf("строка %d: order forward|reverse", line)
			}
			switch f[1] {
			case "forward":
				p.Order = OrderForward
			case "reverse":
				p.Order = OrderReverse
			default:
				return p, fmt.Errorf("строка %d: неизвестный порядок %q", line, f[1])
			}

		default:
			return p, fmt.Errorf("строка %d: неизвестная директива %q", line, f[0])
		}
	}
	if err := sc.Err(); err != nil {
		return p, err
	}
	if !seenHeader {
		return p, fmt.Errorf("нет заголовка d2k-plan")
	}
	return p, nil
}

func parseU16(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	return uint16(n), err
}
