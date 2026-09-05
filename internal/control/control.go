// Package control — Go-сторона управляющего сокета.
//
// Тот же проводной формат, что и в datapath/ctl.c: [длина payload u32 BE]
// [тип u16 BE][payload]. Формат описан один раз в
// docs/decisions/0004-control-socket.md, и обе реализации обязаны ему
// подчиняться. Их согласие проверяется тестом, который гоняет настоящий d2kd
// против этого клиента, а не сравнением исходников на глаз.
//
// Событие — сообщение, а не обязательство. Датапат теряет события, когда
// сокет забит, и считает потери. Здесь это значит: последовательность событий
// НЕ полна, и делать выводы из отсутствия события нельзя.
package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Типы кадров. Обязаны совпадать с datapath/include/d2k_ctl.h.
const (
	EvHello    uint16 = 0x0001
	EvSuspect  uint16 = 0x0002
	EvApplied  uint16 = 0x0003
	EvRefused  uint16 = 0x0004
	EvExchange uint16 = 0x0005
	EvStats    uint16 = 0x0006

	CmdSetName uint16 = 0x0081
	CmdSetAddr uint16 = 0x0082
	CmdDelName uint16 = 0x0083
	CmdDelAddr uint16 = 0x0084
	CmdClear   uint16 = 0x0085
	CmdStats   uint16 = 0x0086
)

// Коды причин подозрения. Обязаны совпадать с datapath/include/d2k_journal.h.
const (
	SuspectRST    uint8 = 1
	SuspectRepeat uint8 = 2
	SuspectSilent uint8 = 3
	SuspectRSTCut uint8 = 4
)

// SuspectText — человеческое имя причины. Источник истины — код; текст
// выводится из него. Сравнивать поведение по тексту нельзя: правка
// формулировки сломала бы логику.
func SuspectText(code uint8) string {
	switch code {
	case SuspectRST:
		return "сброс в ответ на приветствие"
	case SuspectRepeat:
		return "приветствие повторено"
	case SuspectSilent:
		return "ответа на приветствие не было"
	case SuspectRSTCut:
		return "снят чужой сброс в ответ на приветствие"
	default:
		return fmt.Sprintf("подозрение с неизвестным кодом %d", code)
	}
}

// FrameMax — предел кадра, тот же, что у датапата.
const FrameMax = 65536

// Key — канонический ключ потока: низкий конец пары, затем высокий.
// Названия low/high, а не src/dst, потому что у соединения источника нет —
// он есть у пакета.
type Key struct {
	LowIP    [4]byte
	HighIP   [4]byte
	LowPort  uint16
	HighPort uint16
}

func (k Key) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d - %d.%d.%d.%d:%d",
		k.LowIP[0], k.LowIP[1], k.LowIP[2], k.LowIP[3], k.LowPort,
		k.HighIP[0], k.HighIP[1], k.HighIP[2], k.HighIP[3], k.HighPort)
}

func parseKey(b []byte) (Key, error) {
	var k Key
	if len(b) < 12 {
		return k, errors.New("ключ потока короче 12 байт")
	}
	copy(k.LowIP[:], b[0:4])
	copy(k.HighIP[:], b[4:8])
	// Порты лежат в сетевом порядке — ровно как в заголовке.
	k.LowPort = binary.BigEndian.Uint16(b[8:10])
	k.HighPort = binary.BigEndian.Uint16(b[10:12])
	return k, nil
}

// Event — то, что датапат увидел.
type Event struct {
	Type uint16
	Key  Key
	// Имя цели для EvHello. Пустое — нормальное состояние (§5.3), а не сбой.
	Name string
	// Код причины для EvSuspect.
	Code uint8
	// Чем подозрительный пакет отличался от остальных в том же потоке.
	// Ориентир RefTTL взят ИЗ ЭТОГО ЖЕ потока, поэтому разность осмысленна и
	// на чужой линии, где абсолютные значения другие. Из этого складывается
	// отпечаток поведения коробки (§3.3).
	TTL    uint8
	RefTTL uint8
	ToS    uint8
	IPID   uint16
	// Текст причины для EvRefused — свободный, только для показа.
	Note string

	// Для EvExchange: тип первой TLS-записи с обратной стороны и сколько
	// байт нагрузки пришло после приветствия.
	//
	// Это НАБЛЮДЕНИЕ, а не «работает». §4.2 требует различать уровни
	// доказательства: 0x16 (рукопожатие) и 0x15 (предупреждение) — разные
	// вещи, а «ответ пришёл» и «прикладной обмен завершён» тем более.
	// Различает их тот, кто принимает решение, то есть контроллер.
	RecordType uint8
	// Какие типы записей ВСТРЕЧАЛИСЬ в начале пакетов с обратной стороны.
	// Одного RecordType мало: он всегда 22, потому что первым сервер шлёт
	// ServerHello, а §4.2 прямо говорит, что этого недостаточно.
	SeenTypes uint8
	Bytes     uint32
}

// HasAppData — встречались ли прикладные данные. Это и есть признак, по
// которому уровень 3 отличается от уровня 2 (§4.2).
func (e Event) HasAppData() bool { return e.SeenTypes&(1<<(TLSAppData-20)) != 0 }

// Типы записей TLS, встречающиеся в ответе. Не для вывода «работает»: см.
// комментарий к полю RecordType.
const (
	TLSChangeCipherSpec uint8 = 20
	TLSAlert            uint8 = 21
	TLSHandshake        uint8 = 22
	TLSAppData          uint8 = 23
)

// Conn — подключение к датапату.
type Conn struct {
	c   net.Conn
	buf []byte
}

// Dial подключается к управляющему сокету датапата.
func Dial(path string) (*Conn, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return &Conn{c: c}, nil
}

func (c *Conn) Close() error { return c.c.Close() }

// SetDeadline нужен вызывающему: у датапата нет обязанности что-то прислать,
// и ждать вечно — значит повесить контроллер на молчащем сокете.
func (c *Conn) SetDeadline(t time.Time) error { return c.c.SetDeadline(t) }

func (c *Conn) send(typ uint16, body []byte) error {
	if len(body)+2 > FrameMax {
		return fmt.Errorf("кадр %#04x длиннее предела", typ)
	}
	f := make([]byte, 6+len(body))
	binary.BigEndian.PutUint32(f[0:4], uint32(2+len(body)))
	binary.BigEndian.PutUint16(f[4:6], typ)
	copy(f[6:], body)
	_, err := c.c.Write(f)
	return err
}

// SetPlanName ставит план для цели по имени. Имя точнее адреса и потому у
// датапата ищется первым.
func (c *Conn) SetPlanName(name string, tlv []byte) error {
	if len(name) == 0 || len(name) > 255 {
		return fmt.Errorf("имя цели длиной %d байт не годится", len(name))
	}
	body := make([]byte, 0, 1+len(name)+len(tlv))
	body = append(body, byte(len(name)))
	body = append(body, name...)
	body = append(body, tlv...)
	return c.send(CmdSetName, body)
}

// SetPlanAddr ставит план для цели по адресу. Запасной ключ: за одним адресом
// CDN стоят сотни имён, и приписывать по нему домен нельзя (§3.2).
func (c *Conn) SetPlanAddr(ip [4]byte, tlv []byte) error {
	body := make([]byte, 0, 4+len(tlv))
	body = append(body, ip[:]...)
	body = append(body, tlv...)
	return c.send(CmdSetAddr, body)
}

func (c *Conn) DelPlanName(name string) error {
	if len(name) == 0 || len(name) > 255 {
		return fmt.Errorf("имя цели длиной %d байт не годится", len(name))
	}
	return c.send(CmdDelName, append([]byte{byte(len(name))}, name...))
}

func (c *Conn) DelPlanAddr(ip [4]byte) error { return c.send(CmdDelAddr, ip[:]) }

// Next читает одно событие. Возвращает io.EOF, когда датапат закрылся.
func (c *Conn) Next() (Event, error) {
	var ev Event
	var hdr [6]byte
	if _, err := io.ReadFull(c.c, hdr[:]); err != nil {
		return ev, err
	}
	plen := binary.BigEndian.Uint32(hdr[0:4])
	if plen < 2 || plen > FrameMax {
		// Дальше по потоку идти нельзя: следующий заголовок пришлось бы
		// искать по выдуманному смещению.
		return ev, fmt.Errorf("кадр с невозможной длиной %d", plen)
	}
	ev.Type = binary.BigEndian.Uint16(hdr[4:6])

	body := make([]byte, plen-2)
	if _, err := io.ReadFull(c.c, body); err != nil {
		return ev, err
	}

	key, err := parseKey(body)
	if err != nil {
		return ev, err
	}
	ev.Key = key
	rest := body[12:]

	switch ev.Type {
	case EvHello:
		if len(rest) < 1 {
			return ev, errors.New("приветствие без длины имени")
		}
		n := int(rest[0])
		if len(rest) < 1+n {
			return ev, errors.New("имя короче объявленного")
		}
		ev.Name = string(rest[1 : 1+n])
	case EvSuspect:
		if len(rest) < 1 {
			return ev, errors.New("подозрение без кода")
		}
		ev.Code = rest[0]
		if len(rest) >= 6 {
			ev.TTL = rest[1]
			ev.RefTTL = rest[2]
			ev.ToS = rest[3]
			ev.IPID = binary.BigEndian.Uint16(rest[4:6])
		}
	case EvRefused:
		ev.Note = string(rest)
	case EvExchange:
		if len(rest) < 5 {
			return ev, errors.New("обмен без типа записи и длины")
		}
		ev.RecordType = rest[0]
		if len(rest) >= 6 {
			ev.SeenTypes = rest[1]
			ev.Bytes = binary.BigEndian.Uint32(rest[2:6])
		} else {
			ev.Bytes = binary.BigEndian.Uint32(rest[1:5])
		}
	}
	return ev, nil
}
