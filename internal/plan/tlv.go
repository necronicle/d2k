package plan

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Коды записей. Новая операция — новый код и подъём MinExec: исполнитель,
// встретив незнакомый код, обязан отвергнуть план целиком, а не пропустить
// запись. Пропуск дал бы исполнение плана, отличного от измеренного.
const (
	recID      uint16 = 0x0001
	recProto   uint16 = 0x0002
	recPayload uint16 = 0x0010
	recPoison  uint16 = 0x0011
	recSplit   uint16 = 0x0100
	recFake    uint16 = 0x0101
	recSeqovl  uint16 = 0x0102
	recOrder   uint16 = 0x0103
	recGuard   uint16 = 0x0104
)

var magic = [4]byte{'D', '2', 'K', 'P'}

const headerLen = 12

func putRec(b []byte, typ uint16, val []byte) []byte {
	var h [4]byte
	binary.BigEndian.PutUint16(h[0:2], typ)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(val)))
	b = append(b, h[:]...)
	return append(b, val...)
}

// checkRefs — ссылки внутри плана обязаны разрешаться.
//
// Проверка стоит здесь, а не только в исполнителе: план с висячей ссылкой
// нельзя даже породить. Иначе он доедет до C, там будет отвергнут, и мы узнаем
// об ошибке планировщика на роутере вместо сборки.
func (p Plan) checkRefs() error {
	payloads := map[uint16]bool{}
	for _, v := range p.Payloads {
		if payloads[v.ID] {
			return fmt.Errorf("приманка %d объявлена дважды", v.ID)
		}
		payloads[v.ID] = true
	}
	poisons := map[uint16]bool{}
	for _, v := range p.Poisons {
		if poisons[v.ID] {
			return fmt.Errorf("порча %d объявлена дважды", v.ID)
		}
		poisons[v.ID] = true
	}
	// Ноль означает «ничего» и висячей ссылкой не является.
	for i, f := range p.Fakes {
		if f.PayloadID == 0 {
			return fmt.Errorf("фальшивка %d без приманки: слать нечего", i)
		}
		if !payloads[f.PayloadID] {
			return fmt.Errorf("фальшивка %d ссылается на несуществующую приманку %d", i, f.PayloadID)
		}
		if f.PoisonID != 0 && !poisons[f.PoisonID] {
			return fmt.Errorf("фальшивка %d ссылается на несуществующую порчу %d", i, f.PoisonID)
		}
	}
	for i, s := range p.Seqovls {
		if s.PayloadID == 0 {
			return fmt.Errorf("перекрытие %d без приманки: длина перекрытия задаётся её длиной", i)
		}
		if !payloads[s.PayloadID] {
			return fmt.Errorf("перекрытие %d ссылается на несуществующую приманку %d", i, s.PayloadID)
		}
		if s.PoisonID != 0 && !poisons[s.PoisonID] {
			return fmt.Errorf("перекрытие %d ссылается на несуществующую порчу %d", i, s.PoisonID)
		}
	}
	return nil
}

// MarshalTLV — каноническая форма. Порождать её имеет право только этот код:
// исполнитель на C её читает, но никогда не пишет.
func (p Plan) MarshalTLV() ([]byte, error) {
	if err := p.checkRefs(); err != nil {
		return nil, err
	}
	// План, объявивший требование ниже настоящего, доехал бы до старого
	// исполнителя, был бы принят и исполнен НЕ ЦЕЛИКОМ — ровно то, что §2.5
	// запрещает. Поле minexec существует ради этой проверки, и делать её надо
	// здесь, до записи, а не надеяться на внимательность писавшего текст.
	if need := p.NeedExec(); p.MinExec < need {
		return nil, fmt.Errorf(
			"план требует исполнителя версии %d, а объявляет %d", need, p.MinExec)
	}

	var recs []byte
	n := 0

	recs = putRec(recs, recID, p.ID[:])
	n++

	recs = putRec(recs, recProto, []byte{p.Transport, p.Proto})
	n++

	for _, v := range p.Payloads {
		if len(v.Bytes) > 0xffff-2 {
			return nil, fmt.Errorf("приманка %d длиннее записи", v.ID)
		}
		val := make([]byte, 2+len(v.Bytes))
		binary.BigEndian.PutUint16(val[0:2], v.ID)
		copy(val[2:], v.Bytes)
		recs = putRec(recs, recPayload, val)
		n++
	}

	for _, v := range p.Poisons {
		val := make([]byte, 8)
		binary.BigEndian.PutUint16(val[0:2], v.ID)
		val[2] = v.TTL
		val[3] = v.Flags
		binary.BigEndian.PutUint32(val[4:8], uint32(v.SeqShift))
		recs = putRec(recs, recPoison, val)
		n++
	}

	for _, v := range p.Splits {
		val := make([]byte, 4)
		binary.BigEndian.PutUint16(val[0:2], uint16(v.Anchor))
		binary.BigEndian.PutUint16(val[2:4], uint16(v.Offset))
		recs = putRec(recs, recSplit, val)
		n++
	}

	for _, v := range p.Fakes {
		val := make([]byte, 10)
		binary.BigEndian.PutUint16(val[0:2], v.PayloadID)
		binary.BigEndian.PutUint16(val[2:4], v.PoisonID)
		val[4] = v.Repeats
		val[5] = uint8(v.Placement)
		binary.BigEndian.PutUint32(val[6:10], v.GapUS)
		recs = putRec(recs, recFake, val)
		n++
	}

	for _, v := range p.Seqovls {
		val := make([]byte, 4)
		binary.BigEndian.PutUint16(val[0:2], v.PayloadID)
		binary.BigEndian.PutUint16(val[2:4], v.PoisonID)
		recs = putRec(recs, recSeqovl, val)
		n++
	}

	recs = putRec(recs, recOrder, []byte{uint8(p.Order)})
	n++

	// Записывается только когда есть что записывать: план без защиты обязан
	// давать те же байты, что и до появления этой операции, иначе все
	// эталонные файлы разошлись бы разом.
	if p.Guards != 0 {
		recs = putRec(recs, recGuard, []byte{p.Guards})
		n++
	}

	if n > 0xffff {
		return nil, errors.New("слишком много записей")
	}
	out := make([]byte, headerLen, headerLen+len(recs))
	copy(out[0:4], magic[:])
	binary.BigEndian.PutUint16(out[4:6], p.Schema)
	binary.BigEndian.PutUint16(out[6:8], p.MinExec)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], uint16(n))
	return append(out, recs...), nil
}

// UnmarshalTLV нужен тестам и панели: исполнитель на C разбирает TLV сам.
// Держать разбор здесь важно ради круга «текст → TLV → текст», который ловит
// рассинхронизацию двух форм до того, как она доедет до исполнителя.
func UnmarshalTLV(b []byte) (Plan, error) {
	var p Plan
	if len(b) < headerLen || string(b[0:4]) != string(magic[:]) {
		return p, errors.New("не план d2k")
	}
	p.Schema = binary.BigEndian.Uint16(b[4:6])
	p.MinExec = binary.BigEndian.Uint16(b[6:8])
	if p.Schema > SchemaCurrent {
		return p, fmt.Errorf("схема %d новее известной (%d)", p.Schema, SchemaCurrent)
	}
	if binary.BigEndian.Uint16(b[8:10]) != 0 {
		return p, errors.New("ненулевые флаги заголовка")
	}
	want := int(binary.BigEndian.Uint16(b[10:12]))

	off, got := headerLen, 0
	for off < len(b) {
		if off+4 > len(b) {
			return p, errors.New("обрезанный заголовок записи")
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+ln > len(b) {
			return p, fmt.Errorf("запись %#04x выходит за буфер", typ)
		}
		v := b[off : off+ln]
		off += ln
		got++

		switch typ {
		case recID:
			if ln != 16 {
				return p, errors.New("id не 16 байт")
			}
			copy(p.ID[:], v)
		case recProto:
			if ln != 2 {
				return p, errors.New("proto не 2 байта")
			}
			p.Transport, p.Proto = v[0], v[1]
		case recPayload:
			if ln < 2 {
				return p, errors.New("приманка без номера")
			}
			p.Payloads = append(p.Payloads, Payload{
				ID:    binary.BigEndian.Uint16(v[0:2]),
				Bytes: append([]byte(nil), v[2:]...),
			})
		case recPoison:
			if ln != 8 {
				return p, errors.New("порча не 8 байт")
			}
			p.Poisons = append(p.Poisons, Poison{
				ID:       binary.BigEndian.Uint16(v[0:2]),
				TTL:      v[2],
				Flags:    v[3],
				SeqShift: int32(binary.BigEndian.Uint32(v[4:8])),
			})
		case recSplit:
			if ln != 4 {
				return p, errors.New("разрез не 4 байта")
			}
			p.Splits = append(p.Splits, Position{
				Anchor: Anchor(binary.BigEndian.Uint16(v[0:2])),
				Offset: int16(binary.BigEndian.Uint16(v[2:4])),
			})
		case recFake:
			if ln != 10 {
				return p, errors.New("фальшивка не 10 байт")
			}
			p.Fakes = append(p.Fakes, Fake{
				PayloadID: binary.BigEndian.Uint16(v[0:2]),
				PoisonID:  binary.BigEndian.Uint16(v[2:4]),
				Repeats:   v[4],
				Placement: Placement(v[5]),
				GapUS:     binary.BigEndian.Uint32(v[6:10]),
			})
		case recSeqovl:
			if ln != 4 {
				return p, errors.New("перекрытие не 4 байта")
			}
			p.Seqovls = append(p.Seqovls, Seqovl{
				PayloadID: binary.BigEndian.Uint16(v[0:2]),
				PoisonID:  binary.BigEndian.Uint16(v[2:4]),
			})
		case recGuard:
			if ln != 1 {
				return p, errors.New("защита не 1 байт")
			}
			if v[0] & ^GuardRSTAlien != 0 {
				return p, fmt.Errorf("неизвестные биты защиты %#02x", v[0])
			}
			p.Guards = v[0]
		case recOrder:
			if ln != 1 {
				return p, errors.New("порядок не 1 байт")
			}
			p.Order = Order(v[0])
		default:
			return p, fmt.Errorf("неизвестный тип записи %#04x", typ)
		}
	}
	if got != want {
		return p, fmt.Errorf("записей %d, заявлено %d", got, want)
	}
	return p, p.checkRefs()
}
