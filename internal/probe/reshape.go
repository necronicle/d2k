// Package probe — активная проверка цели собственным соединением.
//
// Зачем активно. Пассивный поиск ждёт, пока клиент повторит попытку, и на
// устройстве, которое не повторяет — телевизор, приставка, часть IoT, — не
// срабатывает вовсе. Ждать надо ВРЕМЯ, а не чужие повторы: иначе получается
// тот же ротатор, от которого продукт уходит.
package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Расширения, которые в копию не переносятся.
const (
	extSessionTicket = 35 // TLS 1.2: билет возобновления
	extPreSharedKey  = 41 // TLS 1.3: то же по смыслу
	extEarlyData     = 42 // ранние данные бывают только с билетом
)

// Reshape делает из наблюдённого приветствия то, которое можно послать самим.
//
// Что сохраняется: версия, наборы шифров, способы сжатия, состав и ПОРЯДОК
// расширений, ALPN, имя цели. Всё это коробка и разглядывает, и подменять его
// нельзя — иначе зонд проверяет не тот трафик, что у пользователя (§3.1,
// §5.5).
//
// Что заменяется: случайное поле и идентификатор сессии. Они на форму не
// влияют, зато делают копию буквальным повтором чужого сообщения.
//
// Что ВЫБРАСЫВАЕТСЯ: расширения с билетами возобновления. §2.6 запрещает
// копировать и повторять пользовательские запросы, а билет — это учётные
// данные сессии, и посылать их от себя нельзя. Длина при этом меняется, то
// есть форма чуть-чуть отличается от исходной, и вызывающий об этом узнаёт:
// функция возвращает список выброшенного.
func Reshape(hello []byte, fill byte) (out []byte, dropped []uint16, err error) {
	// Запись TLS.
	if len(hello) < 5 || hello[0] != 0x16 {
		return nil, nil, errors.New("это не запись рукопожатия")
	}
	recLen := int(binary.BigEndian.Uint16(hello[3:5]))
	if 5+recLen > len(hello) {
		return nil, nil, fmt.Errorf("запись объявляет %d байт, а есть %d", recLen, len(hello)-5)
	}
	hs := hello[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, nil, errors.New("это не ClientHello")
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+hsLen > len(hs) {
		return nil, nil, fmt.Errorf("рукопожатие объявляет %d байт, а есть %d", hsLen, len(hs)-4)
	}
	body := hs[4 : 4+hsLen]

	p := 0
	need := func(n int) error {
		if p+n > len(body) {
			return errors.New("приветствие обрывается")
		}
		return nil
	}
	if err := need(2 + 32 + 1); err != nil {
		return nil, nil, err
	}
	var nb []byte
	nb = append(nb, body[p:p+2]...) // версия
	p += 2
	// Случайное поле — своё, детерминированное: один и тот же зонд обязан
	// давать одни и те же байты, иначе измерения не с чем сравнивать (§5.4).
	for i := 0; i < 32; i++ {
		nb = append(nb, fill+byte(i))
	}
	p += 32

	sidLen := int(body[p])
	p++
	if err := need(sidLen); err != nil {
		return nil, nil, err
	}
	nb = append(nb, byte(sidLen))
	for i := 0; i < sidLen; i++ {
		nb = append(nb, fill+byte(i)+0x40)
	}
	p += sidLen

	if err := need(2); err != nil {
		return nil, nil, err
	}
	csLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	if err := need(2 + csLen); err != nil {
		return nil, nil, err
	}
	nb = append(nb, body[p:p+2+csLen]...) // наборы шифров как есть
	p += 2 + csLen

	if err := need(1); err != nil {
		return nil, nil, err
	}
	compLen := int(body[p])
	if err := need(1 + compLen); err != nil {
		return nil, nil, err
	}
	nb = append(nb, body[p:p+1+compLen]...)
	p += 1 + compLen

	// Расширения: порядок сохраняется, часть выбрасывается.
	var exts []byte
	if p < len(body) {
		if err := need(2); err != nil {
			return nil, nil, err
		}
		extTotal := int(binary.BigEndian.Uint16(body[p : p+2]))
		p += 2
		if p+extTotal > len(body) {
			return nil, nil, errors.New("блок расширений выходит за приветствие")
		}
		end := p + extTotal
		for p+4 <= end {
			typ := binary.BigEndian.Uint16(body[p : p+2])
			ln := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
			if p+4+ln > end {
				return nil, nil, fmt.Errorf("расширение %d выходит за блок", typ)
			}
			switch typ {
			case extSessionTicket, extPreSharedKey, extEarlyData:
				dropped = append(dropped, typ)
			default:
				exts = append(exts, body[p:p+4+ln]...)
			}
			p += 4 + ln
		}
	}
	if len(exts) > 0 || p > 0 {
		var el [2]byte
		binary.BigEndian.PutUint16(el[:], uint16(len(exts)))
		nb = append(nb, el[:]...)
		nb = append(nb, exts...)
	}

	// Обратная сборка: рукопожатие и запись.
	outHS := make([]byte, 4, 4+len(nb))
	outHS[0] = 0x01
	outHS[1] = byte(len(nb) >> 16)
	outHS[2] = byte(len(nb) >> 8)
	outHS[3] = byte(len(nb))
	outHS = append(outHS, nb...)

	if len(outHS) > 0xffff {
		return nil, nil, errors.New("копия приветствия не помещается в запись")
	}
	out = make([]byte, 5, 5+len(outHS))
	out[0] = 0x16
	out[1], out[2] = hello[1], hello[2] // версию записи сохраняем
	binary.BigEndian.PutUint16(out[3:5], uint16(len(outHS)))
	out = append(out, outHS...)
	return out, dropped, nil
}
