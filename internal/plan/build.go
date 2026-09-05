package plan

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Hello строит правдоподобное приветствие TLS с заданным именем.
//
// Именно ЦЕЛОЕ приветствие, а не огрызок: замер донора зафиксировал, что
// коробка отбрасывает битую запись целиком и своего имени в ней не ищет.
// Приманка из обрезанной записи не работает вовсе, поэтому здесь собирается
// сообщение, которое пройдёт разбор любым нормальным разборщиком.
//
// Случайность представлена явно (§5.4): поле random заполняется НЕ случайно, а
// заданным байтом. Для воспроизведения решения по записанным входным данным
// достаточно текста плана, и приманка в нём обязана быть той же самой от
// прогона к прогону. Настоящая случайность здесь дала бы разные байты на
// проводе при одном и том же плане, и сравнивать измерения стало бы не с чем.
func Hello(sni string, fill byte) ([]byte, error) {
	if sni == "" {
		return nil, errors.New("приманке нужно имя")
	}
	if len(sni) > 255 {
		return nil, fmt.Errorf("имя приманки длиной %d байт не поместится", len(sni))
	}

	var body []byte
	body = append(body, 0x03, 0x03) // объявленная версия: TLS 1.2
	for i := 0; i < 32; i++ {
		body = append(body, fill+byte(i))
	}
	body = append(body, 0) // без идентификатора сессии

	// Наборы шифров: два современных и два классических — набор, который не
	// вызывает подозрений и не выдаёт сборку.
	suites := []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f}
	body = append(body, byte(len(suites)>>8), byte(len(suites)))
	body = append(body, suites...)
	body = append(body, 0x01, 0x00) // способы сжатия: только «никак»

	// Расширение server_name.
	var sn []byte
	sn = append(sn, 0x00)                              // тип: имя хоста
	sn = append(sn, byte(len(sni)>>8), byte(len(sni))) // длина имени
	sn = append(sn, sni...)
	var snList []byte
	snList = append(snList, byte(len(sn)>>8), byte(len(sn)))
	snList = append(snList, sn...)

	var ext []byte
	ext = append(ext, 0x00, 0x00) // server_name
	ext = append(ext, byte(len(snList)>>8), byte(len(snList)))
	ext = append(ext, snList...)
	// supported_versions: без него приветствие выглядит устаревшим, а нам
	// нужна приманка, неотличимая от обычного клиента.
	ext = append(ext, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)

	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	// Рукопожатие: ClientHello.
	hs := make([]byte, 4, 4+len(body))
	hs[0] = 0x01
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	hs = append(hs, body...)

	// Запись TLS.
	rec := make([]byte, 5, 5+len(hs))
	rec[0] = 0x16
	rec[1], rec[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	rec = append(rec, hs...)
	return rec, nil
}
