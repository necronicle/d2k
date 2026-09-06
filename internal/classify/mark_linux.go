//go:build linux

package classify

import "syscall"

// markControl строит функцию net.Dialer.Control, которая метит исходящий
// сокет зонда значением SO_MARK.
//
// §5.5: «Зонды помечаются и исключаются из повторного обучения и
// собственного преобразования». Цепочка firewall (files/S99d2k) отпускает
// помеченный исходящий пакет мимо очереди нетронутым:
//
//	iptables -t mangle -A "$CHAIN_OUT" -m mark --mark "$MARK" -j RETURN
//
// — то есть датапат просто не видит зонд как трафик, который нужно править
// или на котором нужно учиться. Без этой метки зонд классификации, идущий на
// цель с уже поставленным (пусть даже ещё не проверенным) планом, рискует
// быть преобразован ЭТИМ планом раньше, чем достигнет провода, — измерение
// тогда наблюдает не голое поведение коробки, а поведение коробки ПЛЮС наше
// же преобразование.
//
// Ошибка постановки метки НЕ прерывает Dial: провал разметки — это «исключение
// зонда не гарантировано», отдельное от сетевой ошибки наблюдение, которое
// снижает достоверность вердикта (см. once/measure, Result.Marked, Run), а
// не подменяет собой решение коробки. Поэтому Control ниже всегда возвращает
// nil — сам факт успеха/провала уходит через ok, а не через возврат ошибки.
func markControl(mark uint32, ok *bool) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		ctlErr := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		})
		*ok = ctlErr == nil && sockErr == nil
		return nil
	}
}
