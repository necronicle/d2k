package classify

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// стенд — сервер, ведущий себя как коробка. Меряем правила, а не чужую линию.
//
//	"prefix" — молчит, если ПЕРВЫЙ сегмент начинается с сигнатуры;
//	"reasm"  — склеивает всё прочитанное и молчит, если сигнатура нашлась
//	           где угодно: разрез такую не берёт;
//	"clear"  — отвечает всегда;
//	"delay"  — отвечает всегда, но не раньше чем через delay[0] после
//	           получения чего угодно; sig не используется. Нужен только для
//	           замера ТАЙМИНГА (сужение ожидания по RTT между вопросами
//	           дерева, ревью Task 3, п.5) — содержимое здесь ни при чём,
//	           второй стенд под это заводить незачем.
func stand(t *testing.T, mode string, sig []byte, delay ...time.Duration) string {
	t.Helper()
	var d time.Duration
	if len(delay) > 0 {
		d = delay[0]
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// +3с сверх задержки — тот же запас, что был всегда для
				// остальных режимов (delay=0 для них, ничего не меняется).
				_ = c.SetDeadline(time.Now().Add(d + 3*time.Second))
				buf := make([]byte, 8192)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if mode == "delay" {
					time.Sleep(d)
					_, _ = c.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00})
					return
				}
				first := append([]byte(nil), buf[:n]...)
				all := first
				if mode == "reasm" {
					_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
					for {
						m, err := c.Read(buf)
						if m > 0 {
							all = append(all, buf[:m]...)
						}
						if err != nil {
							break
						}
					}
				}
				blocked := false
				switch mode {
				case "prefix":
					blocked = bytes.HasPrefix(first, sig)
				case "reasm":
					blocked = bytes.Contains(all, sig)
				}
				if !blocked {
					_, _ = c.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00})
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestОракулОтличаетОтветОтМолчания(t *testing.T) {
	tr, err := TLSTrigger("заблокировано.example")
	if err != nil {
		t.Fatal(err)
	}
	sig := tr.Payload[:8]

	clear := stand(t, "clear", sig)
	got := measure(context.Background(), clear, tr, nil, 0, 3, time.Second)
	if got.pass != 3 {
		t.Fatalf("чистая мишень: прошло %d из 3", got.pass)
	}

	blocked := stand(t, "prefix", sig)
	got = measure(context.Background(), blocked, tr, nil, 0, 3, time.Second)
	if got.pass != 0 {
		t.Fatalf("блокирующая мишень: прошло %d из 3, ожидалось 0", got.pass)
	}
}

// loopbackGap — пауза между кусками разреза ТОЛЬКО для этого стенда.
//
// На проводе к реальной цели кусок-в-один-байт и остаток всегда приходят
// разными кадрами: передача первого кадра и путь до цели сами по себе
// занимают время. На loopback этой задержки нет, и стенд читает сокет ОДНИМ
// вызовом Read — если оба Write долетели до буфера ядра раньше, чем этот
// вызов вообще начался, они склеятся в одно чтение и разрез не будет виден,
// хотя на проводе он произошёл. Замер на этой машине (40 попыток на каждое
// значение): gap=0 — разделяется 10 из 40; gap=50мкс — уже 40 из 40. Берём
// запас на два порядка сверх найденного порога для более медленной или
// загруженной машины (например CI), а не число из замера впритык.
const loopbackGap = 5 * time.Millisecond

func TestРазрезЛомаетПрефиксныйМатчер(t *testing.T) {
	tr, _ := TLSTrigger("заблокировано.example")
	sig := tr.Payload[:8]
	addr := stand(t, "prefix", sig)

	whole := measure(context.Background(), addr, tr, nil, 0, 3, time.Second)
	cut := measure(context.Background(), addr, tr, []int{1}, loopbackGap, 3, time.Second)
	if whole.pass != 0 {
		t.Fatal("целиком обязано блокироваться")
	}
	if cut.pass != 3 {
		t.Fatalf("разрез на 1 не прошёл: %d из 3", cut.pass)
	}
}

func TestПересборкуРазрезомНеВзять(t *testing.T) {
	tr, _ := TLSTrigger("заблокировано.example")
	sig := tr.Payload[:8]
	addr := stand(t, "reasm", sig)
	if got := measure(context.Background(), addr, tr, []int{1}, 0, 3, time.Second); got.pass != 0 {
		t.Fatalf("пересобирающая коробка взята разрезом: %d из 3", got.pass)
	}
}
