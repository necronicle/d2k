package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/necronicle/d2k/internal/volume"
)

// cmdVolume — проба на блокировку по объёму соединения.
//
// Отдельная команда, а не режим контроллера, потому что отвечает она на вопрос
// о ЛИНИИ, а не о хосте, и ответ живёт дольше одного поиска. Направление
// накачки открыто наружу намеренно: пока не измерено, за какими байтами следит
// коробка, пассивный наблюдатель не может знать, что ему считать.
func cmdVolume(args []string, out, errOut *os.File) int {
	fs := flag.NewFlagSet("volume", flag.ContinueOnError)
	fs.SetOutput(errOut)
	target := fs.String("target", "", "мишень host:port (обязательно)")
	sni := fs.String("sni", "", "имя в ClientHello; пусто — идём по адресу")
	pump := fs.String("pump", "out", "чьим объёмом качаем: out (наш) | in (мишени) | both")
	repeat := fs.Int("repeat", 1, "сколько раз повторить пробу")
	scan := fs.String("scan", "", "подобрать имя: файл со списком кандидатов, по одному в строке")
	limit := fs.Int("limit", 0, "потолок проверяемых имён при подборе; 0 — без потолка")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" {
		fmt.Fprintln(errOut, "нужен -target host:port")
		return 2
	}

	t, err := parseTarget(*target)
	if err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 2
	}

	var pumps []volume.Pump
	switch *pump {
	case "out":
		pumps = []volume.Pump{volume.PumpOut}
	case "in":
		pumps = []volume.Pump{volume.PumpIn}
	case "both":
		pumps = []volume.Pump{volume.PumpOut, volume.PumpIn}
	default:
		fmt.Fprintf(errOut, "неизвестное направление %q: out, in или both\n", *pump)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if *scan != "" {
		return runScan(ctx, t, *sni, *scan, *limit, out, errOut)
	}

	for i := 0; i < *repeat; i++ {
		for _, p := range pumps {
			fmt.Fprintln(out, volume.Probe(ctx, t, *sni, p))
		}
	}
	return 0
}

// runScan подбирает имя и печатает, чем кончилось. Отбракованные имена
// печатаются отдельно: имя, убившее рукопожатие, — это находка, а не шум.
func runScan(ctx context.Context, t volume.Target, sni, list string, limit int, out, errOut *os.File) int {
	raw, err := os.ReadFile(list)
	if err != nil {
		fmt.Fprintf(errOut, "список имён не прочитан: %v\n", err)
		return 1
	}
	var names []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	t.SNI = sni

	r := volume.Scan(ctx, t, names, volume.ScanOptions{MaxNames: limit, Confirm: true})
	fmt.Fprintf(out, "%s: %s\n", t.IP, r.Verdict)
	if r.CutAtKB > 0 {
		fmt.Fprintf(out, "  обрыв без имени на %d КБ\n", r.CutAtKB)
	}
	if r.Name != "" {
		fmt.Fprintf(out, "  имя %s проводит объём (проверено %d из %d)\n", r.Name, r.Tried, len(names))
	}
	if len(r.Killed) > 0 {
		fmt.Fprintf(out, "  убили рукопожатие: %s\n", strings.Join(r.Killed, ", "))
	}
	if r.Verdict == volume.ScanFound {
		return 0
	}
	return 1
}

func parseTarget(s string) (volume.Target, error) {
	host, portText, ok := strings.Cut(s, ":")
	if !ok {
		return volume.Target{}, fmt.Errorf("мишень %q без порта", s)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return volume.Target{}, fmt.Errorf("порт %q не число", portText)
	}
	return volume.Target{IP: host, Port: port, Plain: port == 80}, nil
}
