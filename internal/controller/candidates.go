package controller

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/plan"
)

//go:embed lists/decoy_names.txt
var decoyList string

// decoyNames — имена, которыми задаётся вопрос «какое проходит на этой линии».
//
// Не база заблокированных доменов, которую §2.2 запрещает, а алфавит
// инструмента. Порядок сохранён от источника: перестановка под собственный
// замер была бы подгонкой под одну линию.
func decoyNames() []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(decoyList))
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Candidate — план, который предстоит проверить на фактической цели.
type Candidate struct {
	// Decoy — какое имя подставлено в приманку. Пустое — приманки нет либо
	// имя не является осью этого кандидата.
	Decoy string
	// Откуда взялся: имя коробки либо «поиск». Нужно счётчику §10 «доля
	// встреч с известными моделями, завершённых без нового поиска».
	Source string
	BoxID  string
	Plan   catalog.Plan
}

// DecoySNI — имя в приманке. Не выдумано: плечо донора измерено именно с ним
// (замер 2026-08-29, hetzner.com — 15 994 байта против 163 654 с приманкой).
// Вынесено в переменную, потому что имя, работающее на одной линии, не обязано
// работать на другой, и подбирать его — часть поиска, а не константа кода.
const DecoySNI = "disk.rzd.ru"

// planID делает имя плана из его текста. Одинаковый план обязан получать
// одинаковое имя: иначе один и тот же приём попал бы в коробку дважды.
func planID(text string) string {
	h := sha256.Sum256([]byte(text))
	return "plan-" + hex.EncodeToString(h[:4])
}

// guardPlan — только защита от подделанного сброса, без единой посылки.
//
// Самый дешёвый кандидат: на провод не уходит ничего, а если блокировка
// состоит только в подделанном сбросе, этого достаточно.
func guardPlan() (catalog.Plan, error) {
	p := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 2,
		Transport: 6, Proto: 1,
		Guards: plan.GuardRSTAlien,
	}
	return wrap(p, "tls")
}

// fakePlan — приманка перед нагрузкой: целое правдоподобное приветствие с
// чужим именем, с малым TTL и испорченной суммой.
//
// TTL нужен, чтобы приманка умерла по дороге и не дошла до сервера; неверная
// сумма — чтобы сервер выбросил её, даже если дойдёт. Оба приёма из плеча
// донора и оба измерены.
func fakePlan(decoy string, ttl uint8, repeats uint8, gapUS uint32, guard bool) (catalog.Plan, error) {
	hello, err := plan.Hello(decoy, 0)
	if err != nil {
		return catalog.Plan{}, err
	}
	p := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 6, Proto: 1,
		Payloads: []plan.Payload{{ID: 1, Bytes: hello}},
		Poisons:  []plan.Poison{{ID: 1, TTL: ttl, Flags: plan.PoisonBadSum}},
		Fakes: []plan.Fake{{
			PayloadID: 1, PoisonID: 1,
			Repeats: repeats, GapUS: gapUS, Placement: plan.PlaceBefore,
		}},
	}
	if guard {
		p.Guards = plan.GuardRSTAlien
		p.MinExec = 2
	}
	return wrap(p, "tls")
}

func wrap(p plan.Plan, proto string) (catalog.Plan, error) {
	// Проверяем сборку прямо здесь: кандидат, который не переводится в
	// каноническую форму, не должен доехать до датапата и быть отвергнутым
	// там — там уже поздно, там идёт чужое соединение.
	if _, err := p.MarshalTLV(); err != nil {
		return catalog.Plan{}, fmt.Errorf("кандидат не собирается: %w", err)
	}
	text := p.Text()
	return catalog.Plan{ID: planID(text), Proto: proto, Text: text}, nil
}

// splitPlan — план «просто разрез», без приманки и без порчи.
//
// Позиция — ЧИСЛОМ, а не якорем (в отличие от остальных планов пакета —
// сравни с комментарием у plan.Anchor: «якорь переносится, число — нет»).
// Здесь это оправдано: число не позаимствовано у чужого хоста, оно измерено
// classify.Run НА ЭТОЙ цели, тем же триггером, что и настоящее приветствие
// (см. verdictCandidates в controller.go). AnchorPayloadStart даёт базу 0,
// и датапат режет по «база + смещение» (datapath/plan_apply.c,
// anchor_offset/split_points) — то есть ровно там же, где резал сам замер
// (internal/classify/measure.go, spans()).
func splitPlan(pos int) (catalog.Plan, error) {
	p := plan.Plan{
		Schema: plan.SchemaCurrent, MinExec: 1,
		Transport: 6, Proto: 1,
		Splits: []plan.Position{{Anchor: plan.AnchorPayloadStart, Offset: int16(pos)}},
	}
	return wrap(p, "tls")
}

// decoyFor — какое имя приманки использовать: измеренное (Traits.PassingName)
// точнее заготовки (fallback), потому что подтверждено пробой объёма НА ЭТОЙ
// линии, а не взято алфавитом инструмента. Общее место для buildQueue и
// askClassify — раньше это правило дублировалось бы в обоих порознь.
func decoyFor(t *Task, fallback string) string {
	if t.Traits.PassingName != "" {
		return t.Traits.PassingName
	}
	return fallback
}
