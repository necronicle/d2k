package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/necronicle/d2k/internal/catalog"
	"github.com/necronicle/d2k/internal/plan"
)

// Candidate — план, который предстоит проверить на фактической цели.
type Candidate struct {
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

// generate строит лестницу кандидатов ИЗ НАБЛЮДЕНИЯ.
//
// Порядок не фиксирован и не угадан: он выводится из того, что видно на линии.
// Сброс и молчание требуют разного, и предлагать защиту от сброса там, где
// сброса не было, значит тратить попытку пользователя впустую.
//
//	виден сброс          защита дешевле всего и прямо показана;
//	молчание или повтор  защита бесполезна, показана приманка;
//	и то и другое        сперва пара, она закрывает оба наблюдения.
//
// Ни один отказ отсюда не попадает на диск (§2.3): лестница строится заново
// при каждом поиске.
func generate(fp catalog.Fingerprint, decoy string) ([]Candidate, error) {
	sawRST, sawQuiet := false, false
	for _, s := range fp.Signals {
		switch s.Kind {
		case "rst", "rst_cut":
			sawRST = true
		case "silent", "repeat":
			sawQuiet = true
		}
	}

	type step struct {
		guard   bool
		fake    bool
		ttl     uint8
		repeats uint8
		gap     uint32
	}
	var steps []step
	switch {
	case sawRST && sawQuiet:
		steps = []step{
			{guard: true, fake: true, ttl: 3, repeats: 2, gap: 78000},
			{guard: true},
			{fake: true, ttl: 3, repeats: 2, gap: 78000},
		}
	case sawRST:
		steps = []step{
			{guard: true},
			{guard: true, fake: true, ttl: 3, repeats: 2, gap: 78000},
			{fake: true, ttl: 3, repeats: 2, gap: 78000},
		}
	default:
		// Молчание, повтор или наблюдение, которого мы ещё не различаем.
		// Защита от сброса тут ничего не даст: сбрасывать некому.
		steps = []step{
			{fake: true, ttl: 3, repeats: 2, gap: 78000},
			{fake: true, ttl: 6, repeats: 2, gap: 78000},
			{fake: true, ttl: 3, repeats: 4, gap: 0},
		}
	}

	out := make([]Candidate, 0, len(steps))
	for _, s := range steps {
		var (
			p   catalog.Plan
			err error
		)
		if s.fake {
			p, err = fakePlan(decoy, s.ttl, s.repeats, s.gap, s.guard)
		} else {
			p, err = guardPlan()
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Candidate{Source: "поиск", Plan: p})
	}
	return out, nil
}
