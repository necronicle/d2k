"use strict";
// Смысловые правила панели без браузера: что можно утверждать по снимку.
const assert = require('node:assert/strict');
const ui = require('../internal/web/assets/panel.js');

const snap = (over) => ({ engine_running: true, controller_running: true, live_fresh: true, mode: 'apply', ...over });

// Нет связи с датапатом — это отсутствие измерения, а не «ноль поисков».
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: false, link_note: 'движок не отдаёт состояние', searches: [{ target: 'x' }] } });
  assert.equal(m.linked, false);
  assert.deepEqual(m.searches, [], 'unlinked snapshot must not show searches as measured');
  assert.match(m.headline.join(''), /Нет связи/);
  assert.match(m.lede, /не «ноль поисков»/);
  assert.match(m.lede, /движок не отдаёт состояние/);
}
// Остановленный движок не выдаётся за работающий, даже если в снимке остались поиски.
{
  const m = ui.model({ snapshot: snap({ engine_running: false }), knowledge: { linked: false, searches: [] } });
  assert.match(m.headline.join(''), /остановлен/);
  assert.equal(m.lamp, 'bad');
}
// MODE=off объясняется словами конфигурации.
{
  const m = ui.model({ snapshot: snap({ engine_running: false, mode: 'off' }), knowledge: {} });
  assert.match(m.lede, /MODE=off/);
}
// Работающий трафик без блокировок — «поисков нет», без утверждения, что интернет работает.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [] } });
  assert.equal(m.hunting, 0);
  assert.doesNotMatch(m.lede + m.headline.join(''), /интернет работает|всё работает|сайты доступны/i);
}
// Подтверждённая задача, которая лишь наблюдает трафик, не считается идущим поиском.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [
    { target: 'a', phase: 'распознаём поведение' },
    { target: 'b', phase: 'подтверждено, смотрим живой трафик' },
  ] } });
  assert.equal(m.hunting, 1);
  assert.match(m.headline.join(''), /1 поиск$/);
}
// Устаревший снимок отмечается, а не выдаётся за текущий.
{
  const m = ui.model({ snapshot: snap({ live_fresh: false }), knowledge: { linked: true } });
  assert.equal(m.lamp, 'warn');
  assert.match(m.state, /снимка/i);
  assert.match(m.headline.join(''), /снимка/i);
  assert.equal(m.linked, false);
  assert.equal(m.linkUnknown, true);
  const stopped = ui.model({ snapshot: snap({ controller_running: false, live_fresh: false }), knowledge: { linked: false } });
  assert.match(stopped.headline.join(''), /контроллер/i);
  assert.equal(stopped.linkUnknown, false);
}
// Мусор вместо массивов не роняет модель.
{
  const m = ui.model({ snapshot: {}, knowledge: { linked: true, groups: { invalid: true }, boxes: 'x', searches: null } });
  assert.deepEqual(m.groups, []);
  assert.deepEqual(m.boxes, []);
  assert.deepEqual(ui.model(null).searches, []);
}

// uptime_seconds — время работы процесса панели, не движка: рядом с состоянием движка его нет.
{
  const m = ui.model({ snapshot: snap({ uptime_seconds: 10 }), knowledge: { linked: true } });
  assert.doesNotMatch(m.stateDetail, /10 с/, 'panel uptime must not be shown as engine uptime');
  assert.match(m.stateDetail, /режим: применение/);
  assert.equal(m.panelUptime, 10);
}
// Поиски в очереди замера отделены от идущих замеров.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [
    { target: 'a', phase: 'распознаём поведение' },
    { target: 'b', phase: 'ожидает безопасного слота замера' },
    { target: 'c', phase: 'ожидает безопасного слота замера' },
  ] } });
  assert.equal(m.hunting, 3);
  assert.deepEqual(m.running.map(s => s.target), ['a']);
  assert.deepEqual(m.queued.map(s => s.target), ['b', 'c']);
  assert.match(m.lede, /2 ждут/);
}

// Шкала фаз: этапы оригинала распознаются целиком, голос — своей шкалой, неизвестное — без шкалы.
assert.equal(ui.trackFor('распознаём поведение').at, 2);
assert.equal(ui.trackFor('проверяем готовое узнанной коробки').at, 5);
assert.equal(ui.trackFor('проверяем выведенный план').at, 5);
assert.equal(ui.trackFor('подтверждено, смотрим живой трафик').at, 6);
assert.equal(ui.trackFor('приём голоса стоит, ждём разговора').voice, true);
assert.equal(ui.trackFor('новый этап из будущей сборки'), null);

// Протоколы и семейства адресов не сливаются.
assert.equal(ui.shapeLabel(1, 6), 'TLS 1.3');
assert.equal(ui.shapeLabel(2, 6), 'TLS 1.2');
assert.equal(ui.shapeLabel(3, 17), 'QUIC');
assert.equal(ui.shapeLabel(6, 6), 'TLS 1.3 + ECH');
assert.equal(ui.shapeLabel(0, 17), 'UDP', 'unknown shape must not be guessed as QUIC');
assert.equal(ui.shapeLabel(undefined, undefined), 'протокол не указан');

// Покрытие семейством: только активное семейство, тот же протокол/IP/путь, не исключение, только имена.
{
  const g = { suffix: 'example.com', active: true, transport: 6, family: 4, shape: 1, probe_path: '/', ech_origin: '',
    exceptions: [{ name: 'skip.example.com' }] };
  const b = (over) => ({ target: 'a.example.com', kind: 'name', transport: 6, family: 4, shape: 1, ...over });
  assert.equal(ui.coveredBy(b(), [g]), g);
  assert.equal(ui.coveredBy(b({ target: 'example.com.' }), [g]), g, 'trailing dot and apex match');
  assert.equal(ui.coveredBy(b({ target: 'notexample.com' }), [g]), null, 'suffix must match on a label boundary');
  assert.equal(ui.coveredBy(b({ target: 'skip.example.com' }), [g]), null, 'exceptions stay visible');
  assert.equal(ui.coveredBy(b({ family: 6 }), [g]), null, 'IPv6 is a different context');
  assert.equal(ui.coveredBy(b({ shape: 2 }), [g]), null, 'TLS 1.2 is a different context');
  assert.equal(ui.coveredBy(b({ transport: 17, shape: 3 }), [g]), null, 'QUIC is a different context');
  assert.equal(ui.coveredBy(b({ kind: 'addr', target: '1.2.3.4' }), [g]), null, 'addresses are never folded into names');
  assert.equal(ui.coveredBy(b(), [{ ...g, active: false }]), null, 'inactive family must not hide hosts');
  assert.equal(ui.coveredBy(b({ probe_path: '/x' }), [g]), null);
}

// Выжимка плана не показывает полезную нагрузку.
{
  const gist = ui.planGist('d2k-plan 1 1\nid 00\nproto tcp tls\npayload 1 0f0f0f0f\nsplit payload_start +1\norder reverse\n');
  assert.equal(gist, 'split payload_start +1 · order reverse');
}

assert.equal(ui.plural(1, 'поиск', 'поиска', 'поисков'), 'поиск');
assert.equal(ui.plural(3, 'поиск', 'поиска', 'поисков'), 'поиска');
assert.equal(ui.plural(11, 'поиск', 'поиска', 'поисков'), 'поисков');
assert.equal(ui.plural(22, 'поиск', 'поиска', 'поисков'), 'поиска');
assert.equal(ui.duration(3725000), '1 ч 2 мин');

// Предел замеров — живой, от 1 до десятков: клетки до 16, дальше шкала; подпись честно говорит, откуда предел.
{
  const weak = ui.slotsView({ active: 1, limit: 1, queued: 3, free_pct: 12, cores: 1 });
  assert.equal(weak.kind, 'cells'); assert.equal(weak.limit, 1); assert.equal(weak.queued, 3);
  assert.equal(weak.short, 'предел по нагрузке роутера');
  const strong = ui.slotsView({ active: 23, limit: 40, queued: 0, free_pct: 80, cores: 4 });
  assert.equal(strong.kind, 'bar', 'dozens of slots are shown as a share, not as 16 capped cells');
  assert.equal(strong.limit, 40);
  const blind = ui.slotsView({ active: 0, limit: 2, queued: 0, free_pct: null, cores: null });
  assert.equal(blind.short, 'предел по умолчанию');
  assert.match(blind.note, /Данных о нагрузке/);
}
// Трафик туннеля: не метроном, а запросы с пачками ответов разного размера; петля бесшовна.
{
  const plan = ui.tunnelTraffic(0xD2C7, 12);
  assert.deepEqual(ui.tunnelTraffic(0xD2C7, 12), plan, 'the schedule is deterministic');
  assert.equal(plan.dropped, 0, 'every packet gets a pool element');
  assert.ok(plan.out.length >= 8 && plan.back.length >= 8, 'both lanes carry traffic');
  for (const lane of [plan.out, plan.back]) {
    const gaps = lane.slice(1).map((p, i) => +(p.t - lane[i].t).toFixed(2));
    assert.ok(new Set(gaps).size > lane.length / 2, 'launch spacing varies');
    assert.ok(Math.max(...lane.map(p => p.w)) - Math.min(...lane.map(p => p.w)) > 5, 'packet sizes vary');
    for (const a of lane) for (const b of lane) {
      if (a === b || a.slot !== b.slot) continue;
      const ahead = (b.t - a.t + plan.period) % plan.period;
      assert.ok(ahead >= a.d, 'a pool element is never reused before its packet lands, across the loop seam too');
    }
  }
  const backMean = plan.back.reduce((s, p) => s + p.w, 0) / plan.back.length;
  const outMean = plan.out.reduce((s, p) => s + p.w, 0) / plan.out.length;
  assert.ok(backMean > outMean, 'responses are larger than requests');
}
console.log('panel model: all checks passed');
