"use strict";
// Раздел «Обновления»: состояние из d2k-update.sh (state/update.json) и
// команды службы /api/control/update-*; без роутера.
const assert = require('node:assert/strict');
const { App } = require('../internal/web/assets/panel.js');
const ids = ['updates-body','nav-updates','update-current','update-state','update-reason','update-checked','update-release','update-version','update-notes','update-notes-text','update-progress','update-progress-text','update-check','update-install','update-warning','update-auto','update-schedule','update-result','update-action','update-lamp'];
function fixture(reply) {
  const nodes = Object.fromEntries(ids.map(id => [id, {textContent:'',hidden:false,disabled:false,checked:false,style:{},attrs:{},listeners:{},parentElement:{setAttribute(){}},setAttribute(k,v){this.attrs[k]=v;},getAttribute(k){return this.attrs[k];},addEventListener(k,v){this.listeners[k]=v;}}]));
  const requests = [];
  const document = {hidden:false,getElementById:id=>nodes[id]};
  const window = {setTimeout,clearTimeout,fetch:async (url,opts={})=>{requests.push({url,method:opts.method});return reply(url,opts);}};
  const app = new App(document, window);
  app.initUpdates();
  return {app,nodes,requests,window};
}
const now = Math.floor(Date.now() / 1000);
function state(over={}) {
  return {busy:'',current:'r1',arch:'arm64',auto:true,checked_utc:now-60,check_ok:true,check_error:'',
    latest:{release_id:'r2',version:'06.10.2026',notes:'<img src=x onerror=alert(1)>',assets:{arm64:{sha256:'a'.repeat(64)}}},
    last_utc:0,last_ok:false,last_release:'',last_message:'',bad_release:'',...over};
}
const json = (data, status=200) => ({ok:status<300,status,json:async()=>data});

(async () => {
  // В простое — один запрос в минуту; действия и восстановление остаются быстрыми.
  {
    const realNow = Date.now;
    let clock = 100000, busy = '', down = false;
    Date.now = () => clock;
    try {
      const {app,requests} = fixture(() => {
        if (down) throw Error('panel unavailable');
        return json(state({busy}));
      });
      await app.pollUpdates();
      for (let i = 0; i < 29; i++) { clock += 2000; await app.pollUpdates(true); }
      assert.equal(requests.length, 1, 'idle ticks must not fetch unchanged update state');
      clock += 2000; await app.pollUpdates(true);
      assert.equal(requests.length, 2, 'idle state refreshes after sixty seconds');
      await app.pollUpdates();
      assert.equal(requests.length, 3, 'explicit refresh bypasses the idle interval');
      busy = 'checking'; await app.pollUpdates();
      clock += 2000; await app.pollUpdates(true);
      assert.equal(requests.length, 5, 'background check retains fast polling');
      busy = 'installing'; await app.pollUpdates();
      clock += 2000; await app.pollUpdates(true);
      assert.equal(requests.length, 7, 'installation retains fast polling');
      busy = ''; await app.pollUpdates();
      app.updatePending = {action:'check',at:clock};
      clock += 2000; await app.pollUpdates(true);
      assert.equal(requests.length, 9, 'pending command retains fast polling before busy is visible');
      app.updatePending = null;
      down = true; await app.pollUpdates();
      down = false; clock += 2000; await app.pollUpdates(true);
      assert.equal(requests.length, 11, 'failed fetch recovers on the next fast tick');
      clock += 2000; await app.pollUpdates(true);
      assert.equal(requests.length, 11, 'successful recovery returns to idle polling');
      app.doc.hidden = true; clock += 60000; await app.pollUpdates(true);
      assert.equal(requests.length, 11, 'hidden tab does not poll');
      app.doc.hidden = false; await app.pollUpdates();
      assert.equal(requests.length, 12, 'visible tab can refresh immediately');
      app.updateInflight = true; await app.pollUpdates();
      assert.equal(requests.length, 12, 'inflight request cannot be duplicated');
    } finally { Date.now = realNow; }
  }
  // Отсутствующая утилита и ещё не проверявшееся состояние тоже не требуют частого опроса.
  for (const reply of [{absent:true}, {never:true}]) {
    const {app,requests} = fixture(() => json(reply));
    await app.pollUpdates();
    await app.pollUpdates(true);
    assert.equal(requests.length, 1, 'absent/never state remains idle');
    await app.pollUpdates();
    assert.equal(requests.length, 2, 'explicit refresh also works without update history');
  }
  // Новый выпуск: кнопка, заметки как текст, тумблер по состоянию.
  {
    const {app,nodes} = fixture(() => json(state()));
    await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Доступна версия 06.10.2026');
    assert.equal(nodes['update-install'].hidden, false);
    assert.equal(nodes['update-install'].disabled, false);
    assert.equal(nodes['update-notes-text'].textContent, '<img src=x onerror=alert(1)>');
    assert.equal(nodes['update-current'].textContent, 'r1', 'подпись «Версия» уже в разметке');
    assert.equal(nodes['update-auto'].checked, true);
    assert.equal(nodes['nav-updates'].textContent, 'новая');
  }
  // Установлена последняя: зелёная лампа, кнопки установки нет.
  {
    const {app,nodes} = fixture(() => json(state({current:'r2'})));
    await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Установлена последняя версия');
    assert.equal(nodes['update-install'].hidden, true);
    assert.equal(nodes['update-lamp'].attrs['data-tone'], 'ok');
  }
  // Ошибки проверки и установки объясняются словами утилиты.
  {
    const {app,nodes} = fixture(() => json(state({check_ok:false,check_error:'подпись выпуска не сошлась'})));
    await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Не удалось проверить обновления');
    assert.equal(nodes['update-reason'].textContent, 'подпись выпуска не сошлась');
  }
  {
    const {app,nodes} = fixture(() => json(state({last_utc:now,last_ok:false,last_release:'r2',bad_release:'r2',
      last_message:'выпуск r2 не прошёл проверку; возвращена прежняя версия'})));
    await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Не удалось установить обновление');
    assert.match(nodes['update-reason'].textContent, /возвращена прежняя версия/);
    assert.equal(nodes['update-install'].textContent, 'Повторить установку вручную');
    assert.match(nodes['update-result'].textContent, /^Последний результат: выпуск r2/);
  }
  // Нет утилиты — «не подключено», действия выключены; не проверялось — сказано.
  {
    const {app,nodes} = fixture(() => json({absent:true}));
    await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Автообновление не подключено');
    assert.equal(nodes['update-check'].disabled, true);
    assert.equal(nodes['update-auto'].disabled, true);
    assert.equal(nodes['updates-body'].attrs['data-mode'], 'absent');
  }
  {
    const {app,nodes} = fixture(() => json({never:true}));
    await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Обновления ещё не проверялись');
    assert.equal(nodes['update-auto'].disabled, false, 'тумблер доступен до первой проверки');
  }
  // Проверка: POST команды службы, «проверяем…» до свежего checked_utc.
  {
    let checked = now - 3600, busy = '';
    const {app,nodes,requests} = fixture((url,opts) => opts.method === 'POST' ? json({ok:true},202) :
      json(state({checked_utc:checked,busy})));
    await app.pollUpdates();
    busy = 'checking';
    await nodes['update-check'].listeners.click();
    assert.deepEqual(requests.filter(r=>r.method==='POST').map(r=>r.url), ['/api/control/update-check']);
    assert.equal(nodes['update-state'].textContent, 'Проверяем обновления…');
    assert.equal(nodes['update-check'].disabled, true);
    busy = ''; await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Проверяем обновления…', 'старый результат не завершает проверку');
    checked = now + 1; await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Доступна версия 06.10.2026');
  }
  // Установка: потерянный ответ (панель перезапускается) — не ошибка, ждём итога.
  {
    let last = 0, current = 'r1', down = false;
    const {app,nodes,requests} = fixture((url,opts) => {
      if (opts.method === 'POST') throw Error('panel restarting');
      if (down) throw Error('panel restarting');
      return json(state({current,last_utc:last,last_ok:last>0,last_release:last?'r2':'',last_message:last?'установлен выпуск r2':''}));
    });
    await app.pollUpdates();
    await nodes['update-install'].listeners.click();
    assert.match(nodes['update-state'].textContent, /^Устанавливаем обновление/);
    assert.equal(nodes['update-action'].hidden, true, 'потерянный ответ на установку не показан ошибкой');
    down = true; await app.pollUpdates();
    assert.match(nodes['update-state'].textContent, /^Устанавливаем обновление/);
    down = false; last = now + 1; current = 'r2'; await app.pollUpdates();
    assert.equal(nodes['update-state'].textContent, 'Установлена последняя версия');
    assert.equal(requests.filter(r=>r.method==='POST').length, 1, 'установка не отправляется повторно');
  }
  // Отказ службы объясняется, тумблер шлёт on/off.
  {
    const {app,nodes,requests} = fixture((url,opts) => opts.method === 'POST' ? json({ok:false},409) : json(state()));
    await app.pollUpdates();
    nodes['update-auto'].checked = false;
    await nodes['update-auto'].listeners.change();
    assert.equal(requests.filter(r=>r.method==='POST')[0].url, '/api/control/update-auto-off');
    assert.match(nodes['update-action'].textContent, /другую команду/);
  }
  console.log('panel updates: state file, commands, install restart, toggle: PASS');
})().catch(error => { console.error(error); process.exit(1); });
