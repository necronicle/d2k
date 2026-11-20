/* Optional local history. No upload or automatic enable on page load. */
(function (root) {
  "use strict";
  function summary(report) {
    var samples = report.samples || [], events = report.events || [];
    var last = samples[samples.length - 1];
    if (!last) return "Сбор включён. Ожидаем первый снимок контроллера.";
    var rss = (last.processes || []).filter(function (p) { return typeof p.rss_kib === "number"; }).map(function (p) {
      var first = samples.find(function (s) {
        return (s.processes || []).some(function (q) { return q.name === p.name && q.pid === p.pid && typeof q.rss_kib === "number"; });
      });
      var before = first && first.processes.find(function (q) { return q.name === p.name && q.pid === p.pid; });
      var delta = before ? p.rss_kib - before.rss_kib : 0;
      return p.name + ": " + (p.rss_kib / 1024).toFixed(1) + " МиБ (" + (delta >= 0 ? "+" : "") + (delta / 1024).toFixed(1) + " за историю этого PID)";
    });
    var failures = events.filter(function (e) { return ["failed", "inconclusive", "unknown", "local-abort", "queue-full"].indexOf(e.outcome) >= 0; }).length;
    return "Снимков: " + samples.length + "/120; завершений поиска: " + events.length + "/64, без подтверждённого результата: " + failures +
      ". Привязок: " + last.bindings + ", планов: " + last.plans + ". " + (rss.length ? rss.join("; ") : "Память процессов недоступна.") +
      " Последний снимок: " + new Date(last.at * 1000).toLocaleTimeString() + ". Рост RSS сам по себе не доказывает утечку.";
  }
  if (typeof module === "object" && module.exports) module.exports = { summary: summary };
  if (!root.document || !root.fetch) return;
  function boot() {
    var doc = root.document, toggle = doc.getElementById("diagnostic-toggle"), status = doc.getElementById("diagnostic-status"), download = doc.getElementById("diagnostic-download");
    if (!toggle || !status || !download) return;
    function render(r) {
      var samples = r.samples || [], events = r.events || [], last = samples[samples.length - 1];
      var state = doc.getElementById("diagnostic-state"), data = doc.getElementById("diagnostic-data");
      state.textContent = enabled ? "Сбор включён" : "Сбор выключен";
      state.dataset.enabled = String(enabled);
      data.hidden = !enabled || !last;
      if (!enabled) { status.textContent = "Сбор выключен. Включите его, чтобы записать память и исходы поиска."; return; }
      if (!last) { status.textContent = "Ожидаем первый снимок. Отчёт обновляется раз в минуту."; return; }
      status.textContent = "Обновлено " + new Date(last.at * 1000).toLocaleTimeString() + " · снимок раз в минуту";
      var body = doc.getElementById("diagnostic-processes"); body.replaceChildren();
      var labels = { d2kc: "Контроллер", d2kd: "Датапат", d2ktg: "Telegram", d2kpanel: "Панель" };
      (last.processes || []).forEach(function (p) {
        var first;
        samples.some(function (s) { first = (s.processes || []).find(function (q) { return q.name === p.name && q.pid === p.pid && typeof q.rss_kib === "number"; }); return !!first; });
        var known = typeof p.rss_kib === "number", delta = known && first ? (p.rss_kib - first.rss_kib) / 1024 : null;
        var row = doc.createElement("tr"), name = doc.createElement("td"), code = doc.createElement("small");
        name.textContent = labels[p.name] || p.name; code.textContent = p.name; name.appendChild(code); row.appendChild(name);
        [known ? (p.rss_kib / 1024).toFixed(1) : "—", delta === null ? "—" : (delta > 0 ? "+" : "") + delta.toFixed(1)].forEach(function (v) { var cell = doc.createElement("td"); cell.textContent = v; row.appendChild(cell); });
        body.appendChild(row);
      });
      doc.getElementById("diagnostic-events").textContent = events.length + " / 64";
      doc.getElementById("diagnostic-unconfirmed").textContent = events.filter(function (e) { return ["failed", "inconclusive", "unknown", "local-abort", "queue-full"].indexOf(e.outcome) >= 0; }).length;
      doc.getElementById("diagnostic-catalog").textContent = last.bindings + " / " + last.plans;
      doc.getElementById("diagnostic-samples").textContent = samples.length + " / 120";
    }
    var enabled = false, busy = false;
    function refresh() {
      return root.fetch("/api/diagnostics?report", { cache: "no-store" }).then(function (r) {
        if (!r.ok && r.status !== 503) throw new Error("HTTP " + r.status);
        return r.json();
      }).then(function (r) {
        enabled = r.enabled === true;
        toggle.textContent = enabled ? "Выключить и удалить историю" : "Включить сбор";
        download.hidden = !enabled;
        render(r);
      }).catch(function () { status.textContent = "Не удалось прочитать состояние диагностики."; });
    }
    toggle.addEventListener("click", function () {
      if (busy) return; busy = true; toggle.disabled = true;
      root.fetch("/api/diagnostics?" + (enabled ? "disable" : "enable"), { method: "POST", cache: "no-store" }).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return refresh();
      }).catch(function () { status.textContent = "Не удалось переключить сбор. Требуется доступ к управлению этой панелью."; })
        .finally(function () { busy = false; toggle.disabled = false; });
    });
    refresh();root.setInterval(function () { if (!busy && !doc.hidden) refresh(); }, 60000);
  }
  if (root.document.readyState === "loading") root.document.addEventListener("DOMContentLoaded", boot); else boot();
})(typeof window !== "undefined" ? window : this);
