#!/usr/bin/env python3
"""Проверки гистограммы попаданий (sweep-histogram.py), без полевых журналов.

Фикстуры пишутся в свой временный каталог: журналы прогонов — свидетельства,
их не подделывают и из тестов не читают.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "sweep-histogram.py")
fails = 0


def check(cond, msg):
    global fails
    if not cond:
        print("ПРОВАЛ: %s" % msg)
        fails += 1


def run(lines, extra=()):
    d = tempfile.mkdtemp(prefix="sweep-hist-")
    with open(os.path.join(d, "d2kc.log"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    cmd = [sys.executable, "-I", TOOL, d, "--json"] + list(extra)
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p


def hit(name, path, target="x.test", search=1, protocol="tcp", family=4):
    return ("12:00:01 по %s приём «%s» НАЙДЕН замером (путь: %s) search=%d protocol=%s family=%d"
            % (target, name, path, search, protocol, family))


def outcome(path, units, verdict="probe-confirmed", target="x.test",
            search=1, protocol="tcp", family=4):
    return ("12:00:02 итог поиска: search=%d target=%s protocol=%s family=%d "
            "outcome=%s path=%s probe_units=%d accounting=scheduler "
            "elapsed_ms=1000 queue_ms=0 live=unknown"
            % (search, target, protocol, family, verdict, path, units))


# --- мало данных: порядок не меняем, и это не молчание ----------------------
p = run([hit("seqovl-1", "свойство"), outcome("property", 7)])
check(p.returncode == 1, "на одном наблюдении инструмент не отказался менять порядок")
check("данных мало" in p.stdout + p.stderr,
      "отказ без объяснения: человек не узнает, почему таблицы нет")

# --- достаточно данных: таблица по источникам ------------------------------
lines = []
for _ in range(12):
    lines += [hit("seqovl-1", "свойство"), outcome("property", 5)]
for _ in range(6):
    lines += [hit("disorder", "свойство"), outcome("property", 9)]
for _ in range(4):
    lines += [hit("oob", "перебор"), outcome("fallback", 41)]
p = run(lines)
check(p.returncode == 0, "на 22 наблюдениях инструмент отказал: %s" % p.stderr[:200])
check("seqovl-1" in p.stdout and "disorder" in p.stdout and "oob" in p.stdout,
      "в таблице нет сработавших гипотез")

p = run(lines, extra=())
j = json.loads(run(lines, ["--json"]).stdout)
by_path = {row["path"]: row for row in j["paths"]}
check("свойство" in by_path and "перебор" in by_path,
      "источники попаданий не разделены: %s" % sorted(by_path))
prop = by_path.get("свойство", {})
names = {h["name"]: h for h in prop.get("hits", [])}
check(names.get("seqovl-1", {}).get("hits") == 12,
      "попадания seqovl-1 посчитаны неверно: %s" % names.get("seqovl-1"))
check(names.get("disorder", {}).get("hits") == 6,
      "попадания disorder посчитаны неверно: %s" % names.get("disorder"))
check(list(names) and list(names)[0] == "seqovl-1",
      "гипотезы не упорядочены по числу попаданий: %s" % list(names))
check(names.get("seqovl-1", {}).get("median_units") == 5,
      "медиана зондов не та: %s" % names.get("seqovl-1"))

# --- гипотезы, которые поле ни разу не подтвердило -------------------------
never = set(j.get("never_hit", []))
check("md5" in never, "гипотеза md5 ни разу не сработала, но в список не попала")
# Семья имён с %d: сработавшее имя из семьи закрывает всю семью. Без этого
# список «ни разу не сработала» врал бы на badsum-x7-g300 и подобных.
j3 = json.loads(run(lines + [hit("badsum-x7-g300", "перебор"), outcome("fallback", 40)],
                    ["--json"]).stdout)
check("badsum-x%d-g%d" not in set(j3.get("never_hit", [])),
      "сработавшее имя из семьи не закрыло семью: %s" % j3.get("never_hit"))
check("seqovl-1" not in never, "сработавшая гипотеза объявлена не срабатывавшей")
check(j.get("list_source", "").endswith("poison.c"),
      "имена гипотез взяты не из списка в коде: %s" % j.get("list_source"))

# --- параллельные поиски: цена принадлежит своей цели ----------------------
# Планировщик ведёт поиски одновременно, и в журнале строки чередуются. Поле
# 24.10.2026 (прогон B1): находка flibusta.is была привязана к итогу
# graph.facebook.com, а собственный итог flibusta.is (46 единиц) потерялся —
# три такие привязки на два журнала. Числа такой гистограммы — не основание
# менять порядок гипотез.
inter = []
for _ in range(20):
    inter += [hit("seqovl-1", "свойство", target="a.test"),
              hit("oob", "перебор", target="b.test"),
              outcome("property", 5, target="a.test"),
              outcome("fallback", 41, target="b.test")]
ji = json.loads(run(inter, ["--json"]).stdout)
pi = {row["path"]: row for row in ji["paths"]}
ni = {h["name"]: h for h in pi.get("свойство", {}).get("hits", [])}
nf = {h["name"]: h for h in pi.get("перебор", {}).get("hits", [])}
check(ni.get("seqovl-1", {}).get("hits") == 20,
      "находка своей цели потеряна при чередовании: %s" % ni.get("seqovl-1"))
check(ni.get("seqovl-1", {}).get("median_units") == 5,
      "цена seqovl-1 взята у чужого поиска: %s" % ni.get("seqovl-1"))
check(nf.get("oob", {}).get("hits") == 20,
      "находка второй цели потеряна при чередовании: %s" % nf.get("oob"))
check(nf.get("oob", {}).get("median_units") == 41,
      "цена oob взята у чужого поиска: %s" % nf.get("oob"))

# --- строки прогонов QUIC считаются отдельным источником -------------------
qlines = list(lines) + ["12:00:03 по y.test (QUIC) стратегия из замера за 6 зондов: длина"] * 3
j2 = json.loads(run(qlines, ["--json"]).stdout)
qp = {row["path"]: row for row in j2["paths"]}
check("QUIC: стратегия из замера" in qp, "прогоны QUIC не выделены: %s" % sorted(qp))
check(qp.get("QUIC: стратегия из замера", {}).get("searches") == 3,
      "прогоны QUIC посчитаны неверно: %s" % qp.get("QUIC: стратегия из замера"))

# A domain is not a search identity: transport, family and retry differ.
spec = importlib.util.spec_from_file_location("histogram", TOOL)
histogram = importlib.util.module_from_spec(spec)
spec.loader.exec_module(histogram)

def scan_lines(rows):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "d2kc.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(rows))
        return histogram.scan([path])[0]

identified = hit("oob", "свойство", search=7)
right = outcome("property", 7, search=7)
for other in [
    outcome("none", 100, search=7, protocol="quic"),
    outcome("none", 100, search=7, family=6),
    outcome("none", 100),
]:
    found = scan_lines([identified, other, right])
    check(found["свойство"]["oob"] == [7], "чужой опыт присвоил цену: %s" % found)

# A restart invalidates pending identities even if the search counter repeats.
found = scan_lines([identified, "d2kc: запущен, сокет /tmp/test", right])
check(found["свойство"]["oob"] == [None], "цена перескочила перезапуск: %s" % found)
# Historical hits have no identity: retain the hit, leave its price unknown.
found = scan_lines([hit("oob", "свойство").split(" search=")[0], right])
check(found["свойство"]["oob"] == [None], "выдумана цена старой находки: %s" % found)

# JSON must expose unknown prices without corrupting the measured median.
legacy = hit("oob", "свойство").split(" search=")[0]
mixed = [legacy, outcome("property", 100)] * 10
mixed += [hit("oob", "свойство"), outcome("property", 7)] * 10
jm = json.loads(run(mixed).stdout)
row = next(h for path in jm["paths"] for h in path["hits"] if h["name"] == "oob")
check(row["hits"] == 20 and row.get("unpriced_hits") == 10 and row["median_units"] == 7,
      "неизвестные цены испортили медиану: %s" % row)

if fails:
    print("ПРОВАЛОВ: %d" % fails)
    sys.exit(1)
print("гистограмма попаданий: все проверки прошли")
