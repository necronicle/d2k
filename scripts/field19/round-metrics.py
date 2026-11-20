#!/usr/bin/env python3
"""Журнальные величины круга: чем взята каждая цель, а не только открылась ли.

Бинарный исход страницы на одной и той же сборке плавает (выпуск 374a6df:
4, 8 и 1 провал из 12 за три круга с чистого листа), поэтому сравнивать сборки
по нему нельзя. Эти величины считаются по каждому поиску и говорят, ЧТО
сделал код: каким путём получен план, сколько зондов стоил, сколько вопросов
о свойствах задано и сколько снято знанием, открывался ли запасной перебор.

    round-metrics.py КАТАЛОГ [КАТАЛОГ ...]

Каталог круга — тот, что оставляет router-round.sh (d2kc.log + targets.txt).
"""
import os
import re
import sys

RE_REPORT = re.compile(r"^\d\d:\d\d:\d\d итог поиска: (.*)$")
RE_Q = re.compile(r"^\d\d:\d\d:\d\d по (\S+) вопрос «(.*)»: (\d+)/(\d+)(.*)$")
# ПЕРЕБОР ОТКРЫТ — только строка, которая его ОТКРЫВАЕТ. Образец «.*запасной
# перебор» ловил и строку доспроса («запасной перебор пока не открываю»): круг
# cand-w1 показывал перебор там, где его как раз не было.
RE_SWEEP = re.compile(r"^\d\d:\d\d:\d\d по (\S+) .*"
                      r"(планов из запасного перебора|запасной список|"
                      r"продолжу запасной перебор)")
RE_EXHAUSTED = re.compile(r"^\d\d:\d\d:\d\d по (\S+) кандидаты замера исчерпаны")
RE_HOP = re.compile(r"^\d\d:\d\d:\d\d по (\S+) .*расстояние до коробки")
# Доспрос опроса после опровергнутого приёма (24.10.2026): без счётчика по нему
# не видно, сработала ли правка и сколько переборов она сняла.
RE_RESUME = re.compile(r"^\d\d:\d\d:\d\d по (\S+) приём «[^»]*» нашёл опрос, "
                       r"а применённый поток его опроверг")

PATHS = ("property", "own-plan", "fallback", "direct", "none")


def targets_of(d):
    """Цели круга из targets.txt; без файла — все имена из журнала."""
    p = os.path.join(d, "targets.txt")
    if not os.path.exists(p):
        return None
    out = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line.split("|")[0])
    return out


def parse(d):
    """Журнал круга -> (поиски, события по целям)."""
    searches = []
    per = {}
    path = os.path.join(d, "d2kc.log")
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = RE_REPORT.match(line)
            if m:
                kv = {}
                for tok in m.group(1).split():
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        kv[k] = v
                searches.append(kv)
                continue
            m = RE_Q.match(line)
            if m:
                name, label, got, sent, tail = m.groups()
                e = per.setdefault(name, {"q": [], "sweep": 0, "hop": 0, "resume": 0})
                # «0/0 — не измерено» — вопрос не задан (нет условий или снят
                # знанием); «— взял» — на нём опрос и кончился.
                e["q"].append({
                    "label": label,
                    "got": int(got),
                    "sent": int(sent),
                    "taken": "взял" in tail,
                    "asked": int(sent) > 0,
                })
                continue
            m = RE_RESUME.match(line)
            if m:
                per.setdefault(m.group(1), {"q": [], "sweep": 0, "hop": 0,
                                            "resume": 0})["resume"] += 1
                continue
            m = RE_EXHAUSTED.match(line) or RE_SWEEP.match(line)
            if m:
                per.setdefault(m.group(1), {"q": [], "sweep": 0, "hop": 0,
                                            "resume": 0})["sweep"] += 1
                continue
            m = RE_HOP.match(line)
            if m:
                per.setdefault(m.group(1), {"q": [], "sweep": 0, "hop": 0,
                                            "resume": 0})["hop"] += 1
                continue
    return searches, per


def median(xs):
    if not xs:
        return None
    xs = sorted(xs)
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def best(rows):
    """Главный итог цели: подтверждение важнее провала, замер важнее перебора."""
    rank = {"probe-confirmed": 0, "stun-confirmed": 0, "discovery-confirmed": 0,
            "probe-direct": 1, "failed": 2, "inconclusive": 3,
            "superseded": 4, "unknown": 5}
    return sorted(rows, key=lambda r: (rank.get(r.get("outcome", ""), 9),
                                       int(r.get("probe_units", 0))))[0]


def round_table(d, searches, per, targets):
    name = os.path.basename(os.path.normpath(d))
    by_target = {}
    for s in searches:
        by_target.setdefault(s.get("target", "?"), []).append(s)

    scope = targets if targets else sorted(by_target)
    print("=== %s" % name)
    print("%-24s %-9s %-16s %6s %6s %9s %5s %7s" %
          ("цель", "путь", "исход", "зондов", "сек", "вопросов", "да", "перебор"))
    units, by_path = [], {}
    for t in scope:
        rows = by_target.get(t)
        e = per.get(t, {"q": [], "sweep": 0, "hop": 0, "resume": 0})
        asked = sum(1 for q in e["q"] if q["asked"])
        skipped = sum(1 for q in e["q"] if not q["asked"])
        taken = sum(1 for q in e["q"] if q["taken"])
        if not rows:
            print("%-24s %-9s %-16s %6s %6s %9s %5s %7s" %
                  (t[:24], "-", "поиска не было", "-", "-",
                   "%d+%d" % (asked, skipped) if e["q"] else "-", "-", "-"))
            continue
        r = best(rows)
        u = int(r.get("probe_units", 0))
        ms = int(r.get("elapsed_ms", -1))
        units.append(u)
        by_path[r.get("path", "?")] = by_path.get(r.get("path", "?"), 0) + 1
        print("%-24s %-9s %-16s %6d %6s %9s %5d %7s" %
              (t[:24], r.get("path", "?"), r.get("outcome", "?"), u,
               "%.0f" % (ms / 1000.0) if ms >= 0 else "-",
               "%d+%d" % (asked, skipped), taken,
               "да" if e["sweep"] else "нет"))
    hops = sum(e["hop"] for e in per.values())
    resumes = sum(e.get("resume", 0) for e in per.values())
    print("  поисков всего %d, по целям круга %d | %s | зондов медиана %s | "
          "вопросов задано %d, не задано %d | расстояние мерили %d раз | "
          "опрос доспрашивали %d раз" %
          (len(searches), sum(1 for t in scope if t in by_target),
           ", ".join("%s %d" % (p, by_path[p]) for p in PATHS if p in by_path) or "путей нет",
           median(units), sum(sum(1 for q in e["q"] if q["asked"]) for e in per.values()),
           sum(sum(1 for q in e["q"] if not q["asked"]) for e in per.values()),
           hops, resumes))
    return {t: (best(by_target[t]) if t in by_target else None) for t in scope}


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cols, order = {}, []
    for d in argv:
        searches, per = parse(d)
        targets = targets_of(d)
        cols[d] = round_table(d, searches, per, targets)
        for t in (targets or sorted(cols[d])):
            if t not in order:
                order.append(t)
        print()
    if len(argv) < 2:
        return 0
    print("=== путь и зонды по кругам")
    print("%-24s %s" % ("цель", "  ".join("%-26s" % os.path.basename(os.path.normpath(d))
                                          for d in argv)))
    for t in order:
        cells = []
        for d in argv:
            r = cols[d].get(t)
            cells.append("%-26s" % ("—" if r is None else
                                    "%s/%s %s" % (r.get("path", "?"),
                                                  r.get("probe_units", "?"),
                                                  r.get("outcome", "?"))))
        print("%-24s %s" % (t[:24], "  ".join(cells)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
