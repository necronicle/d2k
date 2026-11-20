#!/usr/bin/env python3
"""Гистограмма попаданий по полевым журналам: чем коробки берутся на самом деле.

ЗАЧЕМ. Порядок гипотез в detect/poison.c до 23.10.2026 был задан
комментарием: «перекрытие в один байт (facebook), разнесённые дубликаты
(YouTube) и плотная семёрка — первыми». Это подгонка под коробку одной сети, а
не вывод: на другой линии порядок мимо, и сказать, насколько мимо, было нечем.
Инструмент считает по журналам прогонов, какая гипотеза какой коробкой взята и
во сколько зондов, — и этим числом уже можно менять порядок и выбрасывать то,
что поле не подтвердило ни разу (§0: лишние зонды убирать по причине).

ЧТО ОН НЕ ДЕЛАЕТ. Не правит код и не решает за человека. При малом числе
наблюдений прямо отказывается давать порядок: подгонка под двадцать строк —
та же ошибка, что подгонка под одну сеть, только дешевле на вид.

Имена гипотез берутся ИЗ КОДА (detect/poison.c), а не из журналов: иначе
«ни разу не сработала» нельзя отличить от «такой гипотезы и не было».
"""
import argparse
import json
import os
import re
import sys

HIT = re.compile(r"по (\S+) приём «([^»]+)» НАЙДЕН замером \(путь: ([^)]+)\)")
OUTCOME = re.compile(r"итог поиска: .*?\btarget=(\S+).*?\bpath=([a-z-]+)"
                     r".*?\bprobe_units=(\d+)")
QUIC_STRATEGY = re.compile(r"\(QUIC\) стратегия из замера за (\d+) зонд")
QUIC_ARM = re.compile(r"\(QUIC\) плечо подобрано за (\d+) зонд")
IDENTITY = re.compile(r"\bsearch=([1-9][0-9]*)\b.*?\bprotocol=(tcp|quic)\b.*?\bfamily=([46])\b")
ADD = re.compile(r'add\("([^"]+)"')

MIN_OBSERVATIONS = 20


def hypothesis_patterns(poison_c):
    """Имена гипотез из списка в коде. add("badsum-x%d-g%d", …) — это семья
    имён, а не одно имя: %d превращается в «одно или больше цифр»."""
    names = []
    try:
        with open(poison_c, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return names
    for raw in ADD.findall(text):
        # re.escape не трогает «%» (он не особый для регулярных выражений),
        # поэтому подстановка идёт по «%d», а не по «\%d»: с первой версией
        # семьи имён не сопоставлялись вовсе, и список «ни разу не сработала»
        # врал — в нём лежали гипотезы, которые поле подтвердило.
        names.append((raw, re.compile("^" + re.escape(raw).replace("%d", r"\d+") + "$")))
    return names


def median(values):
    v = sorted(value for value in values if value is not None)
    if not v:
        return None
    n = len(v)
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) // 2


def log_files(targets):
    out = []
    for t in targets:
        if os.path.isfile(t):
            out.append(t)
            continue
        for root, _dirs, files in os.walk(t):
            for name in files:
                if name.endswith(".log") or name.endswith(".run.log"):
                    out.append(os.path.join(root, name))
    return sorted(out)


def scan(paths):
    """Цена связывается с поиском, протоколом, семейством и целью.

    Старые строки без идентификатора и незавершённые поиски сохраняют факт
    находки, но не получают цену чужого опыта. None означает «не известно».
    Счётчик search начинается заново при запуске контроллера: строка запуска
    сбрасывает ожидающие связи. Файлы также разбираются независимо.
    """
    hits = {}          # путь -> имя -> [зонды]
    searches = {}      # путь -> сколько итогов
    quic = {}          # псевдопуть -> сколько прогонов
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        pending = {}    # (target, search, protocol, family) -> (список цен, индекс)
        for line in lines:
            if "d2kc: запущен," in line:
                pending.clear()
                continue
            m = HIT.search(line)
            if m:
                target, name, hit_path = m.group(1), m.group(2), m.group(3)
                values = hits.setdefault(hit_path, {}).setdefault(name, [])
                values.append(None)
                identity = IDENTITY.search(line)
                if identity:
                    pending[(target,) + identity.groups()] = (values, len(values) - 1)
                continue
            m = OUTCOME.search(line)
            if m:
                target, mpath, units = m.group(1), m.group(2), m.group(3)
                searches[mpath] = searches.get(mpath, 0) + 1
                identity = IDENTITY.search(line)
                found = pending.pop((target,) + identity.groups(), None) if identity else None
                if found:
                    values, index = found
                    values[index] = int(units)
                continue
            if QUIC_STRATEGY.search(line):
                quic["QUIC: стратегия из замера"] = quic.get("QUIC: стратегия из замера", 0) + 1
            elif QUIC_ARM.search(line):
                quic["QUIC: плечо подобрано"] = quic.get("QUIC: плечо подобрано", 0) + 1
    return hits, searches, quic


def main():
    ap = argparse.ArgumentParser(description="гистограмма попаданий по журналам")
    ap.add_argument("targets", nargs="+", help="каталоги или файлы журналов")
    ap.add_argument("--json", action="store_true", help="машинный вывод")
    ap.add_argument("--poison", default=None, help="путь к detect/poison.c")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    poison_c = args.poison or os.path.normpath(os.path.join(here, "..", "..", "detect", "poison.c"))
    files = log_files(args.targets)
    hits, searches, quic = scan(files)

    total = sum(len(v) for names in hits.values() for v in names.values())
    if total < MIN_OBSERVATIONS:
        msg = ("данных мало: попаданий %d, нужно не меньше %d — порядок не менять. "
               "Подгонка под несколько строк не лучше подгонки под одну сеть."
               % (total, MIN_OBSERVATIONS))
        print(msg)
        return 1

    patterns = hypothesis_patterns(poison_c)
    seen = set()
    for names in hits.values():
        seen.update(names)
    never = [raw for raw, rx in patterns if not any(rx.match(n) for n in seen)]

    rows = []
    for path, names in hits.items():
        items = []
        for name, units in names.items():
            items.append({"name": name, "hits": len(units),
                          "unpriced_hits": units.count(None), "median_units": median(units)})
        items.sort(key=lambda h: (-h["hits"], h["name"]))
        rows.append({"path": path, "searches": sum(h["hits"] for h in items), "hits": items})
    for path, n in quic.items():
        rows.append({"path": path, "searches": n, "hits": []})
    rows.sort(key=lambda r: -r["searches"])

    report = {
        "files": len(files),
        "observations": total,
        "list_source": poison_c,
        "paths": rows,
        "never_hit": never,
        "cost_by_machine_path": searches,
    }
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
        return 0

    print("журналов %d, попаданий %d" % (len(files), total))
    for row in rows:
        print("\n== %s (поисков %d) ==" % (row["path"], row["searches"]))
        for h in row["hits"]:
            price = h["median_units"] if h["median_units"] is not None else "неизвестна"
            print("  %-28s попаданий %4d  медиана зондов %s"
                  % (h["name"], h["hits"], price))
            if h["unpriced_hits"]:
                print("    без привязки цены к опыту: %d" % h["unpriced_hits"])
    if never:
        print("\n== поле не подтвердило ни разу (%d) ==" % len(never))
        for name in never:
            print("  %s" % name)
    print("\nИсходы по машинному пути: %s"
          % ", ".join("%s=%d" % kv for kv in sorted(searches.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
