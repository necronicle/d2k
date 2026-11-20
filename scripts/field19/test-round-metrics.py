#!/usr/bin/env python3
"""Разборщик круга на синтетическом журнале: молчаливый промах недопустим.

Разборщик читает журнал по образцам строк. Строка в d2kc меняется — образец
перестаёт совпадать, и таблица выходит пустой, то есть «поисков не было»
вместо «я не понял журнал». Поэтому: каждое поле проверяется на строке
ровно того вида, который печатает core/sched.c.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

LOG = """03:13:38 по clubtone.net (TCP) начинаю поиск: 185.86.95.62:443, приветствие 1792 байт
03:15:26 по clubtone.net вопрос «перекрытие слева»: 0/2
03:15:26 по clubtone.net вопрос «порядок сегментов»: 0/0 — не измерено
03:15:26 по clubtone.net вопрос «разбор протокола (приманка — »: 2/2 — взял
03:15:26 по clubtone.net кандидаты замера исчерпаны — 8 планов из запасного перебора донора (это не находка замера)
03:15:30 по soundcloud.com приём «oob» нашёл опрос, а применённый поток его опроверг — после оставшихся кандидатов доспрошу опрос со следующего вопроса (опровергнуто приёмов: 1), запасной перебор пока не открываю
03:16:35 итог поиска: search=4 target=clubtone.net protocol=tcp family=4 outcome=failed path=fallback probe_units=66 accounting=scheduler elapsed_ms=177000 queue_ms=0 live=unknown box=- plan=- why=-
03:17:00 итог поиска: search=5 target=soundcloud.com protocol=tcp family=4 outcome=probe-confirmed path=property probe_units=17 accounting=scheduler elapsed_ms=82000 queue_ms=0 live=unknown
"""

TARGETS = "clubtone.net|chrome,safari|/\nsoundcloud.com|chrome,safari|/\nwww.quiet.example|chrome|/\n"


def main():
    with tempfile.TemporaryDirectory() as d:
        r = os.path.join(d, "rel-x1")
        os.mkdir(r)
        with open(os.path.join(r, "d2kc.log"), "w", encoding="utf-8") as f:
            f.write(LOG)
        with open(os.path.join(r, "targets.txt"), "w", encoding="utf-8") as f:
            f.write(TARGETS)
        out = subprocess.run(
            [sys.executable, "-I", os.path.join(HERE, "round-metrics.py"), r],
            capture_output=True, text=True, check=True).stdout

    fails = 0

    def check(cond, why):
        nonlocal fails
        if not cond:
            print("ПРОВАЛ: %s" % why)
            fails += 1

    lines = {ln.split()[0]: ln for ln in out.splitlines() if ln and not ln.startswith(" ")}
    check("clubtone.net" in lines, "строка цели не напечатана — образец «итог поиска» не совпал")
    row = lines.get("clubtone.net", "")
    check("fallback" in row, "путь не прочитан из итога поиска")
    check(" 66 " in row or row.rstrip().endswith("да") and "66" in row,
          "зонды не прочитаны из итога поиска")
    check("177" in row, "время не пересчитано из elapsed_ms в секунды")
    # вопросов задано 2 («0/2» и «2/2»), не задано 1 («0/0 — не измерено»)
    check("2+1" in row, "вопросы посчитаны неверно: ждали «2+1» (задано+не задано)")
    check(row.rstrip().endswith("да"), "открытый перебор не отмечен")
    check("property" in lines.get("soundcloud.com", ""),
          "вторая цель или её путь потерялись")
    # «запасной перебор пока не открываю» — это НЕ открытый перебор
    check(lines.get("soundcloud.com", "").rstrip().endswith("нет"),
          "строка доспроса зачтена как открытый перебор")
    check("опрос доспрашивали 1 раз" in out,
          "доспрос опроса не посчитан")
    check("поиска не было" in lines.get("www.quiet.example", ""),
          "цель без поиска не названа — её молчание так же важно, как итог")
    check("зондов медиана 41.5" in out, "медиана по целям круга посчитана неверно")

    print("round-metrics: %s" % ("ПРОВАЛОВ %d" % fails if fails else "все проверки прошли"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
