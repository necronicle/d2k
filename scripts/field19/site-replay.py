#!/usr/bin/env python3
"""Re-evaluate saved measured site transfers and hash-addressed bodies OFFLINE.

Usage: site-replay.py RUN [--output FILE]
Does not invoke curl, SSH or Worker. Never reads discovery as verdict evidence.
Missing original write-outs/resources remain unknown. Output is a derived JSONL;
original site.jsonl and bodies are never changed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('site_round', Path(__file__).with_name('site-round.py'))
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)


def reclassify(run, row):
    run = Path(run).resolve()
    transfers = row.get('transfers', row.get('requests', []))
    if not transfers:
        # Old parser failures discarded all write-out evidence. No inference.
        return dict(row, replay=True, outcome='unknown', complete=False)
    responses = {}
    for rec in transfers:
        name = rec.get('body_file')
        if not isinstance(name, str):
            raise ValueError('saved transfer lacks body_file')
        path = (run / name).resolve()
        if path.parent != run / 'site-bodies':
            raise ValueError('body path outside site-bodies')
        body = path.read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        if rec.get('sha256') != digest or path.name != digest or rec.get('size') != len(body):
            raise ValueError('saved body hash/size mismatch: ' + rec['url'])
        responses[rec['url']] = dict(rec), rec['headers'], body
    roots = [r['url'] for r in row.get('requests', []) if r.get('document')]
    url = roots[0] if roots else transfers[0]['url']

    class Saved:
        def request(self, current, referer=''):
            if current in row.get('measurement_errors', {}):
                raise ValueError(row['measurement_errors'][current])
            if current not in responses:
                raise ValueError('ресурс не записан в измерительном проходе: ' + current)
            return responses[current]

    result = site.visit(url, Saved())
    site.validate_reuse(result, responses)
    if row.get('reference_file'):
        result['unknown'].append('эталон исходного опыта не переоценён офлайн')
        result.update(complete=False, outcome='unknown')
    expected = (30,) if row['mode'] == 'h3' else (2, 3)
    if any(r['rc'] == 0 and r.get('http_version') not in expected for r in transfers):
        result['unknown'].append('не подтверждён запрошенный протокол ' + row['mode'])
        result.update(complete=False, outcome='unknown')
    return dict(row, **result, replay=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output and (args.output.resolve() == args.run.resolve() or
                        args.run.resolve() in args.output.resolve().parents):
        parser.error('output must be outside the original run directory')
    rows = [reclassify(args.run, json.loads(line))
            for line in (args.run / 'site.jsonl').read_text().splitlines()]
    payload = ''.join(json.dumps(row, ensure_ascii=False)+'\n' for row in rows)
    if args.output:
        args.output.write_text(payload)
    else:
        print(payload, end='')


if __name__ == '__main__':
    main()
