#!/usr/bin/env python3
"""Offline regression for collection → report; never contacts a router."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('report', HERE / 'router-round-report.py')
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)

class RoundContract(unittest.TestCase):
    def test_failed_router_run_still_collects_log_and_reports_incomplete(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); bindir = p / 'bin'; bindir.mkdir()
            stub = bindir / 'ssh'
            stub.write_text("""#!/bin/sh
case "$*" in
 *--version*) echo 'd2kfetch lab-test';;
 *sha256sum*) echo 'test-hash';;
 *'cat /opt/d2k/release-id'*) echo lab-test;;
 *'sh /tmp/rr-'*) exit 1;;
 *'cat /tmp/rr-'*/t0*) echo 12:00:00;;
 *'sh -s --'*) cat >/dev/null; printf 'DONE\\n';;
 *'awk -v t0='*) echo '12:00:01 preserved router log';;
 *'cat >'*) cat >/dev/null;;
 *'rm -rf'*) echo 'unexpected cleanup' >&2; exit 99;;
esac
""")
            stub.chmod(0o755)
            python_stub = bindir / 'python3'
            python_stub.write_text('#!/bin/sh\ncase "$*" in *site-round.py*) exit 0;; esac\nexec '+__import__('sys').executable+' "$@"\n')
            python_stub.chmod(0o755)
            env = dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'],
                       D2K_FIELD_RUNS=str(p / 'runs'), EXPECT='lab-test')
            r = subprocess.run(['sh', str(HERE / 'router-round.sh'), 'fixture'],
                               env=env, capture_output=True, text=True, timeout=10)
            run = p / 'runs/fixture'
            self.assertEqual(r.returncode, 4, r.stdout+r.stderr)
            self.assertIn('preserved router log', (run / 'd2kc.log').read_text())
            self.assertTrue((run / 'report.txt').exists())
            self.assertTrue((run / 'collection-error.txt').exists())
            self.assertNotIn('unexpected cleanup', r.stderr)

    def test_worker_preflight_failure_stops_before_router_or_clear(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            bindir = p / 'bin'; bindir.mkdir()
            stub = bindir / 'ssh'
            stub.write_text('#!/bin/sh\necho unexpected-router-call >&2\nexit 99\n')
            stub.chmod(0o755)
            python_stub = bindir / 'python3'
            python_stub.write_text('#!/bin/sh\nexit 2\n')
            python_stub.chmod(0o755)
            env = dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'],
                       D2K_FIELD_RUNS=str(p / 'runs'))
            r = subprocess.run(['sh', str(HERE / 'router-round.sh'), 'fixture'],
                               env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 4)
            self.assertNotIn('unexpected-router-call', r.stderr)

    def test_transfer_empty_binary_and_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            src = p / 'src'; src.mkdir()
            dst = p / 'dst'; dst.mkdir()
            for content in (None, b'line\nDONE\n\x00binary\xff'):
                if content is not None:
                    (src / 'probe.raw').write_bytes(content)
                r = subprocess.run(['sh', str(HERE / 'd2kfetch-export.sh'), str(src)],
                                   capture_output=True, check=True)
                bundle = p / 'bundle'; bundle.write_bytes(r.stdout)
                subprocess.run(['python3', str(HERE / 'd2kfetch-import.py'), str(bundle), str(dst)], check=True)
                if content is not None:
                    self.assertEqual((dst / 'probe.raw').read_bytes(), content)
            bundle.write_bytes(r.stdout[:-6])
            r = subprocess.run(['python3', str(HERE / 'd2kfetch-import.py'), str(bundle), str(dst)], capture_output=True)
            self.assertNotEqual(r.returncode, 0)

    def test_truncated_transfer_is_atomic_and_is_collection_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            bundle = p / 'bundle'
            bundle.write_bytes(b'probe.raw 20\nshort')
            command = ['python3', str(HERE / 'd2kfetch-import.py'), str(bundle), tmp]
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertFalse((p / 'probe.raw').exists())
            self.assertEqual(sorted(f.name for f in p.iterdir()), ['bundle'])
            row = dict(name='a.example', mode='h3', instrument='d2kfetch', rc=0,
                       probe_file='probe.raw')
            result = report.probe_row(row, tmp)
            self.assertEqual(result.get('collection_error'), 'missing_probe')
            self.assertNotIn('instrument_error', result)
            (p / 'probe.raw').write_bytes(b'previous complete result')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual((p / 'probe.raw').read_bytes(), b'previous complete result')
            self.assertEqual(sorted(f.name for f in p.iterdir()), ['bundle', 'probe.raw'])
            self.assertIn('instrument_error', report.probe_row(row, tmp))

    def test_schema_dns_and_target_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            row = dict(name='a.example', mode='h3', instrument='d2kfetch', rc=2,
                       probe_file='probe.raw')
            probe = dict(schema=2, shape='dns_failed', measured=False,
                         reason='адрес не разрешился', name='a.example', ip=None)
            (p / 'probe.raw').write_text(json.dumps(probe))
            j = report.probe_row(row, tmp)
            self.assertEqual(j.get('collection_error'), 'dns_failed')
            self.assertNotIn('instrument_error', j)
            probe = dict(schema=2, shape='quic', name='a.example', ip='192.0.2.1',
                         http_status=200, response_complete=True, local_refusal=False,
                         measured=True, body_bytes=None, quic_stream_bytes=400,
                         headers_inspected=False, name_ok=1, level=3, elapsed_ms=120)
            row['rc'] = 0
            (p / 'probe.raw').write_text(json.dumps(probe))
            j = report.probe_row(row, tmp)
            self.assertEqual(j.get('ip'), '192.0.2.1')
            self.assertEqual(j.get('name_ok'), 1)
            self.assertEqual(j.get('level'), 3)
            self.assertIn('192.0.2.1', report.verdict(j))
            probe['schema'] = 1
            probe['body_bytes'] = 400
            (p / 'probe.raw').write_text(json.dumps(probe))
            self.assertIn('instrument_error', report.probe_row(row, tmp))

    def test_local_and_missing_are_not_network_failures_or_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'targets.txt').write_text('a.example|h3|/\nb.example|h3|/\nc.example|h3|/\n')
            rows = [dict(name='a.example', mode='h3', instrument='d2kfetch', rc=2,
                         local_refusal=True, measured=False, code=0, err='mark failed'),
                    dict(name='b.example', mode='h3', rc=0, code=200, size=20)]
            (p / 'control.jsonl').write_text(''.join('00:00:00 control '+json.dumps(r)+'\n' for r in rows))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                report.main(['report', tmp])
            s = out.getvalue()
            self.assertIn('измерено 1/3', s)
            self.assertIn('провалов 0/1', s)
            self.assertIn('ошибок инструмента 1', s)
            self.assertIn('нет результатов 1', s)
            self.assertNotIn('FAIL rc2', s)

    def test_malformed_row_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'targets.txt').write_text('a.example|h3|/\n')
            (p / 'control.jsonl').write_text('00:00:00 control {"t":0,470}\n')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                report.main(['report', tmp])
            self.assertIn('повреждённых строк 1', out.getvalue())

    def test_collector_preserves_stdout_stderr_and_exit(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            stub = p / 'fetch'
            stub.write_text("#!/bin/sh\nprintf '%s\\n' 'opaque stdout'\nprintf '%s\\n' 'local diagnostic' >&2\nexit 139\n")
            stub.chmod(0o755)
            env = dict(os.environ, D2KFETCH=str(stub))
            subprocess.run(['sh', str(HERE / 'd2kfetch-record.sh'), tmp,
                            'a.example', '127.0.0.1', '/', 'control'], env=env, check=True)
            row = json.loads((p / 'control.jsonl').read_text().split(' ', 2)[2])
            self.assertEqual(row['rc'], 139)
            self.assertEqual((p / row['probe_file']).read_text(),
                             subprocess.run([str(stub)], capture_output=True, text=True).stdout)
            self.assertEqual((p / (row['probe_file'] + '.err')).read_text(), 'local diagnostic\n')

    def test_partial_and_challenge_remain_distinct(self):
        self.assertIn('FAIL', report.verdict(dict(rc=1, code=200, size=5400)))
        self.assertTrue(report.verdict(dict(rc=0, code=403, size=2000)).startswith('ok?'))
        self.assertTrue(report.verdict(dict(rc=0, code=200, size=2000,
                                           cloudflare_challenge=True)).startswith('ok?'))

    def test_raw_probe_round_trip_and_real_process_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            reason = 'quote " and slash \\ and newline\nend'
            probe = dict(schema=2, shape="quic", name="a.example", ip="192.0.2.1", name_ok=1, level=3,
                         http_status=302, body_bytes=None, quic_stream_bytes=310, response_complete=True,
                         local_refusal=False, measured=True, location='/a?x="quoted"',
                         reason=reason, elapsed_ms=470, cloudflare_challenge=False)
            (p / 'probe.raw').write_text(json.dumps(probe))
            row = dict(name='a.example', mode='h3', instrument='d2kfetch', rc=0, probe_file='probe.raw')
            index = p / 'control.jsonl'
            index.write_text('00:00:00 control '+json.dumps(row)+'\n')
            j = report.load(str(index))[('a.example','h3')][0]
            self.assertEqual(j.get('size'), 310)
            self.assertEqual(j.get('err'), reason)
            self.assertEqual(j.get('loc'), probe['location'])
            self.assertTrue(report.ok(j))
            row['rc'] = 139
            index.write_text('00:00:00 control '+json.dumps(row)+'\n')
            j = report.load(str(index))[('a.example','h3')][0]
            self.assertFalse(report.ok(j))
            self.assertIn('НЕ ИЗМЕРЕНО', report.verdict(j))
            (p / 'probe.raw').write_text('not json')
            j = report.load(str(index))[('a.example','h3')][0]
            self.assertIn('НЕ ИЗМЕРЕНО', report.verdict(j))

class SiteSummary(unittest.TestCase):
    def test_saved_rounds_fallback_is_not_full_page_proof(self):
        for name in ('A-1024-1108', 'A2-1024-1108', 'B3-cand-1108'):
            run = HERE / 'fixtures/instrument-1108' / name
            result = report.site_summary(str(run))
            self.assertEqual(result['total'], 19)
            self.assertEqual(result['legacy_pass'], 18 if name == 'A-1024-1108' else 19)
            self.assertEqual(result['passed'], 0)
            self.assertEqual(len(result['unknown']), 19)
            self.assertEqual(result['h3_total'], 14)
        self.assertEqual(result['h3_pass'], 4)
        self.assertTrue(any('fast-torrent' in h for h, reason in result['unknown']))

    def test_site_failure_comes_from_resource_not_h3(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'targets.txt').write_text('a.example|chrome,h3|/\n')
            (p / 'site.jsonl').write_text(json.dumps(dict(
                schema=1, name='a.example', mode='chrome', complete=False,
                failures=['http://a.example/a.css: портал warning.rt.ru'],
                unknown=[], resources=2))+'\n')
            result = report.site_summary(tmp)
            self.assertEqual(len(result['failed']), 1)
            self.assertEqual(result['passed'], 0)

    def test_synthetic_full_visits_eighteen_and_fast_torrent_failure(self):
        # Explicit synthetic evidence, not a claim about the saved B3 experiment.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            targets = HERE / 'fixtures/instrument-1108/B3-cand-1108/targets.txt'
            (p / 'targets.txt').write_text(targets.read_text())
            rows = []
            for line in targets.read_text().splitlines():
                name, modes, route = line.split('|')
                if route not in ('/', '/ru/'):
                    continue
                for mode in modes.split(','):
                    failure = name == 'www.fast-torrent.ru' or mode == 'h3'
                    rows.append(dict(schema=1, name=name, mode=mode, complete=not failure,
                        failures=['ресурс: портал warning.rt.ru'] if failure else [],
                        unknown=[], resources=2, requests=[{}, {}]))
            (p / 'site.jsonl').write_text(''.join(json.dumps(j)+'\n' for j in rows))
            result = report.site_summary(tmp)
            self.assertEqual(result['passed'], 18)
            self.assertEqual([h for h, reason in result['failed']], ['www.fast-torrent.ru'])
            self.assertEqual(result['unknown'], [])

    def test_inconsistent_complete_visit_is_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'targets.txt').write_text('a.example|chrome|/\n')
            (p / 'site.jsonl').write_text(json.dumps(dict(schema=1, name='a.example',
                mode='chrome', complete=True, failures=[], unknown=[], resources=0, requests=[])))
            result = report.site_summary(tmp)
            self.assertEqual(result['passed'], 0)
            self.assertEqual(len(result['data_errors']), 1)



class PageVisit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('site_round', HERE / 'site-round.py')
        cls.site = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.site)

    def transport(self, responses):
        class Fake:
            def __init__(self):
                self.urls = []
                self.origins = set()
            def request(self, url, referer=""):
                self.urls.append(url)
                rc, status, headers, body = responses[url]
                key = PageVisit.site.origin(url)
                connects = int(key not in self.origins)
                self.origins.add(key)
                meta = dict(rc=rc, code=status, size=len(body), connects=connects,
                            ip='192.0.2.1', local_port=1234, remote_port=key[2])
                return meta, headers, body
        return Fake()

    def test_portal_after_main_on_reused_connection(self):
        t = self.transport({
            'http://www.fast-torrent.ru/': (0, 200, {'content-type': 'text/html'},
                b'<link rel="stylesheet" href="/dynamic.css"><script src="/dynamic.js"></script>'),
            'http://www.fast-torrent.ru/dynamic.css': (0, 302, {'location': 'http://warning.rt.ru/'}, b''),
            'http://www.fast-torrent.ru/dynamic.js': (0, 200, {}, b'// fine'),
        })
        result = self.site.visit('http://www.fast-torrent.ru/', t)
        self.assertFalse(result['complete'])
        self.assertIn('портал', result['failures'][0])
        self.assertEqual(t.urls[1], 'http://www.fast-torrent.ru/dynamic.css')
        self.assertEqual(result['requests'][1]['connects'], 0)

    def test_dynamic_resources_css_cross_origin_and_sizes(self):
        t = self.transport({
            'http://example.test/': (0, 200, {'content-type': 'text/html'},
                b'<base href="/assets/"><link rel="stylesheet" href="a.css"><img src="http://cdn.test/i.png">'),
            'http://example.test/assets/a.css': (0, 200, {'content-type': 'text/css'},
                b'@import "b.css"; a {background:url(/image.png)}'),
            'http://cdn.test/i.png': (0, 200, {}, b'image'),
            'http://example.test/assets/b.css': (0, 200, {'content-type': 'text/css'}, b'/*ok*/'),
            'http://example.test/image.png': (0, 200, {}, b'png'),
        })
        result = self.site.visit('http://example.test/', t, {'http://example.test/image.png': 3})
        self.assertTrue(result['complete'], result)
        self.assertEqual(result['resources'], 5)
        t.urls.clear()
        result = self.site.visit('http://example.test/', t, {'http://example.test/image.png': 99})
        self.assertFalse(result['complete'])
        self.assertIn('эталон 99', result['failures'][0])

    def test_partial_status_reconnect_and_redirect_are_not_success(self):
        local = self.transport({'http://example.test/': (1, 0, {}, b'')})
        local_result = self.site.visit('http://example.test/', local)
        self.assertEqual(local_result['failures'], [])
        self.assertIn('локальный отказ', local_result['unknown'][0])
        for rc, status in ((18, 200), (28, 0), (56, 200)):
            t = self.transport({'http://example.test/': (rc, status, {}, b'partial')})
            self.assertFalse(self.site.visit('http://example.test/', t)['complete'])
        t = self.transport({
            'http://example.test/': (0, 200, {'content-type': 'text/html'}, b'<script src="/a.js"></script>'),
            'http://example.test/a.js': (0, 200, {}, b'js'),
        })
        original = t.request
        def reconnect(url, referer=""):
            meta, headers, body = original(url, referer)
            meta['connects'] = 1
            return meta, headers, body
        t.request = reconnect
        result = self.site.visit('http://example.test/', t)
        self.assertFalse(result['complete'])
        self.assertIn('keep-alive', result['unknown'][0])
        t = self.transport({'http://example.test/': (0, 302, {'location': '/'}, b'')})
        self.assertFalse(self.site.visit('http://example.test/', t)['complete'])

    def test_fixture_h3_failure_tcp_page_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'targets.txt').write_text('a.example|chrome,h3|/\n')
            (p / 'site.jsonl').write_text(''.join(json.dumps(j)+'\n' for j in [
                dict(schema=1, name='a.example', mode='h3', complete=False, failures=['h3 unavailable'], unknown=[]),
                dict(schema=1, name='a.example', mode='chrome', complete=True, failures=[], unknown=[], resources=1, requests=[{}])]))
            result = report.site_summary(tmp)
            self.assertEqual(result['passed'], 1)
            self.assertEqual(result['failed'], [])
            self.assertEqual(result['h3_pass'], 0)


class PersistentWorker(unittest.TestCase):
    site = None

    @classmethod
    def setUpClass(cls):
        PageVisit.setUpClass()
        cls.site = PageVisit.site
    # Exercise actual C worker framing/persistent handle without opening sockets.
    def test_c_worker_rpc_and_missing_impersonation_are_offline(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            worker = p / 'worker'
            lib = p / ('fake.dylib' if sys.platform == 'darwin' else 'fake.so')
            subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror',
                            str(HERE / 'site-fetch.c'), '-o', str(worker),
                            *([] if sys.platform == 'darwin' else ['-ldl'])], check=True)
            source = HERE / 'fixtures/instrument-1108/fake-curl.c'
            build = ['cc', '-std=c99', '-Wall', '-Wextra', '-Werror',
                     '-dynamiclib' if sys.platform == 'darwin' else '-shared', '-fPIC', str(source), '-o', str(lib)]
            subprocess.run(build, check=True)
            transport = self.site.Worker([str(worker), str(lib), 'chrome150', '/unused-ca'])
            try:
                result = self.site.visit('http://example.test/', transport)
                self.assertFalse(result['complete'])
                self.assertIn('портал', result['failures'][0])
                self.assertEqual(result['requests'][1]['connects'], 0)
                self.assertEqual(result['requests'][1]['local_port'], 1234)
            finally:
                transport.close()
            (p / 'targets.txt').write_text('www.fast-torrent.ru|h3,chrome|/\n')
            subprocess.run([sys.executable, '-I', str(HERE / 'site-round.py'), str(p),
                '--backend', 'worker', '--worker', str(worker), '--library', str(lib), '--cacert', '/unused'], check=True)
            visits = [json.loads(line) for line in (p / 'site.jsonl').read_text().splitlines()]
            self.assertEqual([j['mode'] for j in visits], ['h3', 'chrome'])
            self.assertFalse(visits[1]['complete'])
            self.assertTrue((p / visits[1]['requests'][0]['body_file']).is_file())
            self.assertEqual(visits[1]['requests'][1]['connects'], 0)
            subprocess.run(build + ['-DOMIT_IMPERSONATE'], check=True)
            process = subprocess.run([str(worker), str(lib), 'chrome150', '/unused'], capture_output=True)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(process.stdout, b'')
            self.assertIn(b'curl_easy_impersonate', process.stderr)


class LogSlice(unittest.TestCase):
    """Сам срез журнала, а не факт вызова awk: программа берётся из скрипта."""

    def program(self):
        text = (HERE / 'router-round.sh').read_text(encoding='utf-8')
        line = next(l for l in text.splitlines() if 'awk -v t0=' in l and 'd2kc.log' in l)
        prog = line[line.index("'") + 1:line.rindex("'")]
        return prog.replace('\\$', '$')

    def slice(self, t0, lines):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'prog.awk').write_text(self.program(), encoding='utf-8')
            (p / 'log').write_text('\n'.join(lines) + '\n', encoding='utf-8')
            out = subprocess.run(['awk', '-v', 't0=' + t0, '-f', str(p / 'prog.awk'),
                                  str(p / 'log')], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            return out.stdout.splitlines()

    def test_round_crossing_midnight_keeps_its_log(self):
        """Поле 25.10.2026 (h3e-1): круг 23:54→00:09 терял журнал целиком."""
        got = self.slice('23:54:17', [
            '23:40:00 прошлое, до круга',
            '23:54:17 начало круга',
            '23:59:59 перед полуночью',
            '00:00:01 после полуночи',
            '00:09:38 конец круга',
        ])
        self.assertEqual(got, ['23:54:17 начало круга', '23:59:59 перед полуночью',
                               '00:00:01 после полуночи', '00:09:38 конец круга'])

    def test_previous_day_tail_is_replaced_by_fresh_day(self):
        """Хвост прошлых суток не выдаётся за круг: срез начинается заново."""
        got = self.slice('23:54:17', [
            '23:54:18 вчерашний хвост',
            '00:10:00 вчера после полуночи',
            '23:54:17 начало СЕГОДНЯШНЕГО круга',
            '23:55:00 работа круга',
        ])
        self.assertEqual(got, ['23:54:17 начало СЕГОДНЯШНЕГО круга', '23:55:00 работа круга'])

    def test_lines_before_t0_are_skipped_and_untimed_lines_follow_the_slice(self):
        got = self.slice('12:00:00', [
            '11:59:59 до круга',
            'd2kc: строка без времени до круга',
            '12:00:00 начало',
            'd2kc: строка без времени внутри круга',
            '12:00:05 конец',
        ])
        self.assertEqual(got, ['12:00:00 начало', 'd2kc: строка без времени внутри круга',
                               '12:00:05 конец'])


if __name__ == '__main__':
    unittest.main()
