#!/usr/bin/env python3
"""Recorded CLI write-out regressions. No sockets, curl or SSH are executed."""
import importlib.util
import unittest
from unittest.mock import patch
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('site', Path(__file__).with_name('site-round.py'))
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)

ROOT = 'http://www.fast-torrent.ru/'
CSS = ROOT + 'dynamic.css'
FIXTURES = Path(__file__).parent / 'fixtures/instrument-cli-1108'
HTML = b'<link rel="stylesheet" href="/dynamic.css">'


class Recorded:
    def __init__(self, reconnect=False, portal=True):
        self.calls = []
        self.reconnect, self.portal = reconnect, portal

    def batch(self, requests):
        self.calls.append(list(requests))
        rows, files = [], {}
        for i, (url, referer) in enumerate(requests):
            body = HTML if url == ROOT else b'/*ok*/'
            headers = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' if url == ROOT else b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n'
            code = 200
            if url == CSS and self.portal and len(requests) > 1:
                code, body = 302, b''
                headers = b'HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/\r\n\r\n'
            port = 41000 + int(self.reconnect and i > 0)
            rows.append(f'{url}\t{code}\t{len(body)}\t{int(i == 0 or self.reconnect)}\t{port}\t192.0.2.1\t1.1\t0\t80\n')
            files[f'b{i}'], files[f'h{i}'] = body, headers
        if len(requests) == 2 and self.portal:
            rows = [(FIXTURES / ('reconnect.tsv' if self.reconnect else 'portal.tsv')).read_text()]
        return site.parse_cli_output(''.join(rows), requests, files)


class CLITest(unittest.TestCase):
    def test_recorded_export_binary_names_and_invalid_streams(self):
        bundle = FIXTURES / 'export.bundle'
        expected = {'probe.b0': bytes(range(256)) + b'\nDONE\nprobe.fake 4\n',
                    'probe.h0': b'HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\n',
                    'probe.empty-_.09': b''}
        with tempfile.TemporaryDirectory() as tmp:
            site.probe_import.unpack(bundle, tmp)
            self.assertEqual({p.name: p.read_bytes() for p in Path(tmp).iterdir()}, expected)
            for payload in (b'probe.b0 5\nabc', b'DONE\nextra',
                            b'../escape 1\nxDONE\n', b'probe.x/y 0\nDONE\n',
                            b'probe.x -1\nDONE\n', b'probe.x 0\n'):
                bad = Path(tmp) / 'bad.bundle'
                bad.write_bytes(payload)
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    site.probe_import.unpack(bad, tmp)

    def test_cli_accepts_recorded_export_and_rejects_missing_file(self):
        payload = (FIXTURES / 'cli-export.bundle').read_bytes()
        cli = site.CLI('/unused', 'chrome', '/unused')
        with patch.object(cli, 'run_script', return_value=payload):
            result = cli.batch([(ROOT, '')])
        self.assertEqual(result[0][2], bytes(range(256)) + b'\nDONE\n')
        self.assertEqual(result[0][0]['stderr'], 'fixture stderr\n')
        for bad in (b'DONE\n', payload[:-3]):
            with patch.object(cli, 'run_script', return_value=bad), self.assertRaises(ValueError):
                cli.batch([(ROOT, '')])

    def test_fast_torrent_portal_same_process(self):
        cli = Recorded()
        result = site.cli_visit(ROOT, cli)
        self.assertFalse(result['complete'])
        self.assertIn('портал', result['failures'][0])
        self.assertEqual(cli.calls[-1], [(ROOT, ''), (CSS, ROOT)])
        self.assertEqual(result['requests'][1]['connects'], 0)
        self.assertEqual(result['requests'][1]['local_port'], 41000)
        self.assertTrue(result['discovery']['requests'])

    def test_reconnect_portal_is_not_a_verdict(self):
        result = site.cli_visit(ROOT, Recorded(reconnect=True))
        self.assertFalse(result['complete'])
        self.assertEqual(result['failures'], [])
        self.assertIn('keep-alive не сохранён', ' '.join(result['unknown']))

    def test_complete_visit(self):
        self.assertTrue(site.cli_visit(ROOT, Recorded(portal=False))['complete'])

    def test_incomplete_writeout_is_instrument_error(self):
        with self.assertRaises(ValueError):
            site.parse_cli_output('', [(ROOT, '')], {})

    def test_earlier_transfer_error_survives_later_success(self):
        requests = [(ROOT, ''), (CSS, ROOT)]
        files = {'b0': b'partial', 'h0': b'HTTP/1.1 200 OK\r\n\r\n',
                 'b1': b'ok', 'h1': b'HTTP/1.1 200 OK\r\n\r\n'}
        rows = (ROOT+'\t200\t7\t1\t41000\t192.0.2.1\t1.1\t18\t80\n'+
                CSS+'\t200\t2\t0\t41000\t192.0.2.1\t1.1\t0\t80\n')
        result = site.parse_cli_output(rows, requests, files)
        self.assertEqual([r[0]['rc'] for r in result], [18, 0])

    def test_new_connect_same_port_is_unknown(self):
        cli = Recorded(portal=True)
        batch = cli.batch
        def reconnect(requests):
            result = batch(requests)
            if len(result) > 1:
                result[1][0]['connects'] = 1
            return result
        cli.batch = reconnect
        result = site.cli_visit(ROOT, cli)
        self.assertEqual(result['failures'], [])
        self.assertIn('keep-alive', ' '.join(result['unknown']))

    def test_effective_url_can_add_empty_path_slash(self):
        result = site.parse_cli_output(ROOT+'\t200\t2\t1\t41000\t192.0.2.1\t1.1\t0\t80\n',
            [(ROOT.rstrip('/'), '')], {'b0': b'ok', 'h0': b'HTTP/1.1 200 OK\r\n\r\n'})
        self.assertEqual(result[0][0]['url_effective'], ROOT)

    def test_wire_size_is_not_decoded_size(self):
        result = site.parse_cli_output(ROOT+'\t200\t5\t1\t41000\t192.0.2.1\t2\t0\t80\n',
            [(ROOT, '')], {'b0': b'decoded body', 'h0': b'HTTP/2 200\r\n\r\n'})
        self.assertEqual(result[0][0]['size'], 12)
        self.assertEqual(result[0][0]['size_download'], 5)
        self.assertEqual(result[0][0]['http_version'], 3)


    def test_real_shell_envelope_and_controller_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            binary = run / 'fake-curl'
            binary.write_text('#!'+sys.executable+'\nexec(compile(open('+repr(str(FIXTURES / 'fake-cli.py'))+').read(), '+repr(str(FIXTURES / 'fake-cli.py'))+", 'exec'), {'__file__': "+repr(str(FIXTURES / 'fake-cli.py'))+"})\n")
            binary.chmod(0o700)
            (run / 'targets.txt').write_text('www.fast-torrent.ru|h3,http|/\n')
            env = dict(os.environ, FAKE_CLI_CALLS=str(run / 'calls'))
            subprocess.run([sys.executable, '-I', str(Path(site.__file__)), str(run),
                            '--curl', str(binary), '--cacert', '/unused'], env=env, check=True)
            rows = [json.loads(line) for line in (run / 'site.jsonl').read_text().splitlines()]
            self.assertEqual([r['mode'] for r in rows], ['h3', 'http'])
            self.assertEqual([r['backend'] for r in rows], ['cli', 'cli'])
            self.assertFalse(rows[0]['complete'])
            self.assertIn('rc=7', ' '.join(rows[0]['failures']))
            self.assertIn('портал', rows[1]['failures'][0])
            self.assertEqual(rows[1]['requests'][1]['connects'], 0)
            for phase in [rows[1], rows[1]['discovery']]:
                for rec in phase['requests']:
                    self.assertTrue((run / rec['body_file']).is_file())
            calls = [json.loads(line) for line in (run / 'calls').read_text().splitlines()]
            measured = calls[-1]
            self.assertEqual(len(measured), 2)
            for group in measured:
                self.assertIn('--http1.1', group)
                self.assertIn('--compressed', group)
                self.assertIn('--write-out', group)
            self.assertEqual(measured[1][measured[1].index('--referer')+1], ROOT)
            ca = run / 'ca.pem'
            ca.write_text('offline fixture')
            subprocess.run([sys.executable, '-I', str(Path(site.__file__)), str(run),
                            '--curl', str(binary), '--cacert', str(ca), '--check-only'], env=env, check=True)
            self.assertEqual(len((run / 'calls').read_text().splitlines()), len(calls))
            # Same h3 failure followed by a successful full TCP fallback.
            (run / 'site.jsonl').unlink()
            env['FAKE_CLI_PORTAL'] = '0'
            subprocess.run([sys.executable, '-I', str(Path(site.__file__)), str(run),
                            '--curl', str(binary), '--cacert', str(ca)], env=env, check=True)
            report_spec = importlib.util.spec_from_file_location('report', Path(site.__file__).with_name('router-round-report.py'))
            report = importlib.util.module_from_spec(report_spec)
            report_spec.loader.exec_module(report)
            summary = report.site_summary(str(run))
            self.assertEqual(summary['passed'], 1)
            self.assertEqual(summary['h3_pass'], 0)
            self.assertEqual(summary['failed'], [])

    def test_router_envelope_and_safari_profile_with_fake_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            binary = run / 'fake-curl'
            source = str(FIXTURES / 'fake-cli.py')
            binary.write_text('#!'+sys.executable+'\nexec(compile(open('+repr(source)+
                              ').read(), '+repr(source)+", 'exec'), {'__file__': "+repr(source)+"})\n")
            binary.chmod(0o700)
            ssh = run / 'ssh'
            ssh.write_text('#!/bin/sh\ncat > '+str(run / 'remote.sh')+'\nexec sh '+str(run / 'remote.sh')+'\n')
            tar = run / 'tar'
            tar.write_text("#!/bin/sh\necho \"tar: invalid option -- 'c'\" >&2\nexit 1\n")
            tar.chmod(0o700)
            ssh.chmod(0o700)
            # Router shell sees only the utilities used by working field19.
            for utility in ('sh', 'mktemp', 'touch', 'rm', 'wc', 'cat'):
                (run / utility).symlink_to(shutil.which(utility))
            with patch.dict(os.environ, PATH=str(run),
                            FAKE_CLI_CALLS=str(run / 'calls')):
                cli = site.CLI(str(binary), 'safari', '/unused', router=True)
                result = site.cli_visit(ROOT, cli)
            self.assertIn('портал', result['failures'][0])
            remote = (run / 'remote.sh').read_text()
            exporter = Path(site.__file__).with_name('d2kfetch-export.sh').read_text()
            self.assertIn(exporter, remote)
            subprocess.run(['sh', '-n', str(run / 'remote.sh')], check=True)
            calls = [json.loads(line) for line in (run / 'calls').read_text().splitlines()]
            for group in calls[-1]:
                self.assertEqual(group[group.index('--impersonate')+1], 'safari2601')
                self.assertIn('--http2', group)

    def test_other_origins_nested_css_and_changed_document(self):
        class Graph:
            def __init__(self):
                self.calls = []
            def batch(self, requests):
                self.calls.append(requests)
                self_test.assertEqual(len({site.origin(u) for u, _ in requests}), 1)
                responses = []
                for i, (url, referer) in enumerate(requests):
                    content_type, body = graph[url]
                    meta = dict(rc=0, code=200, size=len(body), connects=int(i == 0),
                                ip='192.0.2.1', local_port=41000, remote_port=80, http_version=2)
                    responses.append((meta, {'content-type': content_type}, body))
                return responses
        self_test = self
        graph = {ROOT: ('text/html', b'<link rel="stylesheet" href="/dynamic.css"><img src="http://cdn.test/x">'),
                 CSS: ('text/css', b'@import "nested.css";'),
                 ROOT+'nested.css': ('text/css', b'/*nested*/'),
                 'http://cdn.test/x': ('image/png', b'PNG')}
        cli = Graph()
        result = site.cli_visit(ROOT, cli)
        self.assertTrue(result['complete'], result)
        self.assertEqual(len(cli.calls[-2]), 3)
        self.assertEqual(len(cli.calls[-1]), 1)
        original = cli.batch
        def changed(requests):
            rows = original(requests)
            if len(requests) > 1:
                meta, headers, body = rows[0]
                body += b'<script src="/new.js"></script>'
                meta['size'] = len(body)
                rows[0] = meta, headers, body
            return rows
        graph[ROOT+'new.js'] = ('application/javascript', b'//new')
        cli.batch = changed
        result = site.cli_visit(ROOT, cli)
        self.assertTrue(result['complete'], result)
        self.assertIn(ROOT+'new.js', [r['url'] for r in result['requests']])


if __name__ == '__main__':
    unittest.main()
