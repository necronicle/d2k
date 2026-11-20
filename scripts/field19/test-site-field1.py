#!/usr/bin/env python3
"""Offline regressions: synthetic protocol cases, optional immutable field replay."""
import importlib.util
from pathlib import Path
import unittest
import json
import tempfile
import hashlib
import os
import sys
import io
import contextlib
from unittest.mock import patch

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('site', HERE / 'site-round.py')
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)
ROOT = 'http://example.test/'


class Graph:
    def __init__(self, graph):
        self.graph, self.calls = graph, []

    def batch(self, requests):
        self.calls.append(list(requests))
        result = []
        for i, (url, _) in enumerate(requests):
            rc, code, headers, body = self.graph[url]
            meta = dict(rc=rc, code=code, size=len(body), connects=int(i == 0),
                        ip='192.0.2.1', local_port=41000, remote_port=80, http_version=2)
            result.append((meta, headers, body))
        return result

    def request(self, url, referer=''):
        meta, headers, body = self.batch([(url, referer)])[0]
        meta['connects'] = int(not any(site.origin(u) == site.origin(url)
                              for call in self.calls[:-1] for u, _ in call))
        return meta, headers, body


def response(body=b'ok', code=200, rc=0, **headers):
    return rc, code, headers, body


class FieldRegressions(unittest.TestCase):
    def test_url_values_never_coerce_python_false(self):
        self.assertIsNone(site.web_url(ROOT, False))
        self.assertIsNone(site.web_url(ROOT, None))
        self.assertIsNone(site.web_url(ROOT, ''))
        # A literal server URL is real evidence, not a Python boolean.
        self.assertEqual(site.dependencies(ROOT, {'content-type': 'text/html'},
                         b'<img src="False">'), [ROOT+'False'])

    def test_complete_server_status_is_not_blocking(self):
        for code in (204, 304, 403, 404, 418, 500, 503):
            with self.subTest(code=code):
                g = Graph({ROOT: response(b'', code=code)})
                result = site.visit(ROOT, g)
                self.assertTrue(result['complete'], result)
                self.assertEqual(result['requests'][0]['code'], code)

    def test_external_failure_separate_and_traversal_continues(self):
        g = Graph({ROOT: response(b'<img src="http://cdn.test/a"><script src="/a.js"></script>',
                                 **{'content-type': 'text/html'}),
                   'http://cdn.test/a': response(rc=28), ROOT+'a.js': response(b'js')})
        result = site.visit(ROOT, g)
        self.assertTrue(result['complete'], result)
        self.assertEqual(len(result['third_party']), 1)
        self.assertIn('rc=28', str(result['third_party']))
        self.assertEqual(result['resources'], 3)

    def test_external_batch_instrument_error_does_not_erase_site(self):
        class BrokenExternal(Graph):
            def batch(self, requests):
                if site.origin(requests[0][0])[1] == 'cdn.test':
                    raise ValueError('recorded invalid external write-out')
                return super().batch(requests)
        g = BrokenExternal({ROOT: response(b'<img src="http://cdn.test/a"><script src="/a.js"></script>',
                                          **{'content-type': 'text/html'}),
                            ROOT+'a.js': response()})
        result = site.cli_visit(ROOT, g)
        self.assertTrue(result['complete'], result)
        self.assertIn('invalid external', str(result['third_party']))

    def test_portal_uses_hostname_not_arbitrary_substrings(self):
        g = Graph({ROOT: response(b'', code=302, location='https://imgur.com/Rkn1CqA'),
                   'https://imgur.com/Rkn1CqA': response(b'own server')})
        self.assertTrue(site.visit(ROOT, g)['complete'])
        g = Graph({ROOT: response(b'', code=302, location='http://warning.rt.ru/')})
        self.assertIn('портал', site.visit(ROOT, g)['failures'][0])

    def test_portal_body_requires_interstitial_not_article_link(self):
        for body in (b'<a href="http://warning.rt.ru/">Article about blocking</a>',
                     b'<iframe src="http://warning.rt.ru.evil.test/"></iframe>'):
            result = site.visit(ROOT, Graph({ROOT: response(body, **{'content-type': 'text/html'})}))
            self.assertEqual(result['failures'], [])
        for body in (b'<iframe src="http://warning.rt.ru/"></iframe>',
                     b'<meta http-equiv="refresh" content="0;url=http://warning.rt.ru/">'):
            result = site.visit(ROOT, Graph({ROOT: response(body, **{'content-type': 'text/html'})}))
            self.assertIn('портал', result['failures'][0])

    def test_challenge_has_own_server_response_outcome(self):
        result = site.visit(ROOT, Graph({ROOT: response(b'<title>Just a moment</title>',
                    code=403, **{'content-type': 'text/html'})}))
        self.assertEqual(result['outcome'], 'server_replied_challenge')
        self.assertFalse(result['complete'])
        self.assertEqual(result['unknown'], [])
        self.assertEqual(result['failures'], [])

    def test_failed_transfer_negative_endpoints_and_raw_writeout(self):
        row = ROOT+'\t000\t0\t0\t-1\t\t0\t7\t-1\n'
        meta, _, _ = site.parse_cli_output(row, [(ROOT, '')], {'b0': b'', 'h0': b''})[0]
        self.assertEqual(meta['rc'], 7)
        self.assertEqual(meta['writeout'], row.rstrip('\n'))
        good = ROOT+'\t200\t2\t1\t41000\t192.0.2.1\t1.1\t0\t80\n'
        meta, _, _ = site.parse_cli_output(good, [(ROOT, '')],
                     {'b0': b'ok', 'h0': b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'})[0]
        self.assertEqual(meta['writeout'], good.rstrip('\n'))
        with self.assertRaises(ValueError):
            site.parse_cli_output(row.replace('\t7\t', '\t0\t'), [(ROOT, '')], {'b0': b'', 'h0': b''})

    def test_new_measured_resource_expands_prefix_batch(self):
        class Changing(Graph):
            def batch(self, requests):
                rows = super().batch(requests)
                if len(requests) > 1:
                    meta, headers, _ = rows[0]
                    body = b'<script src="/a.js"></script><img src="/new.png">'
                    rows[0] = dict(meta, size=len(body)), headers, body
                return rows
        g = Changing({ROOT: response(b'<script src="/a.js"></script>', **{'content-type': 'text/html'}),
                      ROOT+'a.js': response(), ROOT+'new.png': response()})
        result = site.cli_visit(ROOT, g)
        self.assertTrue(result['complete'], result)
        self.assertEqual(g.calls[-1], [(ROOT, ''), (ROOT+'a.js', ROOT), (ROOT+'new.png', ROOT)])
        self.assertEqual(result['requests'][-1]['connects'], 0)
        self.assertEqual(len({r['batch'] for r in result['requests']}), 1)

    def test_truncation_and_document_redirect_failure_retained(self):
        for rc in (18, 28, 35, 56):
            result = site.visit(ROOT, Graph({ROOT: response(rc=rc)}))
            self.assertTrue(result['failures'])
        result = site.visit(ROOT, Graph({ROOT: response(b'', code=302, location='https://other.test/'),
                                        'https://other.test/': response(rc=28)}))
        self.assertTrue(result['failures'])


class ReplayAndReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name, filename in [('replay', 'site-replay.py'), ('report', 'router-round-report.py')]:
            spec = importlib.util.spec_from_file_location(name, HERE / filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            setattr(cls, name, module)

    def test_challenge_summary_separate_from_unknown_and_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'targets.txt').write_text('example.test|chrome|/\n')
            row = site.visit(ROOT, Graph({ROOT: response(b'Just a moment', code=403)}))
            row.update(schema=1, name='example.test', mode='chrome')
            (p/'site.jsonl').write_text(json.dumps(row)+'\n')
            result = self.report.site_summary(tmp)
            self.assertEqual(result['passed'], 0)
            self.assertEqual(result['failed'], [])
            self.assertEqual(result['unknown'], [])
            self.assertEqual(len(result['responded']), 1)

    def test_replay_refuses_to_write_inside_source_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'site-bodies').mkdir()
            body = p/'site-bodies'/'original'
            body.write_bytes(b'original')
            row = dict(schema=1, mode='http', name='example.test', complete=False,
                       failures=[], unknown=['missing'], requests=[])
            (p/'site.jsonl').write_text(json.dumps(row)+'\n')
            for target in (body, p/'targets.txt', p/'site.jsonl'):
                with patch.object(sys, 'argv', ['site-replay', str(p), '--output', str(target)]):
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        self.replay.main()
            self.assertEqual(body.read_bytes(), b'original')

    def test_replay_is_measured_only_and_verifies_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'site-bodies').mkdir()
            body = b'<img src="http://third.test/new.png"><script src="/missing.js"></script>'
            digest = hashlib.sha256(body).hexdigest()
            (p/'site-bodies'/digest).write_bytes(body)
            row = dict(schema=1, mode='http', name='example.test', complete=False,
                       failures=[], unknown=[], requests=[], transfers=[dict(url=ROOT,
                       rc=0, code=200, size=len(body), sha256=digest,
                       body_file='site-bodies/'+digest, headers={'content-type':'text/html'},
                       connects=1, ip='192.0.2.1', remote_port=80, local_port=41000, batch=0, http_version=2)])
            row['discovery'] = dict(requests=[dict(url=ROOT+'missing.js')])
            with patch.object(self.replay.site.CLI, 'batch', side_effect=AssertionError('network')):
                result = self.replay.reclassify(p, row)
            self.assertFalse(result['complete'])
            self.assertIn('missing.js', str(result['unknown']))
            self.assertIn('third.test', str(result['third_party']))
            (p/'site-bodies'/digest).write_bytes(b'corrupted')
            with self.assertRaises(ValueError):
                self.replay.reclassify(p, row)


class SavedField(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('D2K_FIELD1_RUN'), 'set D2K_FIELD1_RUN to saved B3-1108b')
    def test_saved_b3_summary_and_fast_torrent_evidence(self):
        spec = importlib.util.spec_from_file_location('report', HERE / 'router-round-report.py')
        report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report)
        run = Path(os.environ['D2K_FIELD1_RUN'])
        before = hashlib.sha256((run/'site.jsonl').read_bytes()).hexdigest()
        with patch.object(report.site_replay.site.CLI, 'batch', side_effect=AssertionError('network')):
            summary = report.site_summary(run)
        self.assertEqual(summary['passed'], 12)
        self.assertEqual([h for h, _ in summary['failed']], ['mailsuite.com'])
        self.assertEqual([h for h, _ in summary['unknown']], ['enimerosi.com'])
        self.assertEqual({h for h, _ in summary['responded']},
                         {'rutracker.org', 'ru.numista.com', 'rua.gr', 'romfea.gr', 'speed.cloudflare.com'})
        self.assertEqual(summary['data_errors'], [])
        fast = summary['visits']['www.fast-torrent.ru', 'http']
        self.assertTrue(fast['complete'])
        same = [r for r in fast['requests'] if site.origin(r['url']) == site.origin('http://www.fast-torrent.ru/')]
        self.assertEqual([r['code'] for r in same], [200, 301, 500])
        self.assertEqual([r['connects'] for r in same], [1, 0, 0])
        self.assertEqual(len({r['local_port'] for r in same}), 1)
        self.assertEqual(same[1]['headers']['location'], '/False/')
        body = (run / same[0]['body_file']).read_bytes()
        self.assertIn(b"src='False'", body)
        self.assertEqual(before, hashlib.sha256((run/'site.jsonl').read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
