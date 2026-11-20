#!/usr/bin/env python3
"""Full static-document visits; host parser, CLI batches or optional libcurl worker.

No execution on import. router-round/lan-round invoke this AFTER h3 diagnostics.
Reads targets.txt: only document paths '/' and '/ru/' are sites, CDN paths remain
independent diagnostics. HTML scripts/styles/images/frames and CSS dependencies
come from responses, never a hand-maintained resource list. JavaScript execution,
viewport/lazy-load decisions and authenticated site functions are not modeled.

site-round.py RUN_DIR --cacert PATH [--router] [--curl PATH]
  --backend worker --worker PATH --library PATH : optional shared-library worker.
  --references JSON : {absolute_url: decoded_body_size}; no implicit baseline.
Default CLI mode needs only the installed curl-impersonate, CA bundle and POSIX sh/BusyBox utilities.
--router uses SSH only when explicitly invoked, never during offline tests.
"""
import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html.parser import HTMLParser
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import threading
import tempfile
import os
from urllib.parse import urljoin, urlsplit, urldefrag

# Load the existing host decoder even under python -I (no sibling sys.path).
_import_spec = importlib.util.spec_from_file_location(
    'd2kfetch_import', Path(__file__).with_name('d2kfetch-import.py'))
probe_import = importlib.util.module_from_spec(_import_spec)
_import_spec.loader.exec_module(probe_import)

def portal_url(url):
    """Match known provider portal hosts, never arbitrary URL substrings."""
    host = (urlsplit(url).hostname or '').lower()
    return (host == 'warning.rt.ru' or host.endswith('.warning.rt.ru') or
            any(label == 'lawfilter' for label in host.split('.')))


def web_url(base, value):
    if not isinstance(value, str) or not value.strip():
        return None
    url = urldefrag(urljoin(base, value.strip()))[0]
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        return None
    if any(ord(c) < 32 or c.isspace() for c in url):
        return None
    return url


class Resources(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.base = url
        self.has_base = False
        self.links = []
        self.in_style = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'base' and a.get('href') and not self.has_base:
            self.base = web_url(self.base, a['href']) or self.base
            self.has_base = True
        values = []
        if tag in ('script', 'img', 'iframe', 'frame', 'source', 'video', 'audio', 'input'):
            values.append(a.get('src', ''))
        if tag == 'video':
            values.append(a.get('poster', ''))
        if tag == 'object':
            values.append(a.get('data', ''))
        if tag == 'link' and set((a.get('rel') or '').lower().split()) & {
                'stylesheet', 'preload', 'modulepreload', 'icon'}:
            values.append(a.get('href', ''))
        if a.get('srcset'):
            values += [v.strip().split()[0] for v in a['srcset'].split(',') if v.strip()]
        self.links.extend((self.base, v) for v in values if v)
        self.links.extend((self.base, v) for v in css_links(a.get('style') or ''))
        self.in_style = self.in_style or tag == 'style'

    def handle_endtag(self, tag):
        if tag == 'style':
            self.in_style = False

    def handle_data(self, data):
        if self.in_style:
            self.links.extend((self.base, v) for v in css_links(data))


def css_links(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    result = []
    for m in re.finditer(r'url\(\s*(?:"([^"]*)"|\x27([^\x27]*)\x27|([^)]*?))\s*\)|'
                         r'@import\s+["\x27]([^"\x27]+)["\x27]', text, re.I):
        result.append(next(v for v in m.groups() if v is not None).strip())
    return result


def dependencies(url, headers, body, document=False):
    content_type = headers.get('content-type', '').lower()
    text = body.decode('utf-8', errors='replace')
    if 'text/html' in content_type or (document and not content_type):
        parser = Resources(url)
        parser.feed(text)
        links = parser.links
    elif 'text/css' in content_type or urlsplit(url).path.lower().endswith('.css'):
        links = [(url, v) for v in css_links(text)]
    else:
        links = []
    return list(dict.fromkeys(u for base, v in links if (u := web_url(base, v))))


def portal_body_url(url, headers, body):
    """An embedded provider interstitial/refresh is stronger than an article link."""
    if 'text/html' not in headers.get('content-type', '').lower():
        return None
    class PortalPage(HTMLParser):
        destination = None
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            value = None
            if tag in ('iframe', 'frame'):
                value = attrs.get('src')
            elif tag == 'form':
                value = attrs.get('action')
            elif tag == 'meta' and (attrs.get('http-equiv') or '').lower() == 'refresh':
                match = re.search(r'url\s*=\s*[\"\']?([^\"\']+)', attrs.get('content') or '', re.I)
                value = match.group(1).strip() if match else None
            destination = web_url(url, value)
            if destination and portal_url(destination):
                self.destination = destination
    page = PortalPage(convert_charrefs=True)
    page.feed(body.decode('utf-8', errors='replace'))
    return page.destination


def origin(url):
    p = urlsplit(url)
    return p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80)


def visit(url, transport, references=None):
    """One visit, no merging retries/attempts. Transport retains its connection pool."""
    references = references or {}
    queue = deque([(url, True, (), "")])
    seen, endpoints, records, failures, unknown = set(), {}, [], [], []
    challenges, third_party = [], []
    document_hosts = {urlsplit(url).hostname}
    def issue(kind, current, document, text):
        if not document and urlsplit(current).hostname not in document_hosts:
            third_party.append(dict(url=current, outcome=kind, reason=text))
        else:
            (failures if kind == 'failed' else unknown).append(text)
    while queue:
        current, document, redirects, referer = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        try:
            meta, headers, body = transport.request(current, referer)
        except (OSError, ValueError, KeyError, EOFError) as exc:
            issue('unknown', current, document, current + ': ошибка прибора: ' + str(exc))
            continue
        if document:
            document_hosts.add(urlsplit(current).hostname)
        rec = dict(meta, url=current, document=document, headers=headers,
                   sha256=hashlib.sha256(body).hexdigest())
        records.append(rec)
        loc = headers.get('location', '')
        destination = web_url(current, loc) if loc else None
        # Portal detection is tied to response location/body, not page keywords
        # like "rkn" which may appear in perfectly legitimate articles/scripts.
        portal_body = portal_body_url(current, headers, body)
        if (destination and portal_url(destination)) or portal_body:
            issue('failed', current, document, current + ': портал ' + (loc or portal_body))
            continue
        if meta['rc'] in (1, 2, 3, 4, 23, 27, 37, 43, 48, 77):
            issue('unknown', current, document, current + ': локальный отказ libcurl rc=' + str(meta['rc']))
            continue
        if meta['rc'] != 0 or meta['size'] != len(body):
            issue('failed', current, document, current + ': неполный ответ rc=' + str(meta['rc']))
            continue
        code = meta['code']
        if current in references and len(body) != references[current]:
            issue('failed', current, document, current + ': размер %d, эталон %d' % (len(body), references[current]))
        if 300 <= code < 400 and loc:
            if destination is None or destination in seen or destination in redirects or len(redirects) >= 20:
                issue('unknown', current, document, current + ': некорректный/циклический redirect ' + loc)
            else:
                queue.appendleft((destination, document, redirects + (current,), referer))
        elif any(marker in body.lower() for marker in
                (b'cf-chl-', b'challenge-platform', b'just a moment')):
            challenges.append(current + ': сервер ответил (проверка браузера), полный визит не измерим статически')
        elif not 100 <= code <= 599:
            issue('unknown', current, document, current + ': нет корректного HTTP-ответа')
        else:
            queue.extend((u, False, (), current) for u in dependencies(current, headers, body, document))
        key = origin(current)
        endpoint = (meta.get('ip'), meta.get('remote_port'), meta.get('local_port'))
        if key in endpoints and (meta.get('connects') != 0 or endpoint != endpoints[key]):
            issue('unknown', current, document, current + ': keep-alive не сохранён (новое TCP-соединение)')
        endpoints[key] = endpoint
    for rec in records:
        if not rec['document'] and urlsplit(rec['url']).hostname not in document_hosts:
            if not any(x['url'] == rec['url'] for x in third_party):
                third_party.append(dict(url=rec['url'], outcome='server_replied',
                                        code=rec['code'], reason='HTTP ' + str(rec['code'])))
    outcome = ('failed' if failures else 'unknown' if unknown else
               'server_replied_challenge' if challenges else 'complete')
    return dict(complete=outcome == 'complete', outcome=outcome, failures=failures,
                unknown=unknown, challenges=challenges, third_party=third_party,
                resources=len(records), requests=records)


class Worker:
    def __init__(self, command, body_dir=None):
        self.body_dir = body_dir
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            ready = json.loads(self.process.stdout.readline())
            if ready != {'ready': 1, 'schema': 1}:
                raise ValueError('unsupported worker schema')
        except BaseException:
            self.close()
            raise

    def read(self, n):
        chunks = bytearray()
        while len(chunks) < n:
            b = self.process.stdout.read(n-len(chunks))
            if not b:
                raise EOFError('worker response truncated')
            chunks.extend(b)
        return bytes(chunks)

    def request(self, url, referer=""):
        if web_url(url, url) != url:
            raise ValueError('invalid URL')
        self.process.stdin.write((url+'\n'+referer+'\n').encode())
        self.process.stdin.flush()
        meta = json.loads(self.process.stdout.readline())
        for k in ('rc', 'code', 'size', 'header_size', 'connects', 'local_port', 'remote_port', 'http_version'):
            if type(meta.get(k)) is not int or meta[k] < 0:
                raise ValueError('invalid worker field ' + k)
        raw = self.read(meta['header_size']).decode('iso-8859-1')
        # Last header block (e.g. after an informational 103).
        block = raw.strip().split('\r\n\r\n')[-1]
        headers = {}
        for line in block.splitlines()[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.lower().strip()] = v.strip()
        body = self.read(meta['size'])
        if self.body_dir is not None:
            digest = hashlib.sha256(body).hexdigest()
            with tempfile.NamedTemporaryFile(dir=self.body_dir, delete=False) as f:
                f.write(body)
                temporary = f.name
            os.replace(temporary, self.body_dir / digest)
            meta['body_file'] = 'site-bodies/' + digest
        return meta, headers, body

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=25)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()


def parse_cli_output(output, requests, files):
    """Parse one curl process, including errors on earlier transfers.

    size_download counts encoded wire bytes; body files contain decoded bytes.
    Keep both, never compare a compressed size_download to decoded body length.
    """
    rows = output.splitlines()
    if len(rows) != len(requests):
        raise ValueError('incomplete CLI write-out')
    responses = []
    versions = {'0': 0, '1': 2, '1.0': 1, '1.1': 2, '2': 3, '2.0': 3, '3': 30, '3.0': 30}
    for i, (line, (url, referer)) in enumerate(zip(rows, requests)):
        fields = line.split('\t')
        if len(fields) != 9:
            raise ValueError('invalid CLI write-out fields')
        # Transfers are bound by ordered --url/--output pairs. curl may
        # normalize an empty path or dot segments in url_effective.
        if web_url(fields[0], fields[0]) != fields[0] or origin(fields[0]) != origin(url):
            raise ValueError('invalid CLI effective origin')
        effective, code, size, connects, port, ip, version, rc, remote_port = fields
        values = [int(v) for v in (code, size, connects, rc)]
        ports = [int(v) for v in (port, remote_port)]
        if (any(v < 0 for v in values) or version not in versions or
                any(v < (-1 if int(rc) else 0) or v > 65535 for v in ports)):
            raise ValueError('invalid CLI write-out values: ' + repr(line))
        body, raw = files['b'+str(i)], files['h'+str(i)]
        headers = {}
        for header_line in raw.decode('iso-8859-1').strip().split('\r\n\r\n')[-1].splitlines()[1:]:
            if ':' in header_line:
                k, v = header_line.split(':', 1)
                headers[k.lower().strip()] = v.strip()
        meta = dict(rc=int(rc), code=int(code), size=len(body), size_download=int(size),
                    connects=int(connects), local_port=int(port), ip=ip,
                    remote_port=int(remote_port), http_version=versions[version],
                    url_effective=effective, writeout=line)
        responses.append((meta, headers, body))
    return responses


class CLI:
    """One process per batch. Existing field19 byte framing crosses SSH; no remote Python needed."""
    def __init__(self, binary, mode, cacert, router=False, body_dir=None):
        self.binary, self.mode, self.cacert = binary, mode, cacert
        self.router, self.body_dir = router, body_dir

    def run_script(self, script, timeout):
        command = ['sh', '-s']
        if self.router:
            command = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                       '-p', '222', 'root@192.168.1.1', 'sh -s']
        result = subprocess.run(command, input=script.encode(), capture_output=True, timeout=timeout)
        if result.returncode:
            raise ValueError('CLI envelope failed: ' + result.stderr.decode(errors='replace')[-500:])
        return result.stdout

    def check(self):
        profile = 'safari2601' if self.mode == 'safari' else 'chrome150'
        output = self.run_script('set -e\ntest -r ' + shlex.quote(self.cacert) + '\n' +
                                 shlex.join([self.binary, '--impersonate', profile, '--version'])+'\n', 30)
        if b'IMPERSONATE' not in output.upper():
            raise ValueError('curl-impersonate version not confirmed')

    def batch(self, requests):
        if not requests or len({origin(u) for u, _ in requests}) != 1:
            raise ValueError('CLI batch must have one origin')
        fmt = '%{url_effective}\t%{http_code}\t%{size_download}\t%{num_connects}\t%{local_port}\t%{remote_ip}\t%{http_version}\t%{exitcode}\t%{remote_port}\n'
        command = [self.binary]
        names = ['writeout', 'errors']
        for i, (url, referer) in enumerate(requests):
            if web_url(url, url) != url or (referer and web_url(referer, referer) != referer):
                raise ValueError('invalid CLI URL')
            if i:
                command += ['--next']
            command += ['--impersonate', 'safari2601' if self.mode == 'safari' else 'chrome150',
                        '-4', '-sS', '--globoff', '--noproxy', '*', '--proto', '=http,https',
                        '--compressed', '--max-time', '20', '--cacert', self.cacert,
                        '--doh-url', 'https://1.1.1.1/dns-query', '--cookie', 'cookies',
                        '--cookie-jar', 'cookies',
                        '--http3-only' if self.mode == 'h3' else ('--http1.1' if self.mode == 'http' else '--http2'),
                        '--output', 'probe.b'+str(i), '--dump-header', 'probe.h'+str(i), '--write-out', fmt]
            if self.mode in ('chrome', 'h3'):
                command += ['--ech', 'true']
            if referer:
                command += ['--referer', referer]
            command += ['--url', url]
            names += ['b'+str(i), 'h'+str(i)]
        # Reuse the working field19 exporter verbatim; only probe.* is exported.
        # Explicit template works with BusyBox mktemp; trap 0 is POSIX shell.
        exporter = Path(__file__).with_name('d2kfetch-export.sh').read_text()
        script = ('set -eu\nd=$(mktemp -d /tmp/d2k-site.XXXXXX)\n'
                  'trap \'rm -rf "$d"\' 0\ntrap \'exit 1\' HUP INT TERM\n'
                  'cd "$d"\ntouch cookies ' +
                  shlex.join(['probe.' + name for name in names]) + '\n' +
                  shlex.join(command) + ' >probe.writeout 2>probe.errors || :\n' +
                  # The exporter's $1 is its directory; a subshell keeps its
                  # positional parameters and set flags separate from cleanup.
                  '(set -- "$d"\n' + exporter + '\n)\n')
        bundle = self.run_script(script, 30 + 25 * len(requests))
        try:
            with tempfile.TemporaryDirectory(prefix='d2k-site-') as tmp:
                transfer = Path(tmp) / 'transfer.bundle'
                transfer.write_bytes(bundle)
                directory = Path(tmp) / 'files'
                directory.mkdir()
                probe_import.unpack(transfer, directory)
                if {p.name for p in directory.iterdir()} != {'probe.' + name for name in names}:
                    raise ValueError('incomplete CLI export file set')
                files = {name: (directory / ('probe.' + name)).read_bytes() for name in names}
            try:
                responses = parse_cli_output(files['writeout'].decode(), requests, files)
            except ValueError as exc:
                raise ValueError(str(exc) + '; raw write-out=' + repr(files['writeout'].decode(errors='replace'))) from exc
        except (OSError, KeyError, UnicodeError) as exc:
            raise ValueError('incomplete CLI export') from exc
        for meta, headers, body in responses:
            meta['stderr'] = files['errors'].decode(errors='replace')
            if self.body_dir is not None:
                digest = hashlib.sha256(body).hexdigest()
                with tempfile.NamedTemporaryFile(dir=self.body_dir, delete=False) as f:
                    f.write(body)
                    temporary = f.name
                os.replace(temporary, self.body_dir / digest)
                meta['body_file'] = 'site-bodies/' + digest
        return responses


def cli_visit(url, cli, references=None):
    class Discovery:
        def __init__(self):
            self.requests = []
        def request(self, current, referer=''):
            self.requests.append((current, referer))
            return cli.batch([(current, referer)])[0]
    discovery = Discovery()
    found = visit(url, discovery)
    groups = {}
    for request in discovery.requests:
        groups.setdefault(origin(request[0]), []).append(request)
    responses, batch_id = {}, 0
    history, batch_errors = [], {}
    def measure(requests):
        nonlocal batch_id
        try:
            batch = cli.batch(requests)
            if len(batch) != len(requests):
                raise ValueError('incomplete CLI batch')
        except (OSError, ValueError, EOFError, subprocess.TimeoutExpired) as exc:
            for current, _ in requests:
                responses.pop(current, None)
                batch_errors[current] = str(exc)
            return
        for (current, _), (meta, headers, body) in zip(requests, batch):
            meta = dict(meta, batch=batch_id, phase='measurement')
            responses[current] = meta, headers, body
            history.append(dict(meta, url=current, headers=headers,
                                sha256=hashlib.sha256(body).hexdigest()))
        batch_id += 1
    for requests in groups.values():
        measure(requests)
    class Expanded(Exception):
        pass
    class Measured:
        def request(self, current, referer=''):
            if current in batch_errors:
                raise ValueError(batch_errors[current])
            if current not in responses:
                requests = groups.setdefault(origin(current), [])
                requests.append((current, referer))
                # Replay the entire origin prefix, never combine a new process's
                # last transfer with the old process's document evidence.
                measure(requests)
                raise Expanded()
            return responses[current]
    while True:
        try:
            result = visit(url, Measured(), references)
            break
        except Expanded:
            continue
    result['measurement_history'] = history
    result['measurement_errors'] = batch_errors
    # Check every transfer BEFORE portal/error branches in the verdict walker.
    # A portal on a different connection is an observation, not this experiment's verdict.
    validate_reuse(result, responses)
    result['discovery'] = dict(found, phase='discovery', verdict_evidence=False)
    # Retain all measured bodies/write-outs even if a redirect/portal changed traversal.
    result['transfers'] = [dict(meta, url=current, headers=headers,
                               sha256=hashlib.sha256(body).hexdigest())
                           for current, (meta, headers, body) in responses.items()]
    return result


def validate_reuse(result, responses):
    """Check all scheduled transfers, even those skipped by changed traversal."""
    endpoints, errors = {}, []
    document_hosts = {urlsplit(r['url']).hostname for r in result['requests'] if r.get('document')}
    for current, (meta, headers, body) in responses.items():
        key = origin(current)
        endpoint = meta.get('ip'), meta.get('remote_port'), meta.get('local_port'), meta.get('batch')
        missing = meta['rc'] == 0 and (not meta.get('ip') or meta.get('local_port', 0) <= 0 or meta.get('remote_port', 0) <= 0)
        changed = key in endpoints and (meta.get('connects') != 0 or endpoint != endpoints[key])
        if missing or changed:
            reason = current + ': keep-alive не сохранён'
            if urlsplit(current).hostname in document_hosts:
                errors.append(reason)
            else:
                result['third_party'].append(dict(url=current, outcome='unknown', reason=reason))
        endpoints[key] = endpoint
    if errors:
        result['observed_failures'] = result['failures']
        result['failures'] = []
        result['unknown'].extend(errors)
        result['complete'] = False
        result['outcome'] = 'unknown'


def documents(path):
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        host, modes, route = line.split('|', 2)
        if route in ('/', '/ru/'):
            yield host, modes.split(','), route


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('--backend', choices=('cli', 'worker'), default='cli')
    parser.add_argument('--curl', default='/opt/d2k-tools/curl-impersonate')
    parser.add_argument('--worker')
    parser.add_argument('--library')
    parser.add_argument('--cacert', required=True)
    parser.add_argument('--router', action='store_true')
    parser.add_argument('--references', type=Path)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    if args.backend == 'worker' and (not args.worker or not args.library):
        parser.error('--backend worker requires --worker and --library')
    references = json.loads(args.references.read_text()) if args.references else {}
    if not isinstance(references, dict) or any(type(v) is not int or v < 0 for v in references.values()):
        parser.error('references must map URLs to non-negative decoded byte counts')
    lock = threading.Lock()

    def command_for(mode):
        profile = {'safari': 'safari260', 'h3': 'chrome150-h3'}.get(mode, 'chrome150')
        command = [args.worker, args.library, profile, args.cacert]
        if args.router:
            command = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                       '-p', '222', 'root@192.168.1.1', shlex.join(command)]
        return command

    if args.check_only:
        for mode in ('chrome', 'safari'):
            if args.backend == 'cli':
                CLI(args.curl, mode, args.cacert, args.router).check()
            else:
                Worker(command_for(mode)).close()
        return


    body_dir = args.run / "site-bodies"
    body_dir.mkdir(exist_ok=True)

    def collect(target):
        host, modes, route = target
        # Each TCP input retains its own identity. Chrome is the default site
        # visit; Safari remains separately visible, not a retry of Chrome.
        for mode in (['h3'] if 'h3' in modes else []) + [m for m in modes if m != 'h3']:
            worker = None
            try:
                url = ('http://' if mode == 'http' else 'https://') + host + route
                if args.backend == 'cli':
                    result = cli_visit(url, CLI(args.curl, mode, args.cacert, args.router, body_dir), references)
                else:
                    worker = Worker(command_for(mode), body_dir)
                    result = visit(url, worker, references)
                expected_versions = (30,) if mode == 'h3' else (2, 3)
                if any(r.get('rc') == 0 and r.get('http_version') not in expected_versions
                       for r in result.get('transfers', result['requests'])):
                    result['unknown'].append('не подтверждён запрошенный протокол ' + mode)
                    result['complete'] = False
                    result['outcome'] = 'unknown'
            except (OSError, ValueError, EOFError, subprocess.TimeoutExpired) as exc:
                result = dict(complete=False, failures=[], unknown=['ошибка прибора: '+str(exc)], resources=0, requests=[])
            finally:
                if worker:
                    worker.close()
            result.update(name=host, mode=mode, schema=1, backend=args.backend,
                          time=datetime.now().isoformat(), reference_file=str(args.references) if args.references else None,
                          transport='HTTP/3 only' if mode == 'h3' else 'TCP HTTP/1.1 or HTTP/2', after_h3='see preceding h3 visit and control.jsonl')
            with lock, (args.run / 'site.jsonl').open('a') as f:
                f.write(json.dumps(result, ensure_ascii=False)+'\n')

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(collect, documents(args.run / 'targets.txt')))


if __name__ == '__main__':
    main()
