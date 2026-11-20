"""Socket-free fake executable. Never imports a network module."""
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if '--version' in args:
    print('curl 8.22.0-IMPERSONATE (offline fake)')
    raise SystemExit(0)
groups = [[]]
for arg in args:
    if arg == '--next':
        groups.append([])
    else:
        groups[-1].append(arg)
with open(os.environ['FAKE_CLI_CALLS'], 'a') as f:
    f.write(json.dumps(groups)+'\n')
fixture = Path(__file__).parent
rows = (fixture / 'portal.tsv').read_text().splitlines()
for i, group in enumerate(groups):
    def option(name):
        return group[group.index(name)+1]
    url = option('--url')
    main = url.endswith('/')
    body = b'<link rel="stylesheet" href="/dynamic.css">' if main else b'/*ok*/'
    header = b'HTTP/1.1 200 OK\r\nContent-Type: '+(b'text/html' if main else b'text/css')+b'\r\n\r\n'
    fields = rows[0 if main else 1].split('\t')
    fields[0] = url
    if '--http3-only' in group:
        body, header = b'', b''
        fields[1:9] = ['000', '0', '0', '0', '', '0', '7', '0']
    elif not main and len(groups) > 1 and os.environ.get('FAKE_CLI_PORTAL', '1') == '1':
        body = b''
        header = b'HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/\r\n\r\n'
    else:
        fields[1], fields[2], fields[3] = '200', str(len(body)), str(int(i == 0))
    Path(option('--output')).write_bytes(body)
    Path(option('--dump-header')).write_bytes(header)
    print('\t'.join(fields))
