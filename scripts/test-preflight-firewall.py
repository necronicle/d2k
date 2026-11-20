#!/usr/bin/env python3
"""Interpret emitted preflight rule contracts; no sockets or host firewall.

Rules are produced by the real S99 functions against the stateful shell double.
This checks queue/clear/NAT semantics and mask preservation. Kernel NAT tuple
allocation remains a field check; this interpreter cannot establish it.
"""
import re
import shlex
import sys
from pathlib import Path

root = Path(sys.argv[1])
BIT, RELEASE = 0x08000000, 0x04000000

def markmatch(value, expr):
    bits = expr.split('/')
    mask = int(bits[1], 0) if len(bits) == 2 else 0xffffffff
    return value & mask == int(bits[0], 0)

def ipt(chain, packet, depth=0):
    assert depth < 8, 'rule loop'
    for line in (root / 'iptables' / 'mangle' / chain).read_text().splitlines():
        a = shlex.split(line)
        match = True
        for opt, field in [('--mark', 'mark')]:
            if opt in a:
                idx = a.index(opt)
                value = packet['ct'] if a[idx-1] == 'connmark' else packet[field]
                match &= markmatch(value, a[idx+1])
        if '-p' in a:
            match &= a[a.index('-p')+1] == 'tcp'
        if '--ctdir' in a:
            match &= a[a.index('--ctdir')+1].lower() == packet['direction']
        # Fixed fixture: IPv4 unicast 10.0.0.2 -> 203.0.113.7:443,
        # packet 19, ACK only, no existing late watch, DNS or DNAT.
        if any(x in a for x in ['-s', '-d', '--dst-type', '--ctstate', '--u32', '--tcp-flags']):
            match = False
        for ports in ['--dports', '--sports']:
            if ports in a and a[a.index(ports)+1] != '0:65535':
                match = False
        if '--connbytes' in a:
            lo, hi = a[a.index('--connbytes')+1].split(':')
            match &= int(lo or 0) <= 19 <= int(hi or 999999)
        if not match:
            continue
        target = a[a.index('-j')+1]
        if target == 'CONNMARK':
            value, mask = map(lambda x:int(x,0), a[a.index('--set-xmark')+1].split('/'))
            packet['ct'] = packet['ct'] & ~mask ^ value
        elif target == 'MARK':
            value, mask = map(lambda x:int(x,0), a[a.index('--set-xmark')+1].split('/'))
            packet['mark'] = packet['mark'] & ~mask ^ value
        elif target in ['NFQUEUE', 'ACCEPT', 'DROP', 'RETURN']:
            return target
        else:
            result = ipt(target, packet, depth+1)
            if result != 'RETURN':
                return result
    return 'RETURN'

def nft(chain, packet, depth=0):
    text = (root / 'nft.rules').read_text()
    body = re.search(r'chain '+chain+r' \{\n(.*?)\n\s*\}', text, re.S)
    assert body, 'missing nft chain '+chain
    for line in body[1].splitlines():
        line = line.strip()
        # The fixture never matches address exclusions, DNS, FIN/RST, UDP.
        if not line or any(x in line for x in ['type ', 'ip saddr', 'ip daddr', 'ip6 ', 'broadcast', 'dnat', 'icmp', 'udp', 'tcp flags']):
            continue
        if 'th dport' in line or 'th sport' in line:
            if '{ 0-65535 }' not in line:
                continue
        if 'ct direction original' in line and packet['direction'] != 'original': continue
        if 'ct direction reply' in line and packet['direction'] != 'reply': continue
        if re.search(r'ct (original|reply) packets 1-8\b',line): continue
        m = re.search(r'meta mark (0x[0-9a-f]+) (ct|queue|return|jump|drop)',line)
        if m and packet['mark'] != int(m[1],16): continue
        m = re.search(r'(meta|ct) mark & (0x[0-9a-f]+) (==|!=) (0x[0-9a-f]+|0)',line)
        if m:
            eq = (packet['mark' if m[1]=='meta' else 'ct'] & int(m[2],16)) == int(m[4],0)
            if eq != (m[3]=='=='): continue
        if 'ct mark set ct mark |' in line: packet['ct'] |= int(line.split('|')[-1].split()[0],0)
        if 'ct mark set ct mark &' in line: packet['ct'] &= int(line.split('&')[-1].split()[0],0)
        m = re.fullmatch(r'meta mark set (0x[0-9a-f]+)', line)
        if m: packet['mark'] = int(m[1], 16)
        if 'jump ' in line:
            result=nft(line.split('jump ')[1].split()[0],packet,depth+1)
            if result != 'RETURN': return result
        if 'queue ' in line: return 'NFQUEUE'
        if line.endswith('return'): return 'RETURN'
        if line.endswith('accept'): return 'ACCEPT'
        if line.endswith('drop'): return 'DROP'
    return 'RETURN'

for backend, run, out, incoming in [('iptables',ipt,'D2K_OUT','D2K_IN'),('nft',nft,'out','in_rules')]:
    for chain,direction in [(out,'original'),(incoming,'reply')]:
        p={'mark':0,'ct':BIT|0x40,'direction':direction}
        assert run(chain,p)=='NFQUEUE', (backend,chain,'preflight_bit_queues_past_connbytes')
        for foreign in (RELEASE, RELEASE|0x1234, RELEASE|0x132, RELEASE|0x133):
            p={'mark':foreign,'ct':BIT|0x40,'direction':direction}
            assert run(chain,p)=='NFQUEUE' and p['ct']==BIT|0x40 and p['mark']==foreign, (backend,chain,'foreign mark must not enter preflight cleanup',p)
        p={'mark':RELEASE|0x32,'ct':BIT|0x40,'direction':direction}
        assert run(chain,p)=='ACCEPT' and p['ct']==0x40 and p['mark']==0x31, (backend,chain,'exact SYN release',p)
        p['mark']=0
        assert run(chain,p)!='NFQUEUE', (backend,chain,'next packet still queued')
    for mark,want in [(0x2d,False),(0x31,True)]:
        p={'mark':mark,'ct':0x40,'direction':'original'}
        assert run(out,p)=='RETURN'
        assert bool(p['ct']&BIT)==want, (backend,'fake_mark_does_not_set_bit',p)
    for mark,want in [(0x32,'ACCEPT'),(0x33,'DROP')]:
        p={'mark':mark,'ct':BIT|0x40,'direction':'original'}
        assert run(out,p)=='NFQUEUE', (backend,'cleanup request never queued')
        p['mark'] |= RELEASE # NF_REPEAT from the daemon
        assert run(out,p)==want and p['ct']==0x40, (backend,'repeat request',p)
        if mark==0x32: assert p['mark']==0x31, 'returned SYN must match NAT without setting watch again'
    print('PASS:',backend,'preflight_bit_queues_past_connbytes / preflight_bit_cleared_by_repeat_mark / fake_mark_does_not_set_bit')

nat=(root/'iptables'/'nat'/'POSTROUTING').read_text()
assert '-p tcp -m mark --mark 0x31 -j MASQUERADE' in nat, 'own_raw_syn_gets_nat iptables'
assert 'meta nfproto ipv4 meta l4proto tcp meta mark 0x31 masquerade' in (root/'nft.rules').read_text(), 'own_raw_syn_gets_nat nft'
print('PASS: own_raw_syn_gets_nat (rule contract, not kernel NAT allocation)')
