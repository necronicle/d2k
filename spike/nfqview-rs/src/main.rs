// nfqview-rs — та же работа, что делают версии на C и на Go, но на Rust.
// Инструмент замера этапа 0 d2k, НЕ продуктовый код.
//
// Зачем существует. Замер 05-09 разложил цену датапата: библиотека netlink
// стоила втрое, язык — примерно полтора раза по процессору и в двадцать раз по
// памяти (C 224 КиБ против Go 5 МБ). На целевом роутере запас есть, но продукт
// поедет и на коробки со 128 МБ, где эта разница решает. Вопрос: даёт ли Rust
// цифры C, не платя тем классом ошибок, который в C уже сработал.
//
// Чтобы сравнение было сравнением рантайма, а не подхода, всё повторяет C:
// один поток, вердикт до разбора, тот же разбор заголовка, предвыделенные
// буферы, те же выходные файлы. Внешних крейтов нет, кроме libc — это
// объявления системных вызовов, а не рантайм.
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::mem;
use std::os::raw::{c_int, c_void};
use std::time::Instant;

const NETLINK_NETFILTER: c_int = 12;
const NFNL_SUBSYS_QUEUE: u16 = 3;

const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;
const NFQNL_MSG_VERDICT_BATCH: u16 = 3;

const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;

const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_META: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;

const NFQA_CFG_F_FAIL_OPEN: u32 = 1;
const NFQA_CFG_F_GSO: u32 = 1 << 2;

// Значения из enum nfqnl_attr_type ядра. VERDICT_HDR = 2, а не 1: единицу
// занимает PACKET_HDR. На этой единице версия для Go молча копила пакеты.
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_PAYLOAD: u16 = 10;

const NF_ACCEPT: u32 = 1;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;

const NLMSG_HDRLEN: usize = 16;
const NLA_HDRLEN: usize = 4;
const NFGENMSG_LEN: usize = 4;

const RECV_BUF: usize = 256 * 1024;
const MAX_SEQ_SAMPLES: usize = 96;

const SOL_NETLINK: c_int = 270;
const NETLINK_NO_ENOBUFS: c_int = 5;

#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
struct FlowKey {
    proto: u8,
    is6: bool,
    local: [u8; 16],
    remote: [u8; 16],
    lport: u16,
    rport: u16,
}

#[derive(Default)]
struct FlowStat {
    first: f64,
    last: f64,
    last_in: f64,
    last_out: f64,
    out_pkts: u64,
    in_pkts: u64,
    out_bytes: u64,
    in_bytes: u64,
    saw_syn: bool,
    saw_synack: bool,
    rst_in: bool,
    rst_out: bool,
    fin_in: bool,
    fin_out: bool,
    client_hello: bool,
    server_hello: bool,
    last_in_fin: bool,
    last_in_rst: bool,
    in_base: u32,
    out_base: u32,
    in_set: bool,
    out_set: bool,
    in_max: u32,
    out_max: u32,
    in_samples: Vec<u32>,
    out_samples: Vec<u32>,
}

struct Opts {
    queue: u16,
    copylen: u32,
    qlen: u32,
    dur: f64,
    tick: f64,
    out: String,
    batch: bool,
    gso: bool,
    lan_addr: u32,
    lan_mask: u32,
}

fn parse_dur(s: &str) -> Option<f64> {
    let (num, mult) = if let Some(v) = s.strip_suffix("ms") {
        (v, 0.001)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1.0)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60.0)
    } else {
        (s, 1.0)
    };
    num.parse::<f64>().ok().map(|v| v * mult)
}

fn parse_lan(cidr: &str) -> Option<(u32, u32)> {
    let (ip, bits) = match cidr.split_once('/') {
        Some((a, b)) => (a, b.parse::<u32>().ok()?),
        None => (cidr, 24),
    };
    if bits > 32 {
        return None;
    }
    let mut addr: u32 = 0;
    let mut n = 0;
    for part in ip.split('.') {
        addr = (addr << 8) | part.parse::<u32>().ok()?;
        n += 1;
    }
    if n != 4 {
        return None;
    }
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some((addr & mask, mask))
}

// ------------------------------------------------------------------ netlink
struct Nl {
    fd: c_int,
    seq: u32,
    buf: [u8; 256],
}

impl Nl {
    fn open() -> std::io::Result<Nl> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Nl { fd, seq: 0, buf: [0u8; 256] })
    }

    fn setup(&self) {
        let one: c_int = 1;
        unsafe {
            if libc::setsockopt(
                self.fd,
                SOL_NETLINK,
                NETLINK_NO_ENOBUFS,
                &one as *const _ as *const c_void,
                mem::size_of::<c_int>() as libc::socklen_t,
            ) < 0
            {
                eprintln!("предупреждение: NO_ENOBUFS не установлен");
            }
            let rcv: c_int = 4 * 1024 * 1024;
            if libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcv as *const _ as *const c_void,
                mem::size_of::<c_int>() as libc::socklen_t,
            ) < 0
            {
                eprintln!("предупреждение: буфер чтения не увеличен");
            }
        }
    }

    fn bind(&self) -> std::io::Result<()> {
        let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::bind(
                self.fd,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_rcv_timeout_ms(&self, ms: i64) {
        let tv = libc::timeval { tv_sec: ms / 1000, tv_usec: ((ms % 1000) * 1000) as _ };
        unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }

    fn msg_init(&mut self, typ: u16, flags: u16, queue: u16) -> usize {
        self.buf[..NLMSG_HDRLEN + NFGENMSG_LEN].fill(0);
        let len = (NLMSG_HDRLEN + NFGENMSG_LEN) as u32;
        self.buf[0..4].copy_from_slice(&len.to_le_bytes());
        self.buf[4..6].copy_from_slice(&typ.to_le_bytes());
        self.buf[6..8].copy_from_slice(&flags.to_le_bytes());
        self.seq += 1;
        self.buf[8..12].copy_from_slice(&self.seq.to_le_bytes());
        self.buf[NLMSG_HDRLEN] = libc::AF_UNSPEC as u8;
        self.buf[NLMSG_HDRLEN + 1] = 0;
        self.buf[NLMSG_HDRLEN + 2..NLMSG_HDRLEN + 4].copy_from_slice(&queue.to_be_bytes());
        NLMSG_HDRLEN + NFGENMSG_LEN
    }

    fn put_attr(&mut self, at: usize, typ: u16, data: &[u8]) -> usize {
        let l = align4(at);
        let alen = (NLA_HDRLEN + data.len()) as u16;
        self.buf[l..l + 2].copy_from_slice(&alen.to_le_bytes());
        self.buf[l + 2..l + 4].copy_from_slice(&typ.to_le_bytes());
        self.buf[l + NLA_HDRLEN..l + NLA_HDRLEN + data.len()].copy_from_slice(data);
        let end = align4(l + NLA_HDRLEN + data.len());
        self.buf[0..4].copy_from_slice(&(end as u32).to_le_bytes());
        end
    }

    fn send(&self, len: usize) -> bool {
        let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::sendto(
                self.fd,
                self.buf.as_ptr() as *const c_void,
                len,
                0,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        rc >= 0
    }

    fn configure(&mut self, o: &Opts) -> bool {
        let mut cmd = [0u8; 4];
        cmd[0] = NFQNL_CFG_CMD_BIND;
        cmd[2..4].copy_from_slice(&(libc::AF_INET as u16).to_be_bytes());
        let l = self.msg_init(
            NFNL_SUBSYS_QUEUE << 8 | NFQNL_MSG_CONFIG,
            NLM_F_REQUEST | NLM_F_ACK,
            o.queue,
        );
        let l = self.put_attr(l, NFQA_CFG_CMD, &cmd);
        if !self.send(l) {
            eprintln!("bind очереди не удался");
            return false;
        }

        // struct nfqnl_msg_config_params упакована: be32 copy_range + u8 copy_mode.
        let mut params = [0u8; 5];
        params[0..4].copy_from_slice(&o.copylen.to_be_bytes());
        params[4] = if o.copylen > 0 { NFQNL_COPY_PACKET } else { NFQNL_COPY_META };
        let maxlen = o.qlen.to_be_bytes();
        let mut fl = NFQA_CFG_F_FAIL_OPEN;
        if o.gso {
            fl |= NFQA_CFG_F_GSO;
        }
        let flags = fl.to_be_bytes();
        let mask = (NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO).to_be_bytes();

        let l = self.msg_init(
            NFNL_SUBSYS_QUEUE << 8 | NFQNL_MSG_CONFIG,
            NLM_F_REQUEST | NLM_F_ACK,
            o.queue,
        );
        let l = self.put_attr(l, NFQA_CFG_PARAMS, &params);
        let l = self.put_attr(l, NFQA_CFG_QUEUE_MAXLEN, &maxlen);
        let l = self.put_attr(l, NFQA_CFG_FLAGS, &flags);
        let l = self.put_attr(l, NFQA_CFG_MASK, &mask);
        if !self.send(l) {
            eprintln!("параметры очереди не приняты");
            return false;
        }
        true
    }

    fn verdict(&mut self, id: u32, batch: bool, queue: u16) -> bool {
        let typ = NFNL_SUBSYS_QUEUE << 8
            | if batch { NFQNL_MSG_VERDICT_BATCH } else { NFQNL_MSG_VERDICT };
        let mut vh = [0u8; 8];
        vh[0..4].copy_from_slice(&NF_ACCEPT.to_be_bytes());
        vh[4..8].copy_from_slice(&id.to_be_bytes());
        let l = self.msg_init(typ, NLM_F_REQUEST, queue);
        let l = self.put_attr(l, NFQA_VERDICT_HDR, &vh);
        self.send(l)
    }
}

// ------------------------------------------------------------------ счётчики
#[derive(Default, Clone, Copy)]
struct QStat {
    depth: u64,
    copy_mode: u64,
    copy_range: u64,
    dropped: u64,
    user_dropped: u64,
    id_seq: u64,
}

// Порядок полей из nfnetlink_queue.c (seq_show): queue_num, peer_portid,
// queue_total, copy_mode, copy_range, queue_dropped, queue_user_dropped,
// id_sequence, 1. queue_total — текущая глубина, не накопленный счётчик.
fn read_qstat(queue: u16) -> QStat {
    let mut s = QStat::default();
    let Ok(txt) = fs::read_to_string("/proc/net/netfilter/nfnetlink_queue") else {
        return s;
    };
    for line in txt.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        if f[0].parse::<u16>() != Ok(queue) {
            continue;
        }
        let g = |i: usize| f[i].parse::<u64>().unwrap_or(0);
        s.depth = g(2);
        s.copy_mode = g(3);
        s.copy_range = g(4);
        s.dropped = g(5);
        s.user_dropped = g(6);
        s.id_seq = g(7);
        return s;
    }
    s
}

fn read_self_cpu() -> f64 {
    let Ok(txt) = fs::read_to_string("/proc/self/stat") else {
        return 0.0;
    };
    let Some(pos) = txt.rfind(')') else { return 0.0 };
    let f: Vec<&str> = txt[pos + 1..].split_whitespace().collect();
    if f.len() < 13 {
        return 0.0;
    }
    let ut: u64 = f[11].parse().unwrap_or(0);
    let st: u64 = f[12].parse().unwrap_or(0);
    (ut + st) as f64 / 100.0
}

fn read_self_rss() -> u64 {
    let Ok(txt) = fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let f: Vec<&str> = txt.split_whitespace().collect();
    if f.len() < 2 {
        return 0;
    }
    let pages: u64 = f[1].parse().unwrap_or(0);
    pages * unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64
}

fn ip_str(ip: &[u8; 16], is6: bool) -> String {
    if is6 {
        let mut parts = Vec::with_capacity(8);
        for i in 0..8 {
            parts.push(format!("{:x}", u16::from_be_bytes([ip[i * 2], ip[i * 2 + 1]])));
        }
        parts.join(":")
    } else {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }
}

// -------------------------------------------------------------------- разбор
struct Stats {
    pkts: u64,
    bytes: u64,
    parse_fail: u64,
    verdict_fail: u64,
    recv_err: u64,
}

fn account(
    p: &[u8],
    t: f64,
    o: &Opts,
    flows: &mut HashMap<FlowKey, FlowStat>,
    st: &mut Stats,
) {
    if p.len() < 20 {
        st.parse_fail += 1;
        return;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    let proto;
    let total: u64;
    let mut l4: &[u8] = &[];
    let is6;

    match p[0] >> 4 {
        4 => {
            let ihl = (p[0] & 0x0f) as usize * 4;
            if ihl < 20 || p.len() < ihl {
                st.parse_fail += 1;
                return;
            }
            is6 = false;
            total = u16::from_be_bytes([p[2], p[3]]) as u64;
            proto = p[9];
            src[..4].copy_from_slice(&p[12..16]);
            dst[..4].copy_from_slice(&p[16..20]);
            if u16::from_be_bytes([p[6], p[7]]) & 0x1fff == 0 {
                l4 = &p[ihl..];
            }
        }
        6 => {
            if p.len() < 40 {
                st.parse_fail += 1;
                return;
            }
            is6 = true;
            total = u16::from_be_bytes([p[4], p[5]]) as u64 + 40;
            proto = p[6];
            src.copy_from_slice(&p[8..24]);
            dst.copy_from_slice(&p[24..40]);
            l4 = &p[40..];
        }
        _ => {
            st.parse_fail += 1;
            return;
        }
    }

    let mut outbound = true;
    if !is6 {
        let s = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        let d = u32::from_be_bytes([dst[0], dst[1], dst[2], dst[3]]);
        if s & o.lan_mask == o.lan_addr {
            outbound = true;
        } else if d & o.lan_mask == o.lan_addr {
            outbound = false;
        }
    }

    let (mut sport, mut dport) = (0u16, 0u16);
    if (proto == 6 || proto == 17) && l4.len() >= 4 {
        sport = u16::from_be_bytes([l4[0], l4[1]]);
        dport = u16::from_be_bytes([l4[2], l4[3]]);
    }

    let key = if outbound {
        FlowKey { proto, is6, local: src, remote: dst, lport: sport, rport: dport }
    } else {
        FlowKey { proto, is6, local: dst, remote: src, lport: dport, rport: sport }
    };

    let f = flows.entry(key).or_insert_with(|| FlowStat { first: t, ..Default::default() });
    f.last = t;

    let (mut fin, mut syn, mut rst, mut ack, mut ch, mut sh) = (false, false, false, false, false, false);
    let mut seq = 0u32;
    if proto == 6 && l4.len() >= 20 {
        seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
        let fl = l4[13];
        fin = fl & 0x01 != 0;
        syn = fl & 0x02 != 0;
        rst = fl & 0x04 != 0;
        ack = fl & 0x10 != 0;
        let doff = (l4[12] >> 4) as usize * 4;
        if doff >= 20 && l4.len() > doff {
            let pay = &l4[doff..];
            if pay.len() >= 6 && pay[0] == 0x16 && pay[1] == 0x03 {
                ch = pay[5] == 0x01;
                sh = pay[5] == 0x02;
            }
        }
    }

    if outbound {
        f.out_pkts += 1;
        f.out_bytes += total;
        f.last_out = t;
        if syn && !ack {
            f.saw_syn = true;
        }
        f.rst_out |= rst;
        f.fin_out |= fin;
        f.client_hello |= ch;
        if proto == 6 {
            if !f.out_set {
                f.out_base = seq;
                f.out_set = true;
            }
            let d = seq.wrapping_sub(f.out_base);
            if d < 1 << 31 {
                if d > f.out_max {
                    f.out_max = d;
                }
                if f.out_samples.len() < MAX_SEQ_SAMPLES {
                    f.out_samples.push(d);
                }
            }
        }
    } else {
        f.in_pkts += 1;
        f.in_bytes += total;
        f.last_in = t;
        if syn && ack {
            f.saw_synack = true;
        }
        f.rst_in |= rst;
        f.fin_in |= fin;
        f.server_hello |= sh;
        f.last_in_fin = fin;
        f.last_in_rst = rst;
        if proto == 6 {
            if !f.in_set {
                f.in_base = seq;
                f.in_set = true;
            }
            let d = seq.wrapping_sub(f.in_base);
            if d < 1 << 31 {
                if d > f.in_max {
                    f.in_max = d;
                }
                if f.in_samples.len() < MAX_SEQ_SAMPLES {
                    f.in_samples.push(d);
                }
            }
        }
    }
}

fn b(v: bool) -> u8 {
    if v {
        b'1'
    } else {
        b'0'
    }
}

fn write_outputs(o: &Opts, flows: &HashMap<FlowKey, FlowStat>, s: &Stats, elapsed: f64, cpu: f64, q0: QStat, ql: QStat) {
    let summary = format!(
        "{{\n  \"impl\": \"rust\",\n  \"queue\": {},\n  \"copylen\": {},\n  \"qlen\": {},\n  \"gso\": {},\n  \"batch_verdict\": {},\n  \"duration_s\": {:.3},\n  \"packets\": {},\n  \"packets_per_s\": {:.1},\n  \"bytes_copied\": {},\n  \"flows\": {},\n  \"parse_fail\": {},\n  \"verdict_fail\": {},\n  \"recv_errors\": {},\n  \"cpu_seconds\": {:.2},\n  \"cpu_percent\": {:.2},\n  \"rss_kib\": {},\n  \"kernel_queue_start\": {{\"queue_depth_now\": {}, \"copy_mode\": {}, \"copy_range\": {}, \"queue_dropped\": {}, \"user_dropped\": {}, \"id_sequence\": {}}},\n  \"kernel_queue_last\": {{\"queue_depth_now\": {}, \"copy_mode\": {}, \"copy_range\": {}, \"queue_dropped\": {}, \"user_dropped\": {}, \"id_sequence\": {}}}\n}}\n",
        o.queue, o.copylen, o.qlen, o.gso, o.batch, elapsed, s.pkts,
        s.pkts as f64 / elapsed.max(0.001), s.bytes, flows.len(),
        s.parse_fail, s.verdict_fail, s.recv_err, cpu, 100.0 * cpu / elapsed.max(0.001),
        read_self_rss() / 1024,
        q0.depth, q0.copy_mode, q0.copy_range, q0.dropped, q0.user_dropped, q0.id_seq,
        ql.depth, ql.copy_mode, ql.copy_range, ql.dropped, ql.user_dropped, ql.id_seq
    );
    let _ = fs::write(format!("{}.summary.json", o.out), &summary);
    print!("{summary}");

    let mut t = String::with_capacity(64 * 1024);
    t.push_str("proto\tlocal\tlport\tremote\trport\tout_pkts\tin_pkts\tout_bytes\tin_bytes\tseen_out_span\tseen_in_span\tsyn\tsynack\trst_in\trst_out\tfin_in\tfin_out\tclient_hello\tserver_hello\tlast_in_fin\tlast_in_rst\tlife_s\tlast_in_after_s\tlast_out_after_s\n");
    for (k, f) in flows {
        let li = if f.last_in > 0.0 { f.last_in - f.first } else { -1.0 };
        let lo = if f.last_out > 0.0 { f.last_out - f.first } else { -1.0 };
        let _ = writeln!(
            t,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.2}\t{:.2}\t{:.2}",
            k.proto, ip_str(&k.local, k.is6), k.lport, ip_str(&k.remote, k.is6), k.rport,
            f.out_pkts, f.in_pkts, f.out_bytes, f.in_bytes, f.out_max, f.in_max,
            b(f.saw_syn) as char, b(f.saw_synack) as char, b(f.rst_in) as char,
            b(f.rst_out) as char, b(f.fin_in) as char, b(f.fin_out) as char,
            b(f.client_hello) as char, b(f.server_hello) as char,
            b(f.last_in_fin) as char, b(f.last_in_rst) as char,
            f.last - f.first, li, lo
        );
    }
    let _ = fs::write(format!("{}.flows.tsv", o.out), t);

    let mut q = String::with_capacity(32 * 1024);
    q.push_str("dir\tlocal\tlport\tremote\trport\tspan\tn_seen\toffsets\n");
    for (k, f) in flows {
        if k.proto != 6 {
            continue;
        }
        for (dir, span, samples) in
            [("in", f.in_max, &f.in_samples), ("out", f.out_max, &f.out_samples)]
        {
            if samples.is_empty() {
                continue;
            }
            let joined: Vec<String> = samples.iter().map(|v| v.to_string()).collect();
            let _ = writeln!(
                q,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                dir, ip_str(&k.local, k.is6), k.lport, ip_str(&k.remote, k.is6), k.rport,
                span, samples.len(), joined.join(",")
            );
        }
    }
    let _ = fs::write(format!("{}.seq.tsv", o.out), q);
}

fn main() {
    let mut o = Opts {
        queue: 200,
        copylen: 128,
        qlen: 8192,
        dur: 60.0,
        tick: 10.0,
        out: "/tmp/nfqview-rs".into(),
        batch: false,
        gso: false,
        lan_addr: 0,
        lan_mask: 0,
    };
    let (mut la, mut lm) = parse_lan("192.168.1.0/24").unwrap();

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let need = |i: usize| -> &str {
            if i + 1 >= args.len() {
                eprintln!("нет значения у {}", args[i]);
                std::process::exit(2);
            }
            &args[i + 1]
        };
        match args[i].as_str() {
            "-q" => { o.queue = need(i).parse().unwrap_or(200); i += 1; }
            "-copylen" => { o.copylen = need(i).parse().unwrap_or(128); i += 1; }
            "-qlen" => { o.qlen = need(i).parse().unwrap_or(8192); i += 1; }
            "-dur" => { o.dur = parse_dur(need(i)).unwrap_or(60.0); i += 1; }
            "-tick" => { o.tick = parse_dur(need(i)).unwrap_or(10.0); i += 1; }
            "-out" => { o.out = need(i).to_string(); i += 1; }
            "-lan" => {
                match parse_lan(need(i)) {
                    Some((a, m)) => { la = a; lm = m; }
                    None => { eprintln!("плохая подсеть -lan"); std::process::exit(2); }
                }
                i += 1;
            }
            "-batch" => o.batch = true,
            "-gso" => o.gso = true,
            _ => {
                eprintln!("nfqview (Rust) — измеритель датапата\n  -q -copylen -qlen -dur -tick -lan -out -batch -gso");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    o.lan_addr = la;
    o.lan_mask = lm;

    let mut nl = match Nl::open() {
        Ok(n) => n,
        Err(e) => { eprintln!("socket netlink: {e}"); std::process::exit(1); }
    };
    nl.setup();
    if let Err(e) = nl.bind() {
        eprintln!("bind: {e}");
        std::process::exit(1);
    }
    if !nl.configure(&o) {
        std::process::exit(1);
    }
    // 20 мс, а не 200: в групповом режиме этим таймаутом добирается остаток
    // пачки, и при 200 мс хвост каждой группы застревает на пятую долю секунды.
    nl.set_rcv_timeout_ms(20);

    let mut flows: HashMap<FlowKey, FlowStat> = HashMap::with_capacity(1024);
    let mut st = Stats { pkts: 0, bytes: 0, parse_fail: 0, verdict_fail: 0, recv_err: 0 };
    let mut buf = vec![0u8; RECV_BUF];

    let q0 = read_qstat(o.queue);
    let mut qlast = q0;
    let started = Instant::now();
    let cpu0 = read_self_cpu();
    let mut next_tick = o.tick;

    let mut batch_id = 0u32;
    let mut batch_n = 0usize;
    const BATCH_SIZE: usize = 16;

    loop {
        let el = started.elapsed().as_secs_f64();
        if el >= o.dur {
            break;
        }

        let n = unsafe { libc::recv(nl.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => {
                    if o.batch && batch_n > 0 {
                        nl.verdict(batch_id, true, o.queue);
                        batch_n = 0;
                    }
                }
                _ => st.recv_err += 1,
            }
        } else {
            let n = n as usize;
            let t = started.elapsed().as_secs_f64();
            // Границы считаются явно, без вычитания выровненной длины из
            // остатка: у последнего атрибута хвоста выравнивания может не быть.
            let (mut pos, mut left) = (0usize, n);
            while left >= NLMSG_HDRLEN {
                let mlen = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
                let mtype = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]);
                if mlen < NLMSG_HDRLEN || mlen > left {
                    break;
                }
                if mtype & 0xff == NFQNL_MSG_PACKET && mtype != 2 && mtype != 3 {
                    let mut id: Option<u32> = None;
                    let mut pay: Option<(usize, usize)> = None;
                    let mut ap = pos + NLMSG_HDRLEN + NFGENMSG_LEN;
                    let mut aleft = mlen - NLMSG_HDRLEN - NFGENMSG_LEN;
                    while aleft >= NLA_HDRLEN {
                        let alen = u16::from_le_bytes([buf[ap], buf[ap + 1]]) as usize;
                        let atype = u16::from_le_bytes([buf[ap + 2], buf[ap + 3]]) & 0x3fff;
                        if alen < NLA_HDRLEN || alen > aleft {
                            break;
                        }
                        if atype == NFQA_PACKET_HDR && alen - NLA_HDRLEN >= 7 {
                            id = Some(u32::from_be_bytes([
                                buf[ap + NLA_HDRLEN], buf[ap + NLA_HDRLEN + 1],
                                buf[ap + NLA_HDRLEN + 2], buf[ap + NLA_HDRLEN + 3],
                            ]));
                        } else if atype == NFQA_PAYLOAD {
                            pay = Some((ap + NLA_HDRLEN, alen - NLA_HDRLEN));
                        }
                        let step = align4(alen);
                        if step > aleft {
                            break;
                        }
                        ap += step;
                        aleft -= step;
                    }

                    if let Some(id) = id {
                        // Вердикт первым делом, как в версиях на C и Go.
                        let ok = if o.batch {
                            if id > batch_id {
                                batch_id = id;
                            }
                            batch_n += 1;
                            if batch_n >= BATCH_SIZE {
                                batch_n = 0;
                                nl.verdict(batch_id, true, o.queue)
                            } else {
                                true
                            }
                        } else {
                            nl.verdict(id, false, o.queue)
                        };
                        if !ok {
                            st.verdict_fail += 1;
                        }
                        st.pkts += 1;
                        if let Some((off, len)) = pay {
                            st.bytes += len as u64;
                            let (head, tail) = buf.split_at(off);
                            let _ = head;
                            account(&tail[..len], t, &o, &mut flows, &mut st);
                        }
                    }
                }
                let step = align4(mlen);
                if step > left {
                    break;
                }
                pos += step;
                left -= step;
            }
        }

        let el = started.elapsed().as_secs_f64();
        if el >= next_tick {
            let q = read_qstat(o.queue);
            if q.id_seq != 0 || q.dropped != 0 || q.user_dropped != 0 {
                qlast = q;
            }
            let cpu = read_self_cpu() - cpu0;
            println!(
                "[{:4.0}с] пакетов={} ({:.0}/с) байт={} потоков={} | ядро: выдано={} глубина={} дроп-очереди={} дроп-юзера={} | cpu={:.1}% rss={}КиБ",
                el, st.pkts, st.pkts as f64 / el, st.bytes, flows.len(),
                q.id_seq, q.depth, q.dropped, q.user_dropped, 100.0 * cpu / el, read_self_rss() / 1024
            );
            let _ = std::io::stdout().flush();
            next_tick = el + o.tick;
        }
    }

    if o.batch && batch_n > 0 {
        nl.verdict(batch_id, true, o.queue);
    }

    let elapsed = started.elapsed().as_secs_f64();
    let cpu = read_self_cpu() - cpu0;
    let q = read_qstat(o.queue);
    if q.id_seq != 0 || q.dropped != 0 || q.user_dropped != 0 {
        qlast = q;
    }
    write_outputs(&o, &flows, &st, elapsed, cpu, q0, qlast);
    eprintln!("потоки записаны: {}.flows.tsv ({})", o.out, flows.len());
}
