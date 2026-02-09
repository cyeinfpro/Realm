from __future__ import annotations

from collections import OrderedDict, deque
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
import weakref
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if s in ('1', 'true', 'yes', 'y', 'on'):
        return True
    if s in ('0', 'false', 'no', 'n', 'off'):
        return False
    return bool(default)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(str(os.getenv(name, str(default))).strip() or default)
    except Exception:
        v = int(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return int(v)


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float(str(os.getenv(name, str(default))).strip() or default)
    except Exception:
        v = float(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return float(v)


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v or '').strip().lower() in ('1', 'true', 'yes', 'y', 'on')

# -----------------------------
# Intranet tunnel (A<->B)
# -----------------------------
# Goals:
# - Deterministic handshakes (HMAC) to avoid "connected but not really" black boxes
# - Ping/pong heartbeats + stale-session cleanup to avoid zombie sessions
# - Rich runtime state for panel "握手检查"
# - Keep deps minimal (no cryptography)

INTRA_DIR = Path(os.getenv('REALM_AGENT_INTRANET_DIR', '/etc/realm-agent/intranet'))
SERVER_KEY = INTRA_DIR / 'server.key'
SERVER_CERT = INTRA_DIR / 'server.crt'
SERVER_PEM = INTRA_DIR / 'server.pem'
LOG_FILE = INTRA_DIR / 'intranet.log'

DEFAULT_TUNNEL_PORT = int(os.getenv('REALM_INTRANET_TUNNEL_PORT', '18443'))
OPEN_TIMEOUT = float(os.getenv('REALM_INTRANET_OPEN_TIMEOUT', '8.0'))
TCP_BACKLOG = int(os.getenv('REALM_INTRANET_TCP_BACKLOG', '256'))
UDP_SESSION_TTL = float(os.getenv('REALM_INTRANET_UDP_TTL', '60.0'))
MAX_FRAME = int(os.getenv('REALM_INTRANET_MAX_UDP_FRAME', '65535'))
FIRST_PACKET_TIMEOUT = _env_float('REALM_INTRANET_FIRST_PACKET_TIMEOUT', 5.0, 1.0, 30.0)
FIRST_PACKET_MAX = _env_int('REALM_INTRANET_FIRST_PACKET_MAX', 65536, 256, 1024 * 1024)
MAX_ACCEPT_WORKERS = _env_int('REALM_INTRANET_MAX_ACCEPT_WORKERS', 512, 8, 8192)
MAX_ACTIVE_FLOWS = _env_int('REALM_INTRANET_MAX_ACTIVE_FLOWS', 1024, 8, 65535)
MAX_CLIENT_OPEN_WORKERS = _env_int('REALM_INTRANET_MAX_CLIENT_OPEN_WORKERS', 512, 8, 8192)
NONCE_TTL_SEC = _env_int('REALM_INTRANET_NONCE_TTL_SEC', 600, 60, 3600)
NONCE_LRU_PER_TOKEN = _env_int('REALM_INTRANET_NONCE_LRU_PER_TOKEN', 2048, 64, 65535)
LOG_ROTATE_BYTES = _env_int('REALM_INTRANET_LOG_ROTATE_BYTES', 10 * 1024 * 1024, 0, 1024 * 1024 * 1024)
LOG_ROTATE_KEEP = _env_int('REALM_INTRANET_LOG_ROTATE_KEEP', 5, 1, 20)

# Handshake/heartbeat
INTRANET_MAGIC = os.getenv('REALM_INTRANET_MAGIC', 'realm-intranet')
INTRANET_PROTO_VER = int(os.getenv('REALM_INTRANET_PROTO_VER', '3'))
HELLO_TIMEOUT = float(os.getenv('REALM_INTRANET_HELLO_TIMEOUT', '6.0'))
PING_INTERVAL = float(os.getenv('REALM_INTRANET_PING_INTERVAL', '15.0'))
PONG_TIMEOUT = float(os.getenv('REALM_INTRANET_PONG_TIMEOUT', '45.0'))
SESSION_STALE = float(os.getenv('REALM_INTRANET_SESSION_STALE', '65.0'))
TS_SKEW_SEC = int(os.getenv('REALM_INTRANET_TS_SKEW_SEC', '300'))

# Keep TLS as secure default.
# Set REALM_INTRANET_ALLOW_PLAINTEXT=1 only for break-glass compatibility.
ALLOW_PLAINTEXT_FALLBACK = _env_bool('REALM_INTRANET_ALLOW_PLAINTEXT', False)
REQUIRE_TLS_SERVER = _env_bool('REALM_INTRANET_REQUIRE_TLS', True)

# Log can be disabled in extreme IO constrained env
ENABLE_LOG = _env_bool('REALM_INTRANET_LOG', True)


def _now() -> float:
    return time.time()


def _now_ms() -> int:
    return int(_now() * 1000)


_LOG_LOCK = threading.Lock()


def _rotate_logs_locked() -> None:
    if LOG_ROTATE_BYTES <= 0:
        return
    try:
        if (not LOG_FILE.exists()) or LOG_FILE.stat().st_size < LOG_ROTATE_BYTES:
            return
    except Exception:
        return

    try:
        oldest = INTRA_DIR / f'{LOG_FILE.name}.{LOG_ROTATE_KEEP}'
        if oldest.exists():
            oldest.unlink()
    except Exception:
        pass

    for i in range(LOG_ROTATE_KEEP - 1, 0, -1):
        src = INTRA_DIR / f'{LOG_FILE.name}.{i}'
        dst = INTRA_DIR / f'{LOG_FILE.name}.{i + 1}'
        try:
            if src.exists():
                src.replace(dst)
        except Exception:
            pass

    try:
        LOG_FILE.replace(INTRA_DIR / f'{LOG_FILE.name}.1')
    except Exception:
        pass


def _log(event: str, **fields: Any) -> None:
    if not ENABLE_LOG:
        return
    try:
        INTRA_DIR.mkdir(parents=True, exist_ok=True)
        payload = {'ts': int(_now()), 'event': event}
        payload.update(fields)
        line = (json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
        with _LOG_LOCK:
            _rotate_logs_locked()
            with open(LOG_FILE, 'ab', buffering=0) as f:
                f.write(line)
    except Exception:
        pass


def _mask_token(t: str) -> str:
    t = str(t or '')
    if len(t) <= 10:
        return t
    return t[:4] + '…' + t[-4:]


def _json_line(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def _recv_line(sock: Any, max_len: int = 65536) -> str:
    """socket/SSLSocket compatible line reader (buffered).

    The old implementation used recv(1) in a loop, which is extremely slow.
    We keep a per-socket buffer so we can recv in chunks while still preserving
    bytes after the newline for the next call.

    IMPORTANT: callers rely on socket.timeout being raised when there is no
    incoming data (they set short timeouts to periodically wake up), so we
    preserve that behaviour.
    """
    with _RECV_LINE_BUFS_LOCK:
        buf = _RECV_LINE_BUFS.get(sock)
        if buf is None:
            buf = bytearray()
            _RECV_LINE_BUFS[sock] = buf

    while True:
        nl = buf.find(b'\n')
        if nl != -1:
            line = bytes(buf[:nl])
            del buf[: nl + 1]
            return line.decode('utf-8', errors='ignore').strip()

        if len(buf) >= max_len:
            line = bytes(buf[:max_len])
            del buf[:max_len]
            return line.decode('utf-8', errors='ignore').strip()

        try:
            chunk = sock.recv(min(4096, max_len - len(buf)))
        except socket.timeout:
            # IMPORTANT: allow callers that use settimeout() to distinguish
            # between "no data yet" (timeout) and a real disconnect.
            raise
        except Exception:
            break

        if not chunk:
            break

        buf.extend(chunk)

    # EOF / error: flush buffer and drop state
    with _RECV_LINE_BUFS_LOCK:
        _RECV_LINE_BUFS.pop(sock, None)

    return buf.decode('utf-8', errors='ignore').strip()


def _safe_close(s: Any) -> None:
    try:
        s.close()
    except Exception:
        pass


def shutil_which(cmd: str) -> Optional[str]:
    # local minimal which, avoid importing shutil at module import time in agent
    try:
        import shutil
        return shutil.which(cmd)
    except Exception:
        return None


def ensure_server_cert() -> None:
    """Ensure we have a self-signed cert for intranet tunnel server.

    We intentionally avoid extra Python dependencies (cryptography).
    If openssl is unavailable and no pre-provisioned cert/key exist, TLS cannot be enabled.
    """
    try:
        INTRA_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return

    if SERVER_CERT.exists() and SERVER_KEY.exists():
        return

    openssl = shutil_which('openssl')
    if not openssl:
        return

    try:
        cmd = [
            openssl,
            'req',
            '-x509',
            '-nodes',
            '-newkey',
            'rsa:2048',
            '-keyout',
            str(SERVER_KEY),
            '-out',
            str(SERVER_CERT),
            '-days',
            '3650',
            '-subj',
            '/CN=realm-intranet',
        ]
        subprocess.run(cmd, capture_output=True, text=True, check=False)
        if SERVER_KEY.exists() and SERVER_CERT.exists():
            pem = (SERVER_KEY.read_text(encoding='utf-8') + '\n' + SERVER_CERT.read_text(encoding='utf-8')).strip() + '\n'
            SERVER_PEM.write_text(pem, encoding='utf-8')
    except Exception:
        return


def load_server_cert_pem() -> str:
    try:
        ensure_server_cert()
        return SERVER_CERT.read_text(encoding='utf-8')
    except Exception:
        return ''


def server_tls_ready() -> bool:
    try:
        return _mk_server_ssl_context() is not None
    except Exception:
        return False


def _mk_server_ssl_context() -> Optional[ssl.SSLContext]:
    ensure_server_cert()
    if not SERVER_CERT.exists() or not SERVER_KEY.exists():
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))
        return ctx
    except Exception:
        return None


# Per-socket buffers for _recv_line (avoid 1-byte recv loop)
_RECV_LINE_BUFS = weakref.WeakKeyDictionary()  # sock -> bytearray
_RECV_LINE_BUFS_LOCK = threading.Lock()


def _mk_client_ssl_context(server_cert_pem: Optional[str], require_verify: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.check_hostname = False
    if server_cert_pem:
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_verify_locations(cadata=server_cert_pem)
        except Exception as exc:
            raise ValueError(f'invalid_server_cert_pem: {exc}') from exc
    else:
        if require_verify:
            raise ValueError('server_cert_missing')
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _set_keepalive(sock_obj: socket.socket) -> None:
    try:
        sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        return
    # Best effort for Linux. Ignore failures.
    try:
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass


def _hmac_sig(token: str, node_id: int, ts: int, nonce: str) -> str:
    msg = f"{INTRANET_MAGIC}|{INTRANET_PROTO_VER}|{node_id}|{ts}|{nonce}".encode('utf-8')
    return hmac.new(token.encode('utf-8'), msg, hashlib.sha256).hexdigest()


def _parse_nonneg_int(v: Any) -> int:
    try:
        iv = int(v)
    except Exception:
        return 0
    return iv if iv > 0 else 0


def _normalize_str_list(raw: Any, max_items: int = 64, item_max_len: int = 128) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    rows: List[Any]
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, str):
        rows = [x for x in str(raw).replace(',', '\n').splitlines()]
    else:
        rows = []
    for row in rows:
        s = str(row or '').strip()
        if not s:
            continue
        if len(s) > item_max_len:
            s = s[:item_max_len]
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= max_items:
            break
    return out


def _parse_hour_range(txt: str) -> Optional[Tuple[int, int]]:
    s = str(txt or '').strip()
    if not s:
        return None
    if '-' not in s:
        return None
    left, right = s.split('-', 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        return None

    def _to_minute(part: str) -> Optional[int]:
        if ':' not in part:
            return None
        hh, mm = part.split(':', 1)
        if (not hh.isdigit()) or (not mm.isdigit()):
            return None
        h = int(hh)
        m = int(mm)
        if h < 0 or h > 23 or m < 0 or m > 59:
            return None
        return h * 60 + m

    lmin = _to_minute(left)
    rmin = _to_minute(right)
    if lmin is None or rmin is None:
        return None
    return lmin, rmin


def _compile_hour_windows(raw: Any) -> List[Tuple[int, int]]:
    rows = _normalize_str_list(raw, max_items=16, item_max_len=16)
    out: List[Tuple[int, int]] = []
    for row in rows:
        it = _parse_hour_range(row)
        if it is not None:
            out.append(it)
    return out


def _match_hour_windows(windows: List[Tuple[int, int]], now_ts: Optional[float] = None) -> bool:
    if not windows:
        return True
    ts = float(now_ts) if now_ts is not None else _now()
    lt = time.localtime(ts)
    minute = int(lt.tm_hour) * 60 + int(lt.tm_min)
    for left, right in windows:
        if left <= right:
            if left <= minute <= right:
                return True
        else:
            # Cross-day window, e.g. 23:00-06:00
            if minute >= left or minute <= right:
                return True
    return False


def _compile_ip_networks(raw: Any) -> List[Any]:
    rows = _normalize_str_list(raw, max_items=128, item_max_len=64)
    out: List[Any] = []
    for row in rows:
        txt = row
        if '/' not in txt:
            # host ip -> strict /32 or /128 network
            if ':' in txt:
                txt = f'{txt}/128'
            else:
                txt = f'{txt}/32'
        try:
            out.append(ipaddress.ip_network(txt, strict=False))
        except Exception:
            continue
    return out


def _ip_acl_allowed(addr: str, allow_nets: List[Any], deny_nets: List[Any]) -> bool:
    ip_txt = str(addr or '').strip()
    if not ip_txt:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_txt)
    except Exception:
        return False

    for net in deny_nets:
        try:
            if ip_obj in net:
                return False
        except Exception:
            continue
    if not allow_nets:
        return True
    for net in allow_nets:
        try:
            if ip_obj in net:
                return True
        except Exception:
            continue
    return False


class _ConnRateLimiter:
    """Simple per-second connection rate limiter."""

    def __init__(self, rate_per_sec: int):
        self.rate = max(0, int(rate_per_sec))
        self._lock = threading.Lock()
        self._events = deque()

    def allow(self) -> bool:
        if self.rate <= 0:
            return True
        now = _now()
        cutoff = now - 1.0
        with self._lock:
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            if len(self._events) >= self.rate:
                return False
            self._events.append(now)
            return True


class _ByteRateLimiter:
    """Thread-safe token-bucket limiter for aggregate byte throughput."""

    def __init__(self, bytes_per_sec: int):
        self.rate = max(0, int(bytes_per_sec))
        self.capacity = max(self.rate, 65536) if self.rate > 0 else 0
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, n: int) -> None:
        if self.rate <= 0:
            return
        need = max(0, int(n))
        if need <= 0:
            return
        while True:
            sleep_s = 0.0
            with self._lock:
                now = time.monotonic()
                elapsed = max(0.0, now - self._last)
                self._last = now
                if elapsed > 0.0:
                    self._tokens = min(float(self.capacity), self._tokens + elapsed * float(self.rate))
                if self._tokens >= float(need):
                    self._tokens -= float(need)
                    return
                short = float(need) - self._tokens
                self._tokens = 0.0
                sleep_s = short / float(self.rate)
            time.sleep(max(0.001, min(0.2, sleep_s)))


@dataclass
class IntranetRule:
    sync_id: str
    role: str  # 'server' or 'client'
    listen: str
    protocol: str
    balance: str
    remotes: List[str]
    token: str
    peer_node_id: int
    peer_host: str
    tunnel_port: int
    server_cert_pem: str = ''  # for client verification
    tokens: List[str] = field(default_factory=list)
    tls_verify: bool = False
    qos_bandwidth_kbps: int = 0
    qos_max_conns: int = 0
    qos_conn_rate: int = 0
    acl_allow_sources: List[str] = field(default_factory=list)
    acl_deny_sources: List[str] = field(default_factory=list)
    acl_allow_hours: List[str] = field(default_factory=list)
    acl_allow_tokens: List[str] = field(default_factory=list)


class _ControlSession:
    def __init__(self, token: str, node_id: int, sock: Any, dial_mode: str, legacy: bool = False):
        self.token = token
        self.tokens: set[str] = {token}
        self.node_id = node_id
        self.sock = sock
        self.dial_mode = dial_mode
        self.legacy = legacy

        self.lock = threading.Lock()
        self.closed = False

        self.connected_at = _now()
        self.hello_ok_at = self.connected_at
        self.last_seen = self.connected_at
        self.last_ping_at = 0.0
        self.rtt_ms: Optional[int] = None

    def send(self, obj: Dict[str, Any]) -> bool:
        if self.closed:
            return False
        try:
            data = _json_line(obj)
            with self.lock:
                self.sock.sendall(data)
            return True
        except Exception:
            self.closed = True
            _safe_close(self.sock)
            return False

    def close(self, reason: str = '') -> None:
        self.closed = True
        try:
            _safe_close(self.sock)
        finally:
            _log('control_closed', token=_mask_token(self.token), node_id=self.node_id, reason=reason)


class _TunnelServer:
    """A-side tunnel server listening on TCP/TLS port (default 18443).

    Accepts both control connections (type=hello) and data connections (type=data/data_udp).
    """

    def __init__(self, port: int):
        self.port = int(port)
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._janitor_th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._tls_required = bool(REQUIRE_TLS_SERVER)
        self._ssl_ctx = _mk_server_ssl_context()
        self._startup_error = ''

        self._allowed_tokens_lock = threading.Lock()
        self._allowed_tokens: set[str] = set()

        self._sessions_lock = threading.Lock()
        self._sessions: Dict[str, _ControlSession] = {}  # token -> session

        self._pending_lock = threading.Lock()
        self._pending: Dict[Tuple[str, str], Dict[str, Any]] = {}  # (token, conn_id) -> {event, client_sock, proto, udp_sender}

        self._accept_sem = threading.BoundedSemaphore(MAX_ACCEPT_WORKERS)
        self._flow_sem = threading.BoundedSemaphore(MAX_ACTIVE_FLOWS)

        self._nonce_lock = threading.Lock()
        self._recent_nonces: Dict[str, OrderedDict[str, float]] = {}

        self._stats_lock = threading.Lock()
        self._accept_active = 0
        self._accept_peak = 0
        self._flow_active = 0
        self._flow_peak = 0
        self._tcp_active = 0
        self._tcp_peak = 0
        self._udp_active = 0
        self._udp_peak = 0
        self._open_total = 0
        self._open_success = 0
        self._open_fail = 0
        self._open_timeout = 0
        self._reject_overload = 0
        self._first_packet_timeout = 0
        self._nonce_replay = 0
        self._acl_reject = 0
        self._qos_reject_conn_rate = 0
        self._qos_reject_max_conns = 0
        self._control_reconnect = 0
        self._reconnect_by_token: Dict[str, int] = {}
        self._open_latency_buckets: Dict[str, int] = {
            'le_50ms': 0,
            'le_100ms': 0,
            'le_300ms': 0,
            'le_1000ms': 0,
            'gt_1000ms': 0,
        }

    def set_allowed_tokens(self, tokens: set[str]) -> None:
        with self._allowed_tokens_lock:
            self._allowed_tokens = set(tokens)
        # drop token mappings not allowed; close orphaned sessions
        orphan_sessions: set[_ControlSession] = set()
        with self._sessions_lock:
            all_sessions = set(self._sessions.values())
            for t in list(self._sessions.keys()):
                if t not in tokens:
                    self._sessions.pop(t, None)
            active_sessions = set(self._sessions.values())
            orphan_sessions = all_sessions - active_sessions
        for sess in orphan_sessions:
            try:
                sess.close('token_removed')
            except Exception:
                pass
        with self._nonce_lock:
            for t in list(self._recent_nonces.keys()):
                if t not in tokens:
                    self._recent_nonces.pop(t, None)
        with self._stats_lock:
            for t in list(self._reconnect_by_token.keys()):
                if t not in tokens:
                    self._reconnect_by_token.pop(t, None)

    def get_session(self, token: str) -> Optional[_ControlSession]:
        with self._sessions_lock:
            s = self._sessions.get(token)
        if s and not s.closed:
            # stale protection
            if (_now() - s.last_seen) > SESSION_STALE:
                s.close('stale')
                with self._sessions_lock:
                    if self._sessions.get(token) is s:
                        self._sessions.pop(token, None)
                return None
            return s
        return None

    def _record_open_result(self, started_at: float, ok: bool, timeout: bool = False) -> None:
        elapsed_ms = int(max(0.0, (_now() - started_at) * 1000.0))
        with self._stats_lock:
            if ok:
                self._open_success += 1
            else:
                self._open_fail += 1
                if timeout:
                    self._open_timeout += 1

            if elapsed_ms <= 50:
                self._open_latency_buckets['le_50ms'] += 1
            elif elapsed_ms <= 100:
                self._open_latency_buckets['le_100ms'] += 1
            elif elapsed_ms <= 300:
                self._open_latency_buckets['le_300ms'] += 1
            elif elapsed_ms <= 1000:
                self._open_latency_buckets['le_1000ms'] += 1
            else:
                self._open_latency_buckets['gt_1000ms'] += 1

    def open_started(self) -> float:
        with self._stats_lock:
            self._open_total += 1
        return _now()

    def open_finished(self, started_at: float, ok: bool, timeout: bool = False) -> None:
        self._record_open_result(started_at, ok=ok, timeout=timeout)

    def acquire_flow_slot(self, proto: str) -> bool:
        if not self._flow_sem.acquire(blocking=False):
            with self._stats_lock:
                self._reject_overload += 1
            return False
        with self._stats_lock:
            self._flow_active += 1
            if self._flow_active > self._flow_peak:
                self._flow_peak = self._flow_active
            if proto == 'udp':
                self._udp_active += 1
                if self._udp_active > self._udp_peak:
                    self._udp_peak = self._udp_active
            else:
                self._tcp_active += 1
                if self._tcp_active > self._tcp_peak:
                    self._tcp_peak = self._tcp_active
        return True

    def release_flow_slot(self, proto: str) -> None:
        with self._stats_lock:
            self._flow_active = max(0, self._flow_active - 1)
            if proto == 'udp':
                self._udp_active = max(0, self._udp_active - 1)
            else:
                self._tcp_active = max(0, self._tcp_active - 1)
        try:
            self._flow_sem.release()
        except Exception:
            pass

    def mark_acl_reject(self) -> None:
        with self._stats_lock:
            self._acl_reject += 1

    def mark_qos_reject(self, kind: str) -> None:
        with self._stats_lock:
            if kind == 'conn_rate':
                self._qos_reject_conn_rate += 1
            elif kind == 'max_conns':
                self._qos_reject_max_conns += 1

    def mark_control_reconnect(self, token: str) -> None:
        tk = str(token or '').strip()
        if not tk:
            return
        with self._stats_lock:
            self._control_reconnect += 1
            self._reconnect_by_token[tk] = int(self._reconnect_by_token.get(tk) or 0) + 1

    def token_reconnects(self, token: str) -> int:
        tk = str(token or '').strip()
        if not tk:
            return 0
        with self._stats_lock:
            return int(self._reconnect_by_token.get(tk) or 0)

    def stats_snapshot(self) -> Dict[str, Any]:
        with self._pending_lock:
            pending = len(self._pending)
        with self._stats_lock:
            return {
                'limits': {
                    'max_accept_workers': int(MAX_ACCEPT_WORKERS),
                    'max_active_flows': int(MAX_ACTIVE_FLOWS),
                },
                'accept_workers_active': int(self._accept_active),
                'accept_workers_peak': int(self._accept_peak),
                'flows_active': int(self._flow_active),
                'flows_peak': int(self._flow_peak),
                'tcp_relays_active': int(self._tcp_active),
                'tcp_relays_peak': int(self._tcp_peak),
                'udp_sessions_active': int(self._udp_active),
                'udp_sessions_peak': int(self._udp_peak),
                'open_total': int(self._open_total),
                'open_success': int(self._open_success),
                'open_fail': int(self._open_fail),
                'open_timeout': int(self._open_timeout),
                'open_latency': dict(self._open_latency_buckets),
                'reject_overload': int(self._reject_overload),
                'first_packet_timeout': int(self._first_packet_timeout),
                'nonce_replay_rejected': int(self._nonce_replay),
                'acl_reject': int(self._acl_reject),
                'qos_reject_conn_rate': int(self._qos_reject_conn_rate),
                'qos_reject_max_conns': int(self._qos_reject_max_conns),
                'control_reconnect': int(self._control_reconnect),
                'pending_opens': int(pending),
                'tls_required': bool(self._tls_required),
                'tls_enabled': bool(self._ssl_ctx is not None),
                'startup_error': str(self._startup_error or ''),
            }

    def _remember_nonce(self, token: str, nonce: str) -> bool:
        now = _now()
        cutoff = now - float(NONCE_TTL_SEC)
        with self._nonce_lock:
            by_token = self._recent_nonces.get(token)
            if by_token is None:
                by_token = OrderedDict()
                self._recent_nonces[token] = by_token

            while by_token:
                _nk, seen_at = next(iter(by_token.items()))
                if seen_at >= cutoff:
                    break
                by_token.popitem(last=False)

            if nonce in by_token:
                return False

            by_token[nonce] = now
            while len(by_token) > NONCE_LRU_PER_TOKEN:
                by_token.popitem(last=False)
            return True

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        self._startup_error = ''
        th = threading.Thread(target=self._serve, name=f'intranet-tunnel:{self.port}', daemon=True)
        th.start()
        self._th = th

        jt = threading.Thread(target=self._janitor_loop, name=f'intranet-janitor:{self.port}', daemon=True)
        jt.start()
        self._janitor_th = jt

    def is_running(self) -> bool:
        return bool(self._th and self._th.is_alive() and (not self._startup_error))

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None
        with self._sessions_lock:
            for s in set(self._sessions.values()):
                s.close('server_stop')
            self._sessions.clear()
        with self._nonce_lock:
            self._recent_nonces.clear()

    def _wrap(self, conn: socket.socket) -> Tuple[Optional[Any], str]:
        # Returns (socket_like, dial_mode)
        if self._ssl_ctx is None:
            if self._tls_required:
                _safe_close(conn)
                return None, 'tls'
            try:
                conn.settimeout(None)
                _set_keepalive(conn)
            except Exception:
                pass
            return conn, 'plain'
        try:
            conn.settimeout(None)
            _set_keepalive(conn)
            ss = self._ssl_ctx.wrap_socket(conn, server_side=True)
            ss.settimeout(None)
            return ss, 'tls'
        except Exception as exc:
            _log('accept_wrap_failed', port=self.port, error=str(exc))
            _safe_close(conn)
            return None, 'tls'

    def _serve(self) -> None:
        if self._tls_required and self._ssl_ctx is None:
            self._startup_error = 'tls_context_unavailable'
            _log('server_tls_unavailable', port=int(self.port))
            return
        try:
            s = _bind_socket('', int(self.port), socket.SOCK_STREAM)
            s.listen(TCP_BACKLOG)
        except Exception as exc:
            self._startup_error = f'listen_failed: {exc}'
            _log('server_listen_failed', port=int(self.port), error=str(exc))
            return
        s.settimeout(1.0)
        self._sock = s
        _log('server_listen', port=self.port, tls=bool(self._ssl_ctx is not None))
        while not self._stop.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except Exception:
                continue
            if not self._accept_sem.acquire(blocking=False):
                with self._stats_lock:
                    self._reject_overload += 1
                _safe_close(conn)
                continue
            with self._stats_lock:
                self._accept_active += 1
                if self._accept_active > self._accept_peak:
                    self._accept_peak = self._accept_active
            th = threading.Thread(target=self._handle_conn_guarded, args=(conn, addr), daemon=True)
            th.start()

    def _handle_conn_guarded(self, conn: socket.socket, addr: Any) -> None:
        try:
            self._handle_conn(conn, addr)
        finally:
            with self._stats_lock:
                self._accept_active = max(0, self._accept_active - 1)
            try:
                self._accept_sem.release()
            except Exception:
                pass

    def _handle_conn(self, conn: socket.socket, addr: Any) -> None:
        ss, dial_mode = self._wrap(conn)
        if ss is None:
            return

        # Read first line
        try:
            try:
                ss.settimeout(FIRST_PACKET_TIMEOUT)
            except Exception:
                pass
            line = _recv_line(ss, max_len=FIRST_PACKET_MAX)
            try:
                ss.settimeout(None)
            except Exception:
                pass
            if not line:
                _safe_close(ss)
                return
            # Detect HTTP proxy / wrong port quickly
            if line.startswith('GET ') or line.startswith('POST ') or line.startswith('HTTP/'):
                _log('reject_http', port=self.port, from_addr=str(addr), head=line[:64])
                _safe_close(ss)
                return
            msg = json.loads(line)
        except socket.timeout:
            with self._stats_lock:
                self._first_packet_timeout += 1
            _safe_close(ss)
            return
        except Exception:
            _safe_close(ss)
            return

        mtype = str(msg.get('type') or '')
        if mtype == 'hello':
            self._handle_control(ss, dial_mode, msg, addr)
            return
        if mtype in ('data', 'data_udp'):
            self._handle_data(ss, msg)
            return
        _safe_close(ss)

    def _token_allowed(self, token: str) -> bool:
        with self._allowed_tokens_lock:
            return token in self._allowed_tokens if self._allowed_tokens else True

    def _send_hello_err(self, ss: Any, err: str) -> None:
        try:
            ss.sendall(_json_line({'type': 'hello_err', 'error': err}))
        except Exception:
            pass

    def _handle_control(self, ss: Any, dial_mode: str, hello: Dict[str, Any], addr: Any) -> None:
        token = str(hello.get('token') or '')
        try:
            node_id = int(hello.get('node_id') or 0)
        except Exception:
            node_id = 0

        if not token or not self._token_allowed(token):
            self._send_hello_err(ss, 'token_invalid')
            _safe_close(ss)
            return

        # HMAC handshake (ver=3). Also accept legacy hello for compatibility.
        legacy = False
        alias_tokens: List[str] = []
        if 'sig' not in hello:
            legacy = True
        else:
            magic = str(hello.get('magic') or '')
            try:
                ver = int(hello.get('ver') or 0)
            except Exception:
                ver = 0
            try:
                ts = int(hello.get('ts') or 0)
            except Exception:
                ts = 0
            nonce = str(hello.get('nonce') or '')
            sig = str(hello.get('sig') or '')

            if magic != INTRANET_MAGIC:
                self._send_hello_err(ss, 'magic_mismatch')
                _safe_close(ss)
                return
            if ver != INTRANET_PROTO_VER:
                self._send_hello_err(ss, 'version_mismatch')
                _safe_close(ss)
                return
            if not nonce or not sig or ts <= 0:
                self._send_hello_err(ss, 'hello_invalid')
                _safe_close(ss)
                return
            if abs(int(_now()) - ts) > TS_SKEW_SEC:
                self._send_hello_err(ss, 'ts_skew')
                _safe_close(ss)
                return
            exp = _hmac_sig(token, node_id, ts, nonce)
            if not hmac.compare_digest(exp, sig):
                self._send_hello_err(ss, 'sig_invalid')
                _safe_close(ss)
                return
            if not self._remember_nonce(token, nonce):
                with self._stats_lock:
                    self._nonce_replay += 1
                self._send_hello_err(ss, 'nonce_replay')
                _safe_close(ss)
                return

            # Optional token aliases allow multiple rules to share one control channel.
            # Each alias must provide its own HMAC signature to prevent token hijacking.
            raw_aliases = hello.get('token_aliases')
            if isinstance(raw_aliases, list):
                seen_aliases: set[str] = {token}
                for row in raw_aliases[:64]:
                    if not isinstance(row, dict):
                        continue
                    alias_token = str(row.get('token') or '').strip()
                    alias_sig = str(row.get('sig') or '').strip()
                    if (not alias_token) or (not alias_sig) or alias_token in seen_aliases:
                        continue
                    if not self._token_allowed(alias_token):
                        continue
                    alias_exp = _hmac_sig(alias_token, node_id, ts, nonce)
                    if not hmac.compare_digest(alias_exp, alias_sig):
                        continue
                    seen_aliases.add(alias_token)
                    alias_tokens.append(alias_token)

        sess = _ControlSession(token=token, node_id=node_id, sock=ss, dial_mode=dial_mode, legacy=legacy)
        bind_tokens = [token] + [x for x in alias_tokens if x != token]
        sess.tokens = set(bind_tokens)
        with self._sessions_lock:
            old_sessions: set[_ControlSession] = set()
            for tk in bind_tokens:
                old = self._sessions.get(tk)
                if old and old is not sess:
                    old_sessions.add(old)
            for old in old_sessions:
                old.close('replaced')
            for tk in bind_tokens:
                if tk in self._sessions and (self._sessions.get(tk) is not sess):
                    self.mark_control_reconnect(tk)
                self._sessions[tk] = sess

        if not sess.send({'type': 'hello_ok', 'ver': INTRANET_PROTO_VER, 'server_ts': int(_now()), 'token_count': len(bind_tokens)}):
            sess.close('hello_ok_send_failed')
            with self._sessions_lock:
                for tk, sv in list(self._sessions.items()):
                    if sv is sess:
                        self._sessions.pop(tk, None)
            return
        _log(
            'control_connected',
            port=self.port,
            token=_mask_token(token),
            node_id=node_id,
            dial_mode=dial_mode,
            legacy=legacy,
            from_addr=str(addr),
            token_count=len(bind_tokens),
        )

        # Keep reading to detect disconnect; also handle ping.
        while not self._stop.is_set() and not sess.closed:
            try:
                line = _recv_line(ss)
                if not line:
                    break
                if line.startswith('GET ') or line.startswith('POST ') or line.startswith('HTTP/'):
                    break
                msg = json.loads(line)
            except Exception:
                break

            t = str(msg.get('type') or '')
            sess.last_seen = _now()

            if t == 'ping':
                sess.last_ping_at = sess.last_seen
                # client may report last measured rtt
                try:
                    rtt = msg.get('rtt_ms')
                    if rtt is not None:
                        sess.rtt_ms = int(rtt)
                except Exception:
                    pass
                try:
                    seq = int(msg.get('seq') or 0)
                except Exception:
                    seq = 0
                try:
                    echo_ts = int(msg.get('ts') or 0)
                except Exception:
                    echo_ts = 0
                sess.send({'type': 'pong', 'seq': seq, 'echo_ts': echo_ts, 'server_ts': _now_ms()})

        sess.close('disconnect')
        with self._sessions_lock:
            for tk, sv in list(self._sessions.items()):
                if sv is sess:
                    self._sessions.pop(tk, None)

    def _handle_data(self, ss: Any, msg: Dict[str, Any]) -> None:
        token = str(msg.get('token') or '')
        conn_id = str(msg.get('conn_id') or '')
        ok = bool(msg.get('ok', True))
        proto = str(msg.get('proto') or 'tcp')

        key = (token, conn_id)
        with self._pending_lock:
            pend = self._pending.get(key)
        if not pend:
            _safe_close(ss)
            return

        pend['data_sock'] = ss
        pend['ok'] = ok
        pend['proto'] = proto
        pend['error'] = str(msg.get('error') or '')
        ev: threading.Event = pend['event']
        ev.set()

    def register_pending(self, token: str, conn_id: str, pend: Dict[str, Any]) -> None:
        with self._pending_lock:
            self._pending[(token, conn_id)] = pend

    def pop_pending(self, token: str, conn_id: str) -> Optional[Dict[str, Any]]:
        with self._pending_lock:
            return self._pending.pop((token, conn_id), None)

    def _janitor_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(2.0)
            now = _now()
            # cleanup stale sessions
            with self._sessions_lock:
                for tok, sess in list(self._sessions.items()):
                    if sess.closed:
                        self._sessions.pop(tok, None)
                        continue
                    if (now - sess.last_seen) > SESSION_STALE:
                        sess.close('stale')
                        self._sessions.pop(tok, None)
            # cleanup pending opens that were never popped (belt & suspenders)
            with self._pending_lock:
                for key, pend in list(self._pending.items()):
                    created = float(pend.get('created_at') or 0.0)
                    if created and (now - created) > max(OPEN_TIMEOUT * 3.0, 30.0):
                        self._pending.pop(key, None)
            # cleanup replay nonce cache
            cutoff = now - float(NONCE_TTL_SEC)
            with self._nonce_lock:
                for tok, by_token in list(self._recent_nonces.items()):
                    while by_token:
                        _nonce, seen_at = next(iter(by_token.items()))
                        if seen_at >= cutoff:
                            break
                        by_token.popitem(last=False)
                    if not by_token:
                        self._recent_nonces.pop(tok, None)


class _TCPListener:
    def __init__(self, rule: IntranetRule, tunnel: _TunnelServer):
        self.rule = rule
        self.tunnel = tunnel
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._rr = 0
        self._rule_lock = threading.Lock()
        self._active_local_conns = 0

        self._acl_allow_nets = _compile_ip_networks(rule.acl_allow_sources)
        self._acl_deny_nets = _compile_ip_networks(rule.acl_deny_sources)
        self._acl_hours = _compile_hour_windows(rule.acl_allow_hours)
        self._acl_tokens = set(_normalize_str_list(rule.acl_allow_tokens, max_items=64, item_max_len=96))
        self._conn_rate = _ConnRateLimiter(rule.qos_conn_rate) if int(rule.qos_conn_rate or 0) > 0 else None
        self._max_conns = int(rule.qos_max_conns or 0)
        bps = int(max(0, int(rule.qos_bandwidth_kbps or 0)) * 1024 / 8)
        self._bw_limiter = _ByteRateLimiter(bps) if bps > 0 else None

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._serve, name=f'intranet-tcp:{self.rule.listen}', daemon=True)
        th.start()
        self._th = th

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _choose_target(self) -> str:
        rs = self.rule.remotes or []
        if not rs:
            return ''
        # round-robin (fix off-by-one)
        target = rs[self._rr % len(rs)]
        self._rr = (self._rr + 1) % len(rs)
        return target

    def _serve(self) -> None:
        try:
            host, port = _split_hostport(self.rule.listen)
            s = _bind_socket(host, port, socket.SOCK_STREAM)
            s.listen(TCP_BACKLOG)
        except Exception as exc:
            _log('tcp_listen_failed', listen=self.rule.listen, error=str(exc))
            return
        s.settimeout(1.0)
        self._sock = s
        while not self._stop.is_set():
            try:
                c, addr = s.accept()
                _set_keepalive(c)
            except socket.timeout:
                continue
            except Exception:
                continue
            th = threading.Thread(target=self._handle_client, args=(c, addr), daemon=True)
            th.start()

    def _allow_client(self, addr: Any) -> Tuple[bool, str]:
        ip_txt = ''
        try:
            if isinstance(addr, tuple) and addr:
                ip_txt = str(addr[0] or '')
        except Exception:
            ip_txt = ''

        if self._acl_tokens and (self.rule.token not in self._acl_tokens):
            return False, 'acl_token'
        if self._acl_hours and (not _match_hour_windows(self._acl_hours)):
            return False, 'acl_time'
        if not _ip_acl_allowed(ip_txt, self._acl_allow_nets, self._acl_deny_nets):
            return False, 'acl_source'
        return True, ''

    def _take_local_conn_slot(self) -> bool:
        if self._max_conns <= 0:
            return True
        with self._rule_lock:
            if self._active_local_conns >= self._max_conns:
                return False
            self._active_local_conns += 1
        return True

    def _release_local_conn_slot(self) -> None:
        if self._max_conns <= 0:
            return
        with self._rule_lock:
            self._active_local_conns = max(0, self._active_local_conns - 1)

    def _handle_client(self, client: socket.socket, addr: Any) -> None:
        local_conn_slot = False
        allowed, deny_reason = self._allow_client(addr)
        if not allowed:
            self.tunnel.mark_acl_reject()
            _log('tcp_acl_reject', listen=self.rule.listen, from_addr=str(addr), reason=deny_reason)
            _safe_close(client)
            return
        if self._conn_rate and (not self._conn_rate.allow()):
            self.tunnel.mark_qos_reject('conn_rate')
            _log('tcp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='conn_rate')
            _safe_close(client)
            return
        if not self._take_local_conn_slot():
            self.tunnel.mark_qos_reject('max_conns')
            _log('tcp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='max_conns')
            _safe_close(client)
            return
        local_conn_slot = True

        if not self.tunnel.acquire_flow_slot('tcp'):
            _safe_close(client)
            self._release_local_conn_slot()
            return

        opened_at = self.tunnel.open_started()
        open_recorded = False
        token = self.rule.token
        try:
            sess = self.tunnel.get_session(token)
            if not sess:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                _safe_close(client)
                return
            target = self._choose_target()
            if not target:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                _safe_close(client)
                return

            conn_id = uuid.uuid4().hex
            ev = threading.Event()
            pend = {'event': ev, 'client_sock': client, 'proto': 'tcp', 'created_at': _now()}
            self.tunnel.register_pending(token, conn_id, pend)

            # ask B to open
            if not sess.send({'type': 'open', 'conn_id': conn_id, 'proto': 'tcp', 'target': target, 'token': token}):
                self.tunnel.pop_pending(token, conn_id)
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                _safe_close(client)
                return

            if not ev.wait(timeout=OPEN_TIMEOUT):
                self.tunnel.pop_pending(token, conn_id)
                self.tunnel.open_finished(opened_at, ok=False, timeout=True)
                open_recorded = True
                _safe_close(client)
                return

            pend2 = self.tunnel.pop_pending(token, conn_id) or pend
            data_sock = pend2.get('data_sock')
            ok = bool(pend2.get('ok', True))
            if not ok or not data_sock:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                _safe_close(client)
                _safe_close(data_sock)
                return

            self.tunnel.open_finished(opened_at, ok=True)
            open_recorded = True
            _relay_tcp(client, data_sock, limiter=self._bw_limiter)
        finally:
            if not open_recorded:
                self.tunnel.open_finished(opened_at, ok=False)
            self.tunnel.release_flow_slot('tcp')
            if local_conn_slot:
                self._release_local_conn_slot()


class _UDPSession:
    def __init__(
        self,
        udp_sock: socket.socket,
        client_addr: Tuple[str, int],
        token: str,
        tunnel: _TunnelServer,
        target: str,
        limiter: Optional[_ByteRateLimiter] = None,
    ):
        self.udp_sock = udp_sock
        self.client_addr = client_addr
        self.token = token
        self.tunnel = tunnel
        self.target = target
        self.conn_id = uuid.uuid4().hex
        self.data_sock: Optional[Any] = None
        self.ok = False
        self.last_seen = _now()
        self._send_lock = threading.Lock()
        self._rx_th: Optional[threading.Thread] = None
        self._flow_slot_acquired = False
        self._limiter = limiter

    def open(self) -> bool:
        if not self.tunnel.acquire_flow_slot('udp'):
            return False
        self._flow_slot_acquired = True
        opened_at = self.tunnel.open_started()
        open_recorded = False
        try:
            sess = self.tunnel.get_session(self.token)
            if not sess:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                self.close()
                return False
            ev = threading.Event()
            pend = {'event': ev, 'proto': 'udp', 'created_at': _now()}
            self.tunnel.register_pending(self.token, self.conn_id, pend)
            if not sess.send({'type': 'open', 'conn_id': self.conn_id, 'proto': 'udp', 'target': self.target, 'token': self.token}):
                self.tunnel.pop_pending(self.token, self.conn_id)
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                self.close()
                return False
            if not ev.wait(timeout=OPEN_TIMEOUT):
                self.tunnel.pop_pending(self.token, self.conn_id)
                self.tunnel.open_finished(opened_at, ok=False, timeout=True)
                open_recorded = True
                self.close()
                return False
            pend2 = self.tunnel.pop_pending(self.token, self.conn_id) or pend
            self.data_sock = pend2.get('data_sock')
            self.ok = bool(pend2.get('ok', True)) and self.data_sock is not None
            if not self.ok:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                _safe_close(self.data_sock)
                self.data_sock = None
                self.close()
                return False

            self.tunnel.open_finished(opened_at, ok=True)
            open_recorded = True
            th = threading.Thread(target=self._rx_loop, name='intranet-udp-rx', daemon=True)
            th.start()
            self._rx_th = th
            return True
        except Exception:
            if not open_recorded:
                self.tunnel.open_finished(opened_at, ok=False)
            self.close()
            return False

    def send_datagram(self, payload: bytes) -> None:
        self.last_seen = _now()
        if not self.data_sock:
            return
        if len(payload) > MAX_FRAME:
            payload = payload[:MAX_FRAME]
        frame = struct.pack('!I', len(payload)) + payload
        try:
            with self._send_lock:
                if self._limiter is not None:
                    self._limiter.consume(len(frame))
                self.data_sock.sendall(frame)
        except Exception:
            self.close()

    def _rx_loop(self) -> None:
        ds = self.data_sock
        if not ds:
            return
        try:
            while True:
                hdr = _recv_exact(ds, 4)
                if not hdr:
                    break
                (n,) = struct.unpack('!I', hdr)
                if n <= 0 or n > MAX_FRAME:
                    break
                data = _recv_exact(ds, n)
                if not data:
                    break
                if self._limiter is not None:
                    self._limiter.consume(len(data))
                self.udp_sock.sendto(data, self.client_addr)
        except Exception:
            pass
        _safe_close(ds)
        self.data_sock = None
        self.ok = False
        self._release_flow_slot()

    def close(self) -> None:
        _safe_close(self.data_sock)
        self.data_sock = None
        self.ok = False
        self._release_flow_slot()

    def _release_flow_slot(self) -> None:
        if not self._flow_slot_acquired:
            return
        self._flow_slot_acquired = False
        self.tunnel.release_flow_slot('udp')


class _UDPListener:
    def __init__(self, rule: IntranetRule, tunnel: _TunnelServer):
        self.rule = rule
        self.tunnel = tunnel
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._sessions: Dict[Tuple[str, int], _UDPSession] = {}
        self._lock = threading.Lock()
        self._rr = 0
        self._acl_allow_nets = _compile_ip_networks(rule.acl_allow_sources)
        self._acl_deny_nets = _compile_ip_networks(rule.acl_deny_sources)
        self._acl_hours = _compile_hour_windows(rule.acl_allow_hours)
        self._acl_tokens = set(_normalize_str_list(rule.acl_allow_tokens, max_items=64, item_max_len=96))
        self._conn_rate = _ConnRateLimiter(rule.qos_conn_rate) if int(rule.qos_conn_rate or 0) > 0 else None
        self._max_conns = int(rule.qos_max_conns or 0)
        bps = int(max(0, int(rule.qos_bandwidth_kbps or 0)) * 1024 / 8)
        self._bw_limiter = _ByteRateLimiter(bps) if bps > 0 else None

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._serve, name=f'intranet-udp:{self.rule.listen}', daemon=True)
        th.start()
        self._th = th

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        with self._lock:
            for s in self._sessions.values():
                s.close()
            self._sessions.clear()

    def _choose_target(self) -> str:
        rs = self.rule.remotes or []
        if not rs:
            return ''
        target = rs[self._rr % len(rs)]
        self._rr = (self._rr + 1) % len(rs)
        return target

    def _allow_client(self, addr: Any) -> Tuple[bool, str]:
        ip_txt = ''
        try:
            if isinstance(addr, tuple) and addr:
                ip_txt = str(addr[0] or '')
        except Exception:
            ip_txt = ''

        if self._acl_tokens and (self.rule.token not in self._acl_tokens):
            return False, 'acl_token'
        if self._acl_hours and (not _match_hour_windows(self._acl_hours)):
            return False, 'acl_time'
        if not _ip_acl_allowed(ip_txt, self._acl_allow_nets, self._acl_deny_nets):
            return False, 'acl_source'
        return True, ''

    def _serve(self) -> None:
        try:
            host, port = _split_hostport(self.rule.listen)
            s = _bind_socket(host, port, socket.SOCK_DGRAM)
        except Exception as exc:
            _log('udp_listen_failed', listen=self.rule.listen, error=str(exc))
            return
        s.settimeout(1.0)
        self._sock = s

        threading.Thread(target=self._cleanup_loop, daemon=True).start()

        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(MAX_FRAME)
            except socket.timeout:
                continue
            except Exception:
                continue

            if not data:
                continue
            allowed, deny_reason = self._allow_client(addr)
            if not allowed:
                self.tunnel.mark_acl_reject()
                _log('udp_acl_reject', listen=self.rule.listen, from_addr=str(addr), reason=deny_reason)
                continue
            with self._lock:
                sess = self._sessions.get(addr)
            if not sess or not sess.ok or sess.data_sock is None:
                if self._conn_rate and (not self._conn_rate.allow()):
                    self.tunnel.mark_qos_reject('conn_rate')
                    _log('udp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='conn_rate')
                    continue
                if self._max_conns > 0:
                    with self._lock:
                        cur_sessions = len(self._sessions)
                    if cur_sessions >= self._max_conns:
                        self.tunnel.mark_qos_reject('max_conns')
                        _log('udp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='max_conns')
                        continue
                target = self._choose_target()
                if not target:
                    continue
                old_sess = sess
                sess = _UDPSession(
                    udp_sock=s,
                    client_addr=addr,
                    token=self.rule.token,
                    tunnel=self.tunnel,
                    target=target,
                    limiter=self._bw_limiter,
                )
                if not sess.open():
                    if old_sess:
                        old_sess.close()
                    continue
                with self._lock:
                    if old_sess:
                        old_sess.close()
                    self._sessions[addr] = sess
            sess.send_datagram(data)

    def _cleanup_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(2.0)
            now = _now()
            dead: List[Tuple[str, int]] = []
            with self._lock:
                for addr, sess in self._sessions.items():
                    if (now - sess.last_seen) > UDP_SESSION_TTL:
                        dead.append(addr)
                for addr in dead:
                    s = self._sessions.pop(addr, None)
                    if s:
                        s.close()


@dataclass
class _ClientState:
    peer_host: str
    peer_port: int
    token: str
    node_id: int
    connected: bool = False
    dial_mode: str = ''
    last_attempt_at: float = 0.0
    last_connected_at: float = 0.0
    last_hello_ok_at: float = 0.0
    last_pong_at: float = 0.0
    rtt_ms: Optional[int] = None
    handshake_ms: Optional[int] = None
    last_error: str = ''
    reconnects: int = 0
    ping_sent: int = 0
    pong_recv: int = 0
    loss_pct: float = 0.0
    jitter_ms: int = 0


class _TunnelClient:
    """B-side client maintaining control connection to A, and opening data connections on demand."""

    def __init__(
        self,
        peer_host: str,
        peer_port: int,
        token: str,
        tokens: Optional[List[str]],
        node_id: int,
        server_cert_pem: str = '',
        tls_verify: bool = False,
    ):
        self.peer_host = peer_host
        self.peer_port = int(peer_port)
        uniq_tokens: List[str] = []
        seen_tokens: set[str] = set()
        for tk in [token] + (tokens or []):
            st = str(tk or '').strip()
            if (not st) or (st in seen_tokens):
                continue
            seen_tokens.add(st)
            uniq_tokens.append(st)
        if not uniq_tokens:
            uniq_tokens = [str(token or '').strip()]
        self.tokens = uniq_tokens
        self._token_set = set(uniq_tokens)
        self.token = uniq_tokens[0]
        self.node_id = int(node_id)
        self.server_cert_pem = server_cert_pem or ''
        self.tls_verify = bool(tls_verify)
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None

        self._state_lock = threading.Lock()
        self._state = _ClientState(peer_host=self.peer_host, peer_port=self.peer_port, token=self.token, node_id=self.node_id)
        self._tls_ctx: Optional[ssl.SSLContext] = None
        self._tls_ctx_err = ''
        self._open_sem = threading.BoundedSemaphore(MAX_CLIENT_OPEN_WORKERS)
        self._had_connected = False
        self._reconnects = 0
        self._build_tls_context()

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._loop, name=f'intranet-client:{self.peer_host}:{self.peer_port}', daemon=True)
        th.start()
        self._th = th

    def stop(self) -> None:
        self._stop.set()

    def get_state(self) -> Dict[str, Any]:
        with self._state_lock:
            st = self._state
            return {
                'peer_host': st.peer_host,
                'peer_port': st.peer_port,
                'token': _mask_token(st.token),
                'token_count': len(self.tokens),
                'connected': st.connected,
                'dial_mode': st.dial_mode,
                'last_attempt_at': int(st.last_attempt_at) if st.last_attempt_at else 0,
                'last_connected_at': int(st.last_connected_at) if st.last_connected_at else 0,
                'last_hello_ok_at': int(st.last_hello_ok_at) if st.last_hello_ok_at else 0,
                'last_pong_at': int(st.last_pong_at) if st.last_pong_at else 0,
                'rtt_ms': st.rtt_ms,
                'handshake_ms': st.handshake_ms,
                'last_error': st.last_error,
                'tls_verify': bool(self.tls_verify),
                'reconnects': int(st.reconnects),
                'ping_sent': int(st.ping_sent),
                'pong_recv': int(st.pong_recv),
                'loss_pct': float(st.loss_pct),
                'jitter_ms': int(st.jitter_ms),
            }

    def _set_state(self, **kwargs: Any) -> None:
        with self._state_lock:
            for k, v in kwargs.items():
                if hasattr(self._state, k):
                    setattr(self._state, k, v)

    def matches_config(self, server_cert_pem: str, tls_verify: bool, tokens: Optional[List[str]] = None) -> bool:
        cfg_tokens = _normalize_str_list(tokens or [], max_items=256, item_max_len=128)
        if not cfg_tokens:
            cfg_tokens = [self.token]
        return (
            (self.server_cert_pem == (server_cert_pem or ''))
            and (self.tls_verify == bool(tls_verify))
            and (set(cfg_tokens) == self._token_set)
        )

    def owns_token(self, token: str) -> bool:
        return str(token or '').strip() in self._token_set

    def _build_tls_context(self) -> None:
        try:
            self._tls_ctx = _mk_client_ssl_context(
                self.server_cert_pem or None,
                require_verify=bool(self.tls_verify),
            )
            self._tls_ctx_err = ''
        except Exception as exc:
            self._tls_ctx = None
            self._tls_ctx_err = f'tls_context_failed: {exc}'

    def _dial(self) -> Tuple[Optional[Any], str, str]:
        """Dial A-side tunnel port.

        Use TLS by default. Plaintext fallback is disabled unless explicitly enabled
        via REALM_INTRANET_ALLOW_PLAINTEXT=1 for break-glass compatibility.

        Returns: (socket_like, dial_mode, error)
        """
        try:
            raw = socket.create_connection((self.peer_host, self.peer_port), timeout=6)
            raw.settimeout(None)
            _set_keepalive(raw)
        except Exception as exc:
            return None, '', f'dial_failed: {exc}'

        if self._tls_ctx is None:
            _safe_close(raw)
            return None, '', (self._tls_ctx_err or 'tls_context_unavailable')

        # TLS first
        try:
            ctx = self._tls_ctx
            ss = ctx.wrap_socket(raw, server_hostname=None)
            ss.settimeout(None)
            return ss, 'tls', ''
        except ssl.SSLCertVerificationError as exc:
            _safe_close(raw)
            return None, '', f'tls_verify_failed: {exc}'
        except ssl.SSLError as exc:
            msg = str(exc).upper()
            # Only fall back when TLS is not required and error indicates server is plaintext/HTTP.
            if (not self.server_cert_pem) and (not self.tls_verify) and ALLOW_PLAINTEXT_FALLBACK and (
                'WRONG_VERSION_NUMBER' in msg or 'UNKNOWN_PROTOCOL' in msg or 'HTTP_REQUEST' in msg
            ):
                # Re-dial plaintext
                try:
                    raw2 = socket.create_connection((self.peer_host, self.peer_port), timeout=6)
                    raw2.settimeout(None)
                    _set_keepalive(raw2)
                    return raw2, 'plain', ''
                except Exception as exc2:
                    return None, '', f'dial_failed: {exc2}'
            _safe_close(raw)
            return None, '', f'dial_tls_failed: {exc}'
        except Exception as exc:
            # Some plaintext servers will immediately close when they see a TLS ClientHello,
            # which can surface as ConnectionResetError (instead of an ssl.SSLError).
            # When we are allowed to fall back to plaintext (i.e. TLS verification is not
            # required), treat this as a strong signal that the peer is running without TLS.
            if (not self.server_cert_pem) and (not self.tls_verify) and ALLOW_PLAINTEXT_FALLBACK and isinstance(exc, ConnectionResetError):
                _safe_close(raw)
                try:
                    raw2 = socket.create_connection((self.peer_host, self.peer_port), timeout=6)
                    raw2.settimeout(None)
                    _set_keepalive(raw2)
                    return raw2, 'plain', ''
                except Exception as exc2:
                    return None, '', f'dial_failed: {exc2}'

            _safe_close(raw)
            return None, '', f'dial_tls_failed: {exc}'

    def _hello(self, ss: Any, dial_mode: str) -> Tuple[bool, str, Optional[int]]:
        """Perform authenticated hello.

        Returns: (ok, err, handshake_ms)
        """
        t0 = _now()
        nonce = uuid.uuid4().hex
        ts = int(_now())
        sig = _hmac_sig(self.token, self.node_id, ts, nonce)

        hello = {
            'type': 'hello',
            'magic': INTRANET_MAGIC,
            'ver': INTRANET_PROTO_VER,
            'node_id': self.node_id,
            'token': self.token,
            'ts': ts,
            'nonce': nonce,
            'sig': sig,
            'dial_mode': dial_mode,
        }
        aliases: List[Dict[str, str]] = []
        for tk in self.tokens[1:64]:
            aliases.append({'token': tk, 'sig': _hmac_sig(tk, self.node_id, ts, nonce)})
        if aliases:
            hello['token_aliases'] = aliases

        try:
            ss.sendall(_json_line(hello))
        except Exception as exc:
            return False, f'hello_send_failed: {exc}', None

        try:
            # Wait hello_ok
            ss.settimeout(HELLO_TIMEOUT)
            line = _recv_line(ss)
            ss.settimeout(None)
        except Exception as exc:
            return False, f'hello_timeout: {exc}', None

        if not line:
            return False, 'hello_no_response', None

        if line.startswith('HTTP/') or line.startswith('GET ') or line.startswith('POST '):
            return False, 'peer_is_http_proxy', None

        try:
            resp = json.loads(line)
        except Exception:
            return False, 'hello_bad_response', None

        if str(resp.get('type') or '') == 'hello_ok':
            hs = int((_now() - t0) * 1000)
            return True, '', hs

        if str(resp.get('type') or '') == 'hello_err':
            return False, str(resp.get('error') or 'hello_err'), None

        return False, 'hello_unexpected_response', None

    def _loop(self) -> None:
        backoff = 1.0
        seq = 0
        last_rtt: Optional[int] = None

        while not self._stop.is_set():
            self._set_state(last_attempt_at=_now(), connected=False)
            ss, dial_mode, dial_err = self._dial()
            if not ss:
                self._set_state(last_error=dial_err, dial_mode='', connected=False)
                time.sleep(min(10.0, backoff))
                backoff = min(10.0, backoff * 1.6 + 0.2)
                continue

            # hello
            ok, herr, hs_ms = self._hello(ss, dial_mode)
            if not ok:
                self._set_state(last_error=herr, dial_mode=dial_mode, connected=False, handshake_ms=None)
                _log('client_hello_failed', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token), dial_mode=dial_mode, error=herr)
                _safe_close(ss)
                time.sleep(min(10.0, backoff))
                backoff = min(10.0, backoff * 1.6 + 0.2)
                continue

            backoff = 1.0
            now = _now()
            if self._had_connected:
                self._reconnects += 1
            self._had_connected = True
            self._set_state(
                connected=True,
                dial_mode=dial_mode,
                last_connected_at=now,
                last_hello_ok_at=now,
                last_pong_at=now,
                rtt_ms=None,
                handshake_ms=hs_ms,
                last_error='',
                reconnects=int(self._reconnects),
                ping_sent=0,
                pong_recv=0,
                loss_pct=0.0,
                jitter_ms=0,
            )
            _log('client_connected', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token), dial_mode=dial_mode, handshake_ms=hs_ms)

            last_ping = 0.0
            while not self._stop.is_set():
                # send ping
                if (_now() - last_ping) >= PING_INTERVAL:
                    seq += 1
                    ping = {'type': 'ping', 'seq': seq, 'ts': _now_ms()}
                    if last_rtt is not None:
                        ping['rtt_ms'] = int(last_rtt)
                    try:
                        ss.sendall(_json_line(ping))
                    except Exception as exc:
                        self._set_state(last_error=f'control_send_failed: {exc}')
                        break
                    with self._state_lock:
                        self._state.ping_sent = int(self._state.ping_sent) + 1
                    last_ping = _now()

                # pong timeout protection
                st = self.get_state()
                lp = float(st.get('last_pong_at') or 0)
                if lp and (_now() - lp) > PONG_TIMEOUT:
                    self._set_state(last_error='pong_timeout')
                    break

                try:
                    ss.settimeout(2.0)
                    line = _recv_line(ss)
                    ss.settimeout(None)
                except socket.timeout:
                    continue
                except Exception as exc:
                    self._set_state(last_error=f'control_recv_failed: {exc}')
                    break

                if not line:
                    self._set_state(last_error='control_closed')
                    break

                if line.startswith('HTTP/') or line.startswith('GET ') or line.startswith('POST '):
                    self._set_state(last_error='peer_is_http_proxy')
                    break

                try:
                    msg = json.loads(line)
                except Exception:
                    continue

                t = str(msg.get('type') or '')

                if t == 'pong':
                    try:
                        echo_ts = int(msg.get('echo_ts') or 0)
                    except Exception:
                        echo_ts = 0
                    now_ts = _now()
                    with self._state_lock:
                        self._state.pong_recv = int(self._state.pong_recv) + 1
                        if echo_ts > 0:
                            rtt = max(0, _now_ms() - echo_ts)
                            last_rtt = int(rtt)
                            prev = self._state.rtt_ms
                            if prev is not None:
                                diff = abs(int(rtt) - int(prev))
                                old_jitter = int(self._state.jitter_ms or 0)
                                self._state.jitter_ms = int((old_jitter * 7 + diff) / 8)
                            self._state.rtt_ms = int(rtt)
                        self._state.last_pong_at = now_ts
                        sent = max(1, int(self._state.ping_sent or 0))
                        recv = max(0, int(self._state.pong_recv or 0))
                        lost = max(0, sent - recv)
                        self._state.loss_pct = round((float(lost) * 100.0) / float(sent), 2)
                    continue

                if t == 'open':
                    if not self._open_sem.acquire(blocking=False):
                        _log('client_open_overload', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token))
                        continue
                    threading.Thread(target=self._handle_open_guarded, args=(msg,), daemon=True).start()
                    continue

            # disconnected
            self._set_state(connected=False)
            _safe_close(ss)
            # next loop with backoff

    def _open_data(self) -> Tuple[Optional[Any], str]:
        ss, dial_mode, err = self._dial()
        if not ss:
            return None, err
        return ss, ''

    def _handle_open(self, msg: Dict[str, Any]) -> None:
        conn_id = str(msg.get('conn_id') or '')
        proto = str(msg.get('proto') or 'tcp').lower()
        target = str(msg.get('target') or '')
        req_token = str(msg.get('token') or self.token).strip()
        if not conn_id or not target or not req_token:
            return
        if not self.owns_token(req_token):
            _log('client_open_token_reject', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token), req_token=_mask_token(req_token))
            return
        if proto == 'udp':
            self._handle_udp(conn_id, target, req_token)
        else:
            self._handle_tcp(conn_id, target, req_token)

    def _handle_open_guarded(self, msg: Dict[str, Any]) -> None:
        try:
            self._handle_open(msg)
        finally:
            try:
                self._open_sem.release()
            except Exception:
                pass

    def _handle_tcp(self, conn_id: str, target: str, req_token: str) -> None:
        try:
            host, port = _split_hostport(target)
            out = socket.create_connection((host, port), timeout=6)
            out.settimeout(None)
            _set_keepalive(out)
        except Exception as exc:
            ds, err = self._open_data()
            if ds:
                try:
                    ds.sendall(_json_line({'type': 'data', 'proto': 'tcp', 'token': req_token, 'conn_id': conn_id, 'ok': False, 'error': str(exc)}))
                except Exception:
                    pass
                _safe_close(ds)
            else:
                _log('data_open_failed', target=target, proto='tcp', error=err)
            return

        ds, err = self._open_data()
        if not ds:
            _safe_close(out)
            _log('data_dial_failed', target=target, proto='tcp', error=err)
            return
        try:
            ds.sendall(_json_line({'type': 'data', 'proto': 'tcp', 'token': req_token, 'conn_id': conn_id, 'ok': True}))
        except Exception:
            _safe_close(ds)
            _safe_close(out)
            return
        _relay_tcp(out, ds)

    def _handle_udp(self, conn_id: str, target: str, req_token: str) -> None:
        try:
            host, port = _split_hostport(target)
            infos = socket.getaddrinfo(host, int(port), socket.AF_UNSPEC, socket.SOCK_DGRAM)
            family, stype, proto, _canon, sockaddr = infos[0]
            us = socket.socket(family, stype, proto)
            us.connect(sockaddr)
            us.settimeout(1.0)
        except Exception as exc:
            ds, err = self._open_data()
            if ds:
                try:
                    ds.sendall(_json_line({'type': 'data_udp', 'proto': 'udp', 'token': req_token, 'conn_id': conn_id, 'ok': False, 'error': str(exc)}))
                except Exception:
                    pass
                _safe_close(ds)
            else:
                _log('data_open_failed', target=target, proto='udp', error=err)
            return

        ds, err = self._open_data()
        if not ds:
            _safe_close(us)
            _log('data_dial_failed', target=target, proto='udp', error=err)
            return
        try:
            ds.sendall(_json_line({'type': 'data_udp', 'proto': 'udp', 'token': req_token, 'conn_id': conn_id, 'ok': True}))
        except Exception:
            _safe_close(ds)
            _safe_close(us)
            return

        stop = threading.Event()
        threading.Thread(target=_udp_from_data_to_target, args=(ds, us, stop), daemon=True).start()
        threading.Thread(target=_udp_from_target_to_data, args=(ds, us, stop), daemon=True).start()
        while not stop.is_set():
            time.sleep(0.5)
        _safe_close(ds)
        _safe_close(us)


def _recv_exact(sock: Any, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except Exception:
            return b''
        if not chunk:
            return b''
        buf += chunk
    return buf


def _relay_tcp(a: socket.socket, b: Any, limiter: Optional[_ByteRateLimiter] = None) -> None:
    """Bidirectional relay between a plain TCP socket and a (TLS/plain) tunnel socket."""
    stop = threading.Event()

    def _pump(src, dst):
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                if limiter is not None:
                    limiter.consume(len(data))
                dst.sendall(data)
        except Exception:
            pass
        stop.set()

    t1 = threading.Thread(target=_pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=_pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    while not stop.is_set():
        time.sleep(0.2)
    _safe_close(a)
    _safe_close(b)


def _udp_from_data_to_target(data_sock: Any, udp_sock: socket.socket, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            hdr = _recv_exact(data_sock, 4)
            if not hdr:
                break
            (n,) = struct.unpack('!I', hdr)
            if n <= 0 or n > MAX_FRAME:
                break
            payload = _recv_exact(data_sock, n)
            if not payload:
                break
            udp_sock.send(payload)
    except Exception:
        pass
    stop.set()


def _udp_from_target_to_data(data_sock: Any, udp_sock: socket.socket, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            try:
                payload = udp_sock.recv(MAX_FRAME)
            except socket.timeout:
                continue
            if not payload:
                continue
            frame = struct.pack('!I', len(payload)) + payload
            data_sock.sendall(frame)
    except Exception:
        pass
    stop.set()


def _split_hostport(addr: str) -> Tuple[str, int]:
    """Parse host:port.

    - IPv6 must use bracket form: [2001:db8::1]:443
    - Raises ValueError when port is missing/invalid.
    """
    s = (addr or '').strip()
    if not s:
        raise ValueError('empty address')

    # URL form
    if '://' in s:
        u = urlparse(s)
        host = (u.hostname or '').strip()
        port = int(u.port or 0)
        if not host or port <= 0 or port > 65535:
            raise ValueError('address must include host and valid port')
        return host, port

    # Bracketed IPv6
    if s.startswith('['):
        if ']' not in s:
            raise ValueError('invalid IPv6 bracket address')
        host = s.split(']')[0][1:].strip()
        rest = s.split(']')[1]
        if not rest.startswith(':'):
            raise ValueError('missing port')
        p = rest[1:]
        if not p.isdigit():
            raise ValueError('invalid port')
        port = int(p)
        if port <= 0 or port > 65535:
            raise ValueError('invalid port')
        return host, port

    # Unbracketed IPv6 is ambiguous because it contains ':'
    if s.count(':') > 1:
        raise ValueError('IPv6 must use [addr]:port')

    if ':' in s:
        host, p = s.rsplit(':', 1)
        if not p.isdigit():
            raise ValueError('invalid port')
        port = int(p)
        if port <= 0 or port > 65535:
            raise ValueError('invalid port')
        return host.strip(), port

    raise ValueError('missing port (expected host:port)')



def _bind_socket(host: str, port: int, socktype: int) -> socket.socket:
    """Bind a socket (TCP/UDP) with IPv4/IPv6 support."""
    bind_host = (host or '').strip()
    if bind_host in ('', '*'):
        bind_host = None  # wildcard

    last_exc: Optional[Exception] = None
    infos = socket.getaddrinfo(bind_host, int(port), socket.AF_UNSPEC, socktype, 0, socket.AI_PASSIVE)
    for family, stype, proto, _canon, sockaddr in infos:
        s: Optional[socket.socket] = None
        try:
            s = socket.socket(family, stype, proto)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
            except Exception:
                pass
            if family == socket.AF_INET6:
                try:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except Exception:
                    pass
            s.bind(sockaddr)
            return s
        except Exception as exc:
            last_exc = exc
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            continue

    if last_exc:
        raise last_exc
    raise OSError('bind failed')



class IntranetManager:
    """Supervise intranet tunnels based on pool_full.json endpoints."""

    def __init__(self, node_id: int):
        self.node_id = int(node_id)
        self._lock = threading.Lock()
        self._servers: Dict[int, _TunnelServer] = {}
        self._tcp_listeners: Dict[str, _TCPListener] = {}  # sync_id -> listener
        self._udp_listeners: Dict[str, _UDPListener] = {}
        self._clients: Dict[str, _TunnelClient] = {}  # key -> client
        self._client_token_index: Dict[str, str] = {}  # token -> client key
        self._rule_client_key: Dict[str, str] = {}  # sync_id -> client key
        self._last_rules: Dict[str, IntranetRule] = {}

    def apply_from_pool(self, pool: Dict[str, Any]) -> None:
        rules = self._parse_rules(pool)
        with self._lock:
            self._apply_rules_locked(rules)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            servers = []
            for p, s in self._servers.items():
                tls_on = bool(getattr(s, '_ssl_ctx', None) is not None)
                srv_stats = s.stats_snapshot()
                sessions = []
                with getattr(s, '_sessions_lock'):
                    sess_map: Dict[int, Dict[str, Any]] = {}
                    for tok, sess in list(getattr(s, '_sessions', {}).items()):
                        sid = id(sess)
                        item = sess_map.get(sid)
                        if not item:
                            item = {
                                'tokens': [],
                                'node_id': sess.node_id,
                                'dial_mode': sess.dial_mode,
                                'legacy': bool(sess.legacy),
                                'connected_at': int(sess.connected_at),
                                'last_seen_at': int(sess.last_seen),
                                'rtt_ms': sess.rtt_ms,
                            }
                            sess_map[sid] = item
                        item['tokens'].append(_mask_token(tok))
                    for item in sess_map.values():
                        sessions.append({
                            'token': (item.get('tokens') or [''])[0],
                            'tokens': item.get('tokens') or [],
                            'token_count': len(item.get('tokens') or []),
                            'node_id': item.get('node_id'),
                            'dial_mode': item.get('dial_mode'),
                            'legacy': bool(item.get('legacy')),
                            'connected_at': int(item.get('connected_at') or 0),
                            'last_seen_at': int(item.get('last_seen_at') or 0),
                            'rtt_ms': item.get('rtt_ms'),
                        })
                servers.append({'port': int(p), 'tls': tls_on, 'sessions': sessions, 'stats': srv_stats})

            clients = []
            for key, c in self._clients.items():
                st = c.get_state()
                st['key'] = key
                clients.append(st)

            # per rule quick view
            rules = []
            for sync_id, r in self._last_rules.items():
                rules.append({
                    'sync_id': sync_id,
                    'role': r.role,
                    'listen': r.listen,
                    'peer_host': r.peer_host,
                    'port': r.tunnel_port,
                    'token': _mask_token(r.token),
                    'token_count': len(r.tokens or [r.token]),
                    'tls_verify': bool(r.tls_verify),
                    'qos': {
                        'bandwidth_kbps': int(r.qos_bandwidth_kbps or 0),
                        'max_conns': int(r.qos_max_conns or 0),
                        'conn_rate': int(r.qos_conn_rate or 0),
                    },
                    'acl': {
                        'allow_sources': list(r.acl_allow_sources or []),
                        'deny_sources': list(r.acl_deny_sources or []),
                        'allow_hours': list(r.acl_allow_hours or []),
                        'allow_tokens': list(r.acl_allow_tokens or []),
                    },
                    'handshake': self.handshake_health(r.sync_id, {
                        'intranet_role': r.role,
                        'intranet_token': r.token,
                        'intranet_server_port': r.tunnel_port,
                        'intranet_peer_host': r.peer_host,
                    }),
                })

            summary = {
                'servers': len(servers),
                'clients': len(clients),
                'rules': len(rules),
                'active_tcp_relays': sum(int((s.get('stats') or {}).get('tcp_relays_active') or 0) for s in servers),
                'active_udp_sessions': sum(int((s.get('stats') or {}).get('udp_sessions_active') or 0) for s in servers),
                'open_fail': sum(int((s.get('stats') or {}).get('open_fail') or 0) for s in servers),
                'reject_overload': sum(int((s.get('stats') or {}).get('reject_overload') or 0) for s in servers),
                'acl_reject': sum(int((s.get('stats') or {}).get('acl_reject') or 0) for s in servers),
                'qos_reject_conn_rate': sum(int((s.get('stats') or {}).get('qos_reject_conn_rate') or 0) for s in servers),
                'qos_reject_max_conns': sum(int((s.get('stats') or {}).get('qos_reject_max_conns') or 0) for s in servers),
                'control_reconnect': sum(int((s.get('stats') or {}).get('control_reconnect') or 0) for s in servers),
            }

            return {
                'servers': servers,
                'tcp_rules': list(self._tcp_listeners.keys()),
                'udp_rules': list(self._udp_listeners.keys()),
                'clients': clients,
                'rules': rules,
                'summary': summary,
            }

    def handshake_health(self, sync_id: str, ex: Dict[str, Any]) -> Dict[str, Any]:
        """Return health payload for panel handshake check.

        Shape:
          {ok:bool, latency_ms?:int, error?:str, message?:str}
        """
        role = str(ex.get('intranet_role') or '').strip()
        token = str(ex.get('intranet_token') or '').strip()
        try:
            port = int(ex.get('intranet_server_port') or DEFAULT_TUNNEL_PORT)
        except Exception:
            port = DEFAULT_TUNNEL_PORT

        # Server side: check control session presence
        if role == 'server':
            srv = self._servers.get(port)
            if not srv:
                return {'ok': False, 'error': 'server_not_running'}
            sess = srv.get_session(token)
            if not sess:
                return {'ok': False, 'error': 'no_client_connected'}
            latency = sess.rtt_ms
            if latency is None:
                latency = int(max(0.0, (_now() - sess.last_seen) * 1000.0))
            payload: Dict[str, Any] = {
                'ok': True,
                'latency_ms': int(latency),
                'dial_mode': str(sess.dial_mode or ''),
                'reconnects': int(srv.token_reconnects(token)),
                'token_count': len(getattr(sess, 'tokens', set()) or {token}),
            }
            if sess.legacy:
                payload['message'] = 'legacy_client'
            return payload

        # Client side: check client runtime
        if role == 'client':
            peer_host = str(ex.get('intranet_peer_host') or '').strip()
            key = ''
            sid = str(sync_id or '').strip()
            if sid:
                key = str(self._rule_client_key.get(sid) or '')
            if (not key) and token:
                key = str(self._client_token_index.get(token) or '')
            if (not key) and peer_host and token:
                key = f"{peer_host}:{port}:{token}"
            c = self._clients.get(key) if key else None
            if not c:
                return {'ok': False, 'error': 'client_not_running'}
            st = c.get_state()
            if st.get('connected'):
                payload2: Dict[str, Any] = {
                    'ok': True,
                    'dial_mode': str(st.get('dial_mode') or ''),
                    'reconnects': int(st.get('reconnects') or 0),
                    'loss_pct': float(st.get('loss_pct') or 0.0),
                    'jitter_ms': int(st.get('jitter_ms') or 0),
                    'token_count': int(st.get('token_count') or 1),
                    'ping_sent': int(st.get('ping_sent') or 0),
                    'pong_recv': int(st.get('pong_recv') or 0),
                }
                if st.get('rtt_ms') is not None:
                    payload2['latency_ms'] = int(st.get('rtt_ms') or 0)
                elif st.get('handshake_ms') is not None:
                    payload2['latency_ms'] = int(st.get('handshake_ms') or 0)
                return payload2
            err = str(st.get('last_error') or 'not_connected')
            return {
                'ok': False,
                'error': err,
                'dial_mode': str(st.get('dial_mode') or ''),
                'reconnects': int(st.get('reconnects') or 0),
                'loss_pct': float(st.get('loss_pct') or 0.0),
                'jitter_ms': int(st.get('jitter_ms') or 0),
                'token_count': int(st.get('token_count') or 1),
                'ping_sent': int(st.get('ping_sent') or 0),
                'pong_recv': int(st.get('pong_recv') or 0),
            }

        return {'ok': None, 'message': 'unknown_role'}

    def _parse_rules(self, pool: Dict[str, Any]) -> Dict[str, IntranetRule]:
        out: Dict[str, IntranetRule] = {}
        eps = pool.get('endpoints') or []
        if not isinstance(eps, list):
            return out
        for e in eps:
            if not isinstance(e, dict):
                continue
            ex = e.get('extra_config')
            if not isinstance(ex, dict):
                continue
            role = str(ex.get('intranet_role') or '').strip()
            if role not in ('server', 'client'):
                continue
            sync_id = str(ex.get('sync_id') or '').strip() or uuid.uuid4().hex
            listen = str(e.get('listen') or '').strip()
            protocol = str(e.get('protocol') or 'tcp+udp').strip().lower() or 'tcp+udp'
            balance = str(e.get('balance') or 'roundrobin').strip() or 'roundrobin'
            remotes: List[str] = []
            if isinstance(e.get('remotes'), list):
                remotes = [str(x).strip() for x in e.get('remotes') if str(x).strip()]
            elif isinstance(e.get('remote'), str) and e.get('remote'):
                remotes = [str(e.get('remote')).strip()]
            token = str(ex.get('intranet_token') or '').strip()
            tokens: List[str] = []
            if token:
                tokens.append(token)
            raw_tokens = ex.get('intranet_tokens')
            if isinstance(raw_tokens, list):
                for tk in raw_tokens:
                    st = str(tk or '').strip()
                    if st:
                        tokens.append(st)
            now_ts = int(_now())
            raw_grace = ex.get('intranet_token_grace')
            if isinstance(raw_grace, list):
                for it in raw_grace:
                    if not isinstance(it, dict):
                        continue
                    st = str(it.get('token') or '').strip()
                    if not st:
                        continue
                    try:
                        exp = int(it.get('expires_at') or 0)
                    except Exception:
                        exp = 0
                    if exp > now_ts:
                        tokens.append(st)
            seen_tokens: set[str] = set()
            uniq_tokens: List[str] = []
            for tk in tokens:
                if tk in seen_tokens:
                    continue
                seen_tokens.add(tk)
                uniq_tokens.append(tk)
            if not token and uniq_tokens:
                token = uniq_tokens[0]
            if not uniq_tokens and token:
                uniq_tokens = [token]
            try:
                peer_node_id = int(ex.get('intranet_peer_node_id') or 0)
            except Exception:
                peer_node_id = 0
            peer_host = str(ex.get('intranet_peer_host') or '').strip()
            try:
                tunnel_port = int(ex.get('intranet_server_port') or DEFAULT_TUNNEL_PORT)
            except Exception:
                tunnel_port = DEFAULT_TUNNEL_PORT
            server_cert_pem = str(ex.get('intranet_server_cert_pem') or '').strip()
            tls_verify = _truthy(ex.get('intranet_tls_verify'))

            qos = ex.get('qos') if isinstance(ex.get('qos'), dict) else {}
            net = e.get('network') if isinstance(e.get('network'), dict) else {}
            net_qos = net.get('qos') if isinstance(net.get('qos'), dict) else {}

            def _pick_qos(keys: Tuple[str, ...]) -> Any:
                for src in (qos, net_qos, ex, net, e):
                    if not isinstance(src, dict):
                        continue
                    for k in keys:
                        if k in src:
                            return src.get(k)
                return 0

            qos_bandwidth_kbps = _parse_nonneg_int(
                _pick_qos(('bandwidth_kbps', 'bandwidth_kbit', 'bandwidth_limit_kbps', 'qos_bandwidth_kbps'))
            )
            if qos_bandwidth_kbps <= 0:
                qos_bandwidth_mbps = _parse_nonneg_int(
                    _pick_qos(('bandwidth_mbps', 'bandwidth_limit_mbps', 'qos_bandwidth_mbps'))
                )
                if qos_bandwidth_mbps > 0:
                    qos_bandwidth_kbps = qos_bandwidth_mbps * 1024
            qos_max_conns = _parse_nonneg_int(
                _pick_qos(('max_conns', 'max_conn', 'max_connections', 'qos_max_conns'))
            )
            qos_conn_rate = _parse_nonneg_int(
                _pick_qos(('conn_rate', 'conn_per_sec', 'new_conn_per_sec', 'new_connections_per_sec', 'qos_conn_rate'))
            )

            acl_cfg = ex.get('intranet_acl') if isinstance(ex.get('intranet_acl'), dict) else {}
            acl_allow_sources = _normalize_str_list(
                acl_cfg.get('allow_sources') if isinstance(acl_cfg, dict) else ex.get('intranet_acl_allow_sources'),
                max_items=128,
                item_max_len=64,
            )
            acl_deny_sources = _normalize_str_list(
                acl_cfg.get('deny_sources') if isinstance(acl_cfg, dict) else ex.get('intranet_acl_deny_sources'),
                max_items=128,
                item_max_len=64,
            )
            acl_allow_hours = _normalize_str_list(
                acl_cfg.get('allow_hours') if isinstance(acl_cfg, dict) else ex.get('intranet_acl_allow_hours'),
                max_items=16,
                item_max_len=16,
            )
            acl_allow_tokens = _normalize_str_list(
                acl_cfg.get('allow_tokens') if isinstance(acl_cfg, dict) else ex.get('intranet_acl_allow_tokens'),
                max_items=64,
                item_max_len=96,
            )

            if not token:
                continue
            if role == 'server' and (not listen or not remotes):
                continue
            if role == 'client' and (not peer_host):
                continue

            out[sync_id] = IntranetRule(
                sync_id=sync_id,
                role=role,
                listen=listen,
                protocol=protocol,
                balance=balance,
                remotes=remotes,
                token=token,
                peer_node_id=peer_node_id,
                peer_host=peer_host,
                tunnel_port=tunnel_port,
                server_cert_pem=server_cert_pem,
                tokens=uniq_tokens,
                tls_verify=tls_verify,
                qos_bandwidth_kbps=qos_bandwidth_kbps,
                qos_max_conns=qos_max_conns,
                qos_conn_rate=qos_conn_rate,
                acl_allow_sources=acl_allow_sources,
                acl_deny_sources=acl_deny_sources,
                acl_allow_hours=acl_allow_hours,
                acl_allow_tokens=acl_allow_tokens,
            )
        return out

    def _apply_rules_locked(self, rules: Dict[str, IntranetRule]) -> None:
        tokens_by_port: Dict[int, set[str]] = {}
        for r in rules.values():
            if r.role == 'server':
                tokens_by_port.setdefault(r.tunnel_port, set()).update(r.tokens or [r.token])

        # start/stop servers
        for port, tokens in tokens_by_port.items():
            srv = self._servers.get(port)
            if srv and (not srv.is_running()):
                try:
                    srv.stop()
                except Exception:
                    pass
                self._servers.pop(port, None)
                srv = None
            if not srv:
                srv = _TunnelServer(port)
                srv.start()
                self._servers[port] = srv
            srv.set_allowed_tokens(tokens)
        for port in list(self._servers.keys()):
            if port not in tokens_by_port:
                self._servers[port].stop()
                self._servers.pop(port, None)

        # rule listeners on server role
        # NOTE: listeners are keyed by sync_id. When the server-side rule is edited (e.g. changing peer node),
        # the sync_id usually stays the same but token/remotes/listen may change. We must update/restart
        # existing listeners, otherwise the panel may show "handshake ok" while forwarding breaks.
        for sync_id, r in rules.items():
            if r.role != 'server':
                continue

            srv = self._servers.get(r.tunnel_port)
            if not srv:
                continue

            # TCP
            if 'tcp' in r.protocol:
                if sync_id not in self._tcp_listeners:
                    lis = _TCPListener(r, srv)
                    lis.start()
                    self._tcp_listeners[sync_id] = lis
                else:
                    # Update existing listener in-place; restart only when listen address or server changes.
                    lis = self._tcp_listeners.get(sync_id)
                    if lis:
                        old_rule = getattr(lis, 'rule', None)
                        old_listen = getattr(old_rule, 'listen', None)
                        need_restart = bool(getattr(lis, 'tunnel', None) is not srv or old_listen != r.listen)
                        if old_rule is not None:
                            if int(getattr(old_rule, 'qos_bandwidth_kbps', 0) or 0) != int(r.qos_bandwidth_kbps or 0):
                                need_restart = True
                            if int(getattr(old_rule, 'qos_max_conns', 0) or 0) != int(r.qos_max_conns or 0):
                                need_restart = True
                            if int(getattr(old_rule, 'qos_conn_rate', 0) or 0) != int(r.qos_conn_rate or 0):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_sources', []) or []) != list(r.acl_allow_sources or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_deny_sources', []) or []) != list(r.acl_deny_sources or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_hours', []) or []) != list(r.acl_allow_hours or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_tokens', []) or []) != list(r.acl_allow_tokens or []):
                                need_restart = True
                        if need_restart:
                            try:
                                lis.stop()
                            except Exception:
                                pass
                            lis2 = _TCPListener(r, srv)
                            lis2.start()
                            self._tcp_listeners[sync_id] = lis2
                        else:
                            lis.rule = r
                            lis.tunnel = srv
            else:
                if sync_id in self._tcp_listeners:
                    self._tcp_listeners[sync_id].stop()
                    self._tcp_listeners.pop(sync_id, None)

            # UDP
            if 'udp' in r.protocol:
                if sync_id not in self._udp_listeners:
                    ul = _UDPListener(r, srv)
                    ul.start()
                    self._udp_listeners[sync_id] = ul
                else:
                    ul = self._udp_listeners.get(sync_id)
                    if ul:
                        old_rule = getattr(ul, 'rule', None)
                        old_listen = getattr(old_rule, 'listen', None)
                        need_restart = bool(getattr(ul, 'tunnel', None) is not srv or old_listen != r.listen)
                        if old_rule is not None:
                            if int(getattr(old_rule, 'qos_bandwidth_kbps', 0) or 0) != int(r.qos_bandwidth_kbps or 0):
                                need_restart = True
                            if int(getattr(old_rule, 'qos_max_conns', 0) or 0) != int(r.qos_max_conns or 0):
                                need_restart = True
                            if int(getattr(old_rule, 'qos_conn_rate', 0) or 0) != int(r.qos_conn_rate or 0):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_sources', []) or []) != list(r.acl_allow_sources or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_deny_sources', []) or []) != list(r.acl_deny_sources or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_hours', []) or []) != list(r.acl_allow_hours or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_tokens', []) or []) != list(r.acl_allow_tokens or []):
                                need_restart = True
                        if need_restart:
                            try:
                                ul.stop()
                            except Exception:
                                pass
                            ul2 = _UDPListener(r, srv)
                            ul2.start()
                            self._udp_listeners[sync_id] = ul2
                        else:
                            ul.rule = r
                            ul.tunnel = srv
            else:
                if sync_id in self._udp_listeners:
                    self._udp_listeners[sync_id].stop()
                    self._udp_listeners.pop(sync_id, None)

        # stop removed listeners
        for sync_id in list(self._tcp_listeners.keys()):
            if sync_id not in rules or rules[sync_id].role != 'server' or ('tcp' not in rules[sync_id].protocol):
                self._tcp_listeners[sync_id].stop()
                self._tcp_listeners.pop(sync_id, None)
        for sync_id in list(self._udp_listeners.keys()):
            if sync_id not in rules or rules[sync_id].role != 'server' or ('udp' not in rules[sync_id].protocol):
                self._udp_listeners[sync_id].stop()
                self._udp_listeners.pop(sync_id, None)

        # clients on client role (group by peer+TLS profile; share one control channel across tokens/rules)
        client_groups: Dict[str, Dict[str, Any]] = {}
        rule_client_key: Dict[str, str] = {}
        for sync_id, r in rules.items():
            if r.role != 'client':
                continue
            cert_sig = hashlib.sha1((r.server_cert_pem or '').encode('utf-8')).hexdigest()[:16]
            key = f"{r.peer_host}:{r.tunnel_port}:{1 if r.tls_verify else 0}:{cert_sig}"
            grp = client_groups.get(key)
            if not grp:
                grp = {
                    'peer_host': r.peer_host,
                    'peer_port': r.tunnel_port,
                    'server_cert_pem': r.server_cert_pem,
                    'tls_verify': bool(r.tls_verify),
                    'tokens': [],
                    'seen': set(),
                }
                client_groups[key] = grp
            for tk in (r.tokens or [r.token]):
                st = str(tk or '').strip()
                if (not st) or (st in grp['seen']):
                    continue
                grp['seen'].add(st)
                grp['tokens'].append(st)
            rule_client_key[sync_id] = key

        desired_keys: set[str] = set(client_groups.keys())
        token_index: Dict[str, str] = {}

        for key, grp in client_groups.items():
            tokens = list(grp.get('tokens') or [])
            if not tokens:
                continue
            desired_keys.add(key)
            c = self._clients.get(key)
            if c and (not c.matches_config(grp.get('server_cert_pem') or '', bool(grp.get('tls_verify')), tokens)):
                c.stop()
                self._clients.pop(key, None)
                c = None
            if not c:
                c = _TunnelClient(
                    peer_host=str(grp.get('peer_host') or ''),
                    peer_port=int(grp.get('peer_port') or DEFAULT_TUNNEL_PORT),
                    token=str(tokens[0] or ''),
                    tokens=tokens,
                    node_id=self.node_id,
                    server_cert_pem=str(grp.get('server_cert_pem') or ''),
                    tls_verify=bool(grp.get('tls_verify')),
                )
                self._clients[key] = c
            c.start()
            for tk in tokens:
                token_index[str(tk)] = key

        for key in list(self._clients.keys()):
            if key not in desired_keys:
                self._clients[key].stop()
                self._clients.pop(key, None)

        self._client_token_index = token_index
        self._rule_client_key = rule_client_key

        self._last_rules = rules
