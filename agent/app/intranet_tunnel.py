from __future__ import annotations

import hashlib
import hmac
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

# Handshake/heartbeat
INTRANET_MAGIC = os.getenv('REALM_INTRANET_MAGIC', 'realm-intranet')
INTRANET_PROTO_VER = int(os.getenv('REALM_INTRANET_PROTO_VER', '3'))
HELLO_TIMEOUT = float(os.getenv('REALM_INTRANET_HELLO_TIMEOUT', '6.0'))
PING_INTERVAL = float(os.getenv('REALM_INTRANET_PING_INTERVAL', '15.0'))
PONG_TIMEOUT = float(os.getenv('REALM_INTRANET_PONG_TIMEOUT', '45.0'))
SESSION_STALE = float(os.getenv('REALM_INTRANET_SESSION_STALE', '65.0'))
TS_SKEW_SEC = int(os.getenv('REALM_INTRANET_TS_SKEW_SEC', '300'))

# Fallback to plaintext only when the server side has no TLS (e.g. openssl missing on A).
# Keep it enabled by default to maximize connectivity; set REALM_INTRANET_ALLOW_PLAINTEXT=0 to force TLS-only.
ALLOW_PLAINTEXT_FALLBACK = bool(int(os.getenv('REALM_INTRANET_ALLOW_PLAINTEXT', '1') or '1'))

# Log can be disabled in extreme IO constrained env
ENABLE_LOG = bool(int(os.getenv('REALM_INTRANET_LOG', '1') or '1'))


def _now() -> float:
    return time.time()


def _now_ms() -> int:
    return int(_now() * 1000)


_LOG_LOCK = threading.Lock()


def _log(event: str, **fields: Any) -> None:
    if not ENABLE_LOG:
        return
    try:
        INTRA_DIR.mkdir(parents=True, exist_ok=True)
        payload = {'ts': int(_now()), 'event': event}
        payload.update(fields)
        line = (json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
        with _LOG_LOCK:
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

    We intentionally avoid extra Python dependencies (cryptography). If openssl is not available,
    the tunnel can still run in plaintext TCP (not recommended), but we try hard to generate.
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


from typing import Optional

# Per-socket buffers for _recv_line (avoid 1-byte recv loop)
_RECV_LINE_BUFS = weakref.WeakKeyDictionary()  # sock -> bytearray
_RECV_LINE_BUFS_LOCK = threading.Lock()


def _mk_client_ssl_context(server_cert_pem: Optional[str]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.check_hostname = False
    if server_cert_pem:
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_verify_locations(cadata=server_cert_pem)
        except Exception:
            ctx.verify_mode = ssl.CERT_NONE
    else:
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


class _ControlSession:
    def __init__(self, token: str, node_id: int, sock: Any, dial_mode: str, legacy: bool = False):
        self.token = token
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
        self._ssl_ctx = _mk_server_ssl_context()

        self._allowed_tokens_lock = threading.Lock()
        self._allowed_tokens: set[str] = set()

        self._sessions_lock = threading.Lock()
        self._sessions: Dict[str, _ControlSession] = {}  # token -> session

        self._pending_lock = threading.Lock()
        self._pending: Dict[Tuple[str, str], Dict[str, Any]] = {}  # (token, conn_id) -> {event, client_sock, proto, udp_sender}

    def set_allowed_tokens(self, tokens: set[str]) -> None:
        with self._allowed_tokens_lock:
            self._allowed_tokens = set(tokens)
        # drop sessions not allowed
        with self._sessions_lock:
            for t in list(self._sessions.keys()):
                if t not in tokens:
                    self._sessions[t].close('token_removed')
                    self._sessions.pop(t, None)

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

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._serve, name=f'intranet-tunnel:{self.port}', daemon=True)
        th.start()
        self._th = th

        jt = threading.Thread(target=self._janitor_loop, name=f'intranet-janitor:{self.port}', daemon=True)
        jt.start()
        self._janitor_th = jt

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        with self._sessions_lock:
            for s in self._sessions.values():
                s.close('server_stop')
            self._sessions.clear()

    def _wrap(self, conn: socket.socket) -> Tuple[Optional[Any], str]:
        # Returns (socket_like, dial_mode)
        if self._ssl_ctx is None:
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
        try:
            s = _bind_socket('', int(self.port), socket.SOCK_STREAM)
            s.listen(TCP_BACKLOG)
        except Exception as exc:
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
            th = threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True)
            th.start()

    def _handle_conn(self, conn: socket.socket, addr: Any) -> None:
        ss, dial_mode = self._wrap(conn)
        if ss is None:
            return

        # Read first line
        try:
            line = _recv_line(ss)
            if not line:
                _safe_close(ss)
                return
            # Detect HTTP proxy / wrong port quickly
            if line.startswith('GET ') or line.startswith('POST ') or line.startswith('HTTP/'):
                _log('reject_http', port=self.port, from_addr=str(addr), head=line[:64])
                _safe_close(ss)
                return
            msg = json.loads(line)
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

        sess = _ControlSession(token=token, node_id=node_id, sock=ss, dial_mode=dial_mode, legacy=legacy)
        with self._sessions_lock:
            old = self._sessions.get(token)
            if old:
                old.close('replaced')
            self._sessions[token] = sess

        sess.send({'type': 'hello_ok', 'ver': INTRANET_PROTO_VER, 'server_ts': int(_now())})
        _log('control_connected', port=self.port, token=_mask_token(token), node_id=node_id, dial_mode=dial_mode, legacy=legacy, from_addr=str(addr))

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
            if self._sessions.get(token) is sess:
                self._sessions.pop(token, None)

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


class _TCPListener:
    def __init__(self, rule: IntranetRule, tunnel: _TunnelServer):
        self.rule = rule
        self.tunnel = tunnel
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._rr = 0

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
                c, _addr = s.accept()
                _set_keepalive(c)
            except socket.timeout:
                continue
            except Exception:
                continue
            th = threading.Thread(target=self._handle_client, args=(c,), daemon=True)
            th.start()

    def _handle_client(self, client: socket.socket) -> None:
        token = self.rule.token
        sess = self.tunnel.get_session(token)
        if not sess:
            _safe_close(client)
            return
        target = self._choose_target()
        if not target:
            _safe_close(client)
            return

        conn_id = uuid.uuid4().hex
        ev = threading.Event()
        pend = {'event': ev, 'client_sock': client, 'proto': 'tcp', 'created_at': _now()}
        self.tunnel.register_pending(token, conn_id, pend)

        # ask B to open
        sess.send({'type': 'open', 'conn_id': conn_id, 'proto': 'tcp', 'target': target})

        if not ev.wait(timeout=OPEN_TIMEOUT):
            self.tunnel.pop_pending(token, conn_id)
            _safe_close(client)
            return

        pend2 = self.tunnel.pop_pending(token, conn_id) or pend
        data_sock = pend2.get('data_sock')
        ok = bool(pend2.get('ok', True))
        if not ok or not data_sock:
            _safe_close(client)
            _safe_close(data_sock)
            return

        _relay_tcp(client, data_sock)


class _UDPSession:
    def __init__(self, udp_sock: socket.socket, client_addr: Tuple[str, int], token: str, tunnel: _TunnelServer, target: str):
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

    def open(self) -> bool:
        sess = self.tunnel.get_session(self.token)
        if not sess:
            return False
        ev = threading.Event()
        pend = {'event': ev, 'proto': 'udp', 'created_at': _now()}
        self.tunnel.register_pending(self.token, self.conn_id, pend)
        sess.send({'type': 'open', 'conn_id': self.conn_id, 'proto': 'udp', 'target': self.target})
        if not ev.wait(timeout=OPEN_TIMEOUT):
            self.tunnel.pop_pending(self.token, self.conn_id)
            return False
        pend2 = self.tunnel.pop_pending(self.token, self.conn_id) or pend
        self.data_sock = pend2.get('data_sock')
        self.ok = bool(pend2.get('ok', True)) and self.data_sock is not None
        if not self.ok:
            _safe_close(self.data_sock)
            self.data_sock = None
            return False

        th = threading.Thread(target=self._rx_loop, name='intranet-udp-rx', daemon=True)
        th.start()
        self._rx_th = th
        return True

    def send_datagram(self, payload: bytes) -> None:
        self.last_seen = _now()
        if not self.data_sock:
            return
        if len(payload) > MAX_FRAME:
            payload = payload[:MAX_FRAME]
        frame = struct.pack('!I', len(payload)) + payload
        try:
            with self._send_lock:
                self.data_sock.sendall(frame)
        except Exception:
            _safe_close(self.data_sock)
            self.data_sock = None

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
                self.udp_sock.sendto(data, self.client_addr)
        except Exception:
            pass
        _safe_close(ds)
        self.data_sock = None

    def close(self) -> None:
        _safe_close(self.data_sock)
        self.data_sock = None


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
            with self._lock:
                sess = self._sessions.get(addr)
            if not sess or not sess.ok or sess.data_sock is None:
                target = self._choose_target()
                if not target:
                    continue
                sess = _UDPSession(udp_sock=s, client_addr=addr, token=self.rule.token, tunnel=self.tunnel, target=target)
                if not sess.open():
                    continue
                with self._lock:
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


class _TunnelClient:
    """B-side client maintaining control connection to A, and opening data connections on demand."""

    def __init__(self, peer_host: str, peer_port: int, token: str, node_id: int, server_cert_pem: str = ''):
        self.peer_host = peer_host
        self.peer_port = int(peer_port)
        self.token = token
        self.node_id = int(node_id)
        self.server_cert_pem = server_cert_pem or ''
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None

        self._state_lock = threading.Lock()
        self._state = _ClientState(peer_host=self.peer_host, peer_port=self.peer_port, token=self.token, node_id=self.node_id)

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
                'connected': st.connected,
                'dial_mode': st.dial_mode,
                'last_attempt_at': int(st.last_attempt_at) if st.last_attempt_at else 0,
                'last_connected_at': int(st.last_connected_at) if st.last_connected_at else 0,
                'last_hello_ok_at': int(st.last_hello_ok_at) if st.last_hello_ok_at else 0,
                'last_pong_at': int(st.last_pong_at) if st.last_pong_at else 0,
                'rtt_ms': st.rtt_ms,
                'handshake_ms': st.handshake_ms,
                'last_error': st.last_error,
            }

    def _set_state(self, **kwargs: Any) -> None:
        with self._state_lock:
            for k, v in kwargs.items():
                if hasattr(self._state, k):
                    setattr(self._state, k, v)

    def _dial(self) -> Tuple[Optional[Any], str, str]:
        """Dial A-side tunnel port.

        Prefer TLS. If A cannot enable TLS (e.g. missing openssl and no cert provisioned),
        the TLS handshake usually fails with WRONG_VERSION_NUMBER/UNKNOWN_PROTOCOL.
        In that case, and only when verification is not required, we fall back to plaintext
        to keep connectivity (still authenticated by token).

        Returns: (socket_like, dial_mode, error)
        """
        try:
            raw = socket.create_connection((self.peer_host, self.peer_port), timeout=6)
            raw.settimeout(None)
            _set_keepalive(raw)
        except Exception as exc:
            return None, '', f'dial_failed: {exc}'

        # TLS first
        try:
            ctx = _mk_client_ssl_context(self.server_cert_pem or None)
            ss = ctx.wrap_socket(raw, server_hostname=None)
            ss.settimeout(None)
            return ss, 'tls', ''
        except ssl.SSLCertVerificationError as exc:
            _safe_close(raw)
            return None, '', f'tls_verify_failed: {exc}'
        except ssl.SSLError as exc:
            msg = str(exc).upper()
            # Only fall back when TLS is not required and error indicates server is plaintext/HTTP.
            if (not self.server_cert_pem) and ALLOW_PLAINTEXT_FALLBACK and (
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
            if (not self.server_cert_pem) and ALLOW_PLAINTEXT_FALLBACK and isinstance(exc, ConnectionResetError):
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
            self._set_state(
                connected=True,
                dial_mode=dial_mode,
                last_connected_at=now,
                last_hello_ok_at=now,
                last_pong_at=now,
                rtt_ms=None,
                handshake_ms=hs_ms,
                last_error='',
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
                    if echo_ts > 0:
                        rtt = max(0, _now_ms() - echo_ts)
                        last_rtt = int(rtt)
                        self._set_state(rtt_ms=int(rtt), last_pong_at=_now())
                    else:
                        self._set_state(last_pong_at=_now())
                    continue

                if t == 'open':
                    threading.Thread(target=self._handle_open, args=(msg,), daemon=True).start()
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
        if not conn_id or not target:
            return
        if proto == 'udp':
            self._handle_udp(conn_id, target)
        else:
            self._handle_tcp(conn_id, target)

    def _handle_tcp(self, conn_id: str, target: str) -> None:
        try:
            host, port = _split_hostport(target)
            out = socket.create_connection((host, port), timeout=6)
            out.settimeout(None)
            _set_keepalive(out)
        except Exception as exc:
            ds, err = self._open_data()
            if ds:
                try:
                    ds.sendall(_json_line({'type': 'data', 'proto': 'tcp', 'token': self.token, 'conn_id': conn_id, 'ok': False, 'error': str(exc)}))
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
            ds.sendall(_json_line({'type': 'data', 'proto': 'tcp', 'token': self.token, 'conn_id': conn_id, 'ok': True}))
        except Exception:
            _safe_close(ds)
            _safe_close(out)
            return
        _relay_tcp(out, ds)

    def _handle_udp(self, conn_id: str, target: str) -> None:
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
                    ds.sendall(_json_line({'type': 'data_udp', 'proto': 'udp', 'token': self.token, 'conn_id': conn_id, 'ok': False, 'error': str(exc)}))
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
            ds.sendall(_json_line({'type': 'data_udp', 'proto': 'udp', 'token': self.token, 'conn_id': conn_id, 'ok': True}))
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


def _relay_tcp(a: socket.socket, b: Any) -> None:
    """Bidirectional relay between a plain TCP socket and a (TLS/plain) tunnel socket."""
    stop = threading.Event()

    def _pump(src, dst):
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
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
                sessions = []
                with getattr(s, '_sessions_lock'):
                    for tok, sess in list(getattr(s, '_sessions', {}).items()):
                        sessions.append({
                            'token': _mask_token(tok),
                            'node_id': sess.node_id,
                            'dial_mode': sess.dial_mode,
                            'legacy': bool(sess.legacy),
                            'connected_at': int(sess.connected_at),
                            'last_seen_at': int(sess.last_seen),
                            'rtt_ms': sess.rtt_ms,
                        })
                servers.append({'port': int(p), 'tls': tls_on, 'sessions': sessions})

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
                    'handshake': self.handshake_health(r.sync_id, {
                        'intranet_role': r.role,
                        'intranet_token': r.token,
                        'intranet_server_port': r.tunnel_port,
                        'intranet_peer_host': r.peer_host,
                    }),
                })

            return {
                'servers': servers,
                'tcp_rules': list(self._tcp_listeners.keys()),
                'udp_rules': list(self._udp_listeners.keys()),
                'clients': clients,
                'rules': rules,
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
            payload: Dict[str, Any] = {'ok': True, 'latency_ms': int(latency)}
            if sess.legacy:
                payload['message'] = 'legacy_client'
            return payload

        # Client side: check client runtime
        if role == 'client':
            peer_host = str(ex.get('intranet_peer_host') or '').strip()
            key = f"{peer_host}:{port}:{token}" if peer_host and token else ''
            c = self._clients.get(key) if key else None
            if not c:
                return {'ok': False, 'error': 'client_not_running'}
            st = c.get_state()
            if st.get('connected'):
                payload2: Dict[str, Any] = {'ok': True}
                if st.get('rtt_ms') is not None:
                    payload2['latency_ms'] = int(st.get('rtt_ms') or 0)
                elif st.get('handshake_ms') is not None:
                    payload2['latency_ms'] = int(st.get('handshake_ms') or 0)
                return payload2
            err = str(st.get('last_error') or 'not_connected')
            return {'ok': False, 'error': err}

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
            )
        return out

    def _apply_rules_locked(self, rules: Dict[str, IntranetRule]) -> None:
        tokens_by_port: Dict[int, set[str]] = {}
        for r in rules.values():
            if r.role == 'server':
                tokens_by_port.setdefault(r.tunnel_port, set()).add(r.token)

        # start/stop servers
        for port, tokens in tokens_by_port.items():
            srv = self._servers.get(port)
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
                        if getattr(lis, 'tunnel', None) is not srv or old_listen != r.listen:
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
                        if getattr(ul, 'tunnel', None) is not srv or old_listen != r.listen:
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

        # clients on client role
        desired_keys: set[str] = set()
        for r in rules.values():
            if r.role != 'client':
                continue
            key = f"{r.peer_host}:{r.tunnel_port}:{r.token}"
            desired_keys.add(key)

            c = self._clients.get(key)
            if not c:
                c = _TunnelClient(
                    peer_host=r.peer_host,
                    peer_port=r.tunnel_port,
                    token=r.token,
                    node_id=self.node_id,
                    server_cert_pem=r.server_cert_pem,
                )
                c.start()
                # ✅ 关键修复：新建的 client 必须写入 self._clients，否则状态检测会一直显示“客户端未启动”
                self._clients[key] = c

        for key in list(self._clients.keys()):
            if key not in desired_keys:
                self._clients[key].stop()
                self._clients.pop(key, None)

        self._last_rules = rules
