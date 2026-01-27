from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ------------------------------------------------------------
# Intranet tunnel (A<->B) - TCP only
# ------------------------------------------------------------
# Design goals (for "new rule created but both sides can't connect" cases):
# - Remove TLS/certs/https-proxy ambiguity: transport is plain TCP.
# - Keep *authentication* while "encryption is relaxed": token is NEVER sent in plaintext;
#   only token_id=sha256(token) + HMAC challenge-response.
# - Deterministic handshake & heartbeat observable in panel ("握手检查").
# - Minimal moving parts: TCP listener on A + outbound dialer on B.
#
# Security note:
# - Transport is NOT encrypted. If you need confidentiality, add TCP-layer encryption later.

INTRA_DIR = Path(os.getenv('REALM_AGENT_INTRANET_DIR', '/etc/realm-agent/intranet'))
LOG_FILE = INTRA_DIR / 'intranet.log'

DEFAULT_TUNNEL_PORT = int(os.getenv('REALM_INTRANET_TUNNEL_PORT', '18443'))
OPEN_TIMEOUT = float(os.getenv('REALM_INTRANET_OPEN_TIMEOUT', '10.0'))
TCP_BACKLOG = int(os.getenv('REALM_INTRANET_TCP_BACKLOG', '256'))

INTRANET_MAGIC = os.getenv('REALM_INTRANET_MAGIC', 'realm-intranet')
INTRANET_PROTO_VER = int(os.getenv('REALM_INTRANET_PROTO_VER', '4'))
HELLO_TIMEOUT = float(os.getenv('REALM_INTRANET_HELLO_TIMEOUT', '6.0'))
PING_INTERVAL = float(os.getenv('REALM_INTRANET_PING_INTERVAL', '15.0'))
PONG_TIMEOUT = float(os.getenv('REALM_INTRANET_PONG_TIMEOUT', '45.0'))
SESSION_STALE = float(os.getenv('REALM_INTRANET_SESSION_STALE', '65.0'))

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


def _safe_close(s: Any) -> None:
    try:
        s.close()
    except Exception:
        pass


def _set_keepalive(sock_obj: socket.socket) -> None:
    try:
        sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        return
    # Best-effort for Linux
    try:
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass


def _mask_token(t: str) -> str:
    t = str(t or '')
    if len(t) <= 10:
        return t
    return t[:4] + '…' + t[-4:]


def _token_id(token: str) -> str:
    return hashlib.sha256((token or '').encode('utf-8')).hexdigest()


def _hmac_hex(token: str, msg: str) -> str:
    return hmac.new((token or '').encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()


def _split_hostport(addr: str) -> Tuple[str, int]:
    addr = (addr or '').strip()
    if not addr:
        return ('', 0)
    if addr.startswith('[') and ']' in addr:
        host = addr.split(']')[0][1:]
        port = int(addr.split(']:', 1)[1])
        return (host, port)
    if addr.count(':') == 1:
        host, p = addr.split(':', 1)
        return (host.strip() or '0.0.0.0', int(p))
    host, p = addr.rsplit(':', 1)
    return (host.strip() or '0.0.0.0', int(p))


def _recv_line(sock_obj: socket.socket, max_len: int = 65536) -> Optional[str]:
    """Read a single JSON line.

    Returns:
      - str  : a line without trailing newline
      - ''   : timeout (no complete line yet)
      - None : connection closed
    """
    buf = bytearray()
    while True:
        try:
            ch = sock_obj.recv(1)
        except socket.timeout:
            return ''
        except Exception:
            return None
        if not ch:
            return None
        if ch == b'\n':
            break
        buf += ch
        if len(buf) >= max_len:
            break
    try:
        return buf.decode('utf-8', errors='ignore').strip()
    except Exception:
        return ''


def _send_json_line(sock_obj: socket.socket, obj: Dict[str, Any]) -> bool:
    try:
        raw = (json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
        sock_obj.sendall(raw)
        return True
    except Exception:
        return False


def _relay(a: socket.socket, b: socket.socket, stop: threading.Event) -> None:
    def _pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        stop.set()

    t1 = threading.Thread(target=_pipe, args=(a, b), daemon=True)
    t2 = threading.Thread(target=_pipe, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    while not stop.is_set():
        time.sleep(0.2)
    _safe_close(a)
    _safe_close(b)


# Compatibility: panel may still call /api/v1/intranet/cert
# We no longer use TLS in the tunnel. Return empty string.

def load_server_cert_pem() -> str:
    return ''


@dataclass
class IntranetRule:
    sync_id: str
    role: str  # server/client
    listen: str
    protocol: str
    balance: str
    remotes: List[str]
    token: str
    peer_node_id: int
    peer_host: str
    tunnel_port: int


@dataclass
class _Session:
    token: str
    token_id: str
    node_id: int
    session_id: str
    sock: socket.socket
    connected_at: float
    last_seen: float
    last_pong_ms: int
    rtt_ms: Optional[int]


@dataclass
class _PendingConn:
    conn_id: str
    token: str
    inbound: socket.socket
    created_at: float
    remote: str


class _TunnelServer:
    def __init__(self, port: int):
        self.port = int(port)
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None
        self._janitor: Optional[threading.Thread] = None
        self._lsock: Optional[socket.socket] = None

        self._allowed_lock = threading.Lock()
        self._tokenid_to_token: Dict[str, str] = {}
        self._allowed_tokens: set[str] = set()

        self._sessions_lock = threading.Lock()
        self._sessions_by_token: Dict[str, _Session] = {}

        self._pending_lock = threading.Lock()
        self._pending: Dict[str, _PendingConn] = {}

    def start(self) -> None:
        if self._t and self._t.is_alive():
            return
        self._stop.clear()
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()
        self._janitor = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._janitor.start()
        _log('server_start', port=self.port)

    def stop(self) -> None:
        self._stop.set()
        if self._lsock:
            _safe_close(self._lsock)
        with self._sessions_lock:
            for s in list(self._sessions_by_token.values()):
                _safe_close(s.sock)
            self._sessions_by_token.clear()
        with self._pending_lock:
            for p in list(self._pending.values()):
                _safe_close(p.inbound)
            self._pending.clear()
        _log('server_stop', port=self.port)

    def set_allowed_tokens(self, tokens: set[str]) -> None:
        with self._allowed_lock:
            self._allowed_tokens = set(tokens)
            self._tokenid_to_token = {_token_id(t): t for t in tokens}

    def get_session(self, token: str) -> Optional[_Session]:
        with self._sessions_lock:
            return self._sessions_by_token.get(token)

    def request_open(self, token: str, remote: str, inbound: socket.socket) -> Tuple[bool, str]:
        sess = self.get_session(token)
        if not sess:
            return (False, 'no_client_connected')

        conn_id = uuid.uuid4().hex
        pc = _PendingConn(conn_id=conn_id, token=token, inbound=inbound, created_at=_now(), remote=remote)
        with self._pending_lock:
            self._pending[conn_id] = pc

        ok = _send_json_line(sess.sock, {
            't': 'open',
            'id': conn_id,
            'remote': remote,
            'ts': _now_ms(),
        })
        if not ok:
            with self._pending_lock:
                self._pending.pop(conn_id, None)
            return (False, 'send_open_failed')

        _log('open_sent', port=self.port, token=_mask_token(token), conn_id=conn_id, remote=remote)
        return (True, conn_id)

    def _serve(self) -> None:
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lsock = ls
        try:
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        try:
            ls.bind(('0.0.0.0', self.port))
        except Exception:
            # fallback ipv6 any
            try:
                ls = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                self._lsock = ls
                ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                ls.bind(('::', self.port))
            except Exception as exc:
                _log('server_bind_failed', port=self.port, error=str(exc))
                return
        try:
            ls.listen(TCP_BACKLOG)
        except Exception as exc:
            _log('server_listen_failed', port=self.port, error=str(exc))
            return

        while not self._stop.is_set():
            try:
                ls.settimeout(1.0)
                c, addr = ls.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                _set_keepalive(c)
            except Exception:
                pass
            threading.Thread(target=self._handle_socket, args=(c, addr), daemon=True).start()

    def _handle_socket(self, c: socket.socket, addr: Any) -> None:
        try:
            c.settimeout(HELLO_TIMEOUT)
        except Exception:
            pass
        line = _recv_line(c)
        if not line:
            _safe_close(c)
            return
        try:
            msg = json.loads(line)
        except Exception:
            _send_json_line(c, {'t': 'err', 'code': 'bad_json'})
            _safe_close(c)
            return

        t = str(msg.get('t') or '')
        if t == 'hello':
            self._handle_control(c, addr, msg)
            return
        if t == 'data':
            self._handle_data(c, addr, msg)
            return

        _send_json_line(c, {'t': 'err', 'code': 'unknown_first_packet'})
        _safe_close(c)

    def _handle_control(self, c: socket.socket, addr: Any, hello: Dict[str, Any]) -> None:
        started = _now_ms()
        magic = str(hello.get('magic') or '')
        ver = int(hello.get('v') or 0)
        token_id = str(hello.get('token_id') or '')
        node_id = int(hello.get('node') or 0)
        c_nonce = str(hello.get('c_nonce') or '')

        if magic != INTRANET_MAGIC or ver != INTRANET_PROTO_VER or not token_id or not c_nonce:
            _send_json_line(c, {'t': 'err', 'code': 'hello_invalid'})
            _safe_close(c)
            return

        with self._allowed_lock:
            token = self._tokenid_to_token.get(token_id)

        if not token:
            _send_json_line(c, {'t': 'err', 'code': 'token_unknown'})
            _safe_close(c)
            return

        s_nonce = uuid.uuid4().hex
        challenge = uuid.uuid4().hex
        ok = _send_json_line(c, {
            't': 'challenge',
            's_nonce': s_nonce,
            'challenge': challenge,
        })
        if not ok:
            _safe_close(c)
            return

        try:
            c.settimeout(HELLO_TIMEOUT)
        except Exception:
            pass
        line2 = _recv_line(c)
        if not line2:
            _send_json_line(c, {'t': 'err', 'code': 'hello2_timeout'})
            _safe_close(c)
            return
        try:
            h2 = json.loads(line2)
        except Exception:
            _send_json_line(c, {'t': 'err', 'code': 'hello2_bad_json'})
            _safe_close(c)
            return
        if str(h2.get('t') or '') != 'hello2':
            _send_json_line(c, {'t': 'err', 'code': 'hello2_invalid'})
            _safe_close(c)
            return

        sig = str(h2.get('sig') or '')
        msg_to_sign = f"{INTRANET_MAGIC}|{INTRANET_PROTO_VER}|{node_id}|{token_id}|{c_nonce}|{s_nonce}|{challenge}"
        expect = _hmac_hex(token, msg_to_sign)
        if not hmac.compare_digest(sig, expect):
            _send_json_line(c, {'t': 'err', 'code': 'sig_invalid'})
            _safe_close(c)
            return

        sess_id = uuid.uuid4().hex
        sess = _Session(
            token=token,
            token_id=token_id,
            node_id=node_id,
            session_id=sess_id,
            sock=c,
            connected_at=_now(),
            last_seen=_now(),
            last_pong_ms=_now_ms(),
            rtt_ms=None,
        )

        with self._sessions_lock:
            old = self._sessions_by_token.get(token)
            if old:
                _safe_close(old.sock)
            self._sessions_by_token[token] = sess

        _send_json_line(c, {
            't': 'ok',
            'session': sess_id,
            'handshake_ms': int(_now_ms() - started),
            'ping_interval': int(PING_INTERVAL),
        })
        _log('control_connected', port=self.port, node_id=node_id, token=_mask_token(token), session=sess_id)

        # control loop
        try:
            c.settimeout(1.0)
        except Exception:
            pass
        while not self._stop.is_set():
            # stale check
            if (_now() - sess.last_seen) > SESSION_STALE:
                _log('session_stale_drop', port=self.port, token=_mask_token(token), session=sess_id)
                break
            line = _recv_line(c)
            if line is None:
                break
            if line == '':
                continue
            try:
                m = json.loads(line)
            except Exception:
                continue
            typ = str(m.get('t') or '')
            sess.last_seen = _now()

            if typ == 'ping':
                seq = m.get('seq')
                echo_ts = m.get('ts')
                _send_json_line(c, {'t': 'pong', 'seq': seq, 'echo_ts': echo_ts, 'server_ts': _now_ms()})
                continue
            if typ == 'pong':
                try:
                    echo_ts = int(m.get('echo_ts') or 0)
                    if echo_ts > 0:
                        sess.rtt_ms = max(0, _now_ms() - echo_ts)
                    sess.last_pong_ms = _now_ms()
                except Exception:
                    pass
                continue
            if typ == 'open_fail':
                cid = str(m.get('id') or '')
                err = str(m.get('error') or 'open_fail')
                _log('open_fail', port=self.port, token=_mask_token(token), conn_id=cid, error=err)
                with self._pending_lock:
                    pc = self._pending.pop(cid, None)
                if pc:
                    _safe_close(pc.inbound)
                continue

        # cleanup session
        with self._sessions_lock:
            cur = self._sessions_by_token.get(token)
            if cur and cur.session_id == sess_id:
                self._sessions_by_token.pop(token, None)
        _safe_close(c)
        _log('control_disconnected', port=self.port, token=_mask_token(token), session=sess_id)

    def _handle_data(self, c: socket.socket, addr: Any, msg: Dict[str, Any]) -> None:
        # Data socket first line is JSON, then raw stream.
        magic = str(msg.get('magic') or '')
        ver = int(msg.get('v') or 0)
        token_id = str(msg.get('token_id') or '')
        conn_id = str(msg.get('id') or '')
        nonce = str(msg.get('nonce') or '')
        sig = str(msg.get('sig') or '')

        if magic != INTRANET_MAGIC or ver != INTRANET_PROTO_VER or not token_id or not conn_id or not nonce:
            _send_json_line(c, {'t': 'err', 'code': 'data_invalid'})
            _safe_close(c)
            return

        with self._allowed_lock:
            token = self._tokenid_to_token.get(token_id)

        if not token:
            _send_json_line(c, {'t': 'err', 'code': 'token_unknown'})
            _safe_close(c)
            return

        expect = _hmac_hex(token, f"data|{conn_id}|{nonce}")
        if not hmac.compare_digest(sig, expect):
            _send_json_line(c, {'t': 'err', 'code': 'sig_invalid'})
            _safe_close(c)
            return

        with self._pending_lock:
            pc = self._pending.pop(conn_id, None)

        if not pc:
            _send_json_line(c, {'t': 'err', 'code': 'conn_not_found'})
            _safe_close(c)
            return

        # Start raw relay
        _log('data_bound', port=self.port, token=_mask_token(token), conn_id=conn_id, remote=pc.remote)
        try:
            c.settimeout(None)
        except Exception:
            pass
        stop = threading.Event()
        threading.Thread(target=_relay, args=(pc.inbound, c, stop), daemon=True).start()

    def _cleanup_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(1.0)
            now = _now()
            # pending opens
            with self._pending_lock:
                for cid, pc in list(self._pending.items()):
                    if (now - pc.created_at) > OPEN_TIMEOUT:
                        _log('open_timeout', port=self.port, token=_mask_token(pc.token), conn_id=cid, remote=pc.remote)
                        self._pending.pop(cid, None)
                        _safe_close(pc.inbound)

            # sessions stale
            with self._sessions_lock:
                for tok, s in list(self._sessions_by_token.items()):
                    if (now - s.last_seen) > SESSION_STALE:
                        _log('session_stale_drop', port=self.port, token=_mask_token(tok), session=s.session_id)
                        self._sessions_by_token.pop(tok, None)
                        _safe_close(s.sock)


class _TCPListener:
    def __init__(self, rule: IntranetRule, server: _TunnelServer):
        self.rule = rule
        self.server = server
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None
        self._lsock: Optional[socket.socket] = None
        self._rr_idx = 0

    def start(self) -> None:
        if self._t and self._t.is_alive():
            return
        self._stop.clear()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        _log('tcp_listener_start', sync_id=self.rule.sync_id, listen=self.rule.listen)

    def stop(self) -> None:
        self._stop.set()
        if self._lsock:
            _safe_close(self._lsock)
        _log('tcp_listener_stop', sync_id=self.rule.sync_id)

    def _pick_remote(self) -> str:
        if not self.rule.remotes:
            return ''
        if (self.rule.balance or 'roundrobin') == 'random':
            # deterministic-ish random without importing random: hash time
            idx = int(hashlib.sha256(str(_now_ns()).encode()).hexdigest(), 16) % len(self.rule.remotes)
            return self.rule.remotes[idx]
        # roundrobin
        r = self.rule.remotes[self._rr_idx % len(self.rule.remotes)]
        self._rr_idx = (self._rr_idx + 1) % (10**9)
        return r

    def _run(self) -> None:
        host, port = _split_hostport(self.rule.listen)
        if port <= 0:
            return
        ls = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM)
        self._lsock = ls
        try:
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        try:
            ls.bind((host, port))
        except Exception:
            # fallback bind 0.0.0.0
            try:
                ls.bind(('0.0.0.0', port))
            except Exception as exc:
                _log('tcp_listener_bind_failed', sync_id=self.rule.sync_id, error=str(exc))
                return
        try:
            ls.listen(TCP_BACKLOG)
        except Exception as exc:
            _log('tcp_listener_listen_failed', sync_id=self.rule.sync_id, error=str(exc))
            return

        while not self._stop.is_set():
            try:
                ls.settimeout(1.0)
                c, addr = ls.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                _set_keepalive(c)
            except Exception:
                pass

            remote = self._pick_remote()
            if not remote:
                _safe_close(c)
                continue
            ok, info = self.server.request_open(self.rule.token, remote, c)
            if not ok:
                _log('open_reject', sync_id=self.rule.sync_id, error=info)
                _safe_close(c)
                continue
            # do not close 'c' here; it is owned by server pending/relay.


def _now_ns() -> int:
    try:
        return time.time_ns()
    except Exception:
        return int(_now() * 1e9)


class _TunnelClient:
    def __init__(self, peer_host: str, peer_port: int, token: str, node_id: int):
        self.peer_host = peer_host
        self.peer_port = int(peer_port)
        self.token = token
        self.token_id = _token_id(token)
        self.node_id = int(node_id)

        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None

        self._state_lock = threading.Lock()
        self._connected = False
        self._last_error: str = ''
        self._handshake_ms: Optional[int] = None
        self._rtt_ms: Optional[int] = None
        self._last_pong_at: Optional[int] = None
        self._last_attempt_at: Optional[int] = None
        self._last_connect_at: Optional[int] = None

    def start(self) -> None:
        if self._t and self._t.is_alive():
            return
        self._stop.clear()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def stop(self) -> None:
        self._stop.set()

    def get_state(self) -> Dict[str, Any]:
        with self._state_lock:
            return {
                'peer': f'{self.peer_host}:{self.peer_port}',
                'connected': bool(self._connected),
                'dial_mode': 'tcp',
                'last_error': self._last_error,
                'handshake_ms': self._handshake_ms,
                'rtt_ms': self._rtt_ms,
                'last_pong_at': self._last_pong_at,
                'last_attempt_at': self._last_attempt_at,
                'last_connect_at': self._last_connect_at,
            }

    def _set_state(self, **kw: Any) -> None:
        with self._state_lock:
            for k, v in kw.items():
                if k == 'connected':
                    self._connected = bool(v)
                elif k == 'last_error':
                    self._last_error = str(v or '')
                elif k == 'handshake_ms':
                    self._handshake_ms = int(v) if v is not None else None
                elif k == 'rtt_ms':
                    self._rtt_ms = int(v) if v is not None else None
                elif k == 'last_pong_at':
                    self._last_pong_at = int(v) if v is not None else None
                elif k == 'last_attempt_at':
                    self._last_attempt_at = int(v) if v is not None else None
                elif k == 'last_connect_at':
                    self._last_connect_at = int(v) if v is not None else None

    def _run(self) -> None:
        backoff = 0.8
        while not self._stop.is_set():
            self._set_state(connected=False)
            self._set_state(last_attempt_at=_now_ms())
            try:
                sock = socket.create_connection((self.peer_host, self.peer_port), timeout=6.0)
                _set_keepalive(sock)
            except Exception as exc:
                self._set_state(last_error=f'dial_failed: {exc}')
                time.sleep(backoff)
                backoff = min(5.0, backoff * 1.4)
                continue

            self._set_state(last_connect_at=_now_ms())
            try:
                sock.settimeout(HELLO_TIMEOUT)
            except Exception:
                pass

            hs_start = _now_ms()
            c_nonce = uuid.uuid4().hex
            ok = _send_json_line(sock, {
                't': 'hello',
                'magic': INTRANET_MAGIC,
                'v': INTRANET_PROTO_VER,
                'node': self.node_id,
                'token_id': self.token_id,
                'c_nonce': c_nonce,
            })
            if not ok:
                _safe_close(sock)
                self._set_state(last_error='hello_send_failed')
                time.sleep(backoff)
                continue

            line = _recv_line(sock)
            if not line:
                _safe_close(sock)
                self._set_state(last_error='challenge_timeout')
                time.sleep(backoff)
                continue

            try:
                ch = json.loads(line)
            except Exception:
                _safe_close(sock)
                self._set_state(last_error='challenge_bad_json')
                time.sleep(backoff)
                continue

            if str(ch.get('t') or '') == 'err':
                code = str(ch.get('code') or 'hello_reject')
                _safe_close(sock)
                self._set_state(last_error=code)
                time.sleep(backoff)
                continue

            if str(ch.get('t') or '') != 'challenge':
                _safe_close(sock)
                self._set_state(last_error='challenge_invalid')
                time.sleep(backoff)
                continue

            s_nonce = str(ch.get('s_nonce') or '')
            challenge = str(ch.get('challenge') or '')
            sig_msg = f"{INTRANET_MAGIC}|{INTRANET_PROTO_VER}|{self.node_id}|{self.token_id}|{c_nonce}|{s_nonce}|{challenge}"
            sig = _hmac_hex(self.token, sig_msg)
            ok = _send_json_line(sock, {'t': 'hello2', 'sig': sig})
            if not ok:
                _safe_close(sock)
                self._set_state(last_error='hello2_send_failed')
                time.sleep(backoff)
                continue

            line2 = _recv_line(sock)
            if not line2:
                _safe_close(sock)
                self._set_state(last_error='hello_ok_timeout')
                time.sleep(backoff)
                continue
            try:
                h2 = json.loads(line2)
            except Exception:
                _safe_close(sock)
                self._set_state(last_error='hello_ok_bad_json')
                time.sleep(backoff)
                continue

            if str(h2.get('t') or '') == 'err':
                code = str(h2.get('code') or 'hello_reject')
                _safe_close(sock)
                self._set_state(last_error=code)
                time.sleep(backoff)
                continue

            if str(h2.get('t') or '') != 'ok':
                _safe_close(sock)
                self._set_state(last_error='hello_ok_invalid')
                time.sleep(backoff)
                continue

            self._set_state(connected=True, last_error='', handshake_ms=int(_now_ms() - hs_start))
            self._set_state(last_pong_at=_now_ms())
            backoff = 0.8
            _log('client_connected', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token))

            # control loop with heartbeat
            try:
                sock.settimeout(1.0)
            except Exception:
                pass
            seq = 0
            next_ping = _now()
            while not self._stop.is_set():
                now = _now()
                # ping
                if now >= next_ping:
                    seq += 1
                    ts = _now_ms()
                    _send_json_line(sock, {'t': 'ping', 'seq': seq, 'ts': ts})
                    next_ping = now + PING_INTERVAL

                # pong timeout
                st = self.get_state()
                lp = st.get('last_pong_at')
                if lp and (_now_ms() - int(lp)) > int(PONG_TIMEOUT * 1000):
                    self._set_state(last_error='pong_timeout')
                    break

                line = _recv_line(sock)
                if line is None:
                    break
                if line == '':
                    continue
                try:
                    m = json.loads(line)
                except Exception:
                    continue

                typ = str(m.get('t') or '')
                if typ == 'pong':
                    echo_ts = int(m.get('echo_ts') or 0)
                    if echo_ts > 0:
                        self._set_state(rtt_ms=max(0, _now_ms() - echo_ts))
                    self._set_state(last_pong_at=_now_ms())
                    continue

                if typ == 'open':
                    conn_id = str(m.get('id') or '')
                    remote = str(m.get('remote') or '')
                    threading.Thread(target=self._handle_open, args=(sock, conn_id, remote), daemon=True).start()
                    continue

                if typ == 'err':
                    self._set_state(last_error=str(m.get('code') or 'server_err'))
                    break

            _safe_close(sock)
            self._set_state(connected=False)
            _log('client_disconnected', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token), err=self.get_state().get('last_error'))

    def _handle_open(self, ctrl_sock: socket.socket, conn_id: str, remote: str) -> None:
        # Connect to remote first
        host, port = _split_hostport(remote)
        if not host or port <= 0:
            _send_json_line(ctrl_sock, {'t': 'open_fail', 'id': conn_id, 'error': 'bad_remote'})
            return

        try:
            target = socket.create_connection((host, port), timeout=OPEN_TIMEOUT)
            _set_keepalive(target)
        except Exception as exc:
            _send_json_line(ctrl_sock, {'t': 'open_fail', 'id': conn_id, 'error': f'target_connect_failed: {exc}'})
            return

        # Then connect back to server for data
        try:
            data_sock = socket.create_connection((self.peer_host, self.peer_port), timeout=OPEN_TIMEOUT)
            _set_keepalive(data_sock)
            data_sock.settimeout(HELLO_TIMEOUT)
            nonce = uuid.uuid4().hex
            sig = _hmac_hex(self.token, f"data|{conn_id}|{nonce}")
            ok = _send_json_line(data_sock, {
                't': 'data',
                'magic': INTRANET_MAGIC,
                'v': INTRANET_PROTO_VER,
                'token_id': self.token_id,
                'id': conn_id,
                'nonce': nonce,
                'sig': sig,
            })
            if not ok:
                raise RuntimeError('data_hello_send_failed')
            # after first line, immediately switch to raw
            try:
                data_sock.settimeout(None)
                target.settimeout(None)
            except Exception:
                pass
        except Exception as exc:
            _send_json_line(ctrl_sock, {'t': 'open_fail', 'id': conn_id, 'error': f'data_dial_failed: {exc}'})
            _safe_close(target)
            _safe_close(data_sock)
            return

        _log('open_ok', peer=f'{self.peer_host}:{self.peer_port}', conn_id=conn_id, remote=remote)
        stop = threading.Event()
        threading.Thread(target=_relay, args=(target, data_sock, stop), daemon=True).start()


class IntranetManager:
    """Supervise intranet tunnels based on pool_full.json endpoints."""

    def __init__(self, node_id: int):
        self.node_id = int(node_id)
        self._lock = threading.Lock()
        self._servers: Dict[int, _TunnelServer] = {}
        self._tcp_listeners: Dict[str, _TCPListener] = {}  # sync_id -> listener
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
                sessions = []
                with s._sessions_lock:
                    for tok, sess in list(s._sessions_by_token.items()):
                        sessions.append({
                            'token': _mask_token(tok),
                            'token_id': sess.token_id[:8] + '…' if sess.token_id else '',
                            'node_id': sess.node_id,
                            'connected_at': int(sess.connected_at),
                            'last_seen_at': int(sess.last_seen),
                            'rtt_ms': sess.rtt_ms,
                        })
                servers.append({'port': int(p), 'tls': False, 'sessions': sessions})

            clients = []
            for key, c in self._clients.items():
                st = c.get_state()
                st['key'] = key
                clients.append(st)

            rules_view = []
            for sync_id, r in self._last_rules.items():
                rules_view.append({
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
                'udp_rules': [],
                'clients': clients,
                'rules': rules_view,
            }

    def handshake_health(self, sync_id: str, ex: Dict[str, Any]) -> Dict[str, Any]:
        role = str(ex.get('intranet_role') or '').strip()
        token = str(ex.get('intranet_token') or '').strip()
        try:
            port = int(ex.get('intranet_server_port') or DEFAULT_TUNNEL_PORT)
        except Exception:
            port = DEFAULT_TUNNEL_PORT

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
            return {'ok': True, 'latency_ms': int(latency)}

        if role == 'client':
            peer_host = str(ex.get('intranet_peer_host') or '').strip()
            key = f"{peer_host}:{port}:{_token_id(token)}" if peer_host and token else ''
            c = self._clients.get(key) if key else None
            if not c:
                return {'ok': False, 'error': 'client_not_running'}
            st = c.get_state()
            if st.get('connected'):
                payload: Dict[str, Any] = {'ok': True}
                if st.get('rtt_ms') is not None:
                    payload['latency_ms'] = int(st.get('rtt_ms') or 0)
                elif st.get('handshake_ms') is not None:
                    payload['latency_ms'] = int(st.get('handshake_ms') or 0)
                return payload
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
            # Force TCP only (ignore udp/tcp+udp)
            protocol = 'tcp'
            balance = str(e.get('balance') or 'roundrobin').strip() or 'roundrobin'

            remotes: List[str] = []
            if isinstance(e.get('remotes'), list):
                remotes = [str(x).strip() for x in e.get('remotes') if str(x).strip()]
            elif isinstance(e.get('remote'), str) and e.get('remote'):
                remotes = [str(e.get('remote')).strip()]

            token = str(ex.get('intranet_token') or '').strip()
            if not token:
                continue
            try:
                peer_node_id = int(ex.get('intranet_peer_node_id') or 0)
            except Exception:
                peer_node_id = 0
            peer_host = str(ex.get('intranet_peer_host') or '').strip()
            try:
                tunnel_port = int(ex.get('intranet_server_port') or DEFAULT_TUNNEL_PORT)
            except Exception:
                tunnel_port = DEFAULT_TUNNEL_PORT

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
            )
        return out

    def _apply_rules_locked(self, rules: Dict[str, IntranetRule]) -> None:
        # Start/stop servers by port, set allowed tokens
        tokens_by_port: Dict[int, set[str]] = {}
        for r in rules.values():
            if r.role == 'server':
                tokens_by_port.setdefault(r.tunnel_port, set()).add(r.token)

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

        # Server-side TCP listeners
        for sync_id, r in rules.items():
            if r.role != 'server':
                continue
            srv = self._servers.get(r.tunnel_port)
            if not srv:
                continue
            if sync_id not in self._tcp_listeners:
                lis = _TCPListener(r, srv)
                lis.start()
                self._tcp_listeners[sync_id] = lis

        for sync_id in list(self._tcp_listeners.keys()):
            if sync_id not in rules or rules[sync_id].role != 'server':
                self._tcp_listeners[sync_id].stop()
                self._tcp_listeners.pop(sync_id, None)

        # Client dialers
        desired: Dict[str, _TunnelClient] = {}
        for r in rules.values():
            if r.role != 'client':
                continue
            key = f"{r.peer_host}:{r.tunnel_port}:{_token_id(r.token)}"
            c = self._clients.get(key)
            if not c:
                c = _TunnelClient(peer_host=r.peer_host, peer_port=r.tunnel_port, token=r.token, node_id=self.node_id)
                c.start()
            desired[key] = c

        for key in list(self._clients.keys()):
            if key not in desired:
                self._clients[key].stop()
                self._clients.pop(key, None)

        self._last_rules = rules
