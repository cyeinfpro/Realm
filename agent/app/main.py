from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import time
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, HTTPException, Request

from .config import CFG

API_KEY_FILE = Path('/etc/realm-agent/api.key')
POOL_FULL = Path('/etc/realm/pool_full.json')
POOL_ACTIVE = Path('/etc/realm/pool.json')
POOL_RUN_FILTER = Path('/etc/realm/pool_to_run.jq')
FALLBACK_RUN_FILTER = Path(__file__).resolve().parents[1] / 'pool_to_run.jq'
REALM_CONFIG = Path(CFG.realm_config_file)
TRAFFIC_TOTALS: Dict[int, Dict[str, Any]] = {}
TCPING_TIMEOUT = 2.0

# 规则连通探测（面板「连通检测」）
# 目标：
# 1) 永远返回可渲染的数据（不因为探测阻塞导致 /stats 超时）
# 2) 返回稳定的延迟（ms），优先使用 socket 直连测量
# 3) 支持并发探测 + 短缓存，避免规则多时整页卡死
# 默认更快：并发探测 + 短缓存下，0.45s 基本够用；若你想更稳可通过环境变量调大。
PROBE_CACHE_TTL = float(os.getenv('REALM_AGENT_PROBE_TTL', '5'))  # seconds
PROBE_TIMEOUT = float(os.getenv('REALM_AGENT_PROBE_TIMEOUT', '0.45'))  # per attempt
PROBE_RETRIES = int(os.getenv('REALM_AGENT_PROBE_RETRIES', '1'))
PROBE_MAX_WORKERS = int(os.getenv('REALM_AGENT_PROBE_WORKERS', '32'))

_PROBE_CACHE: Dict[str, Dict[str, Any]] = {}
_PROBE_LOCK = threading.Lock()


def _read_text(p: Path) -> str:
    return p.read_text(encoding='utf-8')


def _write_text(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')


def _read_json(p: Path, default: Any) -> Any:
    try:
        return json.loads(_read_text(p))
    except FileNotFoundError:
        return default
    except Exception:
        return default


def _write_json(p: Path, data: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    _write_text(p, json.dumps(data, ensure_ascii=False, indent=2))


def _api_key_required(req: Request) -> None:
    api_key = req.headers.get('x-api-key', '')
    try:
        expected = _read_text(API_KEY_FILE).strip()
    except FileNotFoundError:
        raise HTTPException(status_code=401, detail='Agent未初始化API Key')
    if not expected or api_key != expected:
        raise HTTPException(status_code=401, detail='API Key 无效')


def _service_is_active(name: str) -> bool:
    r = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip() == 'active':
        return True
    if shutil.which('service'):
        r = subprocess.run(['service', name, 'status'], capture_output=True, text=True)
        if r.returncode == 0:
            return True
    if shutil.which('rc-service'):
        r = subprocess.run(['rc-service', name, 'status'], capture_output=True, text=True)
        return r.returncode == 0
    return False


def _restart_realm() -> None:
    candidates = []
    if CFG.realm_service:
        candidates.append(CFG.realm_service)
    candidates.extend(['realm.service', 'realm'])
    seen = set()
    services = [s for s in candidates if s and not (s in seen or seen.add(s))]
    errors = []
    for svc in services:
        r = subprocess.run(['systemctl', 'restart', svc], capture_output=True, text=True)
        if r.returncode == 0:
            return
        errors.append(f"systemctl {svc}: {r.stderr.strip() or r.stdout.strip()}")
    if shutil.which('service'):
        for svc in services:
            r = subprocess.run(['service', svc, 'restart'], capture_output=True, text=True)
            if r.returncode == 0:
                return
            errors.append(f"service {svc}: {r.stderr.strip() or r.stdout.strip()}")
    if shutil.which('rc-service'):
        for svc in services:
            r = subprocess.run(['rc-service', svc, 'restart'], capture_output=True, text=True)
            if r.returncode == 0:
                return
            errors.append(f"rc-service {svc}: {r.stderr.strip() or r.stdout.strip()}")
    detail = "; ".join([e for e in errors if e]) or "unknown error"
    raise RuntimeError(f'无法重启 realm 服务（尝试 {", ".join(services)} 失败）：{detail}')


def _apply_pool_to_config() -> None:
    if not shutil.which('jq'):
        raise RuntimeError('缺少 jq 命令，无法生成 realm 配置')
    if not POOL_RUN_FILTER.exists():
        if FALLBACK_RUN_FILTER.exists():
            _write_text(POOL_RUN_FILTER, FALLBACK_RUN_FILTER.read_text(encoding='utf-8').strip() + '\n')
        else:
            raise RuntimeError(f'缺少JQ过滤器: {POOL_RUN_FILTER}')
    if not POOL_FULL.exists():
        active = _read_json(POOL_ACTIVE, {'endpoints': []})
        eps = active.get('endpoints') or []
        for e in eps:
            e.setdefault('disabled', False)
        _write_json(POOL_FULL, {'endpoints': eps})

    # jq -c -f filter pool_full.json > /etc/realm/config.json
    cmd = ['jq', '-c', '-f', str(POOL_RUN_FILTER), str(POOL_FULL)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'JQ生成config失败: {r.stderr.strip()}')
    _write_text(REALM_CONFIG, r.stdout.strip() + '\n')


def _sync_active_pool() -> None:
    full = _read_json(POOL_FULL, {'endpoints': []})
    eps = full.get('endpoints') or []
    active_eps = [e for e in eps if not bool(e.get('disabled'))]
    _write_json(POOL_ACTIVE, {'endpoints': active_eps})


def _parse_listen_port(listen: str) -> int:
    # listen = "0.0.0.0:443" or "[::]:443"
    if not listen:
        return 0
    if listen.count(':') == 1:
        return int(listen.split(':')[-1])
    # ipv6 like [::]:443
    if listen.endswith(']'):
        return 0
    if ']' in listen:
        return int(listen.split(']:')[-1])
    return int(listen.rsplit(':', 1)[-1])


# --- 连接数与流量统计：一次 ss 扫描，避免每条规则都跑 ss 导致偶发超时 ---
# 现象：规则多/连接多时，/api/v1/stats 会触发大量 subprocess.run(ss...)，
# 可能短时间卡住，面板侧会表现为“HTTP 502 / 检测失败”。
# 方案：
# 1) 每次 stats 只扫描一次 `ss -Htin state established`，并按端口聚合；
# 2) 增量累计 bytes，保证总流量可持续增长；
# 3) 给 ss 加 timeout + 短缓存，确保接口稳定快速返回。

_SS_CACHE_LOCK = threading.Lock()
_SS_CACHE_TS = 0.0
_SS_CACHE_DATA: Dict[int, Dict[str, int]] = {}
_SS_CACHE_ERR: str | None = None
SS_CACHE_TTL = float(os.environ.get('REALM_SS_CACHE_TTL', '0.6'))
SS_RUN_TIMEOUT = float(os.environ.get('REALM_SS_TIMEOUT', '1.0'))


def _addr_to_port(addr: str) -> int:
    """从 ss 输出的地址字段解析端口。支持：
    - 1.2.3.4:443
    - [::1]:443
    - *:443
    """
    if not addr:
        return 0
    try:
        if addr.startswith('[') and ']' in addr:
            # [::1]:443
            return int(addr.split(']:')[-1])
        return int(addr.rsplit(':', 1)[-1])
    except Exception:
        return 0


def _scan_ss_once(target_ports: set[int]) -> tuple[Dict[int, Dict[str, int]], str | None]:
    """扫描一次 ss 并聚合为：{port: {connections, rx_bytes, tx_bytes}}。

    备注：rx/tx 使用 TRAFFIC_TOTALS 做增量累计；connections 为当前 established 连接数。
    """
    if not target_ports:
        return {}, None
    if not shutil.which('ss'):
        # 没有 ss，退化为 0
        out = {p: {'connections': 0, 'rx_bytes': 0, 'tx_bytes': 0} for p in target_ports}
        return out, '缺少 ss 命令'

    # 初始化返回数据（即使 ss 失败也能有结构）
    result: Dict[int, Dict[str, int]] = {}
    for p in target_ports:
        totals = TRAFFIC_TOTALS.get(p) or {'sum_rx': 0, 'sum_tx': 0, 'conns': {}}
        result[p] = {
            'connections': 0,
            'rx_bytes': int(totals.get('sum_rx') or 0),
            'tx_bytes': int(totals.get('sum_tx') or 0),
        }

    cmd = ['bash', '-lc', 'ss -Htin state established 2>/dev/null']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=SS_RUN_TIMEOUT)
    except Exception as exc:
        return result, f'ss 执行失败: {exc}'

    if r.returncode != 0:
        return result, 'ss 返回非 0'

    # 记录本次仍存活的连接 key，用于清理已断开的连接
    seen_by_port: Dict[int, set[str]] = {p: set() for p in target_ports}

    def apply_bytes(line_text: str, target_port: int, conn_key: str) -> bool:
        rx_matches = re.findall(r"bytes_received:(\d+)", line_text)
        tx_matches = re.findall(r"bytes_acked:(\d+)", line_text)
        if not tx_matches:
            tx_matches = re.findall(r"bytes_sent:(\d+)", line_text)
        if not rx_matches and not tx_matches:
            return False

        rx_value = int(rx_matches[-1]) if rx_matches else 0
        tx_value = int(tx_matches[-1]) if tx_matches else 0

        totals = TRAFFIC_TOTALS.setdefault(target_port, {'sum_rx': 0, 'sum_tx': 0, 'conns': {}})
        conns: Dict[str, Dict[str, int]] = totals['conns']
        last = conns.get(conn_key)
        if last is None:
            totals['sum_rx'] += rx_value
            totals['sum_tx'] += tx_value
            conns[conn_key] = {'last_rx': rx_value, 'last_tx': tx_value}
        else:
            totals['sum_rx'] += rx_value - last['last_rx'] if rx_value >= last['last_rx'] else rx_value
            totals['sum_tx'] += tx_value - last['last_tx'] if tx_value >= last['last_tx'] else tx_value
            last['last_rx'] = rx_value
            last['last_tx'] = tx_value
        return True

    pending: tuple[int, str] | None = None

    addr_re = re.compile(r"^(?:\\[[^\\]]+\\]|\\*|[0-9A-Fa-f:.]+):\\d+$")

    for raw_line in (r.stdout or '').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        addrs = [p for p in parts if addr_re.match(p)]
        if len(addrs) >= 2:
            local = addrs[-2]
            peer = addrs[-1]
            port = _addr_to_port(local)
            if port not in target_ports:
                pending = None
                continue

            # 当前连接数
            result[port]['connections'] += 1

            # 增量累计流量
            key = f"{local}->{peer}"
            seen_by_port[port].add(key)
            pending = (port, key)
            if apply_bytes(raw_line, port, key):
                pending = None
            continue

        if pending is not None:
            port, key = pending
            if apply_bytes(raw_line, port, key):
                pending = None

    # 清理断开的连接，避免 conns 膨胀
    for p, seen in seen_by_port.items():
        totals = TRAFFIC_TOTALS.get(p)
        if not totals:
            continue
        conns = totals.get('conns') or {}
        for k in list(conns.keys()):
            if k not in seen:
                del conns[k]

        # 回写累计值到 result
        result[p]['rx_bytes'] = int(totals.get('sum_rx') or 0)
        result[p]['tx_bytes'] = int(totals.get('sum_tx') or 0)

    return result, None


def _collect_conn_traffic(target_ports: set[int]) -> tuple[Dict[int, Dict[str, int]], str | None]:
    """带短缓存的 ss 聚合结果。"""
    global _SS_CACHE_TS, _SS_CACHE_DATA, _SS_CACHE_ERR
    now = time.monotonic()
    with _SS_CACHE_LOCK:
        if _SS_CACHE_DATA and (now - _SS_CACHE_TS) <= SS_CACHE_TTL:
            # 直接复用缓存（并按需过滤端口）
            filtered = {p: _SS_CACHE_DATA.get(p, {'connections': 0, 'rx_bytes': 0, 'tx_bytes': 0}) for p in target_ports}
            return filtered, _SS_CACHE_ERR

        data, err = _scan_ss_once(target_ports)
        _SS_CACHE_TS = now
        _SS_CACHE_DATA = data
        _SS_CACHE_ERR = err
        return data, err


def _conn_count(port: int) -> int:
    """兼容旧调用：优先使用缓存的 ss 聚合结果。"""
    if port <= 0:
        return 0
    data, _ = _collect_conn_traffic({port})
    return int((data.get(port) or {}).get('connections') or 0)


def _traffic_bytes(port: int) -> tuple[int, int]:
    """兼容旧调用：优先使用缓存的 ss 聚合结果。"""
    if port <= 0:
        return 0, 0
    data, _ = _collect_conn_traffic({port})
    d = data.get(port) or {}
    return int(d.get('rx_bytes') or 0), int(d.get('tx_bytes') or 0)


def _parse_tcping_latency(output: str) -> float | None:
    matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)\s*ms", output, re.IGNORECASE)
    if matches:
        return float(matches[-1])
    match = re.search(r"time[=<]?\s*([0-9.]+)\s*ms", output, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None


def _parse_tcping_result(output: str, returncode: int) -> tuple[bool, float | None]:
    latency = _parse_tcping_latency(output)
    if latency is not None:
        return True, latency
    if returncode == 0:
        return True, None
    if re.search(r"\bopen\b", output, re.IGNORECASE):
        return True, None
    if re.search(r"\bconnected\b", output, re.IGNORECASE):
        return True, None
    return False, None


def _probe_cache_key(host: str, port: int) -> str:
    # host 可能是域名 / IPv4 / IPv6(不带[])
    return f"{host}:{port}"


def _cache_get(key: str) -> Dict[str, Any] | None:
    now = time.monotonic()
    with _PROBE_LOCK:
        item = _PROBE_CACHE.get(key)
        if not item:
            return None
        if now - float(item.get('ts', 0)) > PROBE_CACHE_TTL:
            _PROBE_CACHE.pop(key, None)
            return None
        return dict(item)


def _cache_set(key: str, ok: bool, latency_ms: float | None, error: str | None = None) -> None:
    with _PROBE_LOCK:
        _PROBE_CACHE[key] = {
            'ts': time.monotonic(),
            'ok': bool(ok),
            'latency_ms': latency_ms,
            'error': error,
        }


def _tcp_probe_uncached(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[bool, float | None, str | None]:
    """尽可能稳定的 TCP 探测：

    - 优先用 socket 直连测延迟（ms），更稳定
    - tcping 若存在仅作为补充（有些系统输出不稳定）
    """
    # 先尝试 socket（最快、最稳定）
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = (time.monotonic() - start) * 1000
            return True, round(latency_ms, 2), None
    except Exception as exc:
        sock_err = str(exc)

    # 再尝试 tcping（如果安装了），有时能在某些网络下更快给出“open/connected”
    tcping = shutil.which('tcping')
    if not tcping:
        return False, None, sock_err
    cmd = [tcping, '-c', '1', '-t', str(max(1, int(TCPING_TIMEOUT))), host, str(port)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TCPING_TIMEOUT + 1)
    except Exception as exc:
        return False, None, sock_err or str(exc)
    output = (result.stdout or '') + (result.stderr or '')
    ok, latency = _parse_tcping_result(output, result.returncode)
    if ok:
        return True, round(latency, 2) if latency is not None else None, None
    return False, None, sock_err


def _tcp_probe_detail(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> Dict[str, Any]:
    """带短缓存 + 重试的 TCP 探测（返回详细原因）。

    返回结构：
      { ok: bool, latency_ms?: float, error?: str }

    这个函数 **绝不抛异常**，确保 /api/v1/stats 不会因为探测报错或阻塞而失败。
    """
    key = _probe_cache_key(host, port)
    cached = _cache_get(key)
    if cached is not None:
        return {
            'ok': bool(cached.get('ok')),
            'latency_ms': cached.get('latency_ms'),
            'error': cached.get('error'),
        }

    last_err: str | None = None
    best_latency: float | None = None
    for i in range(max(1, PROBE_RETRIES)):
        per_timeout = timeout if i == 0 else min(timeout * 1.4, 1.2)
        ok, latency_ms, err = _tcp_probe_uncached(host, port, per_timeout)
        if ok:
            if latency_ms is not None:
                best_latency = latency_ms if best_latency is None else min(best_latency, latency_ms)
            _cache_set(key, True, best_latency, None)
            return {'ok': True, 'latency_ms': best_latency}
        last_err = err or last_err

    _cache_set(key, False, None, last_err)
    return {'ok': False, 'error': last_err}


def _tcp_probe(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[bool, float | None]:
    """兼容旧调用：仅返回 (ok, latency_ms)。"""
    d = _tcp_probe_detail(host, port, timeout)
    return bool(d.get('ok')), d.get('latency_ms')


def _split_hostport(addr: str) -> tuple[str, int]:
    # addr like 1.2.3.4:443 or [::1]:443
    if addr.startswith('['):
        host, rest = addr.split(']', 1)
        host = host[1:]
        port = int(rest.lstrip(':'))
        return host.strip(), port
    host, p = addr.rsplit(':', 1)
    return host.strip(), int(p)


def _load_full_pool() -> Dict[str, Any]:
    full = _read_json(POOL_FULL, None)
    if full is None:
        active = _read_json(POOL_ACTIVE, {'endpoints': []})
        eps = active.get('endpoints') or []
        for e in eps:
            if isinstance(e, dict):
                e.setdefault('disabled', False)
        full = {'endpoints': eps}
        _write_json(POOL_FULL, full)
        return full
    eps = full.get('endpoints') or []
    for e in eps:
        if isinstance(e, dict):
            e.setdefault('disabled', False)
    full['endpoints'] = eps
    return full


def _build_health_entries(rule: Dict[str, Any], remotes: List[str]) -> List[Dict[str, Any]]:
    if rule.get('disabled'):
        return [{'target': '—', 'ok': None, 'message': '规则已暂停'}]
    if not remotes:
        return [{'target': '—', 'ok': None, 'message': '未配置目标'}]
    protocol = str(rule.get('protocol') or 'tcp+udp').lower()
    tcp_probe_enabled = 'tcp' in protocol
    if not tcp_probe_enabled:
        return [{'target': r, 'ok': None, 'message': '协议不支持探测'} for r in remotes]

    health: List[Dict[str, Any]] = []
    for r in remotes:
        try:
            h, p = _split_hostport(r)
        except Exception:
            health.append({'target': r, 'ok': None, 'message': '目标格式无效'})
            continue
        ok, latency_ms = _tcp_probe(h, p)
        payload = {'target': r, 'ok': ok}
        if latency_ms is not None:
            payload['latency_ms'] = latency_ms
        health.append(payload)
    return health


_TRANSPORT_HOST_RE = re.compile(r"host=([^;]+)")


def _parse_transport_host(transport: str) -> str | None:
    if not transport:
        return None
    m = _TRANSPORT_HOST_RE.search(transport)
    if not m:
        return None
    return m.group(1).strip() or None


def _wss_probe_entries(rule: Dict[str, Any]) -> List[Dict[str, str]]:
    """为 WSS 隧道补充探测目标。

    面板常见困扰：WSS 规则的 remote 目标并不是「真正要连的公网域名/端口」，
    导致探测永远离线。这里补一个 “WSS Host” 探测，至少能反映隧道外层是否可达。
    """
    ex = rule.get('extra_config') or {}
    listen = str(rule.get('listen') or '')
    entries: List[Dict[str, str]] = []

    # remote_transport: ws;host=xxx;path=/ws;tls;...
    remote_transport = str(rule.get('remote_transport') or ex.get('remote_transport') or '')
    remote_ws_host = str(ex.get('remote_ws_host') or '').strip() or _parse_transport_host(remote_transport)
    if remote_ws_host:
        tls = bool(ex.get('remote_tls_enabled')) or ('tls' in remote_transport)
        port = 443 if tls else 80
        entries.append({'key': f"{remote_ws_host}:{port}", 'label': f"WSS {remote_ws_host}:{port}"})

    # listen_transport: ws;...  => 探测本机 listen 端口是否在监听（避免显示空白）
    listen_transport = str(rule.get('listen_transport') or ex.get('listen_transport') or '')
    if ('ws' in listen_transport) or ex.get('listen_ws_host'):
        try:
            lp = _parse_listen_port(listen)
        except Exception:
            lp = 0
        if lp > 0:
            # 为 WSS 接收规则补充本机监听探测，便于确认 listen 端口是否真的在跑。
            entries.append({'key': f"127.0.0.1:{lp}", 'label': f"本机监听 127.0.0.1:{lp}"})

    return entries


app = FastAPI(title='Realm Agent', version='31')
REALM_SERVICE_NAMES = [s for s in [CFG.realm_service, 'realm.service', 'realm'] if s]


@app.get('/api/v1/info')
def api_info(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    return {
        'ok': True,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': socket.gethostname(),
        'realm_active': any(_service_is_active(name) for name in REALM_SERVICE_NAMES),
    }


@app.get('/api/v1/pool')
def api_pool(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    full = _read_json(POOL_FULL, None)
    if full is None:
        # 兼容只存在 pool.json 的机器
        active = _read_json(POOL_ACTIVE, {'endpoints': []})
        eps = active.get('endpoints') or []
        for e in eps:
            e.setdefault('disabled', False)
        full = {'endpoints': eps}
        _write_json(POOL_FULL, full)
    # 强制包含 disabled
    eps = full.get('endpoints') or []
    for e in eps:
        e.setdefault('disabled', False)
    return {'ok': True, 'pool': full}


@app.post('/api/v1/pool')
def api_pool_save(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    pool = payload.get('pool') if isinstance(payload, dict) else None
    if not isinstance(pool, dict):
        raise HTTPException(status_code=400, detail='缺少 pool 字段')
    eps = pool.get('endpoints')
    if not isinstance(eps, list):
        raise HTTPException(status_code=400, detail='pool.endpoints 必须是数组')
    for e in eps:
        if isinstance(e, dict):
            e.setdefault('disabled', False)
    _write_json(POOL_FULL, pool)
    _sync_active_pool()
    return {'ok': True}


@app.post('/api/v1/apply')
def api_apply(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    try:
        _sync_active_pool()
        _apply_pool_to_config()
        _restart_realm()
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}
    return {'ok': True}


@app.get('/api/v1/stats')
def api_stats(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    """规则统计 + 连通探测。

    旧版本逐条、逐目标串行探测，规则多时很容易让面板的 /stats 调用超时，从而表现为
    “连通检测不起作用”。这里改成：
    - 全部目标并发探测
    - 短缓存复用探测结果
    - WSS 规则补充探测 WSS Host（显示真实外层延迟）
    """
    full = _load_full_pool()
    eps = full.get('endpoints') or []

    # 收集每条规则要渲染的 health entries（label/key），同时汇总全局需要探测的 key
    per_rule_entries: List[List[Dict[str, str]]] = []
    all_probe_keys: List[str] = []
    all_probe_set: set[str] = set()

    for e in eps:
        entries: List[Dict[str, str]] = []
        if e.get('disabled'):
            # 规则暂停：无需探测，但仍保证面板有可渲染内容
            entries.append({'key': '—', 'label': '—', 'message': '规则已暂停'})
            per_rule_entries.append(entries)
            continue

        remotes: List[str] = []
        if isinstance(e.get('remote'), str) and e.get('remote'):
            remotes.append(e['remote'])
        if isinstance(e.get('remotes'), list):
            remotes += [str(x) for x in e.get('remotes') if x]
        if isinstance(e.get('extra_remotes'), list):
            remotes += [str(x) for x in e.get('extra_remotes') if x]

        # 去重 + 限制数量（防止规则过多时探测过载）
        seen = set()
        remotes = [r for r in remotes if r and not (r in seen or seen.add(r))][:8]

        if not remotes:
            entries.append({'key': '—', 'label': '—', 'message': '未配置目标'})
        else:
            for r in remotes:
                entries.append({'key': r, 'label': r})
                if r not in all_probe_set:
                    all_probe_set.add(r)
                    all_probe_keys.append(r)

        # WSS 规则补充探测项（WSS Host / LISTEN 本地端口）
        for extra in _wss_probe_entries(e):
            entries.append(extra)
            k = extra.get('key')
            if k and k not in all_probe_set:
                all_probe_set.add(k)
                all_probe_keys.append(k)

        per_rule_entries.append(entries)

    # 并发探测所有目标（总耗时约等于最慢目标的超时）
    probe_results: Dict[str, Dict[str, Any]] = {}
    if all_probe_keys:
        max_workers = max(4, min(PROBE_MAX_WORKERS, len(all_probe_keys)))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            fut_map = {}
            for key in all_probe_keys:
                # key 可能是 "—" 或格式不合法，先做保护
                try:
                    host, port = _split_hostport(key)
                except Exception:
                    probe_results[key] = {'ok': None, 'message': '目标格式无效'}
                    continue
                fut = ex.submit(_tcp_probe_detail, host, port, PROBE_TIMEOUT)
                fut_map[fut] = key

            for fut in as_completed(fut_map):
                key = fut_map[fut]
                try:
                    payload = fut.result(timeout=PROBE_TIMEOUT * max(1, PROBE_RETRIES) + 0.6)
                    if not isinstance(payload, dict):
                        probe_results[key] = {'ok': None, 'message': '探测返回异常'}
                    else:
                        probe_results[key] = payload
                except Exception as exc:
                    probe_results[key] = {'ok': None, 'message': f'探测异常: {exc}'}

    # 连接数/流量：一次性聚合（避免每条规则重复调用 ss）
    listen_ports: set[int] = set()
    for e in eps:
        listen = (e.get('listen') or '').strip()
        try:
            p = _parse_listen_port(listen)
        except Exception:
            p = 0
        if p > 0:
            listen_ports.add(p)

    conn_traffic_map, ss_err = _collect_conn_traffic(listen_ports)

    # 组装规则统计
    rules: List[Dict[str, Any]] = []
    for idx, e in enumerate(eps):
        listen = (e.get('listen') or '').strip()
        try:
            port = _parse_listen_port(listen)
        except Exception:
            port = 0

        ct = conn_traffic_map.get(port) or {'connections': 0, 'rx_bytes': 0, 'tx_bytes': 0}
        rx_bytes = int(ct.get('rx_bytes') or 0)
        tx_bytes = int(ct.get('tx_bytes') or 0)

        health: List[Dict[str, Any]] = []
        entries = per_rule_entries[idx] if idx < len(per_rule_entries) else []
        protocol = str(e.get('protocol') or 'tcp+udp').lower()
        tcp_probe_enabled = ('tcp' in protocol) and (not bool(e.get('disabled')))

        for it in entries:
            label = it.get('label', '—')
            key = it.get('key', label)
            # 特殊占位项（暂停 / 无目标等）
            if it.get('message'):
                health.append({'target': label, 'ok': None, 'message': it['message']})
                continue

            if not tcp_probe_enabled:
                # UDP-only 或其他协议，不做 TCP 探测
                health.append({'target': label, 'ok': None, 'message': '协议不支持探测'})
                continue

            res = probe_results.get(key)
            if not res:
                health.append({'target': label, 'ok': None, 'message': '暂无检测数据'})
                continue
            if res.get('ok') is None:
                health.append({'target': label, 'ok': None, 'message': res.get('message', '不可检测')})
                continue
            payload: Dict[str, Any] = {'target': label, 'ok': bool(res.get('ok'))}
            if res.get('latency_ms') is not None:
                payload['latency_ms'] = res.get('latency_ms')
            # 离线原因（面板可展示）
            if payload['ok'] is False and res.get('error'):
                payload['error'] = res.get('error')
            health.append(payload)

        rules.append({
            'idx': idx,
            'listen': listen,
            'disabled': bool(e.get('disabled')),
            'connections': int(ct.get('connections') or 0),
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'health': health,
        })

    resp: Dict[str, Any] = {'ok': True, 'rules': rules}
    if ss_err:
        resp['warning'] = ss_err
    return resp
