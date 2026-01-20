from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import time
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


def _conn_count(port: int) -> int:
    if port <= 0:
        return 0
    if not shutil.which('ss'):
        return 0
    # 只统计 TCP established（足够用了）
    cmd = ['bash', '-lc', f"ss -Htan state established sport = :{port} 2>/dev/null | wc -l"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return 0
    try:
        return int(r.stdout.strip())
    except Exception:
        return 0


def _traffic_bytes(port: int) -> tuple[int, int]:
    if port <= 0:
        return 0, 0
    if not shutil.which('ss'):
        return 0, 0
    cmd = ['bash', '-lc', f"ss -Htin state established sport = :{port} 2>/dev/null"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return 0, 0
    totals = TRAFFIC_TOTALS.setdefault(port, {'sum_rx': 0, 'sum_tx': 0, 'conns': {}})
    conns: Dict[str, Dict[str, int]] = totals['conns']
    seen = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        peer = parts[4]
        key = f"{local}->{peer}"
        seen.add(key)
        rx_matches = re.findall(r"bytes_received:(\d+)", line)
        tx_matches = re.findall(r"bytes_acked:(\d+)", line)
        if not tx_matches:
            tx_matches = re.findall(r"bytes_sent:(\d+)", line)
        rx_value = int(rx_matches[-1]) if rx_matches else 0
        tx_value = int(tx_matches[-1]) if tx_matches else 0
        last = conns.get(key)
        if last is None:
            totals['sum_rx'] += rx_value
            totals['sum_tx'] += tx_value
            conns[key] = {'last_rx': rx_value, 'last_tx': tx_value}
        else:
            if rx_value >= last['last_rx']:
                totals['sum_rx'] += rx_value - last['last_rx']
            else:
                totals['sum_rx'] += rx_value
            if tx_value >= last['last_tx']:
                totals['sum_tx'] += tx_value - last['last_tx']
            else:
                totals['sum_tx'] += tx_value
            last['last_rx'] = rx_value
            last['last_tx'] = tx_value
    for key in list(conns.keys()):
        if key not in seen:
            del conns[key]
    return totals['sum_rx'], totals['sum_tx']


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


def _tcp_probe(host: str, port: int, timeout: float = 0.8) -> tuple[bool, float | None]:
    tcping = shutil.which("tcping")
    if tcping:
        cmd = [
            tcping,
            "-c",
            "1",
            "-t",
            str(int(TCPING_TIMEOUT)),
            host,
            str(port),
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TCPING_TIMEOUT + 1,
            )
        except Exception:
            return False, None
        output = (result.stdout or "") + (result.stderr or "")
        ok, latency = _parse_tcping_result(output, result.returncode)
        if ok:
            return True, round(latency, 2) if latency is not None else None
        # tcping output is unreliable on some distros, fall back to socket probe
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = (time.monotonic() - start) * 1000
            return True, round(latency_ms, 2)
    except Exception:
        return False, None


def _split_hostport(addr: str) -> tuple[str, int]:
    # addr like 1.2.3.4:443 or [::1]:443
    if addr.startswith('['):
        host, rest = addr.split(']', 1)
        host = host[1:]
        port = int(rest.lstrip(':'))
        return host.strip(), port
    host, p = addr.rsplit(':', 1)
    return host.strip(), int(p)


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
    full = _read_json(POOL_FULL, {'endpoints': []})
    eps = full.get('endpoints') or []
    rules = []
    for idx, e in enumerate(eps):
        listen = (e.get('listen') or '').strip()
        port = 0
        try:
            port = _parse_listen_port(listen)
        except Exception:
            port = 0
        remotes: List[str] = []
        if isinstance(e.get('remote'), str) and e.get('remote'):
            remotes.append(e['remote'])
        if isinstance(e.get('remotes'), list):
            remotes += [str(x) for x in e.get('remotes') if x]
        if isinstance(e.get('extra_remotes'), list):
            remotes += [str(x) for x in e.get('extra_remotes') if x]
        seen = set()
        remotes = [r for r in remotes if not (r in seen or seen.add(r))]
        health = _build_health_entries(e, remotes[:8])
        rx_bytes, tx_bytes = _traffic_bytes(port)
        rules.append({
            'idx': idx,
            'listen': listen,
            'disabled': bool(e.get('disabled')),
            'connections': _conn_count(port),
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'health': health,
        })
    return {'ok': True, 'rules': rules}
