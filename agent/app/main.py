from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
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
REALM_CONFIG = Path('/etc/realm/config.json')
TRAFFIC_TOTALS: Dict[int, Dict[str, int]] = {}


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
    cmd = ['bash', '-lc', f"ss -Htin state established sport = :{port} 2>/dev/null"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return 0, 0
    rx_total = 0
    tx_total = 0
    for line in r.stdout.splitlines():
        rx_matches = re.findall(r"bytes_received:(\d+)", line)
        tx_matches = re.findall(r"bytes_acked:(\d+)", line)
        if not tx_matches:
            tx_matches = re.findall(r"bytes_sent:(\d+)", line)
        for value in rx_matches:
            try:
                rx_total += int(value)
            except ValueError:
                continue
        for value in tx_matches:
            try:
                tx_total += int(value)
            except ValueError:
                continue
    totals = TRAFFIC_TOTALS.setdefault(port, {'last_rx': 0, 'last_tx': 0, 'sum_rx': 0, 'sum_tx': 0})
    last_rx = totals['last_rx']
    last_tx = totals['last_tx']
    if rx_total >= last_rx:
        totals['sum_rx'] += rx_total - last_rx
    else:
        totals['sum_rx'] += rx_total
    if tx_total >= last_tx:
        totals['sum_tx'] += tx_total - last_tx
    else:
        totals['sum_tx'] += tx_total
    totals['last_rx'] = rx_total
    totals['last_tx'] = tx_total
    return totals['sum_rx'], totals['sum_tx']


def _tcp_probe(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _split_hostport(addr: str) -> tuple[str, int]:
    # addr like 1.2.3.4:443 or [::1]:443
    if addr.startswith('['):
        host, rest = addr.split(']', 1)
        host = host[1:]
        port = int(rest.lstrip(':'))
        return host.strip(), port
    host, p = addr.rsplit(':', 1)
    return host.strip(), int(p)


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
        health = []
        for r in remotes[:8]:  # 限制探测数量
            try:
                h, p = _split_hostport(r)
                ok = _tcp_probe(h, p)
            except Exception:
                ok = False
            health.append({'target': r, 'ok': ok})
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
