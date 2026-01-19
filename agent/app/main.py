from __future__ import annotations

import json
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, HTTPException, Request

API_KEY_FILE = Path('/etc/realm-agent/api.key')
POOL_FULL = Path('/etc/realm/pool_full.json')
POOL_ACTIVE = Path('/etc/realm/pool.json')
POOL_RUN_FILTER = Path('/etc/realm/pool_to_run.jq')
REALM_CONFIG = Path('/etc/realm/config.json')


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
    return r.returncode == 0 and r.stdout.strip() == 'active'


def _restart_realm() -> None:
    for svc in ['realm.service', 'realm']:
        r = subprocess.run(['systemctl', 'restart', svc], capture_output=True, text=True)
        if r.returncode == 0:
            return
    # 如果 systemd 没有服务名，至少不让 API 崩溃
    raise RuntimeError('无法重启 realm 服务（realm.service/realm 都失败）')


def _apply_pool_to_config() -> None:
    if not POOL_RUN_FILTER.exists():
        raise RuntimeError(f'缺少JQ过滤器: {POOL_RUN_FILTER}')
    if not POOL_FULL.exists():
        raise RuntimeError(f'缺少pool_full.json: {POOL_FULL}')

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


@app.get('/api/v1/info')
def api_info(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    return {
        'ok': True,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': socket.gethostname(),
        'realm_active': _service_is_active('realm.service') or _service_is_active('realm'),
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
    _sync_active_pool()
    _apply_pool_to_config()
    _restart_realm()
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
        rules.append({
            'idx': idx,
            'listen': listen,
            'disabled': bool(e.get('disabled')),
            'connections': _conn_count(port),
            'health': health,
        })
    return {'ok': True, 'rules': rules}
