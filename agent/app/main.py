from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import time
import os
import threading
import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, HTTPException, Request
import requests

from .config import CFG

API_KEY_FILE = Path('/etc/realm-agent/api.key')
ACK_VER_FILE = Path('/etc/realm-agent/panel_ack.version')
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


def _read_int(p: Path, default: int = 0) -> int:
    try:
        return int(_read_text(p).strip())
    except Exception:
        return default


def _write_int(p: Path, value: int) -> None:
    _write_text(p, str(int(value)))


def _sha256_of_obj(obj: Any) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(s.encode("utf-8")).hexdigest()
    except Exception:
        return ""



def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _cmd_signature(secret: str, cmd: Dict[str, Any]) -> str:
    """Return hex HMAC-SHA256 signature for cmd (excluding sig field)."""
    data = {k: v for k, v in cmd.items() if k != "sig"}
    msg = _canonical_json(data).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _verify_cmd_sig(cmd: Dict[str, Any], api_key: str) -> bool:
    sig = str(cmd.get("sig") or "").strip()
    if not sig:
        return False
    expect = _cmd_signature(api_key, cmd)
    try:
        return hmac.compare_digest(sig, expect)
    except Exception:
        return sig == expect


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

# --- 规则流量统计（更可靠）：优先使用 iptables 计数器，避免 ss 快照漏掉短连接 ---
# 说明：
# - ss 方案是“瞬时快照”，如果连接建立/关闭很快，可能在两次扫描之间完全消失，导致统计一直是 0。
# - iptables 计数器是“内核累计计数”，不会漏掉短连接，也同时适用于 TCP/UDP。
# - 我们只做计数，不改变放行/阻断逻辑：用自定义链 + RETURN，确保数据准确且对现有防火墙影响最小。

TRAFFIC_COUNTER_MODE = os.environ.get('REALM_TRAFFIC_COUNTER', 'auto').strip().lower()  # auto/iptables/ss/off
IPT_RUN_TIMEOUT = float(os.environ.get('REALM_IPT_TIMEOUT', '1.2'))
IPT_TABLE = os.environ.get('REALM_IPT_TABLE', 'mangle')
IPT_CHAIN_IN = os.environ.get('REALM_IPT_CHAIN_IN', 'REALMCOUNT_IN')
IPT_CHAIN_OUT = os.environ.get('REALM_IPT_CHAIN_OUT', 'REALMCOUNT_OUT')
IPT_CHAIN_CONN_IN = os.environ.get('REALM_IPT_CHAIN_CONN_IN', 'REALMCONN_IN')

_IPT_CACHE_LOCK = threading.Lock()
_IPT_READY_TS = 0.0
_IPT_CONN_READY_TS = 0.0
IPT_READY_TTL = float(os.environ.get('REALM_IPT_READY_TTL', '5.0'))


def _iptables_available() -> bool:
    return bool(shutil.which('iptables'))


def _run_iptables(args: list[str]) -> tuple[int, str, str]:
    try:
        r = subprocess.run(['iptables', *args], capture_output=True, text=True, timeout=IPT_RUN_TIMEOUT)
        return r.returncode, (r.stdout or ''), (r.stderr or '')
    except Exception as exc:
        return 127, '', str(exc)


def _ipt_ensure_chain(table: str, chain: str) -> None:
    # iptables -t <table> -N <chain> (链已存在会返回非 0)
    _run_iptables(['-t', table, '-N', chain])


def _ipt_ensure_jump(table: str, base_chain: str, target_chain: str) -> None:
    # 确保 base_chain 顶部有一条跳转到 target_chain 的规则
    rc, _, _ = _run_iptables(['-t', table, '-C', base_chain, '-j', target_chain])
    if rc != 0:
        _run_iptables(['-t', table, '-I', base_chain, '1', '-j', target_chain])


def _ipt_ensure_port_rule(table: str, chain: str, proto: str, flag: str, port: int) -> None:
    # 规则形如：-p tcp --dport 443 -j RETURN
    args = ['-t', table, '-C', chain, '-p', proto, flag, str(port), '-j', 'RETURN']
    rc, _, _ = _run_iptables(args)
    if rc != 0:
        _run_iptables(['-t', table, '-A', chain, '-p', proto, flag, str(port), '-j', 'RETURN'])




def _ipt_ensure_conn_new_rule(table: str, chain: str, proto: str, port: int) -> None:
    """Ensure a NEW-connection counter rule exists for the port.

    We count *cumulative* connections by counting packets in conntrack NEW state.
    For TCP we additionally match SYN to reduce noise.
    """
    base = ['-t', table, '-C', chain, '-p', proto]
    if proto == 'tcp':
        # SYN only + NEW state
        args = base + ['-m', 'conntrack', '--ctstate', 'NEW', '-m', 'tcp', '--syn', '--dport', str(port), '-j', 'RETURN']
        rc, _, _ = _run_iptables(args)
        if rc != 0:
            _run_iptables(['-t', table, '-A', chain, '-p', proto, '-m', 'conntrack', '--ctstate', 'NEW', '-m', 'tcp', '--syn', '--dport', str(port), '-j', 'RETURN'])
        return

    # UDP: use conntrack NEW state
    args = base + ['-m', 'conntrack', '--ctstate', 'NEW', '--dport', str(port), '-j', 'RETURN']
    rc, _, _ = _run_iptables(args)
    if rc != 0:
        _run_iptables(['-t', table, '-A', chain, '-p', proto, '-m', 'conntrack', '--ctstate', 'NEW', '--dport', str(port), '-j', 'RETURN'])


def _ensure_conn_counters(target_ports: set[int]) -> str | None:
    """Ensure conn counter chain/rules exist.

    Return None on success, otherwise a warning string.
    """
    if not target_ports:
        return None
    if TRAFFIC_COUNTER_MODE == 'off':
        return 'traffic counter disabled'
    if not _iptables_available():
        return 'iptables not available'

    global _IPT_CONN_READY_TS
    with _IPT_CACHE_LOCK:
        now = time.monotonic()
        if (now - _IPT_CONN_READY_TS) <= IPT_READY_TTL:
            return None

        _ipt_ensure_chain(IPT_TABLE, IPT_CHAIN_CONN_IN)
        _ipt_ensure_jump(IPT_TABLE, 'PREROUTING', IPT_CHAIN_CONN_IN)

        for p in sorted(target_ports):
            if p <= 0:
                continue
            for proto in ('tcp', 'udp'):
                _ipt_ensure_conn_new_rule(IPT_TABLE, IPT_CHAIN_CONN_IN, proto, p)

        _IPT_CONN_READY_TS = now
    return None


def _parse_iptables_chain_pkts(stdout: str, want: set[int], match_token: str) -> dict[int, int]:
    """Parse `iptables -nvxL <CHAIN>` output and return {port: pkts}."""
    out: dict[int, int] = {p: 0 for p in want}
    for line in (stdout or '').splitlines():
        s = line.strip()
        if not s or s.startswith('Chain ') or s.startswith('pkts ') or s.startswith('num '):
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        try:
            pk = int(parts[0])
        except Exception:
            continue
        m = re.search(rf"\b{re.escape(match_token)}(\d+)\b", s)
        if not m:
            continue
        try:
            port = int(m.group(1))
        except Exception:
            continue
        if port in out:
            out[port] += pk
    return out


def _read_conn_counters(target_ports: set[int]) -> tuple[dict[int, int], str | None]:
    """Read cumulative NEW-connection counters from iptables.

    Returns ({port: total_connections}, warning_or_none)
    """
    if not target_ports:
        return {}, None
    warn = _ensure_conn_counters(target_ports)
    if warn:
        return {p: 0 for p in target_ports}, warn

    rc, out1, err1 = _run_iptables(['-t', IPT_TABLE, '-nvxL', IPT_CHAIN_CONN_IN])
    if rc != 0:
        return {p: 0 for p in target_ports}, (err1 or 'iptables list failed')

    pkt_map = _parse_iptables_chain_pkts(out1, target_ports, 'dpt:')
    return {p: int(pkt_map.get(p, 0)) for p in target_ports}, None
def _ensure_traffic_counters(target_ports: set[int]) -> str | None:
    """确保计数链/规则存在。

    返回：None 表示 OK；否则返回 warning 字符串。
    """
    if not target_ports:
        return None
    if TRAFFIC_COUNTER_MODE == 'off':
        return 'traffic counter disabled'
    if TRAFFIC_COUNTER_MODE in ('auto', 'iptables') and _iptables_available():
        with _IPT_CACHE_LOCK:
            now = time.monotonic()
            if (now - _IPT_READY_TS) <= IPT_READY_TTL:
                return None
            # 尽量一次性把基础设施建好（链 + jump）
            _ipt_ensure_chain(IPT_TABLE, IPT_CHAIN_IN)
            _ipt_ensure_chain(IPT_TABLE, IPT_CHAIN_OUT)
            _ipt_ensure_jump(IPT_TABLE, 'PREROUTING', IPT_CHAIN_IN)
            _ipt_ensure_jump(IPT_TABLE, 'OUTPUT', IPT_CHAIN_OUT)
            # 端口规则
            for p in sorted(target_ports):
                if p <= 0:
                    continue
                for proto in ('tcp', 'udp'):
                    _ipt_ensure_port_rule(IPT_TABLE, IPT_CHAIN_IN, proto, '--dport', p)
                    _ipt_ensure_port_rule(IPT_TABLE, IPT_CHAIN_OUT, proto, '--sport', p)
            globals()['_IPT_READY_TS'] = now
        return None
    return 'iptables not available'


def _parse_iptables_chain_bytes(stdout: str, want: set[int], match_token: str) -> dict[int, int]:
    """解析 `iptables -nvxL <CHAIN>` 输出，返回 {port: bytes}。

    match_token: 'dpt:' 或 'spt:'
    """
    out: dict[int, int] = {p: 0 for p in want}
    for line in (stdout or '').splitlines():
        s = line.strip()
        if not s or s.startswith('Chain ') or s.startswith('pkts ') or s.startswith('num '):
            continue
        # 典型：pkts bytes target prot opt in out source destination ... tcp dpt:443
        parts = s.split()
        if len(parts) < 2:
            continue
        try:
            b = int(parts[1])
        except Exception:
            continue
        m = re.search(rf"\b{re.escape(match_token)}(\d+)\b", s)
        if not m:
            continue
        try:
            port = int(m.group(1))
        except Exception:
            continue
        if port in out:
            out[port] += b
    return out


def _read_traffic_counters(target_ports: set[int]) -> tuple[dict[int, dict[str, int]], str | None]:
    """读取 iptables 计数器。返回 {port: {rx_bytes, tx_bytes}}。"""
    if not target_ports:
        return {}, None
    warn = _ensure_traffic_counters(target_ports)
    if warn and TRAFFIC_COUNTER_MODE == 'iptables':
        # 强制使用 iptables 时，直接报 warning
        return {p: {'rx_bytes': 0, 'tx_bytes': 0} for p in target_ports}, warn

    if warn and TRAFFIC_COUNTER_MODE in ('auto', 'ss'):
        # auto 模式下允许回退到 ss
        return {p: {'rx_bytes': 0, 'tx_bytes': 0} for p in target_ports}, warn

    # 读取链计数
    rc1, out1, err1 = _run_iptables(['-t', IPT_TABLE, '-nvxL', IPT_CHAIN_IN])
    rc2, out2, err2 = _run_iptables(['-t', IPT_TABLE, '-nvxL', IPT_CHAIN_OUT])
    if rc1 != 0 or rc2 != 0:
        return {p: {'rx_bytes': 0, 'tx_bytes': 0} for p in target_ports}, (err1 or err2 or 'iptables list failed')

    rx_map = _parse_iptables_chain_bytes(out1, target_ports, 'dpt:')
    tx_map = _parse_iptables_chain_bytes(out2, target_ports, 'spt:')
    res: dict[int, dict[str, int]] = {}
    for p in target_ports:
        res[p] = {'rx_bytes': int(rx_map.get(p, 0)), 'tx_bytes': int(tx_map.get(p, 0))}
    return res, None


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
        out = {p: {'connections': 0, 'connections_active': 0, 'connections_total': 0, 'rx_bytes': 0, 'tx_bytes': 0} for p in target_ports}
        return out, '缺少 ss 命令'

    # 初始化返回数据（即使 ss 失败也能有结构）
    result: Dict[int, Dict[str, int]] = {}
    for p in target_ports:
        totals = TRAFFIC_TOTALS.get(p) or {'sum_rx': 0, 'sum_tx': 0, 'conns': {}}
        result[p] = {
            'connections': 0,
            'connections_active': 0,
            'connections_total': 0,
            'rx_bytes': int(totals.get('sum_rx') or 0),
            'tx_bytes': int(totals.get('sum_tx') or 0),
        }

    # 先尝试用 iptables 读取累计流量（不会漏掉短连接）。
    # 成功时会直接覆盖 rx/tx；失败则保留 ss 增量累计（兼容旧环境）。
    used_iptables_bytes = False
    ipt_warning: str | None = None
    if TRAFFIC_COUNTER_MODE in ('auto', 'iptables') and _iptables_available():
        traffic_map, ipt_warning = _read_traffic_counters(target_ports)
        if ipt_warning is None and isinstance(traffic_map, dict) and traffic_map:
            used_iptables_bytes = True
            for p in target_ports:
                d = traffic_map.get(p) or {}
                if 'rx_bytes' in d:
                    result[p]['rx_bytes'] = int(d.get('rx_bytes') or 0)
                if 'tx_bytes' in d:
                    result[p]['tx_bytes'] = int(d.get('tx_bytes') or 0)

    

    # iptables NEW-conn counters: cumulative connections since rule creation
    if _iptables_available():
        conn_total_map, conn_warn = _read_conn_counters(target_ports)
        if conn_warn is None and isinstance(conn_total_map, dict):
            for p in target_ports:
                result[p]['connections_total'] = int(conn_total_map.get(p, 0) or 0)
        else:
            # keep default 0
            pass
        # merge warning info
        if conn_warn and not ipt_warning:
            ipt_warning = conn_warn
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

    for raw_line in (r.stdout or '').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 5:
            local = parts[3]
            peer = parts[4]
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

        # 回写累计值到 result（仅在未成功启用 iptables 统计时）
        if not used_iptables_bytes:
            result[p]['rx_bytes'] = int(totals.get('sum_rx') or 0)
            result[p]['tx_bytes'] = int(totals.get('sum_tx') or 0)

    for p in target_ports:
        result[p]['connections_active'] = int(result[p].get('connections') or 0)

    return result, ipt_warning


def _collect_conn_traffic(target_ports: set[int]) -> tuple[Dict[int, Dict[str, int]], str | None]:
    """带短缓存的 ss 聚合结果。"""
    global _SS_CACHE_TS, _SS_CACHE_DATA, _SS_CACHE_ERR
    now = time.monotonic()
    with _SS_CACHE_LOCK:
        if _SS_CACHE_DATA and (now - _SS_CACHE_TS) <= SS_CACHE_TTL:
            # 直接复用缓存（并按需过滤端口）
            filtered = {p: _SS_CACHE_DATA.get(p, {'connections': 0, 'connections_active': 0, 'connections_total': 0, 'rx_bytes': 0, 'tx_bytes': 0}) for p in target_ports}
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


# ------------------------ Agent -> Panel Push Report ------------------------
# 目标：让面板不再主动访问 Agent（被控机）端口。
# Agent 以固定间隔（默认 3s）向面板上报：
#   - info / pool / stats 等快照
# 面板按上报数据渲染。
# 当面板侧产生规则变更（desired_pool_version > ack_version）时，
# 面板会在上报响应里返回 commands（例如 sync_pool）。
# Agent 在下一次上报后立即执行同步并回写 ack_version。

PANEL_URL = os.environ.get('REALM_PANEL_URL', '').strip().rstrip('/')
try:
    AGENT_ID = int(os.environ.get('REALM_AGENT_ID', '0') or '0')
except Exception:
    AGENT_ID = 0
try:
    HEARTBEAT_INTERVAL = max(1.0, float(os.environ.get('REALM_AGENT_HEARTBEAT_INTERVAL', '3') or '3'))
except Exception:
    HEARTBEAT_INTERVAL = 3.0

_PUSH_STOP = threading.Event()
_PUSH_THREAD: threading.Thread | None = None
_PUSH_LOCK = threading.Lock()  # 避免与 API 同时写 pool 文件导致竞争
_LAST_SYNC_ERROR: str | None = None


def _read_agent_api_key() -> str:
    try:
        return _read_text(API_KEY_FILE).strip()
    except Exception:
        return ''


def _panel_report_url() -> str:
    if not PANEL_URL:
        return ''
    return f"{PANEL_URL}/api/agent/report"


def _build_push_report() -> Dict[str, Any]:
    """构建上报快照。

    注意：这个快照会以默认 3s 周期调用。
    - 连通探测/连接统计已经做了短缓存与并发，避免规则多时卡死
    - 如果你希望更轻量，可将 interval 调大（例如 5-10s）
    """
    info: Dict[str, Any] = {
        'ok': True,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': socket.gethostname(),
        'realm_active': any(_service_is_active(name) for name in REALM_SERVICE_NAMES),
    }
    pool = _load_full_pool()
    stats = _build_stats_snapshot()
    rep: Dict[str, Any] = {
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'info': info,
        'pool': pool,
        'stats': stats,
    }
    if _LAST_SYNC_ERROR:
        rep['sync_error'] = _LAST_SYNC_ERROR
    return rep


def _apply_sync_pool_cmd(cmd: Dict[str, Any]) -> None:
    """执行面板下发的 pool 同步命令。成功后更新 ack_version。"""
    global _LAST_SYNC_ERROR
    try:
        ver = int(cmd.get('version') or 0)
    except Exception:
        ver = 0
    if ver <= 0:
        return
    ack = _read_int(ACK_VER_FILE, 0)
    if ver <= ack:
        return

    pool = cmd.get('pool')
    if not isinstance(pool, dict):
        _LAST_SYNC_ERROR = 'sync_pool: pool not dict'
        return

    do_apply = bool(cmd.get('apply', True))
    with _PUSH_LOCK:
        try:
            # 写入 full pool
            _write_json(POOL_FULL, pool)
            _sync_active_pool()

            if do_apply:
                _apply_pool_to_config()
                _restart_realm()

            # ✅ 只有成功才 ack
            _write_int(ACK_VER_FILE, ver)
            _LAST_SYNC_ERROR = None
        except Exception as exc:
            _LAST_SYNC_ERROR = f"sync_pool failed: {exc}"




def _apply_pool_patch_cmd(cmd: Dict[str, Any]) -> None:
    """Apply single-rule incremental patch from panel.

    cmd format:
      {type:'pool_patch', version:int, base_version:int, ops:[...], apply:bool, sig:str}
    """
    global _LAST_SYNC_ERROR
    try:
        ver = int(cmd.get('version') or 0)
    except Exception:
        ver = 0
    if ver <= 0:
        return

    ack = _read_int(ACK_VER_FILE, 0)
    if ver <= ack:
        return

    try:
        base_ver = int(cmd.get('base_version') or 0)
    except Exception:
        base_ver = 0

    # Patch only allowed when agent is exactly at base_version
    if ack != base_ver:
        _LAST_SYNC_ERROR = f'pool_patch: base_version mismatch (ack={ack}, base={base_ver})'
        return

    ops = cmd.get('ops')
    if not isinstance(ops, list) or len(ops) != 1:
        _LAST_SYNC_ERROR = 'pool_patch: ops invalid'
        return

    do_apply = bool(cmd.get('apply', True))

    with _PUSH_LOCK:
        try:
            full = _load_full_pool()
            eps = full.get('endpoints') or []
            if not isinstance(eps, list):
                eps = []

            # index by listen, preserve order
            def _key(ep: Any) -> str:
                if not isinstance(ep, dict):
                    return ''
                return str(ep.get('listen') or '').strip()

            base_order = [_key(e) for e in eps if _key(e)]
            mp = {k: e for e in eps if (k := _key(e))}

            op = ops[0]
            typ = str(op.get('op') or '').strip().lower()
            if typ == 'upsert':
                ep = op.get('endpoint')
                if not isinstance(ep, dict) or not str(ep.get('listen') or '').strip():
                    _LAST_SYNC_ERROR = 'pool_patch: endpoint invalid'
                    return
                ep.setdefault('disabled', False)
                mp[str(ep.get('listen')).strip()] = ep
            elif typ == 'remove':
                listen = str(op.get('listen') or '').strip()
                if not listen:
                    _LAST_SYNC_ERROR = 'pool_patch: listen invalid'
                    return
                mp.pop(listen, None)
                base_order = [x for x in base_order if x != listen]
            else:
                _LAST_SYNC_ERROR = f'pool_patch: unknown op {typ}'
                return

            # rebuild endpoints list preserving prior order
            new_eps = []
            seen = set()
            for k in base_order:
                if k in mp:
                    new_eps.append(mp[k])
                    seen.add(k)
            # append new ones
            for k, v in mp.items():
                if k not in seen:
                    new_eps.append(v)

            new_full = dict(full)
            new_full['endpoints'] = new_eps
            _write_json(POOL_FULL, new_full)
            _sync_active_pool()

            if do_apply:
                _apply_pool_to_config()
                _restart_realm()

            _write_int(ACK_VER_FILE, ver)
            _LAST_SYNC_ERROR = None
        except Exception as exc:
            _LAST_SYNC_ERROR = f"pool_patch failed: {exc}"

def _handle_panel_commands(cmds: Any) -> None:
    if not isinstance(cmds, list) or not cmds:
        return

    api_key = _read_agent_api_key()
    for cmd in cmds:
        if not isinstance(cmd, dict):
            continue

        # Signature required for rule sync commands
        t = str(cmd.get('type') or '').strip()
        if t in ('sync_pool', 'pool_patch'):
            if not api_key or not _verify_cmd_sig(cmd, api_key):
                # do not crash; keep reporting error for UI
                global _LAST_SYNC_ERROR
                _LAST_SYNC_ERROR = f'{t}: bad signature'
                continue

        if t == 'sync_pool':
            _apply_sync_pool_cmd(cmd)
        elif t == 'pool_patch':
            _apply_pool_patch_cmd(cmd)

def _push_loop() -> None:
    """后台上报线程。"""
    url = _panel_report_url()
    if not url or AGENT_ID <= 0:
        return

    api_key = _read_agent_api_key()
    if not api_key:
        return

    sess = requests.Session()
    headers = {
        'X-API-Key': api_key,
        'User-Agent': f"realm-agent/{app.version} push-report",
    }

    # 失败退避：连续失败会指数退避，避免刷爆日志/网络
    backoff = 0.0
    max_backoff = 30.0

    while not _PUSH_STOP.is_set():
        started = time.time()
        try:
            ack = _read_int(ACK_VER_FILE, 0)
            payload = {
                'node_id': AGENT_ID,
                'ack_version': ack,
                'report': _build_push_report(),
            }
            r = sess.post(url, json=payload, headers=headers, timeout=3)
            if r.status_code == 200:
                data = r.json() if r.content else {}
                _handle_panel_commands(data.get('commands'))
                backoff = 0.0
            else:
                backoff = min(max_backoff, backoff * 2 + 1.0) if backoff else 2.0
        except Exception:
            backoff = min(max_backoff, backoff * 2 + 1.0) if backoff else 2.0

        # 维持固定节奏：interval - 耗时 + 退避
        cost = time.time() - started
        sleep_s = max(0.1, HEARTBEAT_INTERVAL - cost)
        if backoff:
            sleep_s = max(sleep_s, backoff)
        _PUSH_STOP.wait(timeout=sleep_s)


def _start_push_reporter() -> None:
    global _PUSH_THREAD
    if _PUSH_THREAD and _PUSH_THREAD.is_alive():
        return
    if not PANEL_URL or AGENT_ID <= 0:
        return
    _PUSH_STOP.clear()
    th = threading.Thread(target=_push_loop, name='realm-agent-push', daemon=True)
    th.start()
    _PUSH_THREAD = th


def _stop_push_reporter() -> None:
    _PUSH_STOP.set()


@app.on_event('startup')
def _on_startup() -> None:
    # Agent 启动后自动开启上报（若配置了 REALM_PANEL_URL + REALM_AGENT_ID）
    _start_push_reporter()


@app.on_event('shutdown')
def _on_shutdown() -> None:
    _stop_push_reporter()



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


def _build_stats_snapshot() -> Dict[str, Any]:
    """规则统计 + 连通探测。

    旧版本逐条、逐目标串行探测，规则多时很容易让面板的 /stats 调用超时。
    这里做了：
    - 全部目标并发探测
    - 短缓存复用探测结果
    - WSS 规则补充探测 WSS Host（显示真实外层延迟）

    NOTE: 该函数同时被 /api/v1/stats 与面板 push-report 复用。
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

        ct = conn_traffic_map.get(port) or {'connections': 0, 'connections_active': 0, 'connections_total': 0, 'rx_bytes': 0, 'tx_bytes': 0}
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
            'connections_active': int(ct.get('connections_active') or ct.get('connections') or 0),
            'connections_total': int(ct.get('connections_total') or 0),
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'health': health,
        })

    resp: Dict[str, Any] = {'ok': True, 'rules': rules}
    if ss_err:
        resp['warning'] = ss_err
    return resp


@app.get('/api/v1/stats')
def api_stats(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    return _build_stats_snapshot()
