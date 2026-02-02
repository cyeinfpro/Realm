from __future__ import annotations

import json
import re
import shutil
import shlex
import socket
import subprocess
import time
import os
import threading
import hashlib
import hmac
import ssl
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Request
import requests

from .config import CFG
from .intranet_tunnel import IntranetManager, load_server_cert_pem

API_KEY_FILE = Path('/etc/realm-agent/api.key')
ACK_VER_FILE = Path('/etc/realm-agent/panel_ack.version')
UPDATE_STATE_FILE = Path('/etc/realm-agent/agent_update.json')
TRAFFIC_STATE_FILE = Path('/etc/realm-agent/traffic_state.json')
TRAFFIC_RESET_ACK_FILE = Path('/etc/realm-agent/traffic_reset_ack.version')
POOL_FULL = Path('/etc/realm/pool_full.json')
POOL_ACTIVE = Path('/etc/realm/pool.json')
POOL_RUN_FILTER = Path('/etc/realm/pool_to_run.jq')
FALLBACK_RUN_FILTER = Path(__file__).resolve().parents[1] / 'pool_to_run.jq'
REALM_CONFIG = Path(CFG.realm_config_file)
TRAFFIC_TOTALS: Dict[int, Dict[str, Any]] = {}
_TRAFFIC_LOCK = threading.Lock()
TCPING_TIMEOUT = 2.0

# --- Per-rule traffic baseline (so deleting/recreating rules resets counters in UI) ---
#
# Problem:
#   Flow counters (iptables or ss totals) are cumulative per listen port.
#   When a rule is deleted and the same listen port is later reused, the UI would
#   keep showing old historical bytes.
#
# Solution:
#   Maintain a per-listen-port baseline and subtract it when reporting stats.
#   The baseline is automatically reset when:
#     - the listen port disappears from config (rule deleted)
#     - the rule "signature" changes (edited into a new rule)
#     - raw counters go backwards (iptables -Z / chain reset / agent restart in ss mode)
#
# Persisting baselines makes the behaviour stable across agent restarts.
_TRAFFIC_STATE_LOCK = threading.Lock()
_TRAFFIC_STATE_LOADED = False
_TRAFFIC_STATE: Dict[int, Dict[str, Any]] = {}  # port -> {sig:str, base_rx:int, base_tx:int, ts:int}
_TRAFFIC_STATE_DIRTY = False
_TRAFFIC_STATE_LAST_SAVE = 0.0
TRAFFIC_STATE_SAVE_MIN_INTERVAL = float(os.getenv('REALM_AGENT_TRAFFIC_STATE_SAVE_INTERVAL', '1.0'))

# 活跃连接统计窗口（秒）：显示最近 N 秒内的新连接数（基于 iptables conntrack NEW 计数）
CONN_RATE_WINDOW = int(os.getenv('REALM_AGENT_CONN_RATE_WINDOW', '30'))
_CONN_TOTAL_HISTORY = {}  # port -> deque[(ts, total)]
_CONN_HISTORY_LOCK = threading.Lock()


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
_PROBE_PRUNE_TS = 0.0
_PROBE_LOCK = threading.Lock()

# ---------------- System Snapshot (CPU/Mem/Disk/Net) ----------------
# 说明：不依赖 psutil，纯 /proc + shutil.disk_usage 实现。
# 用于面板节点详情展示（CPU/内存/硬盘/交换/在线时长/流量/实时速率），默认 3s 上报一次。
_SYS_LOCK = threading.Lock()
_SYS_CPU_LAST: Optional[dict] = None  # {total:int, idle:int, ts:float}
_SYS_NET_LAST: Optional[dict] = None  # {rx:int, tx:int, ts:float}


def _read_text(p: Path) -> str:
    return p.read_text(encoding='utf-8')


def _write_text(p: Path, content: str) -> None:
    """原子写文件：先写临时文件再 os.replace，避免并发/异常导致半截文件。

    修复点：如果写入/替换失败，确保临时文件会被清理，避免磁盘堆积。
    """
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = None
    try:
        if p.exists():
            mode = p.stat().st_mode & 0o777
    except Exception:
        mode = None

    tmp = p.with_name(p.name + f".tmp.{os.getpid()}.{threading.get_ident()}")
    try:
        tmp.write_text(content, encoding='utf-8')
        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except Exception:
                pass
        os.replace(tmp, p)
    finally:
        # If os.replace() failed, tmp still exists - remove it.
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass


def _read_json(p: Path, default: Any) -> Any:
    try:
        return json.loads(_read_text(p))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        # 避免因配置文件被截断/写坏导致接口直接 500。
        # 尝试把坏文件改名保留，便于排查。
        try:
            ts = datetime.now().strftime('%Y%m%d-%H%M%S')
            bad = p.with_name(p.name + f".corrupt.{ts}")
            os.replace(p, bad)
        except Exception:
            pass
        return default


def _read_int(p: Path, default: int = 0) -> int:
    try:
        return int(_read_text(p).strip())
    except Exception:
        return default


def _write_int(p: Path, value: int) -> None:
    _write_text(p, str(int(value)))


def _load_update_state() -> Dict[str, Any]:
    st = _read_json(UPDATE_STATE_FILE, {})
    return st if isinstance(st, dict) else {}


def _save_update_state(st: Dict[str, Any]) -> None:
    try:
        _write_json(UPDATE_STATE_FILE, st)
    except Exception:
        pass


def _reconcile_update_state() -> None:
    """If we restarted into a newer agent, flip update state to done."""
    st = _load_update_state()
    if not st:
        return
    # desired_version 可能是 "39-force-<id>" 这种形式（为了兼容旧版 Agent 的版本短路逻辑）。
    # 这里做“前缀数字”解析，确保重启后能正确把 installing -> done。
    desired = 0
    try:
        m = re.match(r"\s*([0-9]+)", str(st.get('desired_version') or ''))
        desired = int(m.group(1)) if m else 0
    except Exception:
        desired = 0
    state = str(st.get('state') or '').strip().lower()
    if desired > 0 and int(str(app.version)) >= desired and state in ('installing', 'sent', 'queued', 'pending'):
        st['state'] = 'done'
        st['finished_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        st.setdefault('from_version', st.get('from_version') or '')
        st['agent_version'] = str(app.version)
        _save_update_state(st)


# ---------------- System Snapshot Helpers ----------------

def _read_first_line(path: str) -> str:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return (f.readline() or '').strip()
    except Exception:
        return ''

def _read_cpu_model() -> str:
    try:
        with open('/proc/cpuinfo', 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.lower().startswith('model name'):
                    return line.split(':', 1)[-1].strip()
    except Exception:
        pass
    return ''

def _read_cpu_times() -> tuple[int, int]:
    # returns (total, idle)
    try:
        with open('/proc/stat', 'r', encoding='utf-8', errors='ignore') as f:
            line = f.readline()
        parts = line.split()
        if not parts or parts[0] != 'cpu':
            return (0, 0)
        nums = [int(x) for x in parts[1:]]
        # user,nice,system,idle,iowait,irq,softirq,steal,...
        idle = 0
        if len(nums) >= 4:
            idle = nums[3]
        if len(nums) >= 5:
            idle += nums[4]
        total = sum(nums)
        return (total, idle)
    except Exception:
        return (0, 0)

def _read_meminfo() -> dict:
    out = {}
    try:
        with open('/proc/meminfo', 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if ':' not in line:
                    continue
                k, v = line.split(':', 1)
                v = v.strip().split()
                if not v:
                    continue
                # values are kB
                try:
                    out[k.strip()] = int(v[0]) * 1024
                except Exception:
                    pass
    except Exception:
        pass
    return out

def _read_net_bytes() -> tuple[int, int]:
    # returns (rx_bytes, tx_bytes) for all non-loopback interfaces
    rx = 0
    tx = 0
    try:
        with open('/proc/net/dev', 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[2:]
        for line in lines:
            if ':' not in line:
                continue
            iface, data = line.split(':', 1)
            iface = iface.strip()
            if iface == 'lo':
                continue
            fields = data.split()
            if len(fields) < 16:
                continue
            # receive bytes is fields[0], transmit bytes is fields[8]
            rx += int(fields[0])
            tx += int(fields[8])
    except Exception:
        return (0, 0)
    return (rx, tx)

def _build_sys_snapshot() -> dict:
    now = time.time()
    cpu_model = _read_cpu_model()
    cores = int(os.cpu_count() or 0)
    total, idle = _read_cpu_times()
    rx, tx = _read_net_bytes()
    mem = _read_meminfo()
    mem_total = int(mem.get('MemTotal', 0) or 0)
    mem_avail = int(mem.get('MemAvailable', 0) or 0)
    mem_used = max(0, mem_total - mem_avail)
    swap_total = int(mem.get('SwapTotal', 0) or 0)
    swap_free = int(mem.get('SwapFree', 0) or 0)
    swap_used = max(0, swap_total - swap_free)
    disk_total = disk_used = 0
    try:
        du = shutil.disk_usage('/')
        disk_total = int(du.total)
        disk_used = int(du.used)
    except Exception:
        pass
    uptime_sec = 0.0
    try:
        up = _read_first_line('/proc/uptime')
        uptime_sec = float((up.split() or ['0'])[0])
    except Exception:
        uptime_sec = 0.0

    cpu_pct = 0.0
    rx_bps = 0.0
    tx_bps = 0.0
    global _SYS_CPU_LAST, _SYS_NET_LAST
    with _SYS_LOCK:
        if _SYS_CPU_LAST and total > 0:
            dt = max(1e-6, float(now - float(_SYS_CPU_LAST.get('ts', now))))
            dtotal = int(total - int(_SYS_CPU_LAST.get('total', total)))
            didle = int(idle - int(_SYS_CPU_LAST.get('idle', idle)))
            if dtotal > 0:
                cpu_pct = max(0.0, min(100.0, (dtotal - didle) * 100.0 / dtotal))
        _SYS_CPU_LAST = {'total': int(total), 'idle': int(idle), 'ts': float(now)}
        if _SYS_NET_LAST:
            dt = max(1e-6, float(now - float(_SYS_NET_LAST.get('ts', now))))
            drx = int(rx - int(_SYS_NET_LAST.get('rx', rx)))
            dtx = int(tx - int(_SYS_NET_LAST.get('tx', tx)))
            rx_bps = max(0.0, drx / dt)
            tx_bps = max(0.0, dtx / dt)
        _SYS_NET_LAST = {'rx': int(rx), 'tx': int(tx), 'ts': float(now)}

    def pct(used: int, total: int) -> float:
        if total <= 0:
            return 0.0
        return max(0.0, min(100.0, used * 100.0 / total))

    return {
        'ok': True,
        'ts': int(now),
        'cpu': {'model': cpu_model, 'cores': cores, 'usage_pct': round(cpu_pct, 2)},
        'mem': {'total': mem_total, 'used': mem_used, 'usage_pct': round(pct(mem_used, mem_total), 2)},
        'swap': {'total': swap_total, 'used': swap_used, 'usage_pct': round(pct(swap_used, swap_total), 2)},
        'disk': {'path': '/', 'total': disk_total, 'used': disk_used, 'usage_pct': round(pct(disk_used, disk_total), 2)},
        'net': {'rx_bytes': int(rx), 'tx_bytes': int(tx), 'rx_bps': round(rx_bps, 2), 'tx_bps': round(tx_bps, 2)},
        'uptime_sec': round(float(uptime_sec), 3),
    }


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

# ---------------- Panel command replay protection ----------------
CMD_SIG_MAX_SKEW_SEC = int(os.getenv("REALM_CMD_SIG_MAX_SKEW_SEC", "300"))  # max allowed clock skew
CMD_NONCE_TTL_SEC = int(os.getenv("REALM_CMD_NONCE_TTL_SEC", "600"))  # how long to remember seen nonces
_CMD_NONCE_LOCK = threading.Lock()
_CMD_NONCE_SEEN: Dict[str, float] = {}  # nonce -> monotonic timestamp


def _remember_cmd_nonce(nonce: str) -> bool:
    """Return True if nonce is new and is remembered, otherwise False (replay)."""
    if not nonce:
        return False
    now = time.monotonic()
    cutoff = now - float(max(1, CMD_NONCE_TTL_SEC))
    with _CMD_NONCE_LOCK:
        # prune old entries
        for k, ts in list(_CMD_NONCE_SEEN.items()):
            if ts < cutoff:
                _CMD_NONCE_SEEN.pop(k, None)
        if nonce in _CMD_NONCE_SEEN:
            return False
        _CMD_NONCE_SEEN[nonce] = now
    return True



def _verify_cmd_sig(cmd: Dict[str, Any], api_key: str) -> bool:
    """Verify command signature + timestamp window + (optional) nonce replay protection."""
    sig = str(cmd.get("sig") or "").strip()
    if not sig:
        return False

    # 1) signature (covers ts/nonce/...)
    expect = _cmd_signature(api_key, cmd)
    if not hmac.compare_digest(sig, expect):
        return False

    # 2) timestamp window check (basic replay mitigation)
    try:
        ts = int(cmd.get("ts") or 0)
    except Exception:
        return False
    if ts <= 0:
        return False
    now = int(time.time())
    if abs(now - ts) > int(max(1, CMD_SIG_MAX_SKEW_SEC)):
        return False

    # 3) nonce replay protection (preferred). Keep legacy compatibility: if nonce missing, accept.
    nonce = str(cmd.get("nonce") or "").strip()
    if nonce:
        if not _remember_cmd_nonce(nonce):
            return False

    return True



def _write_json(p: Path, data: Any) -> None:
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
    detail = "; ".join([e for e in errors if e]) or "未知错误"
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
_SS_CACHE_ERR: Optional[str] = None
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
    """Ensure there is exactly ONE jump into the counting chain.

    背景：早期版本/手工操作/不同 iptables 后端可能导致 base_chain 中存在多条
    `-j <target_chain>` 的跳转规则。这样一个数据包会重复进入计数链，从而造成
    规则流量被放大（常见 2x/3x/4x…）。

    这里做“自愈”：
    - 删除 base_chain 中所有跳转到 target_chain 的规则（包括带条件的跳转）；
    - 再在第 1 条位置插入一条标准跳转：`-I <base_chain> 1 -j <target_chain>`。

    计数器位于 target_chain 内的端口规则上，因此清理/重插 jump 不会清空
    端口计数（只会影响 jump 本身的计数，我们不使用它）。
    """
    try:
        rc, out, _ = _run_iptables(['-t', table, '-S', base_chain])
    except Exception:
        rc, out = 1, ''

    # Fast-path: already exactly one canonical jump and it is the first rule.
    want_line = f"-A {base_chain} -j {target_chain}"
    if rc == 0:
        rule_lines = [ln.strip() for ln in (out or '').splitlines() if ln.strip().startswith(f"-A {base_chain} ")]
        jump_lines = [ln for ln in rule_lines if f"-j {target_chain}" in ln]
        if len(jump_lines) == 1 and rule_lines:
            if jump_lines[0] == want_line and rule_lines[0] == want_line:
                return

        # Delete all jump rules that point to target_chain (including conditional ones)
        for ln in jump_lines:
            try:
                toks = shlex.split(ln)
            except Exception:
                continue
            if len(toks) >= 2 and toks[0] == '-A' and toks[1] == base_chain:
                toks[0] = '-D'
                _run_iptables(['-t', table, *toks])
    else:
        # Fallback: if -S is not available, at least remove unconditional duplicates
        while True:
            rc_del, _, _ = _run_iptables(['-t', table, '-D', base_chain, '-j', target_chain])
            if rc_del != 0:
                break

    # Insert one canonical jump at the top.
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


def _ensure_conn_counters(target_ports: set[int]) -> Optional[str]:
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


def _read_conn_counters(target_ports: set[int]) -> tuple[dict[int, int], Optional[str]]:
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
        return {p: 0 for p in target_ports}, (err1 or '读取 iptables 失败（可能未安装或无权限）')

    pkt_map = _parse_iptables_chain_pkts(out1, target_ports, 'dpt:')
    return {p: int(pkt_map.get(p, 0)) for p in target_ports}, None


def _conn_rate_window(port: int, total: int) -> int:
    """Return NEW-connection delta within CONN_RATE_WINDOW seconds.

    Uses a small in-memory deque per port.
    """
    if port <= 0 or CONN_RATE_WINDOW <= 0:
        return 0
    now = time.monotonic()
    with _CONN_HISTORY_LOCK:
        dq = _CONN_TOTAL_HISTORY.get(port)
        if dq is None:
            dq = deque()
            _CONN_TOTAL_HISTORY[port] = dq
        # drop too-old samples, keep at least 1
        cutoff = now - float(CONN_RATE_WINDOW)
        while len(dq) >= 2 and dq[0][0] < cutoff:
            dq.popleft()
        # baseline: oldest sample within window
        baseline = dq[0][1] if dq else total
        dq.append((now, int(total)))
        # prevent unbounded growth
        while len(dq) > 8:
            dq.popleft()
    try:
        return max(0, int(total) - int(baseline))
    except Exception:
        return 0


def _cleanup_conn_history(active_ports: set[int]) -> None:
    """Prevent unbounded growth when ports are removed from config."""
    if not active_ports:
        return
    with _CONN_HISTORY_LOCK:
        for p in list(_CONN_TOTAL_HISTORY.keys()):
            if p not in active_ports:
                _CONN_TOTAL_HISTORY.pop(p, None)

    # In ss mode we keep an in-memory cumulative counter per port.
    # When a rule is deleted and the listen port disappears, we should drop the
    # historical totals so that reusing the same port starts from 0.
    with _TRAFFIC_LOCK:
        for p in list(TRAFFIC_TOTALS.keys()):
            if p not in active_ports:
                TRAFFIC_TOTALS.pop(p, None)


def _traffic_endpoint_signature(ep: Dict[str, Any]) -> str:
    """Return a stable signature for an endpoint.

    This signature is used ONLY for deciding when to reset traffic baselines.
    We intentionally ignore purely cosmetic fields (e.g. remark) and also ignore
    'disabled' so toggling a rule doesn't wipe its traffic.

    If the rule is edited into a logically different rule (remotes/protocol/...)
    the signature changes and the baseline is reset.
    """
    if not isinstance(ep, dict):
        return ''
    try:
        listen = str(ep.get('listen') or '').strip()
        protocol = str(ep.get('protocol') or '').strip().lower()

        remotes: List[str] = []
        r0 = ep.get('remote')
        if isinstance(r0, str) and r0.strip():
            remotes.append(r0.strip())
        r1 = ep.get('remotes')
        if isinstance(r1, list):
            for x in r1:
                sx = str(x).strip() if x is not None else ''
                if sx:
                    remotes.append(sx)
        r2 = ep.get('extra_remotes')
        if isinstance(r2, list):
            for x in r2:
                sx = str(x).strip() if x is not None else ''
                if sx:
                    remotes.append(sx)

        # Sync/intranet rules: include sync_id/role so identical listen/remotes
        # from different logical pairs don't collide.
        ex = ep.get('extra_config')
        if not isinstance(ex, dict):
            ex = {}
        sync_id = str(ex.get('sync_id') or '').strip()
        role = str(ex.get('sync_role') or ex.get('intranet_role') or '').strip()

        listen_transport = str(ep.get('listen_transport') or '').strip()
        remote_transport = str(ep.get('remote_transport') or '').strip()

        payload = {
            'listen': listen,
            'protocol': protocol,
            'remotes': sorted(set(remotes)),
            'sync_id': sync_id,
            'role': role,
            'listen_transport': listen_transport,
            'remote_transport': remote_transport,
        }
        s = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        return hashlib.sha1(s.encode('utf-8')).hexdigest()
    except Exception:
        return ''


def _load_traffic_state_locked() -> None:
    """Load traffic baseline state from disk (locked)."""
    global _TRAFFIC_STATE_LOADED, _TRAFFIC_STATE
    if _TRAFFIC_STATE_LOADED:
        return

    raw = _read_json(TRAFFIC_STATE_FILE, default={})

    ports_obj: Dict[str, Any] = {}
    if isinstance(raw, dict):
        # v1: {"v":1, "ports": {"443": {...}}}
        if isinstance(raw.get('ports'), dict):
            ports_obj = raw.get('ports') or {}
        else:
            # legacy: direct mapping {"443": {...}}
            # (accept for forward compatibility)
            ports_obj = raw

    st: Dict[int, Dict[str, Any]] = {}
    for k, v in (ports_obj or {}).items():
        try:
            p = int(k)
        except Exception:
            continue
        if p <= 0:
            continue
        if not isinstance(v, dict):
            continue
        try:
            st[p] = {
                'sig': str(v.get('sig') or ''),
                'base_rx': int(v.get('base_rx') or 0),
                'base_tx': int(v.get('base_tx') or 0),
                'ts': int(v.get('ts') or 0),
            }
        except Exception:
            continue

    _TRAFFIC_STATE = st
    _TRAFFIC_STATE_LOADED = True


def _save_traffic_state_locked(force: bool = False) -> None:
    """Persist traffic baseline state to disk (locked)."""
    global _TRAFFIC_STATE_DIRTY, _TRAFFIC_STATE_LAST_SAVE
    now = time.monotonic()
    if not force:
        if not _TRAFFIC_STATE_DIRTY:
            return
        if (now - float(_TRAFFIC_STATE_LAST_SAVE)) < float(TRAFFIC_STATE_SAVE_MIN_INTERVAL):
            return

    data = {
        'v': 1,
        'ports': {str(p): {
            'sig': str(v.get('sig') or ''),
            'base_rx': int(v.get('base_rx') or 0),
            'base_tx': int(v.get('base_tx') or 0),
            'ts': int(v.get('ts') or 0),
        } for p, v in sorted(_TRAFFIC_STATE.items())},
    }
    try:
        _write_json(TRAFFIC_STATE_FILE, data)
        _TRAFFIC_STATE_DIRTY = False
        _TRAFFIC_STATE_LAST_SAVE = now
    except Exception:
        # Keep dirty so we retry later, but avoid tight loops.
        _TRAFFIC_STATE_LAST_SAVE = now


def _apply_traffic_baseline(port_sig: Dict[int, str], conn_map: Dict[int, Dict[str, int]]) -> None:
    """Apply per-port baselines to rx/tx in conn_map (in-place).

    conn_map values are raw cumulative counters. After this function runs,
    rx_bytes/tx_bytes will represent "since this rule was created/last edited".
    """
    global _TRAFFIC_STATE_DIRTY

    if not isinstance(conn_map, dict):
        return
    active_ports = {int(p) for p in (port_sig or {}).keys() if int(p) > 0}

    changed = False
    now_ts = int(time.time())

    with _TRAFFIC_STATE_LOCK:
        _load_traffic_state_locked()

        # No active ports: config emptied / all rules deleted. Clear baselines so
        # reusing a port later will start from 0 as expected.
        if not active_ports:
            if _TRAFFIC_STATE:
                _TRAFFIC_STATE.clear()
                _TRAFFIC_STATE_DIRTY = True
                _save_traffic_state_locked(force=True)
            return

        # Drop baselines for removed ports (rule deleted)
        for p in list(_TRAFFIC_STATE.keys()):
            if p not in active_ports:
                _TRAFFIC_STATE.pop(p, None)
                changed = True

        # Apply/update baselines for active ports
        for p in active_ports:
            sig = str(port_sig.get(p) or '')
            raw = conn_map.get(p)
            if not isinstance(raw, dict):
                continue
            rx = int(raw.get('rx_bytes') or 0)
            tx = int(raw.get('tx_bytes') or 0)

            st = _TRAFFIC_STATE.get(p)
            st_sig = str(st.get('sig') or '') if isinstance(st, dict) else ''
            base_rx = int(st.get('base_rx') or 0) if isinstance(st, dict) else 0
            base_tx = int(st.get('base_tx') or 0) if isinstance(st, dict) else 0

            need_reset = False
            if st is None:
                need_reset = True
            elif st_sig != sig:
                need_reset = True
            elif rx < base_rx or tx < base_tx:
                # counters reset / went backwards
                need_reset = True

            if need_reset:
                _TRAFFIC_STATE[p] = {'sig': sig, 'base_rx': rx, 'base_tx': tx, 'ts': now_ts}
                base_rx = rx
                base_tx = tx
                changed = True

            raw['rx_bytes'] = max(0, rx - base_rx)
            raw['tx_bytes'] = max(0, tx - base_tx)

        if changed:
            _TRAFFIC_STATE_DIRTY = True
            _save_traffic_state_locked()


def _ensure_traffic_counters(target_ports: set[int]) -> Optional[str]:
    """确保计数链/规则存在。

    返回：None 表示 OK；否则返回 warning 字符串。
    """
    global _IPT_READY_TS
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
            _IPT_READY_TS = now
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


def _read_traffic_counters(target_ports: set[int]) -> tuple[dict[int, dict[str, int]], Optional[str]]:
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
        return {p: {'rx_bytes': 0, 'tx_bytes': 0} for p in target_ports}, (err1 or err2 or '读取 iptables 失败（可能未安装或无权限）')

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


def _scan_ss_once(target_ports: set[int]) -> tuple[Dict[int, Dict[str, int]], Optional[str]]:
    """扫描一次 ss 并聚合为：{port: {connections, rx_bytes, tx_bytes}}。

    备注：
    - rx/tx 优先使用 iptables 计数器（更准确，不漏短连接）；失败则回退到 ss 增量累计。
    - ss 增量累计使用 TRAFFIC_TOTALS 保存每条连接的 last_rx/last_tx，并做 delta 叠加。
    - 修复点：所有 TRAFFIC_TOTALS 的读写都通过 _TRAFFIC_LOCK 保护，避免并发导致数据竞争/崩溃。
    """
    if not target_ports:
        return {}, None

    # 防止端口移除后历史缓存无限增长
    _cleanup_conn_history(target_ports)

    if not shutil.which('ss'):
        out = {
            p: {'connections': 0, 'connections_active': 0, 'connections_total': 0, 'rx_bytes': 0, 'tx_bytes': 0}
            for p in target_ports
        }
        return out, '缺少 ss 命令'

    # 初始化返回数据（即使 ss 失败也能有结构）
    result: Dict[int, Dict[str, int]] = {}
    with _TRAFFIC_LOCK:
        for p in target_ports:
            totals = TRAFFIC_TOTALS.get(p) or {'sum_rx': 0, 'sum_tx': 0, 'conns': {}}
            TRAFFIC_TOTALS[p] = totals
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
    ipt_warning: Optional[str] = None
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
                # 近 N 秒新连接数（活跃连接）
                result[p]['connections_active'] = _conn_rate_window(p, result[p]['connections_total'])
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

        try:
            rx_value = int(rx_matches[-1]) if rx_matches else 0
            tx_value = int(tx_matches[-1]) if tx_matches else 0
        except Exception:
            return False

        with _TRAFFIC_LOCK:
            totals = TRAFFIC_TOTALS.setdefault(target_port, {'sum_rx': 0, 'sum_tx': 0, 'conns': {}})
            conns: Dict[str, Dict[str, int]] = totals.setdefault('conns', {})
            last = conns.get(conn_key)
            if last is None:
                totals['sum_rx'] = int(totals.get('sum_rx') or 0) + rx_value
                totals['sum_tx'] = int(totals.get('sum_tx') or 0) + tx_value
                conns[conn_key] = {'last_rx': rx_value, 'last_tx': tx_value}
            else:
                prev_rx = int(last.get('last_rx') or 0)
                prev_tx = int(last.get('last_tx') or 0)
                totals['sum_rx'] = int(totals.get('sum_rx') or 0) + (rx_value - prev_rx if rx_value >= prev_rx else rx_value)
                totals['sum_tx'] = int(totals.get('sum_tx') or 0) + (tx_value - prev_tx if tx_value >= prev_tx else tx_value)
                last['last_rx'] = rx_value
                last['last_tx'] = tx_value

            # 回写累计值到 result（仅在未成功启用 iptables 统计时）
            if not used_iptables_bytes:
                result[target_port]['rx_bytes'] = int(totals.get('sum_rx') or 0)
                result[target_port]['tx_bytes'] = int(totals.get('sum_tx') or 0)

        return True

    pending: Optional[tuple[int, str]] = None

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

    # 清理断开的连接，避免 conns 膨胀 + 读写加锁
    with _TRAFFIC_LOCK:
        for p, seen in seen_by_port.items():
            totals = TRAFFIC_TOTALS.get(p)
            if not totals:
                continue
            conns = totals.get('conns') or {}
            for k in list(conns.keys()):
                if k not in seen:
                    conns.pop(k, None)

            # 回写累计值到 result（仅在未成功启用 iptables 统计时）
            if not used_iptables_bytes:
                result[p]['rx_bytes'] = int(totals.get('sum_rx') or 0)
                result[p]['tx_bytes'] = int(totals.get('sum_tx') or 0)

    for p in target_ports:
        # 保留当前已建立连接数，前端可用于排查（不展示也不影响）
        result[p]['connections_established'] = int(result[p].get('connections') or 0)
        # 如果 conn NEW 计数不可用，则退化为当前已建立连接数
        if int(result[p].get('connections_total') or 0) <= 0 and int(result[p].get('connections_active') or 0) <= 0:
            result[p]['connections_active'] = int(result[p].get('connections') or 0)

    return result, ipt_warning


def _collect_conn_traffic(target_ports: set[int]) -> tuple[Dict[int, Dict[str, int]], Optional[str]]:
    """带短缓存的 ss 聚合结果。

    修复点：避免在持有 _SS_CACHE_LOCK 的情况下执行耗时的 `ss` 扫描，防止阻塞其它请求。
    """
    global _SS_CACHE_TS, _SS_CACHE_DATA, _SS_CACHE_ERR
    now = time.monotonic()

    # Fast path: copy cache snapshot first, then decide outside the lock.
    with _SS_CACHE_LOCK:
        cache_ts = _SS_CACHE_TS
        cache_data = _SS_CACHE_DATA
        cache_err = _SS_CACHE_ERR

    if cache_data and (now - cache_ts) <= SS_CACHE_TTL:
        filtered = {
            p: cache_data.get(
                p,
                {'connections': 0, 'connections_active': 0, 'connections_total': 0, 'rx_bytes': 0, 'tx_bytes': 0},
            )
            for p in target_ports
        }
        return filtered, cache_err

    # Slow path: do the expensive scan WITHOUT holding the cache lock.
    data, err = _scan_ss_once(target_ports)

    with _SS_CACHE_LOCK:
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


def _parse_tcping_latency(output: str) -> Optional[float]:
    matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)\s*ms", output, re.IGNORECASE)
    if matches:
        return float(matches[-1])
    match = re.search(r"time[=<]?\s*([0-9.]+)\s*ms", output, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None


def _parse_tcping_result(output: str, returncode: int) -> tuple[bool, Optional[float]]:
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


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    now = time.monotonic()
    with _PROBE_LOCK:
        item = _PROBE_CACHE.get(key)
        if not item:
            return None
        if now - float(item.get('ts', 0)) > PROBE_CACHE_TTL:
            _PROBE_CACHE.pop(key, None)
            return None
        return dict(item)


def _cache_set(key: str, ok: bool, latency_ms: Optional[float], error: Optional[str] = None) -> None:
    """Set probe cache entry and opportunistically prune expired entries."""
    global _PROBE_PRUNE_TS
    now = time.monotonic()
    with _PROBE_LOCK:
        # prune at most once per TTL window to keep O(n) work bounded
        if (now - float(_PROBE_PRUNE_TS)) > float(PROBE_CACHE_TTL):
            cutoff = now - float(PROBE_CACHE_TTL)
            for k, item in list(_PROBE_CACHE.items()):
                try:
                    if now - float(item.get('ts', 0)) > PROBE_CACHE_TTL:
                        _PROBE_CACHE.pop(k, None)
                except Exception:
                    _PROBE_CACHE.pop(k, None)
            _PROBE_PRUNE_TS = now

        _PROBE_CACHE[key] = {
            'ts': now,
            'ok': bool(ok),
            'latency_ms': latency_ms,
            'error': error,
        }


def _tcp_probe_uncached(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[bool, Optional[float], Optional[str]]:
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

    last_err: Optional[str] = None
    best_latency: Optional[float] = None
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


def _tcp_probe(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[bool, Optional[float]]:
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


def _parse_transport_host(transport: str) -> Optional[str]:
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


app = FastAPI(title='Realm Agent', version='42')
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
_PUSH_THREAD: Optional[threading.Thread] = None
_PUSH_LOCK = threading.Lock()  # 避免与 API 同时写 pool 文件导致竞争
_LAST_SYNC_ERROR: Optional[str] = None

# ------------------------ Intranet Tunnel Supervisor ------------------------
# 说明：公网节点(A) 与 内网节点(B) 之间的一对一“内网穿透”由 Agent 负责：
# - A 侧监听规则的 listen 端口，并把流量通过加密隧道转发给 B；
# - B 侧主动连 A 的隧道端口（默认 18443），按需建立 data 连接并转发到内网目标。
# 这些规则在 pool 中以 extra_config.intranet_role 标记，realm 本体不会接管。

_INTRANET = IntranetManager(node_id=AGENT_ID)


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
        'sys': _build_sys_snapshot(),
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
        _LAST_SYNC_ERROR = '同步规则失败：pool 不是对象'
        return

    do_apply = bool(cmd.get('apply', True))
    with _PUSH_LOCK:
        try:
            # 写入 full pool
            _write_json(POOL_FULL, pool)
            _sync_active_pool()

            # Keep intranet tunnel supervisor in sync for LAN/NAT nodes.
            try:
                _INTRANET.apply_from_pool(pool)
            except Exception:
                pass

            if do_apply:
                _apply_pool_to_config()
                _restart_realm()
                # Keep intranet tunnel supervisor in sync for LAN/NAT nodes.
                try:
                    _INTRANET.apply_from_pool(_load_full_pool())
                except Exception:
                    pass

            # ✅ 只有成功才 ack
            _write_int(ACK_VER_FILE, ver)
            _LAST_SYNC_ERROR = None
        except Exception as exc:
            _LAST_SYNC_ERROR = f"同步规则失败：{exc}"




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
        _LAST_SYNC_ERROR = f'增量同步失败：版本不匹配（ack={ack}, base={base_ver}）'
        return

    ops = cmd.get('ops')
    if not isinstance(ops, list) or len(ops) != 1:
        _LAST_SYNC_ERROR = '增量同步失败：ops 不合法'
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
            mp = {}
            for e in eps:
                k = _key(e)
                if k:
                    mp[k] = e

            op = ops[0]
            typ = str(op.get('op') or '').strip().lower()
            if typ == 'upsert':
                ep = op.get('endpoint')
                if not isinstance(ep, dict) or not str(ep.get('listen') or '').strip():
                    _LAST_SYNC_ERROR = '增量同步失败：endpoint 不合法'
                    return
                ep.setdefault('disabled', False)
                mp[str(ep.get('listen')).strip()] = ep
            elif typ == 'remove':
                listen = str(op.get('listen') or '').strip()
                if not listen:
                    _LAST_SYNC_ERROR = '增量同步失败：listen 不合法'
                    return
                mp.pop(listen, None)
                base_order = [x for x in base_order if x != listen]
            else:
                _LAST_SYNC_ERROR = f'增量同步失败：未知操作 {typ}'
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

            # Keep intranet tunnel supervisor in sync for LAN/NAT nodes.
            try:
                _INTRANET.apply_from_pool(new_full)
            except Exception:
                pass

            if do_apply:
                _apply_pool_to_config()
                _restart_realm()

            _write_int(ACK_VER_FILE, ver)
            _LAST_SYNC_ERROR = None
        except Exception as exc:
            _LAST_SYNC_ERROR = f"增量同步失败：{exc}"


def _get_current_agent_bind() -> tuple[str, int]:
    """Best-effort: parse current bind host/port from systemd unit."""
    host = '0.0.0.0'
    port = 18700
    for unit_path in (Path('/etc/systemd/system/realm-agent.service'), Path('/etc/systemd/system/realm-agent-https.service')):
        if not unit_path.exists():
            continue
        try:
            txt = unit_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        m_host = re.search(r"--host\s+([^\s]+)", txt)
        m_port = re.search(r"--port\s+([0-9]+)", txt)
        if m_host:
            host = m_host.group(1).strip() or host
        if m_port:
            try:
                port = int(m_port.group(1))
            except Exception:
                pass
        break
    return host, port


def _apply_update_agent_cmd(cmd: Dict[str, Any]) -> None:
    """Self-update agent using panel-provided installer + zip.

    IMPORTANT: must run updater in a separate transient systemd unit (systemd-run),
    otherwise stopping realm-agent.service would kill the updater (same cgroup).
    """
    try:
        desired_ver = str(cmd.get('desired_version') or '').strip()
        update_id = str(cmd.get('update_id') or '').strip()
        sh_url = str(cmd.get('sh_url') or '').strip()
        zip_url = str(cmd.get('zip_url') or '').strip()
        zip_sha256 = str(cmd.get('zip_sha256') or '').strip()
        force = bool(cmd.get('force', True))

        if not update_id or not desired_ver or not sh_url or not zip_url:
            st = _load_update_state()
            st.update({
                'update_id': update_id,
                'desired_version': desired_ver,
                'state': 'failed',
                'error': 'update_agent：缺少必要参数',
                'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            })
            _save_update_state(st)
            return

        # ✅ 去重：同一个 update_id 开始安装后（installing/done）不重复触发，避免心跳期间反复 systemd-run。
        st0 = _load_update_state()
        if str(st0.get('update_id') or '').strip() == update_id and str(st0.get('state') or '').strip().lower() in ('installing', 'done'):
            return

        # Already on desired (or newer)
        # 默认行为：若当前版本已满足 desired_version，则直接标记 done，不再安装。
        # 但当 force=true（面板“一键更新”点击触发）时，必须强制按面板/GitHub 文件重新安装，不做版本短路。
        try:
            if (not force) and int(str(app.version)) >= int(desired_ver) and int(desired_ver) > 0:
                st = _load_update_state()
                st.update({
                    'update_id': update_id,
                    'desired_version': desired_ver,
                    'from_version': st.get('from_version') or str(app.version),
                    'state': 'done',
                    'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'agent_version': str(app.version),
                })
                _save_update_state(st)
                return
        except Exception:
            pass

        host, port = _get_current_agent_bind()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        st = {
            'update_id': update_id,
            'desired_version': desired_ver,
            'from_version': str(app.version),
            'state': 'installing',
            'started_at': now,
            'agent_version': str(app.version),
        }
        _save_update_state(st)

        # Build updater script
        script_path = Path(f"/tmp/realm-agent-update-{update_id}.sh")
        log_path = Path(f"/var/log/realm-agent-update-{update_id}.log")
        script = f"""#!/usr/bin/env bash
set -euo pipefail

TMP_ZIP=\"/tmp/realm-agent-repo-{update_id}.zip\"
LOG=\"{log_path}\"
STATE=\"{UPDATE_STATE_FILE}\"

mkdir -p \"$(dirname \"$LOG\")\" || true

fail() {{
  local code=\"$1\"; shift || true
  local msg=\"$*\"
  python3 - <<'PY'
import json, pathlib, datetime, os
p=pathlib.Path(os.environ.get('STATE','/etc/realm-agent/agent_update.json'))
st={{}}
try:
  st=json.loads(p.read_text(encoding='utf-8'))
except Exception:
  st={{}}
st['state']='failed'
st['error']=os.environ.get('ERR_MSG','update failed')
st['finished_at']=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding='utf-8')
PY
  exit \"$code\"
}}

trap 'export ERR_MSG=\"line $LINENO: $BASH_COMMAND\"; fail $?' ERR

echo \"[update] download zip...\" | tee -a \"$LOG\"
# cache-bust to avoid CDN/proxy caching when forcing a reinstall
BUST=\"ts=$(date +%s)\"
ZURL=\"{zip_url}\"
if [[ \"$ZURL\" == http://* || \"$ZURL\" == https://* ]]; then
  if [[ \"$ZURL\" == *\\?* ]]; then
    ZURL=\"$ZURL&$BUST\"
  else
    ZURL=\"$ZURL?$BUST\"
  fi
fi
curl -fsSL -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \"$ZURL\" -o \"$TMP_ZIP\"
if [[ -n \"{zip_sha256}\" ]]; then
  echo \"{zip_sha256}  $TMP_ZIP\" | sha256sum -c -
fi

export REALM_AGENT_ASSUME_YES=1
export REALM_AGENT_MODE=1
export REALM_AGENT_ONLY=1
export REALM_AGENT_HOST=\"{host}\"
export REALM_AGENT_PORT=\"{port}\"
export REALM_AGENT_REPO_ZIP_URL=\"file://$TMP_ZIP\"

echo \"[update] run installer...\" | tee -a \"$LOG\"
SURL=\"{sh_url}\"
if [[ \"$SURL\" == http://* || \"$SURL\" == https://* ]]; then
  if [[ \"$SURL\" == *\\?* ]]; then
    SURL=\"$SURL&$BUST\"
  else
    SURL=\"$SURL?$BUST\"
  fi
fi
curl -fsSL -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \"$SURL\" | bash

python3 - <<'PY'
import json, pathlib, datetime
p=pathlib.Path(r\"{UPDATE_STATE_FILE}\")
st={{}}
try:
  st=json.loads(p.read_text(encoding='utf-8'))
except Exception:
  st={{}}
st['state']='done'
st['finished_at']=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding='utf-8')
PY

echo \"[update] done\" | tee -a \"$LOG\"
"""
        script_path.write_text(script, encoding='utf-8')
        script_path.chmod(0o755)

        # Run updater outside current service cgroup
        if shutil.which('systemd-run'):
            unit = f"realm-agent-update-{update_id}"
            subprocess.Popen(
                ['systemd-run', '--unit', unit, '--collect', '--quiet', '/bin/bash', str(script_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        else:
            st = _load_update_state()
            st.update({
                'state': 'failed',
                'error': '缺少 systemd-run，无法安全执行自更新（避免被 systemd cgroup 一并杀掉）',
                'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            })
            _save_update_state(st)
    except Exception as exc:
        st = _load_update_state()
        st.update({
            'state': 'failed',
            'error': f'update_agent 异常：{exc}',
            'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })
        _save_update_state(st)



def _apply_reset_traffic_cmd(cmd: Dict[str, Any]) -> None:
    """Reset rule traffic counters when panel requests it (push-report command).

    cmd format (signed):
      {type:'reset_traffic', version:int,
       reset_iptables?:bool, reset_baseline?:bool, reset_ss_cache?:bool, reset_conn_history?:bool,
       ts:int, nonce:str, sig:str}

    Notes:
    - Uses a monotonic version to guarantee idempotency (no repeated resets on every report).
    - On failure we DO NOT ack, so panel will retry on next report.
    """
    global _LAST_SYNC_ERROR
    try:
        ver = int(cmd.get('version') or 0)
    except Exception:
        ver = 0
    if ver <= 0:
        return

    ack = _read_int(TRAFFIC_RESET_ACK_FILE, 0)
    if ver <= ack:
        return

    reset_iptables = bool(cmd.get('reset_iptables', True))
    reset_baseline = bool(cmd.get('reset_baseline', True))
    reset_ss_cache = bool(cmd.get('reset_ss_cache', True))
    reset_conn_history = bool(cmd.get('reset_conn_history', True))

    try:
        _reset_traffic_stats(
            reset_iptables=reset_iptables,
            reset_baseline=reset_baseline,
            reset_ss_cache=reset_ss_cache,
            reset_conn_history=reset_conn_history,
        )
        _write_int(TRAFFIC_RESET_ACK_FILE, ver)
    except Exception as exc:
        _LAST_SYNC_ERROR = f'reset_traffic 失败：{exc}'
        return

def _handle_panel_commands(cmds: Any) -> None:
    if not isinstance(cmds, list) or not cmds:
        return

    api_key = _read_agent_api_key()
    for cmd in cmds:
        if not isinstance(cmd, dict):
            continue

        # Signature required for panel commands that modify state
        t = str(cmd.get('type') or '').strip()
        if t in ('sync_pool', 'pool_patch', 'update_agent', 'reset_traffic'):
            if not api_key or not _verify_cmd_sig(cmd, api_key):
                # do not crash; keep reporting error for UI
                global _LAST_SYNC_ERROR
                _LAST_SYNC_ERROR = f'{t}：签名校验失败'
                continue

        if t == 'sync_pool':
            _apply_sync_pool_cmd(cmd)
        elif t == 'pool_patch':
            _apply_pool_patch_cmd(cmd)
        elif t == 'update_agent':
            _apply_update_agent_cmd(cmd)
        elif t == 'reset_traffic':
            _apply_reset_traffic_cmd(cmd)

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

    # If we just restarted into a newer agent, flip update state.
    try:
        _reconcile_update_state()
    except Exception:
        pass

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
                'traffic_ack_version': _read_int(TRAFFIC_RESET_ACK_FILE, 0),
                'agent_version': str(app.version),
                'agent_update': _load_update_state(),
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
    try:
        _reconcile_update_state()
    except Exception:
        pass
    # Apply intranet tunnel rules on boot (if any were persisted)
    try:
        _INTRANET.apply_from_pool(_load_full_pool())
    except Exception:
        pass
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


@app.get('/api/v1/sys')
def api_sys(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    """节点系统信息：CPU/内存/硬盘/交换/在线时长/流量/速率（用于面板节点详情）。"""
    return _build_sys_snapshot()


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


@app.get('/api/v1/intranet/cert')
def api_intranet_cert(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    """返回内网穿透隧道服务端证书。

    面板可从公网节点(A)拉取证书 PEM 并下发给内网节点(B)，用于 TLS 校验（更严格）。
    """
    pem = load_server_cert_pem()
    return {'ok': True, 'cert_pem': pem}


@app.get('/api/v1/intranet/status')
def api_intranet_status(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    """内网穿透运行状态（调试用）。"""
    try:
        st = _INTRANET.status()
    except Exception as exc:
        st = {'error': str(exc)}
    return {'ok': True, 'status': st}


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
    with _PUSH_LOCK:
        _write_json(POOL_FULL, pool)
        _sync_active_pool()
        # Keep intranet tunnel supervisor in sync even if caller forgets to call /apply
        try:
            _INTRANET.apply_from_pool(_load_full_pool())
        except Exception:
            pass
    return {'ok': True}


@app.post('/api/v1/apply')
def api_apply(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    try:
        with _PUSH_LOCK:
            _sync_active_pool()
            _apply_pool_to_config()
            _restart_realm()
            # Apply intranet tunnel rules (handled by agent, not realm)
            try:
                _INTRANET.apply_from_pool(_load_full_pool())
            except Exception:
                # do not fail apply for tunnel supervisor issues
                pass
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}
    return {'ok': True}


# ------------------------ NetProbe (ping/tcping) ------------------------

_NETPROBE_PING_RE = re.compile(r'time[=<]?\s*([0-9.]+)\s*ms', re.IGNORECASE)


def _parse_tcp_target(target: str, default_port: int) -> tuple[str, int]:
    """Parse tcping target.

    Supported:
    - host
    - host:port
    - [ipv6]:port

    If no port is provided, use default_port.
    """
    s = str(target or '').strip()
    if not s:
        return '', default_port

    # [ipv6]:port
    if s.startswith('[') and ']' in s:
        host = s[1:s.index(']')]
        rest = s[s.index(']') + 1:]
        if rest.startswith(':') and rest[1:].isdigit():
            try:
                p = int(rest[1:])
                if 1 <= p <= 65535:
                    return host, p
            except Exception:
                pass
        return host, default_port

    # host:port (avoid误判ipv6: allow only one ':')
    if s.count(':') == 1:
        host, p = s.rsplit(':', 1)
        if p.isdigit():
            try:
                pi = int(p)
                if 1 <= pi <= 65535:
                    return host.strip(), pi
            except Exception:
                pass

    return s, default_port


def _icmp_ping_once(target: str, timeout_sec: float) -> Dict[str, Any]:
    """Run one ICMP ping and return latency (ms)."""
    t = str(target or '').strip()
    if not t:
        return {'ok': False, 'error': 'empty_target'}

    ping_bin = shutil.which('ping') or ''
    if not ping_bin:
        ping_bin = shutil.which('ping6') or ''
    if not ping_bin:
        return {'ok': False, 'error': 'ping_not_found'}

    try:
        to = float(timeout_sec)
    except Exception:
        to = 1.5
    if to < 0.2:
        to = 0.2
    if to > 10:
        to = 10.0

    wait_s = max(1, int(to + 0.999))

    # -n: numeric, -c 1: single packet, -W: per-packet timeout seconds
    cmd = [ping_bin, '-n', '-c', '1', '-W', str(wait_s), t]

    # Best effort: some ping supports -6 for IPv6
    if ':' in t and ping_bin.endswith('ping'):
        cmd = [ping_bin, '-6', '-n', '-c', '1', '-W', str(wait_s), t]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=wait_s + 1.0)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'timeout'}
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}

    out = (r.stdout or '') + "\n" + (r.stderr or '')
    if r.returncode == 0:
        m = _NETPROBE_PING_RE.search(out)
        if m:
            try:
                latency = float(m.group(1))
                return {'ok': True, 'latency_ms': latency}
            except Exception:
                return {'ok': True, 'latency_ms': None}
        if re.search(r'time<\s*1\s*ms', out, re.IGNORECASE):
            return {'ok': True, 'latency_ms': 1.0}
        return {'ok': True, 'latency_ms': None}

    err = out.strip().splitlines()[-1] if out.strip() else 'timeout'
    if len(err) > 200:
        err = err[:200] + '…'
    return {'ok': False, 'error': err}


def _tcp_ping_once(host: str, port: int, timeout_sec: float) -> Dict[str, Any]:
    """TCP connect latency (ms)."""
    h = str(host or '').strip()
    try:
        p = int(port)
    except Exception:
        p = 0
    if not h or p < 1 or p > 65535:
        return {'ok': False, 'error': 'invalid_target'}

    try:
        to = float(timeout_sec)
    except Exception:
        to = 1.5
    if to < 0.2:
        to = 0.2
    if to > 10:
        to = 10.0

    start = time.perf_counter()
    try:
        sock = socket.create_connection((h, p), timeout=to)
        try:
            sock.close()
        except Exception:
            pass
        latency_ms = (time.perf_counter() - start) * 1000.0
        return {'ok': True, 'latency_ms': round(latency_ms, 3)}
    except Exception as exc:
        msg = str(exc)
        if len(msg) > 200:
            msg = msg[:200] + '…'
        return {'ok': False, 'error': msg}


@app.post('/api/v1/netprobe')
def api_netprobe(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    """Batch network probe from this node."""
    mode = str(payload.get('mode') or 'ping').strip().lower()
    targets = payload.get('targets') or []
    tcp_port = payload.get('tcp_port')
    timeout = payload.get('timeout')

    if mode not in ('ping', 'tcping'):
        mode = 'ping'

    if not isinstance(targets, list):
        targets = []

    cleaned: List[str] = []
    seen: set[str] = set()
    for t in targets:
        s = str(t or '').strip()
        if not s:
            continue
        if len(s) > 128:
            continue
        if s in seen:
            continue
        seen.add(s)
        cleaned.append(s)
    targets = cleaned[:50]

    try:
        default_port = int(tcp_port) if tcp_port is not None else 443
    except Exception:
        default_port = 443
    if default_port < 1 or default_port > 65535:
        default_port = 443

    try:
        timeout_f = float(timeout) if timeout is not None else 1.5
    except Exception:
        timeout_f = 1.5
    if timeout_f < 0.2:
        timeout_f = 0.2
    if timeout_f > 10:
        timeout_f = 10.0

    if not targets:
        return {'ok': False, 'error': 'targets_empty'}

    results: Dict[str, Any] = {}

    max_workers = max(4, min(32, len(targets)))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_map = {}
        for t in targets:
            if mode == 'tcping':
                host, port = _parse_tcp_target(t, default_port)
                fut = ex.submit(_tcp_ping_once, host, port, timeout_f)
            else:
                fut = ex.submit(_icmp_ping_once, t, timeout_f)
            fut_map[fut] = t

        for fut in as_completed(fut_map):
            t = fut_map[fut]
            try:
                out = fut.result(timeout=timeout_f + 1.0)
                if isinstance(out, dict):
                    results[t] = out
                else:
                    results[t] = {'ok': False, 'error': 'probe_error'}
            except Exception as exc:
                results[t] = {'ok': False, 'error': str(exc)}

    return {'ok': True, 'mode': mode, 'tcp_port': default_port, 'timeout': timeout_f, 'results': results}




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
        # Intranet tunnel rules are handled by agent (not realm).
        # Skip probing the inner LAN remotes here; we will expose a deterministic "handshake" health entry later.
        ex = e.get('extra_config') if isinstance(e, dict) and isinstance(e.get('extra_config'), dict) else {}
        if isinstance(ex, dict) and (ex.get('intranet_role') or ex.get('intranet_token')):
            per_rule_entries.append([])
            continue

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
    port_sig: Dict[int, str] = {}
    for e in eps:
        listen = (e.get('listen') or '').strip()
        try:
            p = _parse_listen_port(listen)
        except Exception:
            p = 0
        if p > 0:
            listen_ports.add(p)
            # signature for baseline reset (one per listen port)
            if p not in port_sig:
                port_sig[p] = _traffic_endpoint_signature(e)

    conn_traffic_map, ss_err = _collect_conn_traffic(listen_ports)

    # Apply per-rule baselines: delete/recreate rule (or edit it into a new rule)
    # will reset the displayed traffic to 0, even though iptables counters are cumulative.
    _apply_traffic_baseline(port_sig, conn_traffic_map)

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

        # Intranet tunnel rules: expose "handshake" health instead of probing LAN remotes.
        ex = e.get('extra_config') if isinstance(e, dict) and isinstance(e.get('extra_config'), dict) else {}
        if isinstance(ex, dict) and (ex.get('intranet_role') or ex.get('intranet_token')):
            if bool(e.get('disabled')):
                health.append({'target': '—', 'ok': None, 'message': '规则已暂停'})
            else:
                peer = ex.get('intranet_peer_node_name') or ex.get('intranet_peer_host') or ex.get('intranet_peer_node_id') or ''
                sync_id = str(ex.get('sync_id') or '')
                hh = _INTRANET.handshake_health(sync_id, ex)
                item: Dict[str, Any] = {'kind': 'handshake', 'target': f'握手 → {peer}' if peer else '握手'}
                if hh.get('ok') is None:
                    item['ok'] = None
                    item['message'] = hh.get('message') or '不可检测'
                elif hh.get('ok') is True:
                    item['ok'] = True
                    if hh.get('latency_ms') is not None:
                        item['latency_ms'] = hh.get('latency_ms')
                    if hh.get('message'):
                        item['message'] = hh.get('message')
                else:
                    item['ok'] = False
                    item['error'] = hh.get('error') or hh.get('message') or '未连接'
                health.append(item)

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
            continue

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


def _reset_traffic_stats(
    reset_iptables: bool = True,
    reset_baseline: bool = True,
    reset_ss_cache: bool = True,
    reset_conn_history: bool = True,
) -> Dict[str, Any]:
    """Reset traffic/connection statistics for the *rule* counters.

    What this does:
    - Optionally zero iptables counters for REALMCOUNT_IN / REALMCOUNT_OUT / REALMCONN_IN.
    - Clear traffic baseline state file so UI starts from 0.
    - Clear in-memory ss/conn caches (fallback mode).

    What this does NOT do:
    - It does not reset system /proc netdev counters (node total traffic since boot).
    """
    out: Dict[str, Any] = {
        "iptables": {},
        "baseline": {"cleared": False},
        "memory": {"cleared": False},
    }

    # 1) iptables counters
    if reset_iptables and _iptables_available():
        for ch in (IPT_CHAIN_IN, IPT_CHAIN_OUT, IPT_CHAIN_CONN_IN):
            if not ch:
                continue
            rc, _o, _e = _run_iptables(['-t', IPT_TABLE, '-Z', ch])
            out["iptables"][ch] = (rc == 0)
    else:
        out["iptables"]["enabled"] = False

    # 2) baseline state file
    if reset_baseline:
        with _TRAFFIC_STATE_LOCK:
            try:
                _load_traffic_state_locked()
            except Exception:
                pass
            try:
                _TRAFFIC_STATE.clear()
            except Exception:
                pass
            # Force reload-from-disk next time (disk is deleted below)
            global _TRAFFIC_STATE_LOADED, _TRAFFIC_STATE_DIRTY
            _TRAFFIC_STATE_LOADED = False
            _TRAFFIC_STATE_DIRTY = False
            try:
                if TRAFFIC_STATE_FILE.exists():
                    TRAFFIC_STATE_FILE.unlink()
            except Exception:
                pass
        out["baseline"]["cleared"] = True

    # 3) in-memory caches (ss fallback + conn window)
    if reset_ss_cache:
        try:
            with _TRAFFIC_LOCK:
                TRAFFIC_TOTALS.clear()
        except Exception:
            pass
        try:
            with _SS_CACHE_LOCK:
                global _SS_CACHE_TS, _SS_CACHE_DATA, _SS_CACHE_ERR
                _SS_CACHE_TS = 0.0
                _SS_CACHE_DATA = {}
                _SS_CACHE_ERR = None
        except Exception:
            pass

    if reset_conn_history:
        try:
            with _CONN_HISTORY_LOCK:
                _CONN_TOTAL_HISTORY.clear()
        except Exception:
            pass

    out["memory"]["cleared"] = True
    return out


@app.post('/api/v1/traffic/reset')
def api_traffic_reset(
    payload: Dict[str, Any] = Body(default={}),
    _: None = Depends(_api_key_required),
) -> Dict[str, Any]:
    """Reset rule traffic counters.

    Panel usage:
    - POST /api/v1/traffic/reset {}
    """
    if not isinstance(payload, dict):
        payload = {}

    reset_iptables = bool(payload.get("reset_iptables", True))
    reset_baseline = bool(payload.get("reset_baseline", True))
    reset_ss_cache = bool(payload.get("reset_ss_cache", True))
    reset_conn_history = bool(payload.get("reset_conn_history", True))

    detail = _reset_traffic_stats(
        reset_iptables=reset_iptables,
        reset_baseline=reset_baseline,
        reset_ss_cache=reset_ss_cache,
        reset_conn_history=reset_conn_history,
    )

    return {
        "ok": True,
        "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "detail": detail,
    }

@app.get('/api/v1/stats')
def api_stats(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    return _build_stats_snapshot()
