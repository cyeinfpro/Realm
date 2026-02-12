from __future__ import annotations

import base64
import calendar
import gzip
import json
import re
import shutil
import shlex
import socket
import subprocess
import time
import os
import threading
import math
import hashlib
import hmac
import ipaddress
import ssl
import http.client
import glob
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
import requests

from .config import CFG
from .intranet_tunnel import IntranetManager, load_server_cert_pem, server_tls_ready
from .ipt_forward import IptablesForwardManager
from .iptables_cmd import iptables_available, run_iptables
from .qos import apply_qos_from_pool, policies_from_pool


def _env_int(name: str, default: int, min_v: int, max_v: int) -> int:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        v = int(float(raw))
    except Exception:
        v = int(default)
    if v < int(min_v):
        v = int(min_v)
    if v > int(max_v):
        v = int(max_v)
    return int(v)


def _env_float(name: str, default: float, min_v: float, max_v: float) -> float:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        v = float(raw)
    except Exception:
        v = float(default)
    if v < float(min_v):
        v = float(min_v)
    if v > float(max_v):
        v = float(max_v)
    return float(v)


API_KEY_FILE = Path('/etc/realm-agent/api.key')
ACK_VER_FILE = Path('/etc/realm-agent/panel_ack.version')
UPDATE_STATE_FILE = Path('/etc/realm-agent/agent_update.json')
TRAFFIC_STATE_FILE = Path('/etc/realm-agent/traffic_state.json')
TRAFFIC_RESET_ACK_FILE = Path('/etc/realm-agent/traffic_reset_ack.version')
AUTO_RESTART_STATE_FILE = Path('/etc/realm-agent/auto_restart_state.json')
AUTO_RESTART_POLICY_FILE = Path('/etc/realm-agent/auto_restart_policy.json')
AUTO_RESTART_ACK_FILE = Path('/etc/realm-agent/auto_restart_ack.version')
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
try:
    PROBE_HISTORY_TTL = float(os.getenv('REALM_AGENT_PROBE_HISTORY_TTL', '900'))  # seconds
except Exception:
    PROBE_HISTORY_TTL = 900.0
if PROBE_HISTORY_TTL < 60.0:
    PROBE_HISTORY_TTL = 60.0
if PROBE_HISTORY_TTL > 86400.0:
    PROBE_HISTORY_TTL = 86400.0
PROBE_HISTORY_ALPHA_OVERRIDE = os.getenv('REALM_AGENT_PROBE_HISTORY_ALPHA', '').strip()
try:
    PROBE_HISTORY_ALPHA = float(PROBE_HISTORY_ALPHA_OVERRIDE) if PROBE_HISTORY_ALPHA_OVERRIDE else None
except Exception:
    PROBE_HISTORY_ALPHA = None
if PROBE_HISTORY_ALPHA is not None:
    if PROBE_HISTORY_ALPHA < 0.01:
        PROBE_HISTORY_ALPHA = 0.01
    if PROBE_HISTORY_ALPHA > 0.95:
        PROBE_HISTORY_ALPHA = 0.95
try:
    PROBE_HISTORY_HALFLIFE = float(
        os.getenv('REALM_AGENT_PROBE_HISTORY_HALFLIFE', str(max(120.0, PROBE_HISTORY_TTL / 3.0)))
    )
except Exception:
    PROBE_HISTORY_HALFLIFE = max(120.0, PROBE_HISTORY_TTL / 3.0)
if PROBE_HISTORY_HALFLIFE < 30.0:
    PROBE_HISTORY_HALFLIFE = 30.0
if PROBE_HISTORY_HALFLIFE > 86400.0:
    PROBE_HISTORY_HALFLIFE = 86400.0
try:
    PROBE_HISTORY_MIN_SAMPLES = int(os.getenv('REALM_AGENT_PROBE_HISTORY_MIN_SAMPLES', '5'))
except Exception:
    PROBE_HISTORY_MIN_SAMPLES = 5
if PROBE_HISTORY_MIN_SAMPLES < 1:
    PROBE_HISTORY_MIN_SAMPLES = 1
if PROBE_HISTORY_MIN_SAMPLES > 100:
    PROBE_HISTORY_MIN_SAMPLES = 100
try:
    PROBE_DOWN_FAILS = int(os.getenv('REALM_AGENT_PROBE_DOWN_FAILS', '3'))
except Exception:
    PROBE_DOWN_FAILS = 3
if PROBE_DOWN_FAILS < 1:
    PROBE_DOWN_FAILS = 1
if PROBE_DOWN_FAILS > 20:
    PROBE_DOWN_FAILS = 20

_PROBE_CACHE: Dict[str, Dict[str, Any]] = {}
_PROBE_PRUNE_TS = 0.0
_PROBE_HISTORY: Dict[str, Dict[str, Any]] = {}
_PROBE_HISTORY_PRUNE_TS = 0.0
_PROBE_LOCK = threading.Lock()
TRACE_AUTO_INSTALL = str(os.getenv('REALM_AGENT_TRACE_AUTO_INSTALL', '1')).strip().lower() not in ('0', 'false', 'off', 'no')
_TRACE_TOOL_INSTALL_LOCK = threading.Lock()
_TRACE_TOOL_INSTALL_ATTEMPTED = False
_TRACE_TOOL_INSTALL_LAST: Dict[str, Any] = {}

# ---------------- System Snapshot (CPU/Mem/Disk/Net) ----------------
# 说明：不依赖 psutil，纯 /proc + shutil.disk_usage 实现。
# 用于面板节点详情展示（CPU/内存/硬盘/交换/在线时长/流量/实时速率），默认 3s 上报一次。
_SYS_LOCK = threading.Lock()
_SYS_CPU_LAST: Optional[dict] = None  # {total:int, idle:int, ts:float}
_SYS_NET_LAST: Optional[dict] = None  # {rx:int, tx:int, ts:float}

# ---------------- Auto Daily Restart (per-node low-impact window) ----------------
# 基于本机实时吞吐学习“每小时负载画像”（EMA），每天自动选择影响最小小时重启 realm + agent。
AUTO_RESTART_ENABLED = str(os.getenv('REALM_AGENT_AUTO_DAILY_RESTART', '1')).strip().lower() not in (
    '0',
    'false',
    'off',
    'no',
)
AUTO_RESTART_DEFAULT_HOUR = _env_int('REALM_AGENT_AUTO_RESTART_DEFAULT_HOUR', 4, 0, 23)
AUTO_RESTART_BASE_MINUTE = _env_int('REALM_AGENT_AUTO_RESTART_BASE_MINUTE', 8, 0, 59)
AUTO_RESTART_WINDOW_MINUTES = _env_int('REALM_AGENT_AUTO_RESTART_WINDOW_MINUTES', 10, 1, 59)
AUTO_RESTART_MIN_PROFILE_SAMPLES = _env_int('REALM_AGENT_AUTO_RESTART_MIN_PROFILE_SAMPLES', 6, 1, 1000)
AUTO_RESTART_MIN_PROFILE_HOURS = _env_int('REALM_AGENT_AUTO_RESTART_MIN_PROFILE_HOURS', 4, 1, 24)
AUTO_RESTART_PROFILE_ALPHA = _env_float('REALM_AGENT_AUTO_RESTART_PROFILE_ALPHA', 0.20, 0.01, 0.95)
AUTO_RESTART_MIN_UPTIME_SEC = _env_float('REALM_AGENT_AUTO_RESTART_MIN_UPTIME_SEC', 600.0, 30.0, 604800.0)
AUTO_RESTART_MINUTE_JITTER = _env_int('REALM_AGENT_AUTO_RESTART_MINUTE_JITTER', 0, 0, 30)
AUTO_RESTART_SKIP_UPDATE_ACTIVE = str(os.getenv('REALM_AGENT_AUTO_RESTART_SKIP_UPDATE_ACTIVE', '1')).strip().lower() not in (
    '0',
    'false',
    'off',
    'no',
)
AUTO_RESTART_SAVE_MIN_INTERVAL = _env_float('REALM_AGENT_AUTO_RESTART_SAVE_INTERVAL', 20.0, 1.0, 3600.0)
AUTO_RESTART_RETRY_COOLDOWN_SEC = _env_float('REALM_AGENT_AUTO_RESTART_RETRY_COOLDOWN_SEC', 120.0, 5.0, 3600.0)

_AUTO_RESTART_LOCK = threading.Lock()
_AUTO_RESTART_STATE_LOADED = False
_AUTO_RESTART_STATE: Dict[str, Any] = {}
_AUTO_RESTART_LAST_SAVE_TS = 0.0
_AUTO_RESTART_POLICY_LOCK = threading.Lock()
_AUTO_RESTART_POLICY_LOADED = False
_AUTO_RESTART_POLICY: Dict[str, Any] = {}


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


def _canon_update_state(raw: Any) -> str:
    s = str(raw or '').strip().lower()
    if s in ('queued', 'pending'):
        return 'queued'
    if s in ('sent', 'delivered'):
        return 'delivered'
    if s == 'accepted':
        return 'accepted'
    if s in ('installing', 'running'):
        return 'running'
    if s == 'retrying':
        return 'retrying'
    if s in ('done', 'success'):
        return 'done'
    if s in ('failed', 'error'):
        return 'failed'
    if s in ('expired', 'timeout'):
        return 'expired'
    return s


def _to_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return bool(default)
    if isinstance(v, (int, float)):
        return bool(int(v))
    s = str(v).strip().lower()
    if s in ('1', 'true', 'yes', 'on', 'y'):
        return True
    if s in ('0', 'false', 'no', 'off', 'n', ''):
        return False
    return bool(default)


def _load_update_state() -> Dict[str, Any]:
    st = _read_json(UPDATE_STATE_FILE, {})
    if not isinstance(st, dict):
        return {}
    if 'state' in st:
        st['state'] = _canon_update_state(st.get('state'))
    return st


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
    state = _canon_update_state(st.get('state'))
    if desired > 0 and int(str(app.version)) >= desired and state in ('running', 'delivered', 'queued', 'accepted'):
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


def _default_auto_restart_policy() -> Dict[str, Any]:
    return {
        "enabled": bool(AUTO_RESTART_ENABLED),
        "schedule_type": "daily",  # daily | weekly | monthly
        "interval": 1,
        "hour": int(AUTO_RESTART_DEFAULT_HOUR),
        "minute": int(AUTO_RESTART_BASE_MINUTE),
        "weekdays": [1, 2, 3, 4, 5, 6, 7],  # ISO weekday (Mon=1..Sun=7)
        "monthdays": [1],  # 1..31 (overflow days fallback to month end)
    }


def _normalize_auto_restart_policy(raw: Any) -> Dict[str, Any]:
    src = raw if isinstance(raw, dict) else {}
    base = _default_auto_restart_policy()

    enabled = _to_bool(src.get("enabled"), base["enabled"])
    schedule_type = str(src.get("schedule_type") or base["schedule_type"]).strip().lower()
    if schedule_type not in ("daily", "weekly", "monthly"):
        schedule_type = "daily"
    try:
        interval = int(src.get("interval") or base["interval"])
    except Exception:
        interval = int(base["interval"])
    if interval < 1:
        interval = 1
    if interval > 365:
        interval = 365
    hour_raw = src.get("hour", base["hour"])
    if hour_raw is None:
        hour_raw = base["hour"]
    try:
        hour = int(hour_raw)
    except Exception:
        hour = int(base["hour"])
    if hour < 0:
        hour = 0
    if hour > 23:
        hour = 23
    minute_raw = src.get("minute", base["minute"])
    if minute_raw is None:
        minute_raw = base["minute"]
    try:
        minute = int(minute_raw)
    except Exception:
        minute = int(base["minute"])
    if minute < 0:
        minute = 0
    if minute > 59:
        minute = 59

    def _norm_seq(val: Any, lo: int, hi: int, fallback: List[int]) -> List[int]:
        out: List[int] = []
        seen: set[int] = set()
        seq = val if isinstance(val, list) else []
        for x in seq:
            try:
                v = int(x)
            except Exception:
                continue
            if v < int(lo) or v > int(hi):
                continue
            if v in seen:
                continue
            seen.add(v)
            out.append(v)
        if not out:
            return list(fallback)
        return out

    weekdays = _norm_seq(src.get("weekdays"), 1, 7, [1, 2, 3, 4, 5, 6, 7])
    monthdays = _norm_seq(src.get("monthdays"), 1, 31, [1])
    return {
        "enabled": bool(enabled),
        "schedule_type": schedule_type,
        "interval": int(interval),
        "hour": int(hour),
        "minute": int(minute),
        "weekdays": weekdays,
        "monthdays": monthdays,
    }


def _auto_restart_load_policy_locked() -> Dict[str, Any]:
    global _AUTO_RESTART_POLICY_LOADED, _AUTO_RESTART_POLICY
    if _AUTO_RESTART_POLICY_LOADED:
        return dict(_AUTO_RESTART_POLICY)
    raw = _read_json(AUTO_RESTART_POLICY_FILE, {})
    policy = _normalize_auto_restart_policy(raw)
    _AUTO_RESTART_POLICY = policy
    _AUTO_RESTART_POLICY_LOADED = True
    return dict(policy)


def _auto_restart_save_policy_locked(policy: Dict[str, Any]) -> None:
    global _AUTO_RESTART_POLICY_LOADED, _AUTO_RESTART_POLICY
    norm = _normalize_auto_restart_policy(policy)
    try:
        _write_json(AUTO_RESTART_POLICY_FILE, norm)
    except Exception:
        pass
    _AUTO_RESTART_POLICY = dict(norm)
    _AUTO_RESTART_POLICY_LOADED = True


def _auto_restart_default_state() -> Dict[str, Any]:
    return {
        'version': 1,
        'profile': {},  # hour -> {ema_bps: float, samples: int}
        'daily_date': '',
        'daily_hourly': {},  # hour -> {sum_bps: float, samples: int}
        'plan_date': '',
        'plan_hour': int(AUTO_RESTART_DEFAULT_HOUR),
        'plan_minute': int(AUTO_RESTART_BASE_MINUTE),
        'plan_reason': 'init',
        'last_check_at': '',
        'last_load_bps': 0.0,
        'last_skip_reason': '',
        'last_restart_date': '',
        'last_restart_ts': 0,
        'last_attempt_ts': 0,
        'last_restart_hour': -1,
        'last_restart_minute': -1,
        'last_restart_result': '',
        'last_error': '',
    }


def _auto_restart_load_state_locked() -> None:
    global _AUTO_RESTART_STATE_LOADED, _AUTO_RESTART_STATE
    if _AUTO_RESTART_STATE_LOADED:
        return

    raw = _read_json(AUTO_RESTART_STATE_FILE, {})
    st = _auto_restart_default_state()
    if isinstance(raw, dict):
        st['daily_date'] = str(raw.get('daily_date') or '').strip()
        st['plan_date'] = str(raw.get('plan_date') or '').strip()
        st['plan_reason'] = str(raw.get('plan_reason') or 'init').strip() or 'init'
        st['last_check_at'] = str(raw.get('last_check_at') or '').strip()
        st['last_skip_reason'] = str(raw.get('last_skip_reason') or '').strip()
        st['last_restart_date'] = str(raw.get('last_restart_date') or '').strip()
        st['last_restart_result'] = str(raw.get('last_restart_result') or '').strip()
        st['last_error'] = str(raw.get('last_error') or '').strip()
        try:
            st['plan_hour'] = max(0, min(23, int(raw.get('plan_hour') or AUTO_RESTART_DEFAULT_HOUR)))
        except Exception:
            st['plan_hour'] = int(AUTO_RESTART_DEFAULT_HOUR)
        try:
            st['plan_minute'] = max(0, min(59, int(raw.get('plan_minute') or AUTO_RESTART_BASE_MINUTE)))
        except Exception:
            st['plan_minute'] = int(AUTO_RESTART_BASE_MINUTE)
        try:
            st['last_load_bps'] = max(0.0, float(raw.get('last_load_bps') or 0.0))
        except Exception:
            st['last_load_bps'] = 0.0
        try:
            st['last_restart_ts'] = max(0, int(raw.get('last_restart_ts') or 0))
        except Exception:
            st['last_restart_ts'] = 0
        try:
            st['last_attempt_ts'] = max(0, int(raw.get('last_attempt_ts') or 0))
        except Exception:
            st['last_attempt_ts'] = 0
        try:
            st['last_restart_hour'] = int(raw.get('last_restart_hour') or -1)
        except Exception:
            st['last_restart_hour'] = -1
        try:
            st['last_restart_minute'] = int(raw.get('last_restart_minute') or -1)
        except Exception:
            st['last_restart_minute'] = -1

        profile_raw = raw.get('profile')
        if isinstance(profile_raw, dict):
            prof: Dict[str, Dict[str, Any]] = {}
            for hk, hv in profile_raw.items():
                if not isinstance(hv, dict):
                    continue
                try:
                    hi = int(str(hk).strip())
                except Exception:
                    continue
                if hi < 0 or hi > 23:
                    continue
                try:
                    ema = max(0.0, float(hv.get('ema_bps') or 0.0))
                except Exception:
                    ema = 0.0
                try:
                    samples = max(0, int(hv.get('samples') or 0))
                except Exception:
                    samples = 0
                prof[str(hi)] = {'ema_bps': round(float(ema), 4), 'samples': int(min(samples, 1000000))}
            st['profile'] = prof

        daily_raw = raw.get('daily_hourly')
        if isinstance(daily_raw, dict):
            daily: Dict[str, Dict[str, Any]] = {}
            for hk, hv in daily_raw.items():
                if not isinstance(hv, dict):
                    continue
                try:
                    hi = int(str(hk).strip())
                except Exception:
                    continue
                if hi < 0 or hi > 23:
                    continue
                try:
                    sm = max(0.0, float(hv.get('sum_bps') or 0.0))
                except Exception:
                    sm = 0.0
                try:
                    sp = max(0, int(hv.get('samples') or 0))
                except Exception:
                    sp = 0
                daily[str(hi)] = {'sum_bps': round(float(sm), 4), 'samples': int(min(sp, 1000000))}
            st['daily_hourly'] = daily

    _AUTO_RESTART_STATE = st
    _AUTO_RESTART_STATE_LOADED = True


def _auto_restart_save_state_locked(force: bool = False) -> None:
    global _AUTO_RESTART_LAST_SAVE_TS
    now_ts = float(time.time())
    if not force and (now_ts - float(_AUTO_RESTART_LAST_SAVE_TS)) < float(AUTO_RESTART_SAVE_MIN_INTERVAL):
        return
    try:
        _write_json(AUTO_RESTART_STATE_FILE, _AUTO_RESTART_STATE)
        _AUTO_RESTART_LAST_SAVE_TS = now_ts
    except Exception:
        pass


def _auto_restart_ingest_sample_locked(now_dt: datetime, load_bps: float) -> None:
    if not math.isfinite(load_bps) or load_bps < 0:
        load_bps = 0.0
    st = _AUTO_RESTART_STATE
    date_s = now_dt.strftime('%Y-%m-%d')
    hour_k = str(int(now_dt.hour))

    if str(st.get('daily_date') or '') != date_s:
        st['daily_date'] = date_s
        st['daily_hourly'] = {}

    daily = st.get('daily_hourly')
    if not isinstance(daily, dict):
        daily = {}
        st['daily_hourly'] = daily
    dslot = daily.get(hour_k)
    if not isinstance(dslot, dict):
        dslot = {'sum_bps': 0.0, 'samples': 0}
    try:
        dslot_sum = float(dslot.get('sum_bps') or 0.0)
    except Exception:
        dslot_sum = 0.0
    try:
        dslot_samples = int(dslot.get('samples') or 0)
    except Exception:
        dslot_samples = 0
    dslot['sum_bps'] = round(max(0.0, dslot_sum + float(load_bps)), 4)
    dslot['samples'] = int(min(1000000, max(0, dslot_samples + 1)))
    daily[hour_k] = dslot

    prof = st.get('profile')
    if not isinstance(prof, dict):
        prof = {}
        st['profile'] = prof
    pslot = prof.get(hour_k)
    if not isinstance(pslot, dict):
        pslot = {'ema_bps': float(load_bps), 'samples': 0}
    try:
        p_ema = float(pslot.get('ema_bps') or 0.0)
    except Exception:
        p_ema = 0.0
    try:
        p_samples = int(pslot.get('samples') or 0)
    except Exception:
        p_samples = 0
    if p_samples <= 0:
        new_ema = float(load_bps)
    else:
        alpha = float(AUTO_RESTART_PROFILE_ALPHA)
        new_ema = (1.0 - alpha) * p_ema + alpha * float(load_bps)
    pslot['ema_bps'] = round(max(0.0, float(new_ema)), 4)
    pslot['samples'] = int(min(1000000, max(0, p_samples + 1)))
    prof[hour_k] = pslot

    st['last_check_at'] = now_dt.strftime('%Y-%m-%d %H:%M:%S')
    st['last_load_bps'] = round(max(0.0, float(load_bps)), 2)


def _auto_restart_plan_locked(now_dt: datetime) -> tuple[int, int, str]:
    st = _AUTO_RESTART_STATE
    profile = st.get('profile')
    if not isinstance(profile, dict):
        profile = {}

    observed_hours = 0
    candidates: List[Tuple[float, int]] = []
    for hour in range(24):
        slot = profile.get(str(hour))
        if not isinstance(slot, dict):
            continue
        try:
            samples = int(slot.get('samples') or 0)
        except Exception:
            samples = 0
        try:
            ema_bps = float(slot.get('ema_bps') or 0.0)
        except Exception:
            ema_bps = 0.0
        if samples > 0:
            observed_hours += 1
        if samples >= int(AUTO_RESTART_MIN_PROFILE_SAMPLES):
            candidates.append((max(0.0, ema_bps), int(hour)))

    plan_hour = int(AUTO_RESTART_DEFAULT_HOUR)
    plan_reason = 'fallback_default'
    if observed_hours >= int(AUTO_RESTART_MIN_PROFILE_HOURS) and candidates:
        candidates.sort(key=lambda x: (x[0], x[1]))
        plan_hour = int(candidates[0][1])
        plan_reason = 'profile_ema'

    minute = int(AUTO_RESTART_BASE_MINUTE)
    if int(AUTO_RESTART_MINUTE_JITTER) > 0:
        # 节点级固定抖动：避免多节点在同一分钟同时重启。
        seed = f"{socket.gethostname()}:{plan_hour}"
        try:
            hv = int(hashlib.sha256(seed.encode('utf-8')).hexdigest()[:8], 16)
            minute = int((minute + (hv % (int(AUTO_RESTART_MINUTE_JITTER) + 1))) % 60)
        except Exception:
            minute = int(AUTO_RESTART_BASE_MINUTE)

    st['plan_date'] = now_dt.strftime('%Y-%m-%d')
    st['plan_hour'] = int(plan_hour)
    st['plan_minute'] = int(minute)
    st['plan_reason'] = str(plan_reason)
    return int(plan_hour), int(minute), str(plan_reason)


def _auto_restart_match_monthday(now_dt: datetime, monthdays: List[int]) -> bool:
    try:
        last_day = int(calendar.monthrange(int(now_dt.year), int(now_dt.month))[1])
    except Exception:
        last_day = 31
    due_days: set[int] = set()
    for d in monthdays or []:
        try:
            v = int(d)
        except Exception:
            continue
        if v < 1:
            continue
        if v > 31:
            continue
        due_days.add(min(v, last_day))
    if not due_days:
        due_days = {1}
    return int(now_dt.day) in due_days


def _auto_restart_schedule_due(policy: Dict[str, Any], now_dt: datetime, last_restart_ts: int) -> tuple[bool, str]:
    mode = str(policy.get("schedule_type") or "daily").strip().lower()
    interval = int(policy.get("interval") or 1)
    if interval < 1:
        interval = 1

    if mode == "weekly":
        wd = set(int(x) for x in (policy.get("weekdays") or []) if isinstance(x, int) and 1 <= int(x) <= 7)
        if not wd:
            wd = {1, 2, 3, 4, 5, 6, 7}
        if int(now_dt.isoweekday()) not in wd:
            return False, ""
        if last_restart_ts > 0:
            try:
                last_dt = datetime.fromtimestamp(float(last_restart_ts))
                cur_week = (int(now_dt.date().toordinal()) - 1) // 7
                last_week = (int(last_dt.date().toordinal()) - 1) // 7
                week_delta = int(cur_week - last_week)
                if week_delta == 0:
                    if now_dt.date() == last_dt.date():
                        return False, "already_today"
                    return True, ""
                if week_delta < int(interval):
                    return False, "interval_wait"
            except Exception:
                pass
        return True, ""

    if mode == "monthly":
        if not _auto_restart_match_monthday(now_dt, list(policy.get("monthdays") or [])):
            return False, ""
        if last_restart_ts > 0:
            try:
                last_dt = datetime.fromtimestamp(float(last_restart_ts))
                cur_idx = int(now_dt.year) * 12 + int(now_dt.month)
                last_idx = int(last_dt.year) * 12 + int(last_dt.month)
                month_delta = int(cur_idx - last_idx)
                if month_delta == 0:
                    if now_dt.date() == last_dt.date():
                        return False, "already_today"
                    return True, ""
                if month_delta < int(interval):
                    return False, "interval_wait"
            except Exception:
                pass
        return True, ""

    # daily (default)
    if last_restart_ts > 0:
        try:
            last_dt = datetime.fromtimestamp(float(last_restart_ts))
            d_days = int((now_dt.date() - last_dt.date()).days)
            if d_days < int(interval):
                return False, "interval_wait"
        except Exception:
            pass
    return True, ""


def _auto_restart_policy_time(policy: Dict[str, Any]) -> tuple[int, int]:
    try:
        hh = int(policy.get("hour"))
    except Exception:
        hh = int(AUTO_RESTART_DEFAULT_HOUR)
    try:
        mm = int(policy.get("minute"))
    except Exception:
        mm = int(AUTO_RESTART_BASE_MINUTE)
    hh = max(0, min(23, int(hh)))
    mm = max(0, min(59, int(mm)))
    return int(hh), int(mm)


def _auto_restart_status_snapshot() -> Dict[str, Any]:
    now_dt = datetime.now()
    with _AUTO_RESTART_POLICY_LOCK:
        policy = _auto_restart_load_policy_locked()
    with _AUTO_RESTART_LOCK:
        _auto_restart_load_state_locked()
        st = _AUTO_RESTART_STATE
        plan_hour, plan_minute = _auto_restart_policy_time(policy)
        plan_reason = f"policy_{str(policy.get('schedule_type') or 'daily')}"
        st['plan_date'] = now_dt.strftime('%Y-%m-%d')
        st['plan_hour'] = int(plan_hour)
        st['plan_minute'] = int(plan_minute)
        st['plan_reason'] = str(plan_reason)
        return {
            'enabled': bool(policy.get("enabled", False)),
            'schedule_type': str(policy.get("schedule_type") or "daily"),
            'interval': int(policy.get("interval") or 1),
            'weekdays': list(policy.get("weekdays") or [1, 2, 3, 4, 5, 6, 7]),
            'monthdays': list(policy.get("monthdays") or [1]),
            'plan_date': str(st.get('plan_date') or now_dt.strftime('%Y-%m-%d')),
            'plan_hour': int(plan_hour),
            'plan_minute': int(plan_minute),
            'plan_reason': str(plan_reason),
            'window_minutes': int(AUTO_RESTART_WINDOW_MINUTES),
            'last_restart_date': str(st.get('last_restart_date') or ''),
            'last_restart_ts': int(st.get('last_restart_ts') or 0),
            'last_attempt_ts': int(st.get('last_attempt_ts') or 0),
            'ack_version': int(_read_int(AUTO_RESTART_ACK_FILE, 0)),
            'last_restart_result': str(st.get('last_restart_result') or ''),
            'last_error': str(st.get('last_error') or ''),
            'last_skip_reason': str(st.get('last_skip_reason') or ''),
            'last_load_bps': float(st.get('last_load_bps') or 0.0),
        }


def _auto_restart_tick(report: Optional[Dict[str, Any]]) -> None:
    if not isinstance(report, dict):
        return

    now_dt = datetime.now()
    now_ts = float(time.time())
    load_bps = 0.0
    uptime_sec = 0.0

    sys_part = report.get('sys')
    if isinstance(sys_part, dict):
        net = sys_part.get('net')
        if isinstance(net, dict):
            try:
                load_bps = float(net.get('rx_bps') or 0.0) + float(net.get('tx_bps') or 0.0)
            except Exception:
                load_bps = 0.0
        try:
            uptime_sec = float(sys_part.get('uptime_sec') or 0.0)
        except Exception:
            uptime_sec = 0.0
    if not math.isfinite(load_bps) or load_bps < 0.0:
        load_bps = 0.0
    if not math.isfinite(uptime_sec) or uptime_sec < 0.0:
        uptime_sec = 0.0

    with _AUTO_RESTART_POLICY_LOCK:
        policy = _auto_restart_load_policy_locked()

    restart_due = False
    plan_hour, plan_minute = _auto_restart_policy_time(policy)
    plan_reason = f"policy_{str(policy.get('schedule_type') or 'daily')}"
    with _AUTO_RESTART_LOCK:
        _auto_restart_load_state_locked()
        _auto_restart_ingest_sample_locked(now_dt, load_bps)
        st = _AUTO_RESTART_STATE
        st['plan_date'] = now_dt.strftime('%Y-%m-%d')
        st['plan_hour'] = int(plan_hour)
        st['plan_minute'] = int(plan_minute)
        st['plan_reason'] = str(plan_reason)
        today = now_dt.strftime('%Y-%m-%d')
        window_end = min(59, int(plan_minute) + int(AUTO_RESTART_WINDOW_MINUTES) - 1)
        last_attempt_ts = float(st.get('last_attempt_ts') or 0.0)
        last_restart_ts = int(st.get('last_restart_ts') or 0)

        if not bool(policy.get("enabled", False)):
            st['last_skip_reason'] = 'disabled'
            _auto_restart_save_state_locked(force=False)
            return

        if uptime_sec < float(AUTO_RESTART_MIN_UPTIME_SEC):
            st['last_skip_reason'] = 'uptime_too_short'
            _auto_restart_save_state_locked(force=False)
            return

        in_window = (
            int(now_dt.hour) == int(plan_hour)
            and int(now_dt.minute) >= int(plan_minute)
            and int(now_dt.minute) <= int(window_end)
        )
        if not in_window:
            _auto_restart_save_state_locked(force=False)
            return

        due_ok, due_reason = _auto_restart_schedule_due(policy, now_dt, last_restart_ts)
        if not due_ok:
            if due_reason:
                st['last_skip_reason'] = str(due_reason)
            _auto_restart_save_state_locked(force=False)
            return

        if str(st.get('last_restart_date') or '') != today or last_restart_ts <= 0:
            if uptime_sec < float(AUTO_RESTART_MIN_UPTIME_SEC):
                st['last_skip_reason'] = 'uptime_too_short'
            else:
                if last_attempt_ts > 0 and (now_ts - last_attempt_ts) < float(AUTO_RESTART_RETRY_COOLDOWN_SEC):
                    st['last_skip_reason'] = 'retry_cooldown'
                else:
                    block_update = False
                    update_state = ''
                    if AUTO_RESTART_SKIP_UPDATE_ACTIVE:
                        update_state = _canon_update_state((_load_update_state() or {}).get('state'))
                        if update_state in ('accepted', 'running'):
                            block_update = True
                    if block_update:
                        st['last_skip_reason'] = f'update_active:{update_state}'
                    else:
                        restart_due = True
                        st['last_skip_reason'] = ''
                        st['last_attempt_ts'] = int(now_ts)
                        st['last_restart_result'] = 'triggering'
                        st['last_error'] = ''
        _auto_restart_save_state_locked(force=restart_due)

    if not restart_due:
        return

    try:
        _restart_realm()
    except Exception as exc:
        with _AUTO_RESTART_LOCK:
            _auto_restart_load_state_locked()
            st = _AUTO_RESTART_STATE
            st['last_restart_result'] = 'failed_realm'
            st['last_error'] = str(exc)[:500]
            _auto_restart_save_state_locked(force=True)
        return

    try:
        _restart_agent_service()
    except Exception as exc:
        with _AUTO_RESTART_LOCK:
            _auto_restart_load_state_locked()
            st = _AUTO_RESTART_STATE
            st['last_restart_result'] = 'failed_agent'
            st['last_error'] = str(exc)[:500]
            _auto_restart_save_state_locked(force=True)
        return

    with _AUTO_RESTART_LOCK:
        _auto_restart_load_state_locked()
        st = _AUTO_RESTART_STATE
        st['last_restart_date'] = now_dt.strftime('%Y-%m-%d')
        st['last_restart_ts'] = int(now_ts)
        st['last_restart_hour'] = int(plan_hour)
        st['last_restart_minute'] = int(plan_minute)
        st['last_restart_result'] = 'dispatched'
        st['last_error'] = ''
        _auto_restart_save_state_locked(force=True)


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
_PANEL_TIME_LOCK = threading.Lock()
_PANEL_TIME_OFFSET_SEC = 0.0  # panel_unix_ts - local_time.time()


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



def _panel_now_ts() -> int:
    with _PANEL_TIME_LOCK:
        off = float(_PANEL_TIME_OFFSET_SEC)
    return int(time.time() + off)


def _update_panel_time_offset(server_ts: Any) -> None:
    try:
        panel_ts = float(server_ts)
    except Exception:
        return
    if panel_ts <= 0:
        return
    now_local = float(time.time())
    off = panel_ts - now_local
    # Ignore impossible values to avoid poisoning local validation.
    if abs(off) > 365.0 * 24.0 * 3600.0:
        return
    with _PANEL_TIME_LOCK:
        global _PANEL_TIME_OFFSET_SEC
        prev = float(_PANEL_TIME_OFFSET_SEC)
        if prev == 0.0:
            _PANEL_TIME_OFFSET_SEC = off
        else:
            # Smooth jitter between requests.
            _PANEL_TIME_OFFSET_SEC = (prev * 0.8) + (off * 0.2)


def _verify_cmd_sig_detail(cmd: Dict[str, Any], api_key: str) -> Tuple[bool, str]:
    sig = str(cmd.get("sig") or "").strip()
    if not sig:
        return False, "missing_sig"

    # 1) signature (covers ts/nonce/...)
    expect = _cmd_signature(api_key, cmd)
    if not hmac.compare_digest(sig, expect):
        return False, "bad_sig"

    # 2) timestamp window check (basic replay mitigation)
    try:
        ts = int(cmd.get("ts") or 0)
    except Exception:
        return False, "bad_ts"
    if ts <= 0:
        return False, "bad_ts"
    now_panel = int(_panel_now_ts())
    skew = int(now_panel - ts)
    if abs(skew) > int(max(1, CMD_SIG_MAX_SKEW_SEC)):
        return False, f"ts_skew={skew}s"

    # 3) nonce replay protection (preferred). Keep legacy compatibility: if nonce missing, accept.
    nonce = str(cmd.get("nonce") or "").strip()
    if nonce:
        if not _remember_cmd_nonce(nonce):
            return False, "replay_nonce"

    return True, ""


def _verify_cmd_sig(cmd: Dict[str, Any], api_key: str) -> bool:
    """Verify command signature + timestamp window + (optional) nonce replay protection."""
    ok, _ = _verify_cmd_sig_detail(cmd, api_key)
    return bool(ok)



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
    # systemd
    if shutil.which('systemctl'):
        try:
            r = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip() == 'active':
                return True
        except Exception:
            # No systemctl or systemd not running in this environment
            pass

    # sysvinit style
    if shutil.which('service'):
        try:
            r = subprocess.run(['service', name, 'status'], capture_output=True, text=True)
            if r.returncode == 0:
                return True
        except Exception:
            pass

    # openrc
    if shutil.which('rc-service'):
        try:
            r = subprocess.run(['rc-service', name, 'status'], capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False
    return False


def _stop_service(name: str) -> None:
    for cmd in (["systemctl", "stop", name], ["service", name, "stop"], ["rc-service", name, "stop"]):
        if shutil.which(cmd[0]) is None:
            continue
        try:
            subprocess.run(cmd, capture_output=True, text=True)
            return
        except Exception:
            continue


def _restart_realm() -> None:
    candidates = []
    if CFG.realm_service:
        candidates.append(CFG.realm_service)
    candidates.extend(['realm.service', 'realm'])
    seen = set()
    services = [s for s in candidates if s and not (s in seen or seen.add(s))]
    errors = []

    if shutil.which('systemctl'):
        for svc in services:
            try:
                r = subprocess.run(['systemctl', 'restart', svc], capture_output=True, text=True)
                if r.returncode == 0:
                    return
                errors.append(f"systemctl {svc}: {r.stderr.strip() or r.stdout.strip()}")
            except Exception as exc:
                errors.append(f"systemctl {svc}: {exc}")

    if shutil.which('service'):
        for svc in services:
            try:
                r = subprocess.run(['service', svc, 'restart'], capture_output=True, text=True)
                if r.returncode == 0:
                    return
                errors.append(f"service {svc}: {r.stderr.strip() or r.stdout.strip()}")
            except Exception as exc:
                errors.append(f"service {svc}: {exc}")

    if shutil.which('rc-service'):
        for svc in services:
            try:
                r = subprocess.run(['rc-service', svc, 'restart'], capture_output=True, text=True)
                if r.returncode == 0:
                    return
                errors.append(f"rc-service {svc}: {r.stderr.strip() or r.stdout.strip()}")
            except Exception as exc:
                errors.append(f"rc-service {svc}: {exc}")

    detail = '; '.join([e for e in errors if e]) or '未知错误'
    raise RuntimeError(f'无法重启 realm 服务（尝试 {", ".join(services)} 失败）：{detail}')


def _restart_agent_service() -> None:
    candidates = []
    override = str(os.getenv('REALM_AGENT_SERVICE') or '').strip()
    if override:
        candidates.append(override)
    candidates.extend(['realm-agent.service', 'realm-agent-https.service', 'realm-agent'])

    seen = set()
    services = []
    for s in candidates:
        name = str(s or '').strip()
        if not name or name in seen:
            continue
        seen.add(name)
        services.append(name)

    errors = []

    # Prefer detached restart via transient unit, so this function can return
    # before current agent process is stopped by systemd.
    if shutil.which('systemd-run') and shutil.which('systemctl'):
        for svc in services:
            unit = svc if svc.endswith('.service') else f'{svc}.service'
            transient_unit = f"realm-agent-auto-restart-{uuid.uuid4().hex[:10]}"
            cmd = f"sleep 1; systemctl restart {shlex.quote(unit)}"
            try:
                r = subprocess.run(
                    ['systemd-run', '--unit', transient_unit, '--collect', '--quiet', '/bin/sh', '-lc', cmd],
                    capture_output=True,
                    text=True,
                )
                if r.returncode == 0:
                    return
                errors.append(f"systemd-run {unit}: {r.stderr.strip() or r.stdout.strip()}")
            except Exception as exc:
                errors.append(f"systemd-run {unit}: {exc}")

    if shutil.which('systemctl'):
        for svc in services:
            unit = svc if svc.endswith('.service') else f'{svc}.service'
            try:
                r = subprocess.run(['systemctl', 'restart', unit], capture_output=True, text=True)
                if r.returncode == 0:
                    return
                errors.append(f"systemctl {unit}: {r.stderr.strip() or r.stdout.strip()}")
            except Exception as exc:
                errors.append(f"systemctl {unit}: {exc}")

    legacy_names = []
    for svc in services:
        base = svc[:-8] if svc.endswith('.service') else svc
        if base and base not in legacy_names:
            legacy_names.append(base)

    if shutil.which('service'):
        for svc in legacy_names:
            try:
                r = subprocess.run(['service', svc, 'restart'], capture_output=True, text=True)
                if r.returncode == 0:
                    return
                errors.append(f"service {svc}: {r.stderr.strip() or r.stdout.strip()}")
            except Exception as exc:
                errors.append(f"service {svc}: {exc}")

    if shutil.which('rc-service'):
        for svc in legacy_names:
            try:
                r = subprocess.run(['rc-service', svc, 'restart'], capture_output=True, text=True)
                if r.returncode == 0:
                    return
                errors.append(f"rc-service {svc}: {r.stderr.strip() or r.stdout.strip()}")
            except Exception as exc:
                errors.append(f"rc-service {svc}: {exc}")

    detail = '; '.join([e for e in errors if e]) or '未知错误'
    raise RuntimeError(f'无法重启 agent 服务（尝试 {", ".join(services)} 失败）：{detail}')


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
IPT_LIMIT_TABLE = os.environ.get('REALM_IPT_LIMIT_TABLE', 'filter')
IPT_LIMIT_CHAIN_IN = os.environ.get('REALM_IPT_LIMIT_CHAIN_IN', 'REALMLIMIT_IN')

_IPT_CACHE_LOCK = threading.Lock()
_IPT_READY_TS = 0.0
_IPT_CONN_READY_TS = 0.0
IPT_READY_TTL = float(os.environ.get('REALM_IPT_READY_TTL', '5.0'))

_IPT_LIMIT_LOCK = threading.Lock()
_IPT_LIMIT_LAST_SIG = ''
_IPT_LIMIT_LAST_APPLY_TS = 0.0
IPT_LIMIT_APPLY_TTL = float(os.environ.get('REALM_IPT_LIMIT_APPLY_TTL', '15.0'))


def _iptables_available() -> bool:
    return iptables_available()


def _run_iptables(args: list[str]) -> tuple[int, str, str]:
    return run_iptables(args, timeout=IPT_RUN_TIMEOUT)


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


def _ipt_err_noexist(text: str) -> bool:
    s = str(text or '').strip().lower()
    if not s:
        return False
    return (
        ('no chain/target/match by that name' in s)
        or ('does not exist' in s)
        or ('not found' in s)
        or ('bad rule' in s)
        or ('不存在' in s)
    )


def _ipt_limit_clear_chain() -> List[str]:
    errors: List[str] = []
    while True:
        rc, _o, err = _run_iptables(['-t', IPT_LIMIT_TABLE, '-D', 'INPUT', '-j', IPT_LIMIT_CHAIN_IN])
        if rc != 0:
            if err and (not _ipt_err_noexist(err)):
                errors.append(err.strip() or '删除 INPUT 跳转规则失败')
            break

    for args in (
        ['-t', IPT_LIMIT_TABLE, '-F', IPT_LIMIT_CHAIN_IN],
        ['-t', IPT_LIMIT_TABLE, '-X', IPT_LIMIT_CHAIN_IN],
    ):
        rc, _o, err = _run_iptables(args)
        if rc != 0 and (not _ipt_err_noexist(err)):
            errors.append(err.strip() or '清理流量上限链失败')
    return errors


def _ipt_limit_append_drop_rule(proto: str, port: int) -> Optional[str]:
    p = str(proto or '').strip().lower()
    if p not in ('tcp', 'udp'):
        return f'unsupported proto: {proto}'

    if p == 'tcp':
        rc, _o, err = _run_iptables(
            [
                '-t',
                IPT_LIMIT_TABLE,
                '-A',
                IPT_LIMIT_CHAIN_IN,
                '-p',
                'tcp',
                '--dport',
                str(int(port)),
                '-j',
                'REJECT',
                '--reject-with',
                'tcp-reset',
            ]
        )
        if rc == 0:
            return None
        rc2, _o2, err2 = _run_iptables(
            [
                '-t',
                IPT_LIMIT_TABLE,
                '-A',
                IPT_LIMIT_CHAIN_IN,
                '-p',
                'tcp',
                '--dport',
                str(int(port)),
                '-j',
                'DROP',
            ]
        )
        if rc2 == 0:
            return None
        return (err2 or err or 'append tcp drop failed').strip()

    rc, _o, err = _run_iptables(
        [
            '-t',
            IPT_LIMIT_TABLE,
            '-A',
            IPT_LIMIT_CHAIN_IN,
            '-p',
            'udp',
            '--dport',
            str(int(port)),
            '-j',
            'DROP',
        ]
    )
    if rc == 0:
        return None
    return (err or 'append udp drop failed').strip()


def _sync_traffic_limit_firewall(blocked_ports: Dict[int, Dict[str, Any]], has_limits: bool) -> Optional[str]:
    """Apply/remove drop rules for traffic-cap exceeded ports."""
    if has_limits and (not _iptables_available()):
        return '已配置规则总流量上限，但当前系统缺少 iptables，无法执行超限阻断'

    payload = []
    for p in sorted(int(x) for x in blocked_ports.keys() if int(x) > 0):
        item = blocked_ports.get(p) or {}
        protos = item.get('protocols')
        if not isinstance(protos, set):
            protos = set(protos or [])
        protos_norm = sorted(x for x in protos if x in ('tcp', 'udp'))
        if not protos_norm:
            protos_norm = ['tcp', 'udp']
        payload.append({'port': int(p), 'protocols': protos_norm})

    sig_src = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    sig = hashlib.sha1(sig_src.encode('utf-8')).hexdigest()

    global _IPT_LIMIT_LAST_SIG, _IPT_LIMIT_LAST_APPLY_TS
    now = time.monotonic()
    with _IPT_LIMIT_LOCK:
        if (sig == _IPT_LIMIT_LAST_SIG) and ((now - float(_IPT_LIMIT_LAST_APPLY_TS)) <= float(IPT_LIMIT_APPLY_TTL)):
            return None

        errors: List[str] = []
        if not payload:
            errors.extend(_ipt_limit_clear_chain())
        else:
            _ipt_ensure_chain(IPT_LIMIT_TABLE, IPT_LIMIT_CHAIN_IN)
            _ipt_ensure_jump(IPT_LIMIT_TABLE, 'INPUT', IPT_LIMIT_CHAIN_IN)
            rc, _o, err = _run_iptables(['-t', IPT_LIMIT_TABLE, '-F', IPT_LIMIT_CHAIN_IN])
            if rc != 0 and (not _ipt_err_noexist(err)):
                errors.append(err.strip() or '清空流量上限链失败')

            for it in payload:
                port = int(it['port'])
                for proto in (it.get('protocols') or ['tcp', 'udp']):
                    e = _ipt_limit_append_drop_rule(str(proto), port)
                    if e:
                        errors.append(f'port {port}/{proto}: {e}')

        _IPT_LIMIT_LAST_APPLY_TS = now
        _IPT_LIMIT_LAST_SIG = sig
        if errors:
            return '; '.join(errors[:4])
        return None


def _traffic_limit_status_from_pool(
    pool: Dict[str, Any],
    conn_map: Dict[int, Dict[str, int]],
) -> Tuple[Dict[int, Dict[str, Any]], Optional[str]]:
    """Build per-port traffic-cap status and enforce firewall blocks."""
    status_by_port: Dict[int, Dict[str, Any]] = {}
    blocked: Dict[int, Dict[str, Any]] = {}

    try:
        policies, _warnings = policies_from_pool(pool if isinstance(pool, dict) else {'endpoints': []})
    except Exception as exc:
        return {}, f'读取规则 QoS 失败：{exc}'

    has_limits = False
    for p in policies:
        try:
            port = int(getattr(p, 'port', 0) or 0)
        except Exception:
            port = 0
        if port <= 0:
            continue

        try:
            limit = int(getattr(p, 'traffic_total_bytes', 0) or 0)
        except Exception:
            limit = 0
        if limit <= 0:
            continue
        has_limits = True

        raw = conn_map.get(port) or {}
        rx = int(raw.get('rx_bytes') or 0)
        tx = int(raw.get('tx_bytes') or 0)
        used = max(0, rx + tx)
        blocked_now = used >= int(limit)

        status_by_port[port] = {
            'limit_bytes': int(limit),
            'used_bytes': int(used),
            'blocked': bool(blocked_now),
        }

        if blocked_now:
            protos = getattr(p, 'protocols', set()) or set()
            protos_norm = {x for x in protos if x in ('tcp', 'udp')}
            if not protos_norm:
                protos_norm = {'tcp', 'udp'}
            blocked[port] = {'protocols': protos_norm}

    warn = _sync_traffic_limit_firewall(blocked, has_limits=has_limits)
    return status_by_port, warn


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
        forward_tool = str(ex.get('forward_tool') or ep.get('forward_tool') or '').strip().lower()
        if forward_tool in ('ipt', 'iptables'):
            forward_tool = 'iptables'

        payload = {
            'listen': listen,
            'protocol': protocol,
            'remotes': sorted(set(remotes)),
            'sync_id': sync_id,
            'role': role,
            'listen_transport': listen_transport,
            'remote_transport': remote_transport,
            'forward_tool': forward_tool,
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


def _udp_probe_cache_key(host: str, port: int) -> str:
    return f"udp://{host}:{port}"


def _udp_probe_hist_key(host: str, port: int) -> str:
    return f"udp://{host}:{port}"


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


def _cache_set(key: str, ok: Optional[bool], latency_ms: Optional[float], error: Optional[str] = None) -> None:
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
            'ok': (None if ok is None else bool(ok)),
            'latency_ms': latency_ms,
            'error': error,
        }


def _probe_history_prune_locked(now_mono: float) -> None:
    global _PROBE_HISTORY_PRUNE_TS
    interval = min(float(PROBE_HISTORY_TTL), 30.0)
    if interval < 5.0:
        interval = 5.0
    if (now_mono - float(_PROBE_HISTORY_PRUNE_TS)) <= interval:
        return
    for k, item in list(_PROBE_HISTORY.items()):
        try:
            if (now_mono - float(item.get('ts_mono', 0.0))) > float(PROBE_HISTORY_TTL):
                _PROBE_HISTORY.pop(k, None)
        except Exception:
            _PROBE_HISTORY.pop(k, None)
    _PROBE_HISTORY_PRUNE_TS = now_mono


def _probe_history_alpha(now_mono: float, prev_ts_mono: Optional[float]) -> float:
    # Compatibility: explicit alpha keeps legacy behaviour for old deployments.
    if PROBE_HISTORY_ALPHA is not None:
        return float(PROBE_HISTORY_ALPHA)
    dt = 1.0
    try:
        if prev_ts_mono is not None:
            dt = float(now_mono) - float(prev_ts_mono)
    except Exception:
        dt = 1.0
    if dt < 0.2:
        dt = 0.2
    if dt > float(PROBE_HISTORY_TTL):
        dt = float(PROBE_HISTORY_TTL)
    half_life = float(PROBE_HISTORY_HALFLIFE)
    if half_life <= 0.0:
        return 0.5
    alpha = 1.0 - math.pow(0.5, dt / half_life)
    if alpha < 0.01:
        alpha = 0.01
    if alpha > 0.95:
        alpha = 0.95
    return alpha


def _probe_history_update(key: str, ok: bool, latency_ms: Optional[float], error: Optional[str]) -> None:
    now_mono = time.monotonic()
    now_ms = int(time.time() * 1000)
    ok_b = bool(ok)
    lat_v = None
    if latency_ms is not None:
        try:
            lat_v = round(float(latency_ms), 2)
        except Exception:
            lat_v = None

    with _PROBE_LOCK:
        _probe_history_prune_locked(now_mono)

        item = _PROBE_HISTORY.get(key) or {}
        samples = int(item.get('samples') or 0) + 1
        successes = int(item.get('successes') or 0) + (1 if ok_b else 0)
        failures = int(item.get('failures') or 0) + (0 if ok_b else 1)
        alpha = _probe_history_alpha(now_mono, item.get('ts_mono'))
        prev_success_ema = item.get('success_ema')
        try:
            prev_success_ema_f = float(prev_success_ema)
        except Exception:
            prev_success_ema_f = 1.0 if ok_b else 0.0
        success_ema = (float(alpha) * (1.0 if ok_b else 0.0)) + (
            (1.0 - float(alpha)) * prev_success_ema_f
        )
        if success_ema < 0.0:
            success_ema = 0.0
        if success_ema > 1.0:
            success_ema = 1.0

        latency_ema = item.get('latency_ema_ms')
        try:
            latency_ema_f = float(latency_ema) if latency_ema is not None else None
        except Exception:
            latency_ema_f = None
        if ok_b and lat_v is not None:
            if latency_ema_f is None:
                latency_ema_f = float(lat_v)
            else:
                latency_ema_f = (float(alpha) * float(lat_v)) + (
                    (1.0 - float(alpha)) * float(latency_ema_f)
                )
            if latency_ema_f < 0.0:
                latency_ema_f = 0.0

        consecutive_failures = int(item.get('consecutive_failures') or 0)
        if ok_b:
            consecutive_failures = 0
        else:
            consecutive_failures += 1

        out: Dict[str, Any] = {
            'ts_mono': now_mono,
            'last_probe_at_ms': now_ms,
            'samples': samples,
            'successes': successes,
            'failures': failures,
            'success_ema': success_ema,
            'consecutive_failures': consecutive_failures,
            'last_ok': ok_b,
            'alpha_used': round(float(alpha), 4),
        }
        if lat_v is not None:
            out['last_latency_ms'] = lat_v
        if latency_ema_f is not None:
            out['latency_ema_ms'] = round(float(latency_ema_f), 2)
        if error and (not ok_b):
            out['last_error'] = str(error)
        else:
            out['last_error'] = ''

        _PROBE_HISTORY[key] = out


def _probe_history_snapshot(key: str) -> Dict[str, Any]:
    now_mono = time.monotonic()
    with _PROBE_LOCK:
        item = _PROBE_HISTORY.get(key)
        if not item:
            return {}
        try:
            if (now_mono - float(item.get('ts_mono', 0.0))) > float(PROBE_HISTORY_TTL):
                _PROBE_HISTORY.pop(key, None)
                return {}
        except Exception:
            _PROBE_HISTORY.pop(key, None)
            return {}
        snap = dict(item)

    samples = int(snap.get('samples') or 0)
    successes = int(snap.get('successes') or 0)
    failures = int(snap.get('failures') or 0)
    try:
        success_ema = float(snap.get('success_ema'))
    except Exception:
        success_ema = 1.0 if bool(snap.get('last_ok')) else 0.0
    if success_ema < 0.0:
        success_ema = 0.0
    if success_ema > 1.0:
        success_ema = 1.0
    availability = round(success_ema * 100.0, 2)
    error_rate = round(100.0 - availability, 2)

    out: Dict[str, Any] = {
        'samples': samples,
        'successes': successes,
        'failures': failures,
        'availability': availability,
        'error_rate': error_rate,
        'consecutive_failures': int(snap.get('consecutive_failures') or 0),
        'last_ok': bool(snap.get('last_ok')),
        'last_probe_at_ms': int(snap.get('last_probe_at_ms') or 0),
    }
    if snap.get('latency_ema_ms') is not None:
        try:
            out['latency_ema_ms'] = round(float(snap.get('latency_ema_ms')), 2)
        except Exception:
            pass
    if snap.get('last_latency_ms') is not None:
        try:
            out['last_latency_ms'] = round(float(snap.get('last_latency_ms')), 2)
        except Exception:
            pass
    if snap.get('last_error'):
        out['last_error'] = str(snap.get('last_error'))
    out['down'] = (
        out.get('consecutive_failures', 0) >= int(PROBE_DOWN_FAILS)
        and int(samples) >= int(PROBE_HISTORY_MIN_SAMPLES)
    )
    return out


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
            _probe_history_update(key, True, best_latency, None)
            return {'ok': True, 'latency_ms': best_latency}
        last_err = err or last_err

    _cache_set(key, False, None, last_err)
    _probe_history_update(key, False, None, last_err)
    return {'ok': False, 'error': last_err}


def _tcp_probe(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[bool, Optional[float]]:
    """兼容旧调用：仅返回 (ok, latency_ms)。"""
    d = _tcp_probe_detail(host, port, timeout)
    return bool(d.get('ok')), d.get('latency_ms')


def _udp_probe_uncached(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[Optional[bool], Optional[float], Optional[str]]:
    """Lightweight UDP probe.

    Returns:
      - (True, latency, None): received a UDP response
      - (False, None, err): explicit unreachable/refused or hard failure
      - (None, None, msg): sent but got no response (inconclusive for generic UDP)
    """
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)
    except Exception as exc:
        return False, None, str(exc)
    if not infos:
        return False, None, 'dns_no_result'

    payload = b'REALM-PROBE'
    last_err: Optional[str] = None
    for af, sock_type, proto, _canon, sa in infos[:4]:
        s: Optional[socket.socket] = None
        try:
            s = socket.socket(af, sock_type, proto)
            s.settimeout(max(0.1, float(timeout)))
            start = time.monotonic()
            s.connect(sa)
            s.send(payload)
            try:
                _ = s.recv(1)
                latency_ms = (time.monotonic() - start) * 1000.0
                return True, round(latency_ms, 2), None
            except socket.timeout:
                return None, None, 'udp_no_reply'
            except ConnectionRefusedError as exc:
                last_err = str(exc) or 'connection_refused'
                continue
            except OSError as exc:
                msg = str(exc)
                low = msg.lower()
                if ('refused' in low) or ('unreachable' in low) or ('no route' in low):
                    last_err = msg
                    continue
                last_err = msg
                continue
        except Exception as exc:
            last_err = str(exc)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return False, None, last_err or 'udp_probe_failed'


def _udp_probe_detail(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> Dict[str, Any]:
    """UDP probe detail for /api/v1/stats health view."""
    key = _udp_probe_cache_key(host, port)
    hist_key = _udp_probe_hist_key(host, port)
    cached = _cache_get(key)
    if cached is not None:
        ok_cached = cached.get('ok')
        if ok_cached is None:
            return {'ok': None, 'message': 'UDP 无响应（可能在线）'}
        out_cached: Dict[str, Any] = {'ok': bool(ok_cached)}
        if cached.get('latency_ms') is not None:
            out_cached['latency_ms'] = cached.get('latency_ms')
        if out_cached['ok'] is False and cached.get('error'):
            out_cached['error'] = cached.get('error')
        return out_cached

    last_state: Optional[bool] = None
    last_err: Optional[str] = None
    for i in range(max(1, PROBE_RETRIES)):
        per_timeout = timeout if i == 0 else min(timeout * 1.4, 1.2)
        state, latency_ms, err = _udp_probe_uncached(host, port, per_timeout)
        if state is True:
            _cache_set(key, True, latency_ms, None)
            _probe_history_update(hist_key, True, latency_ms, None)
            out_ok: Dict[str, Any] = {'ok': True}
            if latency_ms is not None:
                out_ok['latency_ms'] = latency_ms
            return out_ok
        if state is False:
            last_state = False
            last_err = err or last_err
            continue
        # state is None: no UDP response, inconclusive
        last_state = None
        last_err = err or 'udp_no_reply'

    if last_state is None:
        _cache_set(key, None, None, last_err)
        return {'ok': None, 'message': 'UDP 无响应（可能在线）'}

    _cache_set(key, False, None, last_err)
    _probe_history_update(hist_key, False, None, last_err)
    return {'ok': False, 'error': last_err}


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

    仅补充本机 listen 侧探测，帮助确认接收端监听端口是否真的在跑。
    """
    ex = rule.get('extra_config') or {}
    listen = str(rule.get('listen') or '')
    entries: List[Dict[str, str]] = []

    # listen_transport: ws;...  => 探测本机 listen 端口是否在监听（避免显示空白）
    listen_transport = str(rule.get('listen_transport') or ex.get('listen_transport') or '')
    if ('ws' in listen_transport) or ex.get('listen_ws_host'):
        try:
            lp = _parse_listen_port(listen)
        except Exception:
            lp = 0
        if lp > 0:
            # 为 WSS 接收规则补充本机监听探测，便于确认 listen 端口是否真的在跑。
            entries.append({'key': f"127.0.0.1:{lp}", 'label': f"本机监听 127.0.0.1:{lp}", 'probe': 'tcp'})

    return entries


app = FastAPI(title='Realm Agent', version='43')
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
try:
    REPORT_CONNECT_TIMEOUT = max(
        1.0, min(30.0, float(os.environ.get('REALM_AGENT_REPORT_CONNECT_TIMEOUT', '5') or '5'))
    )
except Exception:
    REPORT_CONNECT_TIMEOUT = 5.0
try:
    REPORT_READ_TIMEOUT = max(
        3.0, min(120.0, float(os.environ.get('REALM_AGENT_REPORT_READ_TIMEOUT', '20') or '20'))
    )
except Exception:
    REPORT_READ_TIMEOUT = 20.0

_PUSH_STOP = threading.Event()
_PUSH_THREAD: Optional[threading.Thread] = None
_PUSH_LOCK = threading.Lock()  # 避免与 API 同时写 pool 文件导致竞争
_LAST_SYNC_ERROR: Optional[str] = None
_QOS_STATUS_LOCK = threading.Lock()
_QOS_STATUS: Dict[str, Any] = {
    "ok": True,
    "backend": "none",
    "ts": int(time.time()),
    "message": "not_applied_yet",
    "caps": {"iptables": False, "nftables": False, "tc": False},
    "stats": {"ports": 0, "rules": 0, "bandwidth_rules": 0, "max_conns_rules": 0, "conn_rate_rules": 0},
    "warnings": [],
    "errors": [],
}
_PANEL_TASK_RESULTS_LOCK = threading.Lock()
_PANEL_TASK_RESULTS: List[Dict[str, Any]] = []
_PANEL_TASK_RESULTS_MAX = max(20, int(os.getenv("REALM_AGENT_PANEL_TASK_RESULTS_MAX", "200") or "200"))

# ------------------------ Intranet Tunnel Supervisor ------------------------
# 说明：公网节点(A) 与 内网节点(B) 之间的一对一“内网穿透”由 Agent 负责：
# - A 侧监听规则的 listen 端口，并把流量通过加密隧道转发给 B；
# - B 侧主动连 A 的隧道端口（默认 18443），按需建立 data 连接并转发到内网目标。
# 这些规则在 pool 中以 extra_config.intranet_role 标记，realm 本体不会接管。

_INTRANET = IntranetManager(node_id=AGENT_ID)
_IPTFWD = IptablesForwardManager()


def _queue_panel_task_result(row: Dict[str, Any]) -> None:
    if not isinstance(row, dict):
        return
    out = dict(row)
    out_id = str(out.get("id") or "").strip()
    if not out_id:
        out["id"] = uuid.uuid4().hex
    out.setdefault("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    with _PANEL_TASK_RESULTS_LOCK:
        _PANEL_TASK_RESULTS.append(out)
        if len(_PANEL_TASK_RESULTS) > _PANEL_TASK_RESULTS_MAX:
            overflow = len(_PANEL_TASK_RESULTS) - _PANEL_TASK_RESULTS_MAX
            del _PANEL_TASK_RESULTS[:overflow]


def _peek_panel_task_results(limit: int = 40) -> List[Dict[str, Any]]:
    n = int(limit or 40)
    if n < 1:
        n = 1
    if n > _PANEL_TASK_RESULTS_MAX:
        n = _PANEL_TASK_RESULTS_MAX
    with _PANEL_TASK_RESULTS_LOCK:
        if not _PANEL_TASK_RESULTS:
            return []
        rows = _PANEL_TASK_RESULTS[:n]
    return [dict(r) for r in rows if isinstance(r, dict)]


def _ack_panel_task_results(ids: List[str]) -> None:
    seq = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not seq:
        return
    done = set(seq)
    with _PANEL_TASK_RESULTS_LOCK:
        if not _PANEL_TASK_RESULTS:
            return
        kept = [r for r in _PANEL_TASK_RESULTS if str((r or {}).get("id") or "").strip() not in done]
        _PANEL_TASK_RESULTS[:] = kept


def _qos_set_status(st: Dict[str, Any]) -> None:
    with _QOS_STATUS_LOCK:
        _QOS_STATUS.clear()
        _QOS_STATUS.update(st)


def _qos_get_status() -> Dict[str, Any]:
    with _QOS_STATUS_LOCK:
        return dict(_QOS_STATUS)


def _qos_apply_safe(pool: Optional[Dict[str, Any]], source: str) -> None:
    try:
        data = apply_qos_from_pool(pool or {"endpoints": []})
        data["source"] = source
        _qos_set_status(data)
    except Exception as exc:
        _qos_set_status(
            {
                "ok": False,
                "backend": "none",
                "ts": int(time.time()),
                "source": source,
                "message": "qos_apply_exception",
                "caps": {"iptables": False, "nftables": False, "tc": False},
                "stats": {
                    "ports": 0,
                    "rules": 0,
                    "bandwidth_rules": 0,
                    "max_conns_rules": 0,
                    "conn_rate_rules": 0,
                },
                "warnings": [],
                "errors": [str(exc)],
            }
        )


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
        'qos': _qos_get_status(),
    }
    pool = _load_full_pool()
    stats = _build_stats_snapshot()
    intranet_meta: Dict[str, Any] = {"tls_ready": False}
    try:
        cert_pem = str(load_server_cert_pem() or "").strip()
    except Exception:
        cert_pem = ""
    try:
        tls_ready = bool(server_tls_ready())
    except Exception:
        tls_ready = False
    intranet_meta["tls_ready"] = bool(tls_ready)
    if cert_pem:
        intranet_meta["cert_pem"] = cert_pem
    if not cert_pem:
        intranet_meta["cert_error"] = "tls_cert_missing"
    elif not tls_ready:
        intranet_meta["cert_error"] = "tls_context_unavailable"
    iptables_meta: Dict[str, Any] = {}
    try:
        iptables_meta = _IPTFWD.status()
    except Exception:
        iptables_meta = {}

    rep: Dict[str, Any] = {
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'info': info,
        'pool': pool,
        'stats': stats,
        'sys': _build_sys_snapshot(),
        'auto_restart': _auto_restart_status_snapshot(),
        'intranet': intranet_meta,
        'iptables': iptables_meta,
        # backward-compat alias
        'ipt': iptables_meta,
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
            prev_full = _load_full_pool()
            if not isinstance(prev_full, dict):
                prev_full = {}

            # 写入 full pool
            _write_json(POOL_FULL, pool)
            _sync_active_pool()
            _qos_apply_safe(pool, "sync_pool")

            # Keep intranet tunnel supervisor in sync for LAN/NAT nodes.
            try:
                _INTRANET.apply_from_pool(pool)
            except Exception:
                pass

            if do_apply:
                # Two-phase apply for iptables-forwarded rules:
                # 1) stop/reconcile listeners that will change (avoid port conflicts)
                # 2) apply realm config + restart realm
                # 3) apply desired iptables rules
                _IPTFWD.prepare_for_pool(pool)
                try:
                    _apply_pool_to_config()
                    _restart_realm()
                    # Keep intranet tunnel supervisor in sync for LAN/NAT nodes.
                    try:
                        _INTRANET.apply_from_pool(_load_full_pool())
                    except Exception:
                        pass
                    _IPTFWD.apply_from_pool(pool)
                except Exception:
                    # Best-effort rollback of managed iptables rules to previous full pool.
                    try:
                        _IPTFWD.apply_from_pool(prev_full)
                    except Exception:
                        pass
                    raise

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
            prev_full = dict(full) if isinstance(full, dict) else {}
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
            _qos_apply_safe(new_full, "pool_patch")

            # Keep intranet tunnel supervisor in sync for LAN/NAT nodes.
            try:
                _INTRANET.apply_from_pool(new_full)
            except Exception:
                pass

            if do_apply:
                _IPTFWD.prepare_for_pool(new_full)
                try:
                    _apply_pool_to_config()
                    _restart_realm()
                    _IPTFWD.apply_from_pool(new_full)
                except Exception:
                    try:
                        _IPTFWD.apply_from_pool(prev_full)
                    except Exception:
                        pass
                    raise

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
        command_id = str(cmd.get('command_id') or '').strip()
        sh_url = str(cmd.get('sh_url') or '').strip()
        zip_url = str(cmd.get('zip_url') or '').strip()
        zip_sha256 = str(cmd.get('zip_sha256') or '').strip()
        panel_url = str(cmd.get('panel_url') or '').strip()
        try:
            panel_ip_fallback_port = int(cmd.get('panel_ip_fallback_port') or 6080)
        except Exception:
            panel_ip_fallback_port = 6080
        if panel_ip_fallback_port <= 0 or panel_ip_fallback_port > 65535:
            panel_ip_fallback_port = 6080
        fallback_sh_url = str(cmd.get('fallback_sh_url') or '').strip()
        fallback_zip_url = str(cmd.get('fallback_zip_url') or '').strip()
        fallback_zip_sha256 = str(cmd.get('fallback_zip_sha256') or '').strip()
        force = _to_bool(cmd.get('force', True), True)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not update_id or not desired_ver or not sh_url or not zip_url:
            st = _load_update_state()
            st.update({
                'command_id': command_id,
                'update_id': update_id,
                'desired_version': desired_ver,
                'state': 'failed',
                'reason_code': 'invalid_command',
                'error': 'update_agent：缺少必要参数',
                'finished_at': now,
                'agent_version': str(app.version),
            })
            _save_update_state(st)
            return

        # 去重：同一个 command_id（优先）/update_id 已进入 accepted|running|done 不重复触发。
        st0 = _load_update_state()
        st0_state = _canon_update_state(st0.get('state'))
        same_cmd = bool(command_id) and str(st0.get('command_id') or '').strip() == command_id
        same_update = str(st0.get('update_id') or '').strip() == update_id
        if (same_cmd and st0_state in ('accepted', 'running', 'done')) or (
            (not command_id) and same_update and st0_state in ('accepted', 'running', 'done')
        ):
            return

        # 先回执 accepted，再进入 running（满足 panel 生命周期：delivered -> accepted -> running）。
        st_ack = _load_update_state()
        st_ack.update({
            'command_id': command_id,
            'update_id': update_id,
            'desired_version': desired_ver,
            'from_version': st_ack.get('from_version') or str(app.version),
            'state': 'accepted',
            'accepted_at': now,
            'agent_version': str(app.version),
            'reason_code': '',
            'error': '',
        })
        _save_update_state(st_ack)

        # Already on desired (or newer)
        # 默认行为：若当前版本已满足 desired_version，则直接标记 done，不再安装。
        # 但当 force=true（面板“一键更新”点击触发）时，必须强制按面板/GitHub 文件重新安装，不做版本短路。
        try:
            if (not force) and int(str(app.version)) >= int(desired_ver) and int(desired_ver) > 0:
                st = _load_update_state()
                st.update({
                    'command_id': command_id,
                    'update_id': update_id,
                    'desired_version': desired_ver,
                    'from_version': st.get('from_version') or str(app.version),
                    'state': 'done',
                    'reason_code': '',
                    'error': '',
                    'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'agent_version': str(app.version),
                })
                _save_update_state(st)
                return
        except Exception:
            pass

        host, port = _get_current_agent_bind()
        st = _load_update_state()
        st.update({
            'command_id': command_id,
            'update_id': update_id,
            'desired_version': desired_ver,
            'from_version': st.get('from_version') or str(app.version),
            'state': 'running',
            'started_at': now,
            'agent_version': str(app.version),
            'reason_code': '',
            'error': '',
        })
        _save_update_state(st)

        # Build updater script
        script_path = Path(f"/tmp/realm-agent-update-{update_id}.sh")
        log_path = Path(f"/var/log/realm-agent-update-{update_id}.log")
        q_sh_url = shlex.quote(sh_url)
        q_zip_url = shlex.quote(zip_url)
        q_zip_sha256 = shlex.quote(zip_sha256)
        q_panel_url = shlex.quote(panel_url)
        q_panel_ip_fallback_port = shlex.quote(str(panel_ip_fallback_port))
        q_fallback_sh_url = shlex.quote(fallback_sh_url)
        q_fallback_zip_url = shlex.quote(fallback_zip_url)
        q_fallback_zip_sha256 = shlex.quote(fallback_zip_sha256)
        script = f"""#!/usr/bin/env bash
set -euo pipefail

TMP_ZIP=\"/tmp/realm-agent-repo-{update_id}.zip\"
TMP_SH=\"/tmp/realm-agent-installer-{update_id}.sh\"
LOG=\"{log_path}\"
STATE=\"{UPDATE_STATE_FILE}\"
SCRIPT_PATH=\"{script_path}\"
PRIMARY_SH_URL={q_sh_url}
PRIMARY_ZIP_URL={q_zip_url}
PRIMARY_ZIP_SHA256={q_zip_sha256}
PANEL_URL={q_panel_url}
PANEL_IP_FALLBACK_PORT={q_panel_ip_fallback_port}
FALLBACK_SH_URL={q_fallback_sh_url}
FALLBACK_ZIP_URL={q_fallback_zip_url}
FALLBACK_ZIP_SHA256={q_fallback_zip_sha256}
LOG_RETENTION_DAYS=\"${{REALM_AGENT_UPDATE_LOG_RETENTION_DAYS:-7}}\"
TMP_RETENTION_DAYS=\"${{REALM_AGENT_UPDATE_TMP_RETENTION_DAYS:-1}}\"
CURL_CONNECT_TIMEOUT=\"${{REALM_AGENT_UPDATE_CURL_CONNECT_TIMEOUT:-20}}\"
CURL_MAX_TIME=\"${{REALM_AGENT_UPDATE_CURL_MAX_TIME:-300}}\"
CURL_RETRY=\"${{REALM_AGENT_UPDATE_CURL_RETRY:-4}}\"
CURL_RETRY_DELAY=\"${{REALM_AGENT_UPDATE_CURL_RETRY_DELAY:-3}}\"

export STATE

mkdir -p \"$(dirname \"$LOG\")\" || true
exec > >(tee -a \"$LOG\") 2>&1

prune_old_artifacts() {{
  if [[ \"$LOG_RETENTION_DAYS\" =~ ^[0-9]+$ ]]; then
    find /var/log -maxdepth 1 -type f -name 'realm-agent-update-*.log' -mtime +\"$LOG_RETENTION_DAYS\" -delete 2>/dev/null || true
  fi
  if [[ \"$TMP_RETENTION_DAYS\" =~ ^[0-9]+$ ]]; then
    find /tmp -maxdepth 1 -type f -name 'realm-agent-update-*.sh' -mtime +\"$TMP_RETENTION_DAYS\" -delete 2>/dev/null || true
    find /tmp -maxdepth 1 -type f -name 'realm-agent-repo-*.zip' -mtime +\"$TMP_RETENTION_DAYS\" -delete 2>/dev/null || true
  fi
}}

cleanup() {{
  rm -f \"$TMP_ZIP\" \"$TMP_SH\" \"$SCRIPT_PATH\" 2>/dev/null || true
  prune_old_artifacts
}}

trap cleanup EXIT

fail() {{
  local code=\"$1\"; shift || true
  local hint=\"\"
  if [[ -f \"$LOG\" ]]; then
    hint=\"$(tail -n 20 \"$LOG\" 2>/dev/null | tr '\\n' ' ' | tail -c 900)\"
  fi
  export ERR_HINT=\"$hint\"
  python3 - <<'PY'
import json, pathlib, datetime, os
p=pathlib.Path(os.environ.get('STATE','/etc/realm-agent/agent_update.json'))
st={{}}
try:
  st=json.loads(p.read_text(encoding='utf-8'))
except Exception:
  st={{}}
cmd_id = r\"{command_id}\"
upd_id = r\"{update_id}\"
des_ver = r\"{desired_ver}\"
st['state']='failed'
st['reason_code']=os.environ.get('ERR_REASON','installer_error')
err = os.environ.get('ERR_MSG','update failed')
hint = os.environ.get('ERR_HINT','').strip()
if hint:
  err = f"{{err}} | {{hint}}"
if len(err) > 1800:
  err = err[-1800:]
st['error']=err
if cmd_id:
  st['command_id']=cmd_id
if upd_id:
  st['update_id']=upd_id
if des_ver:
  st['desired_version']=des_ver
st['finished_at']=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding='utf-8')
PY
  exit \"$code\"
}}

if ! [[ \"$CURL_CONNECT_TIMEOUT\" =~ ^[0-9]+$ ]]; then CURL_CONNECT_TIMEOUT=20; fi
if ! [[ \"$CURL_MAX_TIME\" =~ ^[0-9]+$ ]]; then CURL_MAX_TIME=300; fi
if ! [[ \"$CURL_RETRY\" =~ ^[0-9]+$ ]]; then CURL_RETRY=4; fi
if ! [[ \"$CURL_RETRY_DELAY\" =~ ^[0-9]+$ ]]; then CURL_RETRY_DELAY=3; fi

if [[ -n \"$FALLBACK_ZIP_URL\" && \"$FALLBACK_ZIP_URL\" == \"$PRIMARY_ZIP_URL\" ]]; then
  FALLBACK_ZIP_URL=\"\"
  FALLBACK_ZIP_SHA256=\"\"
fi
if [[ -n \"$FALLBACK_SH_URL\" && \"$FALLBACK_SH_URL\" == \"$PRIMARY_SH_URL\" ]]; then
  FALLBACK_SH_URL=\"\"
fi

if ! command -v curl >/dev/null 2>&1; then
  export ERR_REASON=\"installer_error\"
  export ERR_MSG=\"curl 不存在，无法执行在线更新\"
  fail 30
fi

trap 'export ERR_REASON=\"installer_error\"; export ERR_MSG=\"line $LINENO: $BASH_COMMAND\"; fail $?' ERR

append_cache_bust() {{
  local url=\"$1\"
  local bust=\"ts=$(date +%s)\"
  if [[ \"$url\" == http://* || \"$url\" == https://* ]]; then
    if [[ \"$url\" == *\\?* ]]; then
      printf '%s\\n' \"$url&$bust\"
    else
      printf '%s\\n' \"$url?$bust\"
    fi
  else
    printf '%s\\n' \"$url\"
  fi
}}

verify_sha256() {{
  local expected=\"$1\"
  local file=\"$2\"
  [[ -z \"$expected\" ]] && return 0
  if command -v sha256sum >/dev/null 2>&1; then
    echo \"$expected  $file\" | sha256sum -c - >/dev/null 2>&1
    return $?
  fi
  if command -v shasum >/dev/null 2>&1; then
    local got
    got=\"$(shasum -a 256 \"$file\" | awk '{{print $1}}')\"
    [[ \"$got\" == \"$expected\" ]]
    return $?
  fi
  # 无哈希校验工具时放行，避免旧系统直接失败。
  return 0
}}

curl_fetch() {{
  local url=\"$1\"
  local out=\"$2\"
  local real_url
  real_url=\"$(append_cache_bust \"$url\")\"
  local -a args=(
    --fail
    --silent
    --show-error
    --location
    --connect-timeout \"$CURL_CONNECT_TIMEOUT\"
    --max-time \"$CURL_MAX_TIME\"
    --retry \"$CURL_RETRY\"
    --retry-delay \"$CURL_RETRY_DELAY\"
    -H 'Cache-Control: no-cache'
    -H 'Pragma: no-cache'
    \"$real_url\"
    -o \"$out\"
  )
  if curl --help all 2>/dev/null | grep -q -- '--retry-connrefused'; then
    args=(--retry-connrefused \"${{args[@]}}\")
  fi
  if curl --help all 2>/dev/null | grep -q -- '--retry-all-errors'; then
    args=(--retry-all-errors \"${{args[@]}}\")
  fi
  curl \"${{args[@]}}\"
}}

curl_stream() {{
  local url=\"$1\"
  local real_url
  real_url=\"$(append_cache_bust \"$url\")\"
  local -a args=(
    --fail
    --silent
    --show-error
    --location
    --connect-timeout \"$CURL_CONNECT_TIMEOUT\"
    --max-time \"$CURL_MAX_TIME\"
    --retry \"$CURL_RETRY\"
    --retry-delay \"$CURL_RETRY_DELAY\"
    -H 'Cache-Control: no-cache'
    -H 'Pragma: no-cache'
    \"$real_url\"
  )
  if curl --help all 2>/dev/null | grep -q -- '--retry-connrefused'; then
    args=(--retry-connrefused \"${{args[@]}}\")
  fi
  if curl --help all 2>/dev/null | grep -q -- '--retry-all-errors'; then
    args=(--retry-all-errors \"${{args[@]}}\")
  fi
  curl \"${{args[@]}}\"
}}

build_panel_ip_urls() {{
  local src_url=\"$1\"
  python3 - \"$src_url\" \"$PANEL_URL\" \"$PANEL_IP_FALLBACK_PORT\" <<'PY'
import socket
import sys
from urllib.parse import urlsplit, urlunsplit

src = str(sys.argv[1] if len(sys.argv) > 1 else "").strip()
panel = str(sys.argv[2] if len(sys.argv) > 2 else "").strip()
port_raw = str(sys.argv[3] if len(sys.argv) > 3 else "").strip()
try:
    fallback_port = int(port_raw)
except Exception:
    fallback_port = 6080
if fallback_port <= 0 or fallback_port > 65535:
    fallback_port = 6080

def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").strip().lower()
    except Exception:
        return ""

def explicit_port_of(url: str) -> int:
    try:
        p = int(urlsplit(url).port or 0)
    except Exception:
        p = 0
    if p > 0 and p <= 65535:
        return p
    return 0

def is_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        v = int(p)
        if v < 0 or v > 255:
            return False
    return True

try:
    su = urlsplit(src)
except Exception:
    sys.exit(0)
if not su.scheme or not su.netloc:
    sys.exit(0)
scheme = (su.scheme or "http").strip().lower()
if scheme not in ("http", "https"):
    scheme = "http"
port = explicit_port_of(src) or explicit_port_of(panel) or fallback_port

src_host = host_of(src)
panel_host = host_of(panel)
if panel_host and src_host and src_host != panel_host:
    # only replace panel-origin URLs; do not rewrite github or other mirrors
    sys.exit(0)
if not panel_host:
    panel_host = src_host
if not panel_host:
    sys.exit(0)
if panel_host in ("localhost", "127.0.0.1", "::1") or is_ipv4(panel_host):
    sys.exit(0)

try:
    infos = socket.getaddrinfo(panel_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
except Exception:
    infos = []

seen = set()
for it in infos:
    try:
        ip = str(it[4][0] or "").strip()
    except Exception:
        ip = ""
    if not ip:
        continue
    # keep simple and stable: IPv4 + fixed http port fallback
    if ":" in ip:
        continue
    if ip in seen:
        continue
    seen.add(ip)
    out = urlunsplit((scheme, f"{{ip}}:{{port}}", su.path or "/", su.query, ""))
    print(out)
PY
}}

emit_url_sha_candidates() {{
  local primary_url=\"$1\"
  local primary_sha=\"$2\"
  local fallback_url=\"$3\"
  local fallback_sha=\"$4\"
  declare -A seen=()

  emit_one() {{
    local u=\"$1\"
    local s=\"$2\"
    [[ -n \"$u\" ]] || return 0
    if [[ -n \"${{seen[$u]+x}}\" ]]; then
      return 0
    fi
    seen[\"$u\"]=1
    printf '%s\\t%s\\n' \"$u\" \"$s\"
  }}

  local u
  emit_one \"$primary_url\" \"$primary_sha\"
  while IFS= read -r u; do
    emit_one \"$u\" \"$primary_sha\"
  done < <(build_panel_ip_urls \"$primary_url\")

  if [[ -n \"$fallback_url\" ]]; then
    emit_one \"$fallback_url\" \"$fallback_sha\"
    while IFS= read -r u; do
      emit_one \"$u\" \"$fallback_sha\"
    done < <(build_panel_ip_urls \"$fallback_url\")
  fi
}}

download_asset() {{
  local name=\"$1\"
  local url=\"$2\"
  local out=\"$3\"
  local sha=\"$4\"
  [[ -n \"$url\" ]] || return 1
  echo \"[update] download $name from $url\" | tee -a \"$LOG\"
  if ! curl_fetch \"$url\" \"$out\"; then
    echo \"[update] download failed: $name from $url\" | tee -a \"$LOG\"
    return 1
  fi
  if ! verify_sha256 \"$sha\" \"$out\"; then
    echo \"[update] sha256 mismatch: $name from $url\" | tee -a \"$LOG\"
    return 1
  fi
  return 0
}}

download_asset_candidates() {{
  local name=\"$1\"
  local out=\"$2\"
  local primary_url=\"$3\"
  local primary_sha=\"$4\"
  local fallback_url=\"$5\"
  local fallback_sha=\"$6\"
  local c_url=\"\"
  local c_sha=\"\"

  while IFS=$'\\t' read -r c_url c_sha; do
    [[ -n \"$c_url\" ]] || continue
    if download_asset \"$name\" \"$c_url\" \"$out\" \"$c_sha\"; then
      echo \"[update] selected $name source: $c_url\" | tee -a \"$LOG\"
      return 0
    fi
  done < <(emit_url_sha_candidates \"$primary_url\" \"$primary_sha\" \"$fallback_url\" \"$fallback_sha\")
  return 1
}}

run_installer_stream() {{
  local url=\"$1\"
  local run_log=\"$2\"
  [[ -n \"$url\" ]] || return 1
  : > \"$run_log\"
  echo \"[update] execute installer stream: bash <(curl -fsSL $url)\" | tee -a \"$LOG\"
  set +e
  /bin/bash <(curl_stream \"$url\") 2>&1 | tee -a \"$LOG\" | tee -a \"$run_log\"
  local rc=${{PIPESTATUS[0]}}
  set -e
  local last_line=\"\"
  if [[ -f \"$run_log\" ]]; then
    last_line=\"$(awk 'NF{{line=$0}} END{{print line}}' \"$run_log\" 2>/dev/null || true)\"
  fi
  if [[ -n \"$last_line\" ]]; then
    echo \"[update] installer last line: $last_line\" | tee -a \"$LOG\"
  fi
  if [[ \"$rc\" -ne 0 ]]; then
    return 1
  fi
  if grep -q '\\[OK\\][[:space:]]*Agent 已安装并启动' \"$run_log\" 2>/dev/null; then
    return 0
  fi
  if grep -q 'Agent URL:' \"$run_log\" 2>/dev/null; then
    return 0
  fi
  if [[ \"$last_line\" == *\"已安装并启动\"* ]]; then
    return 0
  fi
  return 1
}}

run_installer_candidates() {{
  local primary_url=\"$1\"
  local fallback_url=\"$2\"
  local run_log=\"/tmp/realm-agent-installer-run-{update_id}.log\"
  local c_url=\"\"
  local c_sha=\"\"
  while IFS=$'\\t' read -r c_url c_sha; do
    [[ -n \"$c_url\" ]] || continue
    if run_installer_stream \"$c_url\" \"$run_log\"; then
      echo \"[update] selected installer source: $c_url\" | tee -a \"$LOG\"
      return 0
    fi
    echo \"[update] installer source failed: $c_url\" | tee -a \"$LOG\"
  done < <(emit_url_sha_candidates \"$primary_url\" \"\" \"$fallback_url\" \"\")
  return 1
}}

ZIP_OK=0
if download_asset_candidates \"agent zip\" \"$TMP_ZIP\" \"$PRIMARY_ZIP_URL\" \"$PRIMARY_ZIP_SHA256\" \"$FALLBACK_ZIP_URL\" \"$FALLBACK_ZIP_SHA256\"; then
  ZIP_OK=1
fi
if [[ \"$ZIP_OK\" != \"1\" ]]; then
  export ERR_REASON=\"download_error\"
  export ERR_MSG=\"下载 agent zip 失败：主备地址均不可用\"
  fail 31
fi

export REALM_AGENT_ASSUME_YES=1
export REALM_AGENT_MODE=1
export REALM_AGENT_ONLY=1
export REALM_AGENT_HOST=\"{host}\"
export REALM_AGENT_PORT=\"{port}\"
export REALM_AGENT_REPO_ZIP_URL=\"file://$TMP_ZIP\"

echo \"[update] run installer...\" | tee -a \"$LOG\"
if ! run_installer_candidates \"$PRIMARY_SH_URL\" \"$FALLBACK_SH_URL\"; then
  export ERR_REASON=\"installer_error\"
  export ERR_MSG=\"执行 installer 失败：主备地址不可用或未检测到成功输出\"
  fail 32
fi

python3 - <<'PY'
import json, pathlib, datetime
p=pathlib.Path(r\"{UPDATE_STATE_FILE}\")
st={{}}
try:
  st=json.loads(p.read_text(encoding='utf-8'))
except Exception:
  st={{}}
cmd_id = r\"{command_id}\"
upd_id = r\"{update_id}\"
des_ver = r\"{desired_ver}\"
st['state']='done'
st['reason_code']=''
st['error']=''
if cmd_id:
  st['command_id']=cmd_id
if upd_id:
  st['update_id']=upd_id
if des_ver:
  st['desired_version']=des_ver
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
                'command_id': command_id,
                'update_id': update_id,
                'state': 'failed',
                'reason_code': 'missing_systemd_run',
                'error': '缺少 systemd-run，无法安全执行自更新（避免被 systemd cgroup 一并杀掉）',
                'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            })
            _save_update_state(st)
    except Exception as exc:
        st = _load_update_state()
        st.update({
            'command_id': str(cmd.get('command_id') or '').strip(),
            'update_id': str(cmd.get('update_id') or '').strip(),
            'state': 'failed',
            'reason_code': 'update_cmd_exception',
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


def _apply_auto_restart_policy_cmd(cmd: Dict[str, Any]) -> None:
    global _LAST_SYNC_ERROR
    try:
        ver = int(cmd.get('version') or 0)
    except Exception:
        ver = 0
    if ver <= 0:
        return

    ack = _read_int(AUTO_RESTART_ACK_FILE, 0)
    if ver <= ack:
        return

    policy_raw = cmd.get('policy')
    if not isinstance(policy_raw, dict):
        _LAST_SYNC_ERROR = 'auto_restart_policy 失败：policy 不合法'
        return

    try:
        policy = _normalize_auto_restart_policy(policy_raw)
        with _AUTO_RESTART_POLICY_LOCK:
            _auto_restart_save_policy_locked(policy)
        _write_int(AUTO_RESTART_ACK_FILE, ver)
        _LAST_SYNC_ERROR = None
    except Exception as exc:
        _LAST_SYNC_ERROR = f'auto_restart_policy 失败：{exc}'
        return


def _cmd_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return bool(default)
    s = str(v).strip().lower()
    if not s:
        return bool(default)
    if s in ("1", "true", "yes", "on", "y"):
        return True
    if s in ("0", "false", "no", "off", "n"):
        return False
    return bool(default)


def _apply_website_task_cmd(cmd: Dict[str, Any]) -> None:
    global _LAST_SYNC_ERROR
    t = str(cmd.get("type") or "").strip()
    try:
        task_id = int(cmd.get("task_id") or 0)
    except Exception:
        task_id = 0
    try:
        attempt = int(cmd.get("attempt") or 0)
    except Exception:
        attempt = 0

    if task_id <= 0:
        return

    result_payload: Dict[str, Any] = {}
    ok = False
    err_text = ""
    try:
        if t == "website_env_ensure":
            req = {
                "need_nginx": _cmd_bool(cmd.get("need_nginx"), True),
                "need_php": _cmd_bool(cmd.get("need_php"), _cmd_bool(cmd.get("include_php"), False)),
                "need_acme": _cmd_bool(cmd.get("need_acme"), True),
            }
            result_payload = api_website_env_ensure(req)
        elif t == "website_env_uninstall":
            req = {
                "purge_data": _cmd_bool(cmd.get("purge_data"), False),
                "deep_uninstall": _cmd_bool(cmd.get("deep_uninstall"), False),
                "sites": cmd.get("sites") if isinstance(cmd.get("sites"), list) else [],
            }
            result_payload = api_website_env_uninstall(req)
        elif t == "website_ssl_issue":
            req = cmd.get("request") if isinstance(cmd.get("request"), dict) else {}
            result_payload = api_ssl_issue(req)
        elif t == "website_ssl_renew":
            req = cmd.get("request") if isinstance(cmd.get("request"), dict) else {}
            result_payload = api_ssl_renew(req)
        else:
            return

        if not isinstance(result_payload, dict):
            result_payload = {"ok": False, "error": "invalid_response"}
        ok = bool(result_payload.get("ok", False))
        if not ok:
            err_text = str(result_payload.get("error") or "执行失败")
            _LAST_SYNC_ERROR = f"{t} 失败：{err_text}"
        else:
            _LAST_SYNC_ERROR = None
    except Exception as exc:
        ok = False
        err_text = str(exc)
        result_payload = {"ok": False, "error": err_text}
        _LAST_SYNC_ERROR = f"{t} 失败：{err_text}"

    _queue_panel_task_result(
        {
            "task_id": int(task_id),
            "type": t,
            "attempt": int(attempt) if attempt > 0 else 1,
            "ok": bool(ok),
            "error": "" if ok else str(err_text or result_payload.get("error") or "执行失败"),
            "result": result_payload,
        }
    )


def _handle_panel_commands(cmds: Any) -> None:
    if not isinstance(cmds, list) or not cmds:
        return

    api_key = _read_agent_api_key()
    for cmd in cmds:
        if not isinstance(cmd, dict):
            continue

        # Signature required for panel commands that modify state
        t = str(cmd.get('type') or '').strip()
        if t in (
            'sync_pool',
            'pool_patch',
            'update_agent',
            'reset_traffic',
            'auto_restart_policy',
            'website_env_ensure',
            'website_env_uninstall',
            'website_ssl_issue',
            'website_ssl_renew',
        ):
            ok_sig = False
            sig_reason = "no_api_key"
            if api_key:
                ok_sig, sig_reason = _verify_cmd_sig_detail(cmd, api_key)
            if not ok_sig:
                # do not crash; keep reporting error for UI
                global _LAST_SYNC_ERROR
                _LAST_SYNC_ERROR = f'{t}：签名校验失败（{sig_reason}）'
                if t == 'update_agent':
                    try:
                        st = _load_update_state()
                        cur_state = _canon_update_state(st.get('state'))
                        cur_update_id = str(st.get('update_id') or '').strip()
                        incoming_update_id = str(cmd.get('update_id') or '').strip()
                        if incoming_update_id and cur_update_id == incoming_update_id and cur_state in ('accepted', 'running', 'done'):
                            # A prior variant already passed signature and started update.
                            continue
                        st.update({
                            'command_id': str(cmd.get('command_id') or '').strip(),
                            'update_id': str(cmd.get('update_id') or '').strip(),
                            'desired_version': str(cmd.get('desired_version') or '').strip() or st.get('desired_version') or '',
                            'state': 'failed',
                            'reason_code': 'signature_rejected',
                            'error': f'update_agent：签名校验失败（{sig_reason}）',
                            'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'agent_version': str(app.version),
                        })
                        _save_update_state(st)
                    except Exception:
                        pass
                continue

        if t == 'sync_pool':
            _apply_sync_pool_cmd(cmd)
        elif t == 'pool_patch':
            _apply_pool_patch_cmd(cmd)
        elif t == 'update_agent':
            _apply_update_agent_cmd(cmd)
        elif t == 'reset_traffic':
            _apply_reset_traffic_cmd(cmd)
        elif t == 'auto_restart_policy':
            _apply_auto_restart_policy_cmd(cmd)
        elif t in ('website_env_ensure', 'website_env_uninstall', 'website_ssl_issue', 'website_ssl_renew'):
            _apply_website_task_cmd(cmd)


def _agent_capabilities() -> Dict[str, Any]:
    # Protocol v2 guarantees command_id + accepted/running lifecycle + reason_code reporting.
    return {
        'update_protocol_version': 2,
        'supports_update_command_id': True,
        'supports_update_accept_ack': True,
        'supports_update_reason_code': True,
    }


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
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip',
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
        report_payload: Optional[Dict[str, Any]] = None
        try:
            ack = _read_int(ACK_VER_FILE, 0)
            task_results = _peek_panel_task_results(limit=40)
            report_payload = _build_push_report()
            payload = {
                'node_id': AGENT_ID,
                'ack_version': ack,
                'traffic_ack_version': _read_int(TRAFFIC_RESET_ACK_FILE, 0),
                'auto_restart_ack_version': _read_int(AUTO_RESTART_ACK_FILE, 0),
                'agent_version': str(app.version),
                'capabilities': _agent_capabilities(),
                'agent_update': _load_update_state(),
                'report': report_payload,
            }
            if task_results:
                payload['task_results'] = task_results
            raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            zipped = gzip.compress(raw, compresslevel=5)
            r = sess.post(url, data=zipped, headers=headers, timeout=(REPORT_CONNECT_TIMEOUT, REPORT_READ_TIMEOUT))
            if r.status_code == 200:
                data = r.json() if r.content else {}
                try:
                    _update_panel_time_offset(data.get('server_ts'))
                except Exception:
                    pass
                if task_results:
                    ack_ids = [str((x or {}).get("id") or "").strip() for x in task_results]
                    _ack_panel_task_results(ack_ids)
                _handle_panel_commands(data.get('commands'))
                backoff = 0.0
            else:
                backoff = min(max_backoff, backoff * 2 + 1.0) if backoff else 2.0
        except Exception:
            backoff = min(max_backoff, backoff * 2 + 1.0) if backoff else 2.0

        try:
            _auto_restart_tick(report_payload)
        except Exception:
            pass

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
    full_pool = _load_full_pool()
    try:
        _reconcile_update_state()
    except Exception:
        pass
    # Apply intranet tunnel rules on boot (if any were persisted)
    try:
        _INTRANET.apply_from_pool(full_pool)
    except Exception:
        pass
    # Apply iptables-forwarded normal rules on boot.
    try:
        _IPTFWD.prepare_for_pool(full_pool)
        _IPTFWD.apply_from_pool(full_pool)
    except Exception:
        pass
    _qos_apply_safe(full_pool, "startup")
    _start_push_reporter()


@app.on_event('shutdown')
def _on_shutdown() -> None:
    _stop_push_reporter()
    try:
        _IPTFWD.stop()
    except Exception:
        pass



@app.get('/api/v1/info')
def api_info(_: None = Depends(_api_key_required)) -> Dict[str, Any]:
    iptables_status = _IPTFWD.status()
    return {
        'ok': True,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': socket.gethostname(),
        'realm_active': any(_service_is_active(name) for name in REALM_SERVICE_NAMES),
        'qos': _qos_get_status(),
        'iptables': iptables_status,
        # backward-compat alias
        'ipt': iptables_status,
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
    pem = str(load_server_cert_pem() or '').strip()
    if not pem:
        return {'ok': False, 'error': 'tls_cert_missing', 'cert_pem': ''}
    if not server_tls_ready():
        return {'ok': False, 'error': 'tls_context_unavailable', 'cert_pem': ''}
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
        _qos_apply_safe(pool, "pool_save")
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
            full_pool = _load_full_pool()
            _qos_apply_safe(full_pool, "apply")
            _IPTFWD.prepare_for_pool(full_pool)
            try:
                _apply_pool_to_config()
                _restart_realm()
                _IPTFWD.apply_from_pool(full_pool)
            except Exception:
                # Keep managed iptables rules from staying in a partially-applied state.
                try:
                    _IPTFWD.apply_from_pool(full_pool)
                except Exception:
                    pass
                raise
            # Apply intranet tunnel rules (handled by agent, not realm)
            try:
                _INTRANET.apply_from_pool(full_pool)
            except Exception:
                # do not fail apply for tunnel supervisor issues
                pass
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}
    return {'ok': True}


# ------------------------ NetProbe (ping/tcping) ------------------------

_NETPROBE_PING_RE = re.compile(r'time[=<]?\s*([0-9.]+)\s*ms', re.IGNORECASE)
_NETPROBE_TRANSPORT_RE = re.compile(r'(^|;)\s*([a-zA-Z0-9_]+)\s*=\s*([^;]+)')
_NETPROBE_TRACE_HOP_RE = re.compile(r'^\s*(\d+)\s+(.*)$')
_NETPROBE_TRACE_MS_RE = re.compile(r'([0-9]+(?:\.[0-9]+)?)\s*ms', re.IGNORECASE)
_NETPROBE_TRACE_HOST_IP_RE = re.compile(r'^(\S+)\s+\(([^)]+)\)')
_NETPROBE_TRACE_SPLIT_RE = re.compile(r'[\s,;]+')


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


def _netprobe_trace_max_hops(raw_hops: Any) -> int:
    try:
        v = int(raw_hops) if raw_hops is not None else 20
    except Exception:
        v = 20
    if v < 3:
        v = 3
    if v > 64:
        v = 64
    return v


def _netprobe_trace_timeout(raw_timeout: Any) -> float:
    try:
        v = float(raw_timeout) if raw_timeout is not None else 1.0
    except Exception:
        v = 1.0
    if v < 0.3:
        v = 0.3
    if v > 5.0:
        v = 5.0
    return v


def _netprobe_trace_probes(raw_probes: Any) -> int:
    try:
        v = int(raw_probes) if raw_probes is not None else 3
    except Exception:
        v = 3
    if v < 1:
        v = 1
    if v > 5:
        v = 5
    return v


def _netprobe_trace_clean_target(raw_target: Any) -> str:
    s = str(raw_target or '').strip()
    if len(s) > 256:
        s = s[:256].strip()
    return s


def _netprobe_trace_host_is_ip(host: str) -> bool:
    h = str(host or '').strip()
    if not h:
        return False
    core = h.split('%', 1)[0]
    try:
        ipaddress.ip_address(core)
        return True
    except Exception:
        return False


def _netprobe_trace_host_valid(host: str) -> bool:
    h = str(host or '').strip()
    if not h:
        return False
    if len(h) > 253:
        return False
    if any(ch.isspace() for ch in h):
        return False
    if h in ('*', '-', '—'):
        return False
    if '/' in h:
        return False
    if _netprobe_trace_host_is_ip(h):
        return True
    if h.endswith('.'):
        h = h[:-1]
    if not h:
        return False
    labels = h.split('.')
    for lb in labels:
        if not lb:
            return False
        if len(lb) > 63:
            return False
        if lb.startswith('-') or lb.endswith('-'):
            return False
        if not re.match(r'^[a-zA-Z0-9-]+$', lb):
            return False
    return True


def _netprobe_trace_host_token(token: str) -> str:
    t = str(token or '').strip().strip(',;')
    if not t:
        return ''

    # Strip common wrappers.
    if t.startswith('(') and t.endswith(')') and len(t) > 2:
        t = t[1:-1].strip()
    if t.startswith('<') and t.endswith('>') and len(t) > 2:
        t = t[1:-1].strip()

    if '://' in t:
        try:
            parsed = urlparse(t)
            t = str(parsed.hostname or '').strip()
        except Exception:
            t = t.split('://', 1)[-1].strip()
            if '/' in t:
                t = t.split('/', 1)[0].strip()

    # [ipv6]:port
    if t.startswith('[') and ']' in t:
        host = t[1:t.index(']')].strip()
        return host

    # host:port (single ':' only to avoid IPv6 false positives)
    if t.count(':') == 1:
        host, p = t.rsplit(':', 1)
        if p.isdigit():
            return host.strip()

    # trim plain path suffix if any
    if '/' in t:
        t = t.split('/', 1)[0].strip()

    return t


def _netprobe_trace_extract_host(raw_target: str) -> str:
    s = _netprobe_trace_clean_target(raw_target)
    if not s:
        return ''

    candidates: List[str] = [s]
    if '→' in s:
        right = s.split('→', 1)[-1].strip()
        if right:
            candidates.insert(0, right)

    # Try right-most token first for labels like "本机监听 127.0.0.1:443".
    toks = [x for x in _NETPROBE_TRACE_SPLIT_RE.split(s) if x]
    for tok in reversed(toks):
        candidates.append(tok)

    seen: set[str] = set()
    for c in candidates:
        cc = str(c or '').strip()
        if not cc:
            continue
        if cc in seen:
            continue
        seen.add(cc)
        host = _netprobe_trace_host_token(cc)
        if _netprobe_trace_host_valid(host):
            return host
    return ''


def _netprobe_trace_num(v: Any) -> Optional[float]:
    if v is None:
        return None
    s = str(v).strip().replace(',', '')
    if not s:
        return None
    try:
        return float(s)
    except Exception:
        return None


def _netprobe_trace_num_int(v: Any, default: int) -> int:
    try:
        return int(float(str(v).strip()))
    except Exception:
        return int(default)


def _netprobe_trace_summary(hops: List[Dict[str, Any]], target_host: str, max_hops: int) -> Dict[str, Any]:
    hops_sorted = sorted([h for h in hops if isinstance(h, dict)], key=lambda x: int(x.get('hop') or 0))
    hops_total = len(hops_sorted)
    responded = 0
    for h in hops_sorted:
        try:
            if float(h.get('loss_pct') or 100.0) < 100.0:
                responded += 1
        except Exception:
            pass

    reached = False
    if hops_sorted:
        last = hops_sorted[-1]
        host = str(last.get('host') or '').strip().lower()
        ip = str(last.get('ip') or '').strip().lower()
        target_l = str(target_host or '').strip().lower()
        if target_l and (host == target_l or ip == target_l):
            reached = True
        elif host and host not in ('*', '???'):
            try:
                reached = float(last.get('loss_pct') or 100.0) < 100.0
            except Exception:
                reached = False

    with_latency = 0
    max_avg_ms: Optional[float] = None
    for h in hops_sorted:
        v = h.get('avg_ms')
        if v is None:
            continue
        try:
            f = float(v)
        except Exception:
            continue
        with_latency += 1
        if max_avg_ms is None or f > max_avg_ms:
            max_avg_ms = f

    out: Dict[str, Any] = {
        'target': str(target_host or ''),
        'hops_total': hops_total,
        'responded_hops': int(responded),
        'with_latency_hops': int(with_latency),
        'max_hops': int(max_hops),
        'reached': bool(reached),
    }
    if max_avg_ms is not None:
        out['max_avg_ms'] = round(float(max_avg_ms), 3)
    return out


def _netprobe_trace_tools_state() -> Dict[str, bool]:
    return {
        'mtr': bool(shutil.which('mtr')),
        'traceroute': bool(shutil.which('traceroute')),
    }


def _netprobe_trace_tools_ready(state: Optional[Dict[str, bool]] = None) -> bool:
    st = state if isinstance(state, dict) else _netprobe_trace_tools_state()
    return bool(st.get('mtr')) or bool(st.get('traceroute'))


def _netprobe_trace_brief(text: Any, limit: int = 220) -> str:
    s = ' '.join(str(text or '').split()).strip()
    if not s:
        return ''
    if len(s) > int(limit):
        return s[: int(limit)] + '…'
    return s


def _netprobe_trace_install_plans(mgr: str) -> List[List[str]]:
    m = str(mgr or '').strip().lower()
    if m == 'apt':
        return [
            ['mtr-tiny', 'traceroute'],
            ['mtr', 'traceroute'],
            ['traceroute'],
            ['mtr-tiny'],
            ['mtr'],
        ]
    return [
        ['mtr', 'traceroute'],
        ['traceroute'],
        ['mtr'],
    ]


def _netprobe_trace_auto_install_once() -> Dict[str, Any]:
    state0 = _netprobe_trace_tools_state()
    if _netprobe_trace_tools_ready(state0):
        return {
            'ok': True,
            'attempted': False,
            'state': state0,
            'detail': 'already_available',
        }

    global _TRACE_TOOL_INSTALL_ATTEMPTED, _TRACE_TOOL_INSTALL_LAST
    with _TRACE_TOOL_INSTALL_LOCK:
        state1 = _netprobe_trace_tools_state()
        if _netprobe_trace_tools_ready(state1):
            return {
                'ok': True,
                'attempted': False,
                'state': state1,
                'detail': 'available_after_wait',
            }

        if _TRACE_TOOL_INSTALL_ATTEMPTED:
            if isinstance(_TRACE_TOOL_INSTALL_LAST, dict) and _TRACE_TOOL_INSTALL_LAST:
                return dict(_TRACE_TOOL_INSTALL_LAST)
            return {
                'ok': False,
                'attempted': True,
                'error': 'install_already_attempted',
                'state': state1,
                'detail': '已尝试自动安装，请检查节点环境',
            }

        _TRACE_TOOL_INSTALL_ATTEMPTED = True

        if not TRACE_AUTO_INSTALL:
            out = {
                'ok': False,
                'attempted': True,
                'error': 'auto_install_disabled',
                'state': state1,
                'detail': '自动安装已禁用（REALM_AGENT_TRACE_AUTO_INSTALL=0）',
            }
            _TRACE_TOOL_INSTALL_LAST = out
            return dict(out)

        try:
            if hasattr(os, 'geteuid') and int(os.geteuid()) != 0:
                out = {
                    'ok': False,
                    'attempted': True,
                    'error': 'install_need_root',
                    'state': state1,
                    'detail': '自动安装需要 root 权限',
                }
                _TRACE_TOOL_INSTALL_LAST = out
                return dict(out)
        except Exception:
            pass

        mgr = _detect_pkg_mgr()
        if not mgr:
            out = {
                'ok': False,
                'attempted': True,
                'error': 'pkg_mgr_not_found',
                'state': state1,
                'detail': '未检测到受支持的包管理器',
            }
            _TRACE_TOOL_INSTALL_LAST = out
            return dict(out)

        logs: List[str] = []
        for plan in _netprobe_trace_install_plans(mgr):
            ok, out_raw = _pkg_install(plan)
            brief = _netprobe_trace_brief(out_raw, 180)
            label = 'ok' if ok else 'fail'
            logs.append(f"{label}:{'+'.join(plan)}{(':' + brief) if brief else ''}")

            st_after = _netprobe_trace_tools_state()
            if _netprobe_trace_tools_ready(st_after):
                installed = [k for k, v in st_after.items() if bool(v) and not bool(state1.get(k))]
                out = {
                    'ok': True,
                    'attempted': True,
                    'manager': mgr,
                    'packages': plan,
                    'installed_tools': installed,
                    'state': st_after,
                    'detail': _netprobe_trace_brief('; '.join(logs), 240) or 'trace_tool_installed',
                }
                _TRACE_TOOL_INSTALL_LAST = out
                return dict(out)

        st_end = _netprobe_trace_tools_state()
        out = {
            'ok': False,
            'attempted': True,
            'error': 'install_failed',
            'manager': mgr,
            'state': st_end,
            'detail': _netprobe_trace_brief('; '.join(logs), 240) or '自动安装失败',
        }
        _TRACE_TOOL_INSTALL_LAST = out
        return dict(out)


def _netprobe_trace_with_install_meta(payload: Dict[str, Any], install_meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out = dict(payload or {})
    if isinstance(install_meta, dict) and install_meta.get('attempted') is True:
        out['auto_install'] = dict(install_meta)
    return out


def _netprobe_trace_parse_mtr(output: str, target_host: str, probes: int, max_hops: int) -> Dict[str, Any]:
    try:
        data = json.loads(str(output or '{}'))
    except Exception:
        return {'ok': False, 'error': 'mtr_parse_failed'}

    report = data.get('report') if isinstance(data, dict) else None
    hubs = report.get('hubs') if isinstance(report, dict) else None
    if not isinstance(hubs, list):
        return {'ok': False, 'error': 'mtr_no_hops'}

    hops: List[Dict[str, Any]] = []
    for idx, hub in enumerate(hubs):
        if not isinstance(hub, dict):
            continue
        hop_n = _netprobe_trace_num_int(hub.get('count') or hub.get('hop') or (idx + 1), idx + 1)
        if hop_n <= 0:
            hop_n = idx + 1

        host = str(hub.get('host') or hub.get('Host') or hub.get('addr') or '*').strip() or '*'
        ip = str(hub.get('ip') or '').strip()
        if (not ip) and _netprobe_trace_host_is_ip(host):
            ip = host

        sent = _netprobe_trace_num_int(hub.get('Snt') or hub.get('sent') or probes, probes)
        if sent <= 0:
            sent = int(probes)

        loss_pct = _netprobe_trace_num(hub.get('Loss%') or hub.get('loss%') or hub.get('loss'))
        last_ms = _netprobe_trace_num(hub.get('Last') or hub.get('last'))
        avg_ms = _netprobe_trace_num(hub.get('Avg') or hub.get('avg'))
        best_ms = _netprobe_trace_num(hub.get('Best') or hub.get('best'))
        worst_ms = _netprobe_trace_num(hub.get('Wrst') or hub.get('worst') or hub.get('Worst'))

        if avg_ms is None and last_ms is not None:
            avg_ms = last_ms
        if best_ms is None and avg_ms is not None:
            best_ms = avg_ms
        if worst_ms is None and avg_ms is not None:
            worst_ms = avg_ms
        if loss_pct is None:
            if avg_ms is None and last_ms is None:
                loss_pct = 100.0
            else:
                loss_pct = 0.0
        loss_pct = max(0.0, min(100.0, float(loss_pct)))

        samples: List[float] = []
        for x in (last_ms, avg_ms, best_ms, worst_ms):
            if x is None:
                continue
            fv = round(float(x), 3)
            if not samples or abs(samples[-1] - fv) > 1e-9:
                samples.append(fv)

        item: Dict[str, Any] = {
            'hop': int(hop_n),
            'host': host,
            'ip': ip,
            'sent': int(sent),
            'loss_pct': round(loss_pct, 2),
            'samples_ms': samples,
        }
        if last_ms is not None:
            item['last_ms'] = round(float(last_ms), 3)
        if avg_ms is not None:
            item['avg_ms'] = round(float(avg_ms), 3)
        if best_ms is not None:
            item['best_ms'] = round(float(best_ms), 3)
        if worst_ms is not None:
            item['worst_ms'] = round(float(worst_ms), 3)
        hops.append(item)

    hops.sort(key=lambda x: int(x.get('hop') or 0))
    if not hops:
        return {'ok': False, 'error': 'mtr_no_hops'}

    return {
        'ok': True,
        'engine': 'mtr',
        'target': str(target_host or ''),
        'max_hops': int(max_hops),
        'probes': int(probes),
        'hops': hops,
        'summary': _netprobe_trace_summary(hops, target_host, max_hops),
    }


def _netprobe_trace_run_mtr(host: str, max_hops: int, per_hop_timeout: float, probes: int) -> Dict[str, Any]:
    mtr_bin = shutil.which('mtr')
    if not mtr_bin:
        return {'ok': False, 'error': 'mtr_not_found'}
    cmd = [
        mtr_bin,
        '-n',
        '--report',
        '--report-cycles',
        str(int(probes)),
        '--json',
        '-m',
        str(int(max_hops)),
        str(host),
    ]
    proc_timeout = float(max(8.0, min(45.0, float(max_hops) * float(per_hop_timeout) * float(probes) * 0.8)))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=proc_timeout)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'mtr_timeout'}
    except Exception as exc:
        return {'ok': False, 'error': f'mtr_exec_error:{exc}'}

    output = ((r.stdout or '') + '\n' + (r.stderr or '')).strip()
    if int(r.returncode or 0) != 0:
        err = output.splitlines()[-1] if output else 'mtr_failed'
        return {'ok': False, 'error': f'mtr_failed:{err[:200]}'}
    parsed = _netprobe_trace_parse_mtr(output, host, probes, max_hops)
    if parsed.get('ok') is not True:
        return {'ok': False, 'error': parsed.get('error') or 'mtr_parse_failed'}
    return parsed


def _netprobe_trace_parse_traceroute(output: str, target_host: str, probes: int, max_hops: int) -> Dict[str, Any]:
    hops: List[Dict[str, Any]] = []
    for raw_line in str(output or '').splitlines():
        line = str(raw_line or '').rstrip()
        m = _NETPROBE_TRACE_HOP_RE.match(line)
        if not m:
            continue
        hop_n = _netprobe_trace_num_int(m.group(1), 0)
        if hop_n <= 0:
            continue
        rest = str(m.group(2) or '').strip()

        host = '*'
        ip = ''
        host_ip_m = _NETPROBE_TRACE_HOST_IP_RE.match(rest)
        if host_ip_m:
            host = str(host_ip_m.group(1) or '').strip() or '*'
            ip = str(host_ip_m.group(2) or '').strip()
        else:
            toks = rest.split()
            if toks:
                t0 = toks[0].strip()
                if t0 != '*':
                    host = t0

        if host.startswith('(') and host.endswith(')') and len(host) > 2:
            host = host[1:-1].strip()
        if host.startswith('[') and host.endswith(']') and len(host) > 2:
            host = host[1:-1].strip()
        if (not ip) and _netprobe_trace_host_is_ip(host):
            ip = host

        samples: List[float] = []
        for mm in _NETPROBE_TRACE_MS_RE.finditer(rest):
            try:
                samples.append(round(float(mm.group(1)), 3))
            except Exception:
                continue

        sent = max(1, int(probes))
        recv = len(samples)
        loss_pct = round(max(0.0, min(100.0, (float(sent - recv) / float(sent)) * 100.0)), 2)

        item: Dict[str, Any] = {
            'hop': int(hop_n),
            'host': host or '*',
            'ip': ip,
            'sent': int(sent),
            'loss_pct': float(loss_pct),
            'samples_ms': samples,
        }
        if samples:
            item['last_ms'] = round(float(samples[-1]), 3)
            item['avg_ms'] = round(float(sum(samples) / len(samples)), 3)
            item['best_ms'] = round(float(min(samples)), 3)
            item['worst_ms'] = round(float(max(samples)), 3)

        note_m = re.search(r'(!\S+)', rest)
        if note_m:
            item['note'] = str(note_m.group(1) or '').strip()

        hops.append(item)

    hops.sort(key=lambda x: int(x.get('hop') or 0))
    if not hops:
        return {'ok': False, 'error': 'traceroute_no_hops'}

    return {
        'ok': True,
        'engine': 'traceroute',
        'target': str(target_host or ''),
        'max_hops': int(max_hops),
        'probes': int(probes),
        'hops': hops,
        'summary': _netprobe_trace_summary(hops, target_host, max_hops),
    }


def _netprobe_trace_run_traceroute(host: str, max_hops: int, per_hop_timeout: float, probes: int) -> Dict[str, Any]:
    tr_bin = shutil.which('traceroute')
    if not tr_bin:
        return {'ok': False, 'error': 'traceroute_not_found'}
    wait_s = max(0.3, min(5.0, float(per_hop_timeout)))
    cmd = [
        tr_bin,
        '-n',
        '-m',
        str(int(max_hops)),
        '-w',
        f'{wait_s:.2f}',
        '-q',
        str(int(probes)),
        str(host),
    ]
    proc_timeout = float(max(6.0, min(60.0, float(max_hops) * wait_s * 1.8)))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=proc_timeout)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'traceroute_timeout'}
    except Exception as exc:
        return {'ok': False, 'error': f'traceroute_exec_error:{exc}'}

    output = ((r.stdout or '') + '\n' + (r.stderr or '')).strip()
    if int(r.returncode or 0) != 0 and not _NETPROBE_TRACE_HOP_RE.search(output):
        err = output.splitlines()[-1] if output else 'traceroute_failed'
        return {'ok': False, 'error': f'traceroute_failed:{err[:200]}'}
    parsed = _netprobe_trace_parse_traceroute(output, host, probes, max_hops)
    if parsed.get('ok') is not True:
        return {'ok': False, 'error': parsed.get('error') or 'traceroute_parse_failed'}
    return parsed


def _netprobe_trace(host: str, max_hops: int, per_hop_timeout: float, probes: int) -> Dict[str, Any]:
    target = str(host or '').strip()
    if not _netprobe_trace_host_valid(target):
        return {'ok': False, 'error': 'invalid_target'}

    tries: List[str] = []
    install_meta: Optional[Dict[str, Any]] = None
    tools = _netprobe_trace_tools_state()
    if not _netprobe_trace_tools_ready(tools):
        install_meta = _netprobe_trace_auto_install_once()
        tools = _netprobe_trace_tools_state()

    if bool(tools.get('mtr')):
        res_mtr = _netprobe_trace_run_mtr(target, max_hops, per_hop_timeout, probes)
        if res_mtr.get('ok') is True:
            return _netprobe_trace_with_install_meta(res_mtr, install_meta)
        tries.append(str(res_mtr.get('error') or 'mtr_failed'))

    if bool(tools.get('traceroute')):
        res_tr = _netprobe_trace_run_traceroute(target, max_hops, per_hop_timeout, probes)
        if res_tr.get('ok') is True:
            return _netprobe_trace_with_install_meta(res_tr, install_meta)
        tries.append(str(res_tr.get('error') or 'traceroute_failed'))

    if not _netprobe_trace_tools_ready(tools):
        detail = 'mtr / traceroute 均不可用'
        if isinstance(install_meta, dict):
            d = _netprobe_trace_brief(install_meta.get('detail'), 160)
            if d:
                detail = f'{detail}；{d}'
        out = {'ok': False, 'error': 'trace_tool_not_found', 'detail': detail}
        return _netprobe_trace_with_install_meta(out, install_meta)

    detail = '; '.join([x for x in tries if x])[:240] if tries else 'trace_failed'
    out = {
        'ok': False,
        'error': 'trace_failed',
        'detail': detail,
        'target': target,
        'max_hops': int(max_hops),
        'probes': int(probes),
    }
    return _netprobe_trace_with_install_meta(out, install_meta)


def _netprobe_clean_targets(raw_targets: Any, max_items: int) -> List[str]:
    if not isinstance(raw_targets, list):
        return []
    cleaned: List[str] = []
    seen: set[str] = set()
    for t in raw_targets:
        s = str(t or '').strip()
        if not s:
            continue
        if len(s) > 128:
            continue
        if s in seen:
            continue
        seen.add(s)
        cleaned.append(s)
    return cleaned[:max_items]


def _netprobe_default_port(raw_port: Any) -> int:
    try:
        p = int(raw_port) if raw_port is not None else 443
    except Exception:
        p = 443
    if p < 1 or p > 65535:
        p = 443
    return p


def _netprobe_timeout(raw_timeout: Any) -> float:
    try:
        to = float(raw_timeout) if raw_timeout is not None else 1.5
    except Exception:
        to = 1.5
    if to < 0.2:
        to = 0.2
    if to > 10:
        to = 10.0
    return to


def _netprobe_target_key(host: str, port: int) -> str:
    h = str(host or '').strip()
    try:
        p = int(port)
    except Exception:
        p = 0
    if not h or p < 1 or p > 65535:
        return ''
    if ':' in h and not h.startswith('['):
        h = f'[{h}]'
    return f'{h}:{p}'


def _netprobe_transport_param(transport: Any, key: str) -> str:
    want = str(key or '').strip().lower()
    if not want:
        return ''
    s = str(transport or '').strip()
    if not s:
        return ''
    for m in _NETPROBE_TRANSPORT_RE.finditer(s):
        k = str(m.group(2) or '').strip().lower()
        if k == want:
            return str(m.group(3) or '').strip()
    return ''


def _netprobe_transport_has_flag(transport: Any, flag: str) -> bool:
    want = str(flag or '').strip().lower()
    if not want:
        return False
    s = str(transport or '').strip().lower()
    if not s:
        return False
    toks = [x.strip() for x in s.split(';') if x and x.strip()]
    for t in toks:
        if '=' in t:
            continue
        if t == want:
            return True
    return False


def _netprobe_is_ws_transport(transport: Any) -> bool:
    s = str(transport or '').strip().lower()
    if not s:
        return False
    head = s.split(';', 1)[0].strip()
    return head in ('ws', 'wss')


def _netprobe_is_ip_literal(host: str) -> bool:
    h = str(host or '').strip()
    if not h:
        return False
    core = h.split('%', 1)[0]
    try:
        socket.inet_pton(socket.AF_INET, core)
        return True
    except Exception:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, core)
        return True
    except Exception:
        return False


def _netprobe_collect_remotes(rule: Dict[str, Any]) -> List[str]:
    remotes: List[str] = []
    r0 = rule.get('remote')
    if isinstance(r0, str) and r0.strip():
        remotes.append(r0.strip())
    r1 = rule.get('remotes')
    if isinstance(r1, list):
        remotes.extend([str(x).strip() for x in r1 if str(x or '').strip()])
    r2 = rule.get('extra_remotes')
    if isinstance(r2, list):
        remotes.extend([str(x).strip() for x in r2 if str(x or '').strip()])
    out: List[str] = []
    seen: set[str] = set()
    for r in remotes:
        if r in seen:
            continue
        seen.add(r)
        out.append(r)
    return out[:16]


def _netprobe_proto_set(protocol: Any) -> set[str]:
    p = str(protocol or 'tcp+udp').strip().lower()
    if p == 'tcp':
        return {'tcp'}
    if p == 'udp':
        return {'udp'}
    return {'tcp', 'udp'}


def _netprobe_read_proc_ports(path: str, tcp: bool) -> set[int]:
    out: set[int] = set()
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[1:]
    except Exception:
        return out

    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        st = parts[3].upper()
        if tcp:
            if st != '0A':
                continue
        else:
            # udp sockets are usually "07" (UNCONN)
            if st not in ('07', '0A'):
                continue
        if ':' not in local:
            continue
        p_hex = local.rsplit(':', 1)[-1]
        try:
            p = int(p_hex, 16)
        except Exception:
            continue
        if p > 0:
            out.add(p)
    return out


def _netprobe_system_listen_ports() -> Dict[str, set[int]]:
    tcp_ports = _netprobe_read_proc_ports('/proc/net/tcp', tcp=True) | _netprobe_read_proc_ports('/proc/net/tcp6', tcp=True)
    udp_ports = _netprobe_read_proc_ports('/proc/net/udp', tcp=False) | _netprobe_read_proc_ports('/proc/net/udp6', tcp=False)
    return {'tcp': tcp_ports, 'udp': udp_ports}


def _netprobe_pool_listen_ports(pool: Dict[str, Any]) -> Dict[str, set[int]]:
    out: Dict[str, set[int]] = {'tcp': set(), 'udp': set()}
    eps = pool.get('endpoints') if isinstance(pool, dict) else []
    if not isinstance(eps, list):
        return out
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        if bool(ep.get('disabled')):
            continue
        ex = ep.get('extra_config') if isinstance(ep.get('extra_config'), dict) else {}
        if isinstance(ex, dict) and str(ex.get('intranet_role') or '').strip() == 'client':
            continue
        listen = str(ep.get('listen') or '').strip()
        if not listen:
            continue
        try:
            lp = int(_parse_listen_port(listen))
        except Exception:
            continue
        if lp <= 0:
            continue
        for proto in _netprobe_proto_set(ep.get('protocol')):
            out[proto].add(lp)
    return out


def _netprobe_read_proc_int(path: str) -> Optional[int]:
    try:
        raw = Path(path).read_text(encoding='utf-8').strip().split()
    except Exception:
        return None
    if not raw:
        return None
    try:
        return int(raw[0])
    except Exception:
        return None


def _netprobe_read_port_range(path: str) -> Optional[Tuple[int, int]]:
    try:
        raw = Path(path).read_text(encoding='utf-8').strip().split()
    except Exception:
        return None
    if len(raw) < 2:
        return None
    try:
        lo = int(raw[0])
        hi = int(raw[1])
    except Exception:
        return None
    if lo <= 0 or hi <= lo:
        return None
    return lo, hi


def _netprobe_run_targets(mode: str, targets: List[str], default_port: int, timeout_f: float) -> Dict[str, Any]:
    if not targets:
        return {}
    results: Dict[str, Any] = {}
    max_workers = max(4, min(48, len(targets)))
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
    return results


def _netprobe_rules(payload: Dict[str, Any], default_port: int, timeout_f: float) -> Dict[str, Any]:
    raw_rules = payload.get('rules')
    if not isinstance(raw_rules, list):
        maybe_pool = payload.get('pool')
        if isinstance(maybe_pool, dict) and isinstance(maybe_pool.get('endpoints'), list):
            raw_rules = maybe_pool.get('endpoints') or []
        else:
            raw_rules = []
    raw_rules = raw_rules[:160]

    rules_meta: List[Dict[str, Any]] = []
    global_targets: List[str] = []
    global_target_set: set[str] = set()
    max_probe_targets = 400

    active_rules = 0
    udp_rules = 0

    for idx, rule in enumerate(raw_rules):
        if not isinstance(rule, dict):
            continue

        ex = rule.get('extra_config') if isinstance(rule.get('extra_config'), dict) else {}
        listen = str(rule.get('listen') or '').strip()
        protocol = str(rule.get('protocol') or 'tcp+udp').strip().lower()
        pset = _netprobe_proto_set(protocol)
        disabled = bool(rule.get('disabled'))
        rid = str(rule.get('id') or '').strip()

        remotes = _netprobe_collect_remotes(rule)
        candidate_targets: List[str] = []
        for r in remotes:
            host, port = _parse_tcp_target(r, default_port)
            k = _netprobe_target_key(host, port)
            if k and k not in candidate_targets:
                candidate_targets.append(k)

        warnings: List[str] = []

        if 'udp' in pset and 'tcp' in pset and remotes:
            common_tcp_ports = {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443}
            ports: List[int] = []
            for r in remotes[:16]:
                _h, p = _parse_tcp_target(r, default_port)
                if 1 <= int(p) <= 65535:
                    ports.append(int(p))
            if ports and all(p in common_tcp_ports for p in ports):
                warnings.append('已启用 UDP（TCP+UDP），目标端口看起来是典型 TCP 端口，可能存在 UDP 误开')

        remote_transport = str(rule.get('remote_transport') or (ex.get('remote_transport') if isinstance(ex, dict) else '') or '').strip()
        remote_ws_mode = _netprobe_is_ws_transport(remote_transport) or bool(
            (ex.get('remote_ws_host') if isinstance(ex, dict) else '') or (ex.get('remote_ws_path') if isinstance(ex, dict) else '')
        )
        if remote_ws_mode:
            ws_host = str((ex.get('remote_ws_host') if isinstance(ex, dict) else '') or _netprobe_transport_param(remote_transport, 'host') or '').strip()
            ws_path = str((ex.get('remote_ws_path') if isinstance(ex, dict) else '') or _netprobe_transport_param(remote_transport, 'path') or '').strip()
            tls = bool((ex.get('remote_tls_enabled') if isinstance(ex, dict) else False)) or _netprobe_transport_has_flag(remote_transport, 'tls')
            insecure = bool((ex.get('remote_tls_insecure') if isinstance(ex, dict) else False)) or _netprobe_transport_has_flag(
                remote_transport, 'insecure'
            )
            sni = str(
                (ex.get('remote_tls_sni') if isinstance(ex, dict) else '')
                or _netprobe_transport_param(remote_transport, 'sni')
                or _netprobe_transport_param(remote_transport, 'servername')
                or ''
            ).strip()
            if not ws_host or not ws_path:
                miss = []
                if not ws_host:
                    miss.append('Host')
                if not ws_path:
                    miss.append('Path')
                warnings.append(f'WSS 参数缺失（remote 侧）：{" / ".join(miss)} 不能为空')
            if ws_host:
                ws_port = 443 if tls else 80
                tk = _netprobe_target_key(ws_host, ws_port)
                if tk and tk not in candidate_targets:
                    candidate_targets.append(tk)
            if tls and insecure:
                warnings.append('TLS 校验已关闭（remote 侧 insecure=true），存在中间人风险')
            if tls and ws_host and (not sni) and (not _netprobe_is_ip_literal(ws_host)):
                warnings.append('TLS 未设置 SNI（remote 侧），证书校验可能失败')

        listen_transport = str(rule.get('listen_transport') or (ex.get('listen_transport') if isinstance(ex, dict) else '') or '').strip()
        listen_ws_mode = _netprobe_is_ws_transport(listen_transport) or bool(
            (ex.get('listen_ws_host') if isinstance(ex, dict) else '') or (ex.get('listen_ws_path') if isinstance(ex, dict) else '')
        )
        if listen_ws_mode:
            ws_host = str((ex.get('listen_ws_host') if isinstance(ex, dict) else '') or _netprobe_transport_param(listen_transport, 'host') or '').strip()
            ws_path = str((ex.get('listen_ws_path') if isinstance(ex, dict) else '') or _netprobe_transport_param(listen_transport, 'path') or '').strip()
            tls = bool((ex.get('listen_tls_enabled') if isinstance(ex, dict) else False)) or _netprobe_transport_has_flag(listen_transport, 'tls')
            insecure = bool((ex.get('listen_tls_insecure') if isinstance(ex, dict) else False)) or _netprobe_transport_has_flag(
                listen_transport, 'insecure'
            )
            servername = str(
                (ex.get('listen_tls_servername') if isinstance(ex, dict) else '')
                or _netprobe_transport_param(listen_transport, 'servername')
                or _netprobe_transport_param(listen_transport, 'sni')
                or ''
            ).strip()
            if not ws_host or not ws_path:
                miss = []
                if not ws_host:
                    miss.append('Host')
                if not ws_path:
                    miss.append('Path')
                warnings.append(f'WSS 参数缺失（listen 侧）：{" / ".join(miss)} 不能为空')
            if tls and insecure:
                warnings.append('TLS 校验已关闭（listen 侧 insecure=true），存在中间人风险')
            if tls and ws_host and (not servername) and (not _netprobe_is_ip_literal(ws_host)):
                warnings.append('TLS 未设置 ServerName（listen 侧），证书校验可能失败')

        probe_targets: List[str] = []
        if (not disabled) and ('tcp' in pset):
            for t in candidate_targets:
                if t not in probe_targets:
                    probe_targets.append(t)
        elif (not disabled) and candidate_targets:
            warnings.append('当前规则未启用 TCP，无法执行 TCP 连通探测')

        listen_port = 0
        try:
            listen_port = int(_parse_listen_port(listen))
        except Exception:
            listen_port = 0

        if not disabled:
            active_rules += 1
            if 'udp' in pset:
                udp_rules += 1

        scheduled_probe_targets: List[str] = []
        truncated_count = 0
        for t in probe_targets:
            if t in global_target_set:
                scheduled_probe_targets.append(t)
                continue
            if len(global_targets) >= max_probe_targets:
                truncated_count += 1
                continue
            global_target_set.add(t)
            global_targets.append(t)
            scheduled_probe_targets.append(t)
        if truncated_count > 0:
            warnings.append(f'探测目标过多，已截断（本次最多 {max_probe_targets} 个）')

        rules_meta.append(
            {
                'idx': idx,
                'rule_id': rid,
                'listen': listen,
                'protocol': protocol or 'tcp+udp',
                'disabled': disabled,
                'proto_set': pset,
                'listen_port': listen_port,
                'targets': candidate_targets[:16],
                'probe_targets': scheduled_probe_targets[:16],
                'warnings': warnings[:16],
            }
        )

    # Check listen port occupancy (new port is already used by other processes).
    try:
        running_pool = _load_full_pool()
    except Exception:
        running_pool = {'endpoints': []}
    current_pool_ports = _netprobe_pool_listen_ports(running_pool)
    system_ports = _netprobe_system_listen_ports()

    for meta in rules_meta:
        if meta.get('disabled'):
            continue
        lp = int(meta.get('listen_port') or 0)
        if lp <= 0:
            continue
        occupied: List[str] = []
        for proto in sorted(meta.get('proto_set') or []):
            if proto not in ('tcp', 'udp'):
                continue
            if lp in (system_ports.get(proto) or set()) and lp not in (current_pool_ports.get(proto) or set()):
                occupied.append(f'{proto.upper()}:{lp}')
        if occupied:
            msg = f"监听端口可能被占用：{', '.join(occupied)}（当前系统已有监听）"
            if msg not in meta['warnings']:
                meta['warnings'].append(msg)
            meta['port_occupied'] = occupied

    probe_results = _netprobe_run_targets('tcping', global_targets, default_port, timeout_f)

    rules_out: List[Dict[str, Any]] = []
    unreachable_targets_total = 0
    unreachable_rules = 0
    warning_total = 0

    for meta in rules_meta:
        per_target: Dict[str, Any] = {}
        unreachable: List[str] = []
        for t in meta.get('probe_targets') or []:
            item = probe_results.get(t)
            if not isinstance(item, dict):
                item = {'ok': False, 'error': 'no_data'}
            per_target[t] = item
            if item.get('ok') is not True:
                unreachable.append(t)

        if meta.get('disabled'):
            ok_val = None
        elif not (meta.get('probe_targets') or []):
            ok_val = None
        else:
            ok_val = len(unreachable) == 0

        if ok_val is False:
            unreachable_rules += 1
        unreachable_targets_total += len(unreachable)
        warning_total += len(meta.get('warnings') or [])

        item = {
            'idx': int(meta.get('idx') or 0),
            'rule_id': str(meta.get('rule_id') or ''),
            'listen': str(meta.get('listen') or ''),
            'protocol': str(meta.get('protocol') or 'tcp+udp'),
            'disabled': bool(meta.get('disabled')),
            'ok': ok_val,
            'targets': list(meta.get('targets') or []),
            'checked_targets': list(meta.get('probe_targets') or []),
            'results': per_target,
            'unreachable': unreachable,
            'warnings': list(meta.get('warnings') or []),
        }
        if meta.get('port_occupied'):
            item['port_occupied'] = list(meta.get('port_occupied') or [])
        rules_out.append(item)

    deps = {
        'ping': bool(shutil.which('ping') or shutil.which('ping6')),
        'ss': bool(shutil.which('ss')),
        'iptables': _iptables_available(),
        'sysctl': bool(shutil.which('sysctl')),
    }

    sysctl_snapshot: Dict[str, Any] = {}
    for k, p in (
        ('net.core.somaxconn', '/proc/sys/net/core/somaxconn'),
        ('net.core.rmem_max', '/proc/sys/net/core/rmem_max'),
        ('net.core.wmem_max', '/proc/sys/net/core/wmem_max'),
        ('net.core.netdev_max_backlog', '/proc/sys/net/core/netdev_max_backlog'),
    ):
        v = _netprobe_read_proc_int(p)
        if v is not None:
            sysctl_snapshot[k] = v
    pr = _netprobe_read_port_range('/proc/sys/net/ipv4/ip_local_port_range')
    if pr is not None:
        sysctl_snapshot['net.ipv4.ip_local_port_range'] = [int(pr[0]), int(pr[1])]

    perf_hints: List[str] = []
    somaxconn = int(sysctl_snapshot.get('net.core.somaxconn') or 0)
    if active_rules >= 32 and 0 < somaxconn < 1024:
        perf_hints.append('规则较多且 somaxconn 偏低，建议提升 net.core.somaxconn（例如 >= 2048）')
    if udp_rules >= 8:
        rmem_max = int(sysctl_snapshot.get('net.core.rmem_max') or 0)
        wmem_max = int(sysctl_snapshot.get('net.core.wmem_max') or 0)
        if 0 < rmem_max < 4 * 1024 * 1024:
            perf_hints.append('UDP 规则较多，建议提高 net.core.rmem_max（例如 >= 4MB）')
        if 0 < wmem_max < 4 * 1024 * 1024:
            perf_hints.append('UDP 规则较多，建议提高 net.core.wmem_max（例如 >= 4MB）')
    if pr is not None and len(global_targets) >= 120:
        span = int(pr[1]) - int(pr[0])
        if span < 20000:
            perf_hints.append('并发探测目标较多且本机临时端口范围较窄，建议扩大 net.ipv4.ip_local_port_range')

    return {
        'ok': True,
        'mode': 'rules',
        'probe_mode': 'tcping',
        'tcp_port': default_port,
        'timeout': timeout_f,
        'deps': deps,
        'sysctl': sysctl_snapshot,
        'perf_hints': perf_hints[:8],
        'summary': {
            'rules_total': len(rules_out),
            'targets_total': len(global_targets),
            'rules_unreachable': int(unreachable_rules),
            'targets_unreachable': int(unreachable_targets_total),
            'warnings': int(warning_total),
        },
        'targets': global_targets,
        'target_results': probe_results,
        'rules': rules_out,
    }


@app.post('/api/v1/netprobe')
def api_netprobe(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    """Batch network probe from this node."""
    mode = str(payload.get('mode') or 'ping').strip().lower()
    default_port = _netprobe_default_port(payload.get('tcp_port'))
    timeout_f = _netprobe_timeout(payload.get('timeout'))

    if mode == 'rules':
        return _netprobe_rules(payload, default_port, timeout_f)

    if mode not in ('ping', 'tcping'):
        mode = 'ping'
    targets = _netprobe_clean_targets(payload.get('targets') or [], 50)
    if not targets:
        return {'ok': False, 'error': 'targets_empty'}

    results = _netprobe_run_targets(mode, targets, default_port, timeout_f)
    return {'ok': True, 'mode': mode, 'tcp_port': default_port, 'timeout': timeout_f, 'results': results}


@app.post('/api/v1/netprobe/trace')
def api_netprobe_trace(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    raw_target = _netprobe_trace_clean_target(payload.get('target'))
    if not raw_target:
        return {'ok': False, 'error': 'target_empty'}

    target_host = _netprobe_trace_extract_host(raw_target)
    if not target_host:
        return {'ok': False, 'error': 'invalid_target'}

    max_hops = _netprobe_trace_max_hops(payload.get('max_hops'))
    timeout_f = _netprobe_trace_timeout(payload.get('timeout'))
    probes = _netprobe_trace_probes(payload.get('probes'))
    return _netprobe_trace(target_host, max_hops, timeout_f, probes)




def _build_stats_snapshot() -> Dict[str, Any]:
    """规则统计 + 连通探测。

    旧版本逐条、逐目标串行探测，规则多时很容易让面板的 /stats 调用超时。
    这里做了：
    - 全部目标并发探测
    - 短缓存复用探测结果
    - 按协议选择探测方式（TCP/UDP）

    NOTE: 该函数同时被 /api/v1/stats 与面板 push-report 复用。
    """
    full = _load_full_pool()
    eps = full.get('endpoints') or []

    # 收集每条规则要渲染的 health entries（label/key/probe），同时汇总全局需要探测的任务
    per_rule_entries: List[List[Dict[str, Any]]] = []
    all_probe_tasks: List[Dict[str, str]] = []
    all_probe_set: set[str] = set()
    for e in eps:
        # Intranet tunnel rules are handled by agent (not realm).
        # Skip probing the inner LAN remotes here; we will expose a deterministic "handshake" health entry later.
        ex = e.get('extra_config') if isinstance(e, dict) and isinstance(e.get('extra_config'), dict) else {}
        if isinstance(ex, dict) and (ex.get('intranet_role') or ex.get('intranet_token')):
            per_rule_entries.append([])
            continue

        entries: List[Dict[str, Any]] = []
        if e.get('disabled'):
            # 规则暂停：无需探测，但仍保证面板有可渲染内容
            entries.append({'key': '—', 'label': '—', 'message': '规则已暂停'})
            per_rule_entries.append(entries)
            continue

        pset = _netprobe_proto_set(e.get('protocol'))
        if 'tcp' in pset:
            default_probe = 'tcp'
        elif 'udp' in pset:
            default_probe = 'udp'
        else:
            default_probe = 'none'

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
                entries.append({'key': r, 'label': r, 'probe': default_probe})
                if default_probe in ('tcp', 'udp'):
                    probe_id = f"{default_probe}|{r}"
                    if probe_id not in all_probe_set:
                        all_probe_set.add(probe_id)
                        all_probe_tasks.append({'probe': default_probe, 'key': r})

        # WSS 规则补充探测项（LISTEN 本地端口）
        for extra in _wss_probe_entries(e):
            k = str(extra.get('key') or '').strip()
            if not k:
                continue
            label = str(extra.get('label') or k).strip() or k
            probe_mode = str(extra.get('probe') or 'tcp').strip().lower() or 'tcp'
            if probe_mode not in ('tcp', 'udp'):
                probe_mode = 'tcp'
            entries.append({'key': k, 'label': label, 'probe': probe_mode})
            probe_id = f"{probe_mode}|{k}"
            if probe_id not in all_probe_set:
                all_probe_set.add(probe_id)
                all_probe_tasks.append({'probe': probe_mode, 'key': k})

        per_rule_entries.append(entries)

    # 并发探测所有目标（总耗时约等于最慢目标的超时）
    probe_results: Dict[str, Dict[str, Any]] = {}
    if all_probe_tasks:
        max_workers = max(4, min(PROBE_MAX_WORKERS, len(all_probe_tasks)))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            fut_map = {}
            for task in all_probe_tasks:
                mode = str(task.get('probe') or 'tcp').strip().lower() or 'tcp'
                key = str(task.get('key') or '').strip()
                rid = f"{mode}|{key}"
                # key 可能是 "—" 或格式不合法，先做保护
                try:
                    host, port = _split_hostport(key)
                except Exception:
                    probe_results[rid] = {'ok': None, 'message': '目标格式无效'}
                    continue
                if mode == 'udp':
                    fut = ex.submit(_udp_probe_detail, host, port, PROBE_TIMEOUT)
                else:
                    fut = ex.submit(_tcp_probe_detail, host, port, PROBE_TIMEOUT)
                fut_map[fut] = rid

            for fut in as_completed(fut_map):
                rid = fut_map[fut]
                try:
                    payload = fut.result(timeout=PROBE_TIMEOUT * max(1, PROBE_RETRIES) + 0.6)
                    if not isinstance(payload, dict):
                        probe_results[rid] = {'ok': None, 'message': '探测返回异常'}
                    else:
                        probe_results[rid] = payload
                except Exception as exc:
                    probe_results[rid] = {'ok': None, 'message': f'探测异常: {exc}'}

    # 每个 remote 的历史统计（可用率/错误率/连续失败/平滑延迟）
    probe_stats_map: Dict[str, Dict[str, Any]] = {}
    probe_remotes: Dict[str, Dict[str, Any]] = {}
    for task in all_probe_tasks:
        mode = str(task.get('probe') or 'tcp').strip().lower() or 'tcp'
        key = str(task.get('key') or '').strip()
        rid = f"{mode}|{key}"

        hist: Dict[str, Any] = {}
        if mode == 'udp':
            try:
                h, p = _split_hostport(key)
                hist = _probe_history_snapshot(_udp_probe_hist_key(h, p))
            except Exception:
                hist = {}
        else:
            hist = _probe_history_snapshot(key)
        if hist:
            probe_stats_map[rid] = hist

        item: Dict[str, Any] = {'target': key}
        res = probe_results.get(rid)
        if isinstance(res, dict):
            if res.get('ok') is None:
                item['ok'] = None
                if res.get('message'):
                    item['message'] = str(res.get('message'))
            else:
                item['ok'] = bool(res.get('ok'))
                if res.get('latency_ms') is not None:
                    item['latency_ms'] = res.get('latency_ms')
                if res.get('error'):
                    item['error'] = str(res.get('error'))
        if hist:
            item.update(hist)
        # Adaptive LB only consumes TCP remotes keyed by "host:port".
        if mode == 'tcp':
            probe_remotes[key] = item

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

    # Traffic cap (per rule/listen port): once cumulative bytes reach limit,
    # block new packets on INPUT for that listen port.
    traffic_limit_status, traffic_limit_warn = _traffic_limit_status_from_pool(full, conn_traffic_map)

    # 组装规则统计
    def _attach_probe_meta(dst: Dict[str, Any], rid: str) -> None:
        meta = probe_stats_map.get(rid)
        if not meta:
            return
        for mk in (
            'samples',
            'successes',
            'failures',
            'availability',
            'error_rate',
            'consecutive_failures',
            'latency_ema_ms',
            'last_latency_ms',
            'last_ok',
            'last_error',
            'last_probe_at_ms',
            'down',
        ):
            if mk in meta:
                dst[mk] = meta.get(mk)

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
        tl = traffic_limit_status.get(port) or {}
        traffic_limit_bytes = int(tl.get('limit_bytes') or 0)
        traffic_used_bytes = int(tl.get('used_bytes') or (rx_bytes + tx_bytes if traffic_limit_bytes > 0 else 0))
        traffic_limit_blocked = bool(tl.get('blocked'))

        health: List[Dict[str, Any]] = []
        entries = per_rule_entries[idx] if idx < len(per_rule_entries) else []

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
                for mk in (
                    'latency_ms',
                    'dial_mode',
                    'reconnects',
                    'loss_pct',
                    'jitter_ms',
                    'token_count',
                    'ping_sent',
                    'pong_recv',
                ):
                    if hh.get(mk) is not None:
                        item[mk] = hh.get(mk)
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
                'traffic_limit_bytes': traffic_limit_bytes,
                'traffic_used_bytes': traffic_used_bytes,
                'traffic_limit_blocked': traffic_limit_blocked,
                'traffic_limited': traffic_limit_blocked,
                'health': health,
            })
            continue

        for it in entries:
            label = it.get('label', '—')
            key = it.get('key', label)
            probe_mode = str(it.get('probe') or '').strip().lower()
            # 特殊占位项（暂停 / 无目标等）
            if it.get('message'):
                health.append({'target': label, 'ok': None, 'message': it['message']})
                continue

            if probe_mode not in ('tcp', 'udp'):
                # 兼容旧数据：当 entry 缺少 probe 时，按规则协议推断一次。
                pset = _netprobe_proto_set(e.get('protocol'))
                if 'tcp' in pset:
                    probe_mode = 'tcp'
                elif 'udp' in pset:
                    probe_mode = 'udp'
                else:
                    health.append({'target': label, 'ok': None, 'message': '协议不支持探测'})
                    continue

            rid = f"{probe_mode}|{key}"
            res = probe_results.get(rid)
            if not res:
                item: Dict[str, Any] = {'target': label, 'ok': None, 'message': '暂无检测数据'}
                _attach_probe_meta(item, rid)
                health.append(item)
                continue
            if res.get('ok') is None:
                item = {'target': label, 'ok': None, 'message': res.get('message', '不可检测')}
                _attach_probe_meta(item, rid)
                health.append(item)
                continue
            payload: Dict[str, Any] = {'target': label, 'ok': bool(res.get('ok'))}
            if res.get('latency_ms') is not None:
                payload['latency_ms'] = res.get('latency_ms')
            # 离线原因（面板可展示）
            if payload['ok'] is False and res.get('error'):
                payload['error'] = res.get('error')
            _attach_probe_meta(payload, rid)
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
            'traffic_limit_bytes': traffic_limit_bytes,
            'traffic_used_bytes': traffic_used_bytes,
            'traffic_limit_blocked': traffic_limit_blocked,
            'traffic_limited': traffic_limit_blocked,
            'health': health,
        })

    resp: Dict[str, Any] = {'ok': True, 'rules': rules, 'probe_remotes': probe_remotes}
    warnings: List[str] = []
    if ss_err:
        warnings.append(str(ss_err))
    if traffic_limit_warn:
        warnings.append(str(traffic_limit_warn))
    if warnings:
        resp['warning'] = '; '.join(dict.fromkeys([w for w in warnings if str(w).strip()]))
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

    # 4) clear traffic-cap drop chain (best-effort)
    try:
        warn = _sync_traffic_limit_firewall({}, has_limits=False)
        out["traffic_limit"] = {"cleared": warn is None, "warning": str(warn or "")}
    except Exception:
        out["traffic_limit"] = {"cleared": False}

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


# =========================
# Website Management: sites / SSL / file manager
# =========================

_WEBSITE_ROOT_BASES_CACHE: Optional[List[Path]] = None


def _website_root_bases() -> List[Path]:
    global _WEBSITE_ROOT_BASES_CACHE
    if _WEBSITE_ROOT_BASES_CACHE is not None:
        return _WEBSITE_ROOT_BASES_CACHE
    raw = (
        os.getenv("REALM_AGENT_WEBSITE_ROOT_BASES")
        or os.getenv("REALM_AGENT_WEBSITE_ROOT_BASE")
        or "/www"
    )
    bases: List[Path] = []
    for item in str(raw).split(","):
        p = (item or "").strip()
        if not p:
            continue
        try:
            bases.append(Path(p).expanduser().resolve())
        except Exception:
            continue
    if not bases:
        bases = [Path("/www").resolve()]
    _WEBSITE_ROOT_BASES_CACHE = bases
    return bases


def _extra_root_bases(extra: Optional[List[str]] = None) -> List[Path]:
    out: List[Path] = []
    if not extra:
        return out
    for item in extra:
        p = (item or "").strip()
        if not p:
            continue
        try:
            out.append(Path(p).expanduser().resolve())
        except Exception:
            continue
    return out


def _is_subpath(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except Exception:
        return False


def _validate_root(root: str, extra_bases: Optional[List[str]] = None) -> Path:
    root = (root or "").strip()
    if not root:
        raise HTTPException(status_code=400, detail="root 不能为空")
    p = Path(root).expanduser()
    if not p.is_absolute():
        raise HTTPException(status_code=400, detail="root 必须是绝对路径")
    resolved = p.resolve()
    allowed = _website_root_bases() + _extra_root_bases(extra_bases)
    if not any(_is_subpath(resolved, base) or resolved == base for base in allowed):
        raise HTTPException(status_code=403, detail="root 不在允许范围内")
    return resolved


def _safe_join(root: Path, subpath: str) -> Path:
    rel = (subpath or "").strip().lstrip("/")
    target = (root / rel).resolve()
    if not _is_subpath(target, root) and target != root:
        raise HTTPException(status_code=400, detail="非法路径")
    return target


def _run_cmd(
    cmd: List[str],
    timeout: Optional[int] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, f"命令超时（{timeout}s）"
    except Exception as exc:
        return 1, str(exc)
    out = (r.stdout or "") + (r.stderr or "")
    return int(r.returncode or 0), out.strip()


def _detect_pkg_mgr() -> Optional[str]:
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("yum"):
        return "yum"
    if shutil.which("apk"):
        return "apk"
    return None


_APT_UPDATED = False


def _pkg_install(packages: List[str]) -> Tuple[bool, str]:
    mgr = _detect_pkg_mgr()
    if not mgr:
        return False, "未检测到包管理器"
    if not packages:
        return True, ""
    env = os.environ.copy()
    if mgr == "apt":
        env.setdefault("DEBIAN_FRONTEND", "noninteractive")
        env.setdefault("APT_LISTCHANGES_FRONTEND", "none")
        global _APT_UPDATED
        if not _APT_UPDATED:
            code, out = _run_cmd(
                ["apt-get", "update", "-y", "-o", "Acquire::Retries=3", "-o", "Dpkg::Lock::Timeout=30"],
                timeout=180,
                env=env,
            )
            if code != 0:
                return False, out or "apt-get update 失败"
            _APT_UPDATED = True
        cmd = [
            "apt-get",
            "install",
            "-y",
            "--no-install-recommends",
            "-o",
            "Dpkg::Lock::Timeout=30",
            *packages,
        ]
    elif mgr == "dnf":
        cmd = ["dnf", "install", "-y", *packages]
    elif mgr == "yum":
        cmd = ["yum", "install", "-y", *packages]
    else:
        cmd = ["apk", "add", "--no-cache", *packages]
    code, out = _run_cmd(cmd, timeout=600, env=env)
    return code == 0, out


def _pkg_is_installed(mgr: str, pkg: str) -> bool:
    if not pkg:
        return False
    if mgr == "apt":
        code, _ = _run_cmd(["dpkg", "-s", pkg], timeout=10)
        return code == 0
    if mgr in ("yum", "dnf"):
        code, _ = _run_cmd(["rpm", "-q", pkg], timeout=10)
        return code == 0
    if mgr == "apk":
        code, _ = _run_cmd(["apk", "info", "-e", pkg], timeout=10)
        return code == 0
    return False


def _pkg_remove(packages: List[str]) -> Tuple[bool, str]:
    mgr = _detect_pkg_mgr()
    if not mgr:
        return False, "未检测到包管理器"
    if not packages:
        return True, ""
    installed = [p for p in packages if _pkg_is_installed(mgr, p)]
    if not installed:
        return True, ""
    env = os.environ.copy()
    if mgr == "apt":
        env.setdefault("DEBIAN_FRONTEND", "noninteractive")
        env.setdefault("APT_LISTCHANGES_FRONTEND", "none")
        cmd = ["apt-get", "purge", "-y", *installed]
    elif mgr == "dnf":
        cmd = ["dnf", "remove", "-y", *installed]
    elif mgr == "yum":
        cmd = ["yum", "remove", "-y", *installed]
    else:
        cmd = ["apk", "del", *installed]
    code, out = _run_cmd(cmd, timeout=300, env=env)
    return code == 0, out


def _start_service(name: str) -> None:
    for cmd in (["systemctl", "enable", "--now", name], ["service", name, "start"], ["rc-service", name, "start"]):
        if shutil.which(cmd[0]) is None:
            continue
        try:
            subprocess.run(cmd, capture_output=True, text=True)
            return
        except Exception:
            continue


def _nginx_main_conf() -> Tuple[Path, Path]:
    """Return (conf_path, prefix) for nginx."""
    conf_path = Path("/etc/nginx/nginx.conf")
    prefix = Path("/etc/nginx")
    try:
        code, out = _run_cmd(["nginx", "-V"], timeout=6)
        if out:
            # nginx -V outputs to stderr; _run_cmd captures both.
            m = re.search(r"--conf-path=([^\\s]+)", out)
            if m:
                conf_path = Path(m.group(1).strip())
            m2 = re.search(r"--prefix=([^\\s]+)", out)
            if m2:
                prefix = Path(m2.group(1).strip())
    except Exception:
        pass
    if not conf_path.is_absolute():
        conf_path = (prefix / conf_path).resolve()
    return conf_path, prefix


def _parse_nginx_include_dirs(conf_path: Path, prefix: Path) -> List[Path]:
    dirs: List[Path] = []
    try:
        text = conf_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return dirs
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"include\\s+([^;]+);", line)
        if not m:
            continue
        pat = m.group(1).strip()
        if "$" in pat:
            # skip variables
            continue
        # normalize relative paths
        if not pat.startswith("/"):
            base = prefix if prefix else conf_path.parent
            pat = str((base / pat).resolve())
        # if wildcard, take parent dir
        if "*" in pat:
            p = Path(pat)
            dirs.append(p.parent)
        else:
            p = Path(pat)
            if p.is_dir():
                dirs.append(p)
    return dirs


def _nginx_conf_locations() -> Tuple[Path, Optional[Path]]:
    # explicit overrides
    override_conf = os.getenv("REALM_NGINX_CONF_DIR")
    override_enabled = os.getenv("REALM_NGINX_ENABLED_DIR")
    if override_conf:
        conf_dir = Path(override_conf).expanduser().resolve()
        enabled_dir = Path(override_enabled).expanduser().resolve() if override_enabled else None
        return conf_dir, enabled_dir

    sites_avail = Path("/etc/nginx/sites-available")
    sites_enabled = Path("/etc/nginx/sites-enabled")
    if sites_avail.is_dir():
        return sites_avail, sites_enabled if sites_enabled.is_dir() else None

    # parse nginx.conf includes
    conf_path, prefix = _nginx_main_conf()
    dirs = _parse_nginx_include_dirs(conf_path, prefix)
    # prefer sites-enabled/conf.d/vhost
    preferred = [d for d in dirs if d.name in ("sites-enabled", "conf.d", "vhost")]
    if preferred:
        conf_dir = preferred[0]
        conf_dir.mkdir(parents=True, exist_ok=True)
        return conf_dir, None
    if dirs:
        conf_dir = dirs[0]
        conf_dir.mkdir(parents=True, exist_ok=True)
        return conf_dir, None

    # fallback
    fallback = Path("/etc/nginx/conf.d")
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback, None


def _slugify(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name or "").strip("-")
    return safe or "site"


def _existing_cert_paths(main_domain: str) -> Optional[Tuple[str, str]]:
    """Return (fullchain, privkey) if certificate files already exist.

    Used to preserve HTTPS config when re-applying nginx conf (e.g. site edit).
    """
    d = str(main_domain or "").strip()
    if not d:
        return None
    safe = _slugify(d)
    cert_dir = Path("/etc/ssl/nexus") / safe
    fullchain_path = cert_dir / "fullchain.pem"
    key_path = cert_dir / "privkey.pem"
    try:
        if fullchain_path.exists() and key_path.exists():
            return str(fullchain_path), str(key_path)
    except Exception:
        return None
    return None


def _default_webroot(main_domain: str, extra_bases: Optional[List[str]] = None) -> str:
    """Choose a sensible default webroot under the allowed base paths.

    For reverse_proxy sites, this webroot is primarily used for ACME HTTP-01
    challenge files.
    """
    d = str(main_domain or "").strip() or "site"
    # Prefer the first extra base from payload, else the global bases.
    bases = _extra_root_bases(extra_bases)
    base = bases[0] if bases else (_website_root_bases()[0] if _website_root_bases() else Path("/www").resolve())
    # Keep it consistent with panel defaults: <base>/wwwroot/<domain>
    return str((base / "wwwroot" / d).absolute())


def _ensure_acme_webroot(root_path: str, extra_bases: Optional[List[str]] = None) -> Tuple[Optional[Path], str]:
    """Validate and ensure ACME challenge directory exists.

    Returns (resolved_root_path, error_message).
    """
    try:
        root_valid = _validate_root(root_path, extra_bases)
        # Ensure webroot exists
        root_valid.mkdir(parents=True, exist_ok=True)
        # Ensure ACME dir exists
        acme_dir = root_valid / ".well-known" / "acme-challenge"
        acme_dir.mkdir(parents=True, exist_ok=True)
        return root_valid, ""
    except Exception as exc:
        return None, str(exc)


def _normalize_proxy_pass_target(proxy_target: str) -> str:
    """Normalize user-supplied reverse proxy target for nginx `proxy_pass`.

    - Accepts full URLs (http://..., https://...).
    - Accepts plain host:port and prefixes http://.
    - Accepts unix socket via `unix:/path.sock` (or `unix:/path.sock:`).
    """
    t = (proxy_target or "").strip()
    if not t:
        return ""
    if t.startswith("unix:"):
        sock = t[len("unix:") :].strip()
        if not sock.startswith("/"):
            sock = "/" + sock
        if not sock.endswith(":"):
            sock = sock + ":"
        return f"http://unix:{sock}"
    if "://" in t:
        return t
    return f"http://{t}"


def _detect_php_fpm_sock() -> Optional[str]:
    candidates = [
        "/run/php/php-fpm.sock",
        "/run/php/php8.3-fpm.sock",
        "/run/php/php8.2-fpm.sock",
        "/run/php/php8.1-fpm.sock",
        "/run/php/php8.0-fpm.sock",
        "/run/php/php7.4-fpm.sock",
        "/var/run/php-fpm.sock",
        "/run/php-fpm/www.sock",
        "/var/run/php/php-fpm.sock",
    ]
    for p in candidates:
        if Path(p).exists():
            return p
    return None


def _gzip_snippet() -> str:
    return (
        "  gzip on;\n"
        "  gzip_comp_level 5;\n"
        "  gzip_min_length 1024;\n"
        "  gzip_vary on;\n"
        "  gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;\n"
    )


def _nexus_header_snippet(domain: str) -> str:
    d = (domain or "").strip()
    if not d:
        return ""
    return f"  add_header X-Nexus-Site {d} always;\n"

def _render_custom_template(template: str, ctx: Dict[str, str]) -> str:
    out = template or ""
    for k, v in ctx.items():
        out = out.replace(f"{{{{{k}}}}}", v)
    return out


def _normalize_proxy_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if t.startswith("unix:"):
        return t
    if "://" in t:
        return t
    # default to http for bare host:port
    return f"http://{t}"


def _payload_root_bases(payload: Dict[str, Any]) -> List[str]:
    raw = None
    if isinstance(payload, dict):
        raw = payload.get("root_bases")
        if raw is None:
            raw = payload.get("root_base")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(x) for x in raw if str(x or "").strip()]
    return []


def _service_active(name: str) -> Tuple[Optional[bool], str]:
    for cmd in (["systemctl", "is-active", name], ["service", name, "status"], ["rc-service", name, "status"]):
        if shutil.which(cmd[0]) is None:
            continue
        code, out = _run_cmd(cmd, timeout=6)
        if code == 0:
            return True, out
        if cmd[0] == "systemctl":
            # systemctl returns non-zero for inactive
            return False, out
    return None, "status_unknown"


def _http_probe(
    host: str,
    port: int,
    host_header: str,
    use_tls: bool,
    timeout: float = 4.0,
) -> Tuple[bool, int, int, str, str]:
    start = time.time()
    status = 0
    try:
        if use_tls:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("HEAD", "/", headers={"Host": host_header, "User-Agent": "Nexus-Health"})
        resp = conn.getresponse()
        status = int(resp.status or 0)
        header_site = str(resp.getheader("X-Nexus-Site") or "").strip()
        try:
            resp.read(1)
        except Exception:
            pass
        conn.close()
        latency = int((time.time() - start) * 1000)
        ok = (200 <= status < 400) or status == 405
        return ok, status, latency, "", header_site
    except Exception as exc:
        latency = int((time.time() - start) * 1000)
        return False, status, latency, str(exc), ""


def _apply_nginx_conf(name: str, content: str) -> Tuple[bool, str, str]:
    """Write nginx conf and reload with rollback on failure.

    Returns (ok, conf_path, message)
    """
    conf_dir, enabled_dir = _nginx_conf_locations()
    conf_dir.mkdir(parents=True, exist_ok=True)
    conf_name = f"nexus-{_slugify(name)}.conf"
    conf_path = conf_dir / conf_name

    old_exists = conf_path.exists()
    old_content = ""
    if old_exists:
        try:
            old_content = conf_path.read_text(encoding="utf-8")
        except Exception:
            old_content = ""

    # atomic write
    tmp_path = conf_path.with_suffix(conf_path.suffix + ".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    try:
        tmp_path.replace(conf_path)
    except Exception:
        # fallback: direct write
        conf_path.write_text(content, encoding="utf-8")
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass

    if enabled_dir:
        enabled_dir.mkdir(parents=True, exist_ok=True)
        link = enabled_dir / conf_name
        if not link.exists():
            try:
                link.symlink_to(conf_path)
            except Exception:
                pass

    ok, out = _nginx_reload()
    if ok:
        return True, str(conf_path), out

    # rollback
    try:
        if old_exists:
            conf_path.write_text(old_content, encoding="utf-8")
        else:
            if conf_path.exists() or conf_path.is_symlink():
                conf_path.unlink()
    except Exception:
        pass
    try:
        _nginx_reload()
    except Exception:
        pass
    return False, str(conf_path), out or "nginx reload 失败"


def _render_nginx_conf(
    site_type: str,
    domains: List[str],
    root_path: str,
    proxy_target: str,
    php_sock: Optional[str] = None,
    https_redirect: bool = False,
    gzip_enabled: bool = True,
    cert_paths: Optional[Tuple[str, str]] = None,
) -> str:
    server_name = " ".join(domains)
    nexus_header = _nexus_header_snippet(domains[0] if domains else "")
    gzip = _gzip_snippet() if gzip_enabled else ""
    has_ssl = bool(cert_paths and cert_paths[0] and cert_paths[1])
    ssl_cert = cert_paths[0] if cert_paths else ""
    ssl_key = cert_paths[1] if cert_paths else ""
    # NOTE: do NOT use a server-level `return 301` for http->https redirect.
    # Otherwise ACME HTTP-01 challenge may be redirected and fail when cert is expired.
    redirect_https = bool(https_redirect and has_ssl)

    # Always try to keep ACME challenge reachable (both on :80 and :443).
    # acme.sh webroot mode writes challenge files under:
    #   <root_path>/.well-known/acme-challenge/<token>
    acme_loc = ""
    if str(root_path or "").strip():
        acme_loc = (
            "  # ACME HTTP-01 challenge\n"
            "  location ^~ /.well-known/acme-challenge/ {\n"
            f"    root {root_path};\n"
            "    default_type \"text/plain\";\n"
            "    try_files $uri =404;\n"
            "  }\n"
        )
    if site_type == "reverse_proxy":
        pt = _normalize_proxy_pass_target(proxy_target)
        http_locations = ""
        if redirect_https:
            http_locations = (
                f"{acme_loc}"
                "  location ^~ / {\n"
                "    return 301 https://$host$request_uri;\n"
                "  }\n"
            )
        else:
            http_locations = (
                f"{acme_loc}"
                "  location / {\n"
                f"    proxy_pass {pt};\n"
                "    proxy_set_header Host $host;\n"
                "    proxy_set_header X-Real-IP $remote_addr;\n"
                "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                "    proxy_set_header X-Forwarded-Proto $scheme;\n"
                "  }\n"
            )

        http_block = (
            "server {\n"
            "  listen 80;\n"
            f"  server_name {server_name};\n"
            f"{nexus_header}"
            f"{gzip}"
            f"{http_locations}"
            "}\n"
        )
        if has_ssl:
            https_block = (
                "server {\n"
                "  listen 443 ssl http2;\n"
                f"  server_name {server_name};\n"
                f"{nexus_header}"
                f"  ssl_certificate {ssl_cert};\n"
                f"  ssl_certificate_key {ssl_key};\n"
                f"{gzip}"
                f"{acme_loc}"
                "  location / {\n"
                f"    proxy_pass {pt};\n"
                "    proxy_set_header Host $host;\n"
                "    proxy_set_header X-Real-IP $remote_addr;\n"
                "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                "    proxy_set_header X-Forwarded-Proto $scheme;\n"
                "  }\n"
                "}\n"
            )
            return http_block + "\n" + https_block
        return http_block
    if site_type == "php":
        sock = php_sock or "/run/php/php-fpm.sock"
        if redirect_https:
            http_block = (
                "server {\n"
                "  listen 80;\n"
                f"  server_name {server_name};\n"
                f"{nexus_header}"
                f"  root {root_path};\n"
                "  index index.php index.html index.htm;\n"
                f"{gzip}"
                f"{acme_loc}"
                "  location ^~ / {\n"
                "    return 301 https://$host$request_uri;\n"
                "  }\n"
                "}\n"
            )
        else:
            http_block = (
                "server {\n"
                "  listen 80;\n"
                f"  server_name {server_name};\n"
                f"{nexus_header}"
                f"  root {root_path};\n"
                "  index index.php index.html index.htm;\n"
                f"{gzip}"
                f"{acme_loc}"
                "  location / {\n"
                "    try_files $uri $uri/ /index.php?$args;\n"
                "  }\n"
                "  location ~ \\.php$ {\n"
                "    include fastcgi_params;\n"
                "    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n"
                f"    fastcgi_pass unix:{sock};\n"
                "  }\n"
                "}\n"
            )
        if has_ssl:
            https_block = (
                "server {\n"
                "  listen 443 ssl http2;\n"
                f"  server_name {server_name};\n"
                f"{nexus_header}"
                f"  root {root_path};\n"
                f"  ssl_certificate {ssl_cert};\n"
                f"  ssl_certificate_key {ssl_key};\n"
                "  index index.php index.html index.htm;\n"
                f"{gzip}"
                f"{acme_loc}"
                "  location / {\n"
                "    try_files $uri $uri/ /index.php?$args;\n"
                "  }\n"
                "  location ~ \\.php$ {\n"
                "    include fastcgi_params;\n"
                "    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n"
                f"    fastcgi_pass unix:{sock};\n"
                "  }\n"
                "}\n"
            )
            return http_block + "\n" + https_block
        return http_block
    # default static
    if redirect_https:
        http_block = (
            "server {\n"
            "  listen 80;\n"
            f"  server_name {server_name};\n"
            f"{nexus_header}"
            f"  root {root_path};\n"
            "  index index.html index.htm;\n"
            f"{gzip}"
            f"{acme_loc}"
            "  location ^~ / {\n"
            "    return 301 https://$host$request_uri;\n"
            "  }\n"
            "}\n"
        )
    else:
        http_block = (
            "server {\n"
            "  listen 80;\n"
            f"  server_name {server_name};\n"
            f"{nexus_header}"
            f"  root {root_path};\n"
            "  index index.html index.htm;\n"
            f"{gzip}"
            f"{acme_loc}"
            "  location / {\n"
            "    try_files $uri $uri/ =404;\n"
            "  }\n"
            "}\n"
        )
    if has_ssl:
        https_block = (
            "server {\n"
            "  listen 443 ssl http2;\n"
            f"  server_name {server_name};\n"
            f"{nexus_header}"
            f"  root {root_path};\n"
            f"  ssl_certificate {ssl_cert};\n"
            f"  ssl_certificate_key {ssl_key};\n"
            "  index index.html index.htm;\n"
            f"{gzip}"
            f"{acme_loc}"
            "  location / {\n"
            "    try_files $uri $uri/ =404;\n"
            "  }\n"
            "}\n"
        )
        return http_block + "\n" + https_block
    return http_block


def _write_nginx_conf(name: str, content: str) -> Path:
    conf_dir, enabled_dir = _nginx_conf_locations()
    conf_dir.mkdir(parents=True, exist_ok=True)
    conf_name = f"nexus-{_slugify(name)}.conf"
    conf_path = conf_dir / conf_name
    conf_path.write_text(content, encoding="utf-8")
    if enabled_dir:
        enabled_dir.mkdir(parents=True, exist_ok=True)
        link = enabled_dir / conf_name
        if not link.exists():
            try:
                link.symlink_to(conf_path)
            except Exception:
                pass
    return conf_path


def _nginx_reload() -> Tuple[bool, str]:
    # nginx -t first
    code, out = _run_cmd(["nginx", "-t"], timeout=15)
    if code != 0:
        return False, out or "nginx -t 失败"
    # reload
    for cmd in (["nginx", "-s", "reload"], ["systemctl", "reload", "nginx"], ["service", "nginx", "reload"]):
        if shutil.which(cmd[0]) is None:
            continue
        code, out = _run_cmd(cmd, timeout=20)
        if code == 0:
            return True, out
    # fallback: try start if reload failed (fresh install / service not running)
    for cmd in (["systemctl", "start", "nginx"], ["service", "nginx", "start"], ["nginx"]):
        if shutil.which(cmd[0]) is None:
            continue
        code, out = _run_cmd(cmd, timeout=20)
        if code == 0:
            return True, "nginx started"
    return False, "nginx reload 失败"


def _remove_nginx_conf_by_domain(domain: str) -> int:
    conf_dir, enabled_dir = _nginx_conf_locations()
    slug = _slugify(domain)
    conf_name = f"nexus-{slug}.conf"
    removed = 0
    for d in (conf_dir, enabled_dir):
        if not d:
            continue
        path = d / conf_name
        try:
            if path.exists() or path.is_symlink():
                path.unlink()
                removed += 1
        except Exception:
            pass
    return removed


def _nginx_conf_path(domain: str) -> Path:
    conf_dir, _ = _nginx_conf_locations()
    conf_name = f"nexus-{_slugify(domain)}.conf"
    return conf_dir / conf_name


def _remove_nginx_conf_with_rollback(domain: str) -> Tuple[bool, str]:
    conf_dir, enabled_dir = _nginx_conf_locations()
    conf_name = f"nexus-{_slugify(domain)}.conf"
    conf_path = conf_dir / conf_name
    link_path = enabled_dir / conf_name if enabled_dir else None

    old_content = ""
    old_exists = conf_path.exists()
    if old_exists:
        try:
            old_content = conf_path.read_text(encoding="utf-8")
        except Exception:
            old_content = ""

    link_existed = False
    if link_path and (link_path.exists() or link_path.is_symlink()):
        link_existed = True

    # remove
    for p in (link_path, conf_path):
        if not p:
            continue
        try:
            if p.exists() or p.is_symlink():
                p.unlink()
        except Exception:
            pass

    ok, out = _nginx_reload()
    if ok:
        return True, out or ""

    # rollback
    try:
        if old_exists:
            conf_path.write_text(old_content, encoding="utf-8")
        if link_path and link_existed and not link_path.exists():
            try:
                link_path.symlink_to(conf_path)
            except Exception:
                pass
    except Exception:
        pass
    try:
        _nginx_reload()
    except Exception:
        pass
    return False, out or "nginx reload 失败"


def _purge_nginx_confs() -> int:
    conf_dir, enabled_dir = _nginx_conf_locations()
    removed = 0
    for d in (conf_dir, enabled_dir):
        if not d or not d.exists():
            continue
        for p in d.glob("nexus-*.conf"):
            try:
                p.unlink()
                removed += 1
            except Exception:
                continue
    return removed


def _delete_site_root(root_path: str, extra_bases: Optional[List[str]] = None) -> Optional[str]:
    if not root_path:
        return "root_path 不能为空"
    try:
        root = _validate_root(root_path, extra_bases)
    except Exception as exc:
        return str(exc)
    for base in _website_root_bases():
        if root == base:
            return "禁止删除根基目录"
    try:
        if root.exists():
            shutil.rmtree(root)
    except Exception as exc:
        return str(exc)
    return None


def _find_acme_sh() -> Optional[str]:
    acme = shutil.which("acme.sh")
    if acme:
        return acme
    # Common install locations
    for p in (
        "/root/.acme.sh/acme.sh",
        "/usr/local/bin/acme.sh",
        "/usr/local/sbin/acme.sh",
        "/opt/acme.sh/acme.sh",
    ):
        if Path(p).exists():
            return p

    # If installed under a different user's HOME (rare), try to locate it.
    # This keeps the scan narrow and fast.
    try:
        home = str(Path.home())
        hp = Path(home) / ".acme.sh" / "acme.sh"
        if hp.exists():
            return str(hp)
    except Exception:
        pass

    try:
        for hp in Path("/home").glob("*/.acme.sh/acme.sh"):
            if hp.exists():
                return str(hp)
    except Exception:
        pass
    return None


def _install_acme_sh() -> Tuple[bool, str]:
    if _find_acme_sh():
        return True, ""

    # Ensure basic dependencies that acme.sh relies on
    if not shutil.which("openssl"):
        _pkg_install(["openssl"])  # best-effort

    curl = shutil.which("curl")
    if not curl:
        ok, out = _pkg_install(["curl"])
        if not ok:
            return False, out or "缺少 curl"
        curl = shutil.which("curl")
        if not curl:
            return False, "缺少 curl"

    # Run the official installer.
    # NOTE: it installs to $HOME/.acme.sh by default.
    env = os.environ.copy()
    if os.geteuid() == 0:
        env.setdefault("HOME", "/root")
    cmd = f"{curl} -fsSL https://get.acme.sh | sh"
    try:
        r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        return False, "acme.sh 安装超时"
    except Exception as exc:
        return False, str(exc)
    if r.returncode != 0:
        out = (r.stdout or "") + (r.stderr or "")
        return False, out.strip() or "acme.sh 安装失败"

    # Best-effort: ensure it's callable from PATH (some environments rely on it)
    try:
        acme_path = _find_acme_sh()
        if acme_path and os.geteuid() == 0:
            dst = Path("/usr/local/bin/acme.sh")
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists():
                try:
                    dst.symlink_to(Path(acme_path))
                except Exception:
                    shutil.copy2(acme_path, str(dst))
                    os.chmod(str(dst), 0o755)
    except Exception:
        pass
    return True, ""



def _acme_env() -> Dict[str, str]:
    """Return environment for running acme.sh.

    systemd services sometimes run with HOME=/, which breaks acme.sh state location.
    """
    env = os.environ.copy()
    if os.geteuid() == 0:
        env.setdefault("HOME", "/root")
    return env


def _acme_home_dir(env: Optional[Dict[str, str]] = None) -> Path:
    e = env or _acme_env()
    home = (e.get("HOME") or "").strip() or str(Path.home())
    return Path(home) / ".acme.sh"


def _read_acme_account_email() -> Optional[str]:
    """Try to read existing ACCOUNT_EMAIL from acme.sh account.conf."""
    env = _acme_env()
    acme_home = _acme_home_dir(env)
    p = acme_home / "account.conf"
    try:
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"^ACCOUNT_EMAIL=['\"]?([^'\"\n]+)", txt, re.MULTILINE)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return None


def _acme_domain_server(domain: str) -> Optional[str]:
    """Try to detect the CA directory URL used by this domain from acme.sh domain conf."""
    d = (domain or "").strip()
    if not d:
        return None
    env = _acme_env()
    acme_home = _acme_home_dir(env)
    candidates = [
        acme_home / d / f"{d}.conf",
        acme_home / f"{d}_ecc" / f"{d}.conf",
    ]
    for p in candidates:
        try:
            if not p.exists():
                continue
            txt = p.read_text(encoding="utf-8", errors="ignore")
            # acme.sh stores CA directory URL in Le_API for many versions.
            m = re.search(r"^Le_API=['\"]?([^'\"\n]+)", txt, re.MULTILINE)
            if m:
                return m.group(1).strip()
            m = re.search(r"^Le_Server=['\"]?([^'\"\n]+)", txt, re.MULTILINE)
            if m:
                return m.group(1).strip()
        except Exception:
            continue
    return None


def _acme_server_for_issue() -> str:
    """Default ACME server for issuing new certs (configurable via env)."""
    s = (os.getenv("REALM_ACME_SERVER") or "").strip()
    return s or "letsencrypt"


def _acme_server_for_domain(domain: str) -> str:
    """Prefer the server stored by acme.sh for this domain; fallback to default."""
    stored = _acme_domain_server(domain)
    if stored:
        return stored
    return _acme_server_for_issue()


def _acme_email_for_domains(domains: List[str]) -> str:
    """Resolve ACME account email.

    Priority:
    1) REALM_ACME_EMAIL env
    2) existing acme.sh account.conf ACCOUNT_EMAIL
    3) fallback to admin@<primary-domain>
    """
    e = (os.getenv("REALM_ACME_EMAIL") or "").strip()
    if e:
        return e
    existing = _read_acme_account_email()
    if existing:
        return existing

    d0 = (str(domains[0]) if domains else "").strip()
    if d0.startswith("*."):
        d0 = d0[2:]
    # strip :port if accidentally present (example.com:80)
    if d0.startswith("[") and "]" in d0:
        d0 = d0[1 : d0.index("]")]
    elif d0.count(":") == 1:
        d0 = d0.split(":", 1)[0]
    if not d0:
        d0 = "example.com"
    return f"admin@{d0}"


def _acme_register_account(acme: str, server: str, email: str) -> Tuple[bool, str]:
    """Ensure ACME account is registered with an email (required by some CAs like ZeroSSL)."""
    env = _acme_env()
    cmd = [acme, "--register-account", "-m", email]
    if server:
        cmd += ["--server", server]
    code, out = _run_cmd(cmd, timeout=120, env=env)
    if code == 0:
        return True, out
    low = (out or "").lower()
    # Some acme.sh versions may return non-zero even if account already exists/registered.
    if "already" in low and "account" in low:
        return True, out
    if "account" in low and "registered" in low:
        return True, out
    return False, out


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(str(ip or "").strip())
    except Exception:
        return False
    return not (
        obj.is_private
        or obj.is_loopback
        or obj.is_link_local
        or obj.is_multicast
        or obj.is_reserved
        or obj.is_unspecified
    )


def _resolve_domain_ips(domain: str) -> List[str]:
    d = str(domain or "").strip()
    if not d:
        return []
    out: List[str] = []
    try:
        rows = socket.getaddrinfo(d, 80, type=socket.SOCK_STREAM)
    except Exception:
        rows = []
    for row in rows:
        try:
            ip = str((row[4] or [None])[0] or "").strip()
        except Exception:
            ip = ""
        if ip and ip not in out:
            out.append(ip)
    return out


def _acme_challenge_probe(domain: str, token: str, timeout: float = 4.5) -> Tuple[bool, int, str]:
    path = f"/.well-known/acme-challenge/{token}"
    try:
        conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=timeout)
        conn.request(
            "GET",
            path,
            headers={"Host": str(domain or ""), "User-Agent": "Nexus-ACME-Preflight"},
        )
        resp = conn.getresponse()
        code = int(resp.status or 0)
        raw = resp.read(4096)
        conn.close()
        body = raw.decode("utf-8", errors="ignore")
        if code == 200 and token in body:
            return True, code, ""
        short = (body or "").strip().replace("\r", " ").replace("\n", " ")
        if len(short) > 180:
            short = short[:180] + "..."
        return False, code, short
    except Exception as exc:
        return False, 0, str(exc)


def _acme_precheck_domains(domains: List[str], root_path: str) -> Tuple[bool, str, List[Dict[str, Any]]]:
    rp = str(root_path or "").strip()
    if not rp:
        return False, "ACME 预检失败：root_path 为空", []
    root = Path(rp)
    out: List[Dict[str, Any]] = []
    for raw in (domains or []):
        d = str(raw or "").strip().lower()
        if not d:
            continue
        if d.startswith("*."):
            return False, f"ACME 预检失败：通配符域名 {d} 不支持 HTTP-01，请改用 DNS-01", out

        ips = _resolve_domain_ips(d)
        diag: Dict[str, Any] = {"domain": d, "dns_ips": ips}
        out.append(diag)
        if not ips:
            return False, f"ACME 预检失败：域名解析失败（{d}）", out

        if not any(_is_public_ip(ip) for ip in ips):
            return False, f"ACME 预检失败：域名 {d} 仅解析到内网/保留地址（{', '.join(ips)}）", out

        token = f"nexus-preflight-{uuid.uuid4().hex[:20]}"
        token_file = root / ".well-known" / "acme-challenge" / token
        try:
            token_file.parent.mkdir(parents=True, exist_ok=True)
            token_file.write_text(token, encoding="utf-8")
        except Exception as exc:
            return False, f"ACME 预检失败：写入 challenge 文件失败（{exc}）", out

        try:
            ok, code, msg = _acme_challenge_probe(d, token)
            diag["local_http_ok"] = bool(ok)
            diag["local_http_status"] = int(code)
            if msg:
                diag["local_http_detail"] = str(msg)
            if not ok:
                hint = f"ACME 预检失败：本机 80 口 challenge 不可达（domain={d}, status={code or '-'}"
                if msg:
                    hint += f", detail={msg}"
                hint += ")"
                return False, hint, out
        finally:
            try:
                if token_file.exists():
                    token_file.unlink()
            except Exception:
                pass

    return True, "", out


def _acme_error_hint(out: str) -> str:
    low = str(out or "").lower()
    if not low:
        return ""
    if "rate limit" in low or "too many failed authorizations" in low or "too many certificates" in low:
        return "触发 CA 频率限制，请等待后重试（可先用 staging 测试）。"
    if "dns problem" in low or "nxdomain" in low or "no valid ip addresses found" in low:
        return "域名 DNS 解析异常或未生效。"
    if "connection refused" in low or "timeout" in low or "connection reset" in low or "all connection attempts failed" in low:
        return "CA 无法从公网访问该域名的 80 端口（请检查解析、放行和转发）。"
    if "invalid response" in low or "404" in low:
        return "challenge 路径返回异常（请确认 Nginx 对 /.well-known/acme-challenge 可访问）。"
    if "wildcard" in low and "http-01" in low:
        return "通配符域名不支持 HTTP-01，需要 DNS-01。"
    return ""


def _acme_error_text(out: str, fallback: str) -> str:
    base = str(out or "").strip() or str(fallback or "证书操作失败")
    if len(base) > 3600:
        base = base[:3600] + "\n...（已截断）"
    hint = _acme_error_hint(base)
    if hint and hint not in base:
        return f"{base}\n提示：{hint}"
    return base


def _acme_renew_skipped(out: str) -> bool:
    """Return True when acme.sh reports renewal was skipped (not due yet)."""
    low = str(out or "").lower()
    if not low:
        return False
    signals = (
        "domains not changed",
        "next renewal time is",
        "add '--force' to force renewal",
        'add "--force" to force renewal',
        "it is not yet time to renew",
        "skip, next renewal time is",
        "skipping. next renewal time is",
    )
    return any(sig in low for sig in signals)


def _cert_dates(cert_path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    code, txt = _run_cmd(["openssl", "x509", "-noout", "-dates", "-in", str(cert_path)])
    if code != 0:
        return out
    for line in txt.splitlines():
        if line.startswith("notBefore="):
            out["not_before"] = line.replace("notBefore=", "").strip()
        if line.startswith("notAfter="):
            out["not_after"] = line.replace("notAfter=", "").strip()
    # compute renew_at (20 days before not_after)
    if out.get("not_after"):
        try:
            dt = datetime.strptime(out["not_after"], "%b %d %H:%M:%S %Y %Z")
            renew = dt - timedelta(days=20)
            out["renew_at"] = renew.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    return out


@app.post("/api/v1/website/env/ensure")
def api_website_env_ensure(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    need_nginx = bool(payload.get("need_nginx"))
    need_php = bool(payload.get("need_php"))
    need_acme = bool(payload.get("need_acme"))

    installed: List[str] = []
    already: List[str] = []
    errors: List[str] = []

    if need_nginx:
        if shutil.which("nginx"):
            already.append("nginx")
        else:
            ok, out = _pkg_install(["nginx"])
            if ok:
                installed.append("nginx")
                _start_service("nginx")
            else:
                errors.append(out or "nginx 安装失败")

    if need_php:
        sock = _detect_php_fpm_sock()
        if sock:
            already.append("php-fpm")
        else:
            pkg_candidates = [
                ["php-fpm", "php-cli"],
                ["php81-fpm", "php81"],
                ["php82-fpm", "php82"],
                ["php8.2-fpm", "php8.2-cli"],
                ["php8.1-fpm", "php8.1-cli"],
                ["php8.0-fpm", "php8.0-cli"],
            ]
            ok = False
            msg = ""
            for pkgs in pkg_candidates:
                ok, msg = _pkg_install(pkgs)
                if ok:
                    installed.append("php-fpm")
                    for svc in ("php-fpm", "php8.2-fpm", "php8.1-fpm", "php8.0-fpm", "php81-fpm", "php82-fpm"):
                        _start_service(svc)
                    break
            if not ok:
                errors.append(msg or "php-fpm 安装失败")

    if need_acme:
        if _find_acme_sh():
            already.append("acme.sh")
        else:
            ok, out = _install_acme_sh()
            if ok:
                installed.append("acme.sh")
            else:
                errors.append(out or "acme.sh 安装失败")

    if errors:
        return {"ok": False, "error": "；".join(errors), "installed": installed, "already": already}
    return {"ok": True, "installed": installed, "already": already}


@app.post("/api/v1/website/site/create")
def api_website_create(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    domains = payload.get("domains") or []
    if not isinstance(domains, list) or not domains:
        return {"ok": False, "error": "domains 不能为空"}
    site_type = str(payload.get("type") or "static").strip()
    root_path = str(payload.get("root_path") or "").strip()
    proxy_target = _normalize_proxy_target(str(payload.get("proxy_target") or ""))
    web_server = str(payload.get("web_server") or "nginx").strip().lower()
    https_redirect = bool(payload.get("https_redirect"))
    gzip_enabled = bool(payload.get("gzip_enabled", True))
    nginx_tpl = str(payload.get("nginx_tpl") or "").strip()

    if web_server != "nginx":
        return {"ok": False, "error": "当前仅支持 nginx"}
    if shutil.which("nginx") is None:
        return {"ok": False, "error": "未检测到 nginx"}

    php_sock = None
    if site_type == "php":
        php_sock = _detect_php_fpm_sock()
        if not php_sock:
            return {"ok": False, "error": "未检测到 php-fpm socket"}

    if site_type != "reverse_proxy":
        if not root_path:
            return {"ok": False, "error": "root_path 不能为空"}
    else:
        if not proxy_target:
            return {"ok": False, "error": "proxy_target 不能为空"}
        # Reverse proxy still needs a local webroot for ACME HTTP-01 challenge.
        # Old panel versions may not send root_path at all.
        if not root_path:
            root_path = _default_webroot(str(domains[0]), extra_bases)

    created_root = False
    root_valid: Optional[Path] = None
    created_index_path: Optional[Path] = None

    # Prepare webroot (also for reverse_proxy, only used for ACME challenge)
    root_pre_exists = False
    if root_path:
        try:
            root_pre_exists = Path(root_path).exists()
        except Exception:
            root_pre_exists = False
        root_valid, err = _ensure_acme_webroot(root_path, extra_bases)
        if err:
            return {"ok": False, "error": f"创建目录失败：{err}"}
        created_root = not root_pre_exists

    if site_type != "reverse_proxy":
        # Create a friendly default index when empty
        try:
            if site_type == "php":
                idxp = Path(root_path) / "index.php"
                if not idxp.exists():
                    idxp.write_text("<?php phpinfo(); ?>\n", encoding="utf-8")
                    created_index_path = idxp
            else:
                idx = Path(root_path) / "index.html"
                if not idx.exists():
                    idx.write_text("<h1>It works!</h1>", encoding="utf-8")
                    created_index_path = idx
        except Exception:
            # ignore default index creation errors
            pass

    # If certificate already exists for the primary domain, keep HTTPS enabled.
    cert_paths = _existing_cert_paths(str(domains[0]))

    if nginx_tpl:
        ssl_cert = cert_paths[0] if cert_paths else ""
        ssl_key = cert_paths[1] if cert_paths else ""
        ctx = {
            "SERVER_NAME": " ".join(domains),
            "ROOT_PATH": root_path,
            "PROXY_TARGET": proxy_target,
            "SSL_CERT": ssl_cert,
            "SSL_KEY": ssl_key,
            "GZIP_CONF": _gzip_snippet() if gzip_enabled else "",
            # Optional helpers for custom templates
            "ACME_ROOT": root_path,
        }
        conf = _render_custom_template(nginx_tpl, ctx)
    else:
        conf = _render_nginx_conf(
            site_type,
            domains,
            root_path,
            proxy_target,
            php_sock,
            https_redirect=https_redirect,
            gzip_enabled=gzip_enabled,
            cert_paths=cert_paths,
        )
    ok, conf_path, out = _apply_nginx_conf(domains[0], conf)
    if not ok:
        # rollback root if we just created it
        try:
            if created_root and root_valid and root_valid.exists():
                shutil.rmtree(root_valid)
            elif created_index_path and created_index_path.exists():
                created_index_path.unlink()
        except Exception:
            pass
        return {"ok": False, "error": out}

    return {"ok": True, "conf_path": str(conf_path)}


@app.post("/api/v1/website/ssl/issue")
def api_ssl_issue(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    domains = payload.get("domains") or []
    if not isinstance(domains, list) or not domains:
        return {"ok": False, "error": "domains 不能为空"}
    update_conf = payload.get("update_conf") if isinstance(payload, dict) else None
    site_type = "static"
    if isinstance(update_conf, dict):
        site_type = str(update_conf.get("type") or "static").strip()

    # webroot is required for ACME HTTP-01 challenge.
    root_path = str(payload.get("root_path") or "").strip()
    if not root_path and isinstance(update_conf, dict):
        # Prefer update_conf.root_path when available
        root_path = str(update_conf.get("root_path") or "").strip()
    if not root_path and site_type == "reverse_proxy":
        # Reverse proxy needs a synthetic webroot just for ACME.
        root_path = _default_webroot(str(domains[0]), extra_bases)
    if not root_path and site_type != "reverse_proxy":
        return {"ok": False, "error": "root_path 不能为空"}

    root_valid, err = _ensure_acme_webroot(root_path, extra_bases)
    if err:
        return {"ok": False, "error": err}
    root_path = str(root_valid) if root_valid else root_path

    pre_ok, pre_err, pre_diag = _acme_precheck_domains(domains, root_path)
    if not pre_ok:
        return {"ok": False, "error": pre_err, "precheck": pre_diag}

    acme = _find_acme_sh()
    if not acme:
        # Auto-install acme.sh on demand (common first-use scenario)
        ok, msg = _install_acme_sh()
        if not ok:
            return {"ok": False, "error": msg or "acme.sh 安装失败"}
        acme = _find_acme_sh()
        if not acme:
            return {"ok": False, "error": "acme.sh 安装后未找到"}

    # Ensure ACME account is registered with an email address.
    # Newer acme.sh defaults to ZeroSSL which requires an email to obtain EAB.
    acme_server = _acme_server_for_issue()
    acme_email = _acme_email_for_domains(domains)
    ok_reg, reg_out = _acme_register_account(acme, acme_server, acme_email)
    if not ok_reg:
        return {"ok": False, "error": reg_out or "ACME 账户注册失败"}

    # Best-effort: ensure Nginx config has ACME location before issuing.
    # This is important for reverse_proxy sites created by older versions.
    if isinstance(update_conf, dict):
        proxy_target = _normalize_proxy_target(str(update_conf.get("proxy_target") or ""))
        https_redirect = bool(update_conf.get("https_redirect"))
        gzip_enabled = bool(update_conf.get("gzip_enabled", True))
        tpl = str(update_conf.get("nginx_tpl") or "").strip()
        php_sock = _detect_php_fpm_sock() if site_type == "php" else None
        # Keep any existing cert config during issuance to avoid unnecessary downtime.
        pre_cert = _existing_cert_paths(str(domains[0]))
        root_for_conf = str(update_conf.get("root_path") or root_path).strip() or root_path
        if site_type == "reverse_proxy" and not root_for_conf:
            root_for_conf = root_path
        if tpl:
            ctx = {
                "SERVER_NAME": " ".join(domains),
                "ROOT_PATH": root_for_conf,
                "PROXY_TARGET": proxy_target,
                "SSL_CERT": pre_cert[0] if pre_cert else "",
                "SSL_KEY": pre_cert[1] if pre_cert else "",
                "GZIP_CONF": _gzip_snippet() if gzip_enabled else "",
                "ACME_ROOT": root_path,
            }
            conf_pre = _render_custom_template(tpl, ctx)
        else:
            conf_pre = _render_nginx_conf(
                site_type,
                domains,
                root_for_conf,
                proxy_target,
                php_sock,
                https_redirect=https_redirect,
                gzip_enabled=gzip_enabled,
                cert_paths=pre_cert,
            )
        ok_conf, _conf_path, msg = _apply_nginx_conf(domains[0], conf_pre)
        if not ok_conf:
            return {"ok": False, "error": f"更新 Nginx 配置失败：{msg}"}

    cmd = [acme, "--issue", "--server", acme_server]
    for d in domains:
        cmd += ["-d", str(d)]
    cmd += ["-w", root_path]
    code, out = _run_cmd(cmd, timeout=300, env=_acme_env())
    if code != 0:
        return {"ok": False, "error": _acme_error_text(out, "证书申请失败")}

    main_domain = str(domains[0])
    safe = _slugify(main_domain)
    cert_dir = Path("/etc/ssl/nexus") / safe
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_path = cert_dir / "privkey.pem"
    fullchain_path = cert_dir / "fullchain.pem"

    install_cmd = [
        acme,
        "--install-cert",
        "-d",
        main_domain,
        "--key-file",
        str(key_path),
        "--fullchain-file",
        str(fullchain_path),
        "--reloadcmd",
        "nginx -s reload",
    ]
    code, out = _run_cmd(install_cmd, timeout=90, env=_acme_env())
    if code != 0:
        return {"ok": False, "error": _acme_error_text(out, "证书安装失败")}

    # Optional: update nginx config to enable HTTPS
    if isinstance(update_conf, dict):
        proxy_target = _normalize_proxy_target(str(update_conf.get("proxy_target") or ""))
        https_redirect = bool(update_conf.get("https_redirect"))
        gzip_enabled = bool(update_conf.get("gzip_enabled", True))
        tpl = str(update_conf.get("nginx_tpl") or "").strip()
        php_sock = _detect_php_fpm_sock() if site_type == "php" else None
        root_for_conf = str(update_conf.get("root_path") or root_path).strip() or root_path
        if site_type == "reverse_proxy" and not root_for_conf:
            root_for_conf = root_path
        if tpl:
            ctx = {
                "SERVER_NAME": " ".join(domains),
                "ROOT_PATH": root_for_conf,
                "PROXY_TARGET": proxy_target,
                "SSL_CERT": str(fullchain_path),
                "SSL_KEY": str(key_path),
                "GZIP_CONF": _gzip_snippet() if gzip_enabled else "",
                "ACME_ROOT": root_path,
            }
            conf = _render_custom_template(tpl, ctx)
        else:
            conf = _render_nginx_conf(
                site_type,
                domains,
                root_for_conf,
                proxy_target,
                php_sock,
                https_redirect=https_redirect,
                gzip_enabled=gzip_enabled,
                cert_paths=(str(fullchain_path), str(key_path)),
            )
        ok_conf, _conf_path, msg = _apply_nginx_conf(domains[0], conf)
        if not ok_conf:
            meta = _cert_dates(fullchain_path)
            return {
                "ok": True,
                "cert_dir": str(cert_dir),
                "warning": f"证书签发成功，但更新 Nginx 配置失败：{msg}",
                **meta,
            }

    meta = _cert_dates(fullchain_path)
    return {
        "ok": True,
        "cert_dir": str(cert_dir),
        **meta,
    }


@app.post("/api/v1/website/ssl/renew")
def api_ssl_renew(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    domains = payload.get("domains") or []
    if not isinstance(domains, list) or not domains:
        return {"ok": False, "error": "domains 不能为空"}
    update_conf = payload.get("update_conf") if isinstance(payload, dict) else None
    site_type = "static"
    if isinstance(update_conf, dict):
        site_type = str(update_conf.get("type") or "static").strip()

    # For renewal, root_path is only needed to ensure ACME challenge can be served
    # and to render nginx config (ROOT_PATH for non-reverse_proxy sites).
    root_path = str(payload.get("root_path") or "").strip()
    if not root_path and isinstance(update_conf, dict):
        root_path = str(update_conf.get("root_path") or "").strip()
    if not root_path and site_type == "reverse_proxy":
        root_path = _default_webroot(str(domains[0]), extra_bases)
    if not root_path and site_type != "reverse_proxy" and isinstance(update_conf, dict):
        return {"ok": False, "error": "root_path 不能为空"}

    if root_path:
        _root_valid, err = _ensure_acme_webroot(root_path, extra_bases)
        if err:
            return {"ok": False, "error": err}
        pre_ok, pre_err, pre_diag = _acme_precheck_domains(domains, root_path)
        if not pre_ok:
            return {"ok": False, "error": pre_err, "precheck": pre_diag}

    acme = _find_acme_sh()
    if not acme:
        ok, msg = _install_acme_sh()
        if not ok:
            return {"ok": False, "error": msg or "acme.sh 安装失败"}
        acme = _find_acme_sh()
        if not acme:
            return {"ok": False, "error": "acme.sh 安装后未找到"}

    acme_server = _acme_server_for_domain(str(domains[0]))
    acme_email = _acme_email_for_domains(domains)
    ok_reg, reg_out = _acme_register_account(acme, acme_server, acme_email)
    if not ok_reg:
        return {"ok": False, "error": reg_out or "ACME 账户注册失败"}

    # Best-effort: ensure Nginx config has ACME location before renewing.
    if isinstance(update_conf, dict):
        proxy_target = _normalize_proxy_target(str(update_conf.get("proxy_target") or ""))
        https_redirect = bool(update_conf.get("https_redirect"))
        gzip_enabled = bool(update_conf.get("gzip_enabled", True))
        tpl = str(update_conf.get("nginx_tpl") or "").strip()
        php_sock = _detect_php_fpm_sock() if site_type == "php" else None
        pre_cert = _existing_cert_paths(str(domains[0]))
        root_for_conf = str(update_conf.get("root_path") or root_path).strip() or root_path
        if site_type == "reverse_proxy" and not root_for_conf:
            root_for_conf = root_path
        if tpl:
            ctx = {
                "SERVER_NAME": " ".join(domains),
                "ROOT_PATH": root_for_conf,
                "PROXY_TARGET": proxy_target,
                "SSL_CERT": pre_cert[0] if pre_cert else "",
                "SSL_KEY": pre_cert[1] if pre_cert else "",
                "GZIP_CONF": _gzip_snippet() if gzip_enabled else "",
                "ACME_ROOT": root_path,
            }
            conf_pre = _render_custom_template(tpl, ctx)
        else:
            conf_pre = _render_nginx_conf(
                site_type,
                domains,
                root_for_conf,
                proxy_target,
                php_sock,
                https_redirect=https_redirect,
                gzip_enabled=gzip_enabled,
                cert_paths=pre_cert,
            )
        ok_conf, _conf_path, msg = _apply_nginx_conf(domains[0], conf_pre)
        if not ok_conf:
            return {"ok": False, "error": f"更新 Nginx 配置失败：{msg}"}

    main_domain = str(domains[0])
    cmd = [acme, "--renew", "-d", main_domain, "--server", acme_server]
    code, out = _run_cmd(cmd, timeout=300, env=_acme_env())
    renew_skipped = False
    if code != 0:
        if _acme_renew_skipped(out):
            renew_skipped = True
        else:
            return {"ok": False, "error": _acme_error_text(out, "证书续期失败")}

    safe = _slugify(main_domain)
    cert_dir = Path("/etc/ssl/nexus") / safe
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_path = cert_dir / "privkey.pem"
    fullchain_path = cert_dir / "fullchain.pem"

    install_cmd = [
        acme,
        "--install-cert",
        "-d",
        main_domain,
        "--key-file",
        str(key_path),
        "--fullchain-file",
        str(fullchain_path),
        "--reloadcmd",
        "nginx -s reload",
    ]
    code, out = _run_cmd(install_cmd, timeout=90, env=_acme_env())
    if code != 0:
        return {"ok": False, "error": _acme_error_text(out, "证书安装失败")}

    if isinstance(update_conf, dict):
        proxy_target = _normalize_proxy_target(str(update_conf.get("proxy_target") or ""))
        https_redirect = bool(update_conf.get("https_redirect"))
        gzip_enabled = bool(update_conf.get("gzip_enabled", True))
        tpl = str(update_conf.get("nginx_tpl") or "").strip()
        php_sock = _detect_php_fpm_sock() if site_type == "php" else None
        root_for_conf = str(update_conf.get("root_path") or root_path).strip() or root_path
        if site_type == "reverse_proxy" and not root_for_conf:
            root_for_conf = root_path
        if tpl:
            ctx = {
                "SERVER_NAME": " ".join(domains),
                "ROOT_PATH": root_for_conf,
                "PROXY_TARGET": proxy_target,
                "SSL_CERT": str(fullchain_path),
                "SSL_KEY": str(key_path),
                "GZIP_CONF": _gzip_snippet() if gzip_enabled else "",
                "ACME_ROOT": root_path,
            }
            conf = _render_custom_template(tpl, ctx)
        else:
            conf = _render_nginx_conf(
                site_type,
                domains,
                root_for_conf,
                proxy_target,
                php_sock,
                https_redirect=https_redirect,
                gzip_enabled=gzip_enabled,
                cert_paths=(str(fullchain_path), str(key_path)),
            )
        ok_conf, _conf_path, msg = _apply_nginx_conf(domains[0], conf)
        if not ok_conf:
            meta = _cert_dates(fullchain_path)
            return {
                "ok": True,
                "cert_dir": str(cert_dir),
                "warning": f"证书续期成功，但更新 Nginx 配置失败：{msg}",
                **meta,
            }

    meta = _cert_dates(fullchain_path)
    ret = {
        "ok": True,
        "cert_dir": str(cert_dir),
        **meta,
    }
    if renew_skipped:
        ret["renew_skipped"] = True
        ret["message"] = "证书未到续期时间，已保持当前证书"
    return ret


@app.post("/api/v1/website/site/delete")
def api_website_delete(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    domains = payload.get("domains") or []
    if not isinstance(domains, list) or not domains:
        return {"ok": False, "error": "domains 不能为空"}
    root_path = str(payload.get("root_path") or "").strip()
    delete_root = bool(payload.get("delete_root"))
    delete_cert = bool(payload.get("delete_cert"))

    warnings: List[str] = []
    removed_conf = 0
    if shutil.which("nginx") is not None:
        ok, out = _remove_nginx_conf_with_rollback(str(domains[0]))
        if not ok:
            return {"ok": False, "error": out or "nginx reload 失败"}
        removed_conf = 1
    else:
        removed_conf = _remove_nginx_conf_by_domain(str(domains[0]))

    if delete_root:
        err = _delete_site_root(root_path, extra_bases)
        if err:
            warnings.append(f"删除站点目录失败：{err}")

    removed_cert = False
    if delete_cert:
        safe = _slugify(str(domains[0]))
        cert_dir = Path("/etc/ssl/nexus") / safe
        try:
            if cert_dir.exists():
                shutil.rmtree(cert_dir)
            removed_cert = True
        except Exception:
            removed_cert = False

    return {"ok": True, "removed_conf": removed_conf, "removed_cert": removed_cert, "warnings": warnings}


@app.post("/api/v1/website/env/uninstall")
def api_website_env_uninstall(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    purge_data = bool(payload.get("purge_data"))
    deep_uninstall = bool(payload.get("deep_uninstall"))
    sites = payload.get("sites") or []
    if not isinstance(sites, list):
        sites = []

    for svc in ("nginx", "apache2", "httpd", "php-fpm", "php8.2-fpm", "php8.1-fpm", "php8.0-fpm"):
        _stop_service(svc)

    errors: List[str] = []
    removed_conf = _purge_nginx_confs()
    if shutil.which("nginx") is not None:
        ok, out = _nginx_reload()
        if not ok:
            # During uninstall we treat reload failures as warnings (nginx may be stopped already).
            errors.append(out or "nginx reload 失败")

    removed_roots = 0
    if purge_data:
        for s in sites:
            if not isinstance(s, dict):
                continue
            rb = str(s.get("root_base") or "").strip()
            root = str(s.get("root_path") or "").strip()
            if not root:
                # reverse_proxy sites may not have a root_path in old panel versions
                continue
            err = _delete_site_root(root, [rb] if rb else None)
            if err:
                errors.append(err)
            else:
                removed_roots += 1
        try:
            cert_dir = Path("/etc/ssl/nexus")
            if cert_dir.exists():
                shutil.rmtree(cert_dir)
        except Exception as exc:
            errors.append(str(exc))

    removed_packages: List[str] = []
    if deep_uninstall:
        pkgs = [
            "nginx",
            "apache2",
            "httpd",
            "php-fpm",
            "php-cli",
            "php",
            "php8.3-fpm",
            "php8.2-fpm",
            "php8.1-fpm",
            "php8.0-fpm",
            "php7.4-fpm",
            "php82-fpm",
            "php81-fpm",
            "php80-fpm",
            "certbot",
            "acme.sh",
        ]
        mgr = _detect_pkg_mgr()
        installed_before = [p for p in pkgs if mgr and _pkg_is_installed(mgr, p)]
        ok, out = _pkg_remove(pkgs)
        if ok:
            removed_packages = installed_before
        else:
            errors.append(out or "深度卸载失败")
        # remove acme.sh if installed via script
        for p in ("/root/.acme.sh", "/usr/local/bin/acme.sh"):
            try:
                if Path(p).exists():
                    if Path(p).is_dir():
                        shutil.rmtree(p)
                    else:
                        Path(p).unlink()
            except Exception:
                pass

    return {
        "ok": True,
        "removed_conf": removed_conf,
        "purged_roots": removed_roots,
        "errors": errors,
        "removed_packages": removed_packages,
    }


def _site_health(payload: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    domains = payload.get("domains") or []
    if not isinstance(domains, list) or not domains:
        return {"ok": False, "error": "domains 不能为空"}
    domain = str(domains[0]).strip()
    site_type = str(payload.get("type") or "static").strip()
    root_path = str(payload.get("root_path") or "").strip()
    proxy_target = _normalize_proxy_target(str(payload.get("proxy_target") or ""))
    extra_bases = _payload_root_bases(payload)

    checks: Dict[str, Any] = {}
    if shutil.which("nginx") is None:
        return {"ok": False, "error": "未检测到 nginx", "checks": checks}

    # nginx config test
    code, out = _run_cmd(["nginx", "-t"], timeout=12)
    checks["nginx_test_ok"] = code == 0
    if verbose:
        checks["nginx_test_output"] = (out or "")[:2000]

    # nginx service status
    svc_ok, svc_msg = _service_active("nginx")
    checks["nginx_active"] = svc_ok
    if verbose:
        checks["nginx_active_msg"] = svc_msg

    conf_path = _nginx_conf_path(domain)
    checks["conf_path"] = str(conf_path)
    checks["conf_exists"] = conf_path.exists()

    if site_type != "reverse_proxy":
        try:
            root_valid = _validate_root(root_path, extra_bases)
            checks["root_exists"] = root_valid.exists()
        except Exception as exc:
            checks["root_exists"] = False
            checks["root_error"] = str(exc)
    else:
        checks["root_exists"] = True

    if site_type == "php":
        php_sock = _detect_php_fpm_sock()
        checks["php_sock"] = php_sock or ""
        checks["php_ok"] = bool(php_sock)
    else:
        checks["php_ok"] = True

    # HTTP probe (local)
    http_ok, status, latency_ms, err, header_site = _http_probe("127.0.0.1", 80, domain, False, timeout=4.5)
    used_https = False
    if not http_ok:
        # try HTTPS 443 (best-effort, no verify)
        http_ok, status, latency_ms, err2, header_site = _http_probe("127.0.0.1", 443, domain, True, timeout=5.5)
        used_https = True
        if err2:
            err = err2
    checks["http_ok"] = http_ok
    checks["http_status"] = int(status or 0)
    checks["http_latency_ms"] = int(latency_ms or 0)
    checks["http_site_header"] = header_site
    if verbose:
        checks["http_tls"] = used_https
        checks["http_error"] = err

    # vhost match (only if we can detect marker)
    vhost_match = None
    if header_site:
        vhost_match = header_site.strip().lower() == domain.strip().lower()
    checks["vhost_match"] = vhost_match

    if verbose:
        # check if conf file is included in nginx -T output
        conf_path = checks.get("conf_path") or ""
        try:
            code_t, out_t = _run_cmd(["nginx", "-T"], timeout=12)
            if code_t == 0 and conf_path:
                checks["conf_included"] = conf_path in out_t
            else:
                checks["conf_included"] = False
        except Exception:
            checks["conf_included"] = False

    ok = bool(checks.get("nginx_test_ok")) and bool(checks.get("conf_exists")) and bool(checks.get("root_exists")) and bool(checks.get("php_ok")) and bool(http_ok)
    if vhost_match is False:
        ok = False

    error = ""
    if not checks.get("nginx_test_ok"):
        error = "nginx -t 失败"
    elif not checks.get("conf_exists"):
        error = "Nginx 配置不存在"
    elif verbose and checks.get("conf_included") is False:
        error = "Nginx 未包含该配置（include 路径不匹配）"
    elif not checks.get("root_exists"):
        error = str(checks.get("root_error") or "站点根目录不存在")
    elif not checks.get("php_ok"):
        error = "php-fpm 未就绪"
    elif vhost_match is False:
        error = "命中默认站点（X-Nexus-Site 不匹配）"
    elif not http_ok:
        error = err or "HTTP 探测失败"

    payload_out: Dict[str, Any] = {
        "ok": ok,
        "status_code": int(status or 0),
        "latency_ms": int(latency_ms or 0),
        "error": error,
        "checks": checks,
    }
    return payload_out


@app.post("/api/v1/website/health")
def api_website_health(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    return _site_health(payload, verbose=False)


@app.post("/api/v1/website/diagnose")
def api_website_diagnose(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    res = _site_health(payload, verbose=True)
    # Attach extra context
    res["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    res["proxy_target"] = _normalize_proxy_target(str(payload.get("proxy_target") or ""))
    return res


@app.get("/api/v1/website/files/list")
def api_files_list(root: str, path: str = "", root_base: Optional[str] = None, _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    extra = [root_base] if root_base else None
    root_path = _validate_root(root, extra)
    target = _safe_join(root_path, path)
    if not target.exists() or not target.is_dir():
        return {"ok": False, "error": "目录不存在"}

    items: List[Dict[str, Any]] = []
    try:
        entries = list(os.scandir(target))
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    entries.sort(key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))
    for entry in entries:
        try:
            st = entry.stat(follow_symlinks=False)
            rel = str(Path(entry.path).relative_to(root_path))
        except Exception:
            continue
        items.append(
            {
                "name": entry.name,
                "path": rel,
                "is_dir": entry.is_dir(follow_symlinks=False),
                "size": int(st.st_size),
                "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    return {"ok": True, "items": items}


@app.get("/api/v1/website/files/read")
def api_files_read(root: str, path: str, root_base: Optional[str] = None, _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    extra = [root_base] if root_base else None
    root_path = _validate_root(root, extra)
    if not path:
        return {"ok": False, "error": "文件路径不能为空"}
    target = _safe_join(root_path, path)
    if not target.exists() or not target.is_file():
        return {"ok": False, "error": "文件不存在"}
    if target.stat().st_size > 1024 * 1024:
        return {"ok": False, "error": "文件过大（限制 1MB）"}
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "content": content}


@app.post("/api/v1/website/files/write")
def api_files_write(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    root_path = _validate_root(str(payload.get("root") or ""), extra_bases)
    path = str(payload.get("path") or "")
    if not path:
        return {"ok": False, "error": "文件路径不能为空"}
    content = str(payload.get("content") or "")
    target = _safe_join(root_path, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_text(content, encoding="utf-8")
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True}


@app.post("/api/v1/website/files/mkdir")
def api_files_mkdir(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    root_path = _validate_root(str(payload.get("root") or ""), extra_bases)
    path = str(payload.get("path") or "")
    name = str(payload.get("name") or "").strip()
    if not name:
        return {"ok": False, "error": "目录名不能为空"}
    if "/" in name or "\\" in name or ".." in name:
        return {"ok": False, "error": "目录名非法"}
    target = _safe_join(root_path, f"{path.rstrip('/')}/{name}")
    try:
        target.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True}


@app.post("/api/v1/website/files/delete")
def api_files_delete(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    root_path = _validate_root(str(payload.get("root") or ""), extra_bases)
    path = str(payload.get("path") or "")
    if not path:
        return {"ok": False, "error": "禁止删除根目录"}
    target = _safe_join(root_path, path)
    if not target.exists():
        return {"ok": False, "error": "文件/目录不存在"}
    try:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True}


@app.post("/api/v1/website/files/upload")
def api_files_upload(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    root_path = _validate_root(str(payload.get("root") or ""), extra_bases)
    path = str(payload.get("path") or "")
    filename = str(payload.get("filename") or "upload.bin").strip()
    filename = os.path.basename(filename) or "upload.bin"
    content_b64 = str(payload.get("content_b64") or "")
    if not content_b64:
        return {"ok": False, "error": "缺少文件内容"}
    try:
        raw = base64.b64decode(content_b64.encode("ascii"))
    except Exception:
        return {"ok": False, "error": "文件内容解析失败"}
    target = _safe_join(root_path, f"{path.rstrip('/')}/{filename}")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_bytes(raw)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True}


@app.post("/api/v1/website/files/upload_chunk")
def api_files_upload_chunk(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    root_path = _validate_root(str(payload.get("root") or ""), extra_bases)
    path = str(payload.get("path") or "")
    filename = str(payload.get("filename") or "upload.bin").strip()
    filename = os.path.basename(filename) or "upload.bin"
    upload_id = str(payload.get("upload_id") or "").strip()
    if not upload_id:
        return {"ok": False, "error": "upload_id 不能为空"}
    try:
        offset = int(payload.get("offset") or 0)
    except Exception:
        offset = 0
    done = bool(payload.get("done"))
    content_b64 = str(payload.get("content_b64") or "")
    chunk_sha256 = str(payload.get("chunk_sha256") or "").strip().lower()
    allow_empty = bool(payload.get("allow_empty"))
    if not content_b64:
        if allow_empty and done and offset == 0:
            target = _safe_join(root_path, f"{path.rstrip('/')}/{filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_bytes(b"")
            except Exception as exc:
                return {"ok": False, "error": str(exc)}
            return {"ok": True, "done": True, "empty": True}
        return {"ok": False, "error": "缺少文件内容"}
    try:
        raw = base64.b64decode(content_b64.encode("ascii"))
    except Exception:
        return {"ok": False, "error": "文件内容解析失败"}
    if chunk_sha256:
        calc = hashlib.sha256(raw).hexdigest()
        if calc != chunk_sha256:
            return {"ok": False, "error": "SHA256 校验失败"}

    target = _safe_join(root_path, f"{path.rstrip('/')}/{filename}")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + f".part.{upload_id}")
    if tmp.exists():
        try:
            cur = tmp.stat().st_size
            if offset != cur:
                return {"ok": False, "error": "offset mismatch", "expected_offset": cur}
        except Exception:
            pass
    try:
        mode = "r+b" if tmp.exists() else "wb"
        with open(tmp, mode) as f:
            if offset:
                f.seek(offset)
            f.write(raw)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    if done:
        try:
            os.replace(tmp, target)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
    return {"ok": True, "done": done}


@app.post("/api/v1/website/files/upload_status")
def api_files_upload_status(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    root_path = _validate_root(str(payload.get("root") or ""), extra_bases)
    path = str(payload.get("path") or "")
    filename = str(payload.get("filename") or "upload.bin").strip()
    filename = os.path.basename(filename) or "upload.bin"
    upload_id = str(payload.get("upload_id") or "").strip()
    if not upload_id:
        return {"ok": False, "error": "upload_id 不能为空"}
    target = _safe_join(root_path, f"{path.rstrip('/')}/{filename}")
    tmp = target.with_name(target.name + f".part.{upload_id}")
    try:
        offset = tmp.stat().st_size if tmp.exists() else 0
    except Exception:
        offset = 0
    return {"ok": True, "offset": offset}


@app.post("/api/v1/website/files/unzip")
def api_files_unzip(payload: Dict[str, Any], _: None = Depends(_api_key_required)) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    extra_bases = _payload_root_bases(payload)
    root_path = _validate_root(str(payload.get("root") or ""), extra_bases)
    path = str(payload.get("path") or "").strip()
    dest = str(payload.get("dest") or "").strip()
    if not path:
        return {"ok": False, "error": "path 不能为空"}
    if not dest:
        # default to same directory
        dest = str(Path(path).parent).strip(".")
    zip_path = _safe_join(root_path, path)
    if not zip_path.exists() or not zip_path.is_file():
        return {"ok": False, "error": "压缩包不存在"}
    dest_dir = _safe_join(root_path, dest)
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        import zipfile
        with zipfile.ZipFile(zip_path, "r") as zf:
            count = 0
            for info in zf.infolist():
                name = (info.filename or "").replace("\\", "/").lstrip("/")
                if not name or name.startswith("../") or "/../" in name:
                    continue
                target = _safe_join(dest_dir, name)
                if info.is_dir() or name.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                count += 1
        return {"ok": True, "files": count}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@app.get("/api/v1/website/files/raw")
def api_files_raw(root: str, path: str, root_base: Optional[str] = None, _: None = Depends(_api_key_required)):
    extra = [root_base] if root_base else None
    root_path = _validate_root(root, extra)
    if not path:
        raise HTTPException(status_code=400, detail="文件路径不能为空")
    target = _safe_join(root_path, path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")
    return FileResponse(path=str(target), filename=target.name)
