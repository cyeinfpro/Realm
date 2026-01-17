#!/usr/bin/env bash
# Realm Agent v3.1 (WSS 收发修复 + 状态增强)
# - 通过 HTTP API 接收面板指令，管理 /etc/realm/realm.toml 并重启 realm
# - 支持多目标负载均衡（roundrobin / iphash）
# - 支持 WSS（发：remote_transport；收：listen_transport）
# - 输出更完整的状态：目标通断 + 连接数 + 规则状态

set -Eeuo pipefail

AGENT_DIR="/opt/realm-agent"
CFG_FILE="${AGENT_DIR}/config.json"
RULES_FILE="${AGENT_DIR}/rules.json"
SERVICE_NAME="realm-agent"
AGENT_PORT_DEFAULT=6080

# -------- utils --------
red() { echo -e "\033[31m$*\033[0m"; }
grn() { echo -e "\033[32m$*\033[0m"; }
yel() { echo -e "\033[33m$*\033[0m"; }
blu() { echo -e "\033[34m$*\033[0m"; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    red "[错误] 请使用 root 运行：sudo -i 或 sudo bash $0"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

json_get() {
  # json_get <file> <python_expr_return_value>
  # Example: json_get config.json 'd.get("token","")'
  python3 - <<PY
import json,sys
p=sys.argv[1]
expr=sys.argv[2]
with open(p,'r',encoding='utf-8') as f:
    d=json.load(f)
print(eval(expr))
PY
}

json_pretty() {
  python3 - <<'PY'
import json,sys
obj=json.load(sys.stdin)
print(json.dumps(obj,ensure_ascii=False,indent=2))
PY
}

# -------- realm install --------
map_arch() {
  local a
  a="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  case "$a" in
    amd64|x86_64) echo "x86_64";;
    arm64|aarch64) echo "aarch64";;
    armhf|armv7l) echo "armv7";;
    *) echo "x86_64";;
  esac
}

fetch_latest_realm_tag() {
  python3 - <<'PY'
import json,urllib.request
url='https://api.github.com/repos/zhboner/realm/releases/latest'
req=urllib.request.Request(url,headers={'User-Agent':'realm-agent'})
with urllib.request.urlopen(req,timeout=10) as r:
    data=json.loads(r.read().decode())
print(data.get('tag_name',''))
PY
}

install_realm_binary() {
  if have_cmd realm; then
    # 已安装就不强制覆盖
    return 0
  fi

  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y curl ca-certificates tar >/dev/null 2>&1 || true

  local arch tag url1 url2 tmpd
  arch="$(map_arch)"
  tag="$(fetch_latest_realm_tag 2>/dev/null || true)"

  if [[ -z "$tag" ]]; then
    # GitHub API 获取失败则尝试 apt
    if apt-get install -y realm >/dev/null 2>&1; then
      grn "[OK] 已通过 apt 安装 realm"
      return 0
    fi
    red "[错误] 无法获取 realm 最新版本，也无法通过 apt 安装，请检查网络或手动安装 realm 后重试。"
    return 1
  fi

  url1="https://github.com/zhboner/realm/releases/download/${tag}/realm-${arch}-unknown-linux-gnu.tar.gz"
  url2="https://github.com/zhboner/realm/releases/download/${tag}/realm-${arch}-unknown-linux-musl.tar.gz"

  tmpd="$(mktemp -d)"
  trap '[[ -n "${tmpd:-}" ]] && rm -rf "$tmpd"' RETURN

  if curl -fsSL "$url1" -o "$tmpd/realm.tgz"; then
    :
  elif curl -fsSL "$url2" -o "$tmpd/realm.tgz"; then
    :
  else
    red "[错误] realm 下载失败：$url1"
    return 1
  fi

  tar -xzf "$tmpd/realm.tgz" -C "$tmpd"
  if [[ ! -f "$tmpd/realm" ]]; then
    # 兼容解压后带目录
    local p
    p="$(find "$tmpd" -maxdepth 2 -type f -name realm 2>/dev/null | head -n1)"
    [[ -n "$p" ]] && mv -f "$p" "$tmpd/realm"
  fi

  install -m 0755 "$tmpd/realm" /usr/local/bin/realm
  ln -sf /usr/local/bin/realm /usr/bin/realm
  grn "[OK] realm 已安装：$(/usr/local/bin/realm --version 2>/dev/null || echo "installed")"
}

ensure_deps() {
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y python3 python3-venv python3-pip iproute2 lsof >/dev/null 2>&1 || true
  install_realm_binary
}

# -------- realm config generation --------
normalize_algo() {
  # input: round_robin / roundrobin / ip_hash / iphash
  python3 - <<'PY'
import sys
s=(sys.stdin.read().strip() or 'roundrobin').lower()
for ch in ['_','-',' ']:
    s=s.replace(ch,'')
if s in ('iphash','ip'):
    print('iphash')
else:
    print('roundrobin')
PY
}

build_remote_transport_wss() {
  # args: host path sni insecure
  local host="$1" path="$2" sni="$3" insecure="$4"
  [[ -z "$host" ]] && host="www.bing.com"
  [[ -z "$path" ]] && path="/ws"
  [[ -z "$sni" ]] && sni="$host"

  local opt
  opt="ws;host=${host};path=${path};tls;sni=${sni}"
  if [[ "$insecure" == "1" || "$insecure" == "true" || "$insecure" == "yes" ]]; then
    opt+=";insecure"
  fi
  echo "$opt"
}

build_realm_toml() {
  # rules.json -> /etc/realm/realm.toml
  python3 - <<'PY'
import json,os,sys
rules_path=os.environ.get('RULES_FILE')
if not rules_path or not os.path.exists(rules_path):
    print('[log]\nlevel="off"\noutput="stdout"\n\n[network]\nno_tcp=false\nuse_udp=false\n')
    sys.exit(0)

with open(rules_path,'r',encoding='utf-8') as f:
    rules=json.load(f)

def norm_algo(a:str)->str:
    a=(a or 'roundrobin').lower().replace('_','').replace('-','').replace(' ','')
    return 'iphash' if a in ('iphash','ip') else 'roundrobin'

def endpoint_network(proto:str):
    p=(proto or 'tcp+udp').lower().replace(' ','')
    if p=='tcp':
        return {'no_tcp': False, 'use_udp': False}
    if p=='udp':
        return {'no_tcp': True, 'use_udp': True}
    # tcp+udp
    return {'no_tcp': False, 'use_udp': True}

lines=[]
lines.append('[log]')
lines.append('level = "off"')
lines.append('output = "stdout"')
lines.append('')
lines.append('[network]')
lines.append('no_tcp = false')
lines.append('use_udp = false')

for r in rules:
    if r.get('paused'):
        continue
    lp=int(r['local_port'])
    targets=[t.strip() for t in (r.get('targets') or []) if t and str(t).strip()]
    if not targets:
        continue

    mode_raw=(r.get('mode') or 'tcp').lower().strip()
    wss_role=(r.get('wss_role') or '').lower().strip()
    if mode_raw in ('wss_send','wss_recv'):
        wss_role = 'client' if mode_raw=='wss_send' else 'server'
        mode='wss'
    elif mode_raw=='wss':
        mode='wss'
        if wss_role not in ('client','server'):
            wss_role='client'
    else:
        mode=mode_raw

    algo=norm_algo(r.get('algo'))

    remote=targets[0]
    extra=targets[1:]

    lines.append('')
    lines.append('[[endpoints]]')
    lines.append(f'listen = "0.0.0.0:{lp}"')
    lines.append(f'remote = "{remote}"')
    if extra:
        arr=', '.join([f'"{x}"' for x in extra])
        lines.append(f'extra_remotes = [{arr}]')
        # weights: remote + extra_remotes
        weights=', '.join(['1']*(1+len(extra)))
        lines.append(f'balance = "{algo}: {weights}"')


    # WSS tunnel transport (client: remote_transport / server: listen_transport)
    if mode=='wss':
        host=(r.get('wss_host') or 'www.bing.com').strip()
        path=(r.get('wss_path') or '/ws').strip()
        sni=(r.get('wss_sni') or host).strip()
        insecure=bool(r.get('wss_insecure'))

        # realm transport string
        opt=f'ws;host={host};path={path};tls;sni={sni}'
        if insecure:
            opt += ';insecure'

        if wss_role=='server':
            lines.append(f'listen_transport = "{opt}"')
        else:
            lines.append(f'remote_transport = "{opt}"')

    proto_for_ep = 'tcp' if mode=='wss' else r.get('protocol')
    nw=endpoint_network(proto_for_ep)
    lines.append('[endpoints.network]')
    lines.append(f"no_tcp = {'true' if nw['no_tcp'] else 'false'}")
    lines.append(f"use_udp = {'true' if nw['use_udp'] else 'false'}")

print('\n'.join(lines)+'\n')
PY
}

realm_apply() {
  mkdir -p /etc/realm
  export RULES_FILE
  build_realm_toml > /etc/realm/realm.toml

  # realm systemd
  cat > /etc/systemd/system/realm.service <<'UNIT'
[Unit]
Description=realm.service - Realm Forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/realm -c /etc/realm/realm.toml
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now realm.service >/dev/null 2>&1 || true
  systemctl restart realm.service >/dev/null 2>&1 || true
}

# -------- agent python app --------
write_agent_py() {
  mkdir -p "$AGENT_DIR"

  cat > "$AGENT_DIR/agent.py" <<'PY'
#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

AGENT_DIR = "/opt/realm-agent"
CFG_FILE = os.path.join(AGENT_DIR, "config.json")
RULES_FILE = os.path.join(AGENT_DIR, "rules.json")


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def auth_ok(headers):
    cfg = load_json(CFG_FILE, {})
    token = cfg.get("token", "")
    if not token:
        return True
    return headers.get("X-Token", "") == token


def sh(cmd):
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)


def realm_apply():
    # call bash function via subprocess
    subprocess.call(["/bin/bash", "-lc", "source /opt/realm-agent/runtime.sh && realm_apply"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def is_port_open(host, port, timeout=0.6):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def conn_count_by_port(port: int) -> int:
    # best-effort count ESTAB connections to local listen port
    try:
        out = sh(["/usr/sbin/ss", "-Htan", f"sport = :{port}"])
        return sum(1 for _ in out.splitlines() if _.strip())
    except Exception:
        return 0


def realm_running() -> bool:
    try:
        subprocess.check_call(["/bin/systemctl", "is-active", "--quiet", "realm.service"])
        return True
    except Exception:
        return False


def local_ip_guess() -> str:
    # best-effort: pick primary outbound ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def normalize_algo(a: str) -> str:
    a = (a or "roundrobin").lower().replace("_", "").replace("-", "").replace(" ", "")
    return "iphash" if a in ("iphash", "ip") else "roundrobin"


def normalize_protocol(p: str) -> str:
    p = (p or "tcp+udp").lower().replace(" ", "")
    if p in ("tcp", "udp", "tcp+udp"):
        return p
    return "tcp+udp"


def status_payload():
    rules = load_json(RULES_FILE, [])
    payload = {
        "ok": True,
        "ts": int(time.time()),
        "realm_running": realm_running(),
        "ip": local_ip_guess(),
        "rules": []
    }

    for r in rules:
        lp = int(r.get("local_port", 0))
        targets = r.get("targets") or []
        targets = [t for t in targets if isinstance(t, str) and ":" in t]
        mode = (r.get("mode") or "tcp").lower()

        conn = conn_count_by_port(lp) if lp else 0
        tgt_states = []
        for t in targets:
            host, port = t.rsplit(":", 1)
            up = is_port_open(host, port)
            tgt_states.append({"target": t, "addr": t, "up": up, "conn": 0})

        payload["rules"].append({
            "local_port": lp,
            "protocol": normalize_protocol(r.get("protocol")),
            "mode": mode,
            "algo": normalize_algo(r.get("algo")),
            "paused": bool(r.get("paused")),
            "targets": tgt_states,
            "targets_count": len(tgt_states),
            "conn": conn,
            "conn_total": conn,
        })

    return payload


class Handler(BaseHTTPRequestHandler):
    server_version = "RealmAgent/2.0"

    def _send(self, code=200, obj=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        if obj is not None:
            self.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _unauth(self):
        self._send(401, {"ok": False, "error": "unauthorized"})

    def _read_json(self):
        ln = int(self.headers.get("Content-Length", "0") or "0")
        if ln <= 0:
            return None
        raw = self.rfile.read(ln)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def do_GET(self):
        if self.path.startswith("/v1/") and not auth_ok(self.headers):
            return self._unauth()

        if self.path == "/v1/ping":
            return self._send(200, {"ok": True, "msg": "pong"})

        if self.path == "/v1/rules":
            rules = load_json(RULES_FILE, [])
            return self._send(200, {"ok": True, "rules": rules})

        if self.path == "/v1/status":
            return self._send(200, status_payload())

        if self.path.startswith("/v1/check"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            target = (q.get("target") or [""])[0].strip()
            if not target or ":" not in target:
                return self._send(400, {"ok": False, "error": "target must be host:port"})
            host, port = target.rsplit(":", 1)
            ok = is_port_open(host, port)
            return self._send(200, {"ok": True, "target": target, "reachable": ok})

        return self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path.startswith("/v1/") and not auth_ok(self.headers):
            return self._unauth()

        if self.path == "/v1/apply":
            realm_apply()
            if not realm_running():
                return self._send(500, {"ok": False, "error": "realm service not running after apply"})
            return self._send(200, {"ok": True, "msg": "applied"})

        if self.path == "/v1/check":
            data = self._read_json() or {}
            target = (data.get("target") or "").strip()
            if not target or ":" not in target:
                return self._send(400, {"ok": False, "error": "target must be host:port"})
            host, port = target.rsplit(":", 1)
            ok = is_port_open(host, port)
            return self._send(200, {"ok": True, "target": target, "reachable": ok})

        if self.path == "/v1/rules/set":
            data = self._read_json() or {}
            rules = data.get("rules")
            if not isinstance(rules, list):
                return self._send(400, {"ok": False, "error": "rules must be list"})

            # basic sanitize
            cleaned = []
            for r in rules:
                if not isinstance(r, dict):
                    continue
                try:
                    lp = int(r.get("local_port"))
                    if lp <= 0 or lp > 65535:
                        continue
                except Exception:
                    continue

                targets = r.get("targets") or []
                if not isinstance(targets, list):
                    targets = []
                targets = [t.strip() for t in targets if isinstance(t, str) and ":" in t and t.strip()]
                mode_raw = (r.get("mode") or "tcp").lower().strip()
                proto = normalize_protocol(r.get("protocol"))
                if mode_raw in ("wss", "wss_send", "wss_recv"):
                    proto = "tcp"

                cleaned.append({
                    "local_port": lp,
                    "protocol": proto,
                    "mode": mode_raw,
                    "algo": normalize_algo(r.get("algo")),
                    "paused": bool(r.get("paused")),
                    "targets": targets,
                    # WSS options (optional)
                    "wss_role": (r.get("wss_role") or "").strip().lower(),
                    "wss_host": (r.get("wss_host") or "").strip(),
                    "wss_path": (r.get("wss_path") or "").strip(),
                    "wss_sni": (r.get("wss_sni") or "").strip(),
                    "wss_insecure": bool(r.get("wss_insecure")),
                })

            save_json(RULES_FILE, cleaned)
            realm_apply()
            if not realm_running():
                return self._send(500, {"ok": False, "error": "realm service not running after apply"})
            return self._send(200, {"ok": True, "rules": cleaned})

        return self._send(404, {"ok": False, "error": "not found"})


def main():
    cfg = load_json(CFG_FILE, {})
    port = int(cfg.get("port", 6080))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"[RealmAgent] listening on 0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
PY

  chmod +x "$AGENT_DIR/agent.py"
}

write_runtime_sh() {
  cat > "$AGENT_DIR/runtime.sh" <<'RUNTIME'
#!/usr/bin/env bash
set -Eeuo pipefail
RULES_FILE="/opt/realm-agent/rules.json"

# realm_apply is defined in outer install script, but we re-implement minimal here
build_realm_toml() {
  python3 - <<'PY'
import json,os,sys
rules_path=os.environ.get('RULES_FILE')
if not rules_path or not os.path.exists(rules_path):
    print('[log]\nlevel="off"\noutput="stdout"\n\n[network]\nno_tcp=false\nuse_udp=false\n')
    sys.exit(0)

with open(rules_path,'r',encoding='utf-8') as f:
    rules=json.load(f)

def norm_algo(a:str)->str:
    a=(a or 'roundrobin').lower().replace('_','').replace('-','').replace(' ','')
    return 'iphash' if a in ('iphash','ip') else 'roundrobin'

def endpoint_network(proto:str):
    p=(proto or 'tcp+udp').lower().replace(' ','')
    if p=='tcp':
        return {'no_tcp': False, 'use_udp': False}
    if p=='udp':
        return {'no_tcp': True, 'use_udp': True}
    return {'no_tcp': False, 'use_udp': True}

lines=[]
lines.append('[log]')
lines.append('level = "off"')
lines.append('output = "stdout"')
lines.append('')
lines.append('[network]')
lines.append('no_tcp = false')
lines.append('use_udp = false')

for r in rules:
    if r.get('paused'):
        continue
    lp=int(r['local_port'])
    targets=[t.strip() for t in (r.get('targets') or []) if t and str(t).strip()]
    if not targets:
        continue

    mode_raw=(r.get('mode') or 'tcp').lower().strip()
    wss_role=(r.get('wss_role') or '').lower().strip()
    if mode_raw in ('wss_send','wss_recv'):
        wss_role = 'client' if mode_raw=='wss_send' else 'server'
        mode='wss'
    elif mode_raw=='wss':
        mode='wss'
        if wss_role not in ('client','server'):
            wss_role='client'
    else:
        mode=mode_raw

    algo=norm_algo(r.get('algo'))

    remote=targets[0]
    extra=targets[1:]

    lines.append('')
    lines.append('[[endpoints]]')
    lines.append(f'listen = "0.0.0.0:{lp}"')
    lines.append(f'remote = "{remote}"')
    if extra:
        arr=', '.join([f'"{x}"' for x in extra])
        lines.append(f'extra_remotes = [{arr}]')
        weights=', '.join(['1']*(1+len(extra)))
        lines.append(f'balance = "{algo}: {weights}"')

    if mode=='wss':
        host=(r.get('wss_host') or 'www.bing.com').strip()
        path=(r.get('wss_path') or '/ws').strip()
        sni=(r.get('wss_sni') or host).strip()
        opt=f'ws;host={host};path={path};tls;sni={sni}'
        if r.get('wss_insecure'):
            opt += ';insecure'
        lines.append(f'remote_transport = "{opt}"')

    proto_for_ep = 'tcp' if mode=='wss' else r.get('protocol')
    nw=endpoint_network(proto_for_ep)
    lines.append('[endpoints.network]')
    lines.append(f"no_tcp = {'true' if nw['no_tcp'] else 'false'}")
    lines.append(f"use_udp = {'true' if nw['use_udp'] else 'false'}")

print('\n'.join(lines)+'\n')
PY
}

realm_apply() {
  mkdir -p /etc/realm
  export RULES_FILE
  build_realm_toml > /etc/realm/realm.toml

  cat > /etc/systemd/system/realm.service <<'UNIT'
[Unit]
Description=realm.service - Realm Forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/realm -c /etc/realm/realm.toml
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now realm.service >/dev/null 2>&1 || true
  systemctl restart realm.service >/dev/null 2>&1 || true
}
RUNTIME

  chmod +x "$AGENT_DIR/runtime.sh"
}

install_agent_service() {
  cat > /etc/systemd/system/${SERVICE_NAME}.service <<UNIT
[Unit]
Description=Realm Agent API Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${AGENT_DIR}/agent.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now ${SERVICE_NAME}.service
}

save_config() {
  local token="$1" port="$2"
  mkdir -p "$AGENT_DIR"
  cat > "$CFG_FILE" <<JSON
{
  "token": "${token}",
  "port": ${port}
}
JSON
}

init_rules_file() {
  mkdir -p "$AGENT_DIR"
  if [[ ! -f "$RULES_FILE" ]]; then
    echo '[]' > "$RULES_FILE"
  fi
}

# -------- CLI --------
usage() {
  cat <<EOF
用法：
  $0 --token <TOKEN> [--port <AGENT_API_PORT>]

示例：
  curl -fsSL http://PANEL:PORT/static/realm_agent.sh | bash -s -- --token xxx --port 6080
EOF
}

main() {
  need_root

  local token="" port="${AGENT_PORT_DEFAULT}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --token) token="$2"; shift 2;;
      --port) port="$2"; shift 2;;
      -h|--help) usage; exit 0;;
      *) red "[错误] 未知参数：$1"; usage; exit 1;;
    esac
  done

  if [[ -z "$token" ]]; then
    red "[错误] 缺少 --token"
    usage
    exit 1
  fi
  if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    red "[错误] --port 不合法"
    exit 1
  fi

  ensure_deps
  save_config "$token" "$port"
  init_rules_file
  write_runtime_sh
  write_agent_py
  install_agent_service

  # 首次应用空规则，确保 realm.service 存在
  realm_apply

  grn "\n[完成] Agent 已安装并启动"
  blu "- Agent API:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1):${port}"
  blu "- Service:    systemctl status ${SERVICE_NAME} --no-pager"
  blu "- Realm:       systemctl status realm.service --no-pager"
}

main "$@"
