import os
import socket
from typing import Any, Dict, List, Tuple

from .storage import Paths, load_json, save_json_atomic, ensure_pool_full, sync_active_from_full
from .utils import sh


POOL_JQ_CONTENT = r'''
   def to_arr(x): if x==null then [] elif (x|type)=="array" then x elif (x|type)=="string" then [x] else [] end;
   def algo_norm(a): (a//"round_robin")|tostring|ascii_downcase|gsub("[_ -]";"")|if .=="iphash" then "iphash" else "roundrobin" end;
   def balance_str(a; n; w):
    if n<=1 then null
    else if (a|type)=="string" and (a|test(":")) then a
    else (algo_norm(a) + ": " + (w|join(", "))) end
    end;

   def ws_rem(x):
    if (x|type)=="object" and (x.remote_transport // "")=="ws"
    then ("ws;host="+(x.remote_ws_host//"")+";path="+(x.remote_ws_path//"")
      +(if (x.remote_tls_enabled//false) then ";tls" else "" end)
      +(if (x.remote_tls_sni//"")!="" then ";sni="+x.remote_tls_sni else "" end)
      +(if (x.remote_tls_insecure//false) then ";insecure" else "" end))
    else null end;

   def ws_lis(x):
    if (x|type)=="object" and (x.listen_transport // "")=="ws"
    then ("ws;host="+(x.listen_ws_host//"")+";path="+(x.listen_ws_path//"")
      +(if (x.listen_tls_enabled//false) then ";tls" else "" end)
      +(if (x.listen_tls_servername//"")!="" then ";servername="+x.listen_tls_servername else "" end)
      +(if (x.listen_tls_insecure//false) then ";insecure" else "" end))
    else null end;
   def protocol_net(p):
    if (p//"")=="udp" then { no_tcp: true, use_udp: true }
    elif (p//"")=="tcp" then { no_tcp: false, use_udp: false }
    else { no_tcp: false, use_udp: true } end;

  {
    log: {level: "off", output: "stdout"},
    endpoints:
      ((.endpoints//[])
        | map(select((.disabled//false)|not))
        | map(. as $e
            | ($e.extra_config//{}) as $x
            | ($e.remote//$e.remotes//null) as $r0
            | (to_arr($r0)+to_arr($e.extra_remotes)) as $remotes
            | ($remotes|map(select(.!=null and .!=""))) as $rs
            | ($rs|length) as $n
            | if ($e.listen//"")=="" or $n==0 then empty else
                (if ($e.weights|type)=="array" and ($e.weights|length)==$n
                  then ($e.weights|map(tostring))
                  else ([range(0;$n)|"1"])
                 end) as $w
                | { listen: $e.listen, remote: $rs[0] }
                + (if $n>1 then
                      { extra_remotes: ($rs[1:]), balance: balance_str($e.balance; $n; $w) }
                   else {} end)
                + (if ($e.through//"")!="" then {through: $e.through} else {} end)
                + (if ($e.interface//"")!="" then {interface: $e.interface} else {} end)
                + (if ($e.listen_interface//"")!="" then {listen_interface: $e.listen_interface} else {} end)
                + { network: protocol_net($e.protocol) }
                + (if ($e.accept_proxy!=null) then {accept_proxy: $e.accept_proxy} else {} end)
                + (if ($e.send_proxy!=null) then {send_proxy: $e.send_proxy} else {} end)
                + (if ($e.listen_transport//"")!="" then {listen_transport:$e.listen_transport}
                   elif (ws_lis($x)!=null) then {listen_transport: ws_lis($x)} else {} end)
                + (if ($e.remote_transport//"")!="" then {remote_transport:$e.remote_transport}
                   elif (ws_rem($x)!=null) then {remote_transport: ws_rem($x)} else {} end)
              end
          ))
  }
'''


def ensure_jq_filter(paths: Paths) -> None:
    os.makedirs(paths.conf_dir, exist_ok=True)
    with open(paths.jq_filter, "w", encoding="utf-8") as f:
        f.write(POOL_JQ_CONTENT.strip() + "\n")


def apply_realm_config(paths: Paths) -> Dict[str, Any]:
    """Generate pool.json + config.json and restart realm."""
    full = ensure_pool_full(paths)
    sync_active_from_full(paths, full)
    ensure_jq_filter(paths)

    code, out, err = sh(f"jq -c -f {paths.jq_filter} {paths.pool_full} > {paths.config_json}")
    if code != 0:
        return {"ok": False, "error": "jq_failed", "detail": err or out}

    # restart realm
    code2, out2, err2 = sh("systemctl restart realm.service")
    if code2 != 0:
        return {"ok": False, "error": "restart_failed", "detail": err2 or out2}

    return {"ok": True}


def realm_service_status() -> Dict[str, Any]:
    code, out, err = sh("systemctl is-active realm.service")
    active = (out.strip() == "active")
    code2, out2, err2 = sh("systemctl show realm.service -p ActiveEnterTimestamp --value")
    return {
        "active": active,
        "active_since": out2.strip(),
        "raw": out.strip() or err.strip(),
    }


def parse_host_port(addr: str) -> Tuple[str, int]:
    # supports host:port
    if addr.startswith('['):
        # [::1]:443
        host, rest = addr.split(']', 1)
        host = host[1:]
        port = int(rest.lstrip(':'))
        return host, port
    if ':' not in addr:
        raise ValueError("missing port")
    host, port_s = addr.rsplit(':', 1)
    return host, int(port_s)


def tcp_health_check(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def conn_count_for_port(port: int) -> int:
    # count established tcp connections for local port
    code, out, err = sh(f"ss -Hnt state established '( sport = :{port} )' 2>/dev/null | wc -l", timeout=5)
    if code != 0:
        return 0
    try:
        return int(out.strip())
    except Exception:
        return 0


def get_rule_metrics(full: Dict[str, Any]) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {"ports": {}, "remotes": {}}
    for ep in full.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        listen = ep.get("listen", "")
        if not listen:
            continue
        try:
            _, port = parse_host_port(listen)
        except Exception:
            continue
        metrics["ports"][str(port)] = {"connections": conn_count_for_port(port)}

        rems: List[str] = []
        if isinstance(ep.get("remote"), str) and ep.get("remote"):
            rems.append(ep["remote"])
        if isinstance(ep.get("remotes"), list):
            rems += [r for r in ep["remotes"] if isinstance(r, str)]
        if isinstance(ep.get("extra_remotes"), list):
            rems += [r for r in ep["extra_remotes"] if isinstance(r, str)]
        rems = list(dict.fromkeys([r for r in rems if r]))
        health_list = []
        for r in rems:
            ok = False
            try:
                h, p = parse_host_port(r)
                ok = tcp_health_check(h, p)
            except Exception:
                ok = False
            health_list.append({"remote": r, "ok": ok})
        metrics["remotes"][listen] = health_list
    return metrics
