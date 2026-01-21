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
