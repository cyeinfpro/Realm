// Realm Pro Panel - front-end

const UI = (() => {
  const state = {
    nodes: [],
    currentNodeId: null,
    currentRules: [],
  };

  function qs(sel, root=document){ return root.querySelector(sel); }
  function qsa(sel, root=document){ return Array.from(root.querySelectorAll(sel)); }

  function toast(msg, type='info'){
    const wrap = qs('#toast_wrap') || (()=>{
      const d = document.createElement('div');
      d.id = 'toast_wrap';
      d.className = 'toast-wrap';
      document.body.appendChild(d);
      return d;
    })();
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    wrap.appendChild(el);
    setTimeout(()=>{ el.classList.add('show'); }, 10);
    setTimeout(()=>{ el.classList.remove('show'); el.remove(); }, 3400);
  }

  async function api(method, url, body=null){
    const opt = { method, headers:{'Content-Type':'application/json'} };
    if(body) opt.body = JSON.stringify(body);
    const res = await fetch(url, opt);
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await res.json() : await res.text();
    if(!res.ok){
      const msg = data?.detail || data?.error || (typeof data === 'string' ? data : '请求失败');
      throw new Error(msg);
    }
    return data;
  }

  function fmtBool(v){ return v ? '是' : '否'; }

  function parseHostPort(hp){
    if(!hp) return {host:'', port:''};
    let s = String(hp).trim();
    if(s.startsWith('[')){
      const m = s.match(/^\[(.+?)\]:(\d+)$/);
      if(m) return {host:m[1], port:m[2]};
      return {host:s, port:''};
    }
    const idx = s.lastIndexOf(':');
    if(idx === -1) return {host:s, port:''};
    return {host:s.slice(0, idx), port:s.slice(idx+1)};
  }

  function targetsOf(ep){
    const pick = (v) => {
      if(v == null) return [];
      if(Array.isArray(v)) return v;
      return [v];
    };
    let arr = [];
    if(ep.remote != null) arr = arr.concat(pick(ep.remote));
    else if(ep.remotes != null) arr = arr.concat(pick(ep.remotes));
    if(ep.extra_remotes != null) arr = arr.concat(pick(ep.extra_remotes));
    // normalize objects host/port
    return arr
      .filter(x=>x!=null && String(x).trim()!=='' && x!=='null')
      .map(x=>{
        if(typeof x === 'object' && x.host != null && x.port != null) return `${x.host}:${x.port}`;
        return String(x);
      });
  }

  function isWssSender(ep){
    const ex = ep.extra_config || {};
    return ex.remote_transport === 'ws';
  }
  function isWssReceiver(ep){
    const ex = ep.extra_config || {};
    return ex.listen_transport === 'ws';
  }
  function ruleType(ep){
    if(isWssSender(ep)) return 'WSS发送';
    if(isWssReceiver(ep)) return 'WSS接收';
    return 'TCP/UDP';
  }

  function badge(text, kind=''){
    const cls = ['badge'];
    if(kind) cls.push(kind);
    return `<span class="${cls.join(' ')}">${text}</span>`;
  }

  // -------- Nodes --------

  async function loadNodes(){
    const t = qs('#nodes_table tbody');
    if(t) t.innerHTML = `<tr><td colspan="4" class="muted">加载中…</td></tr>`;
    try{
      const nodes = await api('GET','/api/nodes');
      state.nodes = nodes;
      if(t) renderNodesTable(nodes);
      // dashboard stats
      const sn = qs('#stat_nodes');
      if(sn) sn.textContent = String(nodes.length);
      // compute total rules/active using topology endpoint
      try{
        const topo = await api('GET','/api/topology');
        const rules = topo.rules || [];
        const active = rules.filter(r=>!r.disabled).length;
        const sr = qs('#stat_rules');
        const sa = qs('#stat_active');
        if(sr) sr.textContent = String(rules.length);
        if(sa) sa.textContent = String(active);
      }catch(e){/* ignore */}
    }catch(err){
      if(t) t.innerHTML = `<tr><td colspan="4" class="muted">${err.message}</td></tr>`;
      toast(err.message,'danger');
    }
  }

  function renderNodesTable(nodes){
    const t = qs('#nodes_table tbody');
    if(!t) return;
    if(!nodes.length){
      t.innerHTML = `<tr><td colspan="4" class="muted">暂无节点，点右上角“添加节点”</td></tr>`;
      return;
    }
    t.innerHTML = nodes.map(n=>{
      return `<tr>
        <td>
          <div class="mono">${escapeHtml(n.id)}</div>
          <div class="muted">${escapeHtml(n.name)}</div>
        </td>
        <td class="mono">${escapeHtml(n.base_url)}</td>
        <td><span class="muted">点击进入查看规则/拓扑/负载均衡</span></td>
        <td style="text-align:right">
          <a class="btn" href="/nodes/${encodeURIComponent(n.id)}">管理</a>
        </td>
      </tr>`;
    }).join('');
  }

  async function deleteNode(id){
    if(!confirm('确定删除该节点？')) return;
    try{
      await api('DELETE',`/api/nodes/${encodeURIComponent(id)}`);
      toast('已删除','ok');
      location.href='/nodes';
    }catch(e){ toast(e.message,'danger'); }
  }

  // -------- Node Detail / Rules --------

  async function loadNode(nodeId){
    state.currentNodeId = nodeId;
    await loadNodeRules(nodeId);
  }

  async function loadNodeRules(nodeId){
    const box = qs('#rules_table');
    if(box) box.innerHTML = `<div class="muted">加载规则中…</div>`;
    try{
      const data = await api('GET', `/api/nodes/${encodeURIComponent(nodeId)}/rules`);
      const eps = data.endpoints || [];
      state.currentRules = eps;
      renderRulesTable(eps);
      renderNodeTopology(eps);
      renderLB(eps);
    }catch(e){
      if(box) box.innerHTML = `<div class="muted">${e.message}</div>`;
      toast(e.message,'danger');
    }
  }

  function renderRulesTable(endpoints){
    const wrap = qs('#rules_table');
    if(!wrap) return;
    if(!endpoints.length){
      wrap.innerHTML = `<div class="muted">暂无规则</div>`;
      return;
    }
    wrap.innerHTML = `
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>端口</th>
              <th>类型</th>
              <th>目标</th>
              <th>策略</th>
              <th>连接</th>
              <th style="text-align:right">操作</th>
            </tr>
          </thead>
          <tbody>
            ${endpoints.map(ep => {
              const lp = parseHostPort(ep.listen).port || '-';
              const tgs = targetsOf(ep);
              const bal = ep.balance || 'round_robin';
              const dis = !!ep.disabled;
              const conn = ep._metrics?.connections ?? '-';
              return `
                <tr class="${dis ? 'row-disabled':''}">
                  <td class="mono">:${escapeHtml(lp)}</td>
                  <td>${badge(ruleType(ep), isWssSender(ep)?'purple':(isWssReceiver(ep)?'blue':'gray'))} ${dis?badge('暂停','warn'):badge('运行','ok')}</td>
                  <td>
                    <div class="targets">
                      ${tgs.slice(0,3).map(t=>`<div class="mono">${escapeHtml(t)}</div>`).join('')}
                      ${tgs.length>3?`<div class="muted">… 共 ${tgs.length} 个</div>`:''}
                    </div>
                  </td>
                  <td>${badge(String(bal).replace('round_robin','RR').replace('ip_hash','IP-HASH'),'')}${tgs.length>1?` ${badge('LB','mint')}`:''}</td>
                  <td class="mono">${escapeHtml(String(conn))}</td>
                  <td style="text-align:right">
                    <button class="btn" onclick="UI.openEditRule('${escapeHtml(ep.id)}')">编辑</button>
                    <button class="btn" onclick="UI.toggleRule('${escapeHtml(ep.id)}', ${dis ? 'false':'true'})">${dis?'恢复':'暂停'}</button>
                    <button class="btn danger" onclick="UI.removeRule('${escapeHtml(ep.id)}')">删除</button>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  async function toggleRule(ruleId, disabled){
    const nodeId = state.currentNodeId;
    try{
      await api('POST', `/api/nodes/${encodeURIComponent(nodeId)}/rules/${encodeURIComponent(ruleId)}/toggle`, {disabled});
      toast(disabled ? '已暂停' : '已恢复', 'ok');
      await loadNodeRules(nodeId);
    }catch(e){ toast(e.message,'danger'); }
  }

  async function removeRule(ruleId){
    const nodeId = state.currentNodeId;
    if(!confirm('确定删除该规则？')) return;
    try{
      await api('DELETE', `/api/nodes/${encodeURIComponent(nodeId)}/rules/${encodeURIComponent(ruleId)}`);
      toast('已删除','ok');
      await loadNodeRules(nodeId);
    }catch(e){ toast(e.message,'danger'); }
  }

  async function applyNode(){
    const nodeId = state.currentNodeId;
    try{
      toast('正在应用配置并重启 realm…','info');
      await api('POST', `/api/nodes/${encodeURIComponent(nodeId)}/apply`);
      toast('已应用','ok');
      await loadNodeRules(nodeId);
    }catch(e){ toast(e.message,'danger'); }
  }

  // -------- Modals --------

  function openModal(title, contentHTML){
    const old = qs('#modal_mask');
    if(old) old.remove();
    const mask = document.createElement('div');
    mask.id = 'modal_mask';
    mask.className = 'modal-mask';
    mask.innerHTML = `
      <div class="modal" role="dialog" aria-modal="true">
        <div class="modal-head">
          <div class="modal-title">${escapeHtml(title)}</div>
          <button class="iconbtn" onclick="UI.closeModal()">✕</button>
        </div>
        <div class="modal-body">${contentHTML}</div>
      </div>
    `;
    mask.addEventListener('click', (e)=>{
      if(e.target === mask) closeModal();
    });
    document.body.appendChild(mask);
  }

  function closeModal(){
    const m = qs('#modal_mask');
    if(m) m.remove();
  }

  // Add Node
  function openAddNode(){
    openModal('添加节点', `
      <div class="form">
        <label>节点名称</label>
        <input id="node_name" placeholder="例如：HK-1" />
        <label>Agent 地址</label>
        <input id="node_url" placeholder="http://1.2.3.4:18700" />
        <label>API Key</label>
        <input id="node_key" placeholder="Agent 安装时生成的 AGENT_API_KEY" />
        <div class="row end mt">
          <button class="btn" onclick="UI.closeModal()">取消</button>
          <button class="btn primary" onclick="UI.submitAddNode()">保存</button>
        </div>
      </div>
    `);
  }

  async function submitAddNode(){
    const name = (qs('#node_name').value||'').trim();
    const base_url = (qs('#node_url').value||'').trim();
    const api_key = (qs('#node_key').value||'').trim();
    try{
      await api('POST','/api/nodes',{name, base_url, api_key});
      toast('已添加','ok');
      closeModal();
      await loadNodes();
    }catch(e){ toast(e.message,'danger'); }
  }

  // Rule Editor
  function openEditRule(ruleId){
    const ep = state.currentRules.find(x=>x.id===ruleId);
    if(!ep){ toast('规则不存在','danger'); return; }
    const tgs = targetsOf(ep);
    const lp = parseHostPort(ep.listen);
    const ex = ep.extra_config || {};
    let kind = 'tcp';
    if(isWssSender(ep)) kind='wss_sender';
    if(isWssReceiver(ep)) kind='wss_receiver';

    openModal('编辑规则', `
      <div class="form grid2">
        <div class="col">
          <label>类型</label>
          <select id="rule_kind" onchange="UI.ruleKindChanged()">
            <option value="tcp" ${kind==='tcp'?'selected':''}>TCP/UDP</option>
            <option value="wss_sender" ${kind==='wss_sender'?'selected':''}>WSS 发送</option>
            <option value="wss_receiver" ${kind==='wss_receiver'?'selected':''}>WSS 接收</option>
          </select>

          <label>Listen</label>
          <div class="row">
            <input id="rule_listen_host" value="${escapeAttr(lp.host||'0.0.0.0')}" placeholder="0.0.0.0" />
            <input id="rule_listen_port" value="${escapeAttr(lp.port||'')}" placeholder="端口" style="width:120px" />
          </div>

          <label>Remote 目标（多行，每行一个 host:port）</label>
          <textarea id="rule_targets" rows="6" placeholder="1.2.3.4:443\n5.6.7.8:443">${escapeHtml(tgs.join('\n'))}</textarea>

          <label>负载均衡策略</label>
          <select id="rule_balance">
            <option value="round_robin" ${(ep.balance||'round_robin')==='round_robin'?'selected':''}>Round Robin</option>
            <option value="ip_hash" ${(ep.balance||'round_robin')==='ip_hash'?'selected':''}>IP Hash</option>
          </select>

          <div class="row mt">
            <label class="chk"><input id="rule_disabled" type="checkbox" ${ep.disabled?'checked':''}/> 暂停</label>
          </div>
        </div>

        <div class="col">
          <div class="wss-box" id="wss_box">
            <div class="muted">WSS 参数</div>
            <div class="grid2">
              <div>
                <label>Host</label>
                <input id="wss_host" value="${escapeAttr(ex.remote_ws_host||ex.listen_ws_host||'')}" placeholder="www.bing.com" />
              </div>
              <div>
                <label>Path</label>
                <input id="wss_path" value="${escapeAttr(ex.remote_ws_path||ex.listen_ws_path||'/ws')}" placeholder="/ws" />
              </div>
            </div>

            <div class="row mt" id="pair_row">
              <button class="btn" onclick="UI.makePairCode()">生成配对码</button>
              <button class="btn" onclick="UI.pastePairCode()">粘贴配对码</button>
            </div>
            <textarea id="pair_code" rows="4" placeholder="配对码（发送端生成 → 接收端粘贴）"></textarea>

            <div class="muted" style="margin-top:8px">提示：发送端只需要 host/path；接收端粘贴配对码会自动填充。</div>
          </div>

          <div class="card mini mt">
            <div class="card-title">预览</div>
            <div class="muted">listen → remote（以及 WSS 叠加参数）</div>
            <div class="mono" id="rule_preview" style="margin-top:8px"></div>
          </div>

          <div class="row end mt">
            <button class="btn" onclick="UI.closeModal()">取消</button>
            <button class="btn primary" onclick="UI.submitRuleEdit('${escapeHtml(ruleId)}')">保存</button>
          </div>
        </div>
      </div>
    `);

    setTimeout(()=>{
      ruleKindChanged();
      updatePreview();
      qsa('#rule_listen_host,#rule_listen_port,#rule_targets,#rule_balance,#wss_host,#wss_path,#rule_kind').forEach(el=>{
        el.addEventListener('input', updatePreview);
        el.addEventListener('change', updatePreview);
      });
    }, 30);
  }

  function ruleKindChanged(){
    const kind = (qs('#rule_kind')?.value)||'tcp';
    const box = qs('#wss_box');
    if(!box) return;
    box.style.display = kind==='tcp' ? 'none' : 'block';
    const pair = qs('#pair_row');
    if(pair) pair.style.display = (kind==='wss_sender' || kind==='wss_receiver') ? 'flex' : 'none';
  }

  function updatePreview(){
    const lh = (qs('#rule_listen_host')?.value||'').trim();
    const lp = (qs('#rule_listen_port')?.value||'').trim();
    const tg = (qs('#rule_targets')?.value||'').trim().split(/\n+/).map(x=>x.trim()).filter(Boolean);
    const kind = (qs('#rule_kind')?.value)||'tcp';
    const wh = (qs('#wss_host')?.value||'').trim();
    const wp = (qs('#wss_path')?.value||'').trim();
    const bal = (qs('#rule_balance')?.value)||'round_robin';

    let txt = `${lh}:${lp}  →  ${tg.join(', ') || '-'}`;
    if(kind !== 'tcp'){
      txt += `\nWSS: host=${wh||'-'} path=${wp||'-'}  (${kind==='wss_sender'?'发送':'接收'})`;
    }
    txt += `\nLB: ${bal}`;
    const p = qs('#rule_preview');
    if(p) p.textContent = txt;
  }

  function makePairCode(){
    const wh = (qs('#wss_host')?.value||'').trim();
    const wp = (qs('#wss_path')?.value||'/ws').trim();
    const obj = {host:wh, path:wp};
    const raw = JSON.stringify(obj);
    const b64 = btoa(unescape(encodeURIComponent(raw)))
      .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    const ta = qs('#pair_code');
    if(ta) ta.value = b64;
    toast('已生成配对码','ok');
  }

  function pastePairCode(){
    const ta = qs('#pair_code');
    if(!ta) return;
    const code = (ta.value||'').trim();
    try{
      const b64 = code.replace(/-/g,'+').replace(/_/g,'/');
      const pad = '='.repeat((4 - (b64.length % 4)) % 4);
      const jsonStr = decodeURIComponent(escape(atob(b64 + pad)));
      const obj = JSON.parse(jsonStr);
      if(obj.host) qs('#wss_host').value = obj.host;
      if(obj.path) qs('#wss_path').value = obj.path;
      toast('配对码已解析','ok');
      updatePreview();
    }catch(e){
      toast('配对码无效','danger');
    }
  }

  async function submitRuleEdit(ruleId){
    const nodeId = state.currentNodeId;
    const lh = (qs('#rule_listen_host').value||'0.0.0.0').trim();
    const lp = (qs('#rule_listen_port').value||'').trim();
    const tg = (qs('#rule_targets').value||'').trim().split(/\n+/).map(x=>x.trim()).filter(Boolean);
    const bal = (qs('#rule_balance').value||'round_robin').trim();
    const kind = (qs('#rule_kind').value||'tcp');
    const disabled = !!qs('#rule_disabled').checked;

    if(!lp){ toast('listen 端口不能为空','danger'); return; }
    if(!tg.length){ toast('remote 目标不能为空','danger'); return; }

    const listen = `${lh}:${lp}`;

    // build rule JSON compatible with realm.sh + agent
    const epOld = state.currentRules.find(x=>x.id===ruleId) || {};
    const ep = JSON.parse(JSON.stringify(epOld));
    ep.listen = listen;
    ep.balance = bal;
    ep.disabled = disabled;

    // targets -> remote / remotes
    if(tg.length === 1) ep.remote = tg[0];
    else ep.remote = tg;
    delete ep.remotes;
    delete ep.extra_remotes;

    // WSS
    if(kind==='tcp'){
      delete ep.extra_config;
    } else {
      const wh = (qs('#wss_host').value||'').trim();
      const wp = (qs('#wss_path').value||'/ws').trim();
      if(!wh || !wp){ toast('WSS Host/Path 不能为空','danger'); return; }
      ep.extra_config = ep.extra_config || {};
      if(kind==='wss_sender'){
        ep.extra_config = {
          remote_transport: 'ws',
          remote_ws_host: wh,
          remote_ws_path: wp,
          remote_tls_enabled: true,
          remote_tls_sni: wh,
          remote_tls_insecure: true,
        };
      } else {
        ep.extra_config = {
          listen_transport: 'ws',
          listen_ws_host: wh,
          listen_ws_path: wp,
          listen_tls_enabled: true,
          listen_tls_servername: wh,
        };
      }
    }

    try{
      await api('PUT', `/api/nodes/${encodeURIComponent(nodeId)}/rules/${encodeURIComponent(ruleId)}`, ep);
      toast('已保存','ok');
      closeModal();
      await loadNodeRules(nodeId);
    }catch(e){ toast(e.message,'danger'); }
  }

  // -------- Topology --------

  function renderNodeTopology(endpoints){
    const box = qs('#topology_canvas');
    if(!box) return;
    box.innerHTML = '';

    const rules = endpoints.map(ep=>{
      const lp = parseHostPort(ep.listen).port || '';
      return {
        id: ep.id,
        listen: ep.listen,
        port: lp,
        disabled: !!ep.disabled,
        type: ruleType(ep),
        targets: targetsOf(ep),
      };
    });

    // build layout columns
    const left = rules.map(r=>({key:r.id, text:`:${r.port}`, sub:r.type, disabled:r.disabled}));
    const mid = rules.map(r=>({key:r.id, text:`规则 ${r.port}`, sub:r.listen, disabled:r.disabled}));

    // unique targets
    const tgtMap = new Map();
    rules.forEach(r=>r.targets.forEach(t=>tgtMap.set(t, t)));
    const right = Array.from(tgtMap.keys()).map(t=>({key:t, text:t, sub:'remote'}));

    // positions
    const w = box.clientWidth || 980;
    const colX = [60, Math.floor(w*0.45), Math.floor(w*0.84)];
    const rowH = 54;
    const padY = 40;

    const svg = document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('width','100%');
    svg.setAttribute('height', String(Math.max(padY*2 + Math.max(left.length, right.length)*rowH, 300)));
    svg.classList.add('topo-svg');

    // helper to place nodes
    const pos = { left:{}, mid:{}, right:{} };
    left.forEach((n,i)=>{ pos.left[n.key]={x:colX[0], y:padY + i*rowH}; });
    mid.forEach((n,i)=>{ pos.mid[n.key]={x:colX[1], y:padY + i*rowH}; });
    right.forEach((n,i)=>{ pos.right[n.key]={x:colX[2], y:padY + i*rowH}; });

    function line(x1,y1,x2,y2, cls){
      const l = document.createElementNS('http://www.w3.org/2000/svg','line');
      l.setAttribute('x1',x1); l.setAttribute('y1',y1);
      l.setAttribute('x2',x2); l.setAttribute('y2',y2);
      l.setAttribute('class', cls);
      svg.appendChild(l);
    }

    // edges: left->mid + mid->right for each target
    rules.forEach(r=>{
      const a = pos.left[r.id];
      const b = pos.mid[r.id];
      if(!a||!b) return;
      line(a.x+18,a.y+10,b.x-18,b.y+10, r.disabled?'edge disabled':'edge');
      r.targets.forEach(t=>{
        const c = pos.right[t];
        if(c) line(b.x+18,b.y+10,c.x-18,c.y+10, r.disabled?'edge disabled':'edge');
      });
    });

    box.appendChild(svg);

    // render cards as absolute layers
    const layer = document.createElement('div');
    layer.className = 'topology-layer';
    box.appendChild(layer);

    function nodeDiv(x,y,title,sub,cls=''){
      const d = document.createElement('div');
      d.className = `topo-node ${cls}`;
      d.style.left = `${x}px`;
      d.style.top = `${y}px`;
      d.innerHTML = `<div class="t">${escapeHtml(title)}</div><div class="s">${escapeHtml(sub||'')}</div>`;
      layer.appendChild(d);
    }

    left.forEach(n=>{
      const p = pos.left[n.key];
      nodeDiv(p.x, p.y, n.text, n.sub, n.disabled?'off':'');
    });
    mid.forEach(n=>{
      const p = pos.mid[n.key];
      nodeDiv(p.x, p.y, '规则', n.sub, n.disabled?'off':'');
    });
    right.forEach(n=>{
      const p = pos.right[n.key];
      nodeDiv(p.x, p.y, n.text, '目标', 'target');
    });
  }

  async function renderGlobalTopology(){
    const box = qs('#global_topology_canvas');
    if(!box) return;
    box.innerHTML = '<div class="muted">加载中…</div>';
    try{
      const topo = await api('GET','/api/topology');
      // Group by node
      const groups = topo.nodes || [];
      const rules = topo.rules || [];
      box.innerHTML='';
      if(!groups.length){ box.innerHTML='<div class="muted">暂无节点</div>'; return; }

      groups.forEach(n=>{
        const block = document.createElement('div');
        block.className = 'card mini topo-block';
        block.innerHTML = `<div class="row between"><div><div class="card-title">${escapeHtml(n.name)}</div><div class="muted mono">${escapeHtml(n.base_url)}</div></div><a class="btn" href="/nodes/${encodeURIComponent(n.id)}">查看</a></div><div class="topology" id="topo_${n.id}"></div>`;
        box.appendChild(block);
        const eps = rules.filter(r=>r.node_id===n.id).map(r=>r.rule);
        setTimeout(()=>{ renderNodeTopologyTo(qs(`#topo_${CSS.escape(n.id)}`), eps); }, 10);
      });
    }catch(e){
      box.innerHTML = `<div class="muted">${escapeHtml(e.message)}</div>`;
      toast(e.message,'danger');
    }
  }

  function renderNodeTopologyTo(container, endpoints){
    // same as renderNodeTopology but to custom container
    const tmp = qs('#topology_canvas');
    const old = state.currentRules;
    const oldNode = state.currentNodeId;
    // Use local function with slight change
    const save = document.createElement('div');
    save.style.width = '100%';
    save.style.height = '240px';
    container.appendChild(save);

    // quick simple view: list rules and targets
    const list = document.createElement('div');
    list.className='simple-topo';
    list.innerHTML = endpoints.map(ep=>{
      const lp = parseHostPort(ep.listen).port || '';
      const tgs = targetsOf(ep);
      return `<div class="simple-topo-row">
        <div class="mono">:${escapeHtml(lp)}</div>
        <div class="muted">→</div>
        <div>${tgs.map(t=>`<span class="pill mono">${escapeHtml(t)}</span>`).join(' ')}</div>
      </div>`;
    }).join('');
    container.appendChild(list);
  }

  // -------- LB --------

  function renderLB(endpoints){
    const box = qs('#lb_canvas');
    if(!box) return;
    const multi = endpoints.filter(ep=>targetsOf(ep).length>1);
    if(!multi.length){
      box.innerHTML = `<div class="muted">暂无多目标负载均衡规则</div>`;
      return;
    }
    box.innerHTML = multi.map(ep=>{
      const lp = parseHostPort(ep.listen).port || '';
      const tgs = targetsOf(ep);
      const bal = ep.balance || 'round_robin';
      const algoName = bal==='ip_hash' ? 'IP Hash' : 'Round Robin';
      const seq = tgs.map((_,i)=>`T${i+1}`).join(' → ');
      return `
        <div class="card mini lb-card ${ep.disabled?'row-disabled':''}">
          <div class="row between">
            <div>
              <div class="card-title">端口 :${escapeHtml(lp)} <span class="muted">(${escapeHtml(ruleType(ep))})</span></div>
              <div class="muted">算法：${escapeHtml(algoName)}  ·  目标数：${tgs.length}</div>
            </div>
            <div>${ep.disabled?badge('暂停','warn'):badge('运行','ok')}</div>
          </div>
          <div class="lb-targets">
            ${tgs.map((t,i)=>`<div class="lb-target"><div class="mono">T${i+1}</div><div class="mono small">${escapeHtml(t)}</div></div>`).join('')}
          </div>
          <div class="muted">${bal==='round_robin' ? `轮询顺序示例：${seq}` : '同一来源 IP 通常固定映射到同一目标（粘性更强）'}</div>
        </div>
      `;
    }).join('');
  }

  // -------- Helpers --------

  function escapeHtml(str){
    return String(str ?? '').replace(/[&<>"']/g, s=>({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[s]));
  }
  function escapeAttr(str){
    return escapeHtml(str).replace(/\n/g,' ');
  }

  // -------- Exposed --------

  return {
    state,
    toast,
    api,
    loadNodes,
    openAddNode,
    submitAddNode,
    deleteNode,
    loadNode,
    loadNodeRules,
    applyNode,
    openEditRule,
    submitRuleEdit,
    toggleRule,
    removeRule,
    openModal,
    closeModal,
    ruleKindChanged,
    makePairCode,
    pastePairCode,
    renderGlobalTopology,
    renderNodeTopology,
    refreshNode: ()=> loadNodeRules(state.currentNodeId),
  };
})();

window.UI = UI;
