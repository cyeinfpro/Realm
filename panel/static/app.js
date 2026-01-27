async function fetchJSON(url, options={}){
  const res = await fetch(url, {
    headers: {"Content-Type":"application/json"},
    credentials: "same-origin",
    ...options,
  });
  const text = await res.text();
  let data;
  try{ data = text ? JSON.parse(text) : {}; }catch(e){ data = {ok:false,error:text}; }
  if(!res.ok){
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}


async function loadNodesList(){
  try{
    const data = await fetchJSON('/api/nodes');
    if(data && data.ok && Array.isArray(data.nodes)){
      NODES_LIST = data.nodes;
      populateReceiverSelect();
      populateIntranetReceiverSelect();
    }
  }catch(e){
    // ignore
  }
}

function populateIntranetReceiverSelect(){
  const sel = document.getElementById('f_intranet_receiver_node');
  if(!sel) return;
  const currentId = window.__NODE_ID__;
  const keep = sel.value;
  sel.innerHTML = '<option value="">请选择内网节点…</option>';
  for(const n of (NODES_LIST||[])){
    if(!n || n.id == null) continue;
    if(String(n.id) === String(currentId)) continue;
    if(!n.is_private) continue;
    const opt = document.createElement('option');
    opt.value = String(n.id);
    const show = n.name ? n.name : ('Node #' + n.id);
    let host = '';
    try{
      const u = new URL(n.base_url.includes('://') ? n.base_url : ('http://' + n.base_url));
      host = u.hostname || '';
    }catch(e){}
    opt.textContent = host ? `${show} (${host})` : show;
    sel.appendChild(opt);
  }
  if(keep) sel.value = keep;
}

function populateReceiverSelect(){
  const sel = document.getElementById('f_wss_receiver_node');
  if(!sel) return;
  const currentId = window.__NODE_ID__;
  const keep = sel.value;
  sel.innerHTML = '<option value="">（不选择=手动配对码模式）</option>';
  for(const n of (NODES_LIST||[])){
    if(!n || n.id == null) continue;
    if(String(n.id) === String(currentId)) continue;
    const opt = document.createElement('option');
    opt.value = String(n.id);
    const show = n.name ? n.name : ('Node #' + n.id);
    let host = '';
    try{
      const u = new URL(n.base_url.includes('://') ? n.base_url : ('http://' + n.base_url));
      host = u.hostname || '';
    }catch(e){}
    opt.textContent = host ? `${show} (${host})` : show;
    sel.appendChild(opt);
  }
  if(keep) sel.value = keep;
}

function q(id){ return document.getElementById(id); }

let CURRENT_POOL = null;
let CURRENT_EDIT_INDEX = -1;
let CURRENT_STATS = null;
let CURRENT_SYS = null;
let PENDING_COMMAND_TEXT = '';
let NODES_LIST = [];

// Remove ?edit=1 from current URL (used for "auto open edit modal" from dashboard)
function stripEditQueryParam(){
  try{
    const u = new URL(window.location.href);
    if(!u.searchParams.has('edit')) return;
    u.searchParams.delete('edit');
    const qs = u.searchParams.toString();
    const next = u.pathname + (qs ? ('?' + qs) : '') + (u.hash || '');
    history.replaceState({}, '', next);
  }catch(_e){}
}

// Rules filter for quick search (listen / remote)
let RULE_FILTER = '';
function setRuleFilter(v){
  RULE_FILTER = (v || '').trim();
  renderRules();
}
window.setRuleFilter = setRuleFilter;

function showTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tabpane').forEach(p=>p.classList.remove('show'));
  document.querySelector(`.tab[data-tab="${name}"]`).classList.add('active');
  q(`tab-${name}`).classList.add('show');
}

function wssMode(e){
  // intranet tunnels are handled separately
  if(intranetMode(e)) return 'intranet';
  const ex = e.extra_config || {};
  const listenTransport = e.listen_transport || ex.listen_transport || '';
  const remoteTransport = e.remote_transport || ex.remote_transport || '';
  const hasLisWs = String(listenTransport).includes('ws') || ex.listen_ws_host || ex.listen_ws_path || ex.listen_tls_servername;
  const hasRemWs = String(remoteTransport).includes('ws') || ex.remote_ws_host || ex.remote_ws_path || ex.remote_tls_sni;
  if(hasLisWs || hasRemWs) return 'wss';
  return 'tcp';
}

function intranetMode(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  return !!(ex && (ex.intranet_role || ex.intranet_peer_node_id || ex.intranet_token || ex.intranet_server_port));
}

function tunnelMode(e){
  const m = wssMode(e);
  return m;
}

function intranetIsLocked(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  return !!(ex && (ex.intranet_lock === true || ex.intranet_role === 'client'));
}

function endpointType(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  if(ex && ex.intranet_role){
    if(ex.intranet_role === 'client') return '内网穿透(内网出口·同步)';
    if(ex.intranet_role === 'server') return '内网穿透(公网入口)';
    return '内网穿透';
  }
  if(ex && ex.sync_id){
    if(ex.sync_role === 'receiver') return 'WSS隧道(接收·同步)';
    if(ex.sync_role === 'sender') return 'WSS隧道(发送·同步)';
  }
  const mode = wssMode(e);
  if(mode === 'wss') return 'WSS隧道';
  if(mode === 'intranet') return '内网穿透';
  return 'TCP/UDP';
}

function formatRemoteForInput(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  if(ex && ex.sync_role === 'sender' && Array.isArray(ex.sync_original_remotes)){
    return ex.sync_original_remotes.join('\n');
  }
  const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
  return rs.join('\n');
}

function formatRemote(e){
  const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
  return rs.join('\n');
}

function renderRemoteTargets(e, idx){
  const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
  if(!rs.length) return '<span class="muted">—</span>';
  const MAX = 2;
  const shown = rs.slice(0, MAX);
  const more = Math.max(0, rs.length - MAX);
  const chips = shown.map(r=>`<span class="remote-chip mono" title="${escapeHtml(r)}">${escapeHtml(r)}</span>`).join('');
  const moreHtml = more>0 ? `<button class="pill ghost remote-more" type="button" data-idx="${idx}" data-more="${more}" aria-expanded="false" title="展开更多目标">+${more}</button>` : '';
  const extraHtml = more>0 ? `<div class="remote-extra" hidden>
    ${rs.slice(MAX).map(r=>`<div class="remote-line"><span class="remote-chip mono" title="${escapeHtml(r)}">${escapeHtml(r)}</span></div>`).join('')}
  </div>` : '';
  return `<div class="remote-wrap">${chips}${moreHtml}${extraHtml}</div>`;
}

// 表格视图：直接展开成多行（不再使用 +N）
function renderRemoteTargetsExpanded(e){
  const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
  if(!rs.length) return '<span class="muted">—</span>';
  const lines = rs.map(r=>`<div class="remote-line"><span class="remote-chip mono" title="${escapeHtml(r)}">${escapeHtml(r)}</span></div>`).join('');
  return `<div class="remote-wrap expanded">${lines}</div>`;
}

// 表格视图：连通检测直接多行展示（不使用 +N）
function renderHealthExpanded(healthList, statsError){
  if(statsError){
    return `<span class="muted">检测失败：${escapeHtml(statsError)}</span>`;
  }
  if(!Array.isArray(healthList) || healthList.length === 0){
    return '<span class="muted">暂无检测数据</span>';
  }
  function friendlyError(err){
    const s = String(err || '').trim();
    if(!s) return '';
    const t = s.toLowerCase();
    // 内网穿透握手错误码（agent 提供）
    if(t === 'no_client_connected') return '未检测到客户端连接';
    if(t === 'client_not_running') return '客户端未启动';
    if(t === 'server_not_running') return '入口未启动';
    if(t === 'client_not_running') return '客户端未启动';
    if(t === 'peer_is_http_proxy') return '走了HTTP反代/代理';
    if(t === 'sig_invalid') return '签名校验失败';
    if(t === 'magic_mismatch') return '协议不匹配';
    if(t === 'version_mismatch') return '版本不匹配';
    if(t === 'ts_skew') return '时间偏差过大';
    if(t === 'pong_timeout') return '心跳超时';
    if(t === 'control_closed') return '连接断开';
    if(t.startsWith('dial_failed')) return '连接失败';
    if(t.startsWith('dial_tls_failed')) return 'TLS握手失败';
    if(t.startsWith('tls_verify_failed')) return '证书校验失败';
    if(t.startsWith('hello_timeout')) return '握手超时';
    if(t.startsWith('hello_')) return '握手失败';
    if(t.includes('timed out') || t.includes('timeout')) return '超时';
    if(t.includes('refused')) return '拒绝连接';
    if(t.includes('no route')) return '无路由';
    if(t.includes('name or service not known') || t.includes('temporary failure in name resolution')) return 'DNS失败';
    if(t.includes('network is unreachable')) return '网络不可达';
    if(t.includes('permission denied')) return '无权限';
    return s.length > 28 ? (s.slice(0, 28) + '…') : s;
  }
  const lines = healthList.map((item)=>{
    const isUnknown = item && item.ok == null;
    const ok = !!item.ok;
    const latencyMs = item && item.latency_ms != null ? item.latency_ms : item && item.latency != null ? item.latency : null;
    const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : ((item && item.kind === 'handshake') ? '未连接' : '离线'));
    const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
    const title = !isUnknown && !ok ? `${(item && item.kind === 'handshake') ? '未连接' : '离线'}原因：${String(item.error || item.message || '').trim()}` : '';
    return `<div class="health-item" title="${escapeHtml(title)}">
      <span class="pill ${isUnknown ? 'warn' : (ok ? 'ok' : 'bad')}">${escapeHtml(label)}</span>
      <span class="mono health-target">${escapeHtml(item.target)}</span>
      ${reason ? `<span class="health-reason">(${escapeHtml(reason)})</span>` : ''}
    </div>`;
  }).join('');
  return `<div class="health-wrap expanded">${lines}</div>`;
}

function showRemoteDetail(idx){
  try{
    const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
    const e = eps[idx] || {};
    const ex = e.extra_config || {};
    // 对于同步 sender，优先展示原始目标
    if(ex && ex.sync_role === 'sender' && Array.isArray(ex.sync_original_remotes) && ex.sync_original_remotes.length){
      openCommandModal('Remote 目标详情（原始目标）', ex.sync_original_remotes.join('\n'));
      return;
    }
    const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
    openCommandModal('Remote 目标详情', rs.join('\n') || '—');
  }catch(err){
    openCommandModal('Remote 目标详情', '暂无详情');
  }
}

function statusPill(e){
  if(e.disabled) return '<span class="pill warn">已暂停</span>';
  return '<span class="pill ok">运行</span>';
}

function escapeHtml(text){
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatBytes(value){
  const num = Number(value) || 0;
  if(num <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = num;
  while(val >= 1024 && idx < units.length - 1){
    val /= 1024;
    idx += 1;
  }
  return `${val.toFixed(val >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}


function formatBps(value){
  const v = Number(value) || 0;
  if(v <= 0) return '0 B/s';
  return formatBytes(v) + '/s';
}

function formatDuration(sec){
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m2 = Math.floor((s % 3600) / 60);
  const s2 = s % 60;
  const parts = [];
  if(d) parts.push(d + '天');
  if(d || h) parts.push(h + '小时');
  if(d || h || m2) parts.push(m2 + '分');
  parts.push(s2 + '秒');
  return parts.join(' ');
}

// Compact duration for dashboard tiles: keep at most 2 units, use d/h/m/s (more professional & shorter)
function formatDurationShort(sec){
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m2 = Math.floor((s % 3600) / 60);
  const s2 = s % 60;
  if(d > 0){
    return h > 0 ? `${d}d ${h}h` : `${d}d`;
  }
  if(h > 0){
    return m2 > 0 ? `${h}h ${m2}m` : `${h}h`;
  }
  if(m2 > 0){
    // keep seconds only when very small to avoid flicker; otherwise show minutes only
    if(m2 < 10 && s2 > 0) return `${m2}m ${s2}s`;
    return `${m2}m`;
  }
  return `${s2}s`;
}

function parseDateTimeLocal(str){
  const t = String(str || '').trim();
  if(!t || t === '-') return null;
  // Supports: YYYY-MM-DD HH:MM:SS / YYYY-MM-DDTHH:MM:SS / with optional ms
  const m = t.match(/(\d{4})-(\d{1,2})-(\d{1,2})[T\s](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?/);
  if(!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]) - 1;
  const d = Number(m[3]);
  const hh = Number(m[4]);
  const mm = Number(m[5]);
  const ss = Number(m[6] || 0);
  const dt = new Date(y, mo, d, hh, mm, ss);
  if(Number.isNaN(dt.getTime())) return null;
  return dt;
}

// Compact "time ago" for dashboard tiles
function formatAgoShort(dateStr){
  const dt = parseDateTimeLocal(dateStr);
  if(!dt) return (dateStr && String(dateStr).trim()) ? String(dateStr).trim() : '-';
  const diff = Math.max(0, Math.floor((Date.now() - dt.getTime()) / 1000));
  if(diff < 5) return '刚刚';
  if(diff < 60) return `${diff}s`;
  const m2 = Math.floor(diff / 60);
  if(m2 < 60) return `${m2}m`;
  const h = Math.floor(m2 / 60);
  if(h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if(d < 7) return `${d}d`;
  // older: show MM-DD (keep full value in title)
  const mm = String(dt.getMonth() + 1).padStart(2, '0');
  const dd = String(dt.getDate()).padStart(2, '0');
  return `${mm}-${dd}`;
}

function refreshDashboardLastSeenShort(){
  const els = document.querySelectorAll('[data-last-seen]');
  els.forEach((el)=>{
    const raw = el.getAttribute('data-last-seen') || '';
    const mode = (el.getAttribute('data-last-seen-mode') || '').trim();
    // Keep full raw time on elements that explicitly request it
    if(mode === 'full' || mode === 'raw'){
      const v = raw && raw.trim() ? raw.trim() : '-';
      if(v !== '-') el.setAttribute('title', v);
      el.textContent = v;
      return;
    }
    // Default: show compact time ago (keep full in title)
    if(raw && raw.trim()) el.setAttribute('title', raw.trim());
    el.textContent = formatAgoShort(raw);
  });
}

function setProgress(elId, pct){
  const el = document.getElementById(elId);
  if(!el) return;
  const v = Math.max(0, Math.min(100, Number(pct) || 0));
  el.style.width = v.toFixed(0) + '%';
}

function setProgressEl(el, pct){
  if(!el) return;
  const v = Math.max(0, Math.min(100, Number(pct) || 0));
  el.style.width = v.toFixed(0) + '%';
}

// Dashboard node tile: render mini system info inside a node card
function renderSysMini(cardEl, sys){
  if(!cardEl) return;
  // New compact dashboard tiles (index.html)
  const hint = cardEl.querySelector('[data-sys="hint"]');
  const setText = (key, text) => {
    const el = cardEl.querySelector(`[data-sys="${key}"]`);
    if(el) el.textContent = text;
  };
  const setTitle = (key, title) => {
    const el = cardEl.querySelector(`[data-sys="${key}"]`);
    if(el) el.setAttribute('title', title || '');
  };
  const setBar = (key, pct) => {
    const el = cardEl.querySelector(`[data-sys-bar="${key}"]`);
    setProgressEl(el, pct);
  };

  // Offline or missing data
  if(!sys || sys.error){
    setText('uptime', '—');
    setText('traffic', '—');
    setText('rate', '—');
    setText('cpuPct', '—');
    setText('memText', '—');
    setText('diskText', '—');
    setBar('cpu', 0);
    setBar('mem', 0);
    setBar('disk', 0);
    if(hint){
      const raw = String((sys && sys.error) ? sys.error : '').toLowerCase();
      let msg = '系统信息暂无数据（等待 Agent 上报）';
      if(raw.includes('offline')) msg = '节点离线（系统信息暂停刷新）';
      else if(raw.includes('timeout')) msg = '系统信息获取超时（请检查网络/Agent）';
      else if(raw.includes('no data') || raw.includes('no_data')) msg = '系统信息暂无数据（等待 Agent 上报）';
      hint.textContent = msg;
      hint.style.display = '';
    }
    return;
  }

  if(hint) hint.style.display = 'none';

  const cpuModel = sys?.cpu?.model || '-';
  const cores = sys?.cpu?.cores || '-';
  const cpuPct = sys?.cpu?.usage_pct ?? 0;

  const memUsed = sys?.mem?.used || 0;
  const memTot = sys?.mem?.total || 0;
  const memPct = sys?.mem?.usage_pct ?? 0;

  const diskUsed = sys?.disk?.used || 0;
  const diskTot = sys?.disk?.total || 0;
  const diskPct = sys?.disk?.usage_pct ?? 0;

  const tx = sys?.net?.tx_bytes || 0;
  const rx = sys?.net?.rx_bytes || 0;
  const txBps = sys?.net?.tx_bps || 0;
  const rxBps = sys?.net?.rx_bps || 0;

  // Compact tile texts
  const uptimeSec = sys?.uptime_sec || 0;
  // Short in value, full in tooltip
  setText('uptime', formatDurationShort(uptimeSec));
  setTitle('uptime', formatDuration(uptimeSec));
  setText('traffic', `↑ ${formatBytes(tx)} · ↓ ${formatBytes(rx)}`);
  setText('rate', `↑ ${formatBps(txBps)} · ↓ ${formatBps(rxBps)}`);
  setText('cpuPct', `${Number(cpuPct).toFixed(0)}%`);

  // Keep the bar head short; put full numbers in tooltip
  const memFull = `${formatBytes(memUsed)} / ${formatBytes(memTot)}  ${Number(memPct).toFixed(0)}%`;
  const diskFull = `${formatBytes(diskUsed)} / ${formatBytes(diskTot)}  ${Number(diskPct).toFixed(0)}%`;
  setText('memText', `${Number(memPct).toFixed(0)}%`);
  setText('diskText', `${Number(diskPct).toFixed(0)}%`);
  setTitle('memText', memFull);
  setTitle('diskText', diskFull);

  setBar('cpu', cpuPct);
  setBar('mem', memPct);
  setBar('disk', diskPct);
}

async function fetchJSONTimeout(url, timeoutMs){
  const ms = Number(timeoutMs) || 2000;
  const ctrl = new AbortController();
  const t = setTimeout(()=>ctrl.abort(), ms);
  try{
    const resp = await fetch(url, { credentials: 'include', signal: ctrl.signal });
    const data = await resp.json();
    return data;
  } finally {
    clearTimeout(t);
  }
}

async function refreshDashboardMiniSys(){
  const cards = Array.from(document.querySelectorAll('.node-card[data-node-id]'));
  if(cards.length === 0) return;
  await Promise.all(cards.map(async (card)=>{
    const nodeId = card.getAttribute('data-node-id');
    const online = card.getAttribute('data-online') === '1';
    if(!nodeId) return;
    if(!online){
      renderSysMini(card, { error: 'offline' });
      return;
    }
    try{
      // Dashboard: 优先读取 panel 的 push-report 缓存，避免直连 agent 卡住
      const res = await fetchJSONTimeout(`/api/nodes/${nodeId}/sys?cached=1`, 3500);
      if(res && res.ok){
        renderSysMini(card, res.sys);
      } else {
        renderSysMini(card, { error: (res && res.error) || 'no data' });
      }
    } catch(e){
      renderSysMini(card, { error: 'timeout' });
    }
  }));
}

function initDashboardMiniSys(){
  const grid = document.getElementById('dashboardGrid');
  if(!grid) return;
  // First paint for compact "last seen" time
  try{ refreshDashboardLastSeenShort(); }catch(_e){}
  // First paint
  refreshDashboardMiniSys();
  // Same refresh cadence as rules: 3s
  setInterval(refreshDashboardMiniSys, 3000);
  // Update "last seen" display every 5s (no network request)
  setInterval(()=>{ try{ refreshDashboardLastSeenShort(); }catch(_e){} }, 5000);
}

// ================= Dashboard: compact controls (filters/search/group collapse) =================
function initDashboardViewControls(){
  const grid = document.getElementById('dashboardGrid');
  const toolbar = document.getElementById('dashboardToolbar');
  if(!grid || !toolbar) return;

  const searchEl = document.getElementById('dashboardSearch');
  const clearEl = document.getElementById('dashboardSearchClear');
  const chips = Array.from(toolbar.querySelectorAll('.chip[data-filter]'));

  // Build group blocks (based on DOM order: head -> cards -> next head)
  const children = Array.from(grid.children);
  const groups = [];
  let cur = null;
  for(const el of children){
    if(el && el.classList && el.classList.contains('dash-group-head')){
      const name = (el.getAttribute('data-group') || '').trim();
      cur = { head: el, name, cards: [] };
      groups.push(cur);
      continue;
    }
    if(cur && el && el.classList && el.classList.contains('node-card')){
      cur.cards.push(el);
    }
  }

  // Pre-index search text for each card
  for(const g of groups){
    for(const card of g.cards){
      const name = (card.querySelector('.node-name')?.textContent || '').trim();
      const host = (card.querySelector('.node-host')?.textContent || '').trim();
      card.dataset.searchText = (name + ' ' + host).toLowerCase();
    }
  }

  const LS_FILTER = 'realm_dash_filter';
  const LS_QUERY = 'realm_dash_query';
  const LS_COLLAPSED = 'realm_dash_collapsed_groups';

  let filter = (localStorage.getItem(LS_FILTER) || 'all').trim();
  if(!['all','online','offline'].includes(filter)) filter = 'all';
  let query = localStorage.getItem(LS_QUERY) || '';

  let collapsed = new Set();
  try{
    const raw = localStorage.getItem(LS_COLLAPSED);
    const arr = raw ? JSON.parse(raw) : [];
    if(Array.isArray(arr)) collapsed = new Set(arr.map(v=>String(v||'').trim()).filter(Boolean));
  }catch(_e){ collapsed = new Set(); }

  const setChipActive = () => {
    chips.forEach((c)=>{
      const v = (c.getAttribute('data-filter') || '').trim();
      const on = v === filter;
      c.classList.toggle('active', on);
      c.setAttribute('aria-selected', on ? 'true' : 'false');
    });
  };

  const saveCollapsed = () => {
    try{ localStorage.setItem(LS_COLLAPSED, JSON.stringify(Array.from(collapsed))); }catch(_e){}
  };

  const apply = () => {
    const q = (query || '').trim().toLowerCase();

    if(clearEl){
      clearEl.style.visibility = q ? 'visible' : 'hidden';
    }

    for(const g of groups){
      const isCollapsed = collapsed.has(g.name);
      let visibleCount = 0;
      let matchCount = 0;
      let onlineCount = 0;
      const total = g.cards.length;

      for(const card of g.cards){
        const isOnline = card.dataset.online === '1';
        if(isOnline) onlineCount += 1;

        // First: whether it matches current filter/search (ignoring collapse)
        let match = true;
        if(filter === 'online' && !isOnline) match = false;
        if(filter === 'offline' && isOnline) match = false;
        if(match && q){
          const st = (card.dataset.searchText || '').toLowerCase();
          if(!st.includes(q)) match = false;
        }
        if(match) matchCount += 1;

        // Second: whether it should be visible (collapse hides cards but NOT the group header)
        const show = match && !isCollapsed;
        card.style.display = show ? '' : 'none';
        if(show) visibleCount += 1;
      }

      // Group header should remain visible when collapsed, as long as there are matches
      if(g.head){
        g.head.style.display = (matchCount > 0) ? '' : 'none';
        g.head.classList.toggle('collapsed', isCollapsed);

        // aria-expanded for accessibility
        const toggleBtn = g.head.querySelector('.dash-group-toggle');
        if(toggleBtn){
          toggleBtn.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
        }

        const countEl = g.head.querySelector('.dash-group-count');
        if(countEl){
          const hasFilterOrQuery = !!q || filter !== 'all';
          if(hasFilterOrQuery){
            // When filtered/searched, show matched count; add "已折叠" label when collapsed
            if(isCollapsed){
              countEl.innerHTML = `已折叠 <strong>${matchCount}</strong>/<strong>${total}</strong>`;
            }else{
              countEl.innerHTML = `显示 <strong>${visibleCount}</strong>/<strong>${total}</strong>`;
            }
          }else{
            // Default view: online/total; add "已折叠" label when collapsed
            if(isCollapsed){
              countEl.innerHTML = `已折叠 · 在线 <strong>${onlineCount}</strong>/<strong>${total}</strong>`;
            }else{
              countEl.innerHTML = `在线 <strong>${onlineCount}</strong>/<strong>${total}</strong>`;
            }
          }
        }
      }
    }
  };

  // Init values
  if(searchEl && typeof query === 'string') searchEl.value = query;
  setChipActive();
  apply();

  // Chips
  chips.forEach((chip)=>{
    chip.addEventListener('click', ()=>{
      const v = (chip.getAttribute('data-filter') || 'all').trim();
      if(!['all','online','offline'].includes(v)) return;
      filter = v;
      try{ localStorage.setItem(LS_FILTER, filter); }catch(_e){}
      setChipActive();
      apply();
    });
  });

  // Search
  if(searchEl){
    let t = null;
    searchEl.addEventListener('input', ()=>{
      if(t) clearTimeout(t);
      t = setTimeout(()=>{
        query = searchEl.value || '';
        try{ localStorage.setItem(LS_QUERY, query); }catch(_e){}
        apply();
      }, 80);
    });
  }

  if(clearEl){
    clearEl.addEventListener('click', ()=>{
      query = '';
      try{ localStorage.setItem(LS_QUERY, ''); }catch(_e){}
      if(searchEl) searchEl.value = '';
      apply();
      try{ searchEl?.focus(); }catch(_e){}
    });
  }

  // Group collapse toggle
  grid.addEventListener('click', (e)=>{
    const btn = e.target && e.target.closest ? e.target.closest('.dash-group-toggle') : null;
    if(!btn) return;
    const name = (btn.getAttribute('data-group-toggle') || '').trim();
    if(!name) return;
    e.preventDefault();
    e.stopPropagation();
    if(collapsed.has(name)) collapsed.delete(name);
    else collapsed.add(name);
    saveCollapsed();
    apply();
  }, true);
}

function renderSysCard(sys){
  const card = document.getElementById('sysCard');
  if(!card) return;
  if(!sys || sys.error){ card.style.display = 'none'; return; }
  card.style.display = '';

  const cpuModel = sys?.cpu?.model || '-';
  const cores = sys?.cpu?.cores || '-';
  const cpuPct = sys?.cpu?.usage_pct ?? 0;

  const memUsed = sys?.mem?.used || 0;
  const memTot = sys?.mem?.total || 0;
  const memPct = sys?.mem?.usage_pct ?? 0;

  const swapUsed = sys?.swap?.used || 0;
  const swapTot = sys?.swap?.total || 0;
  const swapPct = sys?.swap?.usage_pct ?? 0;

  const diskUsed = sys?.disk?.used || 0;
  const diskTot = sys?.disk?.total || 0;
  const diskPct = sys?.disk?.usage_pct ?? 0;

  const tx = sys?.net?.tx_bytes || 0;
  const rx = sys?.net?.rx_bytes || 0;
  const txBps = sys?.net?.tx_bps || 0;
  const rxBps = sys?.net?.rx_bps || 0;

  const setText = (id, text) => { const el = document.getElementById(id); if(el) el.textContent = text; };

  setText('sysCpuInfo', `${cores}核`);
  setText('sysUptime', formatDuration(sys?.uptime_sec || 0));
  setText('sysTraffic', `上传 ${formatBytes(tx)} | 下载 ${formatBytes(rx)}`);
  setText('sysRate', `上传 ${formatBps(txBps)} | 下载 ${formatBps(rxBps)}`);

  setText('sysCpuPct', `${Number(cpuPct).toFixed(0)}%`);
  setText('sysMemText', `${formatBytes(memUsed)} / ${formatBytes(memTot)}  ${Number(memPct).toFixed(0)}%`);
  setText('sysSwapText', `${formatBytes(swapUsed)} / ${formatBytes(swapTot)}  ${Number(swapPct).toFixed(0)}%`);
  setText('sysDiskText', `${formatBytes(diskUsed)} / ${formatBytes(diskTot)}  ${Number(diskPct).toFixed(0)}%`);

  setProgress('sysCpuBar', cpuPct);
  setProgress('sysMemBar', memPct);
  setProgress('sysSwapBar', swapPct);
  setProgress('sysDiskBar', diskPct);
}


// ================= Dashboard: Node mini system info =================
function renderMiniSysOnCard(cardEl, sys){
  // Dashboard tile system info (auto-refresh). Keep it compact and robust.
  const setField = (key, val) => {
    const el = cardEl.querySelector(`[data-sys="${key}"]`);
    if(el) el.textContent = val;
  };
  const setBar = (key, pct) => {
    const el = cardEl.querySelector(`[data-sys="${key}"] .bar > i`);
    if(el) el.style.width = `${clampPct(pct)}%`;
  };

  // Note: CPU item removed per UI requirement
  setField('uptime', fmtUptime(sys.uptime_seconds));
  setField('traffic', `上传 ${fmtBytes(sys.traffic_up_bytes)} | 下载 ${fmtBytes(sys.traffic_down_bytes)}`);
  setField('rate', `上传 ${fmtRate(sys.tx_rate_bps)} | 下载 ${fmtRate(sys.rx_rate_bps)}`);

  setField('memText', `${fmtMB(sys.mem_used_mb)} / ${fmtMB(sys.mem_total_mb)}  ${fmtPct(sys.mem_percent)}`);
  setField('diskText', `${fmtGB(sys.disk_used_gb)} / ${fmtGB(sys.disk_total_gb)}  ${fmtPct(sys.disk_percent)}`);

  setBar('mem', sys.mem_percent);
  setBar('disk', sys.disk_percent);
}

function initDashboardMiniSysV2(){
  const grid = document.getElementById('dashboardGrid');
  if(!grid) return;
  let inflight = false;

  const tick = async () => {
    if(inflight) return;
    inflight = true;
    try{
      const cards = Array.from(document.querySelectorAll('.node-card[data-node-id]'));
      for(const card of cards){
        const nodeId = card.dataset.nodeId;
        const online = card.dataset.online === '1';
        const hintEl = card.querySelector('[data-sys="hint"]');
        try{
          if(!online){
            if(hintEl){ hintEl.textContent = '节点离线（系统信息暂停刷新）'; hintEl.style.display = ''; }
            renderMiniSysOnCard(card, { ok:false, error:'offline' });
            continue;
          }

          // Dashboard: 优先读取 panel 的 push-report 缓存（不直连 Agent），避免因网络不可达导致卡死
          const data = await fetchJSONTimeout(`/api/nodes/${nodeId}/sys?cached=1`, 2200);

          // api returns {ok:true, sys:{...}} or {ok:false, error:'...'}
          if(data && data.ok && data.sys){
            if(data.sys.ok === false){
              if(hintEl){ hintEl.textContent = '系统信息暂无数据（等待 Agent 上报）'; hintEl.style.display = ''; }
            }else{
              if(hintEl){ hintEl.style.display = 'none'; }
            }
            renderMiniSysOnCard(card, data.sys);
          }else{
            if(hintEl){ hintEl.textContent = '系统信息获取失败（请稍后重试）'; hintEl.style.display = ''; }
            renderMiniSysOnCard(card, { ok:false, error: data?.error || 'no_data' });
          }
        }catch(e){
          // 单节点请求失败时，不影响其它节点的刷新
          if(hintEl){ hintEl.textContent = '系统信息请求超时（请检查网络/Agent 上报）'; hintEl.style.display = ''; }
          renderMiniSysOnCard(card, { ok:false, error: 'timeout' });
        }
      }
    }catch(e){
      // silent
    }finally{
      inflight = false;
    }
  };

  tick();
  setInterval(tick, 3000);
}


function buildStatsLookup(){
  const lookup = { byIdx: {}, byListen: {}, error: null };
  if(!CURRENT_STATS) return lookup;
  if(CURRENT_STATS.error) lookup.error = CURRENT_STATS.error;
  const rules = Array.isArray(CURRENT_STATS.rules) ? CURRENT_STATS.rules : [];
  rules.forEach((r)=>{
    if(typeof r.idx === 'number') lookup.byIdx[r.idx] = r;
    const lis = (r && r.listen != null) ? String(r.listen).trim() : '';
    if(lis) lookup.byListen[lis] = r;
  });
  return lookup;
}

function renderHealth(healthList, statsError, idx){
  if(statsError){
    return `<span class="muted">检测失败：${escapeHtml(statsError)}</span>`;
  }
  if(!Array.isArray(healthList) || healthList.length === 0){
    return '<span class="muted">暂无检测数据</span>';
  }
  // 信息收敛：最多展示前 2 个目标，其余用 +N 收起；离线时展示失败原因（tooltip 里有完整信息）
  const MAX_SHOW = 2;

  function friendlyError(err){
    const s = String(err || '').trim();
    if(!s) return '';
    const t = s.toLowerCase();
    // 内网穿透握手错误码（agent 提供）
    if(t === 'no_client_connected') return '未检测到客户端连接';
    if(t === 'client_not_running') return '客户端未启动';
    if(t === 'server_not_running') return '入口未启动';
    if(t === 'client_not_running') return '客户端未启动';
    if(t === 'peer_is_http_proxy') return '走了HTTP反代/代理';
    if(t === 'sig_invalid') return '签名校验失败';
    if(t === 'magic_mismatch') return '协议不匹配';
    if(t === 'version_mismatch') return '版本不匹配';
    if(t === 'ts_skew') return '时间偏差过大';
    if(t === 'pong_timeout') return '心跳超时';
    if(t === 'control_closed') return '连接断开';
    if(t.startsWith('dial_failed')) return '连接失败';
    if(t.startsWith('dial_tls_failed')) return 'TLS握手失败';
    if(t.startsWith('tls_verify_failed')) return '证书校验失败';
    if(t.startsWith('hello_timeout')) return '握手超时';
    if(t.startsWith('hello_')) return '握手失败';
    if(t.includes('timed out') || t.includes('timeout')) return '超时';
    if(t.includes('refused')) return '拒绝连接';
    if(t.includes('no route')) return '无路由';
    if(t.includes('name or service not known') || t.includes('temporary failure in name resolution')) return 'DNS失败';
    if(t.includes('network is unreachable')) return '网络不可达';
    if(t.includes('permission denied')) return '无权限';
    return s.length > 28 ? (s.slice(0, 28) + '…') : s;
  }

  const shown = healthList.slice(0, MAX_SHOW);
  const hiddenCount = Math.max(0, healthList.length - MAX_SHOW);

  const chips = shown.map((item)=>{
    const isUnknown = item && item.ok == null;
    const ok = !!item.ok;
    const latencyMs = item && item.latency_ms != null ? item.latency_ms : item && item.latency != null ? item.latency : null;
    const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : ((item && item.kind === 'handshake') ? '未连接' : '离线'));
    const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
    const title = !isUnknown && !ok ? `${(item && item.kind === 'handshake') ? '未连接' : '离线'}原因：${String(item.error || item.message || '').trim()}` : '';
    return `<div class="health-item" title="${escapeHtml(title)}">
      <span class="pill ${isUnknown ? 'warn' : (ok ? 'ok' : 'bad')}">${escapeHtml(label)}</span>
      <span class="mono health-target">${escapeHtml(item.target)}</span>
      ${reason ? `<span class="health-reason">(${escapeHtml(reason)})</span>` : ''}
    </div>`;
  }).join('');

  const moreBtn = hiddenCount > 0 ? `<button class="pill ghost health-more" type="button" data-idx="${idx}" data-more="${hiddenCount}" aria-expanded="false" title="展开更多目标">+${hiddenCount}</button>` : '';
  const extraHtml = hiddenCount > 0 ? `<div class="health-extra" hidden>
    ${healthList.slice(MAX_SHOW).map((item)=>{
      const isUnknown = item && item.ok == null;
      const ok = !!item.ok;
      const latencyMs = item && item.latency_ms != null ? item.latency_ms : item && item.latency != null ? item.latency : null;
      const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : ((item && item.kind === 'handshake') ? '未连接' : '离线'));
      const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
      const title = !isUnknown && !ok ? `${(item && item.kind === 'handshake') ? '未连接' : '离线'}原因：${String(item.error || item.message || '').trim()}` : '';
      return `<div class="health-item" title="${escapeHtml(title)}">
        <span class="pill ${isUnknown ? 'warn' : (ok ? 'ok' : 'bad')}">${escapeHtml(label)}</span>
        <span class="mono health-target">${escapeHtml(item.target)}</span>
        ${reason ? `<span class="health-reason">(${escapeHtml(reason)})</span>` : ''}
      </div>`;
    }).join('')}
  </div>` : '';
  return `<div class="health-wrap">${chips}${moreBtn}${extraHtml}</div>`;
}

function renderHealthMobile(healthList, statsError, idx){
  // Mobile: 更易读的纵向排版，目标可换行，离线原因直接展示
  if(statsError){
    return `<span class="muted">检测失败：${escapeHtml(statsError)}</span>`;
  }
  if(!Array.isArray(healthList) || healthList.length === 0){
    return '<span class="muted">暂无检测数据</span>';
  }

  const MAX_SHOW = 2;
  function friendlyError(err){
    const s = String(err || '').trim();
    if(!s) return '';
    const t = s.toLowerCase();
    // 内网穿透握手错误码（agent 提供）
    if(t === 'no_client_connected') return '未检测到客户端连接';
    if(t === 'client_not_running') return '客户端未启动';
    if(t === 'server_not_running') return '入口未启动';
    if(t === 'client_not_running') return '客户端未启动';
    if(t === 'peer_is_http_proxy') return '走了HTTP反代/代理';
    if(t === 'sig_invalid') return '签名校验失败';
    if(t === 'magic_mismatch') return '协议不匹配';
    if(t === 'version_mismatch') return '版本不匹配';
    if(t === 'ts_skew') return '时间偏差过大';
    if(t === 'pong_timeout') return '心跳超时';
    if(t === 'control_closed') return '连接断开';
    if(t.startsWith('dial_failed')) return '连接失败';
    if(t.startsWith('dial_tls_failed')) return 'TLS握手失败';
    if(t.startsWith('tls_verify_failed')) return '证书校验失败';
    if(t.startsWith('hello_timeout')) return '握手超时';
    if(t.startsWith('hello_')) return '握手失败';
    if(t.includes('timed out') || t.includes('timeout')) return '超时';
    if(t.includes('refused')) return '拒绝连接';
    if(t.includes('no route')) return '无路由';
    if(t.includes('name or service not known') || t.includes('temporary failure in name resolution')) return 'DNS失败';
    if(t.includes('network is unreachable')) return '网络不可达';
    if(t.includes('permission denied')) return '无权限';
    return s.length > 28 ? (s.slice(0, 28) + '…') : s;
  }

  const shown = healthList.slice(0, MAX_SHOW);
  const hiddenCount = Math.max(0, healthList.length - MAX_SHOW);
  const chips = shown.map((item)=>{
    const isUnknown = item && item.ok == null;
    const ok = !!item.ok;
    const latencyMs = item && item.latency_ms != null ? item.latency_ms : item && item.latency != null ? item.latency : null;
    const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : ((item && item.kind === 'handshake') ? '未连接' : '离线'));
    const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
    const title = (!isUnknown && !ok) ? `${(item && item.kind === 'handshake') ? '未连接' : '离线'}原因：${String(item.error || item.message || '').trim()}` : '';

    return `<div class="health-item mobile" title="${escapeHtml(title)}">
      <span class="pill ${isUnknown ? 'warn' : (ok ? 'ok' : 'bad')}">${escapeHtml(label)}</span>
      <div class="health-meta">
        <div class="mono health-target" title="${escapeHtml(item.target)}">${escapeHtml(item.target)}</div>
        ${reason ? `<div class="health-reason">${escapeHtml(reason)}</div>` : ''}
      </div>
    </div>`;
  }).join('');

  const moreBtn = hiddenCount > 0 ? `<button class="pill ghost health-more" type="button" data-idx="${idx}" data-more="${hiddenCount}" aria-expanded="false" title="展开更多目标">+${hiddenCount}</button>` : '';
  const extraHtml = hiddenCount > 0 ? `<div class="health-extra" hidden>
    ${healthList.slice(MAX_SHOW).map((item)=>{
      const isUnknown = item && item.ok == null;
      const ok = !!item.ok;
      const latencyMs = item && item.latency_ms != null ? item.latency_ms : item && item.latency != null ? item.latency : null;
      const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : ((item && item.kind === 'handshake') ? '未连接' : '离线'));
      const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
      const title = (!isUnknown && !ok) ? `${(item && item.kind === 'handshake') ? '未连接' : '离线'}原因：${String(item.error || item.message || '').trim()}` : '';

      return `<div class="health-item mobile" title="${escapeHtml(title)}">
        <span class="pill ${isUnknown ? 'warn' : (ok ? 'ok' : 'bad')}">${escapeHtml(label)}</span>
        <div class="health-meta">
          <div class="mono health-target" title="${escapeHtml(item.target)}">${escapeHtml(item.target)}</div>
          ${reason ? `<div class="health-reason">${escapeHtml(reason)}</div>` : ''}
        </div>
      </div>`;
    }).join('')}
  </div>` : '';
  return `<div class="health-wrap mobile">${chips}${moreBtn}${extraHtml}</div>`;
}

function showHealthDetail(idx){
  // 使用现有命令弹窗作为“详情弹窗”，避免移动端挤压显示
  try{
    const statsLookup = buildStatsLookup();
    const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
    const lis = (eps[idx] && eps[idx].listen != null) ? String(eps[idx].listen).trim() : '';
    const stats = (statsLookup.byIdx[idx] || (lis ? statsLookup.byListen[lis] : null) || {});
    const list = Array.isArray(stats.health) ? stats.health : [];
    const lines = list.map((it)=>{
      const ok = it && it.ok === true;
      const isUnknown = it && it.ok == null;
      const latency = it && it.latency_ms != null ? `${it.latency_ms} ms` : (it && it.latency != null ? `${it.latency} ms` : '—');
      const isHandshake = it && it.kind === 'handshake';
      const state = isUnknown ? '不可检测' : (ok ? (isHandshake ? '已连接' : '在线') : (isHandshake ? '未连接' : '离线'));
      const reason = (!isUnknown && !ok) ? (it.error || it.message || '') : '';
      return `${state}  ${latency}  ${it.target}${reason ? `\n  原因：${reason}` : ''}`;
    });
    openCommandModal('连通检测详情', lines.join('\n\n'));
  }catch(e){
    openCommandModal('连通检测详情', '暂无详情');
  }
}

function renderRuleCard(e, idx, rowNo, stats, statsError){
  const rx = statsError ? null : (stats.rx_bytes || 0);
  const tx = statsError ? null : (stats.tx_bytes || 0);
  const total = (rx == null || tx == null) ? null : rx + tx;
  const connActive = statsError ? 0 : (stats.connections_active ?? 0);
  const est = statsError ? 0 : (stats.connections_established ?? stats.connections ?? 0);
  const totalStr = total == null ? '—' : formatBytes(total);
  const healthHtml = renderHealthMobile(stats.health, statsError, idx);
  const activeTitle = statsError ? '' : `title="当前已建立连接：${est}"`;
  return `
  <div class="rule-card">
    <div class="rule-head">
      <div class="rule-left">
        <div class="rule-topline">
          <span class="rule-idx">#${rowNo}</span>
          ${statusPill(e)}
        </div>
        <div class="rule-listen mono">${escapeHtml(e.listen)}</div>
        <div class="rule-sub muted sm">${endpointType(e)}</div>
      </div>
      <div class="rule-right">
        <span class="pill ghost" ${activeTitle}>活跃 ${escapeHtml(connActive)}</span>
        <span class="pill ghost">${escapeHtml(totalStr)}</span>
      </div>
    </div>
    <div class="rule-health-block">
      ${healthHtml}
    </div>
    <div class="rule-actions">
      <button class="btn xs icon ghost" title="编辑" onclick="editRule(${idx})">✎</button>
      <button class="btn xs icon" title="${e.disabled?'启用':'暂停'}" onclick="toggleRule(${idx})">${e.disabled?'▶':'⏸'}</button>
      <button class="btn xs icon ghost" title="删除" onclick="deleteRule(${idx})">🗑</button>
    </div>
  </div>`;
}

function renderRules(){
  q('rulesLoading').style.display = 'none';
  const table = q('rulesTable');
  const tbody = q('rulesBody');
  const mobileWrap = q('rulesMobile');
  tbody.innerHTML = '';
  if(mobileWrap) mobileWrap.innerHTML = '';
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  const statsLookup = buildStatsLookup();
  const statsLoading = q('statsLoading');

  // 小屏用卡片，大屏用表格
  const isMobile = window.matchMedia('(max-width: 1024px)').matches;

  // Filter (listen / remote / remark)
  const f = (RULE_FILTER || '').trim().toLowerCase();
  const items = [];
  eps.forEach((e, idx)=>{
    if(f){
      const hay = `${e.listen||''}
${formatRemote(e)}
${(e.remark||'')}
${endpointType(e)}`.toLowerCase();
      if(!hay.includes(f)) return;
    }
    items.push({e, idx});
  });

  if(!items.length){
    q('rulesLoading').style.display = '';
    q('rulesLoading').textContent = f ? '未找到匹配规则' : '暂无规则';
    table.style.display = 'none';
    if(mobileWrap) mobileWrap.style.display = 'none';
    if(statsLoading){
      statsLoading.style.display = 'none';
    }
    return;
  }

  if(statsLoading){
    if(statsLookup.error){
      statsLoading.style.display = '';
      statsLoading.textContent = `流量统计获取失败：${statsLookup.error}`;
    }else{
      statsLoading.style.display = 'none';
    }
  }

  items.forEach((it, i)=>{
    const e = it.e;
    const idx = it.idx;
    const rowNo = i + 1;
    const lis = (e && e.listen != null) ? String(e.listen).trim() : '';
    const stats = statsLookup.byIdx[idx] || (lis ? statsLookup.byListen[lis] : null) || {};
    const statsError = statsLookup.error;

    if(isMobile && mobileWrap){
      const card = document.createElement('div');
      card.innerHTML = renderRuleCard(e, idx, rowNo, stats, statsError);
      mobileWrap.appendChild(card.firstElementChild);
    }else{
      const healthHtml = renderHealthExpanded(stats.health, statsLookup.error);
      const rx = statsError ? null : (stats.rx_bytes || 0);
      const tx = statsError ? null : (stats.tx_bytes || 0);
      const total = (rx == null || tx == null) ? null : rx + tx;
      const connActive = statsError ? 0 : (stats.connections_active ?? 0);
      const est = statsError ? 0 : (stats.connections_established ?? stats.connections ?? 0);

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${rowNo}</td>
        <td>${statusPill(e)}</td>
        <td class="listen">
          <div class="mono">${escapeHtml(e.listen)}</div>
          <div class="muted sm">${endpointType(e)}</div>
        </td>
        <td class="health">${healthHtml}</td>
        <td class="stat" title="当前已建立连接：${escapeHtml(est)}">${statsError ? '—' : escapeHtml(connActive)}</td>
        <td class="stat">${total == null ? '—' : formatBytes(total)}</td>
        <td class="actions">
          <div class="action-inline">
            <button class="btn xs icon ghost" title="编辑" onclick="editRule(${idx})">✎</button>
            <button class="btn xs icon" title="${e.disabled?'启用':'暂停'}" onclick="toggleRule(${idx})">${e.disabled?'▶':'⏸'}</button>
            <button class="btn xs icon ghost" title="删除" onclick="deleteRule(${idx})">🗑</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    }
  });

  if(isMobile && mobileWrap){
    mobileWrap.style.display = '';
    table.style.display = 'none';
  }else{
    if(mobileWrap) mobileWrap.style.display = 'none';
    table.style.display = '';
  }
}

function openModal(){ q('modal').style.display = 'flex'; }
function closeModal(){ q('modal').style.display = 'none'; q('modalMsg').textContent=''; }

// Basic loading state helper (used by WSS auto-sync operations)
// - Disable the modal save button to prevent double submit
// - Show a short message in the modal
function setLoading(on){
  try{
    const modal = q('modal');
    if(modal){
      const btns = modal.querySelectorAll('button');
      btns.forEach(b=>{
        if(b && b.textContent && b.textContent.trim() === '保存') b.disabled = !!on;
      });
    }
    const msg = q('modalMsg');
    if(msg){
      if(on){
        msg.textContent = '处理中…';
      }else{
        // keep existing msg if any
        if(msg.textContent === '处理中…') msg.textContent = '';
      }
    }
    document.body.style.cursor = on ? 'progress' : '';
  }catch(e){
    // ignore
  }
}

function openCommandModal(title, text){
  const modal = q('commandModal');
  if(!modal) return;
  q('commandTitle').textContent = title || '命令';
  const commandText = q('commandText');
  PENDING_COMMAND_TEXT = String(text || '');
  commandText.textContent = PENDING_COMMAND_TEXT;
  modal.style.display = 'flex';
}

function closeCommandModal(){
  const modal = q('commandModal');
  if(!modal) return;
  modal.style.display = 'none';
}

function setField(id, v){ q(id).value = v==null?'':String(v); }

// Read WSS params from the form.
// IMPORTANT: This must match panel backend API expectations:
// {host, path, sni, tls, insecure}
function readWssFields(){
  return {
    host: q('f_wss_host').value.trim(),
    path: q('f_wss_path').value.trim(),
    sni: q('f_wss_sni').value.trim(),
    tls: q('f_wss_tls').value === '1',
    insecure: !!q('f_wss_insecure').checked,
  };
}

function fillWssFields(e){
  const ex = e.extra_config || {};
  // For WSS 隧道：发送端主要用 remote_*；接收端用 listen_*。
  // 这里做一次兜底，优先 remote_*，没有则读 listen_*。
  const host = ex.remote_ws_host || ex.listen_ws_host || '';
  const path = ex.remote_ws_path || ex.listen_ws_path || '';
  const sni = ex.remote_tls_sni || ex.listen_tls_servername || '';
  const tls = (ex.remote_tls_enabled !== undefined) ? ex.remote_tls_enabled : ex.listen_tls_enabled;
  const insecure = (ex.remote_tls_insecure !== undefined) ? ex.remote_tls_insecure : ex.listen_tls_insecure;

  setField('f_wss_host', host || '');
  setField('f_wss_path', path || '');
  setField('f_wss_sni', sni || '');
  q('f_wss_tls').value = (tls === false) ? '0' : '1';
  q('f_wss_insecure').checked = (insecure !== false);
}

function fillIntranetFields(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  // sender side: choose intranet (LAN) node
  const peerId = ex.intranet_peer_node_id ? String(ex.intranet_peer_node_id) : '';
  const port = ex.intranet_server_port != null ? String(ex.intranet_server_port) : '18443';
  const host = ex.intranet_public_host ? String(ex.intranet_public_host) : '';
  if(q('f_intranet_receiver_node')) setField('f_intranet_receiver_node', peerId);
  if(q('f_intranet_server_port')) setField('f_intranet_server_port', port);
  if(q('f_intranet_server_host')) setField('f_intranet_server_host', host);
  populateIntranetReceiverSelect();
}

function showWssBox(){
  const mode = q('f_type').value;
  if(q('wssBox')) q('wssBox').style.display = (mode === 'wss') ? 'block' : 'none';
  if(q('intranetBox')) q('intranetBox').style.display = (mode === 'intranet') ? 'block' : 'none';

  // WSS 隧道统一走“选择接收机自动同步”
  const autoBox = document.getElementById('wssAutoSyncBox');
  if(autoBox){
    autoBox.style.display = (mode === 'wss') ? 'flex' : 'none';
  }
}

function randomToken(len){
  return Math.random().toString(36).slice(2, 2 + len);
}

function randomizeWss(){
  const hosts = [
    'cdn.jsdelivr.net',
    'assets.cloudflare.com',
    'edge.microsoft.com',
    'static.cloudflareinsights.com',
    'ajax.googleapis.com',
    'fonts.gstatic.com',
    'images.unsplash.com',
    'cdn.discordapp.com',
  ];
  const pathTemplates = [
    '/ws',
    '/ws/{token}',
    '/socket',
    '/socket/{token}',
    '/connect',
    '/gateway',
    '/api/ws',
    '/v1/ws/{token}',
    '/edge/{token}',
  ];
  const pick = hosts[Math.floor(Math.random() * hosts.length)];
  const token = randomToken(10);
  const tpl = pathTemplates[Math.floor(Math.random() * pathTemplates.length)];
  const path = tpl.replace('{token}', token);
  setField('f_wss_host', pick);
  setField('f_wss_path', path);
  setField('f_wss_sni', pick);
  q('f_wss_tls').value = '1';
  q('f_wss_insecure').checked = true;
}

function parseWeights(text){
  if(!text) return [];
  return text.split(/[,，]/).map(x=>x.trim()).filter(Boolean).map(x=>Number(x));
}

function formatWeights(weights){
  if(!weights || !weights.length) return '';
  return weights.join(',');
}

function newRule(){
  CURRENT_EDIT_INDEX = -1;
  q('modalTitle').textContent = '新增规则';
  setField('f_listen','0.0.0.0:443');
  setField('f_remotes','');
  q('f_disabled').value = '0';
  q('f_balance').value = 'roundrobin';
  setField('f_weights','');
  q('f_protocol').value = 'tcp+udp';
  q('f_type').value = 'tcp';
  // reset autosync receiver fields
  if(q('f_wss_receiver_node')) setField('f_wss_receiver_node','');
  if(q('f_wss_receiver_port')) setField('f_wss_receiver_port','');
  if(q('f_intranet_receiver_node')) setField('f_intranet_receiver_node','');
  if(q('f_intranet_server_port')) setField('f_intranet_server_port','18443');
  populateReceiverSelect();
  populateIntranetReceiverSelect();
  fillWssFields({});
  fillIntranetFields({});
  showWssBox();
  openModal();
}

function editRule(idx){
  CURRENT_EDIT_INDEX = idx;
  const e = CURRENT_POOL.endpoints[idx];
  const ex = (e && e.extra_config) ? e.extra_config : {};

  q('modalTitle').textContent = `编辑规则 #${idx+1}`;
  setField('f_listen', e.listen || '');
  // synced sender rule should show original targets (not the peer receiver ip:port)
  setField('f_remotes', formatRemoteForInput(e));

  q('f_disabled').value = e.disabled ? '1':'0';
  const balance = e.balance || 'roundrobin';
  q('f_balance').value = balance.startsWith('iphash') ? 'iphash' : 'roundrobin';
  const weights = balance.startsWith('roundrobin:') ? balance.split(':').slice(1).join(':').trim().split(',').map(x=>x.trim()).filter(Boolean) : [];
  setField('f_weights', weights.join(','));
  q('f_protocol').value = e.protocol || 'tcp+udp';

  // infer tunnel mode from endpoint
  q('f_type').value = wssMode(e);

  // autosync receiver selector (WSS sender role only)
  const mode = q('f_type').value;
  if(mode === 'wss'){
    if(q('f_wss_receiver_node')) setField('f_wss_receiver_node', ex.sync_role === 'sender' && ex.sync_peer_node_id ? String(ex.sync_peer_node_id) : '');
    if(q('f_wss_receiver_port')) setField('f_wss_receiver_port', ex.sync_role === 'sender' && ex.sync_receiver_port ? String(ex.sync_receiver_port) : '');
    populateReceiverSelect();
    fillWssFields(e);
  }else{
    if(q('f_wss_receiver_node')) setField('f_wss_receiver_node','');
    if(q('f_wss_receiver_port')) setField('f_wss_receiver_port','');
    fillWssFields({});
  }

  // intranet tunnel fields
  if(mode === 'intranet'){
    fillIntranetFields(e);
  }else{
    fillIntranetFields({});
  }
  showWssBox();
  openModal();
}

async function toggleRule(idx){
  const e = CURRENT_POOL.endpoints[idx];
  const ex = (e && e.extra_config) ? e.extra_config : {};
  // Locked receiver rules cannot be edited here
  if(ex && (ex.sync_lock === true || ex.sync_role === 'receiver')){
    toast('该规则由发送机同步生成，已锁定不可操作，请在发送机节点操作。', true);
    return;
  }

  if(intranetIsLocked(e)){
    toast('该规则由公网入口同步生成，已锁定不可操作，请在公网入口节点操作。', true);
    return;
  }

  const newDisabled = !e.disabled;

  // Synced WSS sender: update both sides via panel API
  if(ex && ex.sync_id && ex.sync_role === 'sender' && ex.sync_peer_node_id){
    try{
      setLoading(true);
      const payload = {
        sender_node_id: window.__NODE_ID__,
        receiver_node_id: ex.sync_peer_node_id,
        listen: e.listen,
        remotes: ex.sync_original_remotes || [],
        disabled: newDisabled,
        balance: e.balance || 'roundrobin',
        protocol: e.protocol || 'tcp+udp',
        receiver_port: ex.sync_receiver_port,
        sync_id: ex.sync_id,
        wss: {
          host: ex.remote_ws_host || '',
          path: ex.remote_ws_path || '',
          sni: ex.remote_tls_sni || '',
          tls: ex.remote_tls_enabled !== false,
          insecure: ex.remote_tls_insecure === true
        }
      };
      const res = await fetchJSON('/api/wss_tunnel/save', {method:'POST', body: JSON.stringify(payload)});
      if(res && res.ok){
        CURRENT_POOL = res.sender_pool;
        renderRules();
        toast('已同步更新（发送/接收两端）');
      }else{
        toast(res && res.error ? res.error : '同步更新失败，请稍后重试', true);
      }
    }catch(err){
      toast(String(err), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  // Intranet tunnel sender: update both sides via panel API
  if(ex && ex.sync_id && ex.intranet_role === 'server' && ex.intranet_peer_node_id){
    try{
      setLoading(true);
      const payload = {
        sender_node_id: window.__NODE_ID__,
        receiver_node_id: ex.intranet_peer_node_id,
        listen: e.listen,
        remotes: ex.intranet_original_remotes || e.remotes || [],
        disabled: newDisabled,
        balance: e.balance || 'roundrobin',
        protocol: e.protocol || 'tcp+udp',
        server_port: ex.intranet_server_port || 18443,
        sync_id: ex.sync_id
      };
      const res = await fetchJSON('/api/intranet_tunnel/save', {method:'POST', body: JSON.stringify(payload)});
      if(res && res.ok){
        CURRENT_POOL = res.sender_pool;
        renderRules();
        toast('已同步更新（公网入口/内网出口两端）');
      }else{
        toast(res && res.error ? res.error : '同步更新失败，请稍后重试', true);
      }
    }catch(err){
      toast(String(err), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  // Normal rule
  e.disabled = newDisabled;
  await savePool();
  renderRules();
}

async function deleteRule(idx){
  const e = CURRENT_POOL.endpoints[idx];
  const ex = (e && e.extra_config) ? e.extra_config : {};

  if(ex && (ex.sync_lock === true || ex.sync_role === 'receiver')){
    toast('该规则由发送机同步生成，已锁定不可删除，请在发送机节点操作。', true);
    return;
  }

  if(intranetIsLocked(e)){
    toast('该规则由公网入口同步生成，已锁定不可删除，请在公网入口节点操作。', true);
    return;
  }

  // Synced sender: delete both sides
  if(ex && ex.sync_id && ex.sync_role === 'sender' && ex.sync_peer_node_id){
    if(!confirm('这将同时删除接收机对应规则，确定继续？（不可恢复）')) return;
    try{
      setLoading(true);
      const payload = { sender_node_id: window.__NODE_ID__, receiver_node_id: ex.sync_peer_node_id, sync_id: ex.sync_id };
      const res = await fetchJSON('/api/wss_tunnel/delete', {method:'POST', body: JSON.stringify(payload)});
      if(res && res.ok){
        CURRENT_POOL = res.sender_pool;
        renderRules();
        toast('已同步删除（发送/接收两端）');
      }else{
        toast(res && res.error ? res.error : '同步删除失败，请稍后重试', true);
      }
    }catch(err){
      toast(String(err), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  // Intranet tunnel sender: delete both sides
  if(ex && ex.sync_id && ex.intranet_role === 'server' && ex.intranet_peer_node_id){
    if(!confirm('这将同时删除内网出口节点对应配置，确定继续？（不可恢复）')) return;
    try{
      setLoading(true);
      const payload = { sender_node_id: window.__NODE_ID__, receiver_node_id: ex.intranet_peer_node_id, sync_id: ex.sync_id };
      const res = await fetchJSON('/api/intranet_tunnel/delete', {method:'POST', body: JSON.stringify(payload)});
      if(res && res.ok){
        CURRENT_POOL = res.sender_pool;
        renderRules();
        toast('已同步删除（公网入口/内网出口两端）');
      }else{
        toast(res && res.error ? res.error : '同步删除失败，请稍后重试', true);
      }
    }catch(err){
      toast(String(err), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  if(!confirm('确定删除这条规则吗？（不可恢复）')) return;
  CURRENT_POOL.endpoints.splice(idx,1);
  await savePool();
  renderRules();
}

async function saveRule(){
  const typeSel = q('f_type').value;
  const listen = q('f_listen').value.trim();
  const remotesRaw = q('f_remotes').value || '';
  const remotes = remotesRaw.split('\n').map(x=>x.trim()).filter(Boolean).map(x=>x.replace('\\r',''));
  const disabled = (q('f_disabled').value === '1');

  // optional weights for roundrobin (comma separated)
  const weightsRaw = q('f_weights') ? (q('f_weights').value || '').trim() : '';
  const weights = weightsRaw ? weightsRaw.split(',').map(x=>x.trim()).filter(Boolean) : [];

  let balTxt = (q('f_balance').value || '').trim();
  let balance = balTxt ? balTxt.split(':')[0].trim() : 'roundrobin';
  if(!balance) balance = 'roundrobin';

  let balanceStr = balance;
  if(balance === 'roundrobin' && weights.length > 0){
    balanceStr = `roundrobin: ${weights.join(',')}`;
  }

  const protocol = q('f_protocol').value || 'tcp+udp';

  if(!listen){ toast('本地监听不能为空', true); return; }
  if(remotes.length === 0){ toast('目标地址不能为空', true); return; }

  // WSS 隧道：必须选择接收机，自动同步生成接收端规则
  if(typeSel === 'wss'){
    const receiverNodeId = q('f_wss_receiver_node') ? q('f_wss_receiver_node').value.trim() : '';
    if(!receiverNodeId){
      toast('WSS 隧道必须选择接收机节点', true);
      return;
    }
    const receiverPortTxt = q('f_wss_receiver_port') ? q('f_wss_receiver_port').value.trim() : '';
    const wss = readWssFields();
    if(!wss.host || !wss.path){
      toast('WSS Host / Path 不能为空', true);
      return;
    }
    let syncId = '';
    if(CURRENT_EDIT_INDEX >= 0){
      const old = CURRENT_POOL.endpoints[CURRENT_EDIT_INDEX];
      const ex = (old && old.extra_config) ? old.extra_config : {};
      if(ex && ex.sync_id) syncId = ex.sync_id;
    }
    const payload = {
      sender_node_id: window.__NODE_ID__,
      receiver_node_id: parseInt(receiverNodeId,10),
      listen,
      remotes,
      disabled,
      balance: balanceStr,
      protocol,
      receiver_port: receiverPortTxt ? parseInt(receiverPortTxt,10) : null,
      sync_id: syncId || undefined,
      wss
    };

    try{
      setLoading(true);
      const res = await fetchJSON('/api/wss_tunnel/save', {method:'POST', body: JSON.stringify(payload)});
      if(res && res.ok){
        CURRENT_POOL = res.sender_pool;
        renderRules();
        closeModal();
        toast('已保存，并自动同步到接收机');
      }else{
        toast((res && res.error) ? res.error : '保存失败，请检查节点是否在线', true);
      }
    }catch(err){
      toast(String(err), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  // 内网穿透：公网入口(本节点) -> 选择的内网节点（内网节点主动连回公网入口）
  if(typeSel === 'intranet'){
    const receiverNodeId = q('f_intranet_receiver_node') ? q('f_intranet_receiver_node').value.trim() : '';
    if(!receiverNodeId){
      toast('内网穿透必须选择内网节点', true);
      return;
    }
    const portTxt = q('f_intranet_server_port') ? q('f_intranet_server_port').value.trim() : '';
    const server_port = portTxt ? parseInt(portTxt,10) : 18443;
    const server_host = q('f_intranet_server_host') ? q('f_intranet_server_host').value.trim() : '';
    let syncId = '';
    if(CURRENT_EDIT_INDEX >= 0){
      const old = CURRENT_POOL.endpoints[CURRENT_EDIT_INDEX];
      const ex = (old && old.extra_config) ? old.extra_config : {};
      if(ex && ex.sync_id) syncId = ex.sync_id;
    }
    const payload = {
      sender_node_id: window.__NODE_ID__,
      receiver_node_id: parseInt(receiverNodeId,10),
      listen,
      remotes,
      disabled,
      balance: balanceStr,
      protocol,
      server_port,
      server_host: server_host || null,
      sync_id: syncId || undefined
    };

    try{
      setLoading(true);
      const res = await fetchJSON('/api/intranet_tunnel/save', {method:'POST', body: JSON.stringify(payload)});
      if(res && res.ok){
        CURRENT_POOL = res.sender_pool;
        renderRules();
        closeModal();
        toast('已保存，并自动下发到内网节点');
      }else{
        toast((res && res.error) ? res.error : '保存失败，请检查节点是否在线', true);
      }
    }catch(err){
      toast(String(err), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  // 普通转发（单机）
  const endpoint = { listen, remotes, disabled, balance: balanceStr, protocol };

    try{
      setLoading(true);
  
      if(CURRENT_EDIT_INDEX >= 0){
        CURRENT_POOL.endpoints[CURRENT_EDIT_INDEX] = endpoint;
      }else{
        CURRENT_POOL.endpoints.push(endpoint);
      }
  
      await savePool('已保存');
      renderRules();
      closeModal();
  
    }catch(err){
      const msg = (err && err.message) ? err.message : String(err || '保存失败');
      toast(msg, true);
      // revert local changes
      try{ await loadPool(); }catch(e){}
    }finally{
      setLoading(false);
    }
  }

async function savePool(msg){
  q('modalMsg') && (q('modalMsg').textContent = '');
  const id = window.__NODE_ID__;
  try{
    const res = await fetchJSON(`/api/nodes/${id}/pool`, {
      method:'POST',
      body: JSON.stringify({ pool: CURRENT_POOL })
    });
    if(res && res.ok){
      CURRENT_POOL = res.pool;
      renderRules();
      if(msg) toast(msg);
      return true;
    }
    const err = (res && res.error) ? res.error : '保存失败';
    q('modalMsg') && (q('modalMsg').textContent = err);
    throw new Error(err);
  }catch(e){
    const m = (e && e.message) ? e.message : String(e || '保存失败');
    q('modalMsg') && (q('modalMsg').textContent = m);
    toast(m, true);
    throw e;
  }
}

function toast(text, isError=false){
  const msg = String(text || '').trim();
  if(!msg) return;

  // Prefer a toast bar if present
  const t = q('toast');
  if(t){
    t.textContent = msg;
    t.style.display = 'block';
    t.classList.toggle('error', !!isError);
    setTimeout(()=>{ t.style.display='none'; }, 1800);
    return;
  }

  // Fallback: show inside modal message area
  const m = q('modalMsg');
  if(m){
    m.textContent = msg;
    m.style.color = isError ? '#ff6b6b' : '';
    return;
  }

  // Last resort
  alert(msg);
}

async function restoreRules(file){
  if(!file) return;
  const id = window.__NODE_ID__;
  const formData = new FormData();
  formData.append('file', file);
  try{
    toast('正在恢复…');
    const res = await fetch(`/api/nodes/${id}/restore`, {
      method: 'POST',
      body: formData,
      credentials: 'same-origin',
    });
    const text = await res.text();
    if(!res.ok){
      let detail = text;
      try{ detail = JSON.parse(text).error || text; }catch(e){}
      throw new Error(detail || `HTTP ${res.status}`);
    }
    const data = text ? JSON.parse(text) : {};
    if(!data.ok){
      throw new Error(data.error || '恢复失败');
    }
    await loadPool();
  await loadNodesList();
    toast('规则恢复完成');
    return true;
  }catch(e){
    toast('恢复失败：' + e.message, true);
    return false;
  }
}

function triggerRestore(){
  openRestoreModal();
}

function openRestoreModal(){
  const modal = q('restoreModal');
  if(modal){
    modal.style.display = '';
  }
  const textarea = q('restoreText');
  if(textarea){
    textarea.focus();
  }
}

function closeRestoreModal(){
  const modal = q('restoreModal');
  if(modal){
    modal.style.display = 'none';
  }
}

async function restoreFromText(){
  const textarea = q('restoreText');
  if(!textarea) return;
  const raw = textarea.value.trim();
  if(!raw){
    alert('请先粘贴备份内容（JSON）');
    return;
  }
  let payload;
  try{
    payload = JSON.parse(raw);
  }catch(e){
    alert('备份内容不是有效的 JSON：' + e.message);
    return;
  }
  const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
  const file = new File([blob], 'realm-rules.json', { type: 'application/json' });
  const ok = await restoreRules(file);
  if(ok){
    textarea.value = '';
    closeRestoreModal();
  }
}

async function refreshStats(){
  const id = window.__NODE_ID__;
  const loading = q('statsLoading');
  if(loading){
    loading.style.display = '';
    loading.textContent = '正在加载流量统计…';
  }
  try{
    const statsData = await fetchJSON(`/api/nodes/${id}/stats`);
    CURRENT_STATS = statsData;
  }catch(e){
    CURRENT_STATS = { ok: false, error: e.message, rules: [] };
  }
  await refreshSys();
  renderRules();
}

async function loadPool(){
  const id = window.__NODE_ID__;
  q('rulesLoading').style.display = '';
  q('rulesLoading').textContent = '正在加载规则…';
  const statsLoading = q('statsLoading');
  if(statsLoading){
    statsLoading.style.display = '';
    statsLoading.textContent = '正在加载流量统计…';
  }
  try{
    const data = await fetchJSON(`/api/nodes/${id}/pool`);
    let statsData = null;
    try{
      statsData = await fetchJSON(`/api/nodes/${id}/stats`);
    }catch(e){
      statsData = { ok: false, error: e.message, rules: [] };
    }
    CURRENT_POOL = data.pool;
    if(!CURRENT_POOL.endpoints) CURRENT_POOL.endpoints = [];
    CURRENT_STATS = statsData;
    renderRules();
    await refreshSys();
  }catch(e){
    q('rulesLoading').textContent = '加载失败：' + e.message;
    if(statsLoading){
      statsLoading.textContent = '加载失败：' + e.message;
    }
  }
}

async function refreshSys(){
  try{
    const nodeId = window.__NODE_ID__ || window.NODE_ID || null;
    if(!nodeId) return;
    const res = await fetchJSON(`/api/nodes/${nodeId}/sys`);
    if(res && res.ok){
      CURRENT_SYS = res.sys;
      renderSysCard(CURRENT_SYS);
    }else{
      CURRENT_SYS = { error: res?.error || '获取失败' };
      renderSysCard(null);
    }
  }catch(err){
    CURRENT_SYS = { error: String(err) };
    renderSysCard(null);
  }
}


function initNodePage(){
  // Compact "last seen" time in header (and anywhere with data-last-seen)
  try{ refreshDashboardLastSeenShort(); }catch(_e){}
  setInterval(()=>{ try{ refreshDashboardLastSeenShort(); }catch(_e){} }, 5000);

  document.querySelectorAll('.tab').forEach(t=>{
    t.addEventListener('click', ()=>{
      const name = t.getAttribute('data-tab');
      showTab(name);
    });
  });
  const installBtn = q('installCmdBtn');
  if(installBtn){
    installBtn.addEventListener('click', ()=>{
      openCommandModal('一键接入命令', window.__INSTALL_CMD__);
    });
  }
  const uninstallBtn = q('uninstallCmdBtn');
  if(uninstallBtn){
    uninstallBtn.addEventListener('click', ()=>{
      openCommandModal('一键卸载 Agent', window.__UNINSTALL_CMD__);
    });
  }
  const restoreBtn = q('restoreRulesBtn');
  if(restoreBtn){
    restoreBtn.addEventListener('click', triggerRestore);
  }
  q('f_type').addEventListener('change', showWssBox);
  if(q('f_wss_receiver_node')) q('f_wss_receiver_node').addEventListener('change', showWssBox);

  // ✅ Load nodes list for WSS auto-sync receiver selector
  // (otherwise the receiver dropdown stays empty and cannot be selected)
  loadNodesList();
  // Load once, then enable auto-refresh by default
  loadPool().finally(()=>{
    try{
      if(!AUTO_REFRESH_TIMER) toggleAutoRefresh();
    }catch(e){}
  });

  // Auto open edit-node modal when coming from dashboard
  try{
    if(window.__AUTO_OPEN_EDIT_NODE__){
      setTimeout(()=>{
        try{ openEditNodeModal(); }catch(_e){}
        // Prevent re-opening on refresh / after save by cleaning the URL once.
        try{ stripEditQueryParam(); }catch(_e){}
      }, 80);
    }
  }catch(_e){}
}

window.initNodePage = initNodePage;
window.editRule = editRule;
window.newRule = newRule;
window.saveRule = saveRule;
window.closeModal = closeModal;
window.toggleRule = toggleRule;
window.deleteRule = deleteRule;
window.triggerRestore = triggerRestore;
window.openRestoreModal = openRestoreModal;
window.closeRestoreModal = closeRestoreModal;
window.restoreFromText = restoreFromText;
window.refreshStats = refreshStats;
window.openCommandModal = openCommandModal;
window.closeCommandModal = closeCommandModal;
window.randomizeWss = randomizeWss;

// -------------------- Small UX enhancements --------------------

let AUTO_REFRESH_TIMER = null;
function toggleAutoRefresh(){
  const btn = q('autoRefreshBtn');
  if(AUTO_REFRESH_TIMER){
    clearInterval(AUTO_REFRESH_TIMER);
    AUTO_REFRESH_TIMER = null;
    if(btn) btn.textContent = '自动刷新：关';
    return;
  }
  if(btn) btn.textContent = '自动刷新：开';
  refreshStats();
  AUTO_REFRESH_TIMER = setInterval(()=>{
    refreshStats();
  }, 3000);
}

async function copyText(text){
  const str = String(text || '').trim();
  if(!str) return;
  try{
    await navigator.clipboard.writeText(str);
    toast('已复制');
  }catch(e){
    alert('复制失败：浏览器未授予剪贴板权限，请手动复制');
  }
}

window.toggleAutoRefresh = toggleAutoRefresh;
window.copyText = copyText;


// ---------------- Groups: Order Modal ----------------
function openGroupOrderModal(groupName, groupOrder){
  const m = document.getElementById('groupOrderModal');
  if(!m) return;
  const name = String(groupName || '').trim() || '默认分组';
  let order = String(groupOrder ?? '').trim();
  if(order === '') order = '1000';
  const nameEl = document.getElementById('groupOrderName');
  const valEl = document.getElementById('groupOrderValue');
  const err = document.getElementById('groupOrderError');
  const btn = document.getElementById('groupOrderSubmit');
  if(nameEl) nameEl.value = name;
  if(valEl) valEl.value = order;
  if(err) err.textContent = '';
  if(btn){ btn.disabled = false; btn.textContent = '保存'; }
  m.style.display = 'flex';
  if(valEl) setTimeout(()=>valEl.focus(), 30);
}

function closeGroupOrderModal(){
  const m = document.getElementById('groupOrderModal');
  if(!m) return;
  m.style.display = 'none';
}

async function saveGroupOrder(){
  const err = document.getElementById('groupOrderError');
  const btn = document.getElementById('groupOrderSubmit');
  try{
    if(err) err.textContent = '';
    if(btn){ btn.disabled = true; btn.textContent = '保存中…'; }

    const name = (document.getElementById('groupOrderName')?.value || '').trim() || '默认分组';
    const raw = (document.getElementById('groupOrderValue')?.value || '').trim();
    if(raw === ''){
      if(err) err.textContent = '请输入排序序号（数字）';
      return;
    }
    const sort_order = parseInt(raw, 10);
    if(Number.isNaN(sort_order)){
      if(err) err.textContent = '排序序号必须是数字';
      return;
    }

    const resp = await fetch('/api/groups/order', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({group_name: name, sort_order})
    });
    const data = await resp.json().catch(()=>({ok:false,error:'接口返回异常'}));
    if(!resp.ok || !data.ok){
      const msg = data.error || ('保存失败（HTTP ' + resp.status + '）');
      if(err) err.textContent = msg;
      try{ toast(msg, true); }catch(_e){}
      return;
    }
    try{ toast('已更新分组排序'); }catch(_e){}
    closeGroupOrderModal();
    // Refresh current page without query string (avoid ?edit=1 side effects)
    setTimeout(()=>{ window.location.href = window.location.pathname; }, 60);
  }catch(e){
    const msg = (e && e.message) ? e.message : String(e || '保存失败');
    if(err) err.textContent = msg;
    try{ toast(msg, true); }catch(_e){}
  }finally{
    if(btn){ btn.disabled = false; btn.textContent = '保存'; }
  }
}

window.openGroupOrderModal = openGroupOrderModal;
window.closeGroupOrderModal = closeGroupOrderModal;
window.saveGroupOrder = saveGroupOrder;

// Click group headers to edit order
document.addEventListener('click', (e)=>{
  const el = e.target && e.target.closest ? e.target.closest('.dash-group-name, .node-group-name') : null;
  if(!el) return;
  const name = (el.getAttribute('data-group-name') || el.textContent || '').trim();
  const order = el.getAttribute('data-group-order');
  if(name){
    e.preventDefault();
    openGroupOrderModal(name, order);
  }
});

// Keyboard accessibility (Enter to open)
document.addEventListener('keydown', (e)=>{
  if(e.key !== 'Enter') return;
  const el = e.target && e.target.classList ? e.target : null;
  if(!el) return;
  if(!(el.classList.contains('dash-group-name') || el.classList.contains('node-group-name'))) return;
  const name = (el.getAttribute('data-group-name') || el.textContent || '').trim();
  const order = el.getAttribute('data-group-order');
  if(name){
    e.preventDefault();
    openGroupOrderModal(name, order);
  }
});

// Close group modal on backdrop click
document.addEventListener('click', (e)=>{
  const m = document.getElementById('groupOrderModal');
  if(!m || m.style.display === 'none') return;
  if(e.target === m) closeGroupOrderModal();
});

// ESC / Enter for group modal
document.addEventListener('keydown', (e)=>{
  const m = document.getElementById('groupOrderModal');
  if(!m || m.style.display === 'none') return;
  if(e.key === 'Escape'){
    closeGroupOrderModal();
    return;
  }
  if(e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey){
    const t = (e.target && e.target.tagName) ? String(e.target.tagName).toLowerCase() : '';
    if(t === 'input'){
      e.preventDefault();
      try{ saveGroupOrder(); }catch(_e){}
    }
  }
});


// ---------------- Dashboard: Add Node Modal ----------------
function openAddNodeModal(){
  const m = document.getElementById("addNodeModal");
  if(!m) return;
  m.style.display = "flex";
  // prefill group
  try{
    const g = localStorage.getItem("realm_last_group") || "";
    const gi = document.getElementById("addNodeGroup");
    if(gi && g) gi.value = g;
  }catch(_e){}
  // focus
  const ip = document.getElementById("addNodeIp");
  if(ip) setTimeout(()=>ip.focus(), 30);
}




// ---------------- Node: Edit Node Modal ----------------
function openEditNodeModal(){
  const m = document.getElementById('editNodeModal');
  if(!m) return;
  // fill current values
  const name = window.__NODE_NAME__ || '';
  const group = window.__NODE_GROUP__ || '默认分组';
  const base = window.__NODE_BASE_URL__ || '';
  const vt = !!window.__NODE_VERIFY_TLS__;
  const ipri = !!window.__NODE_IS_PRIVATE__;

  let scheme = 'http';
  let host = '';
  let port = '';
  try{
    const u = new URL(base.includes('://') ? base : ('http://' + base));
    scheme = (u.protocol || 'http:').replace(':','') || 'http';
    host = u.hostname || '';
    port = u.port || '';
  }catch(e){
    host = String(base || '').replace(/^https?:\/\//,'').replace(/\/.*/,'');
  }

  const nameEl = document.getElementById('editNodeName');
  const groupEl = document.getElementById('editNodeGroup');
  const schemeEl = document.getElementById('editNodeScheme');
  const ipEl = document.getElementById('editNodeIp');
  const vtEl = document.getElementById('editNodeVerifyTls');
  const iprEl = document.getElementById('editNodeIsPrivate');
  const err = document.getElementById('editNodeError');
  const btn = document.getElementById('editNodeSubmit');

  if(err) err.textContent = '';
  if(btn){ btn.disabled = false; btn.textContent = '保存'; }

  if(nameEl) nameEl.value = String(name || '').trim();
  if(groupEl) groupEl.value = String(group || '').trim();
  if(schemeEl) schemeEl.value = scheme;
  if(vtEl) vtEl.checked = !!vt;
  if(iprEl) iprEl.checked = !!ipri;

  // Show host (append :port only when non-default and present)
  let ipVal = host;
  try{
    const def = '18700';
    if(port && port !== def) ipVal = host + ':' + port;
  }catch(_e){}
  if(ipEl) ipEl.value = ipVal;

  m.style.display = 'flex';
  if(nameEl) setTimeout(()=>nameEl.focus(), 30);
}

function closeEditNodeModal(){
  const m = document.getElementById('editNodeModal');
  if(!m) return;
  m.style.display = 'none';
}

function applyEditedNodeToPage(data){
  try{
    if(!data || typeof data !== 'object') return;
    const name = String(data.name || '').trim();
    const displayIp = String(data.display_ip || '').trim();
    const group = String(data.group_name || '').trim() || '默认分组';
    const baseUrl = String(data.base_url || '').trim();
    const verifyTls = !!data.verify_tls;
    const isPrivate = !!data.is_private;

    // update globals (for next time opening the modal)
    if(name) window.__NODE_NAME__ = name;
    if(baseUrl) window.__NODE_BASE_URL__ = baseUrl;
    window.__NODE_GROUP__ = group;
    window.__NODE_VERIFY_TLS__ = verifyTls ? 1 : 0;
    window.__NODE_IS_PRIVATE__ = isPrivate ? 1 : 0;

    // header title
    const titleEl = document.querySelector('.node-title');
    if(titleEl){
      titleEl.textContent = name || displayIp || titleEl.textContent;
    }
    // header display ip
    const ipEl = document.getElementById('nodeDisplayIp');
    if(ipEl){
      ipEl.textContent = `· ${displayIp || '-'}`;
    }
    // header group pill
    const grpEl = document.getElementById('nodeGroupPill');
    if(grpEl){
      grpEl.textContent = group;
    }

    // sidebar active item
    const active = document.querySelector('.node-item.active');
    if(active){
      const nm = active.querySelector('.node-name');
      if(nm) nm.textContent = name || displayIp || nm.textContent;
      const meta = active.querySelector('.node-meta');
      if(meta) meta.textContent = displayIp || meta.textContent;
      const gg = active.querySelector('.node-info .muted.sm');
      if(gg) gg.textContent = group;
    }
  }catch(_e){}
}

async function saveEditNode(){
  const err = document.getElementById('editNodeError');
  const btn = document.getElementById('editNodeSubmit');
  try{
    if(err) err.textContent = '';
    if(btn){ btn.disabled = true; btn.textContent = '保存中…'; }

    // If group changes, we may need a lightweight refresh to re-render sidebar grouping.
    const prevGroup = String(window.__NODE_GROUP__ || '默认分组').trim() || '默认分组';

    const name = (document.getElementById('editNodeName')?.value || '').trim();
    const group_name = (document.getElementById('editNodeGroup')?.value || '').trim();
    const scheme = (document.getElementById('editNodeScheme')?.value || 'http').trim();
    const ip_address = (document.getElementById('editNodeIp')?.value || '').trim();
    const verify_tls = !!document.getElementById('editNodeVerifyTls')?.checked;
    const is_private = !!document.getElementById('editNodeIsPrivate')?.checked;

    if(!ip_address){
      if(err) err.textContent = '节点地址不能为空';
      return;
    }

    const nodeId = window.__NODE_ID__;
    const resp = await fetch(`/api/nodes/${nodeId}/update`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({ name, group_name, scheme, ip_address, verify_tls, is_private })
    });
    const data = await resp.json().catch(()=>({ok:false,error:'接口返回异常'}));
    if(!resp.ok || !data.ok){
      const msg = data.error || ('保存失败（HTTP ' + resp.status + '）');
      if(err) err.textContent = msg;
      toast(msg, true);
      return;
    }
    toast('已保存');
    // apply updates without reloading (avoid modal auto re-open)
    let patch = data && data.node ? data.node : null;
    if(!patch){
      // Fallback when server returns only {ok:true}
      let display_ip = '';
      let base_url = '';
      try{
        const raw = ip_address.includes('://') ? ip_address : (scheme + '://' + ip_address);
        const u = new URL(raw);
        display_ip = u.hostname || '';
        base_url = raw;
      }catch(_e){}
      patch = { name, group_name, display_ip, base_url, verify_tls };
    }
    try{ applyEditedNodeToPage(patch); }catch(_e){}
    try{ stripEditQueryParam(); }catch(_e){}
    closeEditNodeModal();

    // Re-render grouped sidebar when group changed
    try{
      const nextGroup = String(patch.group_name || patch.group || '').trim() || '默认分组';
      if(nextGroup !== prevGroup){
        // Ensure no lingering ?edit=1 then refresh to move the node into correct group section
        setTimeout(()=>{ window.location.href = window.location.pathname; }, 50);
      }
    }catch(_e){}
  }catch(e){
    const msg = (e && e.message) ? e.message : String(e || '保存失败');
    if(err) err.textContent = msg;
    toast(msg, true);
  }finally{
    if(btn){ btn.disabled = false; btn.textContent = '保存'; }
  }
}

window.openEditNodeModal = openEditNodeModal;
window.closeEditNodeModal = closeEditNodeModal;
window.saveEditNode = saveEditNode;

// click backdrop to close

document.addEventListener('click', (e)=>{
  const m = document.getElementById('editNodeModal');
  if(!m || m.style.display === 'none') return;
  if(e.target === m) closeEditNodeModal();
});

// ESC to close edit modal

document.addEventListener('keydown', (e)=>{
  const m = document.getElementById('editNodeModal');
  if(!m || m.style.display === 'none') return;

  if(e.key === 'Escape'){
    closeEditNodeModal();
    return;
  }
  // Press Enter to save (when focus is on an input/select), without page refresh.
  if(e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey){
    const t = (e.target && e.target.tagName) ? String(e.target.tagName).toLowerCase() : '';
    if(t === 'input' || t === 'select'){
      e.preventDefault();
      try{ saveEditNode(); }catch(_e){}
    }
  }
});
// ---------------- Dashboard: Agent Update Modal ----------------
let __AGENT_UPDATE_TIMER__ = null;
let __AGENT_UPDATE_ID__ = '';
let __AGENT_UPDATE_TARGET__ = '';

let __AU_FILTER_STATE__ = 'all';
let __AU_SEARCH__ = '';
let __AU_LAST_ROWS__ = [];
let __AU_LAST_SUMMARY__ = null;
let __AU_BOUND__ = false;

function openAgentUpdateModal(){
  const m = document.getElementById('agentUpdateModal');
  if(!m) return;
  m.style.display = 'flex';
  document.body.classList.add('modal-open');

  // reset state/UI
  __AGENT_UPDATE_ID__ = '';
  __AGENT_UPDATE_TARGET__ = '';
  __AU_FILTER_STATE__ = 'all';
  __AU_SEARCH__ = '';
  __AU_LAST_ROWS__ = [];
  __AU_LAST_SUMMARY__ = null;

  const t = document.getElementById('agentUpdateTarget');
  const id = document.getElementById('agentUpdateId');
  const sum = document.getElementById('agentUpdateSummary');
  const bar = document.getElementById('agentUpdateBar');
  const seg = document.getElementById('agentUpdateSegBar');
  const list = document.getElementById('agentUpdateList');
  const pills = document.getElementById('agentUpdatePills');
  const btn = document.getElementById('agentUpdateStartBtn');
  const search = document.getElementById('agentUpdateSearch');

  if(t) t.textContent = '—';
  if(id) id.textContent = '';
  if(sum) sum.textContent = '—';
  if(bar) bar.style.width = '0%';
  if(seg) seg.innerHTML = '';
  if(list) list.innerHTML = '';
  if(pills) pills.innerHTML = '';
  if(btn){ btn.disabled = false; btn.textContent = '开始更新'; }
  if(search){ search.value = ''; }

  // Bind handlers once
  if(!__AU_BOUND__){
    __AU_BOUND__ = true;

    if(pills){
      pills.addEventListener('click', (e)=>{
        const el = (e.target && e.target.closest) ? e.target.closest('.pill-stat') : null;
        if(!el) return;
        const st = String(el.getAttribute('data-state') || 'all').trim() || 'all';
        __AU_FILTER_STATE__ = st;
        _renderPills(__AU_LAST_SUMMARY__ || {});
        _renderList(__AU_LAST_ROWS__ || []);
      });
    }

    if(search){
      search.addEventListener('input', ()=>{
        __AU_SEARCH__ = String(search.value || '').trim().toLowerCase();
        _renderList(__AU_LAST_ROWS__ || []);
      });
    }
  }

  // fetch latest agent version bundled with panel
  fetch('/api/agents/latest', { credentials: 'include' })
    .then(r=>r.json().catch(()=>({ok:false})))
    .then(d=>{
      if(d && d.ok){
        __AGENT_UPDATE_TARGET__ = String(d.latest_version || '').trim();
        if(t) t.textContent = __AGENT_UPDATE_TARGET__ || '—';
      }
    })
    .catch(()=>{});
}

function closeAgentUpdateModal(){
  const m = document.getElementById('agentUpdateModal');
  if(!m) return;
  m.style.display = 'none';
  document.body.classList.remove('modal-open');
  if(__AGENT_UPDATE_TIMER__){
    clearInterval(__AGENT_UPDATE_TIMER__);
    __AGENT_UPDATE_TIMER__ = null;
  }
}

function _stateText(st){
  const s = String(st || '').toLowerCase();
  if(s === 'done') return '已完成';
  if(s === 'failed') return '失败';
  if(s === 'installing') return '安装中';
  if(s === 'sent') return '已下发';
  if(s === 'queued') return '排队中';
  if(s === 'offline') return '离线';
  return st || '—';
}

function _badgeClass(st){
  const s = String(st || '').toLowerCase();
  if(s === 'done') return 'ok';
  if(s === 'failed') return 'bad';
  if(s === 'installing') return 'warn';
  if(s === 'sent') return 'info';
  if(s === 'queued') return 'muted';
  if(s === 'offline') return 'muted';
  return 'muted';
}

function _statusWeight(st){
  const s = String(st || '').toLowerCase();
  if(s === 'failed') return 1;
  if(s === 'installing') return 2;
  if(s === 'sent') return 3;
  if(s === 'queued') return 4;
  if(s === 'offline') return 5;
  if(s === 'done') return 6;
  return 7;
}

function _renderSegBar(summary){
  const seg = document.getElementById('agentUpdateSegBar');
  if(!seg) return;
  const s = summary || {};
  const total = Number(s.total || 0) || 0;
  if(!total){
    seg.innerHTML = '';
    return;
  }
  const parts = [
    {k:'done', cls:'done', label:'完成'},
    {k:'installing', cls:'installing', label:'安装中'},
    {k:'failed', cls:'failed', label:'失败'},
    {k:'offline', cls:'offline', label:'离线'},
    {k:'sent', cls:'sent', label:'已下发'},
    {k:'queued', cls:'queued', label:'排队'},
  ];
  const html = parts.map(p=>{
    const v = Number(s[p.k] || 0) || 0;
    if(v <= 0) return '';
    const w = Math.max(0, Math.min(100, (v * 100 / total)));
    const title = `${p.label} ${v}/${total}`;
    return `<div class="au-seg ${p.cls}" style="width:${w}%" title="${escapeHtml(title)}"></div>`;
  }).join('');
  seg.innerHTML = html || '';
}

function _renderPills(summary){
  const pills = document.getElementById('agentUpdatePills');
  if(!pills) return;
  const s = summary || {};
  const total = Number(s.total || 0) || 0;
  const items = [
    {state:'all', label:'全部', cls:'muted', val: total},
    {state:'done', label:'完成', cls:'ok', val: Number(s.done || 0)},
    {state:'failed', label:'失败', cls:'bad', val: Number(s.failed || 0)},
    {state:'installing', label:'安装中', cls:'warn', val: Number(s.installing || 0)},
    {state:'sent', label:'已下发', cls:'info', val: Number(s.sent || 0)},
    {state:'queued', label:'排队', cls:'muted', val: Number(s.queued || 0)},
    {state:'offline', label:'离线', cls:'muted', val: Number(s.offline || 0)},
  ];
  pills.innerHTML = items.map(it=>{
    const active = (__AU_FILTER_STATE__ === it.state) ? ' active' : '';
    return `<span class="pill-stat ${it.cls}${active}" data-state="${escapeHtml(it.state)}">${escapeHtml(it.label)} <strong>${escapeHtml(String(it.val))}</strong></span>`;
  }).join('');
}

function _countStates(rows){
  const out = {done:0, failed:0, installing:0, sent:0, queued:0, offline:0, other:0};
  (rows || []).forEach(n=>{
    const st = String((n && n.state) || '').toLowerCase();
    if(out.hasOwnProperty(st)) out[st] += 1;
    else out.other += 1;
  });
  return out;
}

function _renderRow(n){
  const name = (n.name || ('节点-' + n.id));
  const stRaw = (n.state || '');
  const stTxt = _stateText(stRaw);
  const badge = _badgeClass(stRaw);
  const cur = (n.agent_version || '-');
  const des = (n.desired_version || '-');
  const msg = String(n.msg || '').trim();
  const online = !!n.online;
  const dotCls = online ? 'on' : 'off';
  const last = String(n.last_seen_at || '').trim();
  const lastTxt = last ? (`心跳 ${last}`) : '未上报';
  const tail = msg ? (` · ${msg}`) : '';
  const cell = `${lastTxt}${tail}`;
  const title = escapeHtml(cell);

  return `<div class="au-row">
    <div class="au-node">
      <div class="au-node-name">${escapeHtml(String(name))}</div>
    </div>
    <div class="au-status-cell">
      <span class="au-dot ${dotCls}" title="${online ? '在线' : '离线'}"></span>
      <span class="badge ${badge}">${escapeHtml(String(stTxt))}</span>
    </div>
    <div class="au-ver-cell mono">${escapeHtml(String(cur))}→${escapeHtml(String(des))}</div>
    <div class="au-msg-cell" title="${title}">${escapeHtml(cell)}</div>
  </div>`;
}

function _renderList(rows){
  const list = document.getElementById('agentUpdateList');
  if(!list) return;
  const arr = Array.isArray(rows) ? rows : [];

  let view = arr.slice();
  const f = String(__AU_FILTER_STATE__ || 'all').toLowerCase();
  if(f && f !== 'all'){
    view = view.filter(n=> String((n && n.state) || '').toLowerCase() === f);
  }

  const q = String(__AU_SEARCH__ || '').trim().toLowerCase();
  if(q){
    view = view.filter(n=>{
      const hay = [
        n && n.name,
        n && n.group_name,
        n && n.msg,
        n && n.agent_version,
        n && n.desired_version,
        n && n.last_seen_at,
      ].map(x=>String(x || '')).join(' ').toLowerCase();
      return hay.indexOf(q) !== -1;
    });
  }

  if(view.length === 0){
    list.innerHTML = `<div class="au-row"><div class="au-node"><div class="au-node-name">暂无匹配节点</div><div class="au-node-meta"><span class="kv-mini mono">调整筛选条件或搜索关键词</span></div></div></div>`;
    return;
  }

  // group by group_name
  const gmap = new Map();
  view.forEach(n=>{
    const g = String((n && n.group_name) || '').trim() || '默认分组';
    if(!gmap.has(g)) gmap.set(g, []);
    gmap.get(g).push(n);
  });

  const groups = Array.from(gmap.entries()).map(([g, items])=>{
    const ord = (items && items[0] && (items[0].group_order !== undefined)) ? Number(items[0].group_order) : 9999;
    return {g, ord: (isNaN(ord) ? 9999 : ord), items};
  });
  groups.sort((a,b)=>{
    if(a.ord !== b.ord) return a.ord - b.ord;
    return String(a.g).localeCompare(String(b.g), 'zh-Hans-CN');
  });

  groups.forEach(gr=>{
    gr.items.sort((a,b)=>{
      const wa = _statusWeight(a && a.state);
      const wb = _statusWeight(b && b.state);
      if(wa !== wb) return wa - wb;
      return String(a && a.name || '').localeCompare(String(b && b.name || ''), 'zh-Hans-CN');
    });
  });

  list.innerHTML = groups.map(gr=>{
    const c = _countStates(gr.items);
    const head = `<summary>
      <div class="au-group-title">${escapeHtml(gr.g)}</div>
      <div class="au-group-meta">
        <span class="kv-mini mono">${escapeHtml(String(gr.items.length))} 节点</span>
        <span class="kv-mini mono">完成 ${escapeHtml(String(c.done))}</span>
        <span class="kv-mini mono">失败 ${escapeHtml(String(c.failed))}</span>
      </div>
    </summary>`;
    const body = gr.items.map(_renderRow).join('');
    return `<details class="au-group" open>${head}<div class="au-group-body">${body}</div></details>`;
  }).join('');
}

async function _pollAgentUpdate(){
  if(!__AGENT_UPDATE_ID__) return;
  const sumEl = document.getElementById('agentUpdateSummary');
  const bar = document.getElementById('agentUpdateBar');
  const id = document.getElementById('agentUpdateId');

  if(id) id.textContent = __AGENT_UPDATE_ID__ ? ('批次：' + __AGENT_UPDATE_ID__) : '';

  try{
    const r = await fetch('/api/agents/update_progress?update_id=' + encodeURIComponent(__AGENT_UPDATE_ID__), { credentials: 'include' });
    const d = await r.json().catch(()=>({ok:false}));
    if(!r.ok || !d.ok) return;

    const s = d.summary || {};
    const total = Number(s.total || 0) || 0;
    const done = Number(s.done || 0) || 0;
    const failed = Number(s.failed || 0) || 0;
    const offline = Number(s.offline || 0) || 0;
    const installing = Number(s.installing || 0) || 0;
    const sent = Number(s.sent || 0) || 0;
    const queued = Number(s.queued || 0) || 0;

    if(sumEl){
      sumEl.textContent = `${done}/${total} 完成 · 安装中 ${installing} · 失败 ${failed} · 离线 ${offline} · 已下发 ${sent} · 排队 ${queued}`;
    }

    if(bar){
      const pct = total ? Math.max(0, Math.min(100, Math.round(done * 100 / total))) : 0;
      bar.style.width = pct + '%';
    }

    __AU_LAST_SUMMARY__ = s;
    __AU_LAST_ROWS__ = Array.isArray(d.nodes) ? d.nodes : [];

    _renderSegBar(s);
    _renderPills(s);
    _renderList(__AU_LAST_ROWS__);

  }catch(_e){}
}

async function startAgentUpdateAll(){
  const btn = document.getElementById('agentUpdateStartBtn');
  const t = document.getElementById('agentUpdateTarget');
  try{
    if(btn){ btn.disabled = true; btn.textContent = '下发中…'; }
    const r = await fetch('/api/agents/update_all', { method: 'POST', credentials: 'include' });
    const d = await r.json().catch(()=>({ok:false}));
    if(!r.ok || !d.ok){
      toast((d.error || ('更新失败（HTTP ' + r.status + '）')), true);
      if(btn){ btn.disabled = false; btn.textContent = '开始更新'; }
      return;
    }

    __AGENT_UPDATE_ID__ = String(d.update_id || '').trim();
    __AGENT_UPDATE_TARGET__ = String(d.target_version || '').trim();
    if(t) t.textContent = __AGENT_UPDATE_TARGET__ || '—';

    toast('已下发更新任务');

    if(__AGENT_UPDATE_TIMER__){ clearInterval(__AGENT_UPDATE_TIMER__); }
    __AGENT_UPDATE_TIMER__ = setInterval(_pollAgentUpdate, 1800);
    await _pollAgentUpdate();

  }catch(e){
    toast((e && e.message) ? e.message : '更新失败', true);
  }finally{
    if(btn){ btn.disabled = false; btn.textContent = '开始更新'; }
  }
}

window.openAgentUpdateModal = openAgentUpdateModal;
window.closeAgentUpdateModal = closeAgentUpdateModal;
window.startAgentUpdateAll = startAgentUpdateAll;

// close agent update modal on backdrop click / ESC

document.addEventListener('click', (e)=>{
  const m = document.getElementById('agentUpdateModal');
  if(!m || m.style.display === 'none') return;
  if(e.target === m) closeAgentUpdateModal();
});

document.addEventListener('keydown', (e)=>{
  const m = document.getElementById('agentUpdateModal');
  if(!m || m.style.display === 'none') return;
  if(e.key === 'Escape') closeAgentUpdateModal();
});


// ---------------- Dashboard: Full Restore Modal ----------------
function openRestoreFullModal(){
  const m = document.getElementById('restoreFullModal');
  if(!m) return;
  m.style.display = 'flex';
  const input = document.getElementById('restoreFullFile');
  if(input) input.value = '';
  const err = document.getElementById('restoreFullError');
  if(err) err.textContent = '';
  const btn = document.getElementById('restoreFullSubmit');
  if(btn){ btn.disabled = false; btn.textContent = '开始恢复'; }
}

function closeRestoreFullModal(){
  const m = document.getElementById('restoreFullModal');
  if(!m) return;
  m.style.display = 'none';
}

async function restoreFullNow(){
  const fileInput = document.getElementById('restoreFullFile');
  const err = document.getElementById('restoreFullError');
  const btn = document.getElementById('restoreFullSubmit');
  try{
    if(err) err.textContent = '';
    const f = fileInput && fileInput.files ? fileInput.files[0] : null;
    if(!f){
      if(err) err.textContent = '请选择 realm-backup-*.zip 全量备份包';
      return;
    }
    if(btn){ btn.disabled = true; btn.textContent = '恢复中…'; }
    const fd = new FormData();
    fd.append('file', f);
    const resp = await fetch('/api/restore/full', { method: 'POST', body: fd, credentials: 'include' });
    const data = await resp.json().catch(()=>({ ok:false, error: '接口返回异常' }));
    if(!resp.ok || !data.ok){
      const msg = data.error || ('恢复失败（HTTP ' + resp.status + '）');
      if(err) err.textContent = msg;
      toast(msg, true);
      return;
    }
    toast('全量恢复已完成');
    closeRestoreFullModal();
    setTimeout(()=>window.location.reload(), 600);
  }catch(e){
    const msg = (e && e.message) ? e.message : String(e || '恢复失败');
    if(err) err.textContent = msg;
    toast(msg, true);
  }finally{
    if(btn){ btn.disabled = false; btn.textContent = '开始恢复'; }
  }
}

window.openRestoreFullModal = openRestoreFullModal;
window.closeRestoreFullModal = closeRestoreFullModal;
window.restoreFullNow = restoreFullNow;
function closeAddNodeModal(){
  const m = document.getElementById("addNodeModal");
  if(!m) return;
  m.style.display = "none";
}
async function createNodeFromModal(){
  const err = document.getElementById("addNodeError");
  const btn = document.getElementById("addNodeSubmit");
  try{
    if(err) err.textContent = "";
    if(btn){ btn.disabled = true; btn.textContent = "创建中…"; }
    const name = (document.getElementById("addNodeName")?.value || "").trim();
    const ip_address = (document.getElementById("addNodeIp")?.value || "").trim();
    const scheme = (document.getElementById("addNodeScheme")?.value || "http").trim();
    const verify_tls = !!document.getElementById("addNodeVerifyTls")?.checked;
    const is_private = !!document.getElementById("addNodeIsPrivate")?.checked;
    const group_name = (document.getElementById("addNodeGroup")?.value || "").trim();

    if(!ip_address){
      if(err) err.textContent = "节点地址不能为空";
      if(btn){ btn.disabled = false; btn.textContent = "创建并进入"; }
      return;
    }

    const resp = await fetch("/api/nodes/create", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({name, ip_address, scheme, verify_tls, is_private, group_name}),
      // 需要允许后端写入 Session Cookie（用于跳转到节点页后自动弹出接入命令窗口）
      credentials: "include",
    });

    const data = await resp.json().catch(()=>({ok:false,error:"接口返回异常"}));
    if(!resp.ok || !data.ok){
      if(err) err.textContent = data.error || ("创建失败（HTTP " + resp.status + "）。请检查节点地址与协议");
      if(btn){ btn.disabled = false; btn.textContent = "创建并进入"; }
      return;
    }

    try{ if(group_name) localStorage.setItem("realm_last_group", group_name); }catch(_e){}
    closeAddNodeModal();
    if(data.redirect_url){
      window.location.href = data.redirect_url;
    }else if(data.node_id){
      window.location.href = "/nodes/" + data.node_id;
    }else{
      window.location.reload();
    }
  }catch(e){
    if(err) err.textContent = String(e);
  }finally{
    if(btn){ btn.disabled = false; btn.textContent = "创建并进入"; }
  }
}

// 点击遮罩关闭
document.addEventListener("click", (e)=>{
  const m = document.getElementById("addNodeModal");
  if(!m || m.style.display === "none") return;
  if(e.target === m) closeAddNodeModal();
});

document.addEventListener("click", (e)=>{
  const m = document.getElementById("restoreFullModal");
  if(!m || m.style.display === "none") return;
  if(e.target === m) closeRestoreFullModal();
});

// ESC 关闭
document.addEventListener("keydown", (e)=>{
  if(e.key === "Escape"){
    const m = document.getElementById("addNodeModal");
    if(m && m.style.display !== "none") closeAddNodeModal();
    const r = document.getElementById("restoreFullModal");
    if(r && r.style.display !== "none") closeRestoreFullModal();
  }
});

// +N 展开按钮（Remote 目标 / 连通检测）
// 说明：不要依赖 inline onclick（某些浏览器缓存/模板差异会导致 onclick 失效）
// 统一使用事件委托，确保点击永远有效。
document.addEventListener('click', (e)=>{
  const rbtn = e.target.closest && e.target.closest('button.remote-more');
  if(rbtn){
    e.preventDefault();
    const wrap = rbtn.closest('.remote-wrap');
    const extra = wrap ? wrap.querySelector('.remote-extra') : null;
    const more = rbtn.dataset.more || '';
    if(extra){
      const open = !!extra.hidden;
      extra.hidden = !open;
      rbtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      rbtn.textContent = open ? '−' : `+${more}`;
      rbtn.title = open ? '收起' : '展开更多目标';
      if(wrap) wrap.classList.toggle('expanded', open);
    }else{
      const idx = Number(rbtn.dataset.idx);
      if(!Number.isNaN(idx)) showRemoteDetail(idx);
    }
    return;
  }
  const hbtn = e.target.closest && e.target.closest('button.health-more');
  if(hbtn){
    e.preventDefault();
    const wrap = hbtn.closest('.health-wrap');
    const extra = wrap ? wrap.querySelector('.health-extra') : null;
    const more = hbtn.dataset.more || '';
    if(extra){
      const open = !!extra.hidden;
      extra.hidden = !open;
      hbtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      hbtn.textContent = open ? '−' : `+${more}`;
      hbtn.title = open ? '收起' : '展开更多目标';
      if(wrap) wrap.classList.toggle('expanded', open);
    }else{
      const idx = Number(hbtn.dataset.idx);
      if(!Number.isNaN(idx)) showHealthDetail(idx);
    }
    return;
  }
});

// ---------------- Details Menu UX ----------------
// 目标：
// 1) 点击页面空白处自动收起所有“更多/操作”菜单
// 2) 打开一个菜单时，自动关闭其他菜单（避免多个同时展开）
function closeAllMenus(except){
  try{
    document.querySelectorAll('details.menu[open]').forEach((d)=>{
      if(except && d === except) return;
      d.removeAttribute('open');
    });
  }catch(_e){}
}

// 当某个 menu 打开时，关掉其它 menu
document.addEventListener('toggle', (e)=>{
  const t = e.target;
  if(!(t instanceof HTMLElement)) return;
  if(t.matches && t.matches('details.menu') && t.open){
    closeAllMenus(t);
  }
}, true);

// 点击空白区域，关闭所有 menu
document.addEventListener('click', (e)=>{
  const inMenu = e.target && e.target.closest && e.target.closest('details.menu');
  if(!inMenu){
    closeAllMenus(null);
  }
}, true);

// Auto-init dashboard mini system info (safe no-op on non-dashboard pages)
try{ initDashboardMiniSys(); }catch(_e){}
// Auto-init dashboard filters/search/group collapse
try{ initDashboardViewControls(); }catch(_e){}
