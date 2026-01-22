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
    }
  }catch(e){
    // ignore
  }
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
  const ex = e.extra_config || {};
  const listenTransport = e.listen_transport || ex.listen_transport || '';
  const remoteTransport = e.remote_transport || ex.remote_transport || '';
  const hasLisWs = String(listenTransport).includes('ws') || ex.listen_ws_host || ex.listen_ws_path || ex.listen_tls_servername;
  const hasRemWs = String(remoteTransport).includes('ws') || ex.remote_ws_host || ex.remote_ws_path || ex.remote_tls_sni;
  if(hasLisWs || hasRemWs) return 'wss';
  return 'tcp';
}

function endpointType(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  if(ex && ex.sync_id){
    if(ex.sync_role === 'receiver') return 'WSS隧道(接收·同步)';
    if(ex.sync_role === 'sender') return 'WSS隧道(发送·同步)';
  }
  const mode = wssMode(e);
  if(mode === 'wss') return 'WSS隧道';
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
    const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : '离线');
    const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
    const title = !isUnknown && !ok ? `离线原因：${String(item.error || item.message || '').trim()}` : '';
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
  return String(text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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
  const sysCard = cardEl.querySelector('[data-sys-card]');
  if(!sysCard) return;

  const hint = sysCard.querySelector('[data-sys="hint"]');
  const setText = (key, text) => {
    const el = sysCard.querySelector(`[data-sys="${key}"]`);
    if(el) el.textContent = text;
  };
  const setBar = (key, pct) => {
    const el = sysCard.querySelector(`[data-sys-bar="${key}"]`);
    setProgressEl(el, pct);
  };

  // Offline or missing data
  if(!sys || sys.error){
    setText('cpuInfo', '暂无数据');
    setText('uptime', '—');
    setText('traffic', '—');
    setText('rate', '—');
    setText('cpuPct', '0%');
    setText('memText', '—');
    setText('diskText', '—');
    setBar('cpu', 0);
    setBar('mem', 0);
    setBar('disk', 0);
    if(hint) hint.style.display = '';
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

  // CPU 型号信息太占空间：只展示核心数
  setText('cpuInfo', `${cores}核`);
  setText('uptime', formatDuration(sys?.uptime_sec || 0));
  setText('traffic', `上传 ${formatBytes(tx)} | 下载 ${formatBytes(rx)}`);
  setText('rate', `上传 ${formatBps(txBps)} | 下载 ${formatBps(rxBps)}`);
  setText('cpuPct', `${Number(cpuPct).toFixed(0)}%`);
  setText('memText', `${formatBytes(memUsed)} / ${formatBytes(memTot)}  ${Number(memPct).toFixed(0)}%`);
  setText('diskText', `${formatBytes(diskUsed)} / ${formatBytes(diskTot)}  ${Number(diskPct).toFixed(0)}%`);

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
  // First paint
  refreshDashboardMiniSys();
  // Same refresh cadence as rules: 3s
  setInterval(refreshDashboardMiniSys, 3000);
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
    if(r.listen) lookup.byListen[r.listen] = r;
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
    const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : '离线');
    const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
    const title = !isUnknown && !ok ? `离线原因：${String(item.error || item.message || '').trim()}` : '';
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
      const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : '离线');
      const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
      const title = !isUnknown && !ok ? `离线原因：${String(item.error || item.message || '').trim()}` : '';
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
    const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : '离线');
    const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
    const title = (!isUnknown && !ok) ? `离线原因：${String(item.error || item.message || '').trim()}` : '';

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
      const label = isUnknown ? (item.message || '不可检测') : (ok ? `${latencyMs != null ? latencyMs : '—'} ms` : '离线');
      const reason = (!isUnknown && !ok) ? friendlyError(item.error || item.message) : '';
      const title = (!isUnknown && !ok) ? `离线原因：${String(item.error || item.message || '').trim()}` : '';

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
    const stats = (statsLookup.byIdx[idx] || statsLookup.byListen[eps[idx]?.listen] || {});
    const list = Array.isArray(stats.health) ? stats.health : [];
    const lines = list.map((it)=>{
      const ok = it && it.ok === true;
      const isUnknown = it && it.ok == null;
      const latency = it && it.latency_ms != null ? `${it.latency_ms} ms` : (it && it.latency != null ? `${it.latency} ms` : '—');
      const state = isUnknown ? '不可检测' : (ok ? '在线' : '离线');
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
    const stats = statsLookup.byIdx[idx] || statsLookup.byListen[e.listen] || {};
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

function showWssBox(){
  const mode = q('f_type').value;
  q('wssBox').style.display = (mode === 'wss') ? 'block' : 'none';

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
  populateReceiverSelect();
  fillWssFields({});
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

  // autosync receiver selector (sender role only)
  if(q('f_wss_receiver_node')) setField('f_wss_receiver_node', ex.sync_role === 'sender' && ex.sync_peer_node_id ? String(ex.sync_peer_node_id) : '');
  if(q('f_wss_receiver_port')) setField('f_wss_receiver_port', ex.sync_role === 'sender' && ex.sync_receiver_port ? String(ex.sync_receiver_port) : '');
  populateReceiverSelect();

  fillWssFields(e);
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
        toast(res && res.error ? res.error : '同步更新失败', true);
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

  // Synced sender: delete both sides
  if(ex && ex.sync_id && ex.sync_role === 'sender' && ex.sync_peer_node_id){
    if(!confirm('删除后将同步移除接收机对应规则，确定继续？')) return;
    try{
      setLoading(true);
      const payload = { sender_node_id: window.__NODE_ID__, receiver_node_id: ex.sync_peer_node_id, sync_id: ex.sync_id };
      const res = await fetchJSON('/api/wss_tunnel/delete', {method:'POST', body: JSON.stringify(payload)});
      if(res && res.ok){
        CURRENT_POOL = res.sender_pool;
        renderRules();
        toast('已同步删除（发送/接收两端）');
      }else{
        toast(res && res.error ? res.error : '同步删除失败', true);
      }
    }catch(err){
      toast(String(err), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  if(!confirm('确定删除这条规则？')) return;
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
        toast((res && res.error) ? res.error : '保存失败', true);
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
    alert('恢复失败：' + e.message);
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
    alert('请先粘贴备份内容');
    return;
  }
  let payload;
  try{
    payload = JSON.parse(raw);
  }catch(e){
    alert('内容不是有效的 JSON：' + e.message);
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
    alert('复制失败，请手动复制');
  }
}

window.toggleAutoRefresh = toggleAutoRefresh;
window.copyText = copyText;


// ---------------- Dashboard: Add Node Modal ----------------
function openAddNodeModal(){
  const m = document.getElementById("addNodeModal");
  if(!m) return;
  m.style.display = "flex";
  // focus
  const ip = document.getElementById("addNodeIp");
  if(ip) setTimeout(()=>ip.focus(), 30);
}
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

    if(!ip_address){
      if(err) err.textContent = "请填写 IP/域名";
      if(btn){ btn.disabled = false; btn.textContent = "创建并进入"; }
      return;
    }

    const resp = await fetch("/api/nodes/create", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({name, ip_address, scheme, verify_tls})
    });

    const data = await resp.json().catch(()=>({ok:false,error:"返回解析失败"}));
    if(!resp.ok || !data.ok){
      if(err) err.textContent = data.error || ("创建失败（HTTP " + resp.status + "）");
      if(btn){ btn.disabled = false; btn.textContent = "创建并进入"; }
      return;
    }

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

// ESC 关闭
document.addEventListener("keydown", (e)=>{
  if(e.key === "Escape"){
    const m = document.getElementById("addNodeModal");
    if(m && m.style.display !== "none") closeAddNodeModal();
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
