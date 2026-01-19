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

function q(id){ return document.getElementById(id); }

let CURRENT_POOL = null;
let CURRENT_EDIT_INDEX = null;
let CURRENT_STATS = null;
let PENDING_COMMAND_TEXT = '';

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
  if(hasLisWs) return 'wss_recv';
  if(hasRemWs) return 'wss_send';
  return 'tcp';
}

function endpointType(e){
  const mode = wssMode(e);
  if(mode === 'wss_recv') return 'WSS接收';
  if(mode === 'wss_send') return 'WSS发送';
  return 'TCP/UDP';
}

function formatRemote(e){
  const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
  return rs.join('\n');
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

function renderHealth(healthList, statsError){
  if(statsError){
    return `<span class="muted">检测失败：${escapeHtml(statsError)}</span>`;
  }
  if(!Array.isArray(healthList) || healthList.length === 0){
    return '<span class="muted">暂无检测数据</span>';
  }
  return healthList.map((item)=>{
    const ok = !!item.ok;
    const label = ok ? '可达' : '不可达';
    return `<div class="row" style="gap:6px;align-items:center;">
      <span class="pill ${ok ? 'ok' : 'bad'}">${label}</span>
      <span class="mono">${escapeHtml(item.target)}</span>
    </div>`;
  }).join('');
}

function renderRules(){
  q('rulesLoading').style.display = 'none';
  const table = q('rulesTable');
  const tbody = q('rulesBody');
  tbody.innerHTML = '';
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  const statsLookup = buildStatsLookup();
  eps.forEach((e, idx)=>{
    const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
    const stats = statsLookup.byIdx[idx] || statsLookup.byListen[e.listen] || {};
    const healthHtml = renderHealth(stats.health, statsLookup.error);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${idx+1}</td>
      <td>${statusPill(e)}</td>
      <td><div class="mono">${escapeHtml(e.listen)}</div></td>
      <td><div class="mono">${rs.map(escapeHtml).join('<br>')}</div></td>
      <td>${healthHtml}</td>
      <td>${endpointType(e)}</td>
      <td>${e.balance || 'roundrobin'}</td>
      <td>
        <button class="btn sm ghost" onclick="editRule(${idx})">编辑</button>
        <button class="btn sm" onclick="toggleRule(${idx})">${e.disabled?'启用':'暂停'}</button>
        <button class="btn sm ghost" onclick="deleteRule(${idx})">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
  table.style.display = '';
}

function openModal(){ q('modal').style.display = 'flex'; }
function closeModal(){ q('modal').style.display = 'none'; q('modalMsg').textContent=''; }

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

function readWssFields(){
  const mode = q('f_type').value;
  const host = q('f_wss_host').value.trim();
  const path = q('f_wss_path').value.trim();
  const sni = q('f_wss_sni').value.trim();
  const tls = q('f_wss_tls').value === '1';
  const insecure = q('f_wss_insecure').value === '1';
  const ex = {};
  if(mode === 'wss_send'){
    ex.remote_transport = 'ws';
    ex.listen_transport = 'tcp';
    if(host) ex.remote_ws_host = host;
    if(path) ex.remote_ws_path = path;
    if(sni) ex.remote_tls_sni = sni;
    ex.remote_tls_enabled = tls;
    ex.remote_tls_insecure = insecure;
  } else if(mode === 'wss_recv'){
    ex.listen_transport = 'ws';
    ex.remote_transport = 'tcp';
    if(host) ex.listen_ws_host = host;
    if(path) ex.listen_ws_path = path;
    if(sni) ex.listen_tls_servername = sni;
    ex.listen_tls_enabled = tls;
    ex.listen_tls_insecure = insecure;
  }
  return ex;
}

function fillWssFields(e){
  const ex = e.extra_config || {};
  const mode = wssMode(e);
  q('f_type').value = mode;

  const isSend = mode === 'wss_send';
  const host = isSend ? ex.remote_ws_host : ex.listen_ws_host;
  const path = isSend ? ex.remote_ws_path : ex.listen_ws_path;
  const sni = isSend ? ex.remote_tls_sni : ex.listen_tls_servername;
  const tls = isSend ? ex.remote_tls_enabled : ex.listen_tls_enabled;
  const insecure = isSend ? ex.remote_tls_insecure : ex.listen_tls_insecure;

  setField('f_wss_host', host || '');
  setField('f_wss_path', path || '');
  setField('f_wss_sni', sni || '');
  q('f_wss_tls').value = (tls === false) ? '0' : '1';
  q('f_wss_insecure').value = (insecure === true) ? '1' : '0';
}

function showWssBox(){
  const mode = q('f_type').value;
  q('wssBox').style.display = (mode === 'tcp') ? 'none' : 'block';
}

function encodePairingCode(data){
  return btoa(unescape(encodeURIComponent(JSON.stringify(data))));
}

function decodePairingCode(code){
  const text = decodeURIComponent(escape(atob(code.trim())));
  return JSON.parse(text);
}

function buildPairingPayload(){
  return {
    host: q('f_wss_host').value.trim(),
    path: q('f_wss_path').value.trim(),
    sni: q('f_wss_sni').value.trim(),
    tls: q('f_wss_tls').value === '1',
    insecure: q('f_wss_insecure').value === '1',
  };
}

function applyPairingPayload(payload){
  if(!payload) return;
  setField('f_wss_host', payload.host || '');
  setField('f_wss_path', payload.path || '');
  setField('f_wss_sni', payload.sni || '');
  q('f_wss_tls').value = payload.tls === false ? '0' : '1';
  q('f_wss_insecure').value = payload.insecure === true ? '1' : '0';
  showWssBox();
}

function applyPairingCode(){
  const code = q('f_pairing').value.trim();
  if(!code){
    q('modalMsg').textContent = '请先粘贴配对码';
    return;
  }
  try{
    const payload = decodePairingCode(code);
    applyPairingPayload(payload);
    q('modalMsg').textContent = '配对码已解析并填充';
  }catch(e){
    q('modalMsg').textContent = '配对码格式无效';
  }
}

function openPairingModal(code){
  const modal = q('pairingModal');
  const text = q('pairingCodeText');
  text.textContent = code;
  modal.style.display = 'flex';
}

function closePairingModal(){
  q('pairingModal').style.display = 'none';
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
  q('f_wss_insecure').value = '0';
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
  CURRENT_EDIT_INDEX = null;
  q('modalTitle').textContent = '新增规则';
  setField('f_listen','0.0.0.0:443');
  setField('f_remotes','');
  q('f_disabled').value = '0';
  q('f_balance').value = 'roundrobin';
  setField('f_weights','');
  q('f_protocol').value = 'tcp+udp';
  q('f_type').value = 'tcp';
  setField('f_pairing','');
  fillWssFields({});
  showWssBox();
  openModal();
}

function editRule(idx){
  CURRENT_EDIT_INDEX = idx;
  const e = CURRENT_POOL.endpoints[idx];
  q('modalTitle').textContent = `编辑规则 #${idx+1}`;
  setField('f_listen', e.listen || '');
  setField('f_remotes', formatRemote(e));
  q('f_disabled').value = e.disabled ? '1':'0';
  const balance = e.balance || 'roundrobin';
  q('f_balance').value = balance.startsWith('iphash') ? 'iphash' : 'roundrobin';
  const weights = balance.startsWith('roundrobin:') ? balance.split(':').slice(1).join(':').trim().split(',').map(x=>x.trim()).filter(Boolean) : [];
  setField('f_weights', weights.join(','));
  q('f_protocol').value = e.protocol || 'tcp+udp';
  setField('f_pairing','');
  fillWssFields(e);
  showWssBox();
  openModal();
}

async function toggleRule(idx){
  const e = CURRENT_POOL.endpoints[idx];
  e.disabled = !e.disabled;
  await savePool(`已${e.disabled?'暂停':'启用'}规则 #${idx+1}`);
}

async function deleteRule(idx){
  if(!confirm('确认删除该规则？')) return;
  CURRENT_POOL.endpoints.splice(idx,1);
  await savePool('已删除规则');
}

async function saveRule(){
  const listen = q('f_listen').value.trim();
  const remotesText = q('f_remotes').value.trim();
  const remotes = remotesText ? remotesText.split(/\n+/).map(x=>x.trim()).filter(Boolean) : [];
  if(!listen){ q('modalMsg').textContent='listen 不能为空'; return; }
  if(remotes.length===0){ q('modalMsg').textContent='remote 至少需要一个目标'; return; }

  const disabled = q('f_disabled').value === '1';
  const balanceSel = q('f_balance').value;
  let balance = 'roundrobin';
  if(balanceSel === 'iphash'){
    balance = 'iphash';
  }else{
    const weights = parseWeights(q('f_weights').value.trim());
    if(weights.length && weights.length !== remotes.length){
      q('modalMsg').textContent='权重数量必须与 Remote 数量一致';
      return;
    }
    const finalWeights = weights.length ? weights : remotes.map(()=>1);
    if(finalWeights.some((w)=>Number.isNaN(w) || w <= 0)){
      q('modalMsg').textContent='权重必须为正数';
      return;
    }
    balance = `roundrobin: ${finalWeights.join(', ')}`;
  }

  const typeSel = q('f_type').value;
  const protocolSel = q('f_protocol').value;
  if(typeSel === 'wss_send' || typeSel === 'wss_recv'){
    if(!q('f_wss_host').value.trim() || !q('f_wss_path').value.trim()){
      q('modalMsg').textContent='WSS Host 与 Path 不能为空';
      return;
    }
  }
  const ex = readWssFields();

  const endpoint = {
    listen,
    disabled,
    balance,
    protocol: protocolSel || 'tcp+udp',
    remotes,
    extra_config: ex,
  };

  if(CURRENT_EDIT_INDEX == null){
    CURRENT_POOL.endpoints.push(endpoint);
  }else{
    CURRENT_POOL.endpoints[CURRENT_EDIT_INDEX] = endpoint;
  }

  try{
    await savePool('保存成功');
    closeModal();
    if(typeSel === 'wss_send'){
      const code = encodePairingCode(buildPairingPayload());
      openPairingModal(code);
    }
  }catch(e){
    q('modalMsg').textContent = e.message;
  }
}

async function savePool(msg){
  q('modalMsg') && (q('modalMsg').textContent = '');
  const id = window.__NODE_ID__;
  const res = await fetchJSON(`/api/nodes/${id}/pool`, {
    method:'POST',
    body: JSON.stringify({ pool: CURRENT_POOL })
  });
  if(res.ok){
    CURRENT_POOL = res.pool;
    renderRules();
    if(msg) toast(msg);
  }
}

function toast(text){
  const t = q('toast');
  if(!t) return;
  t.textContent = text;
  t.style.display = 'block';
  setTimeout(()=>{t.style.display='none';}, 1800);
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

function renderTraffic(){
  const body = q('trafficBody');
  const table = q('trafficTable');
  const loading = q('trafficLoading');
  if(!body || !table || !loading) return;
  body.innerHTML = '';
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  const statsLookup = buildStatsLookup();
  if(statsLookup.error){
    loading.style.display = '';
    loading.textContent = `统计获取失败：${statsLookup.error}`;
    table.style.display = 'none';
    return;
  }
  if(!eps.length){
    loading.style.display = '';
    loading.textContent = '暂无规则';
    table.style.display = 'none';
    return;
  }
  loading.style.display = 'none';
  table.style.display = '';
  eps.forEach((e, idx)=>{
    const stats = statsLookup.byIdx[idx] || statsLookup.byListen[e.listen] || {};
    const rx = stats.rx_bytes || 0;
    const tx = stats.tx_bytes || 0;
    const total = rx + tx;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${idx + 1}</td>
      <td>${statusPill(e)}</td>
      <td><div class="mono">${escapeHtml(e.listen)}</div></td>
      <td>${stats.connections ?? 0}</td>
      <td>${formatBytes(rx)}</td>
      <td>${formatBytes(tx)}</td>
      <td>${formatBytes(total)}</td>
    `;
    body.appendChild(tr);
  });
}

async function refreshStats(){
  const id = window.__NODE_ID__;
  const loading = q('trafficLoading');
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
  renderRules();
  renderTraffic();
}

async function loadPool(){
  const id = window.__NODE_ID__;
  q('rulesLoading').style.display = '';
  q('rulesLoading').textContent = '正在加载规则…';
  const trafficLoading = q('trafficLoading');
  if(trafficLoading){
    trafficLoading.style.display = '';
    trafficLoading.textContent = '正在加载流量统计…';
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
    renderTraffic();
  }catch(e){
    q('rulesLoading').textContent = '加载失败：' + e.message;
    if(trafficLoading){
      trafficLoading.textContent = '加载失败：' + e.message;
    }
  }
}

function initNodePage(){
  document.querySelectorAll('.tab').forEach(t=>{
    t.addEventListener('click', ()=>{
      const name = t.getAttribute('data-tab');
      showTab(name);
      if(name === 'traffic') renderTraffic();
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
  loadPool();
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
window.applyPairingCode = applyPairingCode;
window.closePairingModal = closePairingModal;
window.randomizeWss = randomizeWss;
