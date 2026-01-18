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

function showTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tabpane').forEach(p=>p.classList.remove('show'));
  document.querySelector(`.tab[data-tab="${name}"]`).classList.add('active');
  q(`tab-${name}`).classList.add('show');
}

function endpointType(e){
  const ex = e.extra_config || {};
  const hasLisWs = (e.listen_transport || '').includes('ws') || (ex.listen_transport === 'ws');
  const hasRemWs = (e.remote_transport || '').includes('ws') || (ex.remote_transport === 'ws');
  if(hasLisWs) return 'WSS接收';
  if(hasRemWs) return 'WSS发送';
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

function renderRules(){
  q('rulesLoading').style.display = 'none';
  const table = q('rulesTable');
  const tbody = q('rulesBody');
  tbody.innerHTML = '';
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  eps.forEach((e, idx)=>{
    const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${idx+1}</td>
      <td>${statusPill(e)}</td>
      <td><div class="mono">${(e.listen||'').replace(/</g,'&lt;')}</div></td>
      <td><div class="mono">${rs.map(x=>x.replace(/</g,'&lt;')).join('<br>')}</div></td>
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
  updateLBSelect();
}

function openModal(){ q('modal').style.display = 'block'; }
function closeModal(){ q('modal').style.display = 'none'; q('modalMsg').textContent=''; }

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
  } else if(mode === 'wss_recv'){
    ex.listen_transport = 'ws';
  }
  if(mode !== 'tcp'){
    if(host) ex.ws_host = host;
    if(path) ex.ws_path = path;
    if(sni) ex.ws_sni = sni;
    ex.ws_tls = tls;
    ex.ws_insecure = insecure;
  }
  return ex;
}

function fillWssFields(e){
  const ex = e.extra_config || {};
  const mode = endpointType(e);
  if(mode === 'WSS发送') q('f_type').value = 'wss_send';
  else if(mode === 'WSS接收') q('f_type').value = 'wss_recv';
  else q('f_type').value = 'tcp';

  setField('f_wss_host', ex.ws_host || '');
  setField('f_wss_path', ex.ws_path || '');
  setField('f_wss_sni', ex.ws_sni || '');
  q('f_wss_tls').value = (ex.ws_tls === false) ? '0' : '1';
  q('f_wss_insecure').value = (ex.ws_insecure === true) ? '1' : '0';
}

function showWssBox(){
  const mode = q('f_type').value;
  q('wssBox').style.display = (mode === 'tcp') ? 'none' : 'block';
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
  q('f_type').value = 'tcp';
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
  const ex = readWssFields();

  const endpoint = {
    listen,
    disabled,
    balance,
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
  }catch(e){
    q('modalMsg').textContent = e.message;
  }
}

async function savePool(msg){
  q('modalMsg') && (q('modalMsg').textContent = '');
  const id = window.__NODE_ID__;
  const res = await fetchJSON(`/api/nodes/${id}/pool`, {
    method:'POST',
    body: JSON.stringify(CURRENT_POOL)
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

async function applyNow(){
  const id = window.__NODE_ID__;
  const btns = document.querySelectorAll('button');
  try{
    toast('正在应用…');
    await fetchJSON(`/api/nodes/${id}/apply`, {method:'POST'});
    toast('已应用并重启');
  }catch(e){
    alert('应用失败：'+e.message);
  }
}

function updateLBSelect(){
  const sel = q('lbSelect');
  if(!sel) return;
  sel.innerHTML = '';
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  eps.forEach((e, idx)=>{
    const opt = document.createElement('option');
    opt.value = String(idx);
    opt.textContent = `#${idx+1} ${e.listen}`;
    sel.appendChild(opt);
  });
  if(eps.length){
    sel.value = '0';
    renderLB(0);
  }
}

function renderLB(idx){
  const box = q('lbBox');
  if(!CURRENT_POOL || !CURRENT_POOL.endpoints || !CURRENT_POOL.endpoints[idx]){
    box.innerHTML = '<div class="muted">暂无规则</div>';
    return;
  }
  const e = CURRENT_POOL.endpoints[idx];
  const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
  const algo = (e.balance||'roundrobin').split(':')[0];
  let html = `<div class="kv"><div class="k">Listen</div><div class="v mono">${e.listen}</div></div>`;
  html += `<div class="kv"><div class="k">策略</div><div class="v">${algo}</div></div>`;
  html += `<div class="kv"><div class="k">目标数量</div><div class="v">${rs.length}</div></div>`;
  html += `<div style="margin-top:12px;">`;
  rs.forEach((r)=>{
    html += `<div class="lb-item"><div class="mono">${r}</div><div class="bar"></div></div>`;
  });
  html += `</div>`;
  box.innerHTML = html;
}

async function loadGraph(){
  const id = window.__NODE_ID__;
  const box = q('graphBox');
  box.innerHTML = '<div class="muted">正在生成连接图…</div>';
  try{
    const data = await fetchJSON(`/api/nodes/${id}/graph`);
    box.innerHTML = '<div id="cy" style="height:520px;"></div>';
    if(typeof cytoscape !== 'function'){
      const script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/cytoscape@3.28.1/dist/cytoscape.min.js';
      script.onload = ()=>renderGraph(data.elements);
      script.onerror = ()=>{ box.innerHTML = '<div class="muted">加载 Cytoscape 失败（CDN 不可用）</div>'; };
      document.body.appendChild(script);
    }else{
      renderGraph(data.elements);
    }
  }catch(e){
    box.innerHTML = `<div class="muted">生成失败：${e.message}</div>`;
  }
}

function renderGraph(elements){
  const cy = cytoscape({
    container: document.getElementById('cy'),
    elements: elements || [],
    style: [
      { selector: 'node', style: { 'label': 'data(label)', 'color': '#e5e7eb', 'text-wrap':'wrap', 'text-max-width': 120, 'font-size': 10, 'background-color': '#60a5fa' } },
      { selector: 'edge', style: { 'label':'data(label)', 'width':2, 'curve-style':'bezier', 'line-color':'#94a3b8', 'target-arrow-shape':'triangle', 'target-arrow-color':'#94a3b8', 'font-size': 10, 'color':'#94a3b8' } },
      { selector: '.listen', style: { 'background-color':'#22c55e' } },
      { selector: '.remote', style: { 'background-color':'#f59e0b' } },
      { selector: '.disabled', style: { 'opacity': 0.35 } }
    ],
    layout: { name: 'breadthfirst', directed: true, padding: 20 }
  });
  cy.fit();
}

async function loadPool(){
  const id = window.__NODE_ID__;
  q('rulesLoading').style.display = '';
  try{
    const data = await fetchJSON(`/api/nodes/${id}/pool`);
    CURRENT_POOL = data.pool;
    if(!CURRENT_POOL.endpoints) CURRENT_POOL.endpoints = [];
    renderRules();
  }catch(e){
    q('rulesLoading').textContent = '加载失败：' + e.message;
  }
}

function initNodePage(){
  document.querySelectorAll('.tab').forEach(t=>{
    t.addEventListener('click', ()=>{
      const name = t.getAttribute('data-tab');
      showTab(name);
      if(name==='graph') loadGraph();
    });
  });
  q('f_type').addEventListener('change', showWssBox);
  q('lbSelect').addEventListener('change', (ev)=>{
    renderLB(parseInt(ev.target.value,10));
  });
  loadPool();
}

window.initNodePage = initNodePage;
window.editRule = editRule;
window.newRule = newRule;
window.saveRule = saveRule;
window.closeModal = closeModal;
window.toggleRule = toggleRule;
window.deleteRule = deleteRule;
window.applyNow = applyNow;
window.renderLB = renderLB;
