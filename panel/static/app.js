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

function formatRequestError(err, fallback){
  const raw = (err && err.message) ? String(err.message) : String(err || '');
  const msg = raw.trim() || String(fallback || '请求失败');
  if(/load failed|failed to fetch|networkerror|network request failed/i.test(msg)){
    return `${String(fallback || '请求失败')}：网络请求中断（可能节点离线、面板重启中或网关超时）`;
  }
  return msg;
}


async function loadNodesList(){
  try{
    const data = await fetchJSON('/api/nodes');
    if(data && data.ok && Array.isArray(data.nodes)){
      NODES_LIST = data.nodes;
      populateReceiverSelect();
      populateIntranetReceiverSelect();
      try{ syncTunnelModeUI(); }catch(_e){}
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
let SYNC_TASKS = new Map(); // job_id -> task status (sync + pool async jobs)
let SYNC_PENDING_SUBMITS = new Map(); // kind:sync_id -> {kind,sync_id,created_at}
const SYNC_TASK_DONE_KEEP_MS = 12000;

function _modePerms(){
  const raw = (window && window.__MODE_PERMS__ && typeof window.__MODE_PERMS__ === 'object') ? window.__MODE_PERMS__ : {};
  return {
    tcp: !!raw.tcp,
    wss: !!raw.wss,
    intranet: !!raw.intranet,
  };
}

function isModeAllowed(mode){
  const m = String(mode || '').trim().toLowerCase();
  const p = _modePerms();
  if(m === 'wss') return !!p.wss;
  if(m === 'intranet') return !!p.intranet;
  return !!p.tcp;
}

function allowedTunnelModes(){
  const out = [];
  if(isModeAllowed('tcp')) out.push('tcp');
  if(isModeAllowed('wss')) out.push('wss');
  if(isModeAllowed('intranet')) out.push('intranet');
  return out;
}

function defaultTunnelMode(){
  const arr = allowedTunnelModes();
  return arr.length ? arr[0] : 'tcp';
}

function modeDenyReason(mode){
  const m = String(mode || '').trim().toLowerCase();
  if(m === 'wss') return '当前账号无 WSS 隧道权限';
  if(m === 'intranet') return '当前账号无内网穿透权限';
  return '当前账号无普通转发权限';
}

function endpointMode(e){
  const m = wssMode(e);
  if(m === 'wss' || m === 'intranet') return m;
  return 'tcp';
}

function canOperateEndpoint(e){
  return isModeAllowed(endpointMode(e));
}

function _nowTs(){
  return Date.now();
}

function syncTaskKindLabel(kind){
  const k = String(kind || '').trim().toLowerCase();
  if(k === 'wss_save') return 'WSS保存';
  if(k === 'intranet_save') return '内网保存';
  if(k === 'wss_delete') return 'WSS删除';
  if(k === 'intranet_delete') return '内网删除';
  if(k === 'pool_save') return '规则保存';
  if(k === 'rule_delete') return '规则删除';
  return '任务';
}

function syncTaskStatusText(task){
  const st = String((task && task.status) || '').trim().toLowerCase();
  const n = Number((task && task.attempts) || 0);
  const m = Number((task && task.max_attempts) || 0);
  const nm = (n > 0 && m > 0) ? `(${n}/${m})` : '';
  if(st === 'queued') return `排队中${nm}`;
  if(st === 'running') return `同步中${nm}`;
  if(st === 'retrying') return `重试中${nm}`;
  if(st === 'success') return '已生效';
  if(st === 'error') return '失败';
  return st || '未知';
}

function syncTaskStatusCls(task){
  const st = String((task && task.status) || '').trim().toLowerCase();
  if(st === 'success') return 'ok';
  if(st === 'error') return 'bad';
  if(st === 'retrying' || st === 'queued' || st === 'running') return 'warn';
  return 'ghost';
}

function _syncTaskMeta(task){
  const meta = (task && task.meta && typeof task.meta === 'object') ? task.meta : {};
  const listen = String(meta.listen || '').trim();
  const sid = String(meta.sync_id || '').trim();
  const idx = Number(meta.idx != null ? meta.idx : -1);
  return {listen, sid, idx};
}

function _syncTaskLabel(task){
  const {listen, sid, idx} = _syncTaskMeta(task);
  const k = syncTaskKindLabel(task && task.kind);
  if(listen) return `${k} ${listen}`;
  if(Number.isFinite(idx) && idx >= 0) return `${k} #${idx + 1}`;
  if(sid) return `${k} ${sid.slice(0, 8)}`;
  const jid = String((task && task.job_id) || '').trim();
  return `${k} ${jid.slice(0, 8)}`;
}

function _syncTasksOrdered(){
  const now = _nowTs();
  const arr = [];
  for(const [jid, task] of Array.from(SYNC_TASKS.entries())){
    if(!task || typeof task !== 'object'){
      SYNC_TASKS.delete(jid);
      continue;
    }
    const st = String(task.status || '').trim().toLowerCase();
    const doneAt = Number(task.done_at_ms || 0);
    if((st === 'success') && doneAt > 0 && (now - doneAt) > SYNC_TASK_DONE_KEEP_MS){
      SYNC_TASKS.delete(jid);
      continue;
    }
    arr.push(task);
  }
  arr.sort((a, b)=>{
    const ap = (a.status === 'error') ? 0 : ((a.status === 'running' || a.status === 'retrying' || a.status === 'queued') ? 1 : 2);
    const bp = (b.status === 'error') ? 0 : ((b.status === 'running' || b.status === 'retrying' || b.status === 'queued') ? 1 : 2);
    if(ap !== bp) return ap - bp;
    const at = Number(a.updated_at_ms || a.created_at_ms || 0);
    const bt = Number(b.updated_at_ms || b.created_at_ms || 0);
    return bt - at;
  });
  return arr;
}

function _syncIdentityFromRule(e){
  const ex = (e && e.extra_config && typeof e.extra_config === 'object') ? e.extra_config : {};
  const sid = String(ex.sync_id || '').trim();
  if(!sid) return {kind:'', sync_id:''};
  if(ex && (ex.intranet_role || ex.intranet_peer_node_id || ex.intranet_lock)){
    return {kind:'intranet', sync_id:sid};
  }
  if(ex && (ex.sync_role || ex.sync_peer_node_id || ex.sync_lock)){
    return {kind:'wss', sync_id:sid};
  }
  return {kind:'', sync_id:''};
}

function _syncTaskMatchKind(taskKind, tunnelKind){
  const tk = String(taskKind || '').trim().toLowerCase();
  const kk = String(tunnelKind || '').trim().toLowerCase();
  if(kk === 'wss') return tk === 'wss_save' || tk === 'wss_delete';
  if(kk === 'intranet') return tk === 'intranet_save' || tk === 'intranet_delete';
  return false;
}

function _findSyncTaskForRule(e){
  const ident = _syncIdentityFromRule(e);
  if(!ident.kind || !ident.sync_id) return null;
  let newestActive = null;
  let newestSuccess = null;
  let newestError = null;
  const _ts = (task)=>{
    const t1 = Number((task && task.updated_at_ms) || 0);
    if(Number.isFinite(t1) && t1 > 0) return t1;
    const t2 = Number((task && task.created_at_ms) || 0);
    if(Number.isFinite(t2) && t2 > 0) return t2;
    const t3 = Number((task && task.updated_at) || 0);
    if(Number.isFinite(t3) && t3 > 0) return t3 * 1000;
    const t4 = Number((task && task.created_at) || 0);
    if(Number.isFinite(t4) && t4 > 0) return t4 * 1000;
    return 0;
  };
  for(const task of _syncTasksOrdered()){
    if(!_syncTaskMatchKind(task && task.kind, ident.kind)) continue;
    const meta = (task && task.meta && typeof task.meta === 'object') ? task.meta : {};
    const sid = String(meta.sync_id || '').trim();
    if(sid !== ident.sync_id) continue;
    const st = String((task && task.status) || '').trim().toLowerCase();
    const curTs = _ts(task);
    if(st === 'queued' || st === 'running' || st === 'retrying'){
      if(!newestActive || curTs >= _ts(newestActive)) newestActive = task;
      continue;
    }
    if(st === 'success'){
      if(!newestSuccess || curTs >= _ts(newestSuccess)) newestSuccess = task;
      continue;
    }
    if(st === 'error'){
      if(!newestError || curTs >= _ts(newestError)) newestError = task;
    }
  }
  return newestActive || newestSuccess || newestError;
}

function _syncPendingKey(kind, syncId){
  const k = String(kind || '').trim().toLowerCase();
  const sid = String(syncId || '').trim();
  if(!k || !sid) return '';
  return `${k}:${sid}`;
}

function _setSyncPendingSubmit(kind, syncId, on){
  const key = _syncPendingKey(kind, syncId);
  if(!key) return;
  if(on){
    SYNC_PENDING_SUBMITS.set(key, {kind: String(kind || ''), sync_id: String(syncId || ''), created_at: _nowTs()});
  }else{
    SYNC_PENDING_SUBMITS.delete(key);
  }
}

function renderSyncTasksBar(){
  const bar = q('nodeSummary');
  if(!bar) return;
  const tasks = _syncTasksOrdered();
  if(!tasks.length){
    bar.style.display = 'none';
    bar.innerHTML = '';
    return;
  }
  const html = tasks.slice(0, 8).map((task)=>{
    const label = _syncTaskLabel(task);
    const stText = syncTaskStatusText(task);
    const stCls = syncTaskStatusCls(task);
    const err = String(task.error || '').trim();
    const jid = String(task.job_id || '').trim();
    const retryBtn = (String(task.status || '').trim() === 'error')
      ? `<button class="btn xs ghost" type="button" onclick="retrySyncTask('${escapeHtml(jid)}')">重试</button>`
      : '';
    return `<span class="summary-pill" title="${escapeHtml(jid)}">
      <strong>${escapeHtml(label)}</strong>
      <span class="pill xs ${stCls}">${escapeHtml(stText)}</span>
      ${err ? `<span class="muted sm">${escapeHtml(err)}</span>` : ''}
      ${retryBtn}
    </span>`;
  }).join('');
  bar.innerHTML = html;
  bar.style.display = '';
}

function _setSyncTask(task){
  if(!task || typeof task !== 'object') return;
  const jid = String(task.job_id || '').trim();
  if(!jid) return;
  const prev = SYNC_TASKS.get(jid) || {};
  const next = Object.assign({}, prev, task);
  if(!next.created_at_ms){
    next.created_at_ms = _nowTs();
  }
  next.updated_at_ms = _nowTs();
  SYNC_TASKS.set(jid, next);
  renderSyncTasksBar();
}

function _markSyncTaskDone(jobId, status){
  const jid = String(jobId || '').trim();
  if(!jid) return;
  const cur = SYNC_TASKS.get(jid);
  if(!cur) return;
  cur.status = status || cur.status;
  cur.done_at_ms = _nowTs();
  cur.updated_at_ms = _nowTs();
  SYNC_TASKS.set(jid, cur);
  renderSyncTasksBar();
}

async function _sleep(ms){
  const n = Number(ms) || 0;
  return await new Promise((resolve)=>setTimeout(resolve, Math.max(50, n)));
}

function _syncJobToTask(job, fallback){
  const fb = (fallback && typeof fallback === 'object') ? fallback : {};
  const j = (job && typeof job === 'object') ? job : {};
  return {
    job_id: String(j.job_id || fb.job_id || '').trim(),
    kind: String(j.kind || fb.kind || '').trim(),
    status: String(j.status || fb.status || '').trim(),
    attempts: Number(j.attempts != null ? j.attempts : (fb.attempts || 0)),
    max_attempts: Number(j.max_attempts != null ? j.max_attempts : (fb.max_attempts || 0)),
    error: String(j.error || '').trim(),
    status_code: Number(j.status_code || 0),
    created_at: Number(j.created_at || 0),
    updated_at: Number(j.updated_at || 0),
    next_retry_at: Number(j.next_retry_at || 0),
    result: (j.result && typeof j.result === 'object') ? j.result : {},
    meta: (j.meta && typeof j.meta === 'object') ? j.meta : ((fb.meta && typeof fb.meta === 'object') ? fb.meta : {}),
    ok_msg: String(fb.ok_msg || ''),
    error_prefix: String(fb.error_prefix || '同步失败'),
    status_url: String(j.status_url || fb.status_url || '').trim(),
    retry_url: String(j.retry_url || fb.retry_url || '').trim(),
    status_url_template: String(fb.status_url_template || ''),
    retry_url_template: String(fb.retry_url_template || ''),
    payload: (fb.payload && typeof fb.payload === 'object') ? fb.payload : {},
  };
}

function _jobUrlWithId(template, jobId){
  const tpl = String(template || '').trim();
  const jid = String(jobId || '').trim();
  if(!tpl || !jid) return '';
  return tpl.replace('{job_id}', encodeURIComponent(jid));
}

async function pollSyncTask(jobId){
  const jid = String(jobId || '').trim();
  if(!jid) return;
  for(let i=0; i<600; i++){
    const local = SYNC_TASKS.get(jid);
    if(!local) return;
    const statusUrl = String(local.status_url || '').trim() || `/api/sync_jobs/${encodeURIComponent(jid)}`;
    let data = null;
    try{
      data = await fetchJSON(statusUrl);
    }catch(err){
      const msg = formatRequestError(err, '读取任务状态失败');
      _setSyncTask(Object.assign({}, local, {error: msg}));
      await _sleep(1200);
      continue;
    }
    if(!(data && data.ok && data.job)){
      _setSyncTask(Object.assign({}, local, {error: (data && data.error) ? String(data.error) : '任务状态读取失败'}));
      await _sleep(1200);
      continue;
    }
    const task = _syncJobToTask(data.job, local);
    _setSyncTask(task);
    const st = String(task.status || '').trim().toLowerCase();
    if(st === 'success'){
      const result = (task.result && typeof task.result === 'object') ? task.result : {};
      if(result.sender_pool && typeof result.sender_pool === 'object'){
        CURRENT_POOL = result.sender_pool;
        if(!CURRENT_POOL.endpoints) CURRENT_POOL.endpoints = [];
      }else if(result.pool && typeof result.pool === 'object'){
        CURRENT_POOL = result.pool;
        if(!CURRENT_POOL.endpoints) CURRENT_POOL.endpoints = [];
      }else{
        try{ await loadPool(); }catch(_e){}
      }
      renderRules();
      toastWithPrecheck(result, task.ok_msg || '同步完成');
      _markSyncTaskDone(jid, 'success');
      return;
    }
    if(st === 'error'){
      const reason = String(task.error || ((task.result && task.result.error) ? task.result.error : '同步失败')).trim();
      _setSyncTask(Object.assign({}, task, {error: reason}));
      const k = String(task.kind || '').trim().toLowerCase();
      if(k === 'pool_save' || k === 'rule_delete'){
        try{
          await loadPool();
          renderRules();
        }catch(_e){}
      }
      toast(`${String(task.error_prefix || '同步失败')}：${reason}`, true, 5200);
      return;
    }
    await _sleep(900);
  }
}

async function enqueueSyncTask(url, payload, options){
  const opts = (options && typeof options === 'object') ? options : {};
  const res = await fetchJSON(url, {method:'POST', body: JSON.stringify(payload || {})});
  const job = (res && res.job && typeof res.job === 'object') ? res.job : null;
  if(!(res && res.ok && job && job.job_id)){
    throw new Error((res && res.error) ? String(res.error) : '提交任务失败');
  }
  const fallback = {
    kind: String(opts.kind || '').trim(),
    ok_msg: String(opts.ok_msg || '').trim(),
    error_prefix: String(opts.error_prefix || '同步失败').trim(),
    payload: (payload && typeof payload === 'object') ? payload : {},
    meta: (opts.meta && typeof opts.meta === 'object') ? opts.meta : {},
    status_url_template: String(opts.status_url_template || ''),
    retry_url_template: String(opts.retry_url_template || ''),
  };
  const task = _syncJobToTask(job, fallback);
  if(!task.status) task.status = 'queued';
  if(!task.kind) task.kind = fallback.kind || 'task';
  if(!task.status_url){
    task.status_url = _jobUrlWithId(task.status_url_template, task.job_id) || `/api/sync_jobs/${encodeURIComponent(task.job_id)}`;
  }
  if(!task.retry_url){
    task.retry_url = _jobUrlWithId(task.retry_url_template, task.job_id) || `/api/sync_jobs/${encodeURIComponent(task.job_id)}/retry`;
  }
  _setSyncTask(task);
  pollSyncTask(task.job_id);
  return task;
}

async function enqueueSyncSaveTask(kind, payload, okMsg){
  const k = String(kind || '').trim().toLowerCase();
  const url = (k === 'intranet') ? '/api/intranet_tunnel/save_async' : '/api/wss_tunnel/save_async';
  const kk = (k === 'intranet') ? 'intranet_save' : 'wss_save';
  return await enqueueSyncTask(url, payload || {}, {
    kind: kk,
    ok_msg: String(okMsg || '').trim(),
    error_prefix: '同步失败',
    status_url_template: '/api/sync_jobs/{job_id}',
    retry_url_template: '/api/sync_jobs/{job_id}/retry',
  });
}

async function enqueueSyncDeleteTask(kind, payload, okMsg){
  const k = String(kind || '').trim().toLowerCase();
  const url = (k === 'intranet') ? '/api/intranet_tunnel/delete_async' : '/api/wss_tunnel/delete_async';
  const kk = (k === 'intranet') ? 'intranet_delete' : 'wss_delete';
  return await enqueueSyncTask(url, payload || {}, {
    kind: kk,
    ok_msg: String(okMsg || '').trim(),
    error_prefix: '同步删除失败',
    status_url_template: '/api/sync_jobs/{job_id}',
    retry_url_template: '/api/sync_jobs/{job_id}/retry',
  });
}

async function enqueueNodePoolTask(kind, payload, okMsg){
  const nodeId = window.__NODE_ID__;
  const k = String(kind || '').trim().toLowerCase();
  const url = (k === 'rule_delete')
    ? `/api/nodes/${encodeURIComponent(nodeId)}/rule_delete_async`
    : `/api/nodes/${encodeURIComponent(nodeId)}/pool_async`;
  const kk = (k === 'rule_delete') ? 'rule_delete' : 'pool_save';
  const okText = String(okMsg || (kk === 'rule_delete' ? '已删除' : '已保存')).trim();
  const errPrefix = (kk === 'rule_delete') ? '规则删除失败' : '规则保存失败';
  return await enqueueSyncTask(url, payload || {}, {
    kind: kk,
    ok_msg: okText,
    error_prefix: errPrefix,
    status_url_template: `/api/nodes/${encodeURIComponent(nodeId)}/pool_jobs/{job_id}`,
    retry_url_template: `/api/nodes/${encodeURIComponent(nodeId)}/pool_jobs/{job_id}/retry`,
  });
}

async function retrySyncTask(jobId){
  const jid = String(jobId || '').trim();
  if(!jid) return;
  const cur = SYNC_TASKS.get(jid);
  try{
    const retryUrl = (cur && cur.retry_url)
      ? String(cur.retry_url)
      : (_jobUrlWithId(cur && cur.retry_url_template, jid) || `/api/sync_jobs/${encodeURIComponent(jid)}/retry`);
    const res = await fetchJSON(retryUrl, {method:'POST', body: JSON.stringify({})});
    if(!(res && res.ok && res.job && res.job.job_id)){
      throw new Error((res && res.error) ? String(res.error) : '重试任务创建失败');
    }
    const task = _syncJobToTask(res.job, cur || {});
    if(cur && cur.ok_msg) task.ok_msg = cur.ok_msg;
    if(cur && cur.payload) task.payload = cur.payload;
    if(!task.status_url){
      task.status_url = _jobUrlWithId(task.status_url_template, task.job_id) || `/api/sync_jobs/${encodeURIComponent(task.job_id)}`;
    }
    if(!task.retry_url){
      task.retry_url = _jobUrlWithId(task.retry_url_template, task.job_id) || `/api/sync_jobs/${encodeURIComponent(task.job_id)}/retry`;
    }
    _setSyncTask(task);
    pollSyncTask(task.job_id);
    toast('已提交重试任务');
  }catch(err){
    toast(formatRequestError(err, '创建重试任务失败'), true);
  }
}
window.retrySyncTask = retrySyncTask;

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

// Rules search / filters
// - RULE_FILTER_TEXT: full-text query (supports key:value syntax)
// - RULE_QUICK_FILTER: quick select filter from UI
let RULE_FILTER_TEXT = '';
let RULE_QUICK_FILTER = '';
let RULE_META_SAVING = false;

// Rules selection (for bulk operations)
// - Store selection by a stable key (sync_id for tunnels; listen+protocol for normal rules)
let RULE_SELECTED_KEYS = new Set();
let LAST_VISIBLE_RULE_KEYS = [];
let BULK_ACTION_RUNNING = false;
const RULE_TEMP_UNLOCK_TTL_MS = 45000;
let RULE_TEMP_UNLOCK = new Map(); // key -> expire_at_ms
let RULE_TEMP_UNLOCK_TIMER = 0;

function cleanupRuleTempUnlock(){
  const now = Date.now();
  let changed = false;
  for(const [k, ts] of Array.from(RULE_TEMP_UNLOCK.entries())){
    if(!k || !Number.isFinite(ts) || ts <= now){
      RULE_TEMP_UNLOCK.delete(k);
      changed = true;
    }
  }
  return changed;
}

function scheduleRuleTempUnlockTimer(){
  try{
    if(RULE_TEMP_UNLOCK_TIMER){
      clearTimeout(RULE_TEMP_UNLOCK_TIMER);
      RULE_TEMP_UNLOCK_TIMER = 0;
    }
  }catch(_e){}
  cleanupRuleTempUnlock();
  if(!RULE_TEMP_UNLOCK.size) return;
  let nextTs = 0;
  for(const ts of RULE_TEMP_UNLOCK.values()){
    if(Number.isFinite(ts) && (nextTs <= 0 || ts < nextTs)) nextTs = ts;
  }
  if(nextTs <= 0) return;
  const delay = Math.max(100, nextTs - Date.now() + 50);
  RULE_TEMP_UNLOCK_TIMER = setTimeout(()=>{
    cleanupRuleTempUnlock();
    renderRules();
    scheduleRuleTempUnlockTimer();
  }, delay);
}

function isRuleTempUnlocked(e){
  cleanupRuleTempUnlock();
  const key = getRuleKey(e);
  if(!key) return false;
  const ts = Number(RULE_TEMP_UNLOCK.get(key) || 0);
  return Number.isFinite(ts) && ts > Date.now();
}

function getRuleTempUnlockLeftSec(e){
  cleanupRuleTempUnlock();
  const key = getRuleKey(e);
  if(!key) return 0;
  const ts = Number(RULE_TEMP_UNLOCK.get(key) || 0);
  if(!Number.isFinite(ts) || ts <= Date.now()) return 0;
  return Math.max(1, Math.ceil((ts - Date.now()) / 1000));
}

function collectUnlockSyncIds(){
  cleanupRuleTempUnlock();
  const out = [];
  for(const [k, ts] of RULE_TEMP_UNLOCK.entries()){
    if(!k || !Number.isFinite(ts) || ts <= Date.now()) continue;
    const s = String(k);
    if(!s.startsWith('wss:')) continue;
    const sid = s.slice(4).trim();
    if(sid) out.push(sid);
  }
  return Array.from(new Set(out));
}

function getRuleKey(e){
  if(!e) return '';
  const ex = (e && e.extra_config) ? e.extra_config : {};
  // WSS tunnel rules
  if(ex && ex.sync_id && (ex.sync_role || ex.sync_peer_node_id || ex.sync_lock)){
    return `wss:${String(ex.sync_id)}`;
  }
  // Intranet tunnel rules
  if(ex && ex.sync_id && (ex.intranet_role || ex.intranet_peer_node_id || ex.intranet_lock)){
    return `intranet:${String(ex.sync_id)}`;
  }
  // Normal rules (listen+protocol should be unique per node)
  const listen = String(e.listen || '').trim();
  const proto = String(e.protocol || 'tcp+udp').trim().toLowerCase();
  return `tcp:${listen}|${proto}`;
}

function getSelectedRuleItems(){
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  const out = [];
  for(let idx=0; idx<eps.length; idx++){
    const e = eps[idx];
    const k = getRuleKey(e);
    if(k && RULE_SELECTED_KEYS.has(k)){
      out.push({idx, e, key: k});
    }
  }
  return out;
}

function clearRuleSelection(){
  RULE_SELECTED_KEYS = new Set();
  updateBulkBar();
  renderRules();
}
window.clearRuleSelection = clearRuleSelection;

function setRuleSelectedByIdx(idx, checked, ev){
  try{
    if(ev){
      ev.preventDefault && ev.preventDefault();
      ev.stopPropagation && ev.stopPropagation();
    }
  }catch(_e){}
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  const e = eps[idx];
  if(!e) return;
  const k = getRuleKey(e);
  if(!k) return;
  if(checked) RULE_SELECTED_KEYS.add(k);
  else RULE_SELECTED_KEYS.delete(k);
  updateBulkBar();
  updateSelectAllCheckbox();
}
window.setRuleSelectedByIdx = setRuleSelectedByIdx;

function toggleSelectAllVisible(checked){
  const on = !!checked;
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  const keys = Array.isArray(LAST_VISIBLE_RULE_KEYS) ? LAST_VISIBLE_RULE_KEYS : [];
  for(const k of keys){
    if(!k) continue;
    // Skip locked rules
    let ep = null;
    for(const e of eps){
      if(getRuleKey(e) === k){ ep = e; break; }
    }
    if(ep){
      const li = getRuleLockInfo(ep);
      if(li && li.locked) continue;
    }
    if(on) RULE_SELECTED_KEYS.add(k);
    else RULE_SELECTED_KEYS.delete(k);
  }
  updateBulkBar();
  renderRules();
}
window.toggleSelectAllVisible = toggleSelectAllVisible;

function updateSelectAllCheckbox(){
  const cb = document.getElementById('rulesSelectAll');
  if(!cb) return;
  const keys = Array.isArray(LAST_VISIBLE_RULE_KEYS) ? LAST_VISIBLE_RULE_KEYS.filter(Boolean) : [];
  if(keys.length === 0){
    cb.checked = false;
    cb.indeterminate = false;
    return;
  }
  let sel = 0;
  let selectable = 0;
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  for(const k of keys){
    let ep = null;
    for(const e of eps){
      if(getRuleKey(e) === k){ ep = e; break; }
    }
    if(ep){
      const li = getRuleLockInfo(ep);
      if(li && li.locked) continue;
    }
    selectable += 1;
    if(RULE_SELECTED_KEYS.has(k)) sel += 1;
  }
  if(selectable === 0){
    cb.checked = false;
    cb.indeterminate = false;
    return;
  }
  cb.checked = (sel === selectable);
  cb.indeterminate = (sel > 0 && sel < selectable);
}

function updateBulkBar(){
  // Prune removed rules from selection
  try{
    const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
    const exist = new Set(eps.map(getRuleKey).filter(Boolean));
    for(const k of Array.from(RULE_SELECTED_KEYS)){
      if(!exist.has(k)) RULE_SELECTED_KEYS.delete(k);
    }
  }catch(_e){}

  const bar = document.getElementById('bulkBar');
  const label = document.getElementById('bulkCount');
  const n = RULE_SELECTED_KEYS.size;
  if(label) label.textContent = `已选 ${n}`;
  if(bar) bar.style.display = n > 0 ? '' : 'none';
}

function setRuleFilter(v){
  RULE_FILTER_TEXT = String(v || '');
  renderRules();
}
window.setRuleFilter = setRuleFilter;

function setRuleQuickFilter(v){
  RULE_QUICK_FILTER = String(v || '').trim();
  renderRules();
}
window.setRuleQuickFilter = setRuleQuickFilter;

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

  // IMPORTANT:
  // WSS 隧道属于「双节点自动同步」功能，应当仅由 sync_* 元数据判定。
  // 如果用户在普通转发里手动配置了 ws/wss transport（listen_transport / remote_transport），
  // 不能误判为隧道模式，否则会强制要求选择接收机节点并导致编辑/保存异常。
  if(ex && (ex.sync_id || ex.sync_role || ex.sync_peer_node_id || ex.sync_lock)) return 'wss';
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

// Auto-sync rules are read-only on the generated side (receiver / intranet client)
function getRuleLockInfo(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  // WSS: receiver side is generated by sender sync
  if(ex && (ex.sync_lock === true || ex.sync_role === 'receiver')){
    const leftSec = getRuleTempUnlockLeftSec(e);
    if(leftSec > 0){
      return {
        locked: false,
        kind: 'wss_receiver',
        temp_unlocked: true,
        unlock_left_sec: leftSec,
        reason: `该规则由 WSS 自动同步生成，当前临时解锁中（约 ${leftSec} 秒后自动重新锁定）。`,
      };
    }
    return {
      locked: true,
      kind: 'wss_receiver',
      temp_unlocked: false,
      reason: '该规则由 WSS 自动同步生成（接收机侧只读）。可点“锁定”按钮临时解锁。'
    };
  }
  // Intranet: client side is generated by server sync
  if(ex && intranetIsLocked(e)){
    return {
      locked: true,
      kind: 'intranet_client',
      reason: '该规则由内网穿透自动同步生成（内网出口侧只读），请在公网入口侧编辑。'
    };
  }
  return { locked: false, kind: '', reason: '' };
}

function getWssReceiverSenderLabel(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  if(!(ex && ex.sync_role === 'receiver')) return '';
  const name = String(ex.sync_from_node_name || '').trim();
  const idRaw = parseInt(ex.sync_from_node_id || 0, 10);
  if(name && idRaw > 0) return `${name}（ID:${idRaw}）`;
  if(name) return name;
  if(idRaw > 0) return `ID:${idRaw}`;
  return '';
}

function renderRuleSourceInfo(e){
  const sender = getWssReceiverSenderLabel(e);
  if(sender){
    return `<div class="muted sm">发送端：${escapeHtml(sender)}</div>`;
  }
  return '';
}

function renderRuleLockBtn(e, idx, lockInfo){
  const li = lockInfo || getRuleLockInfo(e);
  if(!(li && li.kind === 'wss_receiver')) return '';
  if(li.locked){
    return `<button class="btn xs ghost" title="临时解锁 ${Math.ceil(RULE_TEMP_UNLOCK_TTL_MS/1000)} 秒" onclick="toggleRuleTempUnlock(${idx}, event)">🔒 已锁定</button>`;
  }
  const left = Math.max(1, parseInt(li.unlock_left_sec || 0, 10));
  return `<button class="btn xs ghost" title="临时解锁中，点击立即重新锁定" onclick="toggleRuleTempUnlock(${idx}, event)">🔓 ${left}s</button>`;
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

function getRuleRemark(e){
  const v = (e && (e.remark !== undefined)) ? e.remark : '';
  return String(v || '').trim();
}

function isRuleFavorite(e){
  const v = e && (e.favorite !== undefined) ? e.favorite : false;
  return !!v;
}

function getFinalTargets(e){
  // For synced tunnels, use original remotes as the "real" targets.
  const ex = (e && e.extra_config) ? e.extra_config : {};
  if(ex && ex.sync_role === 'sender' && Array.isArray(ex.sync_original_remotes)){
    return ex.sync_original_remotes.map(x=>String(x||'').trim()).filter(Boolean);
  }
  if(ex && ex.intranet_role === 'server' && Array.isArray(ex.intranet_original_remotes)){
    return ex.intranet_original_remotes.map(x=>String(x||'').trim()).filter(Boolean);
  }
  const rs = Array.isArray(e.remotes) ? e.remotes : (e.remote ? [e.remote] : []);
  return rs.map(x=>String(x||'').trim()).filter(Boolean);
}

function getAllSearchTargets(e){
  // Include both "current" remotes and "final" targets so searching works well for synced rules.
  const out = [];
  const seen = new Set();
  const push = (arr)=>{
    (arr||[]).forEach(x=>{
      const s = String(x||'').trim();
      if(!s) return;
      if(seen.has(s)) return;
      seen.add(s);
      out.push(s);
    });
  };
  push(Array.isArray(e && e.remotes) ? e.remotes : (e && e.remote ? [e.remote] : []));
  push(getFinalTargets(e));
  // also include extra_remotes if user imported old schema
  push(Array.isArray(e && e.extra_remotes) ? e.extra_remotes : []);
  return out;
}

function isAdaptiveLbEnabled(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  const raw = ex ? ex.adaptive_lb_enabled : undefined;
  if(raw === false) return false;
  if(raw === true || raw == null) return true;
  const s = String(raw || '').trim().toLowerCase();
  if(!s) return true;
  return !['0','false','off','no'].includes(s);
}

function setAdaptiveLbEnabled(endpoint, enabled){
  const ep = endpoint || {};
  const on = !!enabled;
  let ex = (ep.extra_config && typeof ep.extra_config === 'object' && !Array.isArray(ep.extra_config))
    ? {...ep.extra_config}
    : {};
  if(on){
    try{ delete ex.adaptive_lb_enabled; }catch(_e){}
  }else{
    ex.adaptive_lb_enabled = false;
  }
  try{
    if(Object.keys(ex).length > 0) ep.extra_config = ex;
    else delete ep.extra_config;
  }catch(_e){}
}

function collectRuleRemotes(e){
  const out = [];
  const push = (x)=>{
    const s = String(x || '').trim();
    if(s) out.push(s);
  };
  if(e && typeof e.remote === 'string') push(e.remote);
  if(e && Array.isArray(e.remotes)) e.remotes.forEach(push);
  if(e && Array.isArray(e.extra_remotes)) e.extra_remotes.forEach(push);

  const dedup = [];
  const seen = new Set();
  for(const r of out){
    if(seen.has(r)) continue;
    seen.add(r);
    dedup.push(r);
  }
  return dedup;
}

function parseRuleBalance(balance, remoteCount){
  const n = Math.max(0, parseInt(remoteCount || 0, 10));
  let raw = String(balance || 'roundrobin').trim();
  if(!raw) raw = 'roundrobin';
  let algo = raw;
  let right = '';
  if(raw.includes(':')){
    const arr = raw.split(':');
    algo = String(arr.shift() || '');
    right = arr.join(':');
  }
  let norm = algo.toLowerCase();
  norm = norm.replace(/[_\-\s]/g, '');
  if(norm === 'iphash'){
    return {algo:'iphash', weights:[]};
  }

  let weights = [];
  if(right){
    weights = right
      .replace(/，/g, ',')
      .split(',')
      .map(x=>String(x || '').trim())
      .filter(Boolean)
      .map(x=>parseInt(x, 10))
      .filter(x=>Number.isFinite(x) && x > 0);
  }
  if(n > 0 && weights.length !== n){
    weights = Array(n).fill(1);
  }
  return {algo:'roundrobin', weights};
}

function findHealthByTarget(healthList, target){
  const t = String(target || '').trim();
  if(!t) return null;
  const list = Array.isArray(healthList) ? healthList : [];
  for(const it of list){
    if(!it || typeof it !== 'object') continue;
    const x = String(it.target || '').trim();
    if(!x) continue;
    if(x === t) return it;
    if(x.startsWith('WSS ') && x.slice(4).trim() === t) return it;
  }
  return null;
}

function fmtPct(v){
  const n = Number(v);
  if(!Number.isFinite(n)) return '';
  return (n >= 10 ? n.toFixed(0) : n.toFixed(1)) + '%';
}

function formatHealthAvailability(item){
  const raw = Number(item && item.availability);
  if(!Number.isFinite(raw)) return '';
  const pctRaw = (raw >= 0 && raw <= 1) ? (raw * 100) : raw;
  const pct = Math.max(0, Math.min(100, pctRaw));
  const txt = fmtPct(pct);
  return txt ? `可用率 ${txt}` : '';
}

function renderHealthTargetMeta(item, mobile){
  const t = (item && item.target != null) ? String(item.target) : '';
  const avail = formatHealthAvailability(item);
  if(mobile){
    return `<div class="health-target-line">
      <div class="mono health-target" title="${escapeHtml(t)}">${escapeHtml(t)}</div>
      ${avail ? `<span class="health-avail">${escapeHtml(avail)}</span>` : ''}
    </div>`;
  }
  return `<span class="mono health-target" title="${escapeHtml(t)}">${escapeHtml(t)}</span>
    ${avail ? `<span class="health-avail">${escapeHtml(avail)}</span>` : ''}`;
}

function renderAdaptiveInfo(e, stats, statsError){
  if(wssMode(e) !== 'tcp') return '';
  const remotes = collectRuleRemotes(e);
  if(remotes.length < 2) return '';
  const enabled = isAdaptiveLbEnabled(e);
  const b = parseRuleBalance(e && e.balance, remotes.length);
  const weightsText = (b.algo === 'roundrobin')
    ? ((Array.isArray(b.weights) && b.weights.length) ? b.weights.join(',') : Array(remotes.length).fill(1).join(','))
    : 'IP Hash（无权重）';
  const weightLabel = enabled ? '当前自动权重' : '当前权重';

  return `<div class="adaptive-info">
    <span class="pill xs ${enabled ? 'ok' : 'warn'}">自适应：${enabled ? '开' : '关'}</span>
    <span class="pill xs ghost">${escapeHtml(weightLabel)}：${escapeHtml(weightsText)}</span>
  </div>`;
}

function isLoadBalanceRule(e){
  const targets = getFinalTargets(e);
  return Array.isArray(targets) && targets.length > 1;
}

function getPeerText(e){
  const ex = (e && e.extra_config) ? e.extra_config : {};
  const parts = [];
  if(ex){
    if(ex.sync_peer_node_name) parts.push(ex.sync_peer_node_name);
    if(ex.sync_from_node_name) parts.push(ex.sync_from_node_name);
    if(ex.intranet_peer_node_name) parts.push(ex.intranet_peer_node_name);
    if(ex.intranet_peer_host) parts.push(ex.intranet_peer_host);
    if(ex.intranet_public_host) parts.push(ex.intranet_public_host);
  }
  return parts.map(x=>String(x||'').trim()).filter(Boolean).join(' ');
}

function buildRuleHaystack(e){
  // A single string used for free-text matching.
  // Keep this stable and inclusive so search "just works".
  const parts = [];
  parts.push(String(e && e.listen || ''));
  parts.push(getAllSearchTargets(e).join(' '));
  parts.push(getRuleRemark(e));
  parts.push(endpointType(e));
  parts.push(getPeerText(e));
  parts.push(String(e && e.protocol || ''));
  return parts.join(' \n ').toLowerCase();
}

function tokenizeQuery(text){
  const raw = String(text || '').trim();
  if(!raw) return [];
  // Support quoted segments: "a b" and 'a b'
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  const out = [];
  let m;
  while((m = re.exec(raw)) !== null){
    const tok = (m[1] !== undefined) ? m[1] : (m[2] !== undefined ? m[2] : m[3]);
    if(tok === undefined) continue;
    const s = String(tok).trim();
    if(s) out.push(s);
  }
  return out;
}

function normQueryKey(key){
  const k = String(key || '').trim().toLowerCase();
  if(!k) return '';
  if(k === 'l' || k === 'listen' || k === 'local') return 'listen';
  if(k === 'r' || k === 'remote' || k === 'remotes' || k === 'target' || k === 'to') return 'remote';
  if(k === 'm' || k === 'remark' || k === 'note' || k === 'memo') return 'remark';
  if(k === 't' || k === 'type' || k === 'mode') return 'type';
  if(k === 's' || k === 'status' || k === 'state') return 'status';
  if(k === 'fav' || k === 'favorite' || k === 'star') return 'fav';
  if(k === 'lb' || k === 'balance') return 'lb';
  if(k === 'p' || k === 'port') return 'port';
  if(k === 'peer' || k === 'node') return 'peer';
  if(k === 'proto' || k === 'protocol') return 'protocol';
  if(k === 'id') return 'id';
  return k;
}

function addQueryKV(map, key, value){
  const k = normQueryKey(key);
  if(!k) return;
  if(!map[k]) map[k] = [];
  if(value === undefined || value === null) return;
  const v = String(value).trim();
  if(v === '') return;
  map[k].push(v.toLowerCase());
}

function parseBoolLike(v){
  if(typeof v === 'boolean') return v;
  const s = String(v || '').trim().toLowerCase();
  if(!s) return false;
  return (s === '1' || s === 'true' || s === 'yes' || s === 'y' || s === 'on');
}

function parsePortExpr(expr){
  const raw = String(expr || '').trim();
  if(!raw) return null;
  const m1 = raw.match(/^(>=|<=|>|<)\s*(\d+)$/);
  if(m1){
    return {op: m1[1], n: parseInt(m1[2], 10)};
  }
  const m2 = raw.match(/^(\d+)\s*-\s*(\d+)$/);
  if(m2){
    return {op: 'range', a: parseInt(m2[1], 10), b: parseInt(m2[2], 10)};
  }
  if(/^\d+$/.test(raw)){
    return {op: '=', n: parseInt(raw, 10)};
  }
  return null;
}

function matchPort(portNum, expr){
  const p = parseInt(portNum || 0, 10);
  const e = parsePortExpr(expr);
  if(!e) return false;
  if(e.op === '=') return p === e.n;
  if(e.op === '>') return p > e.n;
  if(e.op === '>=') return p >= e.n;
  if(e.op === '<') return p < e.n;
  if(e.op === '<=') return p <= e.n;
  if(e.op === 'range'){
    const lo = Math.min(e.a, e.b);
    const hi = Math.max(e.a, e.b);
    return p >= lo && p <= hi;
  }
  return false;
}

function parseRuleQuery(input){
  const q = {
    terms: [],
    negTerms: [],
    kv: {},
    not: {},
  };
  const tokens = tokenizeQuery(input);
  for(const t0 of tokens){
    let t = String(t0 || '').trim();
    if(!t) continue;
    let neg = false;
    if(t.startsWith('-') && t.length > 1){
      neg = true;
      t = t.slice(1);
    }
    const lower = t.toLowerCase();
    const idx = t.indexOf(':');
    if(idx > 0){
      const k = t.slice(0, idx);
      const v = t.slice(idx+1);
      if(neg) addQueryKV(q.not, k, v);
      else addQueryKV(q.kv, k, v);
      continue;
    }
    // Shorthands
    const addS = (k, v)=>{ if(neg) addQueryKV(q.not, k, v); else addQueryKV(q.kv, k, v); };
    if(['fav','favorite','star','★'].includes(lower)){ addS('fav', '1'); continue; }
    if(['lb','balance','loadbalance'].includes(lower)){ addS('lb', '1'); continue; }
    if(['remark','note','memo','备注'].includes(lower)){ addS('remark', '1'); continue; }
    if(['running','enabled','on','up','运行'].includes(lower)){ addS('status', 'running'); continue; }
    if(['disabled','paused','off','down','暂停'].includes(lower)){ addS('status', 'disabled'); continue; }
    if(['wss','tcp','intranet'].includes(lower)){ addS('type', lower); continue; }
    if(neg) q.negTerms.push(lower);
    else q.terms.push(lower);
  }
  return q;
}

function matchRuleQuery(e, qobj){
  const hay = buildRuleHaystack(e);

  // Free-text terms (AND)
  for(const term of (qobj.terms || [])){
    if(!term) continue;
    if(!hay.includes(String(term))) return false;
  }
  for(const term of (qobj.negTerms || [])){
    if(!term) continue;
    if(hay.includes(String(term))) return false;
  }

  const getListen = ()=>String(e && e.listen || '').toLowerCase();
  const getRemote = ()=>getAllSearchTargets(e).join('\n').toLowerCase();
  const getRemark = ()=>getRuleRemark(e).toLowerCase();
  const getType = ()=>String(wssMode(e) || '').toLowerCase();
  const getStatus = ()=> (e && e.disabled) ? 'disabled' : 'running';
  const getPeer = ()=>getPeerText(e).toLowerCase();
  const getProtocol = ()=>String(e && e.protocol || '').toLowerCase();
  const getId = ()=>String(e && (e.id !== undefined ? e.id : '') || '').toLowerCase();
  const portNum = parseListenToHostPort(String(e && e.listen || '')).port || '';

  const matchOne = (key, val)=>{
    const v = String(val || '').trim().toLowerCase();
    if(!v && key !== 'remark' && key !== 'fav' && key !== 'lb') return false;
    if(key === 'listen') return getListen().includes(v);
    if(key === 'remote') return getRemote().includes(v);
    if(key === 'remark'){
      if(['1','true','yes','y','on'].includes(v)) return !!getRuleRemark(e);
      if(['0','false','no','n','off'].includes(v)) return !getRuleRemark(e);
      return getRemark().includes(v);
    }
    if(key === 'fav'){
      if(['1','true','yes','y','on'].includes(v)) return isRuleFavorite(e);
      if(['0','false','no','n','off'].includes(v)) return !isRuleFavorite(e);
      // default: treat any value as true
      return isRuleFavorite(e);
    }
    if(key === 'lb'){
      if(['1','true','yes','y','on'].includes(v)) return isLoadBalanceRule(e);
      if(['0','false','no','n','off'].includes(v)) return !isLoadBalanceRule(e);
      return isLoadBalanceRule(e);
    }
    if(key === 'status'){
      if(['running','enabled','on','up','运行'].includes(v)) return !e.disabled;
      if(['disabled','paused','off','down','暂停'].includes(v)) return !!e.disabled;
      return getStatus().includes(v);
    }
    if(key === 'type'){
      // "tcp" matches the normal TCP/UDP rules (not wss/intranet)
      if(v === 'tcp' || v === 'normal') return getType() === 'tcp';
      if(v === 'wss') return getType() === 'wss';
      if(v === 'intranet') return getType() === 'intranet';
      return getType().includes(v);
    }
    if(key === 'port'){
      const p = parseInt(portNum || 0, 10);
      if(!p) return false;
      return matchPort(p, v);
    }
    if(key === 'peer') return getPeer().includes(v);
    if(key === 'protocol') return getProtocol().includes(v);
    if(key === 'id') return getId().includes(v);
    // fallback: search in hay
    return hay.includes(v);
  };

  const applyKV = (kvMap, isNeg)=>{
    for(const k of Object.keys(kvMap || {})){
      const arr = kvMap[k] || [];
      if(!arr.length) continue;
      // OR within a key
      const ok = arr.some(v=>matchOne(k, v));
      if(isNeg){
        if(ok) return false;
      }else{
        if(!ok) return false;
      }
    }
    return true;
  };

  if(!applyKV(qobj.kv, false)) return false;
  if(!applyKV(qobj.not, true)) return false;

  return true;
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
    if(t === 'token_invalid') return '令牌无效';
    if(t === 'nonce_replay') return '握手重放被拒绝';
    if(t === 'server_cert_missing') return '缺少服务端证书';
    if(t === 'peer_is_http_proxy') return '走了HTTP反代/代理';
    if(t === 'sig_invalid') return '签名校验失败';
    if(t === 'magic_mismatch') return '协议不匹配';
    if(t === 'version_mismatch') return '版本不匹配';
    if(t === 'ts_skew') return '时间偏差过大';
    if(t === 'pong_timeout') return '心跳超时';
    if(t === 'control_closed') return '连接断开';
    if(t.startsWith('dial_failed')) return '连接失败';
    if(t.startsWith('dial_tls_failed')) return 'TLS握手失败';
    if(t.startsWith('tls_context_failed')) return 'TLS配置错误';
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
      ${renderHealthTargetMeta(item, false)}
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
  const ident = _syncIdentityFromRule(e);
  if(ident.kind && ident.sync_id){
    const pendingKey = _syncPendingKey(ident.kind, ident.sync_id);
    if(pendingKey && SYNC_PENDING_SUBMITS.has(pendingKey)){
      return '<span class="pill ghost">提交中</span>';
    }
    const task = _findSyncTaskForRule(e);
    if(task){
      const st = String(task.status || '').trim().toLowerCase();
      const tk = String(task.kind || '').trim().toLowerCase();
      if(st === 'queued' || st === 'running' || st === 'retrying'){
        return `<span class="pill ghost">${tk.endsWith('_delete') ? '删除中' : '同步中'}</span>`;
      }
      if(st === 'error'){
        const err = String(task.error || '').trim();
        const title = err ? `同步失败：${err}` : '同步失败';
        return `<span class="pill bad" title="${escapeHtml(title)}">同步失败</span>`;
      }
    }
  }
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
    if(t === 'token_invalid') return '令牌无效';
    if(t === 'nonce_replay') return '握手重放被拒绝';
    if(t === 'server_cert_missing') return '缺少服务端证书';
    if(t === 'peer_is_http_proxy') return '走了HTTP反代/代理';
    if(t === 'sig_invalid') return '签名校验失败';
    if(t === 'magic_mismatch') return '协议不匹配';
    if(t === 'version_mismatch') return '版本不匹配';
    if(t === 'ts_skew') return '时间偏差过大';
    if(t === 'pong_timeout') return '心跳超时';
    if(t === 'control_closed') return '连接断开';
    if(t.startsWith('dial_failed')) return '连接失败';
    if(t.startsWith('dial_tls_failed')) return 'TLS握手失败';
    if(t.startsWith('tls_context_failed')) return 'TLS配置错误';
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
      ${renderHealthTargetMeta(item, false)}
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
        ${renderHealthTargetMeta(item, false)}
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
    if(t === 'token_invalid') return '令牌无效';
    if(t === 'nonce_replay') return '握手重放被拒绝';
    if(t === 'server_cert_missing') return '缺少服务端证书';
    if(t === 'peer_is_http_proxy') return '走了HTTP反代/代理';
    if(t === 'sig_invalid') return '签名校验失败';
    if(t === 'magic_mismatch') return '协议不匹配';
    if(t === 'version_mismatch') return '版本不匹配';
    if(t === 'ts_skew') return '时间偏差过大';
    if(t === 'pong_timeout') return '心跳超时';
    if(t === 'control_closed') return '连接断开';
    if(t.startsWith('dial_failed')) return '连接失败';
    if(t.startsWith('dial_tls_failed')) return 'TLS握手失败';
    if(t.startsWith('tls_context_failed')) return 'TLS配置错误';
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
        ${renderHealthTargetMeta(item, true)}
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
          ${renderHealthTargetMeta(item, true)}
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
      const avail = formatHealthAvailability(it);
      const isHandshake = it && it.kind === 'handshake';
      const state = isUnknown ? '不可检测' : (ok ? (isHandshake ? '已连接' : '在线') : (isHandshake ? '未连接' : '离线'));
      const reason = (!isUnknown && !ok) ? (it.error || it.message || '') : '';
      return `${state}  ${latency}  ${it.target}${avail ? `  ${avail}` : ''}${reason ? `\n  原因：${reason}` : ''}`;
    });
    openCommandModal('连通检测详情', lines.join('\n\n'));
  }catch(e){
    openCommandModal('连通检测详情', '暂无详情');
  }
}

function getTrafficLimitMeta(stats, statsError){
  if(statsError){
    return {enabled:false, blocked:false, label:'', title:''};
  }
  const limitRaw = Number(stats && stats.traffic_limit_bytes != null ? stats.traffic_limit_bytes : 0);
  const limitBytes = Number.isFinite(limitRaw) ? Math.max(0, Math.floor(limitRaw)) : 0;
  if(!(limitBytes > 0)){
    return {enabled:false, blocked:false, label:'', title:''};
  }
  const usedRaw = Number(stats && stats.traffic_used_bytes != null ? stats.traffic_used_bytes : 0);
  const usedBytes = Number.isFinite(usedRaw) ? Math.max(0, Math.floor(usedRaw)) : 0;
  const blocked = !!(stats && (stats.traffic_limit_blocked || stats.traffic_limited));
  const limitTxt = formatBytes(limitBytes);
  const usedTxt = formatBytes(usedBytes);
  const label = blocked ? `流量封禁 ${limitTxt}` : `流量上限 ${limitTxt}`;
  const title = `累计 ${usedTxt} / 上限 ${limitTxt}`;
  return {enabled:true, blocked, label, title};
}

function renderRuleCard(e, idx, rowNo, stats, statsError){
  const rx = statsError ? null : (stats.rx_bytes || 0);
  const tx = statsError ? null : (stats.tx_bytes || 0);
  const total = (rx == null || tx == null) ? null : rx + tx;
  const connActive = statsError ? 0 : (stats.connections_active ?? 0);
  const est = statsError ? 0 : (stats.connections_established ?? stats.connections ?? 0);
  const totalStr = total == null ? '—' : formatBytes(total);
  const trafficTitle = (statsError || total == null) ? '' : `title="↓ ${escapeHtml(formatBytes(rx))}  ↑ ${escapeHtml(formatBytes(tx))}"`;
  const trafficLimitMeta = getTrafficLimitMeta(stats, statsError);
  const trafficLimitPill = trafficLimitMeta.enabled
    ? `<span class="pill ${trafficLimitMeta.blocked ? 'bad' : 'warn'}" title="${escapeHtml(trafficLimitMeta.title)}">${escapeHtml(trafficLimitMeta.label)}</span>`
    : '';
  const healthHtml = renderHealthMobile(stats.health, statsError, idx);
  const adaptiveHtml = renderAdaptiveInfo(e, stats, statsError);
  const activeTitle = statsError ? '' : `title="当前已建立连接：${est}"`;
  const lockInfo = getRuleLockInfo(e);
  const modeAllowed = canOperateEndpoint(e);
  const modeReason = modeAllowed ? '' : modeDenyReason(endpointMode(e));
  const key = getRuleKey(e);
  const sel = key && RULE_SELECTED_KEYS.has(key);
  const selDisabled = (!!(lockInfo && lockInfo.locked)) || (!modeAllowed);
  const selTitle = !modeAllowed ? modeReason : (selDisabled ? (lockInfo.reason || '该规则已锁定不可批量操作') : '选择该规则（用于批量操作）');
  const selHtml = `<input type="checkbox" class="rule-select" ${sel ? 'checked' : ''} ${selDisabled ? 'disabled' : ''} title="${escapeHtml(selTitle)}" onchange="setRuleSelectedByIdx(${idx}, this.checked, event)">`;

  const fav = isRuleFavorite(e);
  const favBtn = `<button class="btn xs icon ghost fav-btn ${fav ? 'active' : ''}" title="${fav ? '取消收藏' : '收藏'}" onclick="toggleFavorite(${idx}, event)">${fav ? '★' : '☆'}</button>`;

  const remark = getRuleRemark(e);
  const remarkHtml = remark ? `<div class="rule-remark" title="${escapeHtml(remark)}">${escapeHtml(remark)}</div>` : '';
  const sourceHtml = renderRuleSourceInfo(e);
  const lockBtn = renderRuleLockBtn(e, idx, lockInfo);

  const actionsHtml = (!modeAllowed) ? `
    <div class="rule-actions">
      <button class="btn xs icon ghost" title="复制" onclick="copyRule(${idx})">⧉</button>
      <span class="pill ghost" title="${escapeHtml(modeReason)}">🔒 无权限</span>
    </div>
  ` : ((lockInfo && lockInfo.locked) ? `
    <div class="rule-actions">
      <button class="btn xs icon ghost" title="复制" onclick="copyRule(${idx})">⧉</button>
      <button class="btn xs icon ghost" title="备注" onclick="editRemark(${idx}, event)">📝</button>
      ${lockBtn || `<span class="pill ghost" title="${escapeHtml(lockInfo.reason || '该规则已锁定（只读）')}">🔒 已锁定</span>`}
    </div>
  ` : `
    <div class="rule-actions">
      <button class="btn xs icon ghost" title="复制" onclick="copyRule(${idx})">⧉</button>
      <button class="btn xs icon ghost" title="备注" onclick="editRemark(${idx}, event)">📝</button>
      <button class="btn xs icon ghost" title="编辑" onclick="editRule(${idx})">✎</button>
      <button class="btn xs icon" title="${e.disabled?'启用':'暂停'}" onclick="toggleRule(${idx})">${e.disabled?'▶':'⏸'}</button>
      <button class="btn xs icon ghost" title="删除" onclick="deleteRule(${idx})">🗑</button>
      ${lockBtn || ''}
    </div>
  `);
  return `
  <div class="rule-card">
    <div class="rule-head">
      <div class="rule-left">
        <div class="rule-topline">
          ${selHtml}
          <span class="rule-idx">#${rowNo}</span>
          ${favBtn}
          ${statusPill(e)}
        </div>
        <div class="rule-listen mono">${escapeHtml(e.listen)}</div>
        <div class="rule-sub muted sm">${endpointType(e)}</div>
        ${sourceHtml}
        ${remarkHtml}
      </div>
      <div class="rule-right">
        <span class="pill ghost" ${activeTitle}>活跃 ${escapeHtml(connActive)}</span>
        <span class="pill ghost" ${trafficTitle}>${escapeHtml(totalStr)}</span>
        ${trafficLimitPill}
      </div>
    </div>
    <div class="rule-health-block">
      ${healthHtml}
      ${adaptiveHtml}
    </div>
    ${actionsHtml}
  </div>`;
}

function renderIntranetHealthCard(statsLookup){
  const card = q('intranetHealthCard');
  const sourceEl = q('intranetHealthSource');
  const summaryEl = q('intranetHealthSummary');
  const listEl = q('intranetHealthList');
  if(!card || !summaryEl || !listEl) return;

  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  const lookup = statsLookup && typeof statsLookup === 'object' ? statsLookup : {byIdx:{}, byListen:{}, error:''};
  const byIdx = (lookup && lookup.byIdx && typeof lookup.byIdx === 'object') ? lookup.byIdx : {};
  const byListen = (lookup && lookup.byListen && typeof lookup.byListen === 'object') ? lookup.byListen : {};
  const statsError = String((lookup && lookup.error) || '').trim();

  const rows = [];
  for(let idx=0; idx<eps.length; idx++){
    const e = eps[idx];
    if(wssMode(e) !== 'intranet') continue;
    const ex = (e && e.extra_config) ? e.extra_config : {};
    const role = String(ex.intranet_role || '').trim();
    const listen = String(e && e.listen || '').trim();
    const peer = String(
      ex.intranet_peer_node_name ||
      ex.intranet_peer_host ||
      ex.intranet_peer_node_id ||
      ''
    ).trim();
    const roleLabel = role === 'server' ? '公网入口' : (role === 'client' ? '内网出口' : '内网穿透');
    const stats = byIdx[idx] || (listen ? byListen[listen] : null) || {};
    const health = Array.isArray(stats && stats.health) ? stats.health : [];
    let hs = null;
    for(const item of health){
      if(item && item.kind === 'handshake'){ hs = item; break; }
    }

    let ok = null;
    if(hs && Object.prototype.hasOwnProperty.call(hs, 'ok')){
      ok = hs.ok;
    }
    const latency = hs && hs.latency_ms != null ? Number(hs.latency_ms) : null;
    const lossPct = hs && hs.loss_pct != null ? Number(hs.loss_pct) : null;
    const jitterMs = hs && hs.jitter_ms != null ? Number(hs.jitter_ms) : null;
    const reconnects = hs && hs.reconnects != null ? parseInt(hs.reconnects, 10) : 0;
    const tokenCount = hs && hs.token_count != null ? parseInt(hs.token_count, 10) : 0;
    const pingSent = hs && hs.ping_sent != null ? parseInt(hs.ping_sent, 10) : 0;
    const pongRecv = hs && hs.pong_recv != null ? parseInt(hs.pong_recv, 10) : 0;
    const dialMode = hs ? String(hs.dial_mode || '').trim() : '';
    const err = hs ? String(hs.error || '').trim() : '';
    const msg = hs ? String(hs.message || '').trim() : '';

    const title = hs && hs.target ? String(hs.target || '').trim() : `${roleLabel}${peer ? ` · ${peer}` : ''}`;
    const meta = [];
    if(listen && listen !== '0.0.0.0:0') meta.push(`入口 ${listen}`);
    if(peer) meta.push(`对端 ${peer}`);
    if(dialMode) meta.push(`模式 ${dialMode}`);
    if(tokenCount > 0) meta.push(`Token ${tokenCount}`);
    if(ok === false && err) meta.push(`错误 ${err}`);
    else if(msg) meta.push(msg);
    if(!meta.length) meta.push(roleLabel);

    rows.push({
      ok,
      latency,
      lossPct,
      jitterMs,
      reconnects: Number.isFinite(reconnects) ? reconnects : 0,
      pingSent: Number.isFinite(pingSent) ? pingSent : 0,
      pongRecv: Number.isFinite(pongRecv) ? pongRecv : 0,
      title,
      meta: meta.join(' · '),
    });
  }

  if(!rows.length){
    card.style.display = 'none';
    if(sourceEl) sourceEl.textContent = '自动刷新时实时更新';
    summaryEl.innerHTML = '';
    listEl.innerHTML = '';
    return;
  }

  card.style.display = '';

  const sourceRaw = String((CURRENT_STATS && CURRENT_STATS.source) || '').trim();
  if(sourceEl){
    sourceEl.textContent = sourceRaw ? `来源：${sourceRaw}` : '自动刷新时实时更新';
    if(statsError){
      sourceEl.textContent += ' · 统计异常';
    }
  }

  const okCount = rows.filter(x=>x.ok === true).length;
  const failCount = rows.filter(x=>x.ok === false).length;
  const unknownCount = Math.max(0, rows.length - okCount - failCount);
  const latArr = rows.map(x=>x.latency).filter(v=>Number.isFinite(v));
  const lossArr = rows.map(x=>x.lossPct).filter(v=>Number.isFinite(v));
  const avgLatency = latArr.length ? Math.round(latArr.reduce((a,b)=>a + b, 0) / latArr.length) : null;
  const avgLoss = lossArr.length ? (lossArr.reduce((a,b)=>a + b, 0) / lossArr.length) : null;
  const reconnectTotal = rows.reduce((a,b)=>a + (Number.isFinite(b.reconnects) ? b.reconnects : 0), 0);

  const summaryParts = [];
  summaryParts.push(`<span class="pill xs ghost">链路 ${rows.length}</span>`);
  summaryParts.push(`<span class="pill xs ok">在线 ${okCount}</span>`);
  if(failCount > 0) summaryParts.push(`<span class="pill xs bad">异常 ${failCount}</span>`);
  if(unknownCount > 0) summaryParts.push(`<span class="pill xs warn">未知 ${unknownCount}</span>`);
  if(avgLatency != null) summaryParts.push(`<span class="pill xs ghost">均延迟 ${avgLatency} ms</span>`);
  if(avgLoss != null){
    const lossCls = avgLoss >= 5 ? 'bad' : (avgLoss >= 1 ? 'warn' : 'ok');
    summaryParts.push(`<span class="pill xs ${lossCls}">均丢包 ${avgLoss >= 10 ? avgLoss.toFixed(0) : avgLoss.toFixed(1)}%</span>`);
  }
  summaryParts.push(`<span class="pill xs ghost">重连 ${reconnectTotal}</span>`);
  if(statsError){
    summaryParts.push(`<span class="pill xs warn" title="${escapeHtml(statsError)}">统计异常</span>`);
  }
  summaryEl.innerHTML = summaryParts.join('');

  listEl.innerHTML = rows.map((row)=>{
    const statusCls = row.ok === true ? 'ok' : (row.ok === false ? 'bad' : 'warn');
    const statusText = row.ok === true ? '在线' : (row.ok === false ? '未连接' : '不可检测');
    const pills = [];
    if(Number.isFinite(row.latency)){
      pills.push(`<span class="pill xs ghost">${Math.round(row.latency)} ms</span>`);
    }
    if(Number.isFinite(row.lossPct)){
      const lossCls = row.lossPct >= 5 ? 'bad' : (row.lossPct >= 1 ? 'warn' : 'ok');
      pills.push(`<span class="pill xs ${lossCls}">丢包 ${row.lossPct >= 10 ? row.lossPct.toFixed(0) : row.lossPct.toFixed(1)}%</span>`);
    }
    if(Number.isFinite(row.jitterMs)){
      pills.push(`<span class="pill xs ghost">抖动 ${Math.round(row.jitterMs)} ms</span>`);
    }
    pills.push(`<span class="pill xs ghost">重连 ${row.reconnects}</span>`);
    if(row.pingSent > 0 || row.pongRecv > 0){
      pills.push(`<span class="pill xs ghost">心跳 ${row.pongRecv}/${row.pingSent}</span>`);
    }

    return `<div class="hist-chart intra-health-row">
      <div class="hist-chart-head">
        <div class="name intra-health-name" title="${escapeHtml(row.title)}">${escapeHtml(row.title)}</div>
        <span class="pill xs ${statusCls}">${statusText}</span>
      </div>
      <div class="intra-health-main">
        <div class="intra-health-meta">${escapeHtml(row.meta)}</div>
      </div>
      <div class="intra-health-pills">${pills.join('')}</div>
    </div>`;
  }).join('');
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

  // Search & filter
  const quick = String(RULE_QUICK_FILTER || '').trim();
  const queryText = String(RULE_FILTER_TEXT || '').trim();
  const qobj = parseRuleQuery(queryText);
  const hasAnyFilter = !!quick || !!queryText;

  const items = [];
  eps.forEach((e, idx)=>{
    // Quick filter (UI)
    if(quick){
      if(quick === 'fav' && !isRuleFavorite(e)) return;
      if(quick === 'running' && !!e.disabled) return;
      if(quick === 'disabled' && !e.disabled) return;
      if(quick === 'tcp' && wssMode(e) !== 'tcp') return;
      if(quick === 'wss' && wssMode(e) !== 'wss') return;
      if(quick === 'intranet' && wssMode(e) !== 'intranet') return;
      if(quick === 'lb' && !isLoadBalanceRule(e)) return;
      if(quick === 'remark' && !getRuleRemark(e)) return;
    }
    // Advanced query
    if(queryText){
      if(!matchRuleQuery(e, qobj)) return;
    }
    items.push({e, idx, key: getRuleKey(e)});
  });

  // Update visible keys for bulk selection helpers
  LAST_VISIBLE_RULE_KEYS = items.map(it=>it.key).filter(Boolean);

  if(!items.length){
    LAST_VISIBLE_RULE_KEYS = [];
    updateBulkBar();
    updateSelectAllCheckbox();

    // History curves: keep rule select options in sync
    try{ histSyncRuleSelect(); }catch(_e){}

    q('rulesLoading').style.display = '';
    q('rulesLoading').textContent = hasAnyFilter ? '未找到匹配规则' : '暂无规则';
    table.style.display = 'none';
    if(mobileWrap) mobileWrap.style.display = 'none';
    if(statsLoading){
      statsLoading.style.display = 'none';
    }
    renderSyncTasksBar();
    renderIntranetHealthCard(statsLookup);
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
      const adaptiveHtml = renderAdaptiveInfo(e, stats, statsError);
      const rx = statsError ? null : (stats.rx_bytes || 0);
      const tx = statsError ? null : (stats.tx_bytes || 0);
      const total = (rx == null || tx == null) ? null : rx + tx;
      const trafficLimitMeta = getTrafficLimitMeta(stats, statsError);
      const trafficLimitHtml = trafficLimitMeta.enabled
        ? `<div class="muted sm"><span class="pill xs ${trafficLimitMeta.blocked ? 'bad' : 'warn'}" title="${escapeHtml(trafficLimitMeta.title)}">${escapeHtml(trafficLimitMeta.label)}</span></div>`
        : '';
      const connActive = statsError ? 0 : (stats.connections_active ?? 0);
      const est = statsError ? 0 : (stats.connections_established ?? stats.connections ?? 0);
      const lockInfo = getRuleLockInfo(e);
      const modeAllowed = canOperateEndpoint(e);
      const modeReason = modeAllowed ? '' : modeDenyReason(endpointMode(e));
      const key = getRuleKey(e);
      const sel = key && RULE_SELECTED_KEYS.has(key);
      const selDisabled = (!!(lockInfo && lockInfo.locked)) || (!modeAllowed);
      const selTitle = (!modeAllowed)
        ? modeReason
        : (selDisabled ? (lockInfo.reason || '该规则已锁定不可批量操作') : '选择该规则（用于批量操作）');
      const fav = isRuleFavorite(e);
      const remark = getRuleRemark(e);
      const sourceHtml = renderRuleSourceInfo(e);
      const lockBtn = renderRuleLockBtn(e, idx, lockInfo);
      const noPermPill = !modeAllowed ? `<span class="pill ghost" title="${escapeHtml(modeReason)}">🔒 无权限</span>` : '';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="sel"><input type="checkbox" class="rule-select" ${sel ? 'checked' : ''} ${selDisabled ? 'disabled' : ''} title="${escapeHtml(selTitle)}" onchange="setRuleSelectedByIdx(${idx}, this.checked, event)"></td>
        <td>${rowNo}</td>
        <td>${statusPill(e)}</td>
        <td class="listen">
          <div class="listen-line">
            <button class="btn xs icon ghost fav-btn ${fav ? 'active' : ''}" title="${fav ? '取消收藏' : '收藏'}" onclick="toggleFavorite(${idx}, event)">${fav ? '★' : '☆'}</button>
            <div class="mono listen-text">${escapeHtml(e.listen)}</div>
          </div>
          <div class="muted sm">${endpointType(e)}</div>
          ${sourceHtml}
          ${remark ? `<div class="rule-remark" title="${escapeHtml(remark)}">${escapeHtml(remark)}</div>` : ''}
        </td>
        <td class="health">${healthHtml}${adaptiveHtml}</td>
        <td class="stat" title="当前已建立连接：${escapeHtml(est)}">${statsError ? '—' : escapeHtml(connActive)}</td>
        <td class="stat" ${statsError || total == null ? '' : `title="↓ ${escapeHtml(formatBytes(rx))}  ↑ ${escapeHtml(formatBytes(tx))}"`}>
          <div>${total == null ? '—' : formatBytes(total)}</div>
          ${trafficLimitHtml}
        </td>
        <td class="actions">
          ${!modeAllowed ? `
            <div class="action-inline">
              <button class="btn xs icon ghost" title="复制" onclick="copyRule(${idx})">⧉</button>
              ${noPermPill}
            </div>
          ` : (lockInfo && lockInfo.locked ? `
            <div class="action-inline">
              <button class="btn xs icon ghost" title="复制" onclick="copyRule(${idx})">⧉</button>
              <button class="btn xs icon ghost" title="备注" onclick="editRemark(${idx}, event)">📝</button>
              ${lockBtn || `<span class="pill ghost" title="${escapeHtml(lockInfo.reason || '该规则已锁定（只读）')}">🔒 已锁定</span>`}
            </div>
          ` : `
            <div class="action-inline">
              <button class="btn xs icon ghost" title="复制" onclick="copyRule(${idx})">⧉</button>
              <button class="btn xs icon ghost" title="备注" onclick="editRemark(${idx}, event)">📝</button>
              <button class="btn xs icon ghost" title="编辑" onclick="editRule(${idx})">✎</button>
              <button class="btn xs icon" title="${e.disabled?'启用':'暂停'}" onclick="toggleRule(${idx})">${e.disabled?'▶':'⏸'}</button>
              <button class="btn xs icon ghost" title="删除" onclick="deleteRule(${idx})">🗑</button>
              ${lockBtn || ''}
            </div>
          `)}
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

  // Bulk selection UI
  updateBulkBar();
  updateSelectAllCheckbox();

  // History curves: keep rule select options in sync
  try{ histSyncRuleSelect(); }catch(_e){}
  renderSyncTasksBar();
  renderIntranetHealthCard(statsLookup);
}

function openModal(){ q('modal').style.display = 'flex'; }
function closeModal(){ q('modal').style.display = 'none'; q('modalMsg').textContent=''; }

// Rule editor: separate screens to reduce information density
// - params: fill in fields
// - intro : mode selection + explanations
function setRuleScreen(screen){
  const s = (String(screen||'').trim() === 'intro') ? 'intro' : 'params';
  const intro = document.getElementById('ruleScreenIntro');
  const params = document.getElementById('ruleScreenParams');
  if(intro) intro.style.display = (s === 'intro') ? 'block' : 'none';
  if(params) params.style.display = (s === 'params') ? 'block' : 'none';

  const tabIntro = document.getElementById('ruleTabIntro');
  const tabParams = document.getElementById('ruleTabParams');
  if(tabIntro){
    tabIntro.classList.toggle('active', s === 'intro');
    tabIntro.setAttribute('aria-selected', (s === 'intro') ? 'true' : 'false');
  }
  if(tabParams){
    tabParams.classList.toggle('active', s === 'params');
    tabParams.setAttribute('aria-selected', (s === 'params') ? 'true' : 'false');
  }

  // Keep hints / pill / guide in sync
  try{ syncTunnelModeUI(); }catch(_e){}
}
window.setRuleScreen = setRuleScreen;

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

function normalizeNodeConfirmLabel(label, nodeId){
  const clean = String(label || '').replace(/\s+/g, ' ').trim();
  if(clean) return clean;
  const idTxt = String(nodeId || '').trim();
  return idTxt ? ('节点-' + idTxt) : '目标节点';
}

function getCurrentNodeConfirmLabel(){
  return normalizeNodeConfirmLabel(
    (window.__NODE_NAME__ || '').trim() || (window.__NODE_IP__ || '').trim(),
    window.__NODE_ID__
  );
}

function confirmAndShowUninstallCommand(){
  const label = getCurrentNodeConfirmLabel();
  const ok = confirm(
    `确认查看“卸载 Agent”命令？\n\n` +
    `执行后节点「${label}」将停止受控，面板无法继续下发配置，直到重新接入。`
  );
  if(!ok) return;
  openCommandModal('一键卸载 Agent', window.__UNINSTALL_CMD__);
}

function submitNodeDeleteForm(nodeId){
  const id = String(nodeId || '').trim();
  if(!id) return;
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `/nodes/${encodeURIComponent(id)}/delete`;
  form.style.display = 'none';
  document.body.appendChild(form);
  form.submit();
}

function confirmAndRemoveNode(nodeId, nodeLabel){
  const id = String(nodeId || '').trim();
  if(!id){
    toast('缺少节点ID', true);
    return;
  }
  const label = normalizeNodeConfirmLabel(nodeLabel, id);
  const ok = confirm(
    `危险操作：将从面板移除节点「${label}」。\n\n` +
    `仅移除面板记录，不会自动卸载节点 Agent。\n` +
    `该操作不可恢复，是否继续？`
  );
  if(!ok) return;

  const typed = prompt(`请输入节点名称「${label}」以确认移除：`);
  if((typed || '').trim() !== label){
    toast('已取消：节点名称不匹配', true);
    return;
  }
  submitNodeDeleteForm(id);
}

function removeCurrentNode(){
  const nodeId = window.__NODE_ID__;
  const label = getCurrentNodeConfirmLabel();
  confirmAndRemoveNode(nodeId, label);
}

window.confirmAndShowUninstallCommand = confirmAndShowUninstallCommand;
window.confirmAndRemoveNode = confirmAndRemoveNode;
window.removeCurrentNode = removeCurrentNode;

function setField(id, v){ q(id).value = v==null?'':String(v); }


// -------------------- Listen field helpers (port-only UI) --------------------

function _trim(v){ return String(v||'').trim(); }

// Parse a listen string into {host, port}. Supports:
// - 0.0.0.0:443
// - [::]:443
// - ::1:443 (best-effort)
// - 443
function parseListenToHostPort(listen){
  const s = _trim(listen);
  let host = '0.0.0.0';
  let port = '';
  if(!s) return {host, port};

  // [::]:443
  if(s.startsWith('[')){
    const r = s.indexOf(']');
    if(r > 0){
      host = s.slice(1, r) || host;
      const rest = s.slice(r + 1);
      const m = rest.match(/^:(\d+)$/);
      if(m) port = m[1];
      return {host, port};
    }
  }

  // pure port
  if(/^\d+$/.test(s)){
    return {host, port: s};
  }

  // host:port (use last ':' as separator)
  const m = s.match(/^(.*):(\d+)$/);
  if(m){
    host = m[1] || host;
    port = m[2] || '';
  }else{
    host = s || host;
  }

  host = host.replace(/^\[(.*)\]$/, '$1') || '0.0.0.0';
  return {host, port};
}

// Normalize host input (strip scheme / strip trailing :port for IPv4/domain)
// NOTE: IPv6 is kept as-is (and will be wrapped with [] when formatting).
function normalizeListenHostInput(raw){
  let h = _trim(raw);
  if(!h) return '';
  // URL -> hostname
  try{
    if(h.includes('://')){
      const u = new URL(h);
      if(u && u.hostname) h = u.hostname;
    }
  }catch(_e){}
  // [::]:443 -> ::
  if(h.startsWith('[') && h.includes(']')){
    return h.slice(1, h.indexOf(']')) || '';
  }
  // host:port -> host (only when host part doesn't look like IPv6)
  const m = h.match(/^(.*):(\d+)$/);
  if(m){
    const left = m[1] || '';
    if(left && !left.includes(':')){
      h = left;
    }
  }
  return h;
}

function _formatListenHost(host){
  const clean = normalizeListenHostInput(host) || '0.0.0.0';
  // IPv6 needs brackets
  if(clean.includes(':') && !clean.startsWith('[') && !clean.endsWith(']')){
    return `[${clean}]`;
  }
  return clean;
}

function getListenHost(){
  const el = q('f_listen_host');
  const raw = el ? el.value : '';
  const h = normalizeListenHostInput(raw) || '0.0.0.0';
  // keep the input tidy
  if(el && _trim(el.value) !== h) el.value = h;
  return h;
}

function getListenPort(){
  const el = q('f_listen_port');
  const raw = el ? _trim(el.value) : '';
  if(!raw) return '';
  return raw.replace(/[^0-9]/g, '');
}

function getListenString(){
  const port = getListenPort();
  if(!port) return '';
  const host = _formatListenHost(getListenHost());
  return `${host}:${port}`;
}

function syncListenComputed(){
  try{
    const full = getListenString();
    const fullEl = q('f_listen');
    if(fullEl) fullEl.value = full;

    const prefix = document.getElementById('listenHostPrefix');
    if(prefix){
      prefix.textContent = `${getListenHost()}:`;
    }
  }catch(_e){}
}


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
  const acl = (ex.intranet_acl && typeof ex.intranet_acl === 'object' && !Array.isArray(ex.intranet_acl)) ? ex.intranet_acl : {};
  const toMulti = (v)=> Array.isArray(v) ? v.map(x=>String(x || '').trim()).filter(Boolean).join('\n') : '';
  if(q('f_intranet_receiver_node')) setField('f_intranet_receiver_node', peerId);
  if(q('f_intranet_server_port')) setField('f_intranet_server_port', port);
  if(q('f_intranet_server_host')) setField('f_intranet_server_host', host);
  if(q('f_intranet_acl_allow_sources')) setField('f_intranet_acl_allow_sources', toMulti(acl.allow_sources));
  if(q('f_intranet_acl_deny_sources')) setField('f_intranet_acl_deny_sources', toMulti(acl.deny_sources));
  if(q('f_intranet_acl_allow_hours')) setField('f_intranet_acl_allow_hours', toMulti(acl.allow_hours));
  if(q('f_intranet_acl_allow_tokens')) setField('f_intranet_acl_allow_tokens', toMulti(acl.allow_tokens));
  populateIntranetReceiverSelect();
}

function readIntranetAclFields(){
  const readList = (id, maxItems=128)=>{
    const el = q(id);
    const raw = el ? String(el.value || '').trim() : '';
    if(!raw) return [];
    const out = [];
    const seen = new Set();
    for(const row0 of raw.replace(/,/g, '\n').split('\n')){
      const row = String(row0 || '').trim();
      if(!row || seen.has(row)) continue;
      seen.add(row);
      out.push(row);
      if(out.length >= maxItems) break;
    }
    return out;
  };
  const acl = {};
  const allowSources = readList('f_intranet_acl_allow_sources', 128);
  const denySources = readList('f_intranet_acl_deny_sources', 128);
  const allowHours = readList('f_intranet_acl_allow_hours', 16);
  const allowTokens = readList('f_intranet_acl_allow_tokens', 64);

  for(const h of allowHours){
    if(!/^\d{2}:\d{2}\-\d{2}:\d{2}$/.test(h)) return {ok:false, error:`ACL 时间窗格式无效：${h}`};
    const [left, right] = h.split('-');
    const [lh, lm] = left.split(':').map(x=>parseInt(x, 10));
    const [rh, rm] = right.split(':').map(x=>parseInt(x, 10));
    if(!(lh >= 0 && lh <= 23 && lm >= 0 && lm <= 59 && rh >= 0 && rh <= 23 && rm >= 0 && rm <= 59)){
      return {ok:false, error:`ACL 时间窗超出范围：${h}`};
    }
  }

  if(allowSources.length) acl.allow_sources = allowSources;
  if(denySources.length) acl.deny_sources = denySources;
  if(allowHours.length) acl.allow_hours = allowHours;
  if(allowTokens.length) acl.allow_tokens = allowTokens;
  return {ok:true, acl};
}


// -------------------- Common advanced params (normal rules) --------------------

function setTriBoolSelect(id, v){
  const el = q(id);
  if(!el) return;
  if(v === true) el.value = '1';
  else if(v === false) el.value = '0';
  else el.value = '';
}

function readTriBoolSelect(id){
  const el = q(id);
  const v = el ? String(el.value || '').trim() : '';
  if(v === '1') return {set:true, value:true};
  if(v === '0') return {set:true, value:false};
  return {set:false, value:false};
}

function readNonnegIntInput(id, label){
  const el = q(id);
  const raw = el ? String(el.value || '').trim() : '';
  if(!raw) return {set:false, value:0};
  if(!/^\d+$/.test(raw)) return {error:`${label} 必须是非负整数`};
  const n = parseInt(raw, 10);
  if(!(n >= 0)) return {error:`${label} 必须 ≥ 0`};
  return {set:true, value:n};
}

function collectQosFromEndpoint(e){
  const ep = e || {};
  const net = (ep.network && typeof ep.network === 'object' && !Array.isArray(ep.network)) ? ep.network : {};
  const ex = (ep.extra_config && typeof ep.extra_config === 'object' && !Array.isArray(ep.extra_config)) ? ep.extra_config : {};
  const exQos = (ex.qos && typeof ex.qos === 'object' && !Array.isArray(ex.qos)) ? ex.qos : {};
  const netQos = (net.qos && typeof net.qos === 'object' && !Array.isArray(net.qos)) ? net.qos : {};

  const pick = (keys)=>{
    for(const src of [exQos, netQos, ex, net, ep]){
      if(!(src && typeof src === 'object' && !Array.isArray(src))) continue;
      for(const k of keys){
        if(src[k] != null && String(src[k]).trim() !== '') return src[k];
      }
    }
    return null;
  };

  const out = {};
  const bwKbpsRaw = pick(['bandwidth_kbps', 'bandwidth_kbit', 'bandwidth_limit_kbps', 'qos_bandwidth_kbps']);
  const bwMbpsRaw = pick(['bandwidth_mbps', 'bandwidth_mb', 'bandwidth_limit_mbps', 'qos_bandwidth_mbps']);
  let bwKbps = parseInt(String(bwKbpsRaw != null ? bwKbpsRaw : ''), 10);
  if(!(Number.isFinite(bwKbps) && bwKbps > 0)){
    bwKbps = 0;
  }
  if(!(bwKbps > 0)){
    const bwMbps = parseInt(String(bwMbpsRaw != null ? bwMbpsRaw : ''), 10);
    if(Number.isFinite(bwMbps) && bwMbps > 0){
      bwKbps = bwMbps * 1024;
    }
  }
  if(bwKbps > 0){
    out.bandwidth_kbps = bwKbps;
  }

  const maxConnsRaw = pick(['max_conns', 'max_connections', 'max_conn', 'qos_max_conns']);
  const maxConns = parseInt(String(maxConnsRaw != null ? maxConnsRaw : ''), 10);
  if(Number.isFinite(maxConns) && maxConns > 0){
    out.max_conns = maxConns;
  }

  const connRateRaw = pick(['conn_rate', 'new_conn_per_sec', 'conn_per_sec', 'new_connections_per_sec', 'qos_conn_rate']);
  const connRate = parseInt(String(connRateRaw != null ? connRateRaw : ''), 10);
  if(Number.isFinite(connRate) && connRate > 0){
    out.conn_rate = connRate;
  }

  const trafficBytesRaw = pick([
    'traffic_total_bytes',
    'traffic_bytes',
    'traffic_limit_bytes',
    'qos_traffic_total_bytes',
  ]);
  const trafficGbRaw = pick([
    'traffic_total_gb',
    'traffic_gb',
    'traffic_limit_gb',
    'qos_traffic_total_gb',
  ]);
  let trafficBytes = parseInt(String(trafficBytesRaw != null ? trafficBytesRaw : ''), 10);
  if(!(Number.isFinite(trafficBytes) && trafficBytes > 0)){
    trafficBytes = 0;
  }
  if(!(trafficBytes > 0)){
    const trafficGb = parseInt(String(trafficGbRaw != null ? trafficGbRaw : ''), 10);
    if(Number.isFinite(trafficGb) && trafficGb > 0){
      trafficBytes = trafficGb * 1024 * 1024 * 1024;
    }
  }
  if(trafficBytes > 0){
    out.traffic_total_bytes = trafficBytes;
  }
  return out;
}

function fillQosFields(e){
  const qos = collectQosFromEndpoint(e);
  const bwKbps = parseInt(String(qos.bandwidth_kbps || '0'), 10);
  const bwMbps = Number.isFinite(bwKbps) && bwKbps > 0 ? Math.max(1, Math.round(bwKbps / 1024)) : '';
  if(q('f_qos_bandwidth_mbps')) setField('f_qos_bandwidth_mbps', bwMbps);

  const maxConns = parseInt(String(qos.max_conns || '0'), 10);
  if(q('f_qos_max_conns')) setField('f_qos_max_conns', Number.isFinite(maxConns) && maxConns > 0 ? maxConns : '');

  const connRate = parseInt(String(qos.conn_rate || '0'), 10);
  if(q('f_qos_conn_rate')) setField('f_qos_conn_rate', Number.isFinite(connRate) && connRate > 0 ? connRate : '');

  const trafficBytes = parseInt(String(qos.traffic_total_bytes || '0'), 10);
  const trafficGb = Number.isFinite(trafficBytes) && trafficBytes > 0
    ? Math.max(1, Math.round(trafficBytes / (1024 * 1024 * 1024)))
    : '';
  if(q('f_qos_traffic_total_gb')) setField('f_qos_traffic_total_gb', trafficGb);
}

function readQosFields(){
  const qos = {};
  const q1 = readNonnegIntInput('f_qos_bandwidth_mbps', '带宽上限');
  if(q1.error) return {ok:false, error:q1.error};
  if(q1.set && q1.value > 0){
    qos.bandwidth_kbps = q1.value * 1024;
  }

  const q2 = readNonnegIntInput('f_qos_max_conns', '最大并发连接');
  if(q2.error) return {ok:false, error:q2.error};
  if(q2.set && q2.value > 0){
    qos.max_conns = q2.value;
  }

  const q3 = readNonnegIntInput('f_qos_conn_rate', '每秒新建连接上限');
  if(q3.error) return {ok:false, error:q3.error};
  if(q3.set && q3.value > 0){
    qos.conn_rate = q3.value;
  }

  const q4 = readNonnegIntInput('f_qos_traffic_total_gb', '总流量上限');
  if(q4.error) return {ok:false, error:q4.error};
  if(q4.set && q4.value > 0){
    qos.traffic_total_bytes = q4.value * 1024 * 1024 * 1024;
  }
  return {ok:true, qos};
}

function fillCommonAdvancedFields(e){
  const ep = e || {};
  const net = (ep.network && typeof ep.network === 'object' && !Array.isArray(ep.network)) ? ep.network : {};
  const ex = (ep.extra_config && typeof ep.extra_config === 'object' && !Array.isArray(ep.extra_config)) ? ep.extra_config : {};

  if(q('f_through')) setField('f_through', ep.through || '');
  if(q('f_interface')) setField('f_interface', ep.interface || '');
  if(q('f_listen_interface')) setField('f_listen_interface', ep.listen_interface || '');

  setTriBoolSelect('f_accept_proxy', ep.accept_proxy);
  if(q('f_accept_proxy_timeout')) setField('f_accept_proxy_timeout', ep.accept_proxy_timeout != null ? ep.accept_proxy_timeout : '');
  setTriBoolSelect('f_send_proxy', ep.send_proxy);
  if(q('f_send_proxy_version')) setField('f_send_proxy_version', ep.send_proxy_version != null ? ep.send_proxy_version : '');
  setTriBoolSelect('f_send_mptcp', ep.send_mptcp);
  setTriBoolSelect('f_accept_mptcp', ep.accept_mptcp);

  if(q('f_listen_transport')) setField('f_listen_transport', ep.listen_transport || '');
  if(q('f_remote_transport')) setField('f_remote_transport', ep.remote_transport || '');

  if(q('f_net_tcp_timeout')) setField('f_net_tcp_timeout', net.tcp_timeout != null ? net.tcp_timeout : '');
  if(q('f_net_udp_timeout')) setField('f_net_udp_timeout', net.udp_timeout != null ? net.udp_timeout : '');
  if(q('f_net_tcp_keepalive')) setField('f_net_tcp_keepalive', net.tcp_keepalive != null ? net.tcp_keepalive : '');
  if(q('f_net_tcp_keepalive_probe')) setField('f_net_tcp_keepalive_probe', net.tcp_keepalive_probe != null ? net.tcp_keepalive_probe : '');

  if(q('f_net_ipv6_only')){
    if(net.ipv6_only === true) q('f_net_ipv6_only').value = '1';
    else if(net.ipv6_only === false) q('f_net_ipv6_only').value = '0';
    else q('f_net_ipv6_only').value = '';
  }
  fillQosFields(ep);
  if(q('f_adaptive_lb')){
    q('f_adaptive_lb').checked = !(ex && ex.adaptive_lb_enabled === false);
  }
}

function applyCommonAdvancedToEndpoint(endpoint){
  const ep = endpoint || {};
  let ex = (ep.extra_config && typeof ep.extra_config === 'object' && !Array.isArray(ep.extra_config)) ? {...ep.extra_config} : {};

  // bind / route
  const through = _trim(q('f_through') ? q('f_through').value : '');
  if(through) ep.through = through; else delete ep.through;

  const iface = _trim(q('f_interface') ? q('f_interface').value : '');
  if(iface) ep.interface = iface; else delete ep.interface;

  const liface = _trim(q('f_listen_interface') ? q('f_listen_interface').value : '');
  if(liface) ep.listen_interface = liface; else delete ep.listen_interface;

  // proxy
  const ap = readTriBoolSelect('f_accept_proxy');
  if(ap.set) ep.accept_proxy = ap.value; else delete ep.accept_proxy;

  const apt = readNonnegIntInput('f_accept_proxy_timeout', '解析超时');
  if(apt.error) return {ok:false, error:apt.error};
  if(apt.set) ep.accept_proxy_timeout = apt.value; else delete ep.accept_proxy_timeout;

  const sp = readTriBoolSelect('f_send_proxy');
  if(sp.set) ep.send_proxy = sp.value; else delete ep.send_proxy;

  const spvEl = q('f_send_proxy_version');
  const spv = spvEl ? String(spvEl.value || '').trim() : '';
  if(!spv){
    delete ep.send_proxy_version;
  }else if(spv === '1' || spv === '2'){
    ep.send_proxy_version = parseInt(spv, 10);
  }else{
    return {ok:false, error:'PROXY 版本仅支持 1 或 2'};
  }

  // mptcp
  const sm = readTriBoolSelect('f_send_mptcp');
  if(sm.set) ep.send_mptcp = sm.value; else delete ep.send_mptcp;

  const am = readTriBoolSelect('f_accept_mptcp');
  if(am.set) ep.accept_mptcp = am.value; else delete ep.accept_mptcp;

  // transport strings
  const ltrans = _trim(q('f_listen_transport') ? q('f_listen_transport').value : '');
  if(ltrans) ep.listen_transport = ltrans; else delete ep.listen_transport;

  const rtrans = _trim(q('f_remote_transport') ? q('f_remote_transport').value : '');
  if(rtrans) ep.remote_transport = rtrans; else delete ep.remote_transport;

  // endpoint.network overrides
  let net = (ep.network && typeof ep.network === 'object' && !Array.isArray(ep.network)) ? ep.network : {};

  const t1 = readNonnegIntInput('f_net_tcp_timeout', 'TCP 连接超时');
  if(t1.error) return {ok:false, error:t1.error};
  if(t1.set) net.tcp_timeout = t1.value; else delete net.tcp_timeout;

  const t2 = readNonnegIntInput('f_net_udp_timeout', 'UDP 关联超时');
  if(t2.error) return {ok:false, error:t2.error};
  if(t2.set) net.udp_timeout = t2.value; else delete net.udp_timeout;

  const t3 = readNonnegIntInput('f_net_tcp_keepalive', 'TCP Keepalive');
  if(t3.error) return {ok:false, error:t3.error};
  if(t3.set) net.tcp_keepalive = t3.value; else delete net.tcp_keepalive;

  const t4 = readNonnegIntInput('f_net_tcp_keepalive_probe', 'Keepalive 重试次数');
  if(t4.error) return {ok:false, error:t4.error};
  if(t4.set) net.tcp_keepalive_probe = t4.value; else delete net.tcp_keepalive_probe;

  const ipv6El = q('f_net_ipv6_only');
  const ipv6 = ipv6El ? String(ipv6El.value || '').trim() : '';
  if(!ipv6){
    delete net.ipv6_only;
  }else if(ipv6 === '1'){
    net.ipv6_only = true;
  }else if(ipv6 === '0'){
    net.ipv6_only = false;
  }else{
    return {ok:false, error:'IPv6 Only 参数无效'};
  }

  // QoS
  const qosRead = readQosFields();
  if(!qosRead.ok) return {ok:false, error:qosRead.error};
  const qos = qosRead.qos;

  if(Object.keys(qos).length > 0){
    ex.qos = qos;
    net.qos = {...qos};
  }else{
    delete ex.qos;
    delete net.qos;
  }

  // cleanup empty network object
  try{
    const keys = Object.keys(net || {});
    if(keys.length === 0){
      delete ep.network;
    }else{
      ep.network = net;
    }
  }catch(_e){
    // keep as-is
  }

  try{
    const exKeys = Object.keys(ex || {});
    if(exKeys.length === 0){
      delete ep.extra_config;
    }else{
      ep.extra_config = ex;
    }
  }catch(_e){
    // keep as-is
  }

  // adaptive load-balance switch (per-rule)
  const autoLb = q('f_adaptive_lb') ? !!q('f_adaptive_lb').checked : true;
  setAdaptiveLbEnabled(ep, autoLb);

  return {ok:true};
}

function showWssBox(){
  const mode = q('f_type').value;
  if(q('wssBox')) q('wssBox').style.display = (mode === 'wss') ? 'block' : 'none';
  if(q('intranetBox')) q('intranetBox').style.display = (mode === 'intranet') ? 'block' : 'none';

  // Advanced sections (collapsed area)
  const commonAdv = document.getElementById('commonAdvancedBox');
  if(commonAdv) commonAdv.style.display = (mode === 'tcp') ? 'block' : 'none';
  const wssAdv = document.getElementById('wssAdvancedBox');
  if(wssAdv) wssAdv.style.display = (mode === 'wss') ? 'block' : 'none';
  const intrAdv = document.getElementById('intranetAdvancedBox');
  if(intrAdv) intrAdv.style.display = (mode === 'intranet') ? 'block' : 'none';

  // Update mode cards / guide / dynamic hints (new UI)
  try{ syncTunnelModeUI(); }catch(_e){}
}



// -------------------- Tunnel mode UX (3 modes) --------------------

function setTunnelMode(mode){
  const req = ['tcp','wss','intranet'].includes(String(mode||'').trim()) ? String(mode||'').trim() : defaultTunnelMode();
  const m = isModeAllowed(req) ? req : defaultTunnelMode();
  if(!isModeAllowed(m)){
    toast('当前账号无可用转发模式', true);
    return;
  }
  if(q('f_type')) q('f_type').value = m;
  showWssBox();
}

// Sync mode cards + dynamic hints/guide in rule modal
function syncTunnelModeUI(){
  const sel = q('f_type');
  if(!sel) return;
  let mode = String(sel.value || 'tcp').trim() || 'tcp';
  if(!isModeAllowed(mode)){
    const fallback = defaultTunnelMode();
    if(isModeAllowed(fallback)){
      mode = fallback;
      sel.value = fallback;
    }
  }

  // Compact mode pill (params screen)
  const modePill = document.getElementById('currentModePill');
  const modeSub = document.getElementById('currentModeSub');
  if(modePill){
    modePill.textContent = (mode === 'wss') ? 'WSS 隧道' : (mode === 'intranet') ? '内网穿透' : '普通转发';
  }
  if(modeSub){
    modeSub.textContent = (mode === 'wss') ? '发送机 ↔ 接收机' : (mode === 'intranet') ? '公网入口 ↔ 内网出口' : '单机监听 → 目标';
  }

  // Mode cards
  const wrap = document.getElementById('modeSwitch');
  if(wrap){
    wrap.querySelectorAll('.mode-card').forEach((btn)=>{
      const m = btn.getAttribute('data-mode');
      if(!isModeAllowed(m)){
        btn.style.display = 'none';
        return;
      }
      btn.style.display = '';
      btn.classList.toggle('active', m === mode);
    });
  }

  // Re-render intro guide for selected mode
  try{ renderModeGuide(mode); }catch(_e){}

  const setText = (el, t)=>{ if(el) el.textContent = t || ''; };
  const setHtml = (el, h)=>{ if(el) el.innerHTML = h || ''; };

  // Common elements
  const remoteMain = document.getElementById('remoteLabelMain');
  const remoteExtra = document.getElementById('remoteLabelExtra');
  const remoteHelp = document.getElementById('remoteHelp');
  const remEl = q('f_remotes');

  const listenMain = document.getElementById('listenLabelMain');
  const listenExample = document.getElementById('listenLabelExample');
  const baseHelp = document.getElementById('baseHelp');
  const portEl = q('f_listen_port');

  // Ensure default listen host exists (advanced)
  if(q('f_listen_host') && !q('f_listen_host').value.trim()){
    q('f_listen_host').value = '0.0.0.0';
  }

  // Keep prefix + hidden listen updated
  syncListenComputed();

  if(mode === 'wss'){
    setText(remoteMain, '最终目标');
    setText(remoteExtra, '（接收机转发，每行一个 host:port）');

    setText(listenMain, '监听端口');
    setText(listenExample, '（发送机对外端口，例如 443）');

    if(remEl) remEl.placeholder = '例如：10.0.0.10:443\n10.0.0.11:443';
    if(portEl && !portEl.placeholder) portEl.placeholder = '443';

    setText(baseHelp, '默认监听 0.0.0.0；保存/删除会同步到接收机。监听 IP / 隧道参数在高级参数。');

    let h = 'Remote 填最终目标（接收机可达）。多行可启用负载均衡。';
    const optCount = q('f_wss_receiver_node') ? q('f_wss_receiver_node').querySelectorAll('option').length : 0;
    if(optCount <= 1){
      h += '<br><span class="muted sm">接收机列表为空？请先在面板接入另一台节点。</span>';
    }
    setHtml(remoteHelp, h);

  }else if(mode === 'intranet'){
    setText(remoteMain, '内网目标');
    setText(remoteExtra, '（B 内网可达地址，每行一个 host:port）');

    setText(listenMain, '监听端口');
    setText(listenExample, '（公网入口对外端口，例如 443）');

    if(remEl) remEl.placeholder = '例如：192.168.1.10:80\n192.168.1.11:80';
    if(portEl && !portEl.placeholder) portEl.placeholder = '443';

    setText(baseHelp, '默认监听 0.0.0.0；保存/删除会同步到内网出口。监听 IP / 隧道参数在高级参数。');

    let h = 'Remote 填内网目标（内网出口 B 可达）。多行可启用负载均衡。';
    const optCount = q('f_intranet_receiver_node') ? q('f_intranet_receiver_node').querySelectorAll('option').length : 0;
    if(optCount <= 1){
      h += '<br><span class="muted sm">内网节点列表为空？先把内网机器接入面板，并在节点设置里勾选“内网机器”。</span>';
    }
    setHtml(remoteHelp, h);

  }else{
    setText(remoteMain, '目标地址');
    setText(remoteExtra, '（每行一个 host:port，多行启用负载均衡）');

    setText(listenMain, '监听端口');
    setText(listenExample, '（例如 443）');

    if(remEl) remEl.placeholder = '203.0.113.10:443\n198.51.100.8:443';
    if(portEl && !portEl.placeholder) portEl.placeholder = '443';

    setText(baseHelp, '默认监听 0.0.0.0；协议/策略/监听 IP 在高级参数。');
    setText(remoteHelp, '多目标时默认轮询；需要按来源 IP 固定落点可选 IP Hash。');
  }

  try{ updateModePreview(); }catch(_e){}
}

function _findNodeNameById(id){
  const rid = String(id || '').trim();
  if(!rid) return '';
  const list = Array.isArray(window.NODES_LIST) ? window.NODES_LIST : [];
  for(const n of list){
    if(String(n.id) === rid){
      return n.name || n.display_ip || ('节点-' + n.id);
    }
  }
  return '';
}

function renderModeGuide(mode){
  const box = document.getElementById('modeGuide');
  if(!box) return;

  const nodeName = (window.__NODE_NAME__ && String(window.__NODE_NAME__).trim())
    ? String(window.__NODE_NAME__).trim()
    : (window.__NODE_IP__ || '当前节点');

  let title = '';
  let desc = '';
  let diagram = '';
  let steps = [];
  let ico = '⚡';

  if(mode === 'wss'){
    ico = '🛡️';
    title = 'WSS 隧道（发送机 ↔ 接收机）';
    desc = '发送机对外监听；面板自动在接收机生成对应规则。Host/Path/SNI 可留空自动生成。';
    diagram = `客户端 → 发送机 ${nodeName} Listen  ⇢  WSS  ⇢  接收机 Receiver → 最终目标 Remotes`;
    steps = [
      '选择 <b>接收机节点</b>（自动同步配置）。',
      'Remote 填 <b>最终目标</b>（接收机可达地址）。',
      '更多细节在「高级参数」：接收机端口 / Host / Path / TLS。',
    ];
  } else if(mode === 'intranet'){
    ico = '🏠';
    title = '内网穿透（公网入口A ↔ 内网出口B）';
    desc = '公网入口监听；内网出口主动连回并把流量转发到内网目标。';
    diagram = `公网用户 → 公网入口A ${nodeName} Listen  ⇢  隧道(默认 18443)  ⇢  内网出口B → 内网目标 Remotes`;
    steps = [
      '先在内网节点 B 的节点设置里勾选 <b>内网机器</b>，再回来选择它。',
      'Remote 填 <b>内网目标</b>（B 可达地址，如 192.168.x.x:80）。',
      '隧道端口/公网地址可在「高级参数」调整。',
    ];
  } else {
    ico = '⚡';
    title = '普通转发（单机）';
    desc = '当前节点监听端口，转发到一个或多个目标地址（多行=负载均衡）。';
    diagram = `客户端 → 当前节点 ${nodeName} Listen → 目标 Remotes`;
    steps = [
      '填 <b>监听端口</b>（默认 0.0.0.0 监听所有网卡）。',
      'Remote 每行一个目标地址（host:port）。',
      '协议/策略/权重 在「高级参数」调整（可选）。',
    ];
  }

  const stepsHtml = steps.map((s, i)=>`<div class="mode-step"><span class="num">${i+1}</span><div class="txt">${s}</div></div>`).join('');
  box.innerHTML = `
    <div class="mode-guide-head">
      <div class="mode-ico">${ico}</div>
      <div style="min-width:0;">
        <div class="mode-guide-title">${title}</div>
        <div class="mode-guide-desc">${desc}</div>
      </div>
    </div>
    <div class="mode-diagram">${escapeHtml(diagram)}</div>
    <div class="mode-steps">${stepsHtml}</div>
    <div class="mode-preview" id="modeGuidePreview"></div>
  `;

  updateModePreview();
}

function _splitLines(raw){
  return String(raw || '').split(/\n/).map(x=>x.trim()).filter(Boolean).map(x=>x.replace('\\r',''));
}

function updateModePreview(){
  const el = document.getElementById('modeGuidePreview');
  if(!el) return;

  // keep listen fields synced (host prefix + hidden full listen)
  syncListenComputed();

  const mode = q('f_type') ? String(q('f_type').value || 'tcp').trim() : 'tcp';
  const listen = getListenString();
  const remotes = _splitLines(q('f_remotes') ? q('f_remotes').value : '');
  const n = remotes.length;
  const nodeName = (window.__NODE_NAME__ && String(window.__NODE_NAME__).trim())
    ? String(window.__NODE_NAME__).trim()
    : (window.__NODE_IP__ || '当前节点');

  if(mode === 'wss'){
    const rid = q('f_wss_receiver_node') ? q('f_wss_receiver_node').value.trim() : '';
    const recvName = _findNodeNameById(rid) || (rid ? ('节点-' + rid) : '未选择');
    const rport = q('f_wss_receiver_port') ? q('f_wss_receiver_port').value.trim() : '';
    const portText = rport ? rport : '（同发送机端口）';
    el.innerHTML = `预览：发送机 <b>${escapeHtml(nodeName)}</b> 监听 <span class="mono">${escapeHtml(listen||'—')}</span> ⇒ WSS ⇒ 接收机 <b>${escapeHtml(recvName)}</b> 端口 <span class="mono">${escapeHtml(portText)}</span> → 目标 <b>${n}</b> 个`;
    return;
  }

  if(mode === 'intranet'){
    const rid = q('f_intranet_receiver_node') ? q('f_intranet_receiver_node').value.trim() : '';
    const recvName = _findNodeNameById(rid) || (rid ? ('节点-' + rid) : '未选择');
    const sport = q('f_intranet_server_port') ? q('f_intranet_server_port').value.trim() : '';
    const shost = q('f_intranet_server_host') ? q('f_intranet_server_host').value.trim() : '';
    el.innerHTML = `预览：公网入口 <b>${escapeHtml(nodeName)}</b> 监听 <span class="mono">${escapeHtml(listen||'—')}</span> ⇒ 隧道端口 <span class="mono">${escapeHtml(sport||'18443')}</span>${shost ? (' · 公网地址 <span class="mono">' + escapeHtml(shost) + '</span>') : ''} ⇒ 内网出口 <b>${escapeHtml(recvName)}</b> → 内网目标 <b>${n}</b> 个`;
    return;
  }

  el.innerHTML = `预览：当前节点 <b>${escapeHtml(nodeName)}</b> 监听 <span class="mono">${escapeHtml(listen||'—')}</span> → 目标 <b>${n}</b> 个`;
}

window.setTunnelMode = setTunnelMode;

function randomToken(len){
  return Math.random().toString(36).slice(2, 2 + len);
}

// WSS 参数：随机生成（用于一键填充/留空自动补全）
const WSS_RANDOM_HOSTS = [
  'cdn.jsdelivr.net',
  'assets.cloudflare.com',
  'edge.microsoft.com',
  'static.cloudflareinsights.com',
  'ajax.googleapis.com',
  'fonts.gstatic.com',
  'images.unsplash.com',
  'cdn.discordapp.com',
];

const WSS_RANDOM_PATH_TPL = [
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

function genWssRandomParams(){
  const host = WSS_RANDOM_HOSTS[Math.floor(Math.random() * WSS_RANDOM_HOSTS.length)];
  const token = randomToken(10);
  const tpl = WSS_RANDOM_PATH_TPL[Math.floor(Math.random() * WSS_RANDOM_PATH_TPL.length)];
  let path = String(tpl || '/ws').replace('{token}', token);
  if(path && !path.startsWith('/')) path = '/' + path;
  return { host, path, sni: host };
}

// If user leaves host/path/sni empty, auto-fill on save.
// Return true if any field was auto-filled.
function autoFillWssIfBlank(){
  try{
    const hostEl = q('f_wss_host');
    const pathEl = q('f_wss_path');
    const sniEl = q('f_wss_sni');
    if(!hostEl || !pathEl || !sniEl) return false;

    let host = hostEl.value.trim();
    let path = pathEl.value.trim();
    let sni = sniEl.value.trim();

    // Normalize: path must start with /
    if(path && !path.startsWith('/')){
      path = '/' + path;
      pathEl.value = path;
    }

    if(host && path && sni) return false;

    const rnd = genWssRandomParams();
    let changed = false;

    if(!host){
      // If user only filled SNI, use it as host for consistency
      host = sni || rnd.host;
      hostEl.value = host;
      changed = true;
    }

    if(!path){
      path = rnd.path;
      pathEl.value = path;
      changed = true;
    }

    if(!sni){
      sni = host || rnd.sni;
      sniEl.value = sni;
      changed = true;
    }

    return changed;
  }catch(_e){
    return false;
  }
}

function randomizeWss(){
  const p = genWssRandomParams();
  setField('f_wss_host', p.host);
  setField('f_wss_path', p.path);
  setField('f_wss_sni', p.sni);
  q('f_wss_tls').value = '1';
  q('f_wss_insecure').checked = true;
}

// ------------------------------
// Save-time validations (Feature 2)
// - Port conflicts
// - Remote format (host:port per line)
// - Weights count must match remote lines

function normalizeHostPort(host, port){
  let h = String(host || '').trim();
  let p = String(port || '').trim();
  if(h.includes(':') && !h.startsWith('[')) h = '[' + h + ']';
  return h + ':' + p;
}

function parseRemoteLine(line){
  const s = String(line || '').replace('\r', '').trim();
  if(!s) return {ok:false, error:'空行', value:''};

  if(s.startsWith('ws;') || s.startsWith('wss;')){
    return {ok:false, error:'这里应填写 host:port，不应包含 ws; 参数', value:''};
  }

  // Allow URL with explicit port (we only use hostname:port)
  if(s.includes('://')){
    try{
      const u = new URL(s);
      const host = String(u.hostname || '').trim();
      const portStr = String(u.port || '').trim();
      if(!host) return {ok:false, error:'缺少主机名', value:''};
      if(!portStr) return {ok:false, error:'缺少端口', value:''};
      if(!/^\d+$/.test(portStr)) return {ok:false, error:'端口必须是数字', value:''};
      const port = parseInt(portStr, 10);
      if(!(port >= 1 && port <= 65535)) return {ok:false, error:'端口范围必须是 1-65535', value:''};
      return {ok:true, value: normalizeHostPort(host, port)};
    }catch(_e){
      return {ok:false, error:'URL 解析失败', value:''};
    }
  }

  // [ipv6]:port
  if(s.startsWith('[')){
    const close = s.indexOf(']');
    if(close < 0) return {ok:false, error:'IPv6 缺少 ]', value:''};
    const host = s.slice(1, close).trim();
    const rest = s.slice(close + 1).trim();
    if(!rest.startsWith(':')) return {ok:false, error:'缺少端口', value:''};
    const portStr = rest.slice(1).trim();
    if(!host) return {ok:false, error:'缺少主机名', value:''};
    if(!/^\d+$/.test(portStr)) return {ok:false, error:'端口必须是数字', value:''};
    const port = parseInt(portStr, 10);
    if(!(port >= 1 && port <= 65535)) return {ok:false, error:'端口范围必须是 1-65535', value:''};
    return {ok:true, value: normalizeHostPort(host, port)};
  }

  // host:port (split by last ':', supports raw IPv6:port)
  const i = s.lastIndexOf(':');
  if(i < 0) return {ok:false, error:'缺少端口（应为 host:port）', value:''};
  const host = s.slice(0, i).trim();
  const portStr = s.slice(i + 1).trim();
  if(!host) return {ok:false, error:'缺少主机名', value:''};
  if(!/^\d+$/.test(portStr)) return {ok:false, error:'端口必须是数字', value:''};
  const port = parseInt(portStr, 10);
  if(!(port >= 1 && port <= 65535)) return {ok:false, error:'端口范围必须是 1-65535', value:''};
  return {ok:true, value: normalizeHostPort(host, port)};
}

function normalizeRemotesText(text){
  const lines = String(text || '').split('\n').map(x=>String(x||'').trim()).filter(Boolean);
  const remotes = [];
  const errors = [];
  for(let i=0;i<lines.length;i++){
    const r = parseRemoteLine(lines[i]);
    if(!r.ok){
      errors.push({line: i+1, raw: lines[i], error: r.error});
    }else{
      remotes.push(r.value);
    }
  }
  return {remotes, errors};
}

function parseWeightTokens(text){
  return String(text || '').split(/[,，]/).map(x=>x.trim()).filter(Boolean);
}

function validateWeights(tokens, remoteCount){
  if(!tokens || tokens.length === 0) return {ok:true, weights:[]};
  if(remoteCount <= 1){
    return {ok:true, weights:[], ignored:true};
  }
  if(tokens.length !== remoteCount){
    return {ok:false, error:`权重数量必须与 Remote 行数一致（Remote ${remoteCount} 行，权重 ${tokens.length} 个）`};
  }
  const out = [];
  for(let i=0;i<tokens.length;i++){
    const t = tokens[i];
    if(!/^\d+$/.test(t)){
      return {ok:false, error:`权重必须是正整数（第 ${i+1} 个：${t}）`};
    }
    const n = parseInt(t, 10);
    if(!(n > 0)){
      return {ok:false, error:`权重必须是正整数（第 ${i+1} 个：${t}）`};
    }
    out.push(String(n));
  }
  return {ok:true, weights:out};
}

function protoSet(proto){
  const p = String(proto || 'tcp+udp').trim().toLowerCase();
  if(p === 'tcp') return {tcp:true, udp:false};
  if(p === 'udp') return {tcp:false, udp:true};
  return {tcp:true, udp:true};
}

function protoOverlap(a, b){
  const o = [];
  if(a.tcp && b.tcp) o.push('tcp');
  if(a.udp && b.udp) o.push('udp');
  return o;
}

function overlapProtoText(overlap){
  if(!overlap || overlap.length === 0) return '';
  if(overlap.length === 2) return 'TCP+UDP';
  return overlap[0] === 'tcp' ? 'TCP' : 'UDP';
}

function hostInfo(host){
  let h = String(host || '').trim();
  if(h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  const lower = h.toLowerCase();
  if(!h) return {fam:'unknown', wild:true, key:''};
  if(lower === '0.0.0.0') return {fam:'v4', wild:true, key:'0.0.0.0'};
  if(lower === '::' || lower === '0:0:0:0:0:0:0:0') return {fam:'v6', wild:true, key:'::'};
  if(h.includes(':')) return {fam:'v6', wild:false, key:lower};
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return {fam:'v4', wild:false, key:h};
  return {fam:'unknown', wild:false, key:lower};
}

function hostsOverlap(aHost, bHost){
  const a = hostInfo(aHost);
  const b = hostInfo(bHost);
  if(a.fam === 'unknown' || b.fam === 'unknown') return true;
  if(a.fam !== b.fam) return a.wild || b.wild;
  if(a.wild || b.wild) return true;
  return a.key === b.key;
}

function getSkipIndexForPortCheck(mode){
  if(CURRENT_EDIT_INDEX < 0) return -1;
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  const old = eps[CURRENT_EDIT_INDEX];
  if(!old) return -1;
  const ex = old.extra_config || {};
  if(mode === 'tcp') return CURRENT_EDIT_INDEX;
  if(mode === 'wss'){
    if(ex && ex.sync_id && ex.sync_role === 'sender') return CURRENT_EDIT_INDEX;
    return -1;
  }
  if(mode === 'intranet'){
    if(ex && ex.sync_id && ex.intranet_role === 'server') return CURRENT_EDIT_INDEX;
    return -1;
  }
  return -1;
}

function findPortConflict(newListen, newProtocol, skipIdx){
  const lp = parseListenToHostPort(newListen || '');
  const newPort = parseInt(lp.port || '0', 10);
  const newHost = lp.host || '0.0.0.0';
  if(!(newPort > 0)) return null;
  const newPs = protoSet(newProtocol);
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  for(let i=0;i<eps.length;i++){
    if(i === skipIdx) continue;
    const e = eps[i];
    if(!e) continue;
    const ex = e.extra_config || {};
    if(ex && ex.intranet_role === 'client') continue; // placeholder, doesn't bind
    const lp2 = parseListenToHostPort(e.listen || '');
    const port2 = parseInt(lp2.port || '0', 10);
    if(port2 !== newPort) continue;
    const ps2 = protoSet(e.protocol || 'tcp+udp');
    const ov = protoOverlap(newPs, ps2);
    if(ov.length === 0) continue;
    const host2 = lp2.host || '0.0.0.0';
    if(!hostsOverlap(newHost, host2)) continue;
    return {idx:i, listen:e.listen, protocolText: overlapProtoText(ov)};
  }
  return null;
}

function newRule(){
  if(allowedTunnelModes().length <= 0){
    toast('当前账号无可用转发模式', true);
    return;
  }
  CURRENT_EDIT_INDEX = -1;
  q('modalTitle').textContent = '新增规则';

  // Listen: port-only UI (default 0.0.0.0:443)
  if(q('f_listen_host')) setField('f_listen_host', '0.0.0.0');
  if(q('f_listen_port')) setField('f_listen_port', '443');
  syncListenComputed();

  setField('f_remotes','');
  if(q('f_remark')) setField('f_remark', '');
  if(q('f_favorite')) q('f_favorite').checked = false;
  q('f_disabled').value = '0';

  // 新建规则：默认启用，不显示“状态”字段（更聚焦）
  try{ const sc = q('statusCol'); if(sc) sc.style.display = 'none'; }catch(_e){}

  // Advanced defaults
  q('f_balance').value = 'roundrobin';
  setField('f_weights','');
  q('f_protocol').value = 'tcp+udp';

  // Mode default
  q('f_type').value = defaultTunnelMode();

  // reset autosync receiver fields
  if(q('f_wss_receiver_node')) setField('f_wss_receiver_node','');
  if(q('f_wss_receiver_port')) setField('f_wss_receiver_port','');
  if(q('f_intranet_receiver_node')) setField('f_intranet_receiver_node','');
  if(q('f_intranet_server_port')) setField('f_intranet_server_port','18443');

  // Close advanced by default
  const adv = document.getElementById('advancedDetails');
  if(adv) adv.open = false;

  populateReceiverSelect();
  populateIntranetReceiverSelect();
  fillWssFields({});
  fillIntranetFields({});
  fillCommonAdvancedFields({});
  showWssBox();
  openModal();
}

// Copy an existing rule as a new draft (opens the editor with fields pre-filled)
function copyRule(idx){
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  const src = eps[idx];
  if(!src) return;
  if(!canOperateEndpoint(src)){
    toast(modeDenyReason(endpointMode(src)), true);
    return;
  }

  // Copy means "new", so clear edit index to avoid overwriting existing
  CURRENT_EDIT_INDEX = -1;

  // Show status field (copy should preserve enabled/disabled)
  try{ const sc = q('statusCol'); if(sc) sc.style.display = ''; }catch(_e){}

  q('modalTitle').textContent = `复制规则 #${idx+1}`;

  // Listen: port-only UI
  const lp = parseListenToHostPort(src.listen || '');
  if(q('f_listen_host')) setField('f_listen_host', lp.host || '0.0.0.0');
  if(q('f_listen_port')) setField('f_listen_port', lp.port || '');
  syncListenComputed();

  // Targets
  setField('f_remotes', formatRemoteForInput(src));

  // meta
  if(q('f_remark')) setField('f_remark', getRuleRemark(src));
  if(q('f_favorite')) q('f_favorite').checked = isRuleFavorite(src);

  // status
  q('f_disabled').value = src.disabled ? '1' : '0';

  // balance + weights
  const balance = src.balance || 'roundrobin';
  q('f_balance').value = balance.startsWith('iphash') ? 'iphash' : 'roundrobin';
  const weights = balance.startsWith('roundrobin:')
    ? balance.split(':').slice(1).join(':').trim().split(',').map(x=>x.trim()).filter(Boolean)
    : [];
  setField('f_weights', weights.join(','));
  q('f_protocol').value = src.protocol || 'tcp+udp';

  // Decide which mode to copy:
  // - tunnel sender/server rules keep their mode
  // - receiver/client generated rules are copied as "tcp" to avoid incomplete peer metadata
  const ex = (src && src.extra_config) ? src.extra_config : {};
  let mode = wssMode(src);
  if(mode === 'wss'){
    if(!(ex && ex.sync_role === 'sender')) mode = 'tcp';
  }
  if(mode === 'intranet'){
    if(!(ex && ex.intranet_role === 'server')) mode = 'tcp';
  }
  q('f_type').value = mode;

  // Reset peer selectors first
  if(q('f_wss_receiver_node')) setField('f_wss_receiver_node','');
  if(q('f_wss_receiver_port')) setField('f_wss_receiver_port','');
  if(q('f_intranet_receiver_node')) setField('f_intranet_receiver_node','');
  if(q('f_intranet_server_port')) setField('f_intranet_server_port','18443');

  // Fill mode-specific fields
  if(mode === 'wss'){
    if(q('f_wss_receiver_node')) setField('f_wss_receiver_node', ex.sync_peer_node_id ? String(ex.sync_peer_node_id) : '');
    if(q('f_wss_receiver_port')) setField('f_wss_receiver_port', ex.sync_receiver_port ? String(ex.sync_receiver_port) : '');
    populateReceiverSelect();
    fillWssFields(src);
    fillIntranetFields({});
    fillCommonAdvancedFields({});
    fillQosFields(src);
  }else if(mode === 'intranet'){
    populateIntranetReceiverSelect();
    fillIntranetFields(src);
    fillWssFields({});
    fillCommonAdvancedFields({});
    fillQosFields(src);
  }else{
    // normal
    fillWssFields({});
    fillIntranetFields({});
    fillCommonAdvancedFields(src);
  }

  showWssBox();

  // Close/open advanced panel based on non-default values (same heuristic as edit)
  const adv = document.getElementById('advancedDetails');
  if(adv){
    let openAdv = false;
    try{
      const host = getListenHost();
      if(host && host !== '0.0.0.0') openAdv = true;
      if(q('f_protocol') && String(q('f_protocol').value || '') !== 'tcp+udp') openAdv = true;
      if(q('f_balance') && String(q('f_balance').value || '') !== 'roundrobin') openAdv = true;
      if(q('f_weights') && String(q('f_weights').value || '').trim()) openAdv = true;
      if(q('f_adaptive_lb') && q('f_adaptive_lb').checked === false) openAdv = true;

      const m = q('f_type') ? String(q('f_type').value || 'tcp') : 'tcp';
      if(m === 'intranet'){
        if(q('f_intranet_server_port') && String(q('f_intranet_server_port').value || '').trim() && String(q('f_intranet_server_port').value).trim() !== '18443') openAdv = true;
        if(q('f_intranet_server_host') && String(q('f_intranet_server_host').value || '').trim()) openAdv = true;
        if(q('f_intranet_acl_allow_sources') && String(q('f_intranet_acl_allow_sources').value || '').trim()) openAdv = true;
        if(q('f_intranet_acl_deny_sources') && String(q('f_intranet_acl_deny_sources').value || '').trim()) openAdv = true;
        if(q('f_intranet_acl_allow_hours') && String(q('f_intranet_acl_allow_hours').value || '').trim()) openAdv = true;
        if(q('f_intranet_acl_allow_tokens') && String(q('f_intranet_acl_allow_tokens').value || '').trim()) openAdv = true;
      }else if(m === 'wss'){
        if(q('f_wss_receiver_port') && String(q('f_wss_receiver_port').value || '').trim()) openAdv = true;
        if(q('f_wss_tls') && String(q('f_wss_tls').value || '1') !== '1') openAdv = true;
        if(q('f_wss_insecure') && q('f_wss_insecure').checked === false) openAdv = true;
      }else{
        // tcp/common advanced
        if(q('f_through') && String(q('f_through').value || '').trim()) openAdv = true;
        if(q('f_interface') && String(q('f_interface').value || '').trim()) openAdv = true;
        if(q('f_listen_interface') && String(q('f_listen_interface').value || '').trim()) openAdv = true;
        if(q('f_accept_proxy') && String(q('f_accept_proxy').value || '').trim()) openAdv = true;
        if(q('f_accept_proxy_timeout') && String(q('f_accept_proxy_timeout').value || '').trim()) openAdv = true;
        if(q('f_send_proxy') && String(q('f_send_proxy').value || '').trim()) openAdv = true;
        if(q('f_send_proxy_version') && String(q('f_send_proxy_version').value || '').trim()) openAdv = true;
        if(q('f_send_mptcp') && String(q('f_send_mptcp').value || '').trim()) openAdv = true;
        if(q('f_accept_mptcp') && String(q('f_accept_mptcp').value || '').trim()) openAdv = true;
        if(q('f_net_tcp_timeout') && String(q('f_net_tcp_timeout').value || '').trim()) openAdv = true;
        if(q('f_net_udp_timeout') && String(q('f_net_udp_timeout').value || '').trim()) openAdv = true;
        if(q('f_net_tcp_keepalive') && String(q('f_net_tcp_keepalive').value || '').trim()) openAdv = true;
        if(q('f_net_tcp_keepalive_probe') && String(q('f_net_tcp_keepalive_probe').value || '').trim()) openAdv = true;
        if(q('f_net_ipv6_only') && String(q('f_net_ipv6_only').value || '').trim()) openAdv = true;
        if(q('f_listen_transport') && String(q('f_listen_transport').value || '').trim()) openAdv = true;
        if(q('f_remote_transport') && String(q('f_remote_transport').value || '').trim()) openAdv = true;
      }
    }catch(_e){}
    adv.open = openAdv;
  }

  openModal();
}
window.copyRule = copyRule;

function toggleRuleTempUnlock(idx, ev){
  try{
    if(ev){
      ev.preventDefault && ev.preventDefault();
      ev.stopPropagation && ev.stopPropagation();
    }
  }catch(_e){}
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  const e = eps[idx];
  if(!e) return;
  const ex = (e && e.extra_config) ? e.extra_config : {};
  if(!(ex && (ex.sync_lock === true || ex.sync_role === 'receiver'))){
    return;
  }
  const key = getRuleKey(e);
  if(!key) return;

  const now = Date.now();
  const cur = Number(RULE_TEMP_UNLOCK.get(key) || 0);
  if(Number.isFinite(cur) && cur > now){
    RULE_TEMP_UNLOCK.delete(key);
    scheduleRuleTempUnlockTimer();
    toast('已重新锁定');
    renderRules();
    return;
  }

  RULE_TEMP_UNLOCK.set(key, now + RULE_TEMP_UNLOCK_TTL_MS);
  scheduleRuleTempUnlockTimer();
  toast(`已临时解锁 ${Math.ceil(RULE_TEMP_UNLOCK_TTL_MS / 1000)} 秒`);
  renderRules();
}
window.toggleRuleTempUnlock = toggleRuleTempUnlock;

function editRule(idx){
  CURRENT_EDIT_INDEX = idx;
  const e = CURRENT_POOL.endpoints[idx];
  if(!canOperateEndpoint(e)){
    toast(modeDenyReason(endpointMode(e)), true);
    return;
  }
  const ex = (e && e.extra_config) ? e.extra_config : {};

  // Auto-sync generated rules are read-only (receiver/client side)
  try{
    const li = getRuleLockInfo(e);
    if(li && li.locked){
      toast(li.reason || '该规则已锁定（只读）', true);
      return;
    }
  }catch(_e){}

  // 编辑规则时允许切换“启用/暂停”
  try{ const sc = q('statusCol'); if(sc) sc.style.display = ''; }catch(_e){}

  q('modalTitle').textContent = `编辑规则 #${idx+1}`;
  // Listen: port-only UI
  const lp = parseListenToHostPort(e.listen || '');
  if(q('f_listen_host')) setField('f_listen_host', lp.host || '0.0.0.0');
  if(q('f_listen_port')) setField('f_listen_port', lp.port || '');
  syncListenComputed();
  // synced sender rule should show original targets (not the peer receiver ip:port)
  setField('f_remotes', formatRemoteForInput(e));

  // meta
  if(q('f_remark')) setField('f_remark', getRuleRemark(e));
  if(q('f_favorite')) q('f_favorite').checked = isRuleFavorite(e);

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

  // common advanced fields (only meaningful for normal rules)
  if(mode === 'tcp') fillCommonAdvancedFields(e);
  else{
    fillCommonAdvancedFields({});
    fillQosFields(e);
  }

  showWssBox();
  // Close/open advanced panel based on non-default values
  const adv = document.getElementById('advancedDetails');
  if(adv){
    let openAdv = false;
    try{
      const host = getListenHost();
      if(host && host !== '0.0.0.0') openAdv = true;
      if(q('f_protocol') && String(q('f_protocol').value || '') !== 'tcp+udp') openAdv = true;
      if(q('f_balance') && String(q('f_balance').value || '') !== 'roundrobin') openAdv = true;
      if(q('f_weights') && String(q('f_weights').value || '').trim()) openAdv = true;
      if(q('f_adaptive_lb') && q('f_adaptive_lb').checked === false) openAdv = true;

      const mode = q('f_type') ? String(q('f_type').value || 'tcp') : 'tcp';
      if(mode === 'intranet'){
        if(q('f_intranet_server_port') && String(q('f_intranet_server_port').value || '').trim() && String(q('f_intranet_server_port').value).trim() !== '18443') openAdv = true;
        if(q('f_intranet_server_host') && String(q('f_intranet_server_host').value || '').trim()) openAdv = true;
        if(q('f_intranet_acl_allow_sources') && String(q('f_intranet_acl_allow_sources').value || '').trim()) openAdv = true;
        if(q('f_intranet_acl_deny_sources') && String(q('f_intranet_acl_deny_sources').value || '').trim()) openAdv = true;
        if(q('f_intranet_acl_allow_hours') && String(q('f_intranet_acl_allow_hours').value || '').trim()) openAdv = true;
        if(q('f_intranet_acl_allow_tokens') && String(q('f_intranet_acl_allow_tokens').value || '').trim()) openAdv = true;
      }else if(mode === 'wss'){
        if(q('f_wss_receiver_port') && String(q('f_wss_receiver_port').value || '').trim()) openAdv = true;
        if(q('f_wss_tls') && String(q('f_wss_tls').value || '1') !== '1') openAdv = true;
        if(q('f_wss_insecure') && q('f_wss_insecure').checked === false) openAdv = true;
      }else{
        // tcp/common advanced
        if(q('f_through') && String(q('f_through').value || '').trim()) openAdv = true;
        if(q('f_interface') && String(q('f_interface').value || '').trim()) openAdv = true;
        if(q('f_listen_interface') && String(q('f_listen_interface').value || '').trim()) openAdv = true;

        if(q('f_accept_proxy') && String(q('f_accept_proxy').value || '').trim()) openAdv = true;
        if(q('f_accept_proxy_timeout') && String(q('f_accept_proxy_timeout').value || '').trim()) openAdv = true;
        if(q('f_send_proxy') && String(q('f_send_proxy').value || '').trim()) openAdv = true;
        if(q('f_send_proxy_version') && String(q('f_send_proxy_version').value || '').trim()) openAdv = true;
        if(q('f_send_mptcp') && String(q('f_send_mptcp').value || '').trim()) openAdv = true;
        if(q('f_accept_mptcp') && String(q('f_accept_mptcp').value || '').trim()) openAdv = true;

        if(q('f_net_tcp_timeout') && String(q('f_net_tcp_timeout').value || '').trim()) openAdv = true;
        if(q('f_net_udp_timeout') && String(q('f_net_udp_timeout').value || '').trim()) openAdv = true;
        if(q('f_net_tcp_keepalive') && String(q('f_net_tcp_keepalive').value || '').trim()) openAdv = true;
        if(q('f_net_tcp_keepalive_probe') && String(q('f_net_tcp_keepalive_probe').value || '').trim()) openAdv = true;
        if(q('f_net_ipv6_only') && String(q('f_net_ipv6_only').value || '').trim()) openAdv = true;
        if(q('f_listen_transport') && String(q('f_listen_transport').value || '').trim()) openAdv = true;
        if(q('f_remote_transport') && String(q('f_remote_transport').value || '').trim()) openAdv = true;
      }
    }catch(_e){}
    adv.open = openAdv;
  }

  openModal();
}

async function toggleRule(idx){
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  const e = eps[idx];
  if(!e){
    toast('规则不存在或已删除', true);
    return;
  }
  if(!canOperateEndpoint(e)){
    toast(modeDenyReason(endpointMode(e)), true);
    return;
  }
  const ex = (e && e.extra_config) ? e.extra_config : {};
  const li = getRuleLockInfo(e);
  if(li && li.locked){
    toast(li.reason || '该规则已锁定（只读）', true);
    return;
  }

  const newDisabled = !e.disabled;

  // Synced WSS sender: update both sides via panel API
  if(ex && ex.sync_id && ex.sync_role === 'sender' && ex.sync_peer_node_id){
    try{
      setLoading(true);
      const qos = collectQosFromEndpoint(e);
      const payload = {
        sender_node_id: window.__NODE_ID__,
        receiver_node_id: ex.sync_peer_node_id,
        listen: e.listen,
        remotes: ex.sync_original_remotes || [],
        disabled: newDisabled,
        balance: e.balance || 'roundrobin',
        protocol: e.protocol || 'tcp+udp',
        remark: getRuleRemark(e),
        favorite: isRuleFavorite(e),
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
      if(Object.keys(qos).length > 0) payload.qos = qos;
      await enqueueSyncSaveTask('wss', payload, '已同步更新（发送/接收两端）');
      toast('已提交同步任务（发送/接收两端）');
    }catch(err){
      toast(formatRequestError(err, 'WSS 隧道保存失败'), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  // Intranet tunnel sender: update both sides via panel API
  if(ex && ex.sync_id && ex.intranet_role === 'server' && ex.intranet_peer_node_id){
    try{
      setLoading(true);
      const qos = collectQosFromEndpoint(e);
      const acl = (ex.intranet_acl && typeof ex.intranet_acl === 'object' && !Array.isArray(ex.intranet_acl)) ? ex.intranet_acl : {};
      const payload = {
        sender_node_id: window.__NODE_ID__,
        receiver_node_id: ex.intranet_peer_node_id,
        listen: e.listen,
        remotes: ex.intranet_original_remotes || e.remotes || [],
        disabled: newDisabled,
        balance: e.balance || 'roundrobin',
        protocol: e.protocol || 'tcp+udp',
        remark: getRuleRemark(e),
        favorite: isRuleFavorite(e),
        server_port: ex.intranet_server_port || 18443,
        sync_id: ex.sync_id
      };
      if(Object.keys(qos).length > 0) payload.qos = qos;
      if(Object.keys(acl).length > 0) payload.acl = acl;
      await enqueueSyncSaveTask('intranet', payload, '已同步更新（公网入口/内网出口两端）');
      toast('已提交同步任务（公网入口/内网出口两端）');
    }catch(err){
      toast(formatRequestError(err, '内网穿透保存失败'), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  // Normal rule
  const draft = clonePool(CURRENT_POOL);
  const draftEps = Array.isArray(draft.endpoints) ? draft.endpoints : [];
  if(idx < 0 || idx >= draftEps.length || !draftEps[idx]){
    toast('规则不存在或已删除', true);
    return;
  }
  draftEps[idx].disabled = newDisabled;
  draft.endpoints = draftEps;
  await savePool('规则状态更新任务已提交', draft);
}

async function toggleFavorite(idx, ev){
  try{
    if(ev){
      ev.preventDefault && ev.preventDefault();
      ev.stopPropagation && ev.stopPropagation();
    }
  }catch(_e){}

  if(RULE_META_SAVING) return;
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  const e = eps[idx];
  if(!e) return;

  const draft = clonePool(CURRENT_POOL);
  const dep = (draft && Array.isArray(draft.endpoints)) ? draft.endpoints[idx] : null;
  if(!dep){
    toast('规则不存在或已删除', true);
    return;
  }
  const old = !!e.favorite;
  if(old) delete dep.favorite;
  else dep.favorite = true;

  RULE_META_SAVING = true;
  try{
    await savePool(old ? '取消收藏任务已提交' : '收藏任务已提交', draft);
  }catch(_err){
    // keep current view until task success refreshes from backend
  }finally{
    RULE_META_SAVING = false;
  }
}

async function editRemark(idx, ev){
  try{
    if(ev){
      ev.preventDefault && ev.preventDefault();
      ev.stopPropagation && ev.stopPropagation();
    }
  }catch(_e){}

  if(RULE_META_SAVING) return;
  const eps = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints : [];
  const e = eps[idx];
  if(!e) return;
  if(!canOperateEndpoint(e)){
    toast(modeDenyReason(endpointMode(e)), true);
    return;
  }

  const next = prompt('规则备注（用于搜索/筛选，可留空清除）：', getRuleRemark(e));
  if(next === null) return;
  const v = String(next || '').trim();
  const draft = clonePool(CURRENT_POOL);
  const dep = (draft && Array.isArray(draft.endpoints)) ? draft.endpoints[idx] : null;
  if(!dep){
    toast('规则不存在或已删除', true);
    return;
  }
  if(v) dep.remark = v;
  else delete dep.remark;

  RULE_META_SAVING = true;
  try{
    await savePool('备注保存任务已提交', draft);
  }catch(_err){
    // keep current view until task success refreshes from backend
  }finally{
    RULE_META_SAVING = false;
  }
}

async function deleteRule(idx){
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];
  const e = eps[idx];
  if(!e){
    toast('规则不存在或已删除', true);
    return;
  }
  if(!canOperateEndpoint(e)){
    toast(modeDenyReason(endpointMode(e)), true);
    return;
  }
  const ex = (e && e.extra_config) ? e.extra_config : {};
  const li = getRuleLockInfo(e);
  if(li && li.locked){
    toast(li.reason || '该规则已锁定（只读）', true);
    return;
  }

  // Synced sender: delete both sides
  if(ex && ex.sync_id && ex.sync_role === 'sender' && ex.sync_peer_node_id){
    if(!confirm('这将同时删除接收机对应规则，确定继续？（不可恢复）')) return;
    try{
      setLoading(true);
      const payload = { sender_node_id: window.__NODE_ID__, receiver_node_id: ex.sync_peer_node_id, sync_id: ex.sync_id };
      await enqueueSyncDeleteTask('wss', payload, '已删除（发送/接收两端）');
      toast('已提交删除任务（发送/接收两端）');
    }catch(err){
      toast(formatRequestError(err, 'WSS 隧道删除失败'), true);
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
      await enqueueSyncDeleteTask('intranet', payload, '已删除（公网入口/内网出口两端）');
      toast('已提交删除任务（公网入口/内网出口两端）');
    }catch(err){
      toast(formatRequestError(err, '内网穿透删除失败'), true);
    }finally{
      setLoading(false);
    }
    return;
  }

  if(!confirm('确定删除这条规则吗？（不可恢复）')) return;
  try{
    setLoading(true);
    const draft = clonePool(CURRENT_POOL);
    if(Array.isArray(draft.endpoints) && idx >= 0 && idx < draft.endpoints.length){
      draft.endpoints.splice(idx, 1);
    }
    await enqueueNodePoolTask(
      'rule_delete',
      { idx, expected_key: getRuleKey(e), unlock_sync_ids: collectUnlockSyncIds() },
      '规则删除任务已提交'
    );
    CURRENT_POOL = draft;
    toast('已提交删除任务，正在后台生效');
  }catch(err){
    toast(String((err && err.message) ? err.message : err), true);
  }finally{
    setLoading(false);
  }
}

// -------------------- Bulk operations --------------------

async function bulkSetDisabled(disabled){
  if(BULK_ACTION_RUNNING) return;
  const wantDisabled = !!disabled;
  const actionName = wantDisabled ? '暂停' : '启用';
  const items = getSelectedRuleItems();
  if(!items.length){
    toast('请先勾选需要批量操作的规则', true);
    return;
  }

  let ok = 0;
  let skipped = 0;
  let failed = 0;
  let queued = 0;

  // Keys for normal rules (handled in one savePool)
  const normalKeys = [];

  BULK_ACTION_RUNNING = true;
  try{
    setLoading(true);

    // 1) Handle synced tunnel sender rules first (server-side API returns updated pools)
    for(const it of items){
      const e = it.e;
      if(!e) continue;
      if(!canOperateEndpoint(e)){
        skipped += 1;
        continue;
      }
      const li = getRuleLockInfo(e);
      if(li && li.locked){
        skipped += 1;
        continue;
      }
      const ex = (e && e.extra_config) ? e.extra_config : {};

      // WSS sender: update both sides
      if(ex && ex.sync_id && ex.sync_role === 'sender' && ex.sync_peer_node_id){
        try{
          const qos = collectQosFromEndpoint(e);
          const payload = {
            sender_node_id: window.__NODE_ID__,
            receiver_node_id: ex.sync_peer_node_id,
            listen: e.listen,
            remotes: ex.sync_original_remotes || [],
            disabled: wantDisabled,
            balance: e.balance || 'roundrobin',
            protocol: e.protocol || 'tcp+udp',
            remark: getRuleRemark(e),
            favorite: isRuleFavorite(e),
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
          if(Object.keys(qos).length > 0) payload.qos = qos;
          await enqueueSyncSaveTask('wss', payload, 'WSS 批量同步已完成');
          ok += 1;
          queued += 1;
        }catch(err){
          failed += 1;
        }
        continue;
      }

      // Intranet server: update both sides
      if(ex && ex.sync_id && ex.intranet_role === 'server' && ex.intranet_peer_node_id){
        try{
          const qos = collectQosFromEndpoint(e);
          const acl = (ex.intranet_acl && typeof ex.intranet_acl === 'object' && !Array.isArray(ex.intranet_acl)) ? ex.intranet_acl : {};
          const payload = {
            sender_node_id: window.__NODE_ID__,
            receiver_node_id: ex.intranet_peer_node_id,
            listen: e.listen,
            remotes: ex.intranet_original_remotes || e.remotes || [],
            disabled: wantDisabled,
            balance: e.balance || 'roundrobin',
            protocol: e.protocol || 'tcp+udp',
            remark: getRuleRemark(e),
            favorite: isRuleFavorite(e),
            server_port: ex.intranet_server_port || 18443,
            sync_id: ex.sync_id
          };
          if(Object.keys(qos).length > 0) payload.qos = qos;
          if(Object.keys(acl).length > 0) payload.acl = acl;
          await enqueueSyncSaveTask('intranet', payload, '内网穿透批量同步已完成');
          ok += 1;
          queued += 1;
        }catch(err){
          failed += 1;
        }
        continue;
      }

      // Normal rule (handled later)
      normalKeys.push(it.key);
    }

    // 2) Apply changes to normal rules and save once
    if(normalKeys.length){
      const draft = clonePool(CURRENT_POOL);
      const eps = (draft && Array.isArray(draft.endpoints)) ? draft.endpoints : [];
      for(const k of normalKeys){
        const j = eps.findIndex(x => getRuleKey(x) === k);
        if(j >= 0){
          eps[j].disabled = wantDisabled;
          ok += 1;
        }else{
          failed += 1;
        }
      }
      draft.endpoints = eps;
      await savePool(`批量${actionName}任务已提交`, draft);
    }

    updateBulkBar();
    const queuedText = queued > 0 ? `，已提交同步任务 ${queued}` : '';
    toast(`批量${actionName}已提交：成功 ${ok}，跳过 ${skipped}${failed ? `，失败 ${failed}` : ''}${queuedText}`);
  }catch(err){
    toast(`批量${actionName}失败：${(err && err.message) ? err.message : String(err)}`, true);
    try{ await loadPool(); }catch(_e){}
  }finally{
    setLoading(false);
    BULK_ACTION_RUNNING = false;
  }
}
window.bulkSetDisabled = bulkSetDisabled;

async function bulkDeleteSelected(){
  if(BULK_ACTION_RUNNING) return;
  const items = getSelectedRuleItems();
  if(!items.length){
    toast('请先勾选需要删除的规则', true);
    return;
  }

  let hasWssSender = false;
  let hasIntranetSender = false;
  let lockedCount = 0;
  for(const it of items){
    const e = it.e;
    if(!e) continue;
    const li = getRuleLockInfo(e);
    if(li && li.locked){ lockedCount += 1; continue; }
    const ex = (e && e.extra_config) ? e.extra_config : {};
    if(ex && ex.sync_id && ex.sync_role === 'sender' && ex.sync_peer_node_id) hasWssSender = true;
    if(ex && ex.sync_id && ex.intranet_role === 'server' && ex.intranet_peer_node_id) hasIntranetSender = true;
  }

  const n = items.length;
  let msg = `确定删除选中的 ${n} 条规则吗？（不可恢复）`;
  if(hasWssSender) msg += `\n\n注意：包含 WSS 隧道发送机规则，删除将同步删除接收机对应规则。`;
  if(hasIntranetSender) msg += `\n\n注意：包含内网穿透公网入口规则，删除将同步删除内网出口对应配置。`;
  if(lockedCount) msg += `\n\n其中 ${lockedCount} 条为锁定规则，将自动跳过。`;
  if(!confirm(msg)) return;

  let ok = 0;
  let skipped = 0;
  let failed = 0;
  const normalKeys = [];

  BULK_ACTION_RUNNING = true;
  try{
    setLoading(true);

    // 1) Synced tunnel sender/server deletions first
    for(const it of items){
      const e = it.e;
      if(!e) continue;
      if(!canOperateEndpoint(e)){
        skipped += 1;
        continue;
      }
      const li = getRuleLockInfo(e);
      if(li && li.locked){
        skipped += 1;
        continue;
      }
      const ex = (e && e.extra_config) ? e.extra_config : {};

      if(ex && ex.sync_id && ex.sync_role === 'sender' && ex.sync_peer_node_id){
        try{
          const payload = { sender_node_id: window.__NODE_ID__, receiver_node_id: ex.sync_peer_node_id, sync_id: ex.sync_id };
          await enqueueSyncDeleteTask('wss', payload, 'WSS 批量删除已完成');
          ok += 1;
        }catch(err){
          failed += 1;
        }
        continue;
      }

      if(ex && ex.sync_id && ex.intranet_role === 'server' && ex.intranet_peer_node_id){
        try{
          const payload = { sender_node_id: window.__NODE_ID__, receiver_node_id: ex.intranet_peer_node_id, sync_id: ex.sync_id };
          await enqueueSyncDeleteTask('intranet', payload, '内网穿透批量删除已完成');
          ok += 1;
        }catch(err){
          failed += 1;
        }
        continue;
      }

      // Normal rules removed in one savePool
      normalKeys.push(it.key);
    }

    // 2) Remove normal rules locally and save once
    if(normalKeys.length){
      const keySet = new Set(normalKeys.filter(Boolean));
      const draft = clonePool(CURRENT_POOL);
      const eps = (draft && Array.isArray(draft.endpoints)) ? draft.endpoints : [];
      const before = eps.length;
      const next = eps.filter(ep => !keySet.has(getRuleKey(ep)));
      const removed = before - next.length;
      draft.endpoints = next;
      if(removed > 0){
        await savePool('批量删除任务已提交', draft);
        ok += removed;
      }
      const missing = normalKeys.length - removed;
      if(missing > 0) failed += missing;
    }

    // Clear selection after delete
    RULE_SELECTED_KEYS = new Set();
    updateBulkBar();

    toast(`批量删除已提交：成功 ${ok}，跳过 ${skipped}${failed ? `，失败 ${failed}` : ''}`);
  }catch(err){
    toast(`批量删除失败：${(err && err.message) ? err.message : String(err)}`, true);
    try{ await loadPool(); }catch(_e){}
  }finally{
    setLoading(false);
    BULK_ACTION_RUNNING = false;
  }
}
window.bulkDeleteSelected = bulkDeleteSelected;

async function saveRule(){
  const typeSel = q('f_type').value;
  if(!isModeAllowed(typeSel)){
    toast(modeDenyReason(typeSel), true);
    return;
  }
  // Listen: port-only UI
  syncListenComputed();
  const listen = getListenString();
  const listenPortNum = parseInt(getListenPort() || '0', 10);
  if(!listen){ toast('本地监听不能为空', true); return; }
  if(!(listenPortNum >= 1 && listenPortNum <= 65535)){
    toast('本地监听端口范围必须是 1-65535', true);
    return;
  }

  // Remote format validation + normalization
  const remotesRaw = q('f_remotes').value || '';
  const nrm = normalizeRemotesText(remotesRaw);
  if(nrm.errors.length){
    const e0 = nrm.errors[0];
    toast(`目标地址格式错误（第 ${e0.line} 行）：${e0.raw}（${e0.error}）`, true);
    return;
  }
  const remotes = nrm.remotes;
  if(remotes.length === 0){ toast('目标地址不能为空', true); return; }
  // Keep form clean (auto-canonicalize IPv6 bracket, trim spaces, etc.)
  try{ q('f_remotes').value = remotes.join('\n'); }catch(_e){}
  const disabled = (q('f_disabled').value === '1');

  // meta
  const remark = q('f_remark') ? String(q('f_remark').value || '').trim() : '';
  const favorite = q('f_favorite') ? !!q('f_favorite').checked : false;

  // optional weights for roundrobin (comma separated)
  const weightsRaw = q('f_weights') ? (q('f_weights').value || '').trim() : '';
  let weightTokens = parseWeightTokens(weightsRaw);

  let balTxt = (q('f_balance').value || '').trim();
  let balance = balTxt ? balTxt.split(':')[0].trim() : 'roundrobin';
  if(!balance) balance = 'roundrobin';

  let balanceStr = balance;
  if(balance !== 'roundrobin'){
    if(weightTokens.length){
      toast('IP Hash 不支持权重，已忽略权重');
    }
    weightTokens = [];
  }
  const wv = validateWeights(weightTokens, remotes.length);
  if(!wv.ok){ toast(wv.error, true); return; }
  if(wv.ignored && weightTokens.length){ toast('只有一个目标时无需权重，已忽略权重'); }
  if(balance === 'roundrobin' && wv.weights.length > 0){
    balanceStr = `roundrobin: ${wv.weights.join(',')}`;
  }
  // Keep weights input clean
  try{
    if(q('f_weights')) q('f_weights').value = (balance === 'roundrobin' && wv.weights.length) ? wv.weights.join(',') : '';
  }catch(_e){}

  const protocol = q('f_protocol').value || 'tcp+udp';

  // Listen port conflict validation (against current node pool)
  const skipIdx = getSkipIndexForPortCheck(typeSel);
  const conflict = findPortConflict(listen, protocol, skipIdx);
  if(conflict){
    toast(`端口冲突：端口 ${listenPortNum} 已被规则 #${conflict.idx+1}（${conflict.listen}）占用（协议：${conflict.protocolText}）`, true);
    return;
  }

  const editingOld = (CURRENT_EDIT_INDEX >= 0 && CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints))
    ? CURRENT_POOL.endpoints[CURRENT_EDIT_INDEX]
    : null;
  const editingEx = (editingOld && editingOld.extra_config && typeof editingOld.extra_config === 'object')
    ? editingOld.extra_config
    : {};
  const editingLockInfo = editingOld ? getRuleLockInfo(editingOld) : { locked: false };
  const allowLocalEditForUnlockedWssReceiver = !!(
    typeSel === 'wss' &&
    CURRENT_EDIT_INDEX >= 0 &&
    editingEx &&
    editingEx.sync_id &&
    (editingEx.sync_role === 'receiver' || editingEx.sync_lock === true) &&
    editingLockInfo &&
    !editingLockInfo.locked
  );

  // WSS 隧道：必须选择接收机，自动同步生成接收端规则
  if(typeSel === 'wss'){
    // Receiver side: when temporarily unlocked, allow direct local save on current node.
    if(allowLocalEditForUnlockedWssReceiver){
      let endpoint = {};
      try{
        endpoint = editingOld ? JSON.parse(JSON.stringify(editingOld)) : {};
      }catch(_e){
        endpoint = {};
      }

      endpoint.listen = listen;
      endpoint.remotes = remotes;
      endpoint.disabled = disabled;
      endpoint.balance = balanceStr;
      endpoint.protocol = protocol;

      try{ delete endpoint.remote; }catch(_e){}
      try{ delete endpoint.extra_remotes; }catch(_e){}
      try{ delete endpoint.balanceStr; }catch(_e){}

      if(remark) endpoint.remark = remark; else { try{ delete endpoint.remark; }catch(_e){} }
      if(favorite) endpoint.favorite = true; else { try{ delete endpoint.favorite; }catch(_e){} }

      const advApply = applyCommonAdvancedToEndpoint(endpoint);
      if(!advApply.ok){ toast(advApply.error || '高级参数无效', true); return; }

      try{
        setLoading(true);
        const draft = clonePool(CURRENT_POOL);
        if(!Array.isArray(draft.endpoints)) draft.endpoints = [];
        if(CURRENT_EDIT_INDEX < 0 || CURRENT_EDIT_INDEX >= draft.endpoints.length){
          throw new Error('规则不存在或已删除');
        }
        draft.endpoints[CURRENT_EDIT_INDEX] = endpoint;
        await savePool('接收端保存任务已提交', draft);
        closeModal();
      }catch(err){
        const msg = (err && err.message) ? err.message : String(err || '保存失败');
        toast(msg, true);
        try{ await loadPool(); }catch(_e){}
      }finally{
        setLoading(false);
      }
      return;
    }

    // Receiver side lock has expired while modal stays open.
    if(
      CURRENT_EDIT_INDEX >= 0 &&
      editingEx &&
      editingEx.sync_id &&
      (editingEx.sync_role === 'receiver' || editingEx.sync_lock === true)
    ){
      toast('该接收端规则已重新锁定，请先点击“锁定”按钮临时解锁后再保存。', true);
      return;
    }

    const receiverNodeId = q('f_wss_receiver_node') ? q('f_wss_receiver_node').value.trim() : '';
    if(!receiverNodeId){
      toast('WSS 隧道必须选择接收机节点', true);
      return;
    }
    const receiverPortTxt = q('f_wss_receiver_port') ? q('f_wss_receiver_port').value.trim() : '';
    const autoFilled = autoFillWssIfBlank();
    const wss = readWssFields();
    const qosRead = readQosFields();
    if(!qosRead.ok){
      toast(qosRead.error || 'QoS 参数无效', true);
      return;
    }
    if(!wss.host || !wss.path){
      toast('WSS Host / Path 不能为空', true);
      return;
    }
    if(autoFilled){
      toast('WSS Host/Path/SNI 留空已自动生成');
    }
    let syncId = '';
    if(CURRENT_EDIT_INDEX >= 0){
      const old = CURRENT_POOL.endpoints[CURRENT_EDIT_INDEX];
      const ex = (old && old.extra_config) ? old.extra_config : {};
      if(ex && ex.sync_id) syncId = ex.sync_id;
    }
    if(!syncId) syncId = genLocalSyncId();
    const payload = {
      sender_node_id: window.__NODE_ID__,
      receiver_node_id: parseInt(receiverNodeId,10),
      listen,
      remotes,
      disabled,
      balance: balanceStr,
      protocol,
      remark,
      favorite,
      qos: qosRead.qos,
      receiver_port: receiverPortTxt ? parseInt(receiverPortTxt,10) : null,
      sync_id: syncId,
      wss
    };

    _setSyncPendingSubmit('wss', syncId, true);
    try{
      upsertLocalSyncSenderRule('wss', payload);
      renderRules();
    }catch(_e){}
    closeModal();
    toast('已提交同步任务，规则正在后台同步到接收机');
    enqueueSyncSaveTask('wss', payload, '已保存，并自动同步到接收机')
      .then(()=>{
        _setSyncPendingSubmit('wss', syncId, false);
        renderRules();
      })
      .catch(async (err)=>{
        _setSyncPendingSubmit('wss', syncId, false);
        toast(formatRequestError(err, 'WSS 隧道保存失败'), true);
        let loaded = false;
        try{
          await loadPool();
          loaded = true;
        }catch(_e){}
        if(!loaded){
          try{ removeLocalSyncRuleById('wss', syncId); }catch(_e){}
        }
        renderRules();
      });
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
    const qosRead = readQosFields();
    if(!qosRead.ok){
      toast(qosRead.error || 'QoS 参数无效', true);
      return;
    }
    const aclRead = readIntranetAclFields();
    if(!aclRead.ok){
      toast(aclRead.error || 'ACL 参数无效', true);
      return;
    }
    let syncId = '';
    if(CURRENT_EDIT_INDEX >= 0){
      const old = CURRENT_POOL.endpoints[CURRENT_EDIT_INDEX];
      const ex = (old && old.extra_config) ? old.extra_config : {};
      if(ex && ex.sync_id) syncId = ex.sync_id;
    }
    if(!syncId) syncId = genLocalSyncId();
    const payload = {
      sender_node_id: window.__NODE_ID__,
      receiver_node_id: parseInt(receiverNodeId,10),
      listen,
      remotes,
      disabled,
      balance: balanceStr,
      protocol,
      remark,
      favorite,
      qos: qosRead.qos,
      acl: aclRead.acl,
      server_port,
      server_host: server_host || null,
      sync_id: syncId
    };

    _setSyncPendingSubmit('intranet', syncId, true);
    try{
      upsertLocalSyncSenderRule('intranet', payload);
      renderRules();
    }catch(_e){}
    closeModal();
    toast('已提交同步任务，规则正在后台下发到内网节点');
    enqueueSyncSaveTask('intranet', payload, '已保存，并自动下发到内网节点')
      .then(()=>{
        _setSyncPendingSubmit('intranet', syncId, false);
        renderRules();
      })
      .catch(async (err)=>{
        _setSyncPendingSubmit('intranet', syncId, false);
        toast(formatRequestError(err, '内网穿透保存失败'), true);
        let loaded = false;
        try{
          await loadPool();
          loaded = true;
        }catch(_e){}
        if(!loaded){
          try{ removeLocalSyncRuleById('intranet', syncId); }catch(_e){}
        }
        renderRules();
      });
    return;
  }

  // 普通转发（单机）
  let endpoint = {};
  if(CURRENT_EDIT_INDEX >= 0){
    try{
      const old = (CURRENT_POOL && CURRENT_POOL.endpoints) ? CURRENT_POOL.endpoints[CURRENT_EDIT_INDEX] : null;
      // Only preserve extra fields when editing an existing normal rule.
      if(old && wssMode(old) === 'tcp'){
        endpoint = JSON.parse(JSON.stringify(old));
      }
    }catch(_e){ endpoint = {}; }
  }

  // Required fields
  endpoint.listen = listen;
  endpoint.remotes = remotes;
  endpoint.disabled = disabled;
  endpoint.balance = balanceStr;
  endpoint.protocol = protocol;

  // Clean legacy schema fields (if any)
  try{ delete endpoint.remote; }catch(_e){}
  try{ delete endpoint.extra_remotes; }catch(_e){}
  try{ delete endpoint.balanceStr; }catch(_e){}

  // meta
  if(remark) endpoint.remark = remark; else { try{ delete endpoint.remark; }catch(_e){} }
  if(favorite) endpoint.favorite = true; else { try{ delete endpoint.favorite; }catch(_e){} }

  // Apply common advanced params
  const advApply = applyCommonAdvancedToEndpoint(endpoint);
  if(!advApply.ok){ toast(advApply.error || '高级参数无效', true); return; }

  try{
    setLoading(true);
    const draft = clonePool(CURRENT_POOL);
    if(!Array.isArray(draft.endpoints)) draft.endpoints = [];
    if(CURRENT_EDIT_INDEX >= 0){
      if(CURRENT_EDIT_INDEX >= draft.endpoints.length){
        throw new Error('规则不存在或已删除');
      }
      draft.endpoints[CURRENT_EDIT_INDEX] = endpoint;
    }else{
      draft.endpoints.push(endpoint);
    }

    await savePool('保存任务已提交', draft);
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

function precheckWarningMessages(resp){
  const issues = (resp && resp.precheck && Array.isArray(resp.precheck.issues)) ? resp.precheck.issues : [];
  return issues
    .filter((it)=>String((it && it.severity) || 'warning').toLowerCase() !== 'error')
    .map((it)=>String((it && it.message) || '').trim())
    .filter(Boolean);
}

function toastWithPrecheck(resp, okMsg){
  const lines = precheckWarningMessages(resp);
  if(lines.length <= 0){
    if(okMsg) toast(okMsg);
    return;
  }
  const short = lines.slice(0, 2).join('；');
  const more = lines.length > 2 ? `；等 ${lines.length} 条` : '';
  const head = okMsg || '已保存';
  toast(`${head}（预检提示：${short}${more}）`, false, 5600);
}

function clonePool(pool){
  try{
    const cloned = JSON.parse(JSON.stringify(pool || {}));
    if(!Array.isArray(cloned.endpoints)) cloned.endpoints = [];
    return cloned;
  }catch(_e){
    return { endpoints: [] };
  }
}

function genLocalSyncId(){
  try{
    if(window.crypto && typeof window.crypto.randomUUID === 'function'){
      return String(window.crypto.randomUUID()).replace(/-/g, '');
    }
  }catch(_e){}
  return `${Date.now().toString(16)}${Math.random().toString(16).slice(2, 10)}`;
}

function upsertLocalSyncSenderRule(kind, payload){
  const kk = String(kind || '').trim().toLowerCase();
  const p = (payload && typeof payload === 'object') ? payload : {};
  const syncId = String(p.sync_id || '').trim();
  if(!syncId) return false;

  const listen = String(p.listen || '').trim();
  if(!listen) return false;
  const remotes = Array.isArray(p.remotes)
    ? p.remotes.map((x)=>String(x || '').trim()).filter(Boolean)
    : [];
  const protocol = String(p.protocol || 'tcp+udp').trim() || 'tcp+udp';
  const balance = String(p.balance || 'roundrobin').trim() || 'roundrobin';
  const disabled = !!p.disabled;
  const receiverId = parseInt(p.receiver_node_id || 0, 10) || 0;

  const ep = {
    listen,
    remotes,
    disabled,
    balance,
    protocol,
  };
  const nowIso = new Date().toISOString();
  const ex = { sync_id: syncId };
  if(kk === 'wss'){
    ex.sync_role = 'sender';
    if(receiverId > 0) ex.sync_peer_node_id = receiverId;
    ex.sync_original_remotes = remotes.slice();
    ex.sync_updated_at = nowIso;
    const wss = (p.wss && typeof p.wss === 'object') ? p.wss : {};
    if(wss.host != null) ex.remote_ws_host = String(wss.host || '').trim();
    if(wss.path != null) ex.remote_ws_path = String(wss.path || '').trim();
    if(wss.sni != null) ex.remote_tls_sni = String(wss.sni || '').trim();
    if(wss.tls != null) ex.remote_tls_enabled = !!wss.tls;
    if(wss.insecure != null) ex.remote_tls_insecure = !!wss.insecure;
  }else if(kk === 'intranet'){
    ex.intranet_role = 'server';
    if(receiverId > 0) ex.intranet_peer_node_id = receiverId;
    ex.intranet_server_port = parseInt(p.server_port || 18443, 10) || 18443;
    ex.intranet_original_remotes = remotes.slice();
    ex.intranet_updated_at = nowIso;
    const host = String(p.server_host || '').trim();
    if(host) ex.intranet_public_host = host;
  }else{
    return false;
  }
  ep.extra_config = ex;

  const remark = String(p.remark || '').trim();
  if(remark) ep.remark = remark;
  if(!!p.favorite) ep.favorite = true;

  const draft = clonePool(CURRENT_POOL);
  if(!Array.isArray(draft.endpoints)) draft.endpoints = [];
  let replaced = false;
  for(let i=0; i<draft.endpoints.length; i++){
    const old = draft.endpoints[i];
    if(!(old && typeof old === 'object')) continue;
    const oldEx = (old.extra_config && typeof old.extra_config === 'object') ? old.extra_config : {};
    if(String(oldEx.sync_id || '').trim() !== syncId) continue;
    if(kk === 'wss' && !(oldEx.sync_role || oldEx.sync_peer_node_id || oldEx.sync_lock)) continue;
    if(kk === 'intranet' && !(oldEx.intranet_role || oldEx.intranet_peer_node_id || oldEx.intranet_lock)) continue;
    draft.endpoints[i] = ep;
    replaced = true;
    break;
  }
  if(!replaced){
    draft.endpoints.push(ep);
  }
  CURRENT_POOL = draft;
  return true;
}

function removeLocalSyncRuleById(kind, syncId){
  const kk = String(kind || '').trim().toLowerCase();
  const sid = String(syncId || '').trim();
  if(!sid) return false;
  const draft = clonePool(CURRENT_POOL);
  const eps = Array.isArray(draft.endpoints) ? draft.endpoints : [];
  const next = eps.filter((ep)=>{
    const ex = (ep && ep.extra_config && typeof ep.extra_config === 'object') ? ep.extra_config : {};
    if(String(ex.sync_id || '').trim() !== sid) return true;
    if(kk === 'wss'){
      return !(ex.sync_role || ex.sync_peer_node_id || ex.sync_lock);
    }
    if(kk === 'intranet'){
      return !(ex.intranet_role || ex.intranet_peer_node_id || ex.intranet_lock);
    }
    return true;
  });
  if(next.length === eps.length) return false;
  draft.endpoints = next;
  CURRENT_POOL = draft;
  return true;
}

async function savePool(msg, poolOverride){
  q('modalMsg') && (q('modalMsg').textContent = '');
  const targetPool = clonePool((poolOverride && typeof poolOverride === 'object') ? poolOverride : CURRENT_POOL);
  try{
    const unlockSyncIds = collectUnlockSyncIds();
    await enqueueNodePoolTask('pool_save', { pool: targetPool, unlock_sync_ids: unlockSyncIds }, msg || '保存已生效');
    // Update local baseline for subsequent edits while keeping UI unchanged until task success.
    CURRENT_POOL = clonePool(targetPool);
    toast('已提交保存任务，正在后台同步');
    return true;
  }catch(e){
    const m = (e && e.message) ? e.message : String(e || '提交保存任务失败');
    q('modalMsg') && (q('modalMsg').textContent = m);
    toast(m, true);
    throw e;
  }
}

function toast(text, isError=false, durationMs){
  const msg = String(text || '').trim();
  if(!msg) return;
  const stayMs = Math.max(1200, Number(durationMs) || 1800);

  // Prefer a toast bar if present
  const t = q('toast');
  if(t){
    t.textContent = msg;
    t.style.display = 'block';
    t.classList.toggle('error', !!isError);
    setTimeout(()=>{ t.style.display='none'; }, stayMs);
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

// -------------------- Dangerous: purge all rules on current node --------------------

async function downloadNodeBackup(nodeId){
  const url = `/api/nodes/${nodeId}/backup`;
  const res = await fetch(url, { method: 'GET', credentials: 'same-origin' });
  const blob = await res.blob();
  if(!res.ok){
    let detail = '';
    try{ detail = await blob.text(); }catch(_e){}
    try{ detail = (JSON.parse(detail) || {}).error || detail; }catch(_e){}
    throw new Error(detail || `HTTP ${res.status}`);
  }

  // filename from Content-Disposition (supports UTF-8)
  let filename = `realm-rules-node-${nodeId}.json`;
  try{
    const cd = res.headers.get('Content-Disposition') || '';
    const mUtf8 = /filename\*=UTF-8''([^;]+)/i.exec(cd);
    if(mUtf8 && mUtf8[1]){
      filename = decodeURIComponent(mUtf8[1]);
    }else{
      const m = /filename="?([^";]+)"?/i.exec(cd);
      if(m && m[1]) filename = m[1];
    }
  }catch(_e){}

  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(()=>{ try{ URL.revokeObjectURL(blobUrl); }catch(_e){} }, 2000);
  return true;
}

async function purgeAllRules(){
  const nodeId = window.__NODE_ID__;
  if(!nodeId){ toast('缺少节点ID', true); return; }
  const nodeLabel = getCurrentNodeConfirmLabel();

  // Step 1: confirm
  const ok1 = confirm(
    `⚠️ 危险操作：将清空节点「${nodeLabel}」的所有规则（包含锁定规则）。\n\n` +
    '继续后会先自动下载一份规则备份，然后执行清空。\n\n' +
    '是否进入下一步确认？'
  );
  if(!ok1) return;

  // Step 2: require exact node label input (frontend), then send server required token.
  const typed = prompt(`为防止误操作，请输入节点名称「${nodeLabel}」后继续：`);
  if((typed || '').trim() !== nodeLabel){
    toast('已取消：节点名称不匹配', true);
    return;
  }

  try{
    setLoading(true);
    // Backup first (must succeed)
    try{
      await downloadNodeBackup(nodeId);
      toast('已生成备份并开始下载…');
    }catch(e){
      toast('备份失败：' + (e && e.message ? e.message : String(e)), true);
      return;
    }

    // Then purge (server also validates confirm_text)
    const res = await fetchJSON(`/api/nodes/${nodeId}/purge`, {
      method: 'POST',
      body: JSON.stringify({ confirm_text: '确认删除' })
    });
    if(res && res.ok){
      // Update UI quickly
      try{
        if(CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)){
          CURRENT_POOL.endpoints = [];
        }
      }catch(_e){}
      try{ await loadPool(); }catch(_e){}
      toast('已清空该节点所有规则');
    }else{
      toast((res && res.error) ? res.error : '清空失败', true);
    }
  }catch(err){
    toast('清空失败：' + (err && err.message ? err.message : String(err)), true);
  }finally{
    setLoading(false);
  }
}
window.purgeAllRules = purgeAllRules;

async function resetNodeTraffic(){
  const nodeId = window.__NODE_ID__;
  if(!nodeId){ toast('缺少节点ID', true); return; }

  const ok = confirm(
    '确认重置当前节点的“规则流量统计/连接计数”？\n\n' +
    '说明：\n' +
    '1) 会清空该节点所有规则的流量/连接累计（面板显示从 0 重新开始）；\n' +
    '2) 不会删除/修改任何规则；\n' +
    '3) 历史统计无法恢复。'
  );
  if(!ok) return;

  try{
    toast('正在重置…');
    const res = await fetchJSON(`/api/nodes/${nodeId}/traffic/reset`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    if(res && res.ok){
      try{ clearRuleHistory(true); }catch(_e){}

      if(res.queued){
        toast('已加入队列：等待节点上报后自动重置');
        try{ await refreshStats(false); }catch(_e){}
      }else{
        toast('已重置：正在刷新统计…');
        // Force agent stats to avoid 3s push-report cache showing old values
        await refreshStats(true);
      }
    }else{
      toast((res && res.error) ? res.error : '重置失败', true);
    }
  }catch(err){
    toast('重置失败：' + (err && err.message ? err.message : String(err)), true);
  }
}
window.resetNodeTraffic = resetNodeTraffic;


async function resetAllTraffic(){
  const ok1 = confirm(
    '⚠️ 批量操作：将对所有已接入节点执行“重置规则流量统计”。\n\n' +
    '不可达节点将自动排队，待节点上报后执行（不需要逐台操作）。\n\n' +
    '是否继续？'
  );
  if(!ok1) return;

  try{
    toast('正在对所有节点重置…');
    const res = await fetchJSON('/api/traffic/reset_all', { method:'POST', body: JSON.stringify({}) });
    if(res && res.ok){
      const okN = res.ok_count ?? 0;
      const queuedN = res.queued_count ?? 0;
      const failN = res.fail_count ?? 0;
      const needDetail = (queuedN || failN);
      toast(`已完成：成功 ${okN}，已排队 ${queuedN}，失败 ${failN}` + (needDetail ? '（点击查看详情）' : ''));

      if(needDetail && Array.isArray(res.results)){
        const queued = res.results.filter(r=>r.ok && r.queued);
        const failed = res.results.filter(r=>!r.ok);
        let msg = '';

        if(queued.length){
          const lines = queued.slice(0, 30).map(r=>{
            const name = r.name || ('Node-' + r.node_id);
            const err = r.direct_error || '';
            return err ? `${name}（直连失败已排队）：${err}` : `${name}（已排队）`;
          });
          const more = queued.length > 30 ? `\n… 还有 ${queued.length - 30} 个已排队节点未展示` : '';
          msg += '以下节点已排队（等待节点上报后自动执行）：\n\n' + lines.join('\n') + more;
        }

        if(failed.length){
          const lines = failed.slice(0, 30).map(r=>{
            const name = r.name || ('Node-' + r.node_id);
            const err = r.error || 'failed';
            return `${name}: ${err}`;
          });
          const more = failed.length > 30 ? `\n… 还有 ${failed.length - 30} 个失败节点未展示` : '';
          msg += (msg ? '\n\n' : '') + '以下节点重置失败（直连失败且排队也失败）：\n\n' + lines.join('\n') + more;
        }

        if(msg){
          alert(msg);
        }
      }
    }else{
      toast((res && res.error) ? res.error : '重置失败', true);
    }
  }catch(err){
    toast('重置失败：' + (err && err.message ? err.message : String(err)), true);
  }
}
window.resetAllTraffic = resetAllTraffic;


// -------------------- Node: Traffic / connections history curves --------------------
// Design:
// - Panel stores persistent history in SQLite (survives browser close).
// - Frontend keeps an in-memory cache and updates it on every stats refresh.
// - Supports "all rules (sum)" and per-rule (by listen) selection.
// - Plots traffic rate (B/s) and active connections over a sliding time window.

const RULE_HIST_STATE = {
  inited: false,
  nodeId: null,
  // max retention in memory (ms). Keep bounded to avoid memory growth on nodes with many rules.
  maxRetentionMs: 60 * 60 * 1000, // 60 min
  windowMs: 10 * 60 * 1000, // default 10 min
  selectedKey: '__all__',
  lastGlobalTs: 0,
  series: new Map(), // key -> HistSeries
  // Persistent history (stored on panel DB)
  persistLoaded: new Set(), // keys already loaded from server
  persistLoading: new Set(), // keys currently in-flight
  trafficChart: null,
  connChart: null,
};

class HistSeries {
  constructor(){
    this.t = [];
    this.rx = [];
    this.tx = [];
    this.conn = [];
    this.start = 0; // index of first valid sample
    this.lastTs = 0;
  }

  push(ts, rx, tx, conn, pruneBefore){
    const t = Number(ts) || 0;
    if(!t) return;
    if(this.lastTs && t <= this.lastTs){
      // Ignore non-monotonic samples (can happen when system clock adjusts or duplicate pushes).
      return;
    }

    this.t.push(t);
    this.rx.push(Number(rx) || 0);
    this.tx.push(Number(tx) || 0);
    this.conn.push(Number(conn) || 0);
    this.lastTs = t;

    if(typeof pruneBefore === 'number' && pruneBefore > 0){
      while(this.start < this.t.length && this.t[this.start] < pruneBefore){
        this.start += 1;
      }

      // Compact arrays periodically to avoid unbounded growth due to start index.
      if(this.start > 200 && this.start > (this.t.length >> 1)){
        this.t = this.t.slice(this.start);
        this.rx = this.rx.slice(this.start);
        this.tx = this.tx.slice(this.start);
        this.conn = this.conn.slice(this.start);
        this.start = 0;
      }
    }
  }

  // Index of the first sample with ts >= cutoff (binary search)
  lowerBound(cutoff){
    const tArr = this.t;
    let lo = this.start;
    let hi = tArr.length;
    while(lo < hi){
      const mid = (lo + hi) >> 1;
      if(tArr[mid] < cutoff) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  size(){
    return Math.max(0, this.t.length - this.start);
  }
}

function _histCssVar(name, fallback){
  try{
    const v = getComputedStyle(document.documentElement).getPropertyValue(name);
    const s = (v || '').trim();
    return s || fallback;
  }catch(_e){
    return fallback;
  }
}

function _histFmtTimeHHMMSS(ts){
  try{
    const d = new Date(Number(ts) || 0);
    const hh = String(d.getHours()).padStart(2,'0');
    const mm = String(d.getMinutes()).padStart(2,'0');
    const ss = String(d.getSeconds()).padStart(2,'0');
    return `${hh}:${mm}:${ss}`;
  }catch(_e){
    return '';
  }
}

function _histNearestIndex(tArr, target){
  // Binary search for nearest timestamp in sorted tArr.
  const n = tArr.length;
  if(!n) return -1;
  let lo = 0, hi = n - 1;
  while(lo < hi){
    const mid = (lo + hi) >> 1;
    if(tArr[mid] < target) lo = mid + 1;
    else hi = mid;
  }
  // lo is first >= target
  if(lo <= 0) return 0;
  if(lo >= n) return n - 1;
  const a = tArr[lo - 1];
  const b = tArr[lo];
  return (Math.abs(a - target) <= Math.abs(b - target)) ? (lo - 1) : lo;
}

class MiniLineChart {
  constructor(canvas, tooltipEl){
    this.canvas = canvas;
    this.tooltipEl = tooltipEl;
    this.ctx = canvas ? canvas.getContext('2d') : null;
    this.data = null;
    this._cache = null;

    this._onMove = (e)=>{ this._handleMove(e); };
    this._onLeave = ()=>{ this._hideTip(); };
    this._onResize = ()=>{ this.render(); };

    try{
      if(this.canvas){
        this.canvas.addEventListener('mousemove', this._onMove);
        this.canvas.addEventListener('mouseleave', this._onLeave);
        this.canvas.addEventListener('touchstart', this._onMove, {passive:true});
        this.canvas.addEventListener('touchmove', this._onMove, {passive:true});
        this.canvas.addEventListener('touchend', this._onLeave, {passive:true});
      }
      window.addEventListener('resize', this._onResize);
    }catch(_e){}
  }

  setData(data){
    this.data = data;
    this.render();
  }

  _resize(){
    if(!this.canvas) return;
    const rect = this.canvas.getBoundingClientRect();
    const cssW = Math.max(10, Math.floor(rect.width));
    const cssH = Math.max(10, Math.floor(rect.height));
    const dpr = Math.max(1, Math.floor((window.devicePixelRatio || 1) * 100) / 100);
    const w = Math.floor(cssW * dpr);
    const h = Math.floor(cssH * dpr);
    if(this.canvas.width !== w || this.canvas.height !== h){
      this.canvas.width = w;
      this.canvas.height = h;
    }
    this._dpr = dpr;
    this._cssW = cssW;
    this._cssH = cssH;
  }

  render(){
    if(!this.canvas || !this.ctx) return;
    this._resize();

    const ctx = this.ctx;
    const dpr = this._dpr || 1;
    const W = this._cssW || 10;
    const H = this._cssH || 10;

    // Draw in CSS pixels (scale once).
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    const data = this.data;
    if(!data || !Array.isArray(data.t) || data.t.length < 2){
      // Placeholder
      ctx.fillStyle = _histCssVar('--muted', '#9CA3AF');
      ctx.font = '12px ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial';
      ctx.fillText('暂无数据', 12, 18);
      this._cache = null;
      return;
    }

    const padL = 52;
    const padR = 12;
    const padT = 10;
    const padB = 22;
    const x0 = padL;
    const y0 = padT;
    const pw = Math.max(10, W - padL - padR);
    const ph = Math.max(10, H - padT - padB);

    const tMin = Number(data.xMin != null ? data.xMin : data.t[0]) || data.t[0];
    const tMax = Number(data.xMax != null ? data.xMax : data.t[data.t.length - 1]) || data.t[data.t.length - 1];
    const tSpan = Math.max(1, tMax - tMin);

    // y range
    let yMax = 0;
    const series = Array.isArray(data.series) ? data.series : [];
    for(const s of series){
      const arr = Array.isArray(s.v) ? s.v : [];
      for(const v of arr){
        const num = Number(v);
        if(Number.isFinite(num) && num > yMax) yMax = num;
      }
    }
    if(!Number.isFinite(yMax) || yMax <= 0) yMax = 1;
    yMax *= 1.15; // headroom

    const yToPx = (v)=> y0 + ph - (Math.max(0, Number(v) || 0) / yMax) * ph;
    const xToPx = (t)=> x0 + ((Number(t) - tMin) / tSpan) * pw;

    // grid
    const grid = _histCssVar('--line', 'rgba(255,255,255,0.10)');
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    ctx.beginPath();
    const hN = 4;
    for(let i=0;i<=hN;i++){
      const y = y0 + (ph * i / hN);
      ctx.moveTo(x0, y);
      ctx.lineTo(x0 + pw, y);
    }
    const vN = 5;
    for(let i=0;i<=vN;i++){
      const x = x0 + (pw * i / vN);
      ctx.moveTo(x, y0);
      ctx.lineTo(x, y0 + ph);
    }
    ctx.stroke();

    // labels
    const muted = _histCssVar('--muted', '#9CA3AF');
    ctx.fillStyle = muted;
    ctx.font = '11px ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial';

    const fmtY = (typeof data.fmtY === 'function') ? data.fmtY : (v)=>String(v);
    const yMaxLabel = fmtY(yMax / 1.15); // label without headroom
    ctx.fillText(yMaxLabel, 8, y0 + 10);
    ctx.fillText('0', 8, y0 + ph);

    const leftT = _histFmtTimeHHMMSS(tMin);
    const rightT = _histFmtTimeHHMMSS(tMax);
    ctx.fillText(leftT, x0, y0 + ph + 16);
    const wRight = ctx.measureText(rightT).width;
    ctx.fillText(rightT, x0 + pw - wRight, y0 + ph + 16);

    // lines
    for(const s of series){
      const arrT = data.t;
      const arrV = Array.isArray(s.v) ? s.v : [];
      if(arrV.length !== arrT.length || arrT.length < 2) continue;

      ctx.beginPath();
      let started = false;
      for(let i=0;i<arrT.length;i++){
        const tt = arrT[i];
        const vv = Number(arrV[i]);
        if(!Number.isFinite(vv)) continue;
        const x = xToPx(tt);
        const y = yToPx(vv);
        if(!started){
          ctx.moveTo(x, y);
          started = true;
        }else{
          ctx.lineTo(x, y);
        }
      }
      if(!started) continue;
      ctx.strokeStyle = s.color || _histCssVar('--accent', '#3B82F6');
      ctx.lineWidth = 1.8;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.stroke();
    }

    // Keep cache for tooltip
    this._cache = {
      tMin, tMax, x0, y0, pw, ph,
      t: data.t,
      series,
      fmtY,
    };
  }

  _hideTip(){
    try{
      if(this.tooltipEl) this.tooltipEl.style.display = 'none';
    }catch(_e){}
  }

  _handleMove(evt){
    if(!this.canvas || !this.tooltipEl || !this.data) return;
    if(!this._cache || !Array.isArray(this._cache.t) || this._cache.t.length < 2) return;

    let clientX = 0, clientY = 0;
    if(evt && evt.touches && evt.touches.length){
      clientX = evt.touches[0].clientX;
      clientY = evt.touches[0].clientY;
    }else{
      clientX = evt.clientX;
      clientY = evt.clientY;
    }

    const rect = this.canvas.getBoundingClientRect();
    const xCss = clientX - rect.left;

    const c = this._cache;
    const x0 = c.x0, pw = c.pw;
    const tMin = c.tMin, tMax = c.tMax;
    const x = Math.min(Math.max(xCss, x0), x0 + pw);
    const t = tMin + ((x - x0) / pw) * (tMax - tMin);

    const idx = _histNearestIndex(c.t, t);
    if(idx < 0) return;

    // Tooltip HTML
    const tt = c.t[idx];
    let html = `<div class="t">${escapeHtml(_histFmtTimeHHMMSS(tt))}</div>`;
    for(const s of (c.series || [])){
      const vv = (Array.isArray(s.v) && s.v.length > idx) ? s.v[idx] : null;
      const name = s.name || '';
      const val = (typeof c.fmtY === 'function') ? c.fmtY(vv) : String(vv);
      html += `<div class="k"><span class="name">${escapeHtml(name)}</span><span class="val">${escapeHtml(val)}</span></div>`;
    }

    try{
      this.tooltipEl.innerHTML = html;
      this.tooltipEl.style.display = '';

      // position relative to chart wrapper
      const wrap = this.tooltipEl.parentElement;
      if(wrap){
        const wrect = wrap.getBoundingClientRect();
        let left = clientX - wrect.left + 12;
        let top = clientY - wrect.top + 12;

        // clamp
        const tipRect = this.tooltipEl.getBoundingClientRect();
        const maxLeft = Math.max(8, wrect.width - tipRect.width - 8);
        const maxTop = Math.max(8, wrect.height - tipRect.height - 8);
        left = Math.min(Math.max(8, left), maxLeft);
        top = Math.min(Math.max(8, top), maxTop);
        this.tooltipEl.style.left = `${left}px`;
        this.tooltipEl.style.top = `${top}px`;
      }
    }catch(_e){}
  }
}

function _histEnsureInited(){
  const panel = document.getElementById('histPanel');
  if(!panel) return false;
  if(RULE_HIST_STATE.inited) return true;

  RULE_HIST_STATE.inited = true;
  RULE_HIST_STATE.nodeId = String(window.__NODE_ID__ || '');

  const ruleSel = document.getElementById('histRuleSelect');
  const winSel = document.getElementById('histWindowSelect');

  if(winSel){
    try{
      const val = parseInt(String(winSel.value || ''), 10);
      if(val > 0) RULE_HIST_STATE.windowMs = val;

      // Max retention = max window option
      let maxV = RULE_HIST_STATE.maxRetentionMs;
      const opts = Array.from(winSel.options || []);
      for(const o of opts){
        const n = parseInt(String(o.value || '0'), 10);
        if(n > maxV) maxV = n;
      }
      RULE_HIST_STATE.maxRetentionMs = maxV;
    }catch(_e){}

    winSel.addEventListener('change', ()=>{
      const n = parseInt(String(winSel.value || '0'), 10);
      if(n > 0){
        RULE_HIST_STATE.windowMs = n;
        try{ histRender(); }catch(_e){}
      }
    });
  }

  if(ruleSel){
    ruleSel.addEventListener('change', ()=>{
      RULE_HIST_STATE.selectedKey = String(ruleSel.value || '__all__') || '__all__';
      // When user switches rule, load persisted history for that series (best-effort).
      try{ histLoadPersisted(RULE_HIST_STATE.selectedKey, true); }catch(_e){}
      try{ histRender(); }catch(_e){}
    });
  }

  const trafficCanvas = document.getElementById('histTrafficCanvas');
  const connCanvas = document.getElementById('histConnCanvas');
  const trafficTip = document.getElementById('histTrafficTip');
  const connTip = document.getElementById('histConnTip');

  if(trafficCanvas){
    RULE_HIST_STATE.trafficChart = new MiniLineChart(trafficCanvas, trafficTip);
  }
  if(connCanvas){
    RULE_HIST_STATE.connChart = new MiniLineChart(connCanvas, connTip);
  }

  // Keep the select options in sync with pool/rules.
  try{ histSyncRuleSelect(); }catch(_e){}

  // Prefill persisted history on first render (do not block UI).
  try{
    const k0 = String(RULE_HIST_STATE.selectedKey || '__all__') || '__all__';
    setTimeout(()=>{ try{ histLoadPersisted(k0, true); }catch(_e){} }, 30);
  }catch(_e){}

  return true;
}

function histSyncRuleSelect(){
  if(!_histEnsureInited()) return;
  const selEl = document.getElementById('histRuleSelect');
  if(!selEl) return;

  const keep = String(RULE_HIST_STATE.selectedKey || '__all__');
  const eps = (CURRENT_POOL && Array.isArray(CURRENT_POOL.endpoints)) ? CURRENT_POOL.endpoints : [];

  const options = [];
  options.push({ value: '__all__', label: '全部规则（汇总）' });

  const seen = new Set(['__all__']);
  for(let i=0;i<eps.length;i++){
    const e = eps[i];
    if(!e) continue;
    const lis = (e.listen != null) ? String(e.listen).trim() : '';
    if(!lis) continue;
    if(seen.has(lis)) continue;
    seen.add(lis);

    let label = `${i+1}. ${lis}`;
    const remark = getRuleRemark(e);
    if(remark) label += ` · ${remark}`;
    if(e.disabled) label += '（暂停）';
    options.push({ value: lis, label });
  }

  // Update DOM only if changed (avoid losing focus)
  let changed = false;
  if(selEl.options.length !== options.length){
    changed = true;
  }else{
    for(let i=0;i<options.length;i++){
      const o = selEl.options[i];
      const want = options[i];
      if(!o || o.value !== want.value || (o.textContent || '') !== want.label){
        changed = true;
        break;
      }
    }
  }

  if(changed){
    selEl.innerHTML = '';
    for(const it of options){
      const o = document.createElement('option');
      o.value = it.value;
      o.textContent = it.label;
      selEl.appendChild(o);
    }
  }

  const hasKeep = options.some(o=>o.value === keep);
  RULE_HIST_STATE.selectedKey = hasKeep ? keep : '__all__';
  selEl.value = RULE_HIST_STATE.selectedKey;
}


// -------------------- Persistent history (panel-side DB) --------------------

function _histMergePersistedSeries(key, tArr, rxArr, txArr, connArr){
  if(!_histEnsureInited()) return false;

  const k = String(key || '__all__') || '__all__';
  if(!Array.isArray(tArr) || !Array.isArray(rxArr) || !Array.isArray(txArr) || !Array.isArray(connArr)){
    return false;
  }

  const n = Math.min(tArr.length, rxArr.length, txArr.length, connArr.length);
  if(n <= 0) return false;

  const sNew = new HistSeries();
  // Build from persisted arrays
  for(let i=0;i<n;i++){
    const ts = Number(tArr[i]) || 0;
    if(!ts) continue;
    sNew.push(ts, Number(rxArr[i]) || 0, Number(txArr[i]) || 0, Number(connArr[i]) || 0, null);
  }

  // Merge any newer in-memory points (if we already started collecting in this session)
  const old = RULE_HIST_STATE.series.get(k);
  if(old && old.size && old.size() > 0){
    try{
      for(let i=old.start; i<old.t.length; i++){
        const ts = old.t[i];
        if(!ts) continue;
        if(sNew.lastTs && ts <= sNew.lastTs) continue;
        sNew.push(ts, old.rx[i], old.tx[i], old.conn[i], null);
      }
    }catch(_e){}
  }

  // Apply in-memory retention window
  try{
    const lastTs = sNew.lastTs || Date.now();
    const pruneBefore = lastTs - (Number(RULE_HIST_STATE.maxRetentionMs) || (60 * 60 * 1000));
    if(pruneBefore > 0){
      while(sNew.start < sNew.t.length && sNew.t[sNew.start] < pruneBefore){
        sNew.start += 1;
      }
      if(sNew.start > 200 && sNew.start > (sNew.t.length >> 1)){
        sNew.t = sNew.t.slice(sNew.start);
        sNew.rx = sNew.rx.slice(sNew.start);
        sNew.tx = sNew.tx.slice(sNew.start);
        sNew.conn = sNew.conn.slice(sNew.start);
        sNew.start = 0;
      }
    }
  }catch(_e){}

  RULE_HIST_STATE.series.set(k, sNew);
  return true;
}


async function histLoadPersisted(key='__all__', quiet=true){
  if(!_histEnsureInited()) return false;
  const nodeId = RULE_HIST_STATE.nodeId || String(window.__NODE_ID__ || '');
  if(!nodeId) return false;

  const k = String(key || '__all__') || '__all__';
  if(RULE_HIST_STATE.persistLoaded && RULE_HIST_STATE.persistLoaded.has(k)){
    return false;
  }
  if(RULE_HIST_STATE.persistLoading && RULE_HIST_STATE.persistLoading.has(k)){
    return false;
  }
  try{ RULE_HIST_STATE.persistLoading.add(k); }catch(_e){}

  // Load at least maxRetentionMs so user can switch windows without reloading.
  const wantWin = Math.max(
    Number(RULE_HIST_STATE.maxRetentionMs) || (60 * 60 * 1000),
    Number(RULE_HIST_STATE.windowMs) || (10 * 60 * 1000),
  );

  const url = `/api/nodes/${encodeURIComponent(nodeId)}/stats_history?key=${encodeURIComponent(k)}&window_ms=${encodeURIComponent(String(wantWin))}`;
  try{
    const res = await fetchJSON(url);
    if(res && res.ok){
      const okMerge = _histMergePersistedSeries(k, res.t || [], res.rx || [], res.tx || [], res.conn || []);
      if(okMerge){
        try{ RULE_HIST_STATE.persistLoaded.add(k); }catch(_e){}
        // Align lastGlobalTs to avoid immediate duplicate insertion
        try{
          const s = RULE_HIST_STATE.series.get(k);
          if(s && s.lastTs && (!RULE_HIST_STATE.lastGlobalTs || s.lastTs > RULE_HIST_STATE.lastGlobalTs)){
            RULE_HIST_STATE.lastGlobalTs = s.lastTs;
          }
        }catch(_e){}
        try{ histRender(); }catch(_e){}
      }
      // Mark loaded even if empty to avoid spamming the API.
      try{ RULE_HIST_STATE.persistLoaded.add(k); }catch(_e){}
      return true;
    }
    if(!quiet){
      toast((res && res.error) ? res.error : '加载历史失败', true);
    }
  }catch(err){
    if(!quiet){
      toast('加载历史失败：' + (err && err.message ? err.message : String(err)), true);
    }
  }finally{
    try{ RULE_HIST_STATE.persistLoading.delete(k); }catch(_e){}
  }
  return false;
}


function histIngestStats(statsData){
  if(!_histEnsureInited()) return;
  if(!statsData){
    try{ histRender(); }catch(_e){}
    return;
  }
  if(statsData.ok === false){
    // Keep existing history, just refresh UI hint/messages.
    try{ histRender(); }catch(_e){}
    return;
  }

  // Use panel-side timestamp when available (aligns with persistent DB history).
  let now = Date.now();
  try{
    const serverTs = (statsData && statsData.ts_ms != null) ? Number(statsData.ts_ms) : 0;
    if(Number.isFinite(serverTs) && serverTs > 0) now = serverTs;
  }catch(_e){}
  // Guard: avoid double-insert within a very short time window.
  if(RULE_HIST_STATE.lastGlobalTs && (now - RULE_HIST_STATE.lastGlobalTs) < 800){
    return;
  }
  RULE_HIST_STATE.lastGlobalTs = now;

  const rules = Array.isArray(statsData.rules) ? statsData.rules : [];
  const pruneBefore = now - RULE_HIST_STATE.maxRetentionMs;

  // Aggregate
  let sumRx = 0;
  let sumTx = 0;
  let sumConn = 0;

  for(const r of rules){
    if(!r) continue;
    sumRx += (Number(r.rx_bytes) || 0);
    sumTx += (Number(r.tx_bytes) || 0);
    sumConn += (Number(r.connections_active ?? 0) || 0);
  }

  let sAll = RULE_HIST_STATE.series.get('__all__');
  if(!sAll){
    sAll = new HistSeries();
    RULE_HIST_STATE.series.set('__all__', sAll);
  }
  sAll.push(now, sumRx, sumTx, sumConn, pruneBefore);

  // Per-rule
  for(const r of rules){
    if(!r) continue;
    const key = (r.listen != null) ? String(r.listen).trim() : '';
    if(!key) continue;

    let s = RULE_HIST_STATE.series.get(key);
    if(!s){
      s = new HistSeries();
      RULE_HIST_STATE.series.set(key, s);
    }
    s.push(
      now,
      Number(r.rx_bytes) || 0,
      Number(r.tx_bytes) || 0,
      Number(r.connections_active ?? 0) || 0,
      pruneBefore,
    );
  }

  // Keep selection valid
  const sel = String(RULE_HIST_STATE.selectedKey || '__all__');
  if(sel !== '__all__' && !RULE_HIST_STATE.series.has(sel)){
    RULE_HIST_STATE.selectedKey = '__all__';
    const selEl = document.getElementById('histRuleSelect');
    if(selEl) selEl.value = '__all__';
  }

  // If the panel is open, re-render the charts
  try{ histRender(); }catch(_e){}
}

function _histSetKpis(rxBps, txBps, conn){
  const kpis = document.getElementById('histKpis');
  if(!kpis) return;
  const rxTxt = (rxBps == null) ? '—' : formatBps(rxBps);
  const txTxt = (txBps == null) ? '—' : formatBps(txBps);
  const connTxt = (conn == null) ? '—' : String(Math.max(0, Math.round(Number(conn) || 0)));

  kpis.innerHTML = `
    <span class="pill xs ghost">↓ ${escapeHtml(rxTxt)}</span>
    <span class="pill xs ghost">↑ ${escapeHtml(txTxt)}</span>
    <span class="pill xs ghost">活跃 ${escapeHtml(connTxt)}</span>
  `;
}

function histRender(){
  if(!_histEnsureInited()) return;

  const panel = document.getElementById('histPanel');
  const isOpen = !(panel && panel.open === false);

  const noDataEl = document.getElementById('histNoData');

  const key = String(RULE_HIST_STATE.selectedKey || '__all__');
  const s = RULE_HIST_STATE.series.get(key);

  // Hint in header (auto-refresh state)
  try{
    const hint = document.getElementById('histHeadHint');
    if(hint){
      const ar = !!AUTO_REFRESH_TIMER;
      const t = (s && s.lastTs ? _histFmtTimeHHMMSS(s.lastTs) : '—');
      hint.textContent = ar ? `自动刷新：开 · 更新于 ${t}` : `自动刷新：关 · 最近更新 ${t}`;
    }
  }catch(_e){}

  if(!isOpen){
    // Panel collapsed: skip canvas redraw.
    return;
  }
  if(!s || s.size() < 2){
    if(noDataEl) noDataEl.style.display = '';
    _histSetKpis(null, null, null);
    try{ RULE_HIST_STATE.trafficChart && RULE_HIST_STATE.trafficChart.setData(null); }catch(_e){}
    try{ RULE_HIST_STATE.connChart && RULE_HIST_STATE.connChart.setData(null); }catch(_e){}
    return;
  }

  if(noDataEl) noDataEl.style.display = 'none';

  const wallNow = Date.now();
  const lastTs = Number((s && s.lastTs) || 0);
  // Keep a small right-side breathing room, but avoid a huge blank area when
  // report timestamp lags behind browser time (clock skew / push delay).
  const maxRightGapMs = 12 * 1000;
  let now = wallNow;
  if(lastTs > 0){
    if(wallNow > lastTs + maxRightGapMs){
      now = lastTs + maxRightGapMs;
    }else if(wallNow < lastTs){
      now = lastTs;
    }
  }
  const windowMs = Math.max(60 * 1000, Number(RULE_HIST_STATE.windowMs) || (10 * 60 * 1000));
  const cutoff = now - windowMs;

  const tArr = s.t;
  const rxArr = s.rx;
  const txArr = s.tx;
  const connArr = s.conn;
  const end = tArr.length;

  // Connections series (raw)
  const i0 = s.lowerBound(cutoff);
  const tConn = [];
  const vConn = [];
  for(let i=i0; i<end; i++){
    tConn.push(tArr[i]);
    vConn.push(connArr[i]);
  }

  // Traffic rate series (delta/second) needs previous point
  let iRate = Math.max(i0, s.start + 1);
  const tRate = [];
  const vRx = [];
  const vTx = [];
  for(let i=iRate; i<end; i++){
    const prev = i - 1;
    const dt = (tArr[i] - tArr[prev]) / 1000.0;
    if(!Number.isFinite(dt) || dt <= 0) continue;

    let drx = (Number(rxArr[i]) || 0) - (Number(rxArr[prev]) || 0);
    let dtx = (Number(txArr[i]) || 0) - (Number(txArr[prev]) || 0);
    if(drx < 0) drx = 0; // counter reset
    if(dtx < 0) dtx = 0;

    tRate.push(tArr[i]);
    vRx.push(drx / dt);
    vTx.push(dtx / dt);
  }

  // Update KPIs using the latest point
  const lastRx = vRx.length ? vRx[vRx.length - 1] : null;
  const lastTx = vTx.length ? vTx[vTx.length - 1] : null;
  const lastConn = vConn.length ? vConn[vConn.length - 1] : null;
  _histSetKpis(lastRx, lastTx, lastConn);

  const cDl = _histCssVar('--accent2', '#22D3EE');
  const cUl = _histCssVar('--accent', '#3B82F6');
  const cConn = _histCssVar('--ok', '#22C55E');

  // Render charts
  const trafficData = {
    t: tRate,
    xMin: cutoff,
    xMax: now,
    fmtY: (v)=>formatBps(v),
    series: [
      { name: '下载', color: cDl, v: vRx },
      { name: '上传', color: cUl, v: vTx },
    ],
  };

  const connData = {
    t: tConn,
    xMin: cutoff,
    xMax: now,
    fmtY: (v)=>{
      const n = Number(v) || 0;
      return String(Math.max(0, Math.round(n)));
    },
    series: [
      { name: '活跃', color: cConn, v: vConn },
    ],
  };

  try{ RULE_HIST_STATE.trafficChart && RULE_HIST_STATE.trafficChart.setData(trafficData); }catch(_e){}
  try{ RULE_HIST_STATE.connChart && RULE_HIST_STATE.connChart.setData(connData); }catch(_e){}
}

async function clearRuleHistory(silent=false){
  if(!_histEnsureInited()) return;

  const nodeId = RULE_HIST_STATE.nodeId || String(window.__NODE_ID__ || '');
  if(!nodeId){
    if(!silent) toast('缺少节点ID', true);
    return;
  }

  const doLocalClear = ()=>{
    try{
      RULE_HIST_STATE.series = new Map();
      RULE_HIST_STATE.lastGlobalTs = 0;
      // Reset persistent load markers so future loads are allowed.
      RULE_HIST_STATE.persistLoaded = new Set();
      RULE_HIST_STATE.persistLoading = new Set();
    }catch(_e){}

    try{ _histSetKpis(null, null, null); }catch(_e){}
    try{ RULE_HIST_STATE.trafficChart && RULE_HIST_STATE.trafficChart.setData(null); }catch(_e){}
    try{ RULE_HIST_STATE.connChart && RULE_HIST_STATE.connChart.setData(null); }catch(_e){}

    const noDataEl = document.getElementById('histNoData');
    if(noDataEl) noDataEl.style.display = '';
  };

  if(!silent){
    const ok = confirm(
      '确定清空该节点的“历史曲线”吗？\n\n' +
      '这会删除面板已持久化存储的历史记录，无法恢复。'
    );
    if(!ok) return;
  }

  // Silent mode is used by traffic reset to avoid confusing charts; clear local immediately.
  if(silent){
    try{ doLocalClear(); }catch(_e){}
  }

  try{
    const res = await fetchJSON(`/api/nodes/${encodeURIComponent(nodeId)}/stats_history/clear`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    if(res && res.ok){
      if(!silent){
        doLocalClear();
        toast('已清空历史记录');
      }
    }else{
      if(!silent) toast((res && res.error) ? res.error : '清空失败', true);
    }
  }catch(err){
    if(!silent) toast('清空失败：' + (err && err.message ? err.message : String(err)), true);
  }
}
window.clearRuleHistory = clearRuleHistory;




async function refreshStats(forceAgent=false){
  const id = window.__NODE_ID__;
  const loading = q('statsLoading');
  if(loading){
    loading.style.display = '';
    loading.textContent = '正在加载流量统计…';
  }
  try{
    const statsUrl = `/api/nodes/${id}/stats` + (forceAgent ? `?force=1` : ``);
    const statsData = await fetchJSON(statsUrl);
    CURRENT_STATS = statsData;
    try{ histIngestStats(CURRENT_STATS); }catch(_e){}
  }catch(e){
    CURRENT_STATS = { ok: false, error: e.message, rules: [] };
    try{ histIngestStats(CURRENT_STATS); }catch(_e){}
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
    try{ histIngestStats(CURRENT_STATS); }catch(_e){}
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
  try{
    const selMode = q('f_type');
    if(selMode){
      Array.from(selMode.options || []).forEach((opt)=>{
        const mv = String((opt && opt.value) || '').trim();
        if(!mv) return;
        opt.disabled = !isModeAllowed(mv);
      });
      if(!isModeAllowed(String(selMode.value || '').trim())){
        selMode.value = defaultTunnelMode();
      }
    }
  }catch(_e){}

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

  // Tunnel mode switcher cards (new UI)
  document.querySelectorAll('#modeSwitch .mode-card').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const mode = btn.getAttribute('data-mode');
      setTunnelMode(mode);
    });
  });

  // Update mode preview as you type/select
  ['f_listen_port','f_listen_host','f_remotes','f_wss_receiver_node','f_wss_receiver_port','f_intranet_receiver_node','f_intranet_server_port','f_intranet_server_host'].forEach((id)=>{
    const el = document.getElementById(id);
    if(!el) return;
    const fn = ()=>{ try{ updateModePreview(); }catch(_e){} };
    el.addEventListener('input', fn);
    el.addEventListener('change', fn);
  });

  // Initial render for mode guide/hints
  try{ syncTunnelModeUI(); }catch(_e){}

  // ✅ Load nodes list for WSS auto-sync receiver selector
  // (otherwise the receiver dropdown stays empty and cannot be selected)
  loadNodesList();

  // Sidebar node groups: collapsible
  try{
    const LS = 'nexus_nodes_collapsed_groups';
    let collapsed = new Set();
    try{
      const arr = JSON.parse(localStorage.getItem(LS) || '[]');
      if(Array.isArray(arr)) collapsed = new Set(arr.map(v=>String(v||'').trim()).filter(Boolean));
    }catch(_e){ collapsed = new Set(); }

    const applyCollapsed = () => {
      document.querySelectorAll('.node-group').forEach((g)=>{
        const btn = g.querySelector('.node-group-toggle');
        const name = (btn?.getAttribute('data-group-toggle') || '').trim();
        if(!name) return;
        const isCol = collapsed.has(name);
        g.classList.toggle('collapsed', isCol);
        if(btn){
          btn.setAttribute('aria-expanded', isCol ? 'false' : 'true');
          btn.textContent = isCol ? '▸' : '▾';
        }
      });
    };

    applyCollapsed();

    document.querySelectorAll('.node-group-toggle').forEach((btn)=>{
      btn.addEventListener('click', (e)=>{
        e.preventDefault();
        e.stopPropagation();
        const name = (btn.getAttribute('data-group-toggle') || '').trim();
        if(!name) return;
        if(collapsed.has(name)) collapsed.delete(name);
        else collapsed.add(name);
        try{ localStorage.setItem(LS, JSON.stringify(Array.from(collapsed))); }catch(_e){}
        applyCollapsed();
      }, true);
    });
  }catch(_e){}
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

// Dashboard: quick edit from node card (no page jump)
function openEditNodeModalFromCard(btn){
  try{
    const card = btn && btn.closest ? btn.closest('.node-card') : null;
    if(!card) return;
    const ds = card.dataset || {};
    const nodeObj = {
      id: ds.nodeId || card.getAttribute('data-node-id'),
      name: ds.nodeName || '',
      base_url: ds.nodeBaseUrl || '',
      group_name: ds.nodeGroup || '',
      verify_tls: String(ds.nodeVerifyTls || '0') === '1',
      is_private: String(ds.nodeIsPrivate || '0') === '1',
      role: ds.nodeRole || 'normal',
      website_root_base: ds.nodeWebsiteRoot || ''
    };
    openEditNodeModal(nodeObj);
  }catch(_e){}
}
window.openEditNodeModalFromCard = openEditNodeModalFromCard;

// ---------------- Node: Edit Node Modal ----------------
function openEditNodeModal(nodeObj){
  const m = document.getElementById('editNodeModal');
  if(!m) return;
  // fill current values
  const hasObj = !!(nodeObj && typeof nodeObj === 'object' && (nodeObj.id !== undefined && nodeObj.id !== null));
  const name = hasObj ? (nodeObj.name || '') : (window.__NODE_NAME__ || '');
  const group = (hasObj ? (nodeObj.group_name || nodeObj.group || '') : (window.__NODE_GROUP__ || '')) || '默认分组';
  const base = hasObj ? (nodeObj.base_url || nodeObj.base || '') : (window.__NODE_BASE_URL__ || '');
  const vt = hasObj ? !!nodeObj.verify_tls : !!window.__NODE_VERIFY_TLS__;
  const ipri = hasObj ? !!nodeObj.is_private : !!window.__NODE_IS_PRIVATE__;
  const role = hasObj ? (nodeObj.role || '') : (window.__NODE_ROLE__ || '');
  const websiteRoot = hasObj ? (nodeObj.website_root_base || nodeObj.website_root || '') : (window.__NODE_WEBSITE_ROOT__ || '');

  // Track current editing target (dashboard / node page share the same modal)
  const editId = hasObj ? nodeObj.id : window.__NODE_ID__;
  window.__EDITING_NODE_ID__ = editId;
  window.__EDITING_NODE_CONTEXT__ = hasObj ? 'dashboard' : 'node';
  window.__EDITING_NODE_PREV_GROUP__ = String(group || '默认分组').trim() || '默认分组';

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
  const websiteEl = document.getElementById('editNodeIsWebsite');
  const websiteRootEl = document.getElementById('editNodeWebsiteRoot');
  const err = document.getElementById('editNodeError');
  const btn = document.getElementById('editNodeSubmit');

  if(err) err.textContent = '';
  if(btn){ btn.disabled = false; btn.textContent = '保存'; }

  if(nameEl) nameEl.value = String(name || '').trim();
  if(groupEl) groupEl.value = String(group || '').trim();
  if(schemeEl) schemeEl.value = scheme;
  if(vtEl) vtEl.checked = !!vt;
  if(iprEl) iprEl.checked = !!ipri;
  if(websiteEl) websiteEl.checked = String(role || '').toLowerCase() === 'website';
  if(websiteRootEl) websiteRootEl.value = String(websiteRoot || '').trim() || '/www';

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

function applyEditedNodeToPage(data, nodeId){
  try{
    if(!data || typeof data !== 'object') return;
    const name = String(data.name || '').trim();
    const displayIp = String(data.display_ip || data.displayIp || '').trim();
    const group = String(data.group_name || data.group || '').trim() || '默认分组';
    const baseUrl = String(data.base_url || data.baseUrl || '').trim();
    const verifyTls = !!data.verify_tls;
    const isPrivate = !!data.is_private;
    const role = String(data.role || data.node_role || data.nodeRole || 'normal').trim() || 'normal';
    const websiteRoot = String(data.website_root_base || data.website_root || '').trim();

    const id = (nodeId !== undefined && nodeId !== null) ? String(nodeId) : String(window.__EDITING_NODE_ID__ || window.__NODE_ID__ || '');

    // Update dashboard card if present (inline edit)
    try{
      const card = id ? document.querySelector(`.node-card[data-node-id="${id}"]`) : null;
      if(card){
        if(name) card.dataset.nodeName = name;
        if(baseUrl) card.dataset.nodeBaseUrl = baseUrl;
        card.dataset.nodeGroup = group;
        card.dataset.nodeVerifyTls = verifyTls ? '1' : '0';
        card.dataset.nodeIsPrivate = isPrivate ? '1' : '0';
        card.dataset.nodeRole = role;
        card.dataset.nodeWebsiteRoot = websiteRoot;

        const nm = card.querySelector('.node-name');
        if(nm && name){ nm.textContent = name; nm.title = name; }
        const hostEl = card.querySelector('.node-host');
        if(hostEl && displayIp){ hostEl.textContent = displayIp; hostEl.title = displayIp; }
      }
    }catch(_e){}

    // Update node-page sidebar item (row + quick-menu dataset)
    try{
      const row = id ? document.querySelector(`.node-item-row[data-node-id="${id}"]`) : null;
      if(row){
        if(name) row.dataset.nodeName = name;
        if(displayIp) row.dataset.nodeDisplayIp = displayIp;
        if(baseUrl) row.dataset.nodeBaseUrl = baseUrl;
        row.dataset.nodeGroup = group;
        row.dataset.nodeVerifyTls = verifyTls ? '1' : '0';
        row.dataset.nodeIsPrivate = isPrivate ? '1' : '0';
        row.dataset.nodeRole = role;
        row.dataset.nodeWebsiteRoot = websiteRoot;

        const nm = row.querySelector('.node-name');
        if(nm){
          nm.textContent = name || displayIp || nm.textContent;
        }
        const meta = row.querySelector('.node-meta');
        if(meta && displayIp){
          meta.textContent = displayIp;
        }
        const gg = row.querySelector('.node-info .muted.sm');
        if(gg){
          gg.textContent = group;
        }
      }
    }catch(_e){}

    // Update current node page (only when editing the current node)
    try{
      if(window.__NODE_ID__ && id && String(window.__NODE_ID__) === String(id)){
        if(name) window.__NODE_NAME__ = name;
        if(displayIp) window.__NODE_IP__ = displayIp;
        if(baseUrl) window.__NODE_BASE_URL__ = baseUrl;
        window.__NODE_GROUP__ = group;
        window.__NODE_VERIFY_TLS__ = verifyTls ? 1 : 0;
        window.__NODE_IS_PRIVATE__ = isPrivate ? 1 : 0;
        window.__NODE_ROLE__ = role;
        window.__NODE_WEBSITE_ROOT__ = websiteRoot;

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
      }
    }catch(_e){}
  }catch(_e){}
}

async function saveEditNode(){
  const err = document.getElementById('editNodeError');
  const btn = document.getElementById('editNodeSubmit');
  try{
    if(err) err.textContent = '';
    if(btn){ btn.disabled = true; btn.textContent = '保存中…'; }

    // If group changes, we may need a lightweight refresh to re-render grouping.
    const prevGroup = String(window.__EDITING_NODE_PREV_GROUP__ || window.__NODE_GROUP__ || '默认分组').trim() || '默认分组';

    const name = (document.getElementById('editNodeName')?.value || '').trim();
    const group_name = (document.getElementById('editNodeGroup')?.value || '').trim();
    const scheme = (document.getElementById('editNodeScheme')?.value || 'http').trim();
    const ip_address = (document.getElementById('editNodeIp')?.value || '').trim();
    const verify_tls = !!document.getElementById('editNodeVerifyTls')?.checked;
    const is_private = !!document.getElementById('editNodeIsPrivate')?.checked;
    const is_website = !!document.getElementById('editNodeIsWebsite')?.checked;
    const website_root_base = (document.getElementById('editNodeWebsiteRoot')?.value || '').trim();

    if(!ip_address){
      if(err) err.textContent = '节点地址不能为空';
      return;
    }

    const nodeId = window.__EDITING_NODE_ID__ || window.__NODE_ID__;
    if(nodeId === undefined || nodeId === null || String(nodeId) === ''){
      if(err) err.textContent = '未找到要编辑的节点 ID';
      return;
    }
    const resp = await fetch(`/api/nodes/${nodeId}/update`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({ name, group_name, scheme, ip_address, verify_tls, is_private, is_website, website_root_base })
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
      patch = { name, group_name, display_ip, base_url, verify_tls, is_private };
    }
    try{ applyEditedNodeToPage(patch, nodeId); }catch(_e){}
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

  if(t) t.textContent = '—';
  if(id) id.textContent = '';
  if(sum) sum.textContent = '—';
  if(bar) bar.style.width = '0%';
  if(seg) seg.innerHTML = '';
  if(list) list.innerHTML = '';
  if(pills) pills.innerHTML = '';
  if(btn){ btn.disabled = false; btn.textContent = '开始更新'; }

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

  if(view.length === 0){
    list.innerHTML = `<div class="au-row"><div class="au-node"><div class="au-node-name">暂无匹配节点</div><div class="au-node-meta"><span class="kv-mini mono">调整筛选条件后重试</span></div></div></div>`;
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
  const btn = document.getElementById('agentUpdateStartBtn');

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

    // Terminal states:
    // - no nodes to update, or
    // - done/failed/offline only, no installing/sent/queued left.
    if(total === 0 || (installing + sent + queued) === 0){
      if(__AGENT_UPDATE_TIMER__){
        clearInterval(__AGENT_UPDATE_TIMER__);
        __AGENT_UPDATE_TIMER__ = null;
      }
      if(btn){
        btn.disabled = false;
        btn.textContent = '再次更新';
      }
    }

  }catch(_e){}
}

async function startAgentUpdateAll(){
  const btn = document.getElementById('agentUpdateStartBtn');
  const t = document.getElementById('agentUpdateTarget');
  let started = false;
  try{
    if(btn){ btn.disabled = true; btn.textContent = '更新中…'; }
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
    started = true;

    if(__AGENT_UPDATE_TIMER__){ clearInterval(__AGENT_UPDATE_TIMER__); }
    __AGENT_UPDATE_TIMER__ = setInterval(_pollAgentUpdate, 1000);
    await _pollAgentUpdate();

  }catch(e){
    toast((e && e.message) ? e.message : '更新失败', true);
  }finally{
    if(!started && btn){
      btn.disabled = false;
      btn.textContent = '开始更新';
    }
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


// ---------------- Dashboard: Full Backup / Restore ----------------
let __FULL_BACKUP_JOB_ID__ = '';
let __FULL_BACKUP_TIMER__ = null;

function _extractDownloadFilename(contentDisposition, fallback){
  let filename = String(fallback || 'download.bin');
  try{
    const cd = String(contentDisposition || '');
    const mUtf8 = /filename\*=UTF-8''([^;]+)/i.exec(cd);
    if(mUtf8 && mUtf8[1]){
      filename = decodeURIComponent(mUtf8[1]);
      return filename;
    }
    const m = /filename="?([^";]+)"?/i.exec(cd);
    if(m && m[1]) filename = m[1];
  }catch(_e){}
  return filename;
}

function _downloadBlobFile(blob, filename){
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(()=>{ try{ URL.revokeObjectURL(blobUrl); }catch(_e){} }, 2000);
}

function _renderFullBackupCounts(counts){
  const box = document.getElementById('backupFullCounts');
  if(!box) return;
  const c = (counts && typeof counts === 'object') ? counts : {};
  const rows = [
    ['nodes', '节点'],
    ['rules', '规则快照'],
    ['sites', '网站'],
    ['site_files', '网站文件'],
    ['certificates', '证书'],
    ['netmon_monitors', '网络波动'],
    ['files', '备份文件'],
  ];
  box.innerHTML = rows.map(([key, label])=>{
    const val = Number(c[key] || 0);
    return `<div class="backup-full-count"><span class="k">${label}</span><span class="v mono">${val}</span></div>`;
  }).join('');
}

function _renderFullBackupSteps(steps){
  const box = document.getElementById('backupFullSteps');
  if(!box) return;
  const arr = Array.isArray(steps) ? steps : [];
  if(!arr.length){
    box.innerHTML = '<div class="muted sm">等待任务启动…</div>';
    return;
  }
  const stText = { pending: '待处理', running: '进行中', done: '已完成', failed: '失败' };
  box.innerHTML = arr.map((s)=>{
    const key = String(s && s.key ? s.key : '').trim();
    const label = escapeHtml(String(s && s.label ? s.label : key || '步骤'));
    const detail = escapeHtml(String(s && s.detail ? s.detail : ''));
    const status = String(s && s.status ? s.status : 'pending').trim() || 'pending';
    const cls = ['pending', 'running', 'done', 'failed'].includes(status) ? status : 'pending';
    return (
      `<div class="backup-full-step ${cls}">` +
        `<div class="left">` +
          `<span class="label">${label}</span>` +
          (detail ? `<span class="detail mono">${detail}</span>` : '') +
        `</div>` +
        `<span class="status">${stText[status] || escapeHtml(status)}</span>` +
      `</div>`
    );
  }).join('');
}

function _stopFullBackupPolling(){
  if(__FULL_BACKUP_TIMER__){
    clearInterval(__FULL_BACKUP_TIMER__);
    __FULL_BACKUP_TIMER__ = null;
  }
}

function _syncFullBackupView(data){
  const stageEl = document.getElementById('backupFullStage');
  const barEl = document.getElementById('backupFullBar');
  const ptxEl = document.getElementById('backupFullProgressText');
  const errEl = document.getElementById('backupFullError');
  const dlBtn = document.getElementById('backupFullDownloadBtn');

  const progress = Math.max(0, Math.min(100, Number((data && data.progress) || 0)));
  const stage = String((data && data.stage) || '').trim() || '备份中…';
  const status = String((data && data.status) || '').trim();
  const canDownload = !!(data && data.can_download);
  const errText = String((data && data.error) || '').trim();

  if(stageEl) stageEl.textContent = stage;
  if(barEl) barEl.style.width = `${progress}%`;
  if(ptxEl) ptxEl.textContent = `进度 ${progress}%` + (status ? ` · ${status}` : '');

  if(errEl){
    if(status === 'done'){
      errEl.style.color = 'var(--ok)';
      errEl.textContent = '备份完成，可直接下载。';
    }else if(status === 'failed'){
      errEl.style.color = 'var(--bad)';
      errEl.textContent = errText || '备份失败';
    }else{
      errEl.style.color = 'var(--muted)';
      errEl.textContent = '';
    }
  }

  if(dlBtn) dlBtn.disabled = !canDownload;

  _renderFullBackupCounts((data && data.counts) || {});
  _renderFullBackupSteps((data && data.steps) || []);
}

async function _pollFullBackupProgress(){
  const jid = String(__FULL_BACKUP_JOB_ID__ || '').trim();
  if(!jid) return;
  try{
    const r = await fetch(`/api/backup/full/progress?job_id=${encodeURIComponent(jid)}`, { credentials: 'include' });
    const d = await r.json().catch(()=>({ ok:false, error:'接口返回异常' }));
    if(!r.ok || !d.ok){
      const msg = d.error || ('进度查询失败（HTTP ' + r.status + '）');
      const errEl = document.getElementById('backupFullError');
      if(errEl){
        errEl.style.color = 'var(--bad)';
        errEl.textContent = msg;
      }
      _stopFullBackupPolling();
      return;
    }
    _syncFullBackupView(d);
    const st = String(d.status || '').trim();
    if(st === 'done' || st === 'failed'){
      _stopFullBackupPolling();
    }
  }catch(e){
    const msg = (e && e.message) ? e.message : String(e || '进度查询失败');
    const errEl = document.getElementById('backupFullError');
    if(errEl){
      errEl.style.color = 'var(--bad)';
      errEl.textContent = msg;
    }
    _stopFullBackupPolling();
  }
}

async function _startFullBackupJob(){
  const errEl = document.getElementById('backupFullError');
  const dlBtn = document.getElementById('backupFullDownloadBtn');
  try{
    if(errEl){
      errEl.style.color = 'var(--muted)';
      errEl.textContent = '';
    }
    if(dlBtn) dlBtn.disabled = true;
    __FULL_BACKUP_JOB_ID__ = '';
    _stopFullBackupPolling();

    const r = await fetch('/api/backup/full/start', { method: 'POST', credentials: 'include' });
    const d = await r.json().catch(()=>({ ok:false, error:'接口返回异常' }));
    if(!r.ok || !d.ok){
      const msg = d.error || ('启动备份失败（HTTP ' + r.status + '）');
      if(errEl){
        errEl.style.color = 'var(--bad)';
        errEl.textContent = msg;
      }
      toast(msg, true);
      return;
    }

    __FULL_BACKUP_JOB_ID__ = String(d.job_id || '').trim();
    _syncFullBackupView(d);

    __FULL_BACKUP_TIMER__ = setInterval(_pollFullBackupProgress, 1200);
    await _pollFullBackupProgress();
  }catch(e){
    const msg = (e && e.message) ? e.message : String(e || '启动备份失败');
    if(errEl){
      errEl.style.color = 'var(--bad)';
      errEl.textContent = msg;
    }
    toast(msg, true);
  }
}

function openFullBackupModal(){
  const m = document.getElementById('backupFullModal');
  if(!m) return;
  m.style.display = 'flex';
  try{
    const menu = document.querySelector('.page-head details.menu[open]');
    if(menu) menu.removeAttribute('open');
  }catch(_e){}
  _renderFullBackupCounts({});
  _renderFullBackupSteps([]);
  const stageEl = document.getElementById('backupFullStage');
  const barEl = document.getElementById('backupFullBar');
  const ptxEl = document.getElementById('backupFullProgressText');
  const errEl = document.getElementById('backupFullError');
  const dlBtn = document.getElementById('backupFullDownloadBtn');
  if(stageEl) stageEl.textContent = '准备中…';
  if(barEl) barEl.style.width = '0%';
  if(ptxEl) ptxEl.textContent = '进度 0%';
  if(errEl){
    errEl.style.color = 'var(--muted)';
    errEl.textContent = '';
  }
  if(dlBtn){
    dlBtn.disabled = true;
    dlBtn.textContent = '下载备份包';
  }
  _startFullBackupJob();
}

function closeFullBackupModal(){
  const m = document.getElementById('backupFullModal');
  if(!m) return;
  m.style.display = 'none';
  _stopFullBackupPolling();
}

async function downloadFullBackupResult(){
  const jid = String(__FULL_BACKUP_JOB_ID__ || '').trim();
  if(!jid){
    toast('备份任务未启动', true);
    return;
  }
  const btn = document.getElementById('backupFullDownloadBtn');
  const errEl = document.getElementById('backupFullError');
  try{
    if(btn){
      btn.disabled = true;
      btn.textContent = '下载中…';
    }
    const r = await fetch(`/api/backup/full/download?job_id=${encodeURIComponent(jid)}`, { credentials: 'include' });
    const blob = await r.blob();
    if(!r.ok){
      let msg = `下载失败（HTTP ${r.status}）`;
      try{
        const t = await blob.text();
        const j = JSON.parse(t);
        if(j && j.error) msg = j.error;
      }catch(_e){}
      if(errEl){
        errEl.style.color = 'var(--bad)';
        errEl.textContent = msg;
      }
      toast(msg, true);
      return;
    }
    const filename = _extractDownloadFilename(r.headers.get('Content-Disposition') || '', `nexus-backup-${Date.now()}.zip`);
    _downloadBlobFile(blob, filename);
    if(errEl){
      errEl.style.color = 'var(--ok)';
      errEl.textContent = '备份包已下载到本地。';
    }
    if(btn){
      btn.disabled = false;
      btn.textContent = '重新下载';
    }
    toast('全量备份已下载');
  }catch(e){
    const msg = (e && e.message) ? e.message : String(e || '下载失败');
    if(errEl){
      errEl.style.color = 'var(--bad)';
      errEl.textContent = msg;
    }
    toast(msg, true);
  }finally{
    if(btn && btn.textContent === '下载中…'){
      btn.disabled = false;
      btn.textContent = '下载备份包';
    }
  }
}

let __RESTORE_FULL_JOB_ID__ = '';
let __RESTORE_FULL_TIMER__ = null;
let __RESTORE_FULL_PROGRESS__ = 0;
let __RESTORE_FULL_STEPS__ = [];
let __RESTORE_FULL_POLLING__ = false;
let __RESTORE_FULL_RELOADING__ = false;

function _restoreFullStepsTemplate(){
  return [
    { key: 'upload', label: '上传备份包', status: 'pending', detail: '' },
    { key: 'parse', label: '解析备份包', status: 'pending', detail: '' },
    { key: 'rules', label: '恢复节点与规则', status: 'pending', detail: '' },
    { key: 'sites_files', label: '恢复网站与文件', status: 'pending', detail: '' },
    { key: 'certs_netmon', label: '恢复证书与网络波动', status: 'pending', detail: '' },
    { key: 'finalize', label: '收尾与校验', status: 'pending', detail: '' },
  ];
}

function _renderRestoreFullSteps(){
  const box = document.getElementById('restoreFullSteps');
  if(!box) return;
  const stText = { pending: '待处理', running: '进行中', done: '已完成', failed: '失败' };
  const arr = Array.isArray(__RESTORE_FULL_STEPS__) ? __RESTORE_FULL_STEPS__ : [];
  if(!arr.length){
    box.innerHTML = '<div class="muted sm">等待任务启动…</div>';
    return;
  }
  box.innerHTML = arr.map((s)=>{
    const key = String(s && s.key ? s.key : '').trim();
    const label = escapeHtml(String(s && s.label ? s.label : key || '步骤'));
    const detail = escapeHtml(String(s && s.detail ? s.detail : ''));
    const status = String(s && s.status ? s.status : 'pending').trim() || 'pending';
    const cls = ['pending', 'running', 'done', 'failed'].includes(status) ? status : 'pending';
    return (
      `<div class="backup-full-step ${cls}">` +
        `<div class="left">` +
          `<span class="label">${label}</span>` +
          (detail ? `<span class="detail mono">${detail}</span>` : '') +
        `</div>` +
        `<span class="status">${stText[status] || escapeHtml(status)}</span>` +
      `</div>`
    );
  }).join('');
}

function _syncRestoreFullProgress(progress, stage){
  const p = Math.max(0, Math.min(100, Number(progress || 0)));
  __RESTORE_FULL_PROGRESS__ = p;
  const bar = document.getElementById('restoreFullBar');
  const ptx = document.getElementById('restoreFullProgressText');
  const stg = document.getElementById('restoreFullStage');
  if(bar) bar.style.width = `${p}%`;
  if(ptx) ptx.textContent = `进度 ${Math.round(p)}%`;
  if(stg) stg.textContent = stage ? String(stage) : '恢复中…';
}

function _buildRestoreFullSummary(result){
  const payload = result && typeof result === 'object' ? result : {};
  const nodes = payload.nodes || {};
  const rules = payload.rules || {};
  const sites = payload.sites || {};
  const siteFiles = payload.site_files || {};
  const certs = payload.certificates || {};
  const netmon = payload.netmon || {};
  return (
    `节点 新增 ${Number(nodes.added||0)} / 更新 ${Number(nodes.updated||0)} / 跳过 ${Number(nodes.skipped||0)}\n` +
    `规则 恢复 ${Number(rules.restored||0)} / 未匹配 ${Number(rules.unmatched||0)} / 失败 ${Number(rules.failed||0)}\n` +
    `站点 新增 ${Number(sites.added||0)} / 更新 ${Number(sites.updated||0)} / 跳过 ${Number(sites.skipped||0)}\n` +
    `文件 恢复 ${Number(siteFiles.restored||0)} / 未匹配 ${Number(siteFiles.unmatched||0)} / 失败 ${Number(siteFiles.failed||0)} / 跳过 ${Number(siteFiles.skipped||0)}\n` +
    `证书 新增 ${Number(certs.added||0)} / 更新 ${Number(certs.updated||0)} / 跳过 ${Number(certs.skipped||0)}\n` +
    `网络波动 新增 ${Number(netmon.added||0)} / 更新 ${Number(netmon.updated||0)} / 跳过 ${Number(netmon.skipped||0)}`
  );
}

function _stopRestoreFullPolling(){
  if(__RESTORE_FULL_TIMER__){
    clearInterval(__RESTORE_FULL_TIMER__);
    __RESTORE_FULL_TIMER__ = null;
  }
  __RESTORE_FULL_POLLING__ = false;
}

function _resetRestoreFullUI(){
  __RESTORE_FULL_PROGRESS__ = 0;
  __RESTORE_FULL_STEPS__ = _restoreFullStepsTemplate();
  __RESTORE_FULL_RELOADING__ = false;
  _renderRestoreFullSteps();
  _syncRestoreFullProgress(0, '等待开始');
  const summary = document.getElementById('restoreFullSummary');
  if(summary) summary.textContent = '等待恢复完成…';
  const err = document.getElementById('restoreFullError');
  if(err){
    err.style.color = 'var(--muted)';
    err.textContent = '';
  }
}

function _syncRestoreFullView(data){
  const err = document.getElementById('restoreFullError');
  const btn = document.getElementById('restoreFullSubmit');
  const summary = document.getElementById('restoreFullSummary');

  const status = String((data && data.status) || '').trim();
  const progress = Math.max(0, Math.min(100, Number((data && data.progress) || 0)));
  const stage = String((data && data.stage) || '').trim() || '恢复中…';
  const errText = String((data && data.error) || '').trim();
  const steps = Array.isArray(data && data.steps) ? data.steps : [];
  if(steps.length){
    __RESTORE_FULL_STEPS__ = steps;
    _renderRestoreFullSteps();
  }
  _syncRestoreFullProgress(progress, stage);

  const ptx = document.getElementById('restoreFullProgressText');
  if(ptx && status){
    ptx.textContent = `进度 ${Math.round(progress)}% · ${status}`;
  }

  if(status === 'done'){
    if(err){
      err.style.color = 'var(--ok)';
      err.textContent = '全量恢复成功，页面将在 2 秒后刷新。';
    }
    if(summary){
      summary.textContent = _buildRestoreFullSummary((data && data.result) || {});
    }
    if(btn){
      btn.disabled = true;
      btn.textContent = '恢复完成';
    }
    if(!__RESTORE_FULL_RELOADING__){
      __RESTORE_FULL_RELOADING__ = true;
      toast('全量恢复成功');
      setTimeout(()=>{
        closeRestoreFullModal();
        window.location.reload();
      }, 2000);
    }
    return;
  }

  if(status === 'failed'){
    if(err){
      err.style.color = 'var(--bad)';
      err.textContent = errText || '恢复失败';
    }
    if(summary){
      summary.textContent = `恢复失败：${errText || '执行失败'}`;
    }
    if(btn){
      btn.disabled = false;
      btn.textContent = '开始恢复';
    }
    return;
  }

  if(btn){
    btn.disabled = true;
    btn.textContent = '恢复中…';
  }
}

async function _pollRestoreFullProgress(){
  if(__RESTORE_FULL_POLLING__) return;
  const jid = String(__RESTORE_FULL_JOB_ID__ || '').trim();
  if(!jid) return;
  __RESTORE_FULL_POLLING__ = true;
  try{
    const resp = await fetch(`/api/restore/full/progress?job_id=${encodeURIComponent(jid)}`, { credentials: 'include' });
    const data = await resp.json().catch(()=>({ ok:false, error: '接口返回异常' }));
    if(!resp.ok || !data.ok){
      const msg = data.error || (`恢复进度查询失败（HTTP ${resp.status}）`);
      _stopRestoreFullPolling();
      const err = document.getElementById('restoreFullError');
      const summary = document.getElementById('restoreFullSummary');
      const btn = document.getElementById('restoreFullSubmit');
      if(err){
        err.style.color = 'var(--bad)';
        err.textContent = msg;
      }
      if(summary) summary.textContent = `恢复失败：${msg}`;
      if(btn){
        btn.disabled = false;
        btn.textContent = '开始恢复';
      }
      toast(msg, true);
      return;
    }
    _syncRestoreFullView(data);
    const st = String(data.status || '').trim();
    if(st === 'done' || st === 'failed'){
      _stopRestoreFullPolling();
      if(st === 'failed'){
        toast(String(data.error || '恢复失败'), true);
      }
    }
  }catch(e){
    _stopRestoreFullPolling();
    const msg = (e && e.message) ? e.message : String(e || '恢复进度查询失败');
    const err = document.getElementById('restoreFullError');
    const summary = document.getElementById('restoreFullSummary');
    const btn = document.getElementById('restoreFullSubmit');
    if(err){
      err.style.color = 'var(--bad)';
      err.textContent = msg;
    }
    if(summary) summary.textContent = `恢复失败：${msg}`;
    if(btn){
      btn.disabled = false;
      btn.textContent = '开始恢复';
    }
    toast(msg, true);
  }finally{
    __RESTORE_FULL_POLLING__ = false;
  }
}

function openRestoreFullModal(){
  const m = document.getElementById('restoreFullModal');
  if(!m) return;
  m.style.display = 'flex';
  try{
    const menu = document.querySelector('.page-head details.menu[open]');
    if(menu) menu.removeAttribute('open');
  }catch(_e){}
  const input = document.getElementById('restoreFullFile');
  if(input) input.value = '';
  __RESTORE_FULL_JOB_ID__ = '';
  _stopRestoreFullPolling();
  _resetRestoreFullUI();
  const btn = document.getElementById('restoreFullSubmit');
  if(btn){
    btn.disabled = false;
    btn.textContent = '开始恢复';
  }
}

function closeRestoreFullModal(){
  const m = document.getElementById('restoreFullModal');
  if(!m) return;
  m.style.display = 'none';
  _stopRestoreFullPolling();
}

async function restoreFullNow(){
  const fileInput = document.getElementById('restoreFullFile');
  const err = document.getElementById('restoreFullError');
  const btn = document.getElementById('restoreFullSubmit');
  const summaryEl = document.getElementById('restoreFullSummary');
  try{
    if(err){
      err.style.color = 'var(--bad)';
      err.textContent = '';
    }
    const f = fileInput && fileInput.files ? fileInput.files[0] : null;
    if(!f){
      if(err) err.textContent = '请选择 nexus-backup-*.zip 全量备份包';
      return;
    }
    _stopRestoreFullPolling();
    _resetRestoreFullUI();
    if(btn){
      btn.disabled = true;
      btn.textContent = '恢复中…';
    }
    _syncRestoreFullProgress(3, '上传备份包中…');
    __RESTORE_FULL_STEPS__ = _restoreFullStepsTemplate();
    if(__RESTORE_FULL_STEPS__[0]){
      __RESTORE_FULL_STEPS__[0].status = 'running';
      __RESTORE_FULL_STEPS__[0].detail = '上传中';
    }
    _renderRestoreFullSteps();

    const fd = new FormData();
    fd.append('file', f);
    const resp = await fetch('/api/restore/full/start', { method: 'POST', body: fd, credentials: 'include' });
    const data = await resp.json().catch(()=>({ ok:false, error: '接口返回异常' }));
    if(!resp.ok || !data.ok){
      const msg = data.error || ('启动恢复失败（HTTP ' + resp.status + '）');
      if(err){
        err.style.color = 'var(--bad)';
        err.textContent = msg;
      }
      if(summaryEl) summaryEl.textContent = `恢复失败：${msg}`;
      if(btn){
        btn.disabled = false;
        btn.textContent = '开始恢复';
      }
      toast(msg, true);
      return;
    }

    __RESTORE_FULL_JOB_ID__ = String(data.job_id || '').trim();
    _syncRestoreFullView(data);
    _stopRestoreFullPolling();
    __RESTORE_FULL_TIMER__ = setInterval(_pollRestoreFullProgress, 1200);
    await _pollRestoreFullProgress();
  }catch(e){
    _stopRestoreFullPolling();
    const msg = (e && e.message) ? e.message : String(e || '恢复失败');
    if(err){
      err.style.color = 'var(--bad)';
      err.textContent = msg;
    }
    if(summaryEl) summaryEl.textContent = `恢复失败：${msg}`;
    if(btn){
      btn.disabled = false;
      btn.textContent = '开始恢复';
    }
    toast(msg, true);
  }
}

window.openFullBackupModal = openFullBackupModal;
window.closeFullBackupModal = closeFullBackupModal;
window.downloadFullBackupResult = downloadFullBackupResult;
window.openRestoreFullModal = openRestoreFullModal;
window.closeRestoreFullModal = closeRestoreFullModal;
window.restoreFullNow = restoreFullNow;
function closeAddNodeModal(){
  const m = document.getElementById("addNodeModal");
  if(!m) return;
  m.style.display = "none";
}

function inferAddNodeScheme(ipOrUrl){
  const raw = String(ipOrUrl || '').trim().toLowerCase();
  if(raw.startsWith('https://')) return 'https';
  if(raw.startsWith('http://')) return 'http';
  return 'http';
}

async function createNodeFromModal(){
  const err = document.getElementById("addNodeError");
  const btn = document.getElementById("addNodeSubmit");
  try{
    if(err) err.textContent = "";
    if(btn){ btn.disabled = true; btn.textContent = "创建中…"; }
    const name = (document.getElementById("addNodeName")?.value || "").trim();
    const ip_address = (document.getElementById("addNodeIp")?.value || "").trim();
    const scheme = inferAddNodeScheme(ip_address);
    const verifyEl = document.getElementById("addNodeVerifyTls");
    const is_private = !!document.getElementById("addNodeIsPrivate")?.checked;
    const is_website = !!document.getElementById("addNodeIsWebsite")?.checked;
    const group_name = (document.getElementById("addNodeGroup")?.value || "默认分组").trim() || "默认分组";
    let website_root_base = (document.getElementById("addNodeWebsiteRoot")?.value || "").trim();

    if(!ip_address){
      if(err) err.textContent = "节点地址不能为空";
      if(btn){ btn.disabled = false; btn.textContent = "创建并进入"; }
      return;
    }

    if(is_website && !website_root_base){
      website_root_base = "/www";
    }
    if(!is_website){
      website_root_base = "";
    }

    const payload = {
      name,
      ip_address,
      scheme,
      is_private,
      is_website,
      group_name,
      website_root_base
    };
    if(verifyEl){
      payload.verify_tls = !!verifyEl.checked;
    }

    const resp = await fetch("/api/nodes/create", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload),
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
  const m = document.getElementById("backupFullModal");
  if(!m || m.style.display === "none") return;
  if(e.target === m) closeFullBackupModal();
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
    const b = document.getElementById("backupFullModal");
    if(b && b.style.display !== "none") closeFullBackupModal();
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

// NOTE: details.menu UX (close on outside click / prevent off-screen popovers)
// is implemented globally in base.html so all pages behave consistently.

// Auto-init dashboard mini system info (safe no-op on non-dashboard pages)
try{ initDashboardMiniSys(); }catch(_e){}
// Auto-init dashboard filters/search/group collapse
try{ initDashboardViewControls(); }catch(_e){}

// ========================= Network fluctuation monitor (NetMon) =========================

let NETMON_STATE = null;

function initNetMonPage(){
  const chartsBox = document.getElementById('netmonCharts');
  if(!chartsBox) return; // not on this page

  const groups = window.__NETMON_NODE_GROUPS__ || [];

  // Wallboard mode (NOC / TV screen)
  let wallboard = false;
  try{
    const params = new URLSearchParams(window.location.search || '');
    wallboard = !!window.__NETMON_WALLBOARD__
      || params.get('wall') === '1'
      || params.get('wallboard') === '1'
      || (String(window.location.pathname || '').includes('/netmon/wall'));
  }catch(_e){
    wallboard = !!window.__NETMON_WALLBOARD__;
  }

  // Read-only display mode (share / wallboard)
  let readOnly = false;
  try{
    const params = new URLSearchParams(window.location.search || '');
    readOnly = !!window.__NETMON_READONLY__
      || params.get('ro') === '1'
      || params.get('readonly') === '1'
      || (String(window.location.pathname || '').includes('/netmon/view'))
      || wallboard;
  }catch(_e){
    readOnly = !!window.__NETMON_READONLY__;
  }

  // Share token (no-login read-only link)
  let shareToken = null;
  try{
    const params = new URLSearchParams(window.location.search || '');
    shareToken = params.get('t');
  }catch(_e){
    shareToken = null;
  }

  // Kiosk/minimal UI (for share links / clean mobile view)
  let kiosk = false;
  try{
    const params = new URLSearchParams(window.location.search || '');
    const ui = String(params.get('ui') || '').toLowerCase();
    kiosk = kiosk
      || params.get('kiosk') === '1'
      || params.get('minimal') === '1'
      || params.get('min') === '1'
      || ui === 'kiosk'
      || ui === 'minimal'
      || ui === 'min';
  }catch(_e){
    kiosk = false;
  }
  if(wallboard) kiosk = true;

  // Build node checkbox list for modal
  const nodesMeta = {};
  _netmonBuildNodes(groups, document.getElementById('netmonMNodes'), nodesMeta);

  NETMON_STATE = {
    inflight: false,
    timer: null,
    lastTs: Date.now(),
    cutoffMs: null,
    windowSec: null,
    rollupMs: 0,

    // UI view config
    windowMin: 10,
    autoRefresh: true,
    // Resolution override (ms). null = auto tiers, 0 = raw, >0 = rollup bucket
    resolutionMs: null,
    searchQuery: '',
    filterMode: 'all',

    // Wallboard
    wallboard: wallboard,
    wallRotateSec: 0,
    wallRotateIndex: 0,
    wallRotateTimer: null,

    // URL shared view (apply once after first snapshot)
    urlState: _netmonParseUrlState(),
    urlApplied: false,

    nodesMeta: nodesMeta,       // from template (fallback). will be replaced by snapshot.nodes
    readOnly: readOnly,
    kiosk: kiosk,
    shareToken: (shareToken || null),
    monitors: [],
    monitorsMap: {},
    series: {},
    charts: {},
    editingId: null,
  };

  // Apply body UI class flags early
  try{ if(kiosk) document.body.classList.add('netmon-kiosk'); }catch(_e){}

  // Restore view config
  try{
    const saved = JSON.parse(localStorage.getItem('netmon_view') || '{}');
    if(saved && typeof saved === 'object'){
      if(saved.windowMin) NETMON_STATE.windowMin = Math.max(1, Number(saved.windowMin) || 10);
      if(saved.autoRefresh === false) NETMON_STATE.autoRefresh = false;
      if(Object.prototype.hasOwnProperty.call(saved, 'resolutionMs')){
        const rv = saved.resolutionMs;
        if(rv == null || rv === 'auto'){
          NETMON_STATE.resolutionMs = null;
        }else{
          const n = Number(rv);
          if(Number.isFinite(n)) NETMON_STATE.resolutionMs = n;
        }
      }
      if(typeof saved.searchQuery === 'string') NETMON_STATE.searchQuery = saved.searchQuery;
      if(saved.filterMode) NETMON_STATE.filterMode = String(saved.filterMode);
      if(Object.prototype.hasOwnProperty.call(saved, 'wallRotateSec')){
        const rs = Number(saved.wallRotateSec);
        if(Number.isFinite(rs) && rs >= 0 && rs <= 600) NETMON_STATE.wallRotateSec = rs;
      }
    }
  }catch(_e){}

  // Apply shared-view window override from URL (if any)
  try{
    const u = NETMON_STATE.urlState;
    if(u && u.winMin){
      NETMON_STATE.windowMin = Math.max(Number(NETMON_STATE.windowMin)||10, Number(u.winMin)||0);
    }
  }catch(_e){}

  // Init toolbar UI
  const winEl = document.getElementById('netmonViewWindow');
  if(winEl) winEl.value = String(Math.max(1, Math.min(1440, NETMON_STATE.windowMin)));
  const autoEl = document.getElementById('netmonAutoRefresh');
  if(autoEl) autoEl.value = NETMON_STATE.autoRefresh ? 'on' : 'off';

  // Resolution override
  const resEl = document.getElementById('netmonResolution');
  if(resEl){
    const rv = (NETMON_STATE.resolutionMs == null) ? 'auto' : String(NETMON_STATE.resolutionMs);
    resEl.value = rv;
  }

  const searchEl = document.getElementById('netmonSearch');
  if(searchEl) searchEl.value = String(NETMON_STATE.searchQuery || '');
  const filterEl = document.getElementById('netmonFilter');
  if(filterEl) filterEl.value = String(NETMON_STATE.filterMode || 'all');

  if(winEl){
    winEl.addEventListener('change', ()=>{
      const v = Math.max(1, Math.min(1440, Number(winEl.value) || 10));
      NETMON_STATE.windowMin = v;
      _netmonSaveView();
      netmonRefresh(true);
    });
  }

  if(autoEl){
    autoEl.addEventListener('change', ()=>{
      NETMON_STATE.autoRefresh = (autoEl.value !== 'off');
      _netmonSaveView();
      _netmonSyncAutoTimer();
    });
  }

  if(resEl){
    resEl.addEventListener('change', ()=>{
      const raw = String(resEl.value || 'auto');
      if(raw === 'auto'){
        NETMON_STATE.resolutionMs = null;
      }else{
        const n = Number(raw);
        if(Number.isFinite(n) && n >= 0) NETMON_STATE.resolutionMs = n;
      }
      _netmonSaveView();
      netmonRefresh(true);
    });
  }

  // Wallboard controls
  const rotateEl = document.getElementById('netmonWallRotate');
  if(rotateEl){
    try{ rotateEl.value = String(Math.round(Number(NETMON_STATE.wallRotateSec) || 0)); }catch(_e){}
    rotateEl.addEventListener('change', ()=>{
      const s = Math.max(0, Math.min(600, Number(rotateEl.value) || 0));
      NETMON_STATE.wallRotateSec = s;
      _netmonSaveView();
      _netmonSyncWallRotate();
    });
  }
  const wallFsBtn = document.getElementById('netmonWallFullscreen');
  if(wallFsBtn){
    wallFsBtn.addEventListener('click', async ()=>{
      try{
        const el = document.documentElement;
        if(!document.fullscreenElement && el && el.requestFullscreen){
          await el.requestFullscreen();
        }else if(document.fullscreenElement && document.exitFullscreen){
          await document.exitFullscreen();
        }
      }catch(_e){}
    });
  }

  if(wallboard){
    _netmonStartWallClock();
    _netmonSyncWallRotate();
  }

  // Search & filter
  let _netmonSearchTimer = null;
  if(searchEl){
    searchEl.addEventListener('input', ()=>{
      if(_netmonSearchTimer) clearTimeout(_netmonSearchTimer);
      _netmonSearchTimer = setTimeout(()=>{
        _netmonSearchTimer = null;
        NETMON_STATE.searchQuery = String(searchEl.value || '');
        _netmonSaveView();
        _netmonApplyCardFilters();
      }, 140);
    });
  }

  if(filterEl){
    filterEl.addEventListener('change', ()=>{
      NETMON_STATE.filterMode = String(filterEl.value || 'all');
      _netmonSaveView();
      _netmonApplyCardFilters();
    });
  }

  const refreshBtn = document.getElementById('netmonRefreshBtn');
  if(refreshBtn) refreshBtn.addEventListener('click', ()=>netmonRefresh(true));

  const newBtn = document.getElementById('netmonNewBtn');
  if(newBtn){
    if(readOnly){
      newBtn.style.display = 'none';
    }else{
      newBtn.addEventListener('click', ()=>openNetMonMonitorModal(null));
    }
  }

  // Modal UX
  const cancelBtn = document.getElementById('netmonModalCancel');
  if(cancelBtn) cancelBtn.addEventListener('click', closeNetMonMonitorModal);

  const submitBtn = document.getElementById('netmonModalSubmit');
  if(submitBtn) submitBtn.addEventListener('click', netmonSubmitMonitorModal);

  const selAllBtn = document.getElementById('netmonMSelectAll');
  const selNoneBtn = document.getElementById('netmonMSelectNone');
  if(selAllBtn) selAllBtn.addEventListener('click', ()=>_netmonModalSelectAll(true));
  if(selNoneBtn) selNoneBtn.addEventListener('click', ()=>_netmonModalSelectAll(false));

  const modeSel = document.getElementById('netmonMMode');
  if(modeSel) modeSel.addEventListener('change', _netmonSyncModalModeUI);
  _netmonSyncModalModeUI();

  // Chart card actions (event delegation)
  chartsBox.addEventListener('click', async (e)=>{
    try{
      const pop = e.target.closest && e.target.closest('.menu-pop');
      if(pop){
        const det = pop.closest && pop.closest('details.menu');
        if(det) det.open = false;
      }
    }catch(_e){}
    const fullBtn = e.target.closest && e.target.closest('button.netmon-full');
    if(fullBtn){
      e.preventDefault();
      const mid = fullBtn.getAttribute('data-mid');
      const st = NETMON_STATE;
      const ch = (st && st.charts && mid) ? st.charts[String(mid)] : null;
      if(ch && ch.toggleFullscreen) ch.toggleFullscreen();
      return;
    }
    const shareBtn = e.target.closest && e.target.closest('button.netmon-share');
    if(shareBtn){
      e.preventDefault();
      const mid = shareBtn.getAttribute('data-mid');
      const st = NETMON_STATE;
      const ch = (st && st.charts && mid) ? st.charts[String(mid)] : null;
      if(ch && ch.copyShareLink) await ch.copyShareLink();
      return;
    }
    const exportBtn = e.target.closest && e.target.closest('button.netmon-export');
    if(exportBtn){
      e.preventDefault();
      const mid = exportBtn.getAttribute('data-mid');
      const st = NETMON_STATE;
      const ch = (st && st.charts && mid) ? st.charts[String(mid)] : null;
      if(ch && ch.exportPNG) ch.exportPNG();
      return;
    }
    const editBtn = e.target.closest && e.target.closest('button.netmon-edit');
    if(editBtn){
      e.preventDefault();
      const mid = editBtn.getAttribute('data-mid');
      if(mid) openNetMonMonitorModal(mid);
      return;
    }
    const toggleBtn = e.target.closest && e.target.closest('button.netmon-toggle');
    if(toggleBtn){
      e.preventDefault();
      const mid = toggleBtn.getAttribute('data-mid');
      if(mid) await netmonToggleMonitor(mid);
      return;
    }
    const delBtn = e.target.closest && e.target.closest('button.netmon-delete');
    if(delBtn){
      e.preventDefault();
      const mid = delBtn.getAttribute('data-mid');
      if(mid) await netmonDeleteMonitor(mid);
      return;
    }
  });

  // Esc exits full screen
  window.addEventListener('keydown', (e)=>{
    if(e && (e.key === 'Escape' || e.key === 'Esc')){
      try{ _netmonExitFullscreenAll(); }catch(_e){}
    }
  });

  // Resize redraw (debounced)
  let _resizeTimer = null;
  window.addEventListener('resize', ()=>{
    if(!_resizeTimer){
      _resizeTimer = setTimeout(()=>{
        _resizeTimer = null;
        try{ netmonRenderAll(true); }catch(_e){}
      }, 120);
    }
  });

  // First refresh and start polling
  netmonRefresh(true);
  _netmonSyncAutoTimer();
}

function _netmonSaveView(){
  try{
    localStorage.setItem('netmon_view', JSON.stringify({
      windowMin: NETMON_STATE ? NETMON_STATE.windowMin : 10,
      autoRefresh: NETMON_STATE ? NETMON_STATE.autoRefresh : true,
      resolutionMs: NETMON_STATE ? NETMON_STATE.resolutionMs : null,
      searchQuery: NETMON_STATE ? NETMON_STATE.searchQuery : '',
      filterMode: NETMON_STATE ? NETMON_STATE.filterMode : 'all',
      wallRotateSec: NETMON_STATE ? NETMON_STATE.wallRotateSec : 0,
    }));
  }catch(_e){}
}

function _netmonSyncAutoTimer(){
  const st = NETMON_STATE;
  if(!st) return;
  if(st.timer){
    clearInterval(st.timer);
    st.timer = null;
  }
  if(st.autoRefresh){
    st.timer = setInterval(()=>netmonRefresh(false), 2000);
  }
}

function _netmonBuildNodes(groups, boxEl, nodesMeta){
  if(!boxEl) return;
  boxEl.innerHTML = '';
  const frag = document.createDocumentFragment();

  (Array.isArray(groups) ? groups : []).forEach((g)=>{
    const gName = (g && g.name) ? String(g.name) : '默认分组';
    const gNodes = (g && Array.isArray(g.nodes)) ? g.nodes : [];
    const online = Number(g && g.online) || 0;
    const total = Number(g && g.total) || gNodes.length;

    const wrap = document.createElement('div');
    wrap.className = 'netmon-group';

    const head = document.createElement('div');
    head.className = 'netmon-group-head';
    head.innerHTML = `
      <div class="netmon-group-name">${escapeHtml(gName)} <span class="muted sm">在线 <strong>${online}</strong>/<strong>${total}</strong></span></div>
    `;
    wrap.appendChild(head);

    const items = document.createElement('div');
    items.className = 'netmon-group-items';

    gNodes.forEach((n)=>{
      if(!n || n.id == null) return;
      const nid = String(n.id);
      const name = n.name ? String(n.name) : ('节点-' + nid);
      const host = n.display_ip ? String(n.display_ip) : '';
      const isOnline = !!n.online;
      nodesMeta[nid] = { id: nid, name, host, group: gName, online: isOnline };

      const label = document.createElement('label');
      label.className = 'netmon-node';
      label.innerHTML = `
        <input type="checkbox" data-node-id="${escapeHtml(nid)}" checked>
        <span class="dot ${isOnline ? 'online' : 'offline'}"></span>
        <span class="netmon-node-name">${escapeHtml(name)}</span>
        ${host ? `<span class="muted mono sm">${escapeHtml(host)}</span>` : ''}
      `;
      items.appendChild(label);
    });

    wrap.appendChild(items);
    frag.appendChild(wrap);
  });

  boxEl.appendChild(frag);
}

function _netmonModalSelectAll(on){
  document.querySelectorAll('#netmonMNodes input[type=checkbox][data-node-id]').forEach((cb)=>{
    cb.checked = !!on;
  });
}

function _netmonSyncModalModeUI(){
  const mode = (document.getElementById('netmonMMode')?.value || 'ping').toLowerCase();
  const box = document.getElementById('netmonMTcpPortBox');
  if(box) box.style.display = (mode === 'tcping') ? '' : 'none';
}

function openNetMonMonitorModal(monitorIdOrNull){
  const st = NETMON_STATE;
  if(!st) return;

  const modal = document.getElementById('netmonMonitorModal');
  if(!modal) return;

  const titleEl = document.getElementById('netmonModalTitle');
  const errEl = document.getElementById('netmonModalError');
  if(errEl) errEl.textContent = '';

  let mon = null;
  if(monitorIdOrNull){
    const mid = String(monitorIdOrNull);
    mon = st.monitorsMap ? st.monitorsMap[mid] : null;
    st.editingId = mid;
    if(titleEl) titleEl.textContent = '编辑监控';
  }else{
    st.editingId = null;
    if(titleEl) titleEl.textContent = '新建监控';
  }

  const targetEl = document.getElementById('netmonMTarget');
  const modeEl = document.getElementById('netmonMMode');
  const portEl = document.getElementById('netmonMTcpPort');
  const intervalEl = document.getElementById('netmonMInterval');
  const warnEl = document.getElementById('netmonMWarn');
  const critEl = document.getElementById('netmonMCrit');

  // Defaults for new monitor (restore from last create)
  let defaults = {mode:'ping', tcp_port:443, interval_sec:5, warn_ms:0, crit_ms:0, node_ids:[]};
  try{
    const saved = JSON.parse(localStorage.getItem('netmon_last_create') || '{}');
    if(saved && typeof saved === 'object'){
      if(saved.mode) defaults.mode = String(saved.mode);
      if(saved.tcp_port) defaults.tcp_port = Number(saved.tcp_port) || 443;
      if(saved.interval_sec) defaults.interval_sec = Number(saved.interval_sec) || 5;
      if(saved.warn_ms != null) defaults.warn_ms = Number(saved.warn_ms) || 0;
      if(saved.crit_ms != null) defaults.crit_ms = Number(saved.crit_ms) || 0;
      if(Array.isArray(saved.node_ids)) defaults.node_ids = saved.node_ids;
    }
  }catch(_e){}

  if(targetEl) targetEl.value = mon ? (mon.target || '') : '';
  if(modeEl) modeEl.value = mon ? String(mon.mode || 'ping') : String(defaults.mode || 'ping');
  if(portEl) portEl.value = String(mon ? (mon.tcp_port || 443) : (defaults.tcp_port || 443));
  if(intervalEl) intervalEl.value = String(mon ? (mon.interval_sec || 5) : (defaults.interval_sec || 5));
  if(warnEl) warnEl.value = String(mon ? (mon.warn_ms || 0) : (defaults.warn_ms || 0));
  if(critEl) critEl.value = String(mon ? (mon.crit_ms || 0) : (defaults.crit_ms || 0));

  _netmonSyncModalModeUI();

  // Node selection
  const want = new Set((mon ? (mon.node_ids || []) : (defaults.node_ids || [])).map(x=>String(x)));
  const hasWant = want.size > 0;
  document.querySelectorAll('#netmonMNodes input[type=checkbox][data-node-id]').forEach((cb)=>{
    if(!hasWant){
      cb.checked = true;
      return;
    }
    const id = cb.getAttribute('data-node-id');
    cb.checked = id ? want.has(String(id)) : false;
  });

  modal.style.display = 'flex';
  if(targetEl) setTimeout(()=>targetEl.focus(), 30);
}

function closeNetMonMonitorModal(){
  const modal = document.getElementById('netmonMonitorModal');
  if(!modal) return;
  modal.style.display = 'none';
  if(NETMON_STATE) NETMON_STATE.editingId = null;
}

window.closeNetMonMonitorModal = closeNetMonMonitorModal;

function _netmonReadModal(){
  const target = String(document.getElementById('netmonMTarget')?.value || '').trim();
  const mode = String(document.getElementById('netmonMMode')?.value || 'ping').trim().toLowerCase() || 'ping';
  const tcp_port = Number(document.getElementById('netmonMTcpPort')?.value || 443) || 443;
  const interval_sec = Number(document.getElementById('netmonMInterval')?.value || 5) || 5;

  const node_ids = [];
  const warn_ms = Number(document.getElementById('netmonMWarn')?.value || 0) || 0;
  const crit_ms = Number(document.getElementById('netmonMCrit')?.value || 0) || 0;

  document.querySelectorAll('#netmonMNodes input[type=checkbox][data-node-id]').forEach((cb)=>{
    if(cb.checked){
      const id = cb.getAttribute('data-node-id');
      if(id && !node_ids.includes(id)) node_ids.push(id);
    }
  });

  return { target, mode, tcp_port, interval_sec, warn_ms, crit_ms, node_ids };
}

async function netmonSubmitMonitorModal(){
  const st = NETMON_STATE;
  if(!st) return;
  const errEl = document.getElementById('netmonModalError');
  const btn = document.getElementById('netmonModalSubmit');

  const cfg = _netmonReadModal();
  if(!cfg.target){
    if(errEl) errEl.textContent = '请输入目标（IP / 域名）';
    return;
  }
  if(cfg.target.length > 128){
    if(errEl) errEl.textContent = '目标太长（>128）';
    return;
  }
  if(cfg.mode !== 'ping' && cfg.mode !== 'tcping'){
    cfg.mode = 'ping';
  }
  if(cfg.tcp_port < 1 || cfg.tcp_port > 65535) cfg.tcp_port = 443;
  if(cfg.interval_sec < 1) cfg.interval_sec = 1;
  if(cfg.interval_sec > 3600) cfg.interval_sec = 3600;
  if(cfg.warn_ms == null || !Number.isFinite(Number(cfg.warn_ms))) cfg.warn_ms = 0;
  if(cfg.crit_ms == null || !Number.isFinite(Number(cfg.crit_ms))) cfg.crit_ms = 0;
  cfg.warn_ms = Math.max(0, Math.min(600000, Math.floor(Number(cfg.warn_ms))));
  cfg.crit_ms = Math.max(0, Math.min(600000, Math.floor(Number(cfg.crit_ms))));
  if(cfg.warn_ms > 0 && cfg.crit_ms > 0 && cfg.warn_ms > cfg.crit_ms){
    // keep warn <= crit
    const tmp = cfg.warn_ms; cfg.warn_ms = cfg.crit_ms; cfg.crit_ms = tmp;
  }

  if(!cfg.node_ids.length){
    if(errEl) errEl.textContent = '请选择至少一个节点';
    return;
  }

  // persist last-create defaults
  try{
    localStorage.setItem('netmon_last_create', JSON.stringify({
      mode: cfg.mode,
      tcp_port: cfg.tcp_port,
      interval_sec: cfg.interval_sec,
      warn_ms: cfg.warn_ms,
      crit_ms: cfg.crit_ms,
      node_ids: cfg.node_ids,
    }));
  }catch(_e){}

  try{
    if(errEl) errEl.textContent = '';
    if(btn){ btn.disabled = true; btn.textContent = '保存中…'; }

    if(st.editingId){
      const mid = st.editingId;
      await fetchJSON(`/api/netmon/monitors/${encodeURIComponent(mid)}`, {
        method: 'POST',
        body: JSON.stringify({
          target: cfg.target,
          mode: cfg.mode,
          tcp_port: cfg.tcp_port,
          interval_sec: cfg.interval_sec,
          warn_ms: cfg.warn_ms,
          crit_ms: cfg.crit_ms,
          node_ids: cfg.node_ids,
        }),
      });
      toast('已更新监控');
    }else{
      await fetchJSON('/api/netmon/monitors', {
        method: 'POST',
        body: JSON.stringify({
          target: cfg.target,
          mode: cfg.mode,
          tcp_port: cfg.tcp_port,
          interval_sec: cfg.interval_sec,
          warn_ms: cfg.warn_ms,
          crit_ms: cfg.crit_ms,
          node_ids: cfg.node_ids,
          enabled: true,
        }),
      });
      toast('已创建监控');
    }

    closeNetMonMonitorModal();
    await netmonRefresh(true);
  }catch(e){
    const msg = (e && e.message) ? e.message : String(e);
    if(errEl) errEl.textContent = msg;
  }finally{
    if(btn){ btn.disabled = false; btn.textContent = '保存'; }
  }
}

async function netmonToggleMonitor(monitorId){
  const st = NETMON_STATE;
  if(!st) return;
  const mid = String(monitorId);
  const mon = st.monitorsMap ? st.monitorsMap[mid] : null;
  if(!mon) return;

  try{
    await fetchJSON(`/api/netmon/monitors/${encodeURIComponent(mid)}`, {
      method: 'POST',
      body: JSON.stringify({ enabled: !mon.enabled }),
    });
    toast(mon.enabled ? '已停用' : '已启用');
    await netmonRefresh(true);
  }catch(e){
    toast((e && e.message) ? e.message : String(e), true);
  }
}

async function netmonDeleteMonitor(monitorId){
  const st = NETMON_STATE;
  if(!st) return;
  const mid = String(monitorId);
  const mon = st.monitorsMap ? st.monitorsMap[mid] : null;
  const name = mon ? (mon.target || ('#' + mid)) : ('#' + mid);
  if(!confirm(`确认删除监控：${name} ？\n（将同时删除历史采集数据）`)) return;

  try{
    await fetchJSON(`/api/netmon/monitors/${encodeURIComponent(mid)}/delete`, { method:'POST', body: '{}' });
    toast('已删除');
    await netmonRefresh(true);
  }catch(e){
    toast((e && e.message) ? e.message : String(e), true);
  }
}

async function netmonRefresh(force){
  const st = NETMON_STATE;
  if(!st) return;
  if(st.inflight) return;
  st.inflight = true;

  const statusEl = document.getElementById('netmonStatus');
  try{
    const winMin = Math.max(1, Math.min(1440, Number(st.windowMin) || 10));
    let url = `/api/netmon/snapshot?window_min=${encodeURIComponent(winMin)}`;

    // Resolution override (server-side rollup). When omitted, backend uses tiering.
    try{
      if(st.resolutionMs != null){
        const rm = Math.max(0, Math.round(Number(st.resolutionMs) || 0));
        url += `&rollup_ms=${encodeURIComponent(String(rm))}`;
      }
    }catch(_e){}
    // Read-only share page usually focuses a single monitor. Fetch only what we need.
    try{
      const u = st.urlState;
      if(st.readOnly && u && u.mid){
        url += `&mid=${encodeURIComponent(String(u.mid))}`;
      }
    }catch(_e){}

    try{
      if(st.shareToken){
        url += `&t=${encodeURIComponent(String(st.shareToken))}`;
      }
    }catch(_e){}

    const res = await fetchJSON(url);
    st.lastTs = (res && res.ts) ? Number(res.ts) : Date.now();

    // Loaded window bounds (for zoom/pan clamping)
    st.cutoffMs = (res && res.cutoff_ms) ? Number(res.cutoff_ms) : null;
    st.windowSec = (res && res.window_sec) ? Number(res.window_sec) : (winMin * 60);
    st.rollupMs = (res && res.rollup_ms != null) ? Number(res.rollup_ms) : 0;

    // Update node meta from server (better names/online state)
    if(res && res.nodes && typeof res.nodes === 'object'){
      st.nodesMeta = res.nodes;
    }

    const monitors = (res && Array.isArray(res.monitors)) ? res.monitors : [];
    st.monitors = monitors;
    st.monitorsMap = {};
    monitors.forEach((m)=>{
      if(!m || m.id == null) return;
      st.monitorsMap[String(m.id)] = m;
    });

    st.series = (res && res.series && typeof res.series === 'object') ? res.series : {};

    _netmonEnsureCards();
    _netmonApplyUrlStateIfNeeded();
    netmonRenderAll(force);
    if(st.wallboard){
      try{ _netmonReorderCardsByLevel(); }catch(_e){}
    }
    _netmonApplyCardFilters();

    const empty = document.getElementById('netmonEmpty');
    if(empty) empty.style.display = monitors.length ? 'none' : '';
  }catch(e){
    const msg = (e && e.message) ? e.message : String(e);
    if(statusEl) statusEl.textContent = `加载失败：${msg}`;
    if(force) toast(`加载失败：${msg}`, true);
  }finally{
    st.inflight = false;
  }
}

function _netmonEnsureCards(){
  const st = NETMON_STATE;
  if(!st) return;
  const chartsBox = document.getElementById('netmonCharts');
  if(!chartsBox) return;

  const keep = new Set();
  const monitors = Array.isArray(st.monitors) ? st.monitors.slice() : [];
  // Default sort: enabled first, then newest first
  monitors.sort((a,b)=>{
    const ae = a && a.enabled ? 1 : 0;
    const be = b && b.enabled ? 1 : 0;
    if(ae !== be) return be - ae;
    return (Number(b.id)||0) - (Number(a.id)||0);
  });

  monitors.forEach((m)=>{
    if(!m || m.id == null) return;
    const mid = String(m.id);
    keep.add(mid);
    if(!st.charts[mid]){
      const card = _netmonCreateMonitorCard(m);
      chartsBox.appendChild(card);
      st.charts[mid] = new NetMonChart(card, mid);
    }else{
      // update info + keep order by append
      const ch = st.charts[mid];
      if(ch && ch.card){
        _netmonUpdateMonitorCard(ch.card, m);
        chartsBox.appendChild(ch.card);
      }
    }
  });

  // Remove deleted monitors
  Object.keys(st.charts || {}).forEach((mid)=>{
    if(!keep.has(mid)){
      const ch = st.charts[mid];
      if(ch && ch.card && ch.card.parentNode) ch.card.parentNode.removeChild(ch.card);
      delete st.charts[mid];
    }
  });
}

function netmonRenderAll(force){
  const st = NETMON_STATE;
  if(!st || !st.charts) return;
  Object.keys(st.charts).forEach((mid)=>{
    const ch = st.charts[mid];
    if(ch) ch.render(force);
  });
}

function _netmonApplyCardFilters(){
  const st = NETMON_STATE;
  if(!st || !st.charts) return;

  const q = String(st.searchQuery || '').trim().toLowerCase();
  const mode = String(st.filterMode || 'all');

  let shown = 0;
  let total = 0;

  Object.keys(st.charts).forEach((mid)=>{
    const ch = st.charts[mid];
    if(!ch || !ch.card) return;
    total += 1;

    const mon = st.monitorsMap ? st.monitorsMap[String(mid)] : null;
    const target = mon ? String(mon.target || '') : '';

    let match = true;
    if(q){
      match = target.toLowerCase().includes(q) || String(mid).includes(q);
    }

    if(match){
      if(mode === 'enabled' && mon && !mon.enabled) match = false;
      if(mode === 'disabled' && mon && mon.enabled) match = false;
      if(mode === 'abnormal'){
        const lv = String(ch.level || 'none');
        match = (lv === 'warn' || lv === 'crit');
      }
      if(mode === 'crit'){
        match = String(ch.level || '') === 'crit';
      }
    }

    ch.card.style.display = match ? '' : 'none';
    if(match) shown += 1;
  });

  // Update status text with shown count (based on last snapshot)
  try{
    const statusEl = document.getElementById('netmonStatus');
    if(statusEl && Array.isArray(st.monitors)){
      const tsTxt = _netmonFormatClock(st.lastTs);
      let rollTxt = '';
      try{
        const rm = Number(st.rollupMs) || 0;
        if(rm > 0){
          if(rm >= 3600000) rollTxt = ` · 分辨率 ${Math.round(rm/3600000)}h`;
          else if(rm >= 60000) rollTxt = ` · 分辨率 ${Math.round(rm/60000)}m`;
          else if(rm >= 1000) rollTxt = ` · 分辨率 ${Math.round(rm/1000)}s`;
          else rollTxt = ` · 分辨率 ${rm}ms`;
        }
      }catch(_e){}

      statusEl.textContent = `${shown}/${total}${rollTxt} · 更新 ${tsTxt}`;
    }
  }catch(_e){}

  // Wallboard summary (if present)
  try{ _netmonUpdateWallboardSummary({shown, total}); }catch(_e){}
}

function _netmonLevelRank(lv){
  const s = String(lv || '');
  if(s === 'crit') return 3;
  if(s === 'warn') return 2;
  if(s === 'ok') return 1;
  return 0;
}

function _netmonReorderCardsByLevel(){
  const st = NETMON_STATE;
  if(!st || !st.charts) return;
  const chartsBox = document.getElementById('netmonCharts');
  if(!chartsBox) return;
  const mids = Object.keys(st.charts);
  if(mids.length <= 1) return;
  mids.sort((a,b)=>{
    const ca = st.charts[a];
    const cb = st.charts[b];
    const ra = _netmonLevelRank(ca ? ca.level : '');
    const rb = _netmonLevelRank(cb ? cb.level : '');
    if(ra !== rb) return rb - ra;
    const ma = st.monitorsMap ? st.monitorsMap[String(a)] : null;
    const mb = st.monitorsMap ? st.monitorsMap[String(b)] : null;
    const ae = ma && ma.enabled ? 1 : 0;
    const be = mb && mb.enabled ? 1 : 0;
    if(ae !== be) return be - ae;
    return (Number(b)||0) - (Number(a)||0);
  });
  for(const mid of mids){
    const ch = st.charts[mid];
    if(ch && ch.card) chartsBox.appendChild(ch.card);
  }
}

let NETMON_WALL_CLOCK_TIMER = null;
function _netmonStartWallClock(){
  if(NETMON_WALL_CLOCK_TIMER) return;
  const el = document.getElementById('netmonWallClock');
  if(!el) return;
  const tick = ()=>{
    try{ el.textContent = _netmonFormatClock(Date.now()); }catch(_e){}
  };
  tick();
  NETMON_WALL_CLOCK_TIMER = setInterval(tick, 1000);
}

function _netmonSyncWallRotate(){
  const st = NETMON_STATE;
  if(!st || !st.wallboard) return;
  if(st.wallRotateTimer){
    clearInterval(st.wallRotateTimer);
    st.wallRotateTimer = null;
  }
  const sec = Math.max(0, Number(st.wallRotateSec) || 0);
  if(sec > 0){
    st.wallRotateTimer = setInterval(()=>{
      try{ _netmonWallRotateOnce(); }catch(_e){}
    }, Math.max(4, sec) * 1000);
  }
}

function _netmonWallRotateOnce(){
  const st = NETMON_STATE;
  if(!st || !st.charts) return;
  // Pick visible cards
  const visible = [];
  for(const mid of Object.keys(st.charts)){
    const ch = st.charts[mid];
    if(!ch || !ch.card) continue;
    if(ch.card.style && ch.card.style.display === 'none') continue;
    visible.push(String(mid));
  }
  if(!visible.length) return;

  const abnormal = visible.filter((mid)=>{
    const lv = st.charts[mid] ? st.charts[mid].level : '';
    return lv === 'warn' || lv === 'crit';
  });
  const pool = abnormal.length ? abnormal : visible;
  pool.sort((a,b)=>{
    const ra = _netmonLevelRank(st.charts[a] ? st.charts[a].level : '');
    const rb = _netmonLevelRank(st.charts[b] ? st.charts[b].level : '');
    if(ra !== rb) return rb - ra;
    return (Number(b)||0) - (Number(a)||0);
  });

  st.wallRotateIndex = (Number(st.wallRotateIndex) || 0) + 1;
  const idx = st.wallRotateIndex % pool.length;
  const mid = pool[idx];
  const ch = st.charts[mid];
  if(!ch || !ch.card) return;
  try{
    ch.card.classList.add('netmon-wall-focus');
    ch.card.scrollIntoView({behavior:'smooth', block:'center'});
    setTimeout(()=>{
      try{ ch.card.classList.remove('netmon-wall-focus'); }catch(_e){}
    }, 2200);
  }catch(_e){}
}

function _netmonUpdateWallboardSummary({shown, total}={}){
  const st = NETMON_STATE;
  if(!st || !st.wallboard) return;
  const okEl = document.getElementById('netmonWallOk');
  const warnEl = document.getElementById('netmonWallWarn');
  const critEl = document.getElementById('netmonWallCrit');
  const totalEl = document.getElementById('netmonWallTotal');
  const subEl = document.getElementById('netmonWallSub');
  if(!okEl && !warnEl && !critEl && !totalEl && !subEl) return;

  let ok = 0, warn = 0, crit = 0, tot = 0;
  for(const mid of Object.keys(st.charts || {})){
    const ch = st.charts[mid];
    const mon = st.monitorsMap ? st.monitorsMap[String(mid)] : null;
    if(mon && mon.enabled === false) continue;
    tot += 1;
    const lv = ch ? String(ch.level || '') : '';
    if(lv === 'crit') crit += 1;
    else if(lv === 'warn') warn += 1;
    else ok += 1;
  }

  if(okEl) okEl.textContent = `OK ${ok}`;
  if(warnEl) warnEl.textContent = `WARN ${warn}`;
  if(critEl) critEl.textContent = `CRIT ${crit}`;
  if(totalEl) totalEl.textContent = `TOTAL ${tot}`;

  if(subEl){
    const tsTxt = _netmonFormatClock(st.lastTs);
    const winMin = Math.max(1, Math.min(1440, Number(st.windowMin) || 10));
    let rollTxt = '';
    try{
      const rm = (st.resolutionMs != null) ? Number(st.resolutionMs) : Number(st.rollupMs);
      if(Number.isFinite(rm) && rm >= 0){
        if(rm === 0) rollTxt = '原始';
        else if(rm >= 3600000) rollTxt = `${Math.round(rm/3600000)}h`;
        else if(rm >= 60000) rollTxt = `${Math.round(rm/60000)}m`;
        else if(rm >= 1000) rollTxt = `${Math.round(rm/1000)}s`;
        else rollTxt = `${rm}ms`;
      }
    }catch(_e){}
    const s = (shown != null && total != null) ? ` · 显示 ${shown}/${total}` : '';
    subEl.textContent = `窗口 ${winMin}min${s}${rollTxt ? (' · 分辨率 ' + rollTxt) : ''} · 更新 ${tsTxt}`;
  }
}

function _netmonCreateMonitorCard(m){
  const card = document.createElement('div');
  card.className = 'card netmon-chart-card';
  card.setAttribute('data-mid', String(m.id));

  const ro = !!(NETMON_STATE && NETMON_STATE.readOnly);

  // Desktop: keep explicit buttons; Mobile: compact icon bar + overflow menu.
  const actionsDesktop = ro ? `
        <button class="btn xs ghost netmon-full" type="button" data-mid="${escapeHtml(String(m.id))}" title="全屏查看该图表">全屏</button>
        <button class="btn xs ghost netmon-share" type="button" data-mid="${escapeHtml(String(m.id))}" title="复制只读展示链接（包含当前视图/隐藏曲线）">分享</button>
        <button class="btn xs ghost netmon-export" type="button" data-mid="${escapeHtml(String(m.id))}" title="导出当前图表为 PNG">PNG</button>
  ` : `
        <button class="btn xs ghost netmon-full" type="button" data-mid="${escapeHtml(String(m.id))}" title="全屏查看该图表">全屏</button>
        <button class="btn xs ghost netmon-share" type="button" data-mid="${escapeHtml(String(m.id))}" title="复制分享链接（包含当前视图/隐藏曲线）">分享</button>
        <button class="btn xs ghost netmon-export" type="button" data-mid="${escapeHtml(String(m.id))}" title="导出当前图表为 PNG">PNG</button>
        <button class="btn xs ghost netmon-edit" type="button" data-mid="${escapeHtml(String(m.id))}">编辑</button>
        <button class="btn xs ghost netmon-toggle" type="button" data-mid="${escapeHtml(String(m.id))}">停用</button>
        <button class="btn xs danger netmon-delete" type="button" data-mid="${escapeHtml(String(m.id))}">删除</button>
  `;

  const actionsMobile = ro ? `
        <button class="btn icon xs ghost netmon-full" type="button" data-mid="${escapeHtml(String(m.id))}" title="全屏">⛶</button>
        <button class="btn icon xs ghost netmon-share" type="button" data-mid="${escapeHtml(String(m.id))}" title="分享链接">🔗</button>
        <button class="btn icon xs ghost netmon-export" type="button" data-mid="${escapeHtml(String(m.id))}" title="导出 PNG">⬇</button>
  ` : `
        <button class="btn icon xs ghost netmon-full" type="button" data-mid="${escapeHtml(String(m.id))}" title="全屏">⛶</button>
        <button class="btn icon xs ghost netmon-share" type="button" data-mid="${escapeHtml(String(m.id))}" title="分享链接">🔗</button>
        <button class="btn icon xs ghost netmon-export" type="button" data-mid="${escapeHtml(String(m.id))}" title="导出 PNG">⬇</button>

        <details class="menu netmon-actions-menu">
          <summary class="btn icon xs ghost" aria-label="更多操作">⋯</summary>
          <div class="menu-pop">
            <button class="menu-item netmon-edit" type="button" data-mid="${escapeHtml(String(m.id))}">编辑</button>
            <button class="menu-item netmon-toggle" type="button" data-mid="${escapeHtml(String(m.id))}">停用</button>
            <div class="menu-sep"></div>
            <button class="menu-item danger netmon-delete" type="button" data-mid="${escapeHtml(String(m.id))}">删除</button>
          </div>
        </details>
  `;

  const actions = `
    <div class="netmon-actions-desktop">
      ${actionsDesktop}
    </div>
    <div class="netmon-actions-mobile">
      ${actionsMobile}
    </div>
  `;

  card.innerHTML = `
    <div class="card-header netmon-card-head" style="padding:12px 12px 8px;">
      <div style="min-width:0;">
        <div class="card-title mono netmon-title"></div>
        <div class="card-sub netmon-sub"></div>
        <div class="netmon-stats" aria-label="metrics"></div>
        <div class="netmon-legend"></div>
      </div>
      <div class="right netmon-actions" style="flex:0 0 auto;">
        ${actions}
      </div>
    </div>
    <div class="netmon-canvas-wrap">
      <canvas class="netmon-canvas" height="220"></canvas>
      <canvas class="netmon-nav-canvas" height="44"></canvas>
      <button class="btn xs primary netmon-realtime-btn" type="button" style="display:none;" title="回到实时窗口">回到实时</button>
      <div class="netmon-tooltip" style="display:none;"></div>
    </div>
    <div class="netmon-events">
      <div class="netmon-events-row">
        <div class="muted sm">异常</div>
        <div class="right" style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; justify-content:flex-end;">
          <div class="netmon-events-badges" aria-label="abnormal summary"></div>
          <button class="btn xs ghost netmon-events-open" type="button" title="查看全部异常">查看</button>
        </div>
      </div>
      <div class="netmon-events-bar" aria-label="abnormal events timeline"></div>
      <div class="netmon-events-foot"></div>
    </div>
  `;

  _netmonUpdateMonitorCard(card, m);
  return card;
}

function _netmonUpdateMonitorCard(card, m){
  if(!card || !m) return;
  const title = card.querySelector('.netmon-title');
  if(title) title.textContent = String(m.target || ('#' + m.id));

  const sub = card.querySelector('.netmon-sub');
  const enabled = !!m.enabled;
  const mode = String(m.mode || 'ping');
  const interval = Number(m.interval_sec || 5) || 5;
  const nodeCount = Array.isArray(m.node_ids) ? m.node_ids.length : 0;

  let lastTxt = '';
  if(m.last_run_ts_ms){
    lastTxt = ` · 最近采集 ${_netmonFormatClock(Number(m.last_run_ts_ms))}`;
  }else{
    lastTxt = ' · 尚未采集';
  }

  if(sub){
    const extra = (!enabled) ? '（已停用）' : '';
    const warn = Number(m.warn_ms || 0) || 0;
    const crit = Number(m.crit_ms || 0) || 0;
    let thrTxt = '';
    if(warn > 0 || crit > 0){
      const w = warn > 0 ? ('W' + warn) : 'W-';
      const c = crit > 0 ? ('C' + crit) : 'C-';
      thrTxt = ` · 阈值 ${w}/${c}ms`;
    }
    sub.textContent = `${mode}${mode==='tcping' ? ('/' + (m.tcp_port || 443)) : ''} · ${interval}s · 节点 ${nodeCount}${thrTxt}${lastTxt} ${extra}`;
  }

  const toggleBtns = card.querySelectorAll('button.netmon-toggle');
  if(toggleBtns && toggleBtns.length){
    toggleBtns.forEach((b)=>{ try{ b.textContent = enabled ? '停用' : '启用'; }catch(_e){} });
  }

  card.classList.toggle('netmon-disabled', !enabled);
}

function _netmonColorForNode(nodeId){
  const s = String(nodeId || '0');
  let h = 0;
  for(let i=0;i<s.length;i++) h = (h*31 + s.charCodeAt(i)) % 360;
  const hue = (h + 210) % 360;
  return `hsl(${hue}, 70%, 60%)`;
}

function _netmonNiceMax(v){
  const x = Math.max(1, Number(v) || 1);
  // 1,2,5 * 10^n
  const pow = Math.pow(10, Math.floor(Math.log10(x)));
  const n = x / pow;
  let m = 1;
  if(n <= 1) m = 1;
  else if(n <= 2) m = 2;
  else if(n <= 5) m = 5;
  else m = 10;
  return m * pow;
}

function _netmonFormatClock(ts){
  const d = new Date(Number(ts) || Date.now());
  const hh = String(d.getHours()).padStart(2,'0');
  const mm = String(d.getMinutes()).padStart(2,'0');
  const ss = String(d.getSeconds()).padStart(2,'0');
  return `${hh}:${mm}:${ss}`;
}

function _netmonFormatTs(ts){
  const t = Number(ts) || 0;
  if(!t) return '';
  const d = new Date(t);
  const now = new Date();
  const hh = String(d.getHours()).padStart(2,'0');
  const mm = String(d.getMinutes()).padStart(2,'0');
  const ss = String(d.getSeconds()).padStart(2,'0');
  const time = `${hh}:${mm}:${ss}`;
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  if(sameDay) return time;
  const MM = String(d.getMonth()+1).padStart(2,'0');
  const DD = String(d.getDate()).padStart(2,'0');
  return `${MM}-${DD} ${time}`;
}

function _netmonFormatDur(ms){
  const m = Math.max(0, Number(ms) || 0);
  if(m < 1000) return `${Math.round(m)}ms`;
  const s = m / 1000;
  if(s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  const mm = Math.floor(s / 60);
  const ss = Math.floor(s % 60);
  if(mm < 60) return `${mm}m ${String(ss).padStart(2,'0')}s`;
  const hh = Math.floor(mm / 60);
  const rem = mm % 60;
  return `${hh}h ${String(rem).padStart(2,'0')}m`;
}

function _netmonLSHiddenKey(mid){
  return `netmon_hidden_${String(mid||'')}`;
}

function _netmonLoadHidden(mid){
  try{
    const raw = localStorage.getItem(_netmonLSHiddenKey(mid));
    if(!raw) return new Set();
    const arr = JSON.parse(raw);
    if(Array.isArray(arr)) return new Set(arr.map(x=>String(x)));
  }catch(_e){}
  return new Set();
}

function _netmonSaveHidden(mid, setObj){
  try{
    const arr = Array.from(setObj || []).map(x=>String(x));
    localStorage.setItem(_netmonLSHiddenKey(mid), JSON.stringify(arr));
  }catch(_e){}
}

function _netmonSanitizeFilename(name){
  const s = String(name || 'export')
    .replace(/[:\/\\?%*|"<>]/g, '_')
    .replace(/\s+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');
  return s ? s.slice(0, 60) : 'export';
}

function _netmonParseUrlState(){
  try{
    const params = new URLSearchParams(window.location.search || '');
    const mid = params.get('mid');
    if(!mid) return null;

    const modeRaw = String(params.get('mode') || '').toLowerCase();
    const mode = (modeRaw === 'fixed') ? 'fixed' : 'follow';

    const num = (x)=>{
      const v = Number(x);
      return Number.isFinite(v) ? v : null;
    };

    const from = num(params.get('from'));
    const to = num(params.get('to'));
    const span = num(params.get('span'));
    const win = num(params.get('win'));

    const hiddenRaw = params.get('hidden');
    const hidden = hiddenRaw ? String(hiddenRaw).split(',').map(s=>String(s).trim()).filter(Boolean) : [];

    return {
      mid: String(mid),
      mode,
      from,
      to,
      span,
      hidden,
      winMin: (win != null) ? Math.max(1, Math.min(1440, win)) : null,
    };
  }catch(_e){
    return null;
  }
}

function _netmonApplyUrlStateIfNeeded(){
  const st = NETMON_STATE;
  if(!st || st.urlApplied) return;

  const u = st.urlState;
  if(!u || !u.mid){
    st.urlApplied = true;
    return;
  }

  const mid = String(u.mid);
  const ch = (st.charts && st.charts[mid]) ? st.charts[mid] : null;
  const mon = (st.monitorsMap && st.monitorsMap[mid]) ? st.monitorsMap[mid] : null;

  // If monitor doesn't exist, mark applied and notify once.
  if(!mon){
    st.urlApplied = true;
    try{ toast('分享链接的监控不存在或已删除', true); }catch(_e){}
    return;
  }

  // Wait until card is created.
  if(!ch) return;

  // Apply hidden nodes (list means "hidden")
  if(Array.isArray(u.hidden)){
    const next = new Set(u.hidden.map(x=>String(x)));
    const allow = new Set((Array.isArray(mon.node_ids) ? mon.node_ids : []).map(x=>String(x)));
    for(const x of Array.from(next)){
      if(!allow.has(String(x))) next.delete(String(x));
    }
    ch.hiddenNodes = next;
    _netmonSaveHidden(mid, next);
  }

  // Apply range
  if(u.mode === 'fixed' && u.from != null && u.to != null && Number(u.to) > Number(u.from)){
    ch.viewMode = 'fixed';
    ch.fixed.xMin = Number(u.from);
    ch.fixed.xMax = Number(u.to);
  }else{
    ch.viewMode = 'follow';
    ch.fixed.xMin = null;
    ch.fixed.xMax = null;
    if(u.span != null && Number.isFinite(Number(u.span))){
      ch.spanMs = Number(u.span);
    }
  }

  try{ ch._syncHistoryUI(); }catch(_e){}
  ch.hover = null;
  try{ ch._hideTooltip(); }catch(_e){}

  // Focus the card briefly
  try{
    if(ch.card){
      ch.card.classList.add('netmon-focus');
      setTimeout(()=>{ try{ ch.card.classList.remove('netmon-focus'); }catch(_e){} }, 2200);
      ch.card.scrollIntoView({behavior:'smooth', block:'start'});
    }
  }catch(_e){}

  st.urlApplied = true;
}

// Fullscreen helpers (single-card fullscreen with backdrop)
let NETMON_FS_BACKDROP = null;

function _netmonEnsureFsBackdrop(){
  if(NETMON_FS_BACKDROP) return;
  const d = document.createElement('div');
  d.className = 'netmon-backdrop';
  d.addEventListener('click', ()=>{
    try{ _netmonExitFullscreenAll(); }catch(_e){}
  });
  document.body.appendChild(d);
  NETMON_FS_BACKDROP = d;
}

function _netmonRemoveFsBackdrop(){
  if(NETMON_FS_BACKDROP && NETMON_FS_BACKDROP.parentNode){
    NETMON_FS_BACKDROP.parentNode.removeChild(NETMON_FS_BACKDROP);
  }
  NETMON_FS_BACKDROP = null;
}

function _netmonExitFullscreenAll(){
  const st = NETMON_STATE;
  if(st && st.charts){
    Object.keys(st.charts).forEach((mid)=>{
      const ch = st.charts[mid];
      if(ch && ch.setFullscreen) ch.setFullscreen(false, {skipGlobal:true});
    });
  }
  _netmonRemoveFsBackdrop();
  try{ document.body.classList.remove('netmon-noscroll'); }catch(_e){}
}

// Event detail modal (diagnosis)
let NETMON_EVENT_MODAL = null;
let NETMON_EVENT_MODAL_CTX = null; // {mid, from, to}

function _netmonCloseEventModal(){
  if(NETMON_EVENT_MODAL) NETMON_EVENT_MODAL.style.display = 'none';
  NETMON_EVENT_MODAL_CTX = null;
}

function _netmonEnsureEventModal(){
  if(NETMON_EVENT_MODAL) return NETMON_EVENT_MODAL;
  const m = document.createElement('div');
  m.id = 'netmonEventModal';
  m.className = 'modal';
  m.style.display = 'none';
  m.innerHTML = `
    <div class="modal-inner" style="max-width:860px;">
      <div class="row" style="align-items:center;">
        <div class="col"><div class="h2" id="netmonEvtH2">异常详情</div></div>
        <div class="col right"><button class="btn xs ghost" type="button" data-action="close">关闭</button></div>
      </div>
      <div class="muted sm" id="netmonEvtTitle" style="margin-top:6px;"></div>
      <div id="netmonEvtBody" style="margin-top:12px;"></div>
      <div class="row" style="gap:10px; justify-content:flex-end; margin-top:14px;">
        <button class="btn xs ghost" type="button" data-action="close">关闭</button>
        <button class="btn xs ghost" type="button" data-action="jump">跳转到图表</button>
        <button class="btn xs" type="button" data-action="copy">复制只读链接</button>
      </div>
    </div>
  `;

  m.addEventListener('click', (e)=>{
    try{
      // backdrop click
      if(e.target === m){
        _netmonCloseEventModal();
        return;
      }
      const actEl = e.target && e.target.closest ? e.target.closest('[data-action]') : null;
      if(!actEl) return;
      const act = String(actEl.getAttribute('data-action') || '');
      if(act === 'close'){
        _netmonCloseEventModal();
        return;
      }
      const ctx = NETMON_EVENT_MODAL_CTX;
      if(!ctx || !NETMON_STATE || !NETMON_STATE.charts) return;
      const ch = NETMON_STATE.charts[String(ctx.mid)];
      if(!ch) return;
      if(act === 'jump'){
        ch.jumpToRange(Number(ctx.from), Number(ctx.to));
        _netmonCloseEventModal();
      }else if(act === 'copy'){
        if(ch.copyShareLinkForRange) ch.copyShareLinkForRange(Number(ctx.from), Number(ctx.to));
      }
    }catch(_e){}
  });

  // ESC to close (once)
  window.addEventListener('keydown', (e)=>{
    try{
      if(e.key === 'Escape' && NETMON_EVENT_MODAL && NETMON_EVENT_MODAL.style.display !== 'none'){
        _netmonCloseEventModal();
      }
    }catch(_e){}
  });

  document.body.appendChild(m);
  NETMON_EVENT_MODAL = m;
  return m;
}

function _netmonClamp(v, a, b){
  const x = Number(v);
  if(!Number.isFinite(x)) return a;
  return Math.min(b, Math.max(a, x));
}

function _netmonBinarySearchByT(arr, t){
  const target = Number(t) || 0;
  let lo = 0;
  let hi = arr.length;
  while(lo < hi){
    const mid = (lo + hi) >> 1;
    const mt = Number(arr[mid] && arr[mid].t ? arr[mid].t : 0);
    if(mt < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function _netmonLTTB(data, threshold){
  // Largest-Triangle-Three-Buckets downsampling
  // data: array of {t, v} sorted by t
  const n = Array.isArray(data) ? data.length : 0;
  const th = Math.max(3, Math.floor(Number(threshold) || 0));
  if(!n || th >= n) return data;

  const sampled = [];
  const every = (n - 2) / (th - 2);
  let a = 0;
  sampled.push(data[a]);

  for(let i=0;i<th-2;i++){
    const avgRangeStart = Math.floor((i + 1) * every) + 1;
    let avgRangeEnd = Math.floor((i + 2) * every) + 1;
    if(avgRangeEnd > n) avgRangeEnd = n;

    // average of next bucket
    let avgX = 0;
    let avgY = 0;
    let avgLen = avgRangeEnd - avgRangeStart;
    if(avgLen <= 0) avgLen = 1;

    for(let j=avgRangeStart;j<avgRangeEnd;j++){
      avgX += Number(data[j].t);
      avgY += Number(data[j].v);
    }
    avgX /= avgLen;
    avgY /= avgLen;

    const rangeOffs = Math.floor(i * every) + 1;
    let rangeTo = Math.floor((i + 1) * every) + 1;
    if(rangeTo > n - 1) rangeTo = n - 1;

    const ax = Number(data[a].t);
    const ay = Number(data[a].v);

    let maxArea = -1;
    let maxIdx = rangeOffs;

    for(let j=rangeOffs;j<rangeTo;j++){
      const bx = Number(data[j].t);
      const by = Number(data[j].v);
      const area = Math.abs((ax - avgX) * (by - ay) - (ax - bx) * (avgY - ay));
      if(area > maxArea){
        maxArea = area;
        maxIdx = j;
      }
    }

    sampled.push(data[maxIdx]);
    a = maxIdx;
  }

  sampled.push(data[n - 1]);
  return sampled;
}

class NetMonChart{
  constructor(card, monitorId){
    this.card = card;
    this.monitorId = String(monitorId || '');
    this.canvas = card.querySelector('canvas.netmon-canvas');
    this.ctx = this.canvas ? this.canvas.getContext('2d') : null;
    this.navCanvas = card.querySelector('canvas.netmon-nav-canvas');
    this.navCtx = this.navCanvas ? this.navCanvas.getContext('2d') : null;
    this.legendEl = card.querySelector('.netmon-legend');
    this.statsEl = card.querySelector('.netmon-stats');
    this.tooltipEl = card.querySelector('.netmon-tooltip');
    this.eventsBar = card.querySelector('.netmon-events-bar');
    this.eventsBadges = card.querySelector('.netmon-events-badges');
    this.eventsOpenBtn = card.querySelector('button.netmon-events-open');
    this.eventsFoot = card.querySelector('.netmon-events-foot');
    this.realtimeBtn = card.querySelector('.netmon-realtime-btn');
    this.fullBtn = card.querySelector('button.netmon-full');

    this.hiddenNodes = _netmonLoadHidden(this.monitorId);

    // current computed status level (for filters)
    this.level = 'none';

    // view state
    this.viewMode = 'follow'; // 'follow' | 'fixed'
    this.spanMs = null;       // follow mode span
    this.fixed = { xMin: null, xMax: null };

    // interaction state
    this.layout = null;
    this.hover = null;
    this.drag = { active:false, pointerId:null, startX:0, startY:0, startRange:null, moved:false, mode:'pan', prevView:null };

    this.navLayout = null;
    this.navDrag = { active:false, pointerId:null, mode:'move', startX:0, startRange:null, moved:false };
    this._raf = null;

    // cached UI fragments
    this._statsKey = '';
    this._eventsKey = '';
    this._legendClickTimer = null;
    // Prevent double-trigger on mobile (pointerup + click)
    this._evtTapTs = 0;

    this._bindEvents();
  }

  _bindEvents(){
    if(this.legendEl){
      this.legendEl.addEventListener('click', (e)=>{
        const item = e.target && e.target.closest ? e.target.closest('.netmon-legend-item') : null;
        if(!item) return;

        const action = item.getAttribute('data-action');
        if(action === 'showall'){
          e.preventDefault();
          this.showAllNodes();
          return;
        }

        const nid = item.getAttribute('data-nid');
        if(!nid) return;
        e.preventDefault();

        // Power-user: Shift+click = solo (only show this node)
        if(e.shiftKey){
          this.soloNode(nid);
          return;
        }

        // Single click toggles hide/show, double click solos.
        // Use a short delay so dblclick won't flicker.
        const clickCount = Number(e.detail || 1);
        if(clickCount >= 2){
          if(this._legendClickTimer){
            clearTimeout(this._legendClickTimer);
            this._legendClickTimer = null;
          }
          this.soloNode(nid);
          return;
        }

        if(this._legendClickTimer){
          clearTimeout(this._legendClickTimer);
          this._legendClickTimer = null;
        }
        this._legendClickTimer = setTimeout(()=>{
          this._legendClickTimer = null;
          this.toggleNode(nid);
        }, 220);
      });
    }

    if(this.realtimeBtn){
      this.realtimeBtn.addEventListener('click', (e)=>{
        e.preventDefault();
        this.resetView();
      });
    }

    const _evtMarkTap = ()=>{
      try{ this._evtTapTs = Date.now(); }catch(_e){}
    };
    const _evtRecentlyTapped = ()=>{
      try{ return (Date.now() - (this._evtTapTs || 0)) < 380; }catch(_e){ return false; }
    };

    // Abnormal events timeline: click/tap to jump into that segment
    if(this.eventsBar){
      // Mobile: pointerup is more responsive than click. We still keep click as fallback.
      this.eventsBar.addEventListener('pointerup', (e)=>{
        const seg = e.target && e.target.closest ? e.target.closest('.netmon-event') : null;
        if(!seg) return;
        const from = Number(seg.getAttribute('data-from'));
        const to = Number(seg.getAttribute('data-to'));
        if(Number.isFinite(from) && Number.isFinite(to) && to > from){
          e.preventDefault();
          _evtMarkTap();
          // Default: open the abnormal center modal (show all events, focus this segment)
          // Power-user: hold Shift/Alt/Meta to directly jump the chart to this range.
          if(e.shiftKey || e.altKey || e.metaKey){
            this.jumpToRange(from, to);
          }else{
            this.openAbModal(from, to);
          }
        }
      });

      this.eventsBar.addEventListener('click', (e)=>{
        if(_evtRecentlyTapped()) return;
        const seg = e.target && e.target.closest ? e.target.closest('.netmon-event') : null;
        if(!seg) return;
        const from = Number(seg.getAttribute('data-from'));
        const to = Number(seg.getAttribute('data-to'));
        if(Number.isFinite(from) && Number.isFinite(to) && to > from){
          e.preventDefault();
          _evtMarkTap();
          // Shift/Alt/Meta: open diagnosis detail modal
          // Default: open the abnormal center modal (show all events, focus this segment)
          // Power-user: hold Shift/Alt/Meta to directly jump the chart to this range.
          if(e.shiftKey || e.altKey || e.metaKey){
            this.jumpToRange(from, to);
          }else{
            this.openAbModal(from, to);
          }
        }
      });
    }


    // Abnormal center: open a single modal that lists ALL abnormal segments in current window
    const _openAbCenter = (e)=>{
      try{ if(e) e.preventDefault(); }catch(_e){}
      _evtMarkTap();
      try{ this.openAbModal(null, null); }catch(_e){}
    };

    if(this.eventsOpenBtn){
      this.eventsOpenBtn.addEventListener('pointerup', (e)=>{ _openAbCenter(e); });
      this.eventsOpenBtn.addEventListener('click', (e)=>{ if(_evtRecentlyTapped()) return; _openAbCenter(e); });
    }

    if(this.eventsFoot){
      this.eventsFoot.addEventListener('pointerup', (e)=>{ 
        const el = e.target && e.target.closest ? e.target.closest('[data-action="openab"]') : null;
        if(!el) return;
        _openAbCenter(e);
      });
      this.eventsFoot.addEventListener('click', (e)=>{ 
        if(_evtRecentlyTapped()) return;
        const el = e.target && e.target.closest ? e.target.closest('[data-action="openab"]') : null;
        if(!el) return;
        _openAbCenter(e);
      });
    }

    if(this.canvas){
      this.canvas.addEventListener('wheel', (e)=>this._onWheel(e), {passive:false});
      this.canvas.addEventListener('pointerdown', (e)=>this._onPointerDown(e));
      this.canvas.addEventListener('pointermove', (e)=>this._onPointerMove(e));
      this.canvas.addEventListener('pointerup', (e)=>this._onPointerUp(e));
      this.canvas.addEventListener('pointercancel', (e)=>this._onPointerUp(e));
      this.canvas.addEventListener('mouseleave', ()=>this._onMouseLeave());
      this.canvas.addEventListener('dblclick', (e)=>{ e.preventDefault(); this.resetView(); });
    }

    if(this.navCanvas){
      this.navCanvas.addEventListener('pointerdown', (e)=>this._onNavPointerDown(e));
      this.navCanvas.addEventListener('pointermove', (e)=>this._onNavPointerMove(e));
      this.navCanvas.addEventListener('pointerup', (e)=>this._onNavPointerUp(e));
      this.navCanvas.addEventListener('pointercancel', (e)=>this._onNavPointerUp(e));
      this.navCanvas.addEventListener('mouseleave', ()=>this._onNavMouseLeave());
      this.navCanvas.addEventListener('dblclick', (e)=>{ e.preventDefault(); this.resetView(); });
    }
  }

  toggleNode(nid){
    const id = String(nid);
    if(this.hiddenNodes.has(id)) this.hiddenNodes.delete(id);
    else this.hiddenNodes.add(id);
    _netmonSaveHidden(this.monitorId, this.hiddenNodes);
    this.hover = null;
    this._hideTooltip();
    this._syncHistoryUI();
    this._scheduleRender(true);
  }

  showAllNodes(){
    if(!this.hiddenNodes || this.hiddenNodes.size === 0) return;
    this.hiddenNodes.clear();
    _netmonSaveHidden(this.monitorId, this.hiddenNodes);
    this.hover = null;
    this._hideTooltip();
    this._scheduleRender(true);
  }

  soloNode(nid){
    const id = String(nid);
    const st = NETMON_STATE;
    const mon = st && st.monitorsMap ? st.monitorsMap[this.monitorId] : null;
    const nodeIds = Array.isArray(mon && mon.node_ids) ? mon.node_ids.map(x=>String(x)) : [];
    if(!nodeIds.length) return;
    if(!nodeIds.includes(id)) return;

    const visible = nodeIds.filter(x=>!this.hiddenNodes.has(String(x)));
    const alreadySolo = (visible.length === 1 && String(visible[0]) === id);

    if(alreadySolo){
      this.hiddenNodes.clear();
    }else{
      const next = new Set();
      nodeIds.forEach((x)=>{ if(String(x) !== id) next.add(String(x)); });
      this.hiddenNodes = next;
    }

    _netmonSaveHidden(this.monitorId, this.hiddenNodes);
    this.hover = null;
    this._hideTooltip();
    this._scheduleRender(true);
  }

  toggleFullscreen(){
    if(!this.card) return;
    const on = !this.card.classList.contains('netmon-fullscreen');
    if(on){
      // ensure only one fullscreen chart
      try{ _netmonExitFullscreenAll(); }catch(_e){}
      _netmonEnsureFsBackdrop();
      try{ document.body.classList.add('netmon-noscroll'); }catch(_e){}
    }
    this.setFullscreen(on);
  }

  setFullscreen(on, opts){
    if(!this.card) return;
    const enable = !!on;
    this.card.classList.toggle('netmon-fullscreen', enable);
    if(this.fullBtn) this.fullBtn.textContent = enable ? '退出全屏' : '全屏';

    if(!enable && !(opts && opts.skipGlobal)){
      // if no more fullscreen charts, remove backdrop
      const any = document.querySelector('.netmon-chart-card.netmon-fullscreen');
      if(!any){
        _netmonRemoveFsBackdrop();
        try{ document.body.classList.remove('netmon-noscroll'); }catch(_e){}
      }
    }

    // force re-layout
    this._scheduleRender(true);
  }

  getShareUrl(){
    const st = NETMON_STATE;
    // Share as a dedicated read-only display page
    const url = new URL(window.location.origin + '/netmon/view');

    url.searchParams.set('ro', '1');
    // Minimal/kiosk UI for external viewers by default
    url.searchParams.set('kiosk', '1');

    // Keep query with shared view state
    url.searchParams.set('mid', String(this.monitorId));
    if(st && st.windowMin) url.searchParams.set('win', String(st.windowMin));

    // series visibility
    if(this.hiddenNodes && this.hiddenNodes.size > 0){
      url.searchParams.set('hidden', Array.from(this.hiddenNodes).map(x=>String(x)).join(','));
    }else{
      url.searchParams.delete('hidden');
    }

    if(this.viewMode === 'fixed' && this.fixed.xMin != null && this.fixed.xMax != null){
      url.searchParams.set('mode', 'fixed');
      url.searchParams.set('from', String(Math.round(Number(this.fixed.xMin))));
      url.searchParams.set('to', String(Math.round(Number(this.fixed.xMax))));
      url.searchParams.delete('span');
    }else{
      url.searchParams.set('mode', 'follow');
      const span = (this.spanMs != null) ? Number(this.spanMs) : ((st && st.windowSec) ? (Number(st.windowSec) * 1000) : (10*60*1000));
      url.searchParams.set('span', String(Math.round(span)));
      url.searchParams.delete('from');
      url.searchParams.delete('to');
    }

    // Keep server-side rollup selection in the link (optional)
    try{
      if(st && st.resolutionMs != null){
        url.searchParams.set('rollup_ms', String(Math.max(0, Math.round(Number(st.resolutionMs)||0))));
      }
    }catch(_e){}

    // If we're already on a share link, preserve its token for re-share.
    try{
      if(st && st.shareToken){
        url.searchParams.set('t', String(st.shareToken));
      }
    }catch(_e){}

    url.searchParams.set('v', '1');
    return url.toString();
  }

  getShareUrlForRange(from, to){
    // Share as a dedicated read-only display page (fixed range)
    const st = NETMON_STATE;
    const url = new URL(window.location.origin + '/netmon/view');
    url.searchParams.set('ro', '1');
    url.searchParams.set('kiosk', '1');
    url.searchParams.set('mid', String(this.monitorId));
    if(st && st.windowMin) url.searchParams.set('win', String(st.windowMin));
    if(this.hiddenNodes && this.hiddenNodes.size > 0){
      url.searchParams.set('hidden', Array.from(this.hiddenNodes).map(x=>String(x)).join(','));
    }
    url.searchParams.set('mode', 'fixed');
    url.searchParams.set('from', String(Math.round(Number(from) || 0)));
    url.searchParams.set('to', String(Math.round(Number(to) || 0)));
    url.searchParams.delete('span');
    // Keep server-side rollup selection in the link (optional)
    try{
      if(st && st.resolutionMs != null){
        url.searchParams.set('rollup_ms', String(Math.max(0, Math.round(Number(st.resolutionMs)||0))));
      }
    }catch(_e){}

    // If we're already on a share link, preserve its token for re-share.
    try{
      if(st && st.shareToken){
        url.searchParams.set('t', String(st.shareToken));
      }
    }catch(_e){}

    url.searchParams.set('v', '1');
    return url.toString();
  }

  async copyShareLinkForRange(from, to){
    const st = NETMON_STATE;
    let link = null;

    // Only copy/build locally when we are *already* on a shared read-only URL
    // (i.e. the token exists in the current URL). On the管理页, even if we
    // previously generated a token, the current URL usually has no `t=...`.
    // In that case we must call backend to generate a correct share link.
    let hasUrlToken = false;
    try{
      const p = new URLSearchParams(window.location.search || '');
      hasUrlToken = !!p.get('t');
    }catch(_e){ hasUrlToken = false; }

    if(hasUrlToken && st && st.shareToken){
      link = this.getShareUrlForRange(from, to);
    }else{
      // Request a signed token from backend (requires login)
      const payload = {
        page: 'view',
        mid: Number(this.monitorId),
        mode: 'fixed',
        from: Math.round(Number(from) || 0),
        to: Math.round(Number(to) || 0),
        kiosk: 1,
      };

      try{
        if(st && st.windowMin) payload.win = Number(st.windowMin) || 10;
        if(this.hiddenNodes && this.hiddenNodes.size > 0){
          payload.hidden = Array.from(this.hiddenNodes).map(x=>String(x));
        }
        if(st && st.resolutionMs != null) payload.rollup_ms = Math.max(0, Math.round(Number(st.resolutionMs)||0));
      }catch(_e){}

      try{
        const res = await fetchJSON('/api/netmon/share', {method:'POST', body: JSON.stringify(payload)});
        link = (res && res.url) ? String(res.url) : null;
        if(!link) throw new Error((res && res.error) ? String(res.error) : 'share_failed');
      }catch(e){
        const msg = (e && e.message) ? e.message : String(e);
        toast(`生成分享链接失败：${msg}（请刷新/重新登录）`, true);
        return;
      }
    }

    try{
      if(navigator.clipboard && navigator.clipboard.writeText){
        await navigator.clipboard.writeText(link);
      }else{
        throw new Error('clipboard unavailable');
      }
      toast('已复制只读链接');
    }catch(_e){
      // fallback
      try{
        const ta = document.createElement('textarea');
        ta.value = link;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        toast('已复制只读链接');
      }catch(e2){
        prompt('复制只读链接：', link);
      }
    }
  }

  async copyShareLink(){
    const st = NETMON_STATE;
    let link = null;

    // Only copy current URL when it is *already* a share URL (contains t=...).
    // Avoid accidentally copying /netmon (管理页) which always requires login.
    let hasUrlToken = false;
    try{
      const p = new URLSearchParams(window.location.search || '');
      hasUrlToken = !!p.get('t');
    }catch(_e){ hasUrlToken = false; }

    if(hasUrlToken){
      link = window.location.href;
    }else{
      // Request a signed share URL from backend (requires login)
      const payload = { page: 'view', mid: Number(this.monitorId), kiosk: 1 };

      try{
        if(st && st.windowMin) payload.win = Number(st.windowMin) || 10;
        if(this.hiddenNodes && this.hiddenNodes.size > 0){
          payload.hidden = Array.from(this.hiddenNodes).map(x=>String(x));
        }
        if(st && st.resolutionMs != null) payload.rollup_ms = Math.max(0, Math.round(Number(st.resolutionMs)||0));
      }catch(_e){}

      // Preserve current view mode
      try{
        if(this.viewMode === 'fixed' && this.fixed && this.fixed.xMin != null && this.fixed.xMax != null){
          payload.mode = 'fixed';
          payload.from = Math.round(Number(this.fixed.xMin) || 0);
          payload.to = Math.round(Number(this.fixed.xMax) || 0);
        }else{
          payload.mode = 'follow';
          if(this.spanMs != null) payload.span = Math.round(Number(this.spanMs) || 0);
        }
      }catch(_e){}

      try{
        const res = await fetchJSON('/api/netmon/share', {method:'POST', body: JSON.stringify(payload)});
        link = (res && res.url) ? String(res.url) : null;
        if(!link) throw new Error((res && res.error) ? String(res.error) : 'share_failed');
      }catch(e){
        const msg = (e && e.message) ? e.message : String(e);
        toast(`生成分享链接失败：${msg}（请刷新/重新登录）`, true);
        return;
      }
    }

    try{
      if(navigator.clipboard && navigator.clipboard.writeText){
        await navigator.clipboard.writeText(link);
      }else{
        throw new Error('clipboard unavailable');
      }
      toast('已复制分享链接');
    }catch(_e){
      // fallback
      try{
        const ta = document.createElement('textarea');
        ta.value = link;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        toast('已复制分享链接');
      }catch(e2){
        prompt('复制分享链接：', link);
      }
    }
  }

  exportPNG(){
    try{
      const st = NETMON_STATE;
      const mon = (st && st.monitorsMap) ? st.monitorsMap[String(this.monitorId)] : null;
      const target = mon ? String(mon.target || ('monitor-' + this.monitorId)) : ('monitor-' + this.monitorId);

      if(!this.canvas) return;

      const w = Math.max(200, this.canvas.clientWidth || 0);
      const hMain = Math.max(140, this.canvas.clientHeight || 0);
      const hNav = (this.navCanvas ? Math.max(28, this.navCanvas.clientHeight || 0) : 0);
      const topPad = 44;
      const gap = hNav ? 10 : 0;
      const botPad = 14;

      const srcDpr = (this.canvas.width && w) ? (this.canvas.width / w) : (window.devicePixelRatio || 1);
      const outH = topPad + hMain + gap + hNav + botPad;

      const out = document.createElement('canvas');
      out.width = Math.floor(w * srcDpr);
      out.height = Math.floor(outH * srcDpr);
      const ctx = out.getContext('2d');
      if(!ctx) return;

      ctx.setTransform(srcDpr, 0, 0, srcDpr, 0, 0);

      // background (match card background as much as possible)
      let bg = 'rgba(2,6,23,0.96)';
      try{
        const cs = getComputedStyle(this.card);
        if(cs && cs.backgroundColor) bg = cs.backgroundColor;
      }catch(_e){}
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, w, outH);

      // title
      ctx.fillStyle = 'rgba(226,232,240,0.95)';
      ctx.font = '700 14px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(target, 12, 10);

      // subtitle: time range / mode
      const range = this._currentRange();
      const left = _netmonFormatTs(range.xMin);
      const right = _netmonFormatTs(range.xMax);
      const modeTxt = (this.viewMode === 'fixed') ? '历史' : '实时';
      ctx.fillStyle = 'rgba(148,163,184,0.95)';
      ctx.font = '12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';
      ctx.fillText(`${modeTxt} · ${left} ~ ${right}`, 12, 26);

      // draw canvases
      ctx.drawImage(this.canvas, 0, topPad, w, hMain);
      if(this.navCanvas && hNav){
        ctx.drawImage(this.navCanvas, 0, topPad + hMain + gap, w, hNav);
      }

      // watermark
      ctx.fillStyle = 'rgba(148,163,184,0.55)';
      ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'bottom';
      const stamp = new Date().toLocaleString();
      ctx.fillText(stamp, w - 10, outH - 6);

      const dataUrl = out.toDataURL('image/png');
      const name = `netmon_${_netmonSanitizeFilename(target)}_${Date.now()}.png`;

      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      toast('已导出 PNG');
    }catch(e){
      toast('导出失败：' + ((e && e.message) ? e.message : String(e)), true);
    }
  }

  resetView(){
    const st = NETMON_STATE;
    this.viewMode = 'follow';
    this.fixed.xMin = null;
    this.fixed.xMax = null;
    if(st && st.windowSec){
      this.spanMs = Number(st.windowSec) * 1000;
    }else if(st){
      this.spanMs = (Number(st.windowMin || 10) * 60 * 1000);
    }else{
      this.spanMs = null;
    }
    this.hover = null;
    this._hideTooltip();
    this._syncHistoryUI();
    this._scheduleRender(true);
  }

  jumpToRange(fromTs, toTs){
    const st = NETMON_STATE;
    let a = Number(fromTs);
    let b = Number(toTs);
    if(!Number.isFinite(a) || !Number.isFinite(b) || b <= a) return;

    const span = Math.max(1000, b - a);
    // Add a little context on both sides (capped)
    const pad = Math.min(span * 0.22, 8 * 60 * 1000);
    a = a - pad;
    b = b + pad;

    const loadedMin = (st && st.cutoffMs != null) ? Number(st.cutoffMs) : null;
    const loadedMax = (st && st.lastTs != null) ? Number(st.lastTs) : Date.now();

    if(loadedMin != null && Number.isFinite(loadedMin)) a = Math.max(a, loadedMin);
    if(loadedMax != null && Number.isFinite(loadedMax)) b = Math.min(b, loadedMax);
    if(b <= a) return;

    const clamped = this._clampRange(a, b, (loadedMin != null ? loadedMin : a), (loadedMax != null ? loadedMax : b));

    this.viewMode = 'fixed';
    this.fixed.xMin = clamped.xMin;
    this.fixed.xMax = clamped.xMax;
    this.hover = null;
    this._hideTooltip();
    this._syncHistoryUI();
    this._scheduleRender(true);
  }

  openAbModal(focusFromTs, focusToTs){
    const st = NETMON_STATE;
    const mon = (st && st.monitorsMap) ? st.monitorsMap[String(this.monitorId)] : null;
    const target = mon ? String(mon.target || ('monitor-' + this.monitorId)) : ('monitor-' + this.monitorId);

    // Prefer the last events-scan range; fallback to current visible range
    let xMin = (this._eventsXMin != null) ? Number(this._eventsXMin) : null;
    let xMax = (this._eventsXMax != null) ? Number(this._eventsXMax) : null;
    if(!Number.isFinite(xMin) || !Number.isFinite(xMax)){
      try{
        const r = this._currentRange();
        xMin = (r && r.xMin != null) ? Number(r.xMin) : null;
        xMax = (r && r.xMax != null) ? Number(r.xMax) : null;
      }catch(_e){}
    }

    const events = Array.isArray(this._eventsAll) ? this._eventsAll : [];
    try{
      _netmonOpenAbModal({
        mid: this.monitorId,
        target,
        events,
        xMin,
        xMax,
        focusFrom: focusFromTs,
        focusTo: focusToTs,
      });
    }catch(e){
      toast('打开异常窗口失败：' + ((e && e.message) ? e.message : String(e)), true);
    }
  }


  async openEventDetail(fromTs, toTs){
    const from = Number(fromTs);
    const to = Number(toTs);
    if(!Number.isFinite(from) || !Number.isFinite(to) || to <= from) return;

    // New UX: route to the Abnormal Center modal (one window shows all abnormal segments)
    try{ this.openAbModal(from, to); }catch(_e){}
    return;

    const modal = _netmonEnsureEventModal();
    if(!modal) return;

    NETMON_EVENT_MODAL_CTX = {mid: this.monitorId, from, to};
    modal.style.display = '';

    const titleEl = modal.querySelector ? modal.querySelector('#netmonEvtTitle') : null;
    const bodyEl = modal.querySelector ? modal.querySelector('#netmonEvtBody') : null;
    const h2El = modal.querySelector ? modal.querySelector('#netmonEvtH2') : null;

    const st = NETMON_STATE;
    const mon = (st && st.monitorsMap) ? st.monitorsMap[String(this.monitorId)] : null;
    const target = mon ? String(mon.target || ('monitor-' + this.monitorId)) : ('monitor-' + this.monitorId);

    if(h2El) h2El.textContent = '异常详情';
    if(titleEl) titleEl.textContent = `${target} · ${_netmonFormatTs(from)} ~ ${_netmonFormatTs(to)} · ${_netmonFormatDur(to - from)}`;
    if(bodyEl) bodyEl.innerHTML = `<div class="muted sm">加载中…</div>`;

    try{
      let url = `/api/netmon/range?mid=${encodeURIComponent(String(this.monitorId))}&from=${encodeURIComponent(String(Math.round(from)))}&to=${encodeURIComponent(String(Math.round(to)))}`;
      try{ if(st && st.shareToken){ url += `&t=${encodeURIComponent(String(st.shareToken))}`; } }catch(_e){}
      const res = await fetchJSON(url);
      if(!res || res.ok === false){
        throw new Error(res && res.error ? res.error : '加载失败');
      }

      const mInfo = res.monitor || mon || {};
      const nodesMeta = (res.nodes && typeof res.nodes === 'object') ? res.nodes : (st ? st.nodesMeta : {});
      const series = (res.series && typeof res.series === 'object') ? res.series : {};

      let warnThr = Number(mInfo.warn_ms) || 0;
      let critThr = Number(mInfo.crit_ms) || 0;
      if(warnThr > 0 && critThr > 0 && warnThr > critThr){
        const tmp = warnThr; warnThr = critThr; critThr = tmp;
      }

      const nodeIdsRaw = Array.isArray(mInfo.node_ids) ? mInfo.node_ids : Object.keys(series);
      const nodeIds = [];
      for(const nid of nodeIdsRaw){
        const s = String(nid);
        if(!nodeIds.includes(s)) nodeIds.push(s);
      }
      for(const k of Object.keys(series)){
        const s = String(k);
        if(!nodeIds.includes(s)) nodeIds.push(s);
      }

      const stats = [];
      let gMax = null;
      let gMaxNid = null;
      let gVals = [];
      let gTotal = 0;
      let gFail = 0;

      for(const nid of nodeIds){
        const pts = Array.isArray(series[nid]) ? series[nid] : [];
        let vals = [];
        let total = 0;
        let fail = 0;
        let lastOk = null;
        for(const p of pts){
          if(!p) continue;
          total += 1;
          gTotal += 1;
          if(p.ok){
            const v = Number(p.v);
            if(Number.isFinite(v)){
              vals.push(v);
              gVals.push(v);
              lastOk = v;
              if(gMax == null || v > gMax){
                gMax = v;
                gMaxNid = nid;
              }
            }
          }else{
            fail += 1;
            gFail += 1;
          }
        }

        const okCnt = vals.length;
        const maxV = okCnt ? Math.max(...vals) : null;
        let avgV = null;
        if(okCnt){
          let sum = 0;
          for(const v of vals) sum += v;
          avgV = sum / okCnt;
        }
        let p95 = null;
        if(okCnt >= 3){
          const sorted = vals.slice().sort((a,b)=>a-b);
          const idx = Math.min(sorted.length - 1, Math.floor(0.95 * (sorted.length - 1)));
          p95 = sorted[idx];
        }else if(okCnt > 0){
          p95 = maxV;
        }
        const failRate = total > 0 ? (fail / total) : 0;

        let sev = 0;
        if(failRate >= 0.5) sev = 2;
        else if(critThr > 0 && maxV != null && maxV >= critThr) sev = 2;
        else if(warnThr > 0 && maxV != null && maxV >= warnThr) sev = 1;
        else if(failRate > 0) sev = 1;

        let nm = '节点-' + nid;
        let online = null;
        try{
          if(nodesMeta && nodesMeta[nid]){
            nm = String(nodesMeta[nid].name || nodesMeta[nid].display_ip || nm);
            online = !!nodesMeta[nid].online;
          }
        }catch(_e){}

        stats.push({nid, name: nm, online, total, fail, failRate, okCnt, maxV, avgV, p95, lastOk, sev});
      }

      const totNodes = stats.length;
      const impacted = stats.filter(s=>s.sev > 0).length;
      const impactedRatio = totNodes ? (impacted / totNodes) : 0;
      const failRateAll = gTotal ? (gFail / gTotal) : 0;

      let p95All = null;
      if(gVals.length){
        const sortedAll = gVals.slice().sort((a,b)=>a-b);
        const idx = Math.min(sortedAll.length - 1, Math.floor(0.95 * (sortedAll.length - 1)));
        p95All = sortedAll[idx];
      }

      let hintCls = 'info';
      let hint = '';
      if(impactedRatio >= 0.7 && (failRateAll >= 0.2 || (critThr > 0 && gMax != null && gMax >= critThr))){
        hintCls = 'crit';
        hint = '全局异常：多节点同时超阈/失败，疑似目标侧/公网链路波动。';
      }else if(impactedRatio <= 0.25 && impacted > 0){
        hintCls = 'warn';
        hint = '局部异常：少数节点异常，疑似单节点出口/单线路问题。';
      }else if(impactedRatio >= 0.7 && impacted > 0){
        hintCls = 'warn';
        hint = '多节点受影响：可能是区域性链路抖动或目标端拥塞。';
      }else if(impacted > 0){
        hintCls = 'warn';
        hint = '部分节点受影响：建议对比异常节点的出口/ISP/路由。';
      }else{
        hintCls = 'ok';
        hint = '该区间未检测到明显异常（可能阈值较高或数据不足）。';
      }

      let maxNodeName = '';
      try{
        if(gMaxNid && nodesMeta && nodesMeta[String(gMaxNid)]){
          maxNodeName = String(nodesMeta[String(gMaxNid)].name || '');
        }
      }catch(_e){}
      if(!maxNodeName && gMaxNid) maxNodeName = '节点-' + gMaxNid;

      const kpi = [];
      kpi.push(`<span class="netmon-pill ${hintCls}"><span class="k">影响节点</span><span class="v">${impacted}/${totNodes || 0}</span></span>`);
      if(gMax != null){
        const maxTxt = `${Number(gMax).toFixed(1)}ms`;
        kpi.push(`<span class="netmon-pill ${hintCls}"><span class="k">峰值</span><span class="v">${escapeHtml(maxTxt)}${maxNodeName ? (' · ' + escapeHtml(maxNodeName)) : ''}</span></span>`);
      }
      if(p95All != null){
        kpi.push(`<span class="netmon-pill"><span class="k">P95</span><span class="v">${Number(p95All).toFixed(1)}ms</span></span>`);
      }
      if(gTotal > 0){
        kpi.push(`<span class="netmon-pill ${failRateAll>0 ? 'warn' : 'ok'}"><span class="k">失败率</span><span class="v">${Math.round(failRateAll*100)}% (${gFail}/${gTotal})</span></span>`);
      }
      if(warnThr > 0) kpi.push(`<span class="netmon-pill warn"><span class="k">Warn</span><span class="v">${warnThr}ms</span></span>`);
      if(critThr > 0) kpi.push(`<span class="netmon-pill crit"><span class="k">Crit</span><span class="v">${critThr}ms</span></span>`);

      stats.sort((a,b)=>{
        if(a.sev !== b.sev) return b.sev - a.sev;
        const am = (a.maxV != null) ? a.maxV : -1;
        const bm = (b.maxV != null) ? b.maxV : -1;
        if(am !== bm) return bm - am;
        return (b.failRate || 0) - (a.failRate || 0);
      });

      let table = `<div class="table-wrap"><table class="table netmon-evt-table"><thead><tr>
        <th style="width:220px;">节点</th>
        <th>最大</th>
        <th>平均</th>
        <th>P95</th>
        <th>失败率</th>
        <th>样本</th>
      </tr></thead><tbody>`;

      for(const s of stats){
        const rowCls = (s.sev >= 2) ? 'crit' : ((s.sev >= 1) ? 'warn' : '');
        const maxTxt = (s.maxV != null && Number.isFinite(s.maxV)) ? `${s.maxV.toFixed(1)}ms` : '—';
        const avgTxt = (s.avgV != null && Number.isFinite(s.avgV)) ? `${s.avgV.toFixed(1)}ms` : '—';
        const p95Txt = (s.p95 != null && Number.isFinite(s.p95)) ? `${s.p95.toFixed(1)}ms` : '—';
        const frTxt = (s.total > 0) ? `${Math.round(s.failRate*100)}%` : '—';
        const smpTxt = `${s.total || 0}`;
        const dotCls = (s.online === null) ? 'offline' : (s.online ? 'online' : 'offline');
        const nm = escapeHtml(String(s.name || ('节点-' + s.nid)));
        let maxClass = '';
        if(s.sev >= 2) maxClass = 'bad';
        else if(s.sev >= 1) maxClass = 'warnc';

        table += `<tr class="${rowCls}">
          <td><span class="n-dot ${dotCls}" aria-hidden="true"></span><span class="mono">${nm}</span></td>
          <td class="${maxClass} mono">${escapeHtml(maxTxt)}</td>
          <td class="mono">${escapeHtml(avgTxt)}</td>
          <td class="mono">${escapeHtml(p95Txt)}</td>
          <td class="mono">${escapeHtml(frTxt)}</td>
          <td class="mono muted">${escapeHtml(smpTxt)}</td>
        </tr>`;
      }
      table += `</tbody></table></div>`;

      const hintHtml = `<div class="netmon-evt-hint"><strong>${escapeHtml(hint)}</strong></div>`;
      const html = `${hintHtml}<div class="netmon-evt-kpis">${kpi.join('')}</div><div style="margin-top:10px;">${table}</div>`;

      if(bodyEl) bodyEl.innerHTML = html;
      NETMON_EVENT_MODAL_CTX = {mid: this.monitorId, from, to};
    }catch(e){
      const msg = (e && e.message) ? e.message : String(e);
      if(bodyEl) bodyEl.innerHTML = `<div class="muted" style="color:var(--bad);">加载失败：${escapeHtml(msg)}</div>`;
    }
  }

  _syncHistoryUI(){
    if(this.realtimeBtn){
      const show = (this.viewMode === 'fixed');
      this.realtimeBtn.style.display = show ? '' : 'none';
    }
    if(this.card){
      this.card.classList.toggle('netmon-history', this.viewMode === 'fixed');
    }
  }

  _applyViewState(v){
    if(!v) return;
    this.viewMode = (v.viewMode === 'fixed') ? 'fixed' : 'follow';
    if(v.spanMs != null) this.spanMs = v.spanMs;
    if(v.fixed && v.fixed.xMin != null && v.fixed.xMax != null){
      this.fixed.xMin = v.fixed.xMin;
      this.fixed.xMax = v.fixed.xMax;
    }else{
      this.fixed.xMin = null;
      this.fixed.xMax = null;
    }
  }

  _scheduleRender(force){
    if(this._raf) return;
    this._raf = requestAnimationFrame(()=>{
      this._raf = null;
      try{ this.render(force); }catch(_e){}
    });
  }

  _getPos(e){
    if(!this.canvas) return null;
    const rect = this.canvas.getBoundingClientRect();
    const x = (e.clientX || 0) - rect.left;
    const y = (e.clientY || 0) - rect.top;
    return {x, y, rect};
  }

  _inPlot(x, y){
    if(!this.layout) return false;
    return x >= this.layout.padL && x <= (this.layout.padL + this.layout.plotW)
      && y >= this.layout.padT && y <= (this.layout.padT + this.layout.plotH);
  }

  _loadedRange(st){
    const now = (st && st.lastTs) ? Number(st.lastTs) : Date.now();
    let minMs = (st && st.cutoffMs) ? Number(st.cutoffMs) : null;
    const fallbackSpan = (st && st.windowSec) ? (Number(st.windowSec) * 1000) : (Number((st && st.windowMin) ? st.windowMin : 10) * 60 * 1000);
    if(minMs == null || !Number.isFinite(minMs) || minMs <= 0){
      minMs = now - fallbackSpan;
    }
    const maxMs = now;
    const spanMs = Math.max(1, maxMs - minMs);
    return {minMs, maxMs, spanMs};
  }

  _clampRange(xMin, xMax, minAllowed, maxAllowed){
    let a = Number(xMin);
    let b = Number(xMax);
    if(!Number.isFinite(a) || !Number.isFinite(b) || b <= a){
      a = minAllowed;
      b = maxAllowed;
    }

    let span = b - a;
    const maxSpan = maxAllowed - minAllowed;
    if(span > maxSpan){
      span = maxSpan;
      a = minAllowed;
      b = maxAllowed;
    }

    if(a < minAllowed){
      a = minAllowed;
      b = a + span;
    }
    if(b > maxAllowed){
      b = maxAllowed;
      a = b - span;
    }

    if(a < minAllowed) a = minAllowed;
    if(b > maxAllowed) b = maxAllowed;
    if(b <= a){
      a = minAllowed;
      b = maxAllowed;
    }
    return {xMin:a, xMax:b};
  }

  _currentRange(){
    const st = NETMON_STATE;
    const loaded = this._loadedRange(st);
    const loadedSpan = loaded.spanMs;

    if(this.viewMode === 'fixed' && this.fixed.xMin != null && this.fixed.xMax != null){
      const r = this._clampRange(this.fixed.xMin, this.fixed.xMax, loaded.minMs, loaded.maxMs);
      this.fixed.xMin = r.xMin;
      this.fixed.xMax = r.xMax;
      return r;
    }

    // follow latest
    let span = (this.spanMs != null) ? Number(this.spanMs) : loadedSpan;
    span = _netmonClamp(span, 10000, loadedSpan); // 10s - loaded window
    this.spanMs = span;
    return {xMin: loaded.maxMs - span, xMax: loaded.maxMs};
  }

  _onWheel(e){
    if(!this.layout) return;
    const pos = this._getPos(e);
    if(!pos) return;
    if(!this._inPlot(pos.x, pos.y)) return;

    e.preventDefault();

    const st = NETMON_STATE;
    const loaded = this._loadedRange(st);
    const loadedSpan = loaded.spanMs;
    if(loadedSpan <= 0) return;

    // natural: wheel up -> zoom in; wheel down -> zoom out
    const factor = (e.deltaY < 0) ? 0.85 : 1.18;

    if(this.viewMode === 'follow'){
      let curSpan = (this.spanMs != null) ? Number(this.spanMs) : loadedSpan;
      let nextSpan = curSpan * factor;
      nextSpan = _netmonClamp(nextSpan, 10000, loadedSpan);
      this.spanMs = nextSpan;
    }else{
      // fixed: zoom around cursor
      const span = Math.max(1, this.layout.xMax - this.layout.xMin);
      let nextSpan = span * factor;
      nextSpan = _netmonClamp(nextSpan, 10000, loadedSpan);

      const tCursor = this.layout.xMin + ((pos.x - this.layout.padL) / this.layout.plotW) * span;

      let newMin = tCursor - (tCursor - this.layout.xMin) * (nextSpan / span);
      let newMax = newMin + nextSpan;
      const clamped = this._clampRange(newMin, newMax, loaded.minMs, loaded.maxMs);
      this.fixed.xMin = clamped.xMin;
      this.fixed.xMax = clamped.xMax;
    }

    this.hover = null;
    this._hideTooltip();
    this._syncHistoryUI();
    this._scheduleRender(true);
  }

  _onPointerDown(e){
    if(!this.layout) return;
    if(e.pointerType === 'mouse' && e.button !== 0) return;

    const pos = this._getPos(e);
    if(!pos) return;
    if(!this._inPlot(pos.x, pos.y)) return;

    try{ this.canvas.setPointerCapture(e.pointerId); }catch(_e){}

    const wantBox = !!(e.shiftKey);

    this.drag.active = true;
    this.drag.pointerId = e.pointerId;
    this.drag.startX = pos.x;
    this.drag.startY = pos.y;
    this.drag.moved = false;
    this.drag.mode = wantBox ? 'box' : 'pan';
    this.drag.prevView = null;

    this.hover = null;
    this._hideTooltip();

    if(wantBox){
      // Freeze current view so selection doesn't drift while data auto-refreshes
      const r = this._currentRange();
      this.drag.startRange = {xMin:r.xMin, xMax:r.xMax};
      this.drag.prevView = {
        viewMode: this.viewMode,
        spanMs: this.spanMs,
        fixed: {xMin: this.fixed.xMin, xMax: this.fixed.xMax},
      };

      this.viewMode = 'fixed';
      this.fixed.xMin = r.xMin;
      this.fixed.xMax = r.xMax;

      const x0 = _netmonClamp(pos.x, this.layout.padL, this.layout.padL + this.layout.plotW);
      const y0 = _netmonClamp(pos.y, this.layout.padT, this.layout.padT + this.layout.plotH);
      this.boxSel = {active:true, x0, y0, x1:x0, y1:y0};

      if(this.canvas) this.canvas.classList.add('is-boxing');
      this._syncHistoryUI();
      this._scheduleRender(false);
      return;
    }

    this.drag.startRange = this._currentRange();
    if(this.canvas) this.canvas.classList.add('is-dragging');
  }

  _onPointerMove(e){
    const pos = this._getPos(e);
    if(!pos) return;

    if(this.drag.active && this.drag.pointerId === e.pointerId){
      if(!this.layout) return;

      if(this.drag.mode === 'box'){
        if(!this.boxSel || !this.boxSel.active) return;

        const x = _netmonClamp(pos.x, this.layout.padL, this.layout.padL + this.layout.plotW);
        const y = _netmonClamp(pos.y, this.layout.padT, this.layout.padT + this.layout.plotH);

        this.boxSel.x1 = x;
        this.boxSel.y1 = y;

        const dx = x - this.boxSel.x0;
        const dy = y - this.boxSel.y0;
        if(Math.abs(dx) > 2 || Math.abs(dy) > 2) this.drag.moved = true;

        this._scheduleRender(false);
        return;
      }

      // pan
      if(!this.drag.startRange) return;

      const dx = pos.x - this.drag.startX;
      const dy = pos.y - this.drag.startY;
      if(Math.abs(dx) > 2 || Math.abs(dy) > 2) this.drag.moved = true;

      const span = Math.max(1, this.drag.startRange.xMax - this.drag.startRange.xMin);
      const dt = -(dx / this.layout.plotW) * span;

      const st = NETMON_STATE;
      const loaded = this._loadedRange(st);

      let newMin = this.drag.startRange.xMin + dt;
      let newMax = this.drag.startRange.xMax + dt;
      const clamped = this._clampRange(newMin, newMax, loaded.minMs, loaded.maxMs);

      // switch to history mode
      this.viewMode = 'fixed';
      this.fixed.xMin = clamped.xMin;
      this.fixed.xMax = clamped.xMax;
      this._syncHistoryUI();

      this._scheduleRender(false);
      return;
    }

    this._updateHover(pos.x, pos.y);
  }

  _onPointerUp(e){
    if(!this.drag.active) return;
    if(this.drag.pointerId !== e.pointerId) return;

    if(this.drag.mode === 'box'){
      const sel = (this.boxSel && this.boxSel.active) ? { ...this.boxSel } : null;
      const startRange = this.drag.startRange;
      const prevView = this.drag.prevView;

      if(this.canvas) this.canvas.classList.remove('is-boxing');
      if(this.boxSel) this.boxSel.active = false;

      let didZoom = false;

      if(this.drag.moved && sel && this.layout && startRange){
        const minX = Math.min(sel.x0, sel.x1);
        const maxX = Math.max(sel.x0, sel.x1);
        const w = maxX - minX;

        if(w >= 14){
          const span = Math.max(1, startRange.xMax - startRange.xMin);
          const r0 = _netmonClamp((minX - this.layout.padL) / this.layout.plotW, 0, 1);
          const r1 = _netmonClamp((maxX - this.layout.padL) / this.layout.plotW, 0, 1);

          let newMin = startRange.xMin + r0 * span;
          let newMax = startRange.xMin + r1 * span;

          const MIN_SPAN = 10000; // 10s
          if(newMax - newMin < MIN_SPAN){
            const c = (newMin + newMax) / 2;
            newMin = c - MIN_SPAN / 2;
            newMax = c + MIN_SPAN / 2;
          }

          const st = NETMON_STATE;
          const loaded = this._loadedRange(st);
          const clamped = this._clampRange(newMin, newMax, loaded.minMs, loaded.maxMs);

          this.viewMode = 'fixed';
          this.fixed.xMin = clamped.xMin;
          this.fixed.xMax = clamped.xMax;
          didZoom = true;
        }
      }

      if(!didZoom && prevView){
        this._applyViewState(prevView);
      }

      this.hover = null;
      this._hideTooltip();
      this._syncHistoryUI();
      this._scheduleRender(true);
    }

    // end drag (pan or box)
    this.drag.active = false;
    this.drag.pointerId = null;
    this.drag.startRange = null;
    this.drag.prevView = null;
    this.drag.mode = 'pan';

    if(this.canvas) this.canvas.classList.remove('is-dragging');
  }

  _onMouseLeave(){
    if(this.drag.active) return;
    this.hover = null;
    this._hideTooltip();
    this._scheduleRender(false);
  }

  _updateHover(mouseX, mouseY){
    if(!this.layout) return;

    if(!this._inPlot(mouseX, mouseY)){
      if(this.hover){
        this.hover = null;
        this._hideTooltip();
        this._scheduleRender(false);
      }
      return;
    }

    const st = NETMON_STATE;
    if(!st) return;
    const mon = st.monitorsMap ? st.monitorsMap[this.monitorId] : null;
    if(!mon) return;

    const per = (st.series && st.series[this.monitorId]) ? st.series[this.monitorId] : {};
    const nodeIdsRaw = Array.isArray(mon.node_ids) ? mon.node_ids : Object.keys(per);
    const nodeIds = [];
    const seen = new Set();
    for(const x of nodeIdsRaw){
      const s = String(x);
      if(!s || seen.has(s)) continue;
      seen.add(s);
      nodeIds.push(s);
    }

    const span = Math.max(1, this.layout.xMax - this.layout.xMin);
    const mx = _netmonClamp(mouseX, this.layout.padL, this.layout.padL + this.layout.plotW);
    const my = _netmonClamp(mouseY, this.layout.padT, this.layout.padT + this.layout.plotH);
    const tCursor = this.layout.xMin + ((mx - this.layout.padL) / this.layout.plotW) * span;

    // --- snap-to-point (so hovering *on* a point feels precise)
    let snap = null;
    let snapD2 = Infinity;
    const SNAP_RADIUS = 10; // px
    const probe = 4;

    for(const nid of nodeIds){
      if(this.hiddenNodes.has(nid)) continue;
      const arr = per[nid] || [];
      if(!arr.length) continue;

      const idx = _netmonBinarySearchByT(arr, tCursor);
      for(let k=-probe;k<=probe;k++){
        const i = idx + k;
        if(i < 0 || i >= arr.length) continue;
        const p = arr[i];
        if(!p) continue;

        const t = Number(p.t);
        if(!Number.isFinite(t)) continue;
        if(t < this.layout.xMin || t > this.layout.xMax) continue;

        // Prefer snapping to points with numeric latency.
        if(p.v == null) continue;
        const v = Number(p.v);
        if(!Number.isFinite(v)) continue;

        const x = this.layout.padL + ((t - this.layout.xMin) / span) * this.layout.plotW;
        const y = this.layout.padT + this.layout.plotH - (Math.max(0, Math.min(this.layout.yMax, v)) / this.layout.yMax) * this.layout.plotH;
        const dx = x - mx;
        const dy = y - my;
        const d2 = dx*dx + dy*dy;
        if(d2 < snapD2){
          snapD2 = d2;
          snap = {nid, t, v};
        }
      }
    }

    const SNAP_THR2 = SNAP_RADIUS * SNAP_RADIUS;
    const anchorT = (snap && snapD2 <= SNAP_THR2) ? Number(snap.t) : tCursor;

    const intervalMs = Math.max(1, (Number(mon.interval_sec) || 5)) * 1000;
    const tolMs = Math.max(900, intervalMs * 1.25);

    const rows = [];
    for(const nid of nodeIds){
      if(this.hiddenNodes.has(nid)) continue;
      const arr = per[nid] || [];
      let best = null;
      let bestDt = Infinity;

      if(arr.length){
        const idx = _netmonBinarySearchByT(arr, anchorT);
        for(const i of [idx-2, idx-1, idx, idx+1, idx+2]){
          if(i < 0 || i >= arr.length) continue;
          const p = arr[i];
          if(!p) continue;
          const t = Number(p.t);
          if(!Number.isFinite(t)) continue;
          if(t < this.layout.xMin || t > this.layout.xMax) continue;
          const dt = Math.abs(t - anchorT);
          if(dt < bestDt){
            bestDt = dt;
            best = p;
          }
        }
      }

      const row = { nid, t:null, v:null, ok:null, e:'', dt:null, n:null, f:null };
      if(best && bestDt <= tolMs){
        const bt = Number(best.t);
        row.t = Number.isFinite(bt) ? bt : null;
        row.v = (best.v == null) ? null : Number(best.v);
        if(typeof best.ok === 'boolean') row.ok = !!best.ok;
        else row.ok = (best.v != null);
        if(best.e != null) row.e = String(best.e);
        if(best.n != null) row.n = Number(best.n);
        if(best.f != null) row.f = Number(best.f);
        row.dt = (row.t != null) ? (row.t - anchorT) : null;
      }
      rows.push(row);
    }

    if(!rows.length){
      if(this.hover){
        this.hover = null;
        this._hideTooltip();
        this._scheduleRender(false);
      }
      return;
    }

    const hv = {
      t: anchorT,
      cursorT: tCursor,
      snapNid: (snap && snapD2 <= SNAP_THR2) ? String(snap.nid) : null,
      mouseX: mx,
      mouseY: my,
      intervalMs,
      tolMs,
      rows,
    };

    this.hover = hv;
    this._showTooltip(hv);
    this._scheduleRender(false);
  }

  _showTooltip(hv){
    if(!this.tooltipEl || !hv || !this.canvas) return;
    const st = NETMON_STATE;

    const rows = Array.isArray(hv.rows) ? hv.rows : [];
    const tTxt = _netmonFormatTs(hv.t);

    const out = [];
    out.push(`
      <div class="netmon-tt-top">
        <div class="netmon-tt-title mono">${escapeHtml(tTxt)}</div>
        <div class="netmon-tt-sub muted sm">提示：单击图例隐藏，双击独显 · Shift+单击也可独显</div>
      </div>
      <div class="netmon-tt-table">
    `);

    const dtBadge = (dtMs, intervalMs)=>{
      if(dtMs == null || !Number.isFinite(Number(dtMs))) return '<span class="netmon-tt-delta muted mono"></span>';
      const abs = Math.abs(Number(dtMs));
      // Only show when the nearest sample is meaningfully off from the crosshair time
      if(abs < Math.max(250, intervalMs * 0.35)) return '<span class="netmon-tt-delta muted mono"></span>';
      const s = (Number(dtMs) >= 0) ? '+' : '-';
      const sec = (abs / 1000);
      const txt = sec >= 10 ? `${s}${sec.toFixed(0)}s` : `${s}${sec.toFixed(1)}s`;
      return `<span class="netmon-tt-delta muted mono">${escapeHtml(txt)}</span>`;
    };

    for(const r of rows){
      if(!r || !r.nid) continue;
      const nid = String(r.nid);
      const meta = (st && st.nodesMeta && st.nodesMeta[nid]) ? st.nodesMeta[nid] : null;
      const name = meta ? (meta.name || ('节点-' + nid)) : ('节点-' + nid);
      const color = _netmonColorForNode(nid);

      let vTxt = '—';
      let isBad = false;
      let errTxt = '';
      let metaTxt = '';
      if(r.v != null && Number.isFinite(Number(r.v))){
        vTxt = `${Number(r.v).toFixed(1)} ms`;
      }else if(r.ok === false){
        vTxt = '失败';
        isBad = true;
        if(r.e) errTxt = String(r.e);
      }

      // Rollup extra: show failed/total when available
      try{
        const n = (r.n != null) ? Number(r.n) : null;
        const f = (r.f != null) ? Number(r.f) : null;
        if(Number.isFinite(n) && n > 0){
          const nn = Math.max(1, Math.round(n));
          const ff = (Number.isFinite(f) ? Math.max(0, Math.round(f)) : 0);
          if(ff > 0){
            const pct = Math.min(100, Math.max(0, (ff / nn) * 100));
            metaTxt = `失败 ${ff}/${nn} (${pct.toFixed(0)}%)`;
            if(pct >= 50) isBad = true;
          }
        }
      }catch(_e){}

      out.push(`
        <div class="netmon-tt-row">
          <span class="netmon-dot" style="background:${escapeHtml(color)}"></span>
          <span class="mono netmon-tt-name">${escapeHtml(name)}</span>
          ${dtBadge(r.dt, hv.intervalMs || 1000)}
          <span class="mono netmon-tt-val ${isBad ? 'bad' : ''}">${escapeHtml(vTxt)}</span>
        </div>
      `);
      if(errTxt){
        out.push(`<div class="netmon-tt-err muted mono">${escapeHtml(errTxt)}</div>`);
      }
      if(metaTxt){
        out.push(`<div class="netmon-tt-meta muted mono">${escapeHtml(metaTxt)}</div>`);
      }
    }

    out.push(`</div>`);

    this.tooltipEl.innerHTML = out.join('');

    // show first to measure
    this.tooltipEl.style.display = '';

    const wrap = this.tooltipEl.parentElement;
    const wrapW = wrap ? wrap.clientWidth : 0;
    const wrapH = wrap ? wrap.clientHeight : 0;

    // canvas offset within wrap (because wrap has padding)
    let offX = 0;
    let offY = 0;
    try{
      if(wrap){
        const cRect = this.canvas.getBoundingClientRect();
        const wRect = wrap.getBoundingClientRect();
        offX = cRect.left - wRect.left;
        offY = cRect.top - wRect.top;
      }
    }catch(_e){}

    const tipRect = this.tooltipEl.getBoundingClientRect();
    const offset = 12;

    let left = offX + (hv.mouseX || 0) + offset;
    let top = offY + (hv.mouseY || 0) + offset;

    const maxLeft = Math.max(8, wrapW - tipRect.width - 8);
    const maxTop = Math.max(8, wrapH - tipRect.height - 8);

    if(left > maxLeft) left = offX + (hv.mouseX || 0) - tipRect.width - offset;
    if(top > maxTop) top = offY + (hv.mouseY || 0) - tipRect.height - offset;

    left = _netmonClamp(left, 8, maxLeft);
    top = _netmonClamp(top, 8, maxTop);

    this.tooltipEl.style.left = `${left}px`;
    this.tooltipEl.style.top = `${top}px`;
  }

  _hideTooltip(){
    if(!this.tooltipEl) return;
    this.tooltipEl.style.display = 'none';
  }

  _getNavPos(e){
    if(!this.navCanvas) return null;
    const rect = this.navCanvas.getBoundingClientRect();
    const x = (e.clientX || 0) - rect.left;
    const y = (e.clientY || 0) - rect.top;
    return {x, y, rect};
  }

  _inNavPlot(x, y){
    if(!this.navLayout) return false;
    return x >= this.navLayout.padL && x <= (this.navLayout.padL + this.navLayout.plotW)
      && y >= this.navLayout.padT && y <= (this.navLayout.padT + this.navLayout.plotH);
  }

  _navXToT(x){
    if(!this.navLayout) return null;
    const nl = this.navLayout;
    const span = Math.max(1, Number(nl.loadedMax) - Number(nl.loadedMin));
    const r = _netmonClamp((Number(x) - nl.padL) / nl.plotW, 0, 1);
    return Number(nl.loadedMin) + r * span;
  }

  _onNavPointerDown(e){
    if(!this.navCanvas) return;
    if(!this.navLayout) return;
    if(e.pointerType === 'mouse' && e.button !== 0) return;

    const pos = this._getNavPos(e);
    if(!pos) return;
    if(!this._inNavPlot(pos.x, pos.y)) return;

    try{ this.navCanvas.setPointerCapture(e.pointerId); }catch(_e){}

    // Freeze view into history mode while dragging navigator
    const cur = this._currentRange();
    this.viewMode = 'fixed';
    this.fixed.xMin = cur.xMin;
    this.fixed.xMax = cur.xMax;

    const nl = this.navLayout;
    const loadedSpan = Math.max(1, Number(nl.loadedMax) - Number(nl.loadedMin));
    const span = Math.max(10000, Number(cur.xMax) - Number(cur.xMin));

    let selX0 = nl.padL + ((Number(cur.xMin) - Number(nl.loadedMin)) / loadedSpan) * nl.plotW;
    let selX1 = nl.padL + ((Number(cur.xMax) - Number(nl.loadedMin)) / loadedSpan) * nl.plotW;
    const x = _netmonClamp(pos.x, nl.padL, nl.padL + nl.plotW);

    const EDGE = 8;
    const inSel = x >= selX0 && x <= selX1;
    let mode = 'move';
    if(inSel && Math.abs(x - selX0) <= EDGE) mode = 'left';
    else if(inSel && Math.abs(x - selX1) <= EDGE) mode = 'right';
    else if(inSel) mode = 'move';
    else mode = 'jump';

    // Jump: center window around pointer time first
    if(mode === 'jump'){
      const t = this._navXToT(x);
      if(t != null){
        let newMin = Number(t) - span / 2;
        let newMax = newMin + span;
        const clamped = this._clampRange(newMin, newMax, Number(nl.loadedMin), Number(nl.loadedMax));
        this.fixed.xMin = clamped.xMin;
        this.fixed.xMax = clamped.xMax;
        selX0 = nl.padL + ((Number(this.fixed.xMin) - Number(nl.loadedMin)) / loadedSpan) * nl.plotW;
        selX1 = nl.padL + ((Number(this.fixed.xMax) - Number(nl.loadedMin)) / loadedSpan) * nl.plotW;
        mode = 'move';
      }
    }

    this.navDrag.active = true;
    this.navDrag.pointerId = e.pointerId;
    this.navDrag.mode = mode;
    this.navDrag.startX = x;
    this.navDrag.startRange = {xMin:Number(this.fixed.xMin), xMax:Number(this.fixed.xMax)};
    this.navDrag.moved = false;

    this.hover = null;
    this._hideTooltip();

    if(this.navCanvas) this.navCanvas.classList.add('is-dragging');
    this._syncHistoryUI();
    this._scheduleRender(false);
  }

  _onNavPointerMove(e){
    if(!this.navDrag || !this.navDrag.active) return;
    if(this.navDrag.pointerId !== e.pointerId) return;
    if(!this.navLayout) return;

    const pos = this._getNavPos(e);
    if(!pos) return;

    const nl = this.navLayout;
    const x = _netmonClamp(pos.x, nl.padL, nl.padL + nl.plotW);

    const dx = x - Number(this.navDrag.startX || 0);
    if(Math.abs(dx) > 1) this.navDrag.moved = true;

    const loadedSpan = Math.max(1, Number(nl.loadedMax) - Number(nl.loadedMin));
    const dt = (dx / nl.plotW) * loadedSpan;

    const start = this.navDrag.startRange;
    if(!start) return;

    let newMin = Number(start.xMin);
    let newMax = Number(start.xMax);

    if(this.navDrag.mode === 'move'){
      newMin = Number(start.xMin) + dt;
      newMax = Number(start.xMax) + dt;
    }else if(this.navDrag.mode === 'left'){
      newMin = Number(start.xMin) + dt;
      newMax = Number(start.xMax);
    }else if(this.navDrag.mode === 'right'){
      newMin = Number(start.xMin);
      newMax = Number(start.xMax) + dt;
    }

    const MIN_SPAN = 10000; // 10s
    if(newMax - newMin < MIN_SPAN){
      if(this.navDrag.mode === 'left') newMin = newMax - MIN_SPAN;
      else newMax = newMin + MIN_SPAN;
    }

    const clamped = this._clampRange(newMin, newMax, Number(nl.loadedMin), Number(nl.loadedMax));
    this.viewMode = 'fixed';
    this.fixed.xMin = clamped.xMin;
    this.fixed.xMax = clamped.xMax;
    this._syncHistoryUI();

    this.hover = null;
    this._hideTooltip();
    this._scheduleRender(false);
  }

  _onNavPointerUp(e){
    if(!this.navDrag || !this.navDrag.active) return;
    if(this.navDrag.pointerId !== e.pointerId) return;

    this.navDrag.active = false;
    this.navDrag.pointerId = null;
    this.navDrag.startRange = null;
    this.navDrag.mode = 'move';

    if(this.navCanvas) this.navCanvas.classList.remove('is-dragging');
    this._scheduleRender(true);
  }

  _onNavMouseLeave(){
    if(this.navDrag && this.navDrag.active) return;
    // nothing for now
  }

  _renderNavigator(mon, per, curRange){
    if(!this.navCanvas || !this.navCtx) return;
    const st = NETMON_STATE;
    if(!st) return;

    const loaded = this._loadedRange(st);
    const loadedMin = Number(loaded.minMs);
    const loadedMax = Number(loaded.maxMs);
    const loadedSpan = Math.max(1, loadedMax - loadedMin);

    const w = Math.max(200, this.navCanvas.clientWidth || 0);
    const h = Math.max(28, this.navCanvas.clientHeight || 0);
    const dpr = window.devicePixelRatio || 1;
    const needResize = (this.navCanvas.width !== Math.floor(w * dpr)) || (this.navCanvas.height !== Math.floor(h * dpr));
    if(needResize){
      this.navCanvas.width = Math.floor(w * dpr);
      this.navCanvas.height = Math.floor(h * dpr);
    }

    this.navCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.navCtx.clearRect(0, 0, w, h);

    const padL = 10;
    const padR = 10;
    const padT = 6;
    const padB = 6;
    const plotW = Math.max(10, w - padL - padR);
    const plotH = Math.max(10, h - padT - padB);

    // Build bucketed overview (max latency across visible nodes)
    const BUCKETS = Math.max(80, Math.min(420, Math.floor(plotW)));
    const buckets = new Array(BUCKETS);
    for(let i=0;i<BUCKETS;i++) buckets[i] = 0;

    const nodeIds = Array.isArray(mon && mon.node_ids) ? mon.node_ids.map(x=>String(x)) : [];
    for(const nid of nodeIds){
      if(this.hiddenNodes && this.hiddenNodes.has(String(nid))) continue;
      const arr = (per && per[String(nid)]) ? per[String(nid)] : [];
      if(!arr.length) continue;
      const step = Math.max(1, Math.ceil(arr.length / 5000));
      for(let i=0;i<arr.length;i+=step){
        const p = arr[i];
        if(!p || p.v == null) continue;
        const t = Number(p.t);
        if(!Number.isFinite(t)) continue;
        if(t < loadedMin) continue;
        if(t > loadedMax) break;
        const v = Number(p.v);
        if(!Number.isFinite(v) || v < 0) continue;
        const r = (t - loadedMin) / loadedSpan;
        const idx = Math.max(0, Math.min(BUCKETS-1, Math.floor(r * BUCKETS)));
        if(v > buckets[idx]) buckets[idx] = v;
      }
    }

    let maxV = 0;
    for(const v of buckets){ if(v > maxV) maxV = v; }

    // include thresholds so overview line doesn't look "flat" under a low yMax
    const warnThr = Number(mon.warn_ms || 0) || 0;
    const critThr = Number(mon.crit_ms || 0) || 0;
    if(warnThr > 0) maxV = Math.max(maxV, warnThr);
    if(critThr > 0) maxV = Math.max(maxV, critThr);

    let yMax = maxV > 0 ? _netmonNiceMax(maxV * 1.15) : 10;
    if(yMax < 10) yMax = 10;

    // background
    this.navCtx.fillStyle = 'rgba(2,6,23,0.24)';
    this.navCtx.fillRect(0, 0, w, h);

    // area
    this.navCtx.save();
    this.navCtx.beginPath();
    for(let i=0;i<BUCKETS;i++){
      const x = padL + (i / (BUCKETS-1)) * plotW;
      const v = buckets[i];
      const y = padT + plotH - (Math.max(0, Math.min(yMax, v)) / yMax) * plotH;
      if(i === 0) this.navCtx.moveTo(x, y);
      else this.navCtx.lineTo(x, y);
    }
    this.navCtx.lineTo(padL + plotW, padT + plotH);
    this.navCtx.lineTo(padL, padT + plotH);
    this.navCtx.closePath();
    this.navCtx.fillStyle = 'rgba(226,232,240,0.10)';
    this.navCtx.fill();
    this.navCtx.strokeStyle = 'rgba(226,232,240,0.18)';
    this.navCtx.lineWidth = 1;
    this.navCtx.stroke();
    this.navCtx.restore();

    // thresholds in navigator (subtle)
    const yFor = (val)=> padT + plotH - (Math.max(0, Math.min(yMax, val)) / yMax) * plotH;
    this.navCtx.save();
    this.navCtx.lineWidth = 1;
    try{ this.navCtx.setLineDash([4,4]); }catch(_e){}
    if(warnThr > 0){
      const y = yFor(warnThr);
      this.navCtx.strokeStyle = 'rgba(245,158,11,0.35)';
      this.navCtx.beginPath();
      this.navCtx.moveTo(padL, y);
      this.navCtx.lineTo(padL + plotW, y);
      this.navCtx.stroke();
    }
    if(critThr > 0){
      const y = yFor(critThr);
      this.navCtx.strokeStyle = 'rgba(248,113,113,0.35)';
      this.navCtx.beginPath();
      this.navCtx.moveTo(padL, y);
      this.navCtx.lineTo(padL + plotW, y);
      this.navCtx.stroke();
    }
    try{ this.navCtx.setLineDash([]); }catch(_e){}
    this.navCtx.restore();

    const curMin = Number(curRange && curRange.xMin != null ? curRange.xMin : loadedMax - Math.min(loadedSpan, 10*60*1000));
    const curMax = Number(curRange && curRange.xMax != null ? curRange.xMax : loadedMax);

    const selX0 = padL + ((curMin - loadedMin) / loadedSpan) * plotW;
    const selX1 = padL + ((curMax - loadedMin) / loadedSpan) * plotW;

    const a = Math.min(selX0, selX1);
    const b = Math.max(selX0, selX1);

    // shade outside selection
    this.navCtx.fillStyle = 'rgba(0,0,0,0.34)';
    this.navCtx.fillRect(padL, padT, Math.max(0, a - padL), plotH);
    this.navCtx.fillRect(Math.min(b, padL + plotW), padT, Math.max(0, (padL + plotW) - b), plotH);

    // selection border + handles
    this.navCtx.save();
    this.navCtx.strokeStyle = 'rgba(226,232,240,0.55)';
    this.navCtx.lineWidth = (this.navDrag && this.navDrag.active) ? 1.6 : 1;
    this.navCtx.strokeRect(a + 0.5, padT + 0.5, Math.max(1, b - a), plotH - 1);

    // handles
    this.navCtx.fillStyle = 'rgba(226,232,240,0.65)';
    const hw = 2;
    this.navCtx.fillRect(a - hw, padT + 3, hw, plotH - 6);
    this.navCtx.fillRect(b, padT + 3, hw, plotH - 6);
    this.navCtx.restore();

    // save layout for interactions
    this.navLayout = {w, h, padL, padR, padT, padB, plotW, plotH, loadedMin, loadedMax};
  }

  render(force){
    const st = NETMON_STATE;
    if(!st || !this.canvas || !this.ctx) return;

    const mon = st.monitorsMap ? st.monitorsMap[this.monitorId] : null;
    if(!mon) return;

    this._syncHistoryUI();

    const w = Math.max(200, this.canvas.clientWidth || 0);
    const h = Math.max(140, this.canvas.clientHeight || 0);
    const dpr = window.devicePixelRatio || 1;

    const needResize = force || (this.canvas.width !== Math.floor(w * dpr)) || (this.canvas.height !== Math.floor(h * dpr));
    if(needResize){
      this.canvas.width = Math.floor(w * dpr);
      this.canvas.height = Math.floor(h * dpr);
    }

    // draw in CSS pixels
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.ctx.clearRect(0, 0, w, h);

    const padL = 54;
    const padR = 12;
    const padT = 14;
    const padB = 30;

    const plotW = Math.max(10, w - padL - padR);
    const plotH = Math.max(10, h - padT - padB);

    const range = this._currentRange();
    const xMin = range.xMin;
    const xMax = range.xMax;

    const per = (st.series && st.series[this.monitorId]) ? st.series[this.monitorId] : {};

    const nodeIdsRaw = Array.isArray(mon.node_ids) ? mon.node_ids : Object.keys(per);
    const nodeIds = [];
    const seen = new Set();
    for(const x of nodeIdsRaw){
      const s = String(x);
      if(!s || seen.has(s)) continue;
      seen.add(s);
      nodeIds.push(s);
    }

    // prune hidden set (if nodes changed)
    let hiddenChanged = false;
    for(const hid of Array.from(this.hiddenNodes)){
      if(!seen.has(hid)){
        this.hiddenNodes.delete(hid);
        hiddenChanged = true;
      }
    }
    if(hiddenChanged) _netmonSaveHidden(this.monitorId, this.hiddenNodes);

    // yMax based on visible nodes within view
    let maxV = 0;
    for(const nid of nodeIds){
      if(this.hiddenNodes.has(nid)) continue;
      const arr = per[nid] || [];
      for(const p of arr){
        if(!p) continue;
        const t = Number(p.t);
        if(t < xMin) continue;
        if(t > xMax) break;
        if(p.v == null) continue;
        const v = Number(p.v);
        if(!Number.isNaN(v)) maxV = Math.max(maxV, v);
      }
    }

    // thresholds (optional)
    let warnThr = Number(mon.warn_ms || 0) || 0;
    let critThr = Number(mon.crit_ms || 0) || 0;
    if(warnThr > 0 && critThr > 0 && warnThr > critThr){
      const tmp = warnThr; warnThr = critThr; critThr = tmp;
    }
    if(warnThr > 0) maxV = Math.max(maxV, warnThr);
    if(critThr > 0) maxV = Math.max(maxV, critThr);

    let yMax = maxV > 0 ? _netmonNiceMax(maxV * 1.25) : 10;
    if(yMax < 10) yMax = 10;

    // keep for hit-test & tooltip
    this.layout = {w, h, padL, padR, padT, padB, plotW, plotH, xMin, xMax, yMax, warnThr, critThr};

    // threshold background (subtle)
    if(warnThr > 0 || critThr > 0){
      const yFor = (val)=> padT + plotH - (Math.max(0, Math.min(yMax, val)) / yMax) * plotH;
      this.ctx.save();
      if(critThr > 0){
        const yC = yFor(critThr);
        this.ctx.fillStyle = 'rgba(248,113,113,0.06)';
        this.ctx.fillRect(padL, padT, plotW, Math.max(0, yC - padT));
      }
      if(warnThr > 0){
        const yW = yFor(warnThr);
        const yTop = (critThr > 0) ? yFor(critThr) : padT;
        this.ctx.fillStyle = 'rgba(245,158,11,0.06)';
        this.ctx.fillRect(padL, yTop, plotW, Math.max(0, yW - yTop));
      }
      this.ctx.restore();
    }

    // grid
    this.ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    this.ctx.lineWidth = 1;
    for(let i=0;i<=4;i++){
      const y = padT + (plotH * i / 4);
      this.ctx.beginPath();
      this.ctx.moveTo(padL, y);
      this.ctx.lineTo(padL + plotW, y);
      this.ctx.stroke();
    }

    // axes
    this.ctx.strokeStyle = 'rgba(255,255,255,0.18)';
    this.ctx.beginPath();
    this.ctx.moveTo(padL, padT);
    this.ctx.lineTo(padL, padT + plotH);
    this.ctx.lineTo(padL + plotW, padT + plotH);
    this.ctx.stroke();

    // labels
    const fontMono = '12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';
    this.ctx.font = fontMono;
    this.ctx.fillStyle = 'rgba(255,255,255,0.55)';

    for(let i=0;i<=4;i++){
      const val = yMax * (1 - i/4);
      const y = padT + (plotH * i / 4);
      const label = `${Math.round(val)}`;
      this.ctx.textAlign = 'right';
      this.ctx.textBaseline = 'middle';
      this.ctx.fillText(label, padL - 8, y);
    }

    const xSpan = Math.max(1, xMax - xMin);
    for(let i=0;i<=4;i++){
      const ts = xMin + (xSpan * i / 4);
      const x = padL + (plotW * i / 4);
      const label = _netmonFormatClock(ts);
      this.ctx.textAlign = 'center';
      this.ctx.textBaseline = 'top';
      this.ctx.fillText(label, x, padT + plotH + 8);
    }


    // threshold lines
    if(warnThr > 0 || critThr > 0){
      const yFor = (val)=> padT + plotH - (Math.max(0, Math.min(yMax, val)) / yMax) * plotH;
      this.ctx.save();
      this.ctx.lineWidth = 1;
      try{ this.ctx.setLineDash([6,4]); }catch(_e){}

      const drawLine = (val, stroke, label)=>{
        const y = yFor(val);
        this.ctx.strokeStyle = stroke;
        this.ctx.beginPath();
        this.ctx.moveTo(padL, y);
        this.ctx.lineTo(padL + plotW, y);
        this.ctx.stroke();

        // label on the right
        this.ctx.fillStyle = stroke;
        this.ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';
        this.ctx.textAlign = 'right';
        this.ctx.textBaseline = 'bottom';
        const yTxt = _netmonClamp(y - 2, padT + 12, padT + plotH - 2);
        this.ctx.fillText(label, padL + plotW - 4, yTxt);
      };

      if(warnThr > 0) drawLine(warnThr, 'rgba(245,158,11,0.65)', `W ${Math.round(warnThr)}ms`);
      if(critThr > 0) drawLine(critThr, 'rgba(248,113,113,0.65)', `C ${Math.round(critThr)}ms`);

      try{ this.ctx.setLineDash([]); }catch(_e){}
      this.ctx.restore();
    }

    // lines (downsample in long windows to keep rendering snappy)
    const maxPts = Math.max(220, Math.floor(plotW * 1.6));
    for(const nid of nodeIds){
      if(this.hiddenNodes.has(nid)) continue;
      const arr = per[nid] || [];
      const color = _netmonColorForNode(nid);
      this.ctx.strokeStyle = color;
      this.ctx.lineWidth = 2;
      this.ctx.beginPath();

      // Build continuous segments within current x-range
      const segments = [];
      let seg = [];
      for(const p of arr){
        if(!p) continue;
        const t = Number(p.t);
        if(t < xMin) continue;
        if(t > xMax) break;

        if(p.v == null){
          if(seg.length){ segments.push(seg); seg = []; }
          continue;
        }
        const v = Number(p.v);
        if(Number.isNaN(v)){
          if(seg.length){ segments.push(seg); seg = []; }
          continue;
        }
        seg.push({t, v});
      }
      if(seg.length) segments.push(seg);

      let any = false;
      for(const s of segments){
        const pts = (s.length > maxPts) ? _netmonLTTB(s, maxPts) : s;
        for(let i=0;i<pts.length;i++){
          const pt = pts[i];
          const x = padL + ((pt.t - xMin) / xSpan) * plotW;
          const y = padT + plotH - (Math.max(0, Math.min(yMax, pt.v)) / yMax) * plotH;
          if(i === 0) this.ctx.moveTo(x, y);
          else this.ctx.lineTo(x, y);
        }
        if(pts.length) any = true;
      }

      if(any) this.ctx.stroke();
    }

    // box zoom selection
    if(this.boxSel && this.boxSel.active){
      const x0 = Number(this.boxSel.x0);
      const y0 = Number(this.boxSel.y0);
      const x1 = Number(this.boxSel.x1);
      const y1 = Number(this.boxSel.y1);
      const x = Math.min(x0, x1);
      const y = Math.min(y0, y1);
      const rw = Math.abs(x1 - x0);
      const rh = Math.abs(y1 - y0);
      if(rw > 1 && rh > 1){
        this.ctx.save();
        this.ctx.fillStyle = 'rgba(255,255,255,0.06)';
        this.ctx.strokeStyle = 'rgba(255,255,255,0.35)';
        this.ctx.lineWidth = 1;
        try{ this.ctx.setLineDash([6,4]); }catch(_e){}
        this.ctx.fillRect(x, y, rw, rh);
        this.ctx.strokeRect(x + 0.5, y + 0.5, rw, rh);
        try{ this.ctx.setLineDash([]); }catch(_e){}
        this.ctx.restore();
      }
    }

    // hover highlight (crosshair + multi-series point markers)
    if(this.hover && Array.isArray(this.hover.rows)){
      const t = Number(this.hover.t);
      if(Number.isFinite(t) && t >= xMin && t <= xMax){
        const x = padL + ((t - xMin) / xSpan) * plotW;

        // crosshair
        this.ctx.save();
        this.ctx.strokeStyle = 'rgba(255,255,255,0.14)';
        this.ctx.lineWidth = 1;
        try{ this.ctx.setLineDash([4,4]); }catch(_e){}
        this.ctx.beginPath();
        this.ctx.moveTo(x, padT);
        this.ctx.lineTo(x, padT + plotH);
        this.ctx.stroke();
        try{ this.ctx.setLineDash([]); }catch(_e){}
        this.ctx.restore();

        const rows = this.hover.rows;
        for(const r of rows){
          if(!r || !r.nid) continue;
          const nid = String(r.nid);
          if(this.hiddenNodes.has(nid)) continue;
          if(r.v == null || !Number.isFinite(Number(r.v))) continue;
          if(r.t == null || !Number.isFinite(Number(r.t))) continue;
          const ptT = Number(r.t);
          if(ptT < xMin || ptT > xMax) continue;
          const ptV = Number(r.v);

          const px = padL + ((ptT - xMin) / xSpan) * plotW;
          const py = padT + plotH - (Math.max(0, Math.min(yMax, ptV)) / yMax) * plotH;

          const c = _netmonColorForNode(nid);
          const isSnap = (this.hover.snapNid && String(this.hover.snapNid) === nid);
          const radius = isSnap ? 5.2 : 4.2;

          this.ctx.beginPath();
          this.ctx.arc(px, py, radius, 0, Math.PI * 2);
          this.ctx.fillStyle = c;
          this.ctx.fill();
          this.ctx.lineWidth = 2;
          this.ctx.strokeStyle = 'rgba(11,15,20,0.85)';
          this.ctx.stroke();
        }
      }
    }

    try{ this._renderNavigator(mon, per, range); }catch(_e){}

    this._renderStats(mon, per, xMin, xMax);
    this._renderLegend(mon, per, xMin, xMax);
    this._renderEvents(mon, per, xMin, xMax);
  }

  _renderStats(mon, per, xMin, xMax){
    const st = NETMON_STATE;
    if(!st || !this.statsEl) return;
    const nodeIds = Array.isArray(mon && mon.node_ids) ? mon.node_ids.map(x=>String(x)) : [];

    // Cache by range + hidden set + latest snapshot timestamp
    const hiddenKey = Array.from(this.hiddenNodes || []).sort().join(',');
    const key = `${Math.round(Number(xMin)||0)}|${Math.round(Number(xMax)||0)}|${hiddenKey}|${Math.round(Number(st.lastTs)||0)}`;
    if(key === this._statsKey) return;
    this._statsKey = key;

    const visibleNodes = nodeIds.filter(nid=>!this.hiddenNodes.has(String(nid)));

    // Online count
    let online = 0;
    for(const nid of visibleNodes){
      const meta = (st.nodesMeta && st.nodesMeta[String(nid)]) ? st.nodesMeta[String(nid)] : null;
      if(meta && meta.online) online += 1;
    }

    // Collect values in range
    let total = 0;
    let fail = 0;
    let values = [];

    // Last per node (within range) for max-last
    let lastMax = null;

    const xMinN = Number(xMin) || 0;
    const xMaxN = Number(xMax) || 0;

    for(const nid of visibleNodes){
      const arr = (per && per[String(nid)]) ? per[String(nid)] : [];
      if(!arr.length) continue;

      // last within range
      let lastV = null;
      for(let i=arr.length-1;i>=0;i--){
        const p = arr[i];
        if(!p) continue;
        const t = Number(p.t);
        if(!Number.isFinite(t)) continue;
        if(t < xMinN) break;
        if(t > xMaxN) continue;
        if(p.v != null && Number.isFinite(Number(p.v))){ lastV = Number(p.v); break; }
      }
      if(lastV != null){
        if(lastMax == null) lastMax = lastV;
        else lastMax = Math.max(Number(lastMax), Number(lastV));
      }

      const start = _netmonBinarySearchByT(arr, xMinN);
      for(let i=start;i<arr.length;i++){
        const p = arr[i];
        if(!p) continue;
        const t = Number(p.t);
        if(!Number.isFinite(t)) continue;
        if(t > xMaxN) break;
        total += 1;
        if(p.v == null){
          fail += 1;
          continue;
        }
        const v = Number(p.v);
        if(Number.isFinite(v)) values.push(v);
      }
    }

    // Downsample if too many points (keep UI snappy even with long windows)
    const MAX_N = 20000;
    if(values.length > MAX_N){
      const step = Math.ceil(values.length / MAX_N);
      const sampled = [];
      for(let i=0;i<values.length;i+=step) sampled.push(values[i]);
      values = sampled;
    }

    let avg = null;
    let p50 = null;
    let p95 = null;
    if(values.length){
      let sum = 0;
      for(const v of values) sum += Number(v) || 0;
      avg = sum / values.length;

      const sorted = values.slice().sort((a,b)=>a-b);
      const q = (p)=>{
        if(!sorted.length) return null;
        const idx = Math.max(0, Math.min(sorted.length-1, Math.floor(p * (sorted.length-1))));
        return sorted[idx];
      };
      p50 = q(0.50);
      p95 = q(0.95);
    }

    const jitter = (p95 != null && p50 != null) ? (Number(p95) - Number(p50)) : null;
    const loss = (total > 0) ? (fail / total) : null;

    const pill = (k, v, cls, title)=>{
      const c = cls ? ` ${cls}` : '';
      const t = title ? ` title="${escapeHtml(title)}"` : '';
      return `<div class="netmon-pill${c}"${t}><span class="k">${escapeHtml(k)}</span><span class="v mono">${escapeHtml(v)}</span></div>`;
    };

    const pills = [];

    // thresholds status (use P95 when available)
    const thrW0 = Number(mon.warn_ms || 0) || 0;
    const thrC0 = Number(mon.crit_ms || 0) || 0;
    let thrW = thrW0;
    let thrC = thrC0;
    if(thrW > 0 && thrC > 0 && thrW > thrC){
      const tmp = thrW; thrW = thrC; thrC = tmp;
    }

    const ref = (p95 != null && Number.isFinite(Number(p95))) ? Number(p95)
      : ((lastMax != null && Number.isFinite(Number(lastMax))) ? Number(lastMax) : null);

    let level = 'none';
    if(thrW > 0 || thrC > 0){
      if(ref != null){
        if(thrC > 0 && ref >= thrC) level = 'crit';
        else if(thrW > 0 && ref >= thrW) level = 'warn';
        else level = 'ok';
      }else{
        level = 'ok';
      }

      const thrTxt = `W${thrW > 0 ? Math.round(thrW) : '-'} / C${thrC > 0 ? Math.round(thrC) : '-'}ms`;
      const stTxt = (level === 'crit') ? 'CRIT' : (level === 'warn') ? 'WARN' : 'OK';
      pills.push(pill('状态', stTxt, level, '基于当前窗口 P95（优先）或最新值与阈值对比'));
      pills.push(pill('阈值', thrTxt, '', '该监控的告警/严重阈值（0 表示关闭）'));
    }

    // Card accent
    if(this.card){
      this.card.classList.remove('netmon-level-ok','netmon-level-warn','netmon-level-crit');
      if(level === 'crit') this.card.classList.add('netmon-level-crit');
      else if(level === 'warn') this.card.classList.add('netmon-level-warn');
      else if(level === 'ok') this.card.classList.add('netmon-level-ok');
    }

    // Expose for toolbar filters
    this.level = level;

    pills.push(pill('在线', `${online}/${visibleNodes.length}`, '', '当前可见节点在线数 / 可见节点数'));
    pills.push(pill('当前', (lastMax != null) ? `${Number(lastMax).toFixed(1)}ms` : '—', '', '可见节点在当前窗口内的“最新延迟”的最大值'));
    pills.push(pill('均值', (avg != null) ? `${Number(avg).toFixed(1)}ms` : '—', '', '窗口内全部成功采样点的均值'));
    pills.push(pill('P95', (p95 != null) ? `${Number(p95).toFixed(1)}ms` : '—', '', '窗口内全部成功采样点的 95 分位'));
    pills.push(pill('抖动', (jitter != null) ? `${Number(jitter).toFixed(1)}ms` : '—', '', 'P95 - P50（越大说明波动越明显）'));
    pills.push(pill('失败', (loss != null) ? `${(loss*100).toFixed(1)}%` : '—', (loss != null && loss > 0.02) ? 'warn' : '', '失败采样占比（v 为空/探测失败）'));


    this.statsEl.innerHTML = `<div class="netmon-stats-wrap">${pills.join('')}</div>`;
  }

  _renderLegend(mon, per, xMin, xMax){
    const st = NETMON_STATE;
    if(!st || !this.legendEl) return;

    const nodeIds = Array.isArray(mon.node_ids) ? mon.node_ids.map(x=>String(x)) : [];

    const parts = [];
    for(const nidStr of nodeIds){
      const meta = (st.nodesMeta && st.nodesMeta[nidStr]) ? st.nodesMeta[nidStr] : null;
      const showName = meta ? (meta.name || ('节点-' + nidStr)) : ('节点-' + nidStr);
      const color = _netmonColorForNode(nidStr);
      const hidden = this.hiddenNodes.has(nidStr);

      // latest non-null within view
      let last = null;
      const arr = per && per[nidStr] ? per[nidStr] : [];
      for(let i=arr.length-1;i>=0;i--){
        const p = arr[i];
        if(!p) continue;
        const t = Number(p.t);
        if(t < xMin) break;
        if(t > xMax) continue;
        if(p.v != null){ last = p.v; break; }
      }
      // fallback
      if(last == null){
        for(let i=arr.length-1;i>=0;i--){
          const p = arr[i];
          if(p && p.v != null){ last = p.v; break; }
        }
      }

      const valTxt = (last != null && !Number.isNaN(Number(last))) ? `${Number(last).toFixed(1)} ms` : '—';

      parts.push(`
        <button class="netmon-legend-item ${hidden ? 'off' : ''}" type="button" data-nid="${escapeHtml(nidStr)}" title="单击隐藏/显示 · 双击仅看该节点 · Shift+单击也可独显">
          <span class="netmon-dot" style="background:${escapeHtml(color)}"></span>
          <span class="mono">${escapeHtml(showName)}</span>
          <span class="muted mono">${escapeHtml(valTxt)}</span>
        </button>
      `);
    }

    // Show-all shortcut when some series are hidden
    if(this.hiddenNodes && this.hiddenNodes.size > 0 && nodeIds.length > 0){
      parts.push(`
        <button class="netmon-legend-item aux" type="button" data-action="showall" title="显示全部曲线">
          <span class="muted">显示全部</span>
        </button>
      `);
    }

    this.legendEl.innerHTML = `<div class="netmon-legend-wrap">${parts.join('')}</div>`;
  }

  _renderEvents(mon, per, xMin, xMax){
    const st = NETMON_STATE;
    if(!st || !this.eventsBar || !this.eventsFoot) return;

    const warn0 = Number(mon && mon.warn_ms) || 0;
    const crit0 = Number(mon && mon.crit_ms) || 0;
    const rm = Number(st.rollupMs) || 0;
    // Note: abnormal scan is based on ALL configured nodes, independent of curve visibility.
    const key = `${Math.round(Number(xMin)||0)}|${Math.round(Number(xMax)||0)}|${Math.round(Number(st.lastTs)||0)}|${Math.round(warn0)}|${Math.round(crit0)}|${Math.round(rm)}`;
    if(key === this._eventsKey) return;
    this._eventsKey = key;

    let warnThr = warn0;
    let critThr = crit0;
    if(warnThr > 0 && critThr > 0 && warnThr > critThr){
      const tmp = warnThr; warnThr = critThr; critThr = tmp;
    }

    // Choose bucketing resolution for event scan.
    let bucketMs = (rm > 0) ? rm : (Math.max(1, (Number(mon.interval_sec) || 5)) * 1000);
    if(!Number.isFinite(bucketMs) || bucketMs <= 0) bucketMs = 5000;
    bucketMs = Math.max(1000, Math.min(bucketMs, 60 * 60 * 1000));

    const xMinN = Number(xMin) || 0;
    const xMaxN = Number(xMax) || 0;
    const span = Math.max(1, xMaxN - xMinN);

    // Build bucket map (worst severity across visible nodes).
    const buckets = new Map(); // t -> {lvl, maxV, maxNid, fail, total}
    const updBucket = (bt, lvl, v, nid, failAdd, totalAdd)=>{
      let b = buckets.get(bt);
      if(!b){
        b = {lvl:0, maxV:null, maxNid:null, fail:0, total:0};
        buckets.set(bt, b);
      }
      if(lvl > b.lvl) b.lvl = lvl;
      if(v != null && Number.isFinite(Number(v))){
        const vv = Number(v);
        if(b.maxV == null || vv > Number(b.maxV)){
          b.maxV = vv;
          b.maxNid = nid;
        }
      }
      if(totalAdd){
        b.total += Math.max(0, Number(totalAdd) || 0);
      }
      if(failAdd){
        b.fail += Math.max(0, Number(failAdd) || 0);
      }
    };

    const nodeIds = Array.isArray(mon && mon.node_ids) ? mon.node_ids.map(x=>String(x)) : Object.keys(per || {});
    for(const nid of nodeIds){
      const nidStr = String(nid);
      const arr = (per && per[nidStr]) ? per[nidStr] : [];
      if(!arr.length) continue;
      const start = _netmonBinarySearchByT(arr, xMinN);
      for(let i=start;i<arr.length;i++){
        const p = arr[i];
        if(!p) continue;
        const t = Number(p.t);
        if(!Number.isFinite(t)) continue;
        if(t > xMaxN) break;
        if(t < xMinN) continue;

        const bt = t - (t % bucketMs);

        let lvl = 0;
        let v = null;
        if(p.v != null && Number.isFinite(Number(p.v))){
          v = Number(p.v);
          if(critThr > 0 && v >= critThr) lvl = 2;
          else if(warnThr > 0 && v >= warnThr) lvl = 1;
        }else{
          // failed sample
          if(p.ok === false || p.v == null) lvl = 2;
        }

        let totalAdd = 0;
        let failAdd = 0;
        if(p.n != null){
          totalAdd = Number(p.n) || 0;
          failAdd = Number(p.f) || 0;
        }else{
          totalAdd = 1;
          if(p.v == null) failAdd = 1;
        }

        updBucket(bt, lvl, v, nidStr, failAdd, totalAdd);
      }
    }

    const times = Array.from(buckets.keys()).sort((a,b)=>a-b);
    const events = [];
    let cur = null;
    let prevT = null;

    const closeCur = ()=>{
      if(cur) events.push(cur);
      cur = null;
    };

    for(const t of times){
      const b = buckets.get(t);
      if(!b) continue;
      let lvl = Number(b.lvl) || 0;

      // Failure ratio overrides (rollup-aware)
      try{
        if(b.total > 0 && b.fail > 0){
          const pct = b.fail / b.total;
          if(pct >= 0.5) lvl = Math.max(lvl, 2);
          else lvl = Math.max(lvl, 1);
        }
      }catch(_e){}

      const gapBreak = (prevT != null) ? (Number(t) - Number(prevT) > bucketMs * 2.2) : false;

      if(lvl <= 0){
        closeCur();
        prevT = t;
        continue;
      }

      if(!cur || cur.lvl !== lvl || gapBreak){
        closeCur();
        cur = {
          lvl,
          start: Number(t),
          end: Number(t) + bucketMs,
          maxV: (b.maxV != null ? Number(b.maxV) : null),
          maxNid: (b.maxNid != null ? String(b.maxNid) : null),
          fail: Number(b.fail) || 0,
          total: Number(b.total) || 0,
        };
      }else{
        cur.end = Number(t) + bucketMs;
        cur.fail += Number(b.fail) || 0;
        cur.total += Number(b.total) || 0;
        if(b.maxV != null && Number.isFinite(Number(b.maxV))){
          const vv = Number(b.maxV);
          if(cur.maxV == null || vv > Number(cur.maxV)){
            cur.maxV = vv;
            cur.maxNid = (b.maxNid != null ? String(b.maxNid) : null);
          }
        }
      }

      prevT = t;
    }
    closeCur();

    // Merge same-level events separated by tiny gaps (reduce noisy fragmentation)
    try{
      const merged = [];
      const gapAllow = bucketMs * 1.10;
      for(const ev of events){
        if(!ev) continue;
        if(ev.parts == null) ev.parts = 1;
        if(!merged.length){
          merged.push(ev);
          continue;
        }
        const last = merged[merged.length-1];
        const gap = Number(ev.start) - Number(last.end);
        if(last && ev.lvl === last.lvl && gap >= 0 && gap <= gapAllow){
          last.end = Math.max(Number(last.end), Number(ev.end));
          last.fail = (Number(last.fail) || 0) + (Number(ev.fail) || 0);
          last.total = (Number(last.total) || 0) + (Number(ev.total) || 0);
          last.parts = (Number(last.parts) || 1) + (Number(ev.parts) || 1);
          if(ev.maxV != null && Number.isFinite(Number(ev.maxV))){
            const vv = Number(ev.maxV);
            if(last.maxV == null || vv > Number(last.maxV)){
              last.maxV = vv;
              last.maxNid = ev.maxNid;
            }
          }
        }else{
          merged.push(ev);
        }
      }
      events.splice(0, events.length, ...merged);
    }catch(_e){}

    // Cache for abnormal center modal
    try{
      this._eventsAll = events.slice();
      this._eventsXMin = xMinN;
      this._eventsXMax = xMaxN;
    }catch(_e){}

    // --- render timeline bar
    const segHtml = [];
    for(const ev of events){
      if(!ev) continue;
      const left = ((ev.start - xMinN) / span) * 100;
      const width = ((ev.end - ev.start) / span) * 100;
      const l = _netmonClamp(left, -2, 102);
      const w = _netmonClamp(width, 0, 102);
      if(w <= 0.05) continue;

      const cls = (ev.lvl >= 2) ? 'crit' : 'warn';
      const stTxt = (ev.lvl >= 2) ? 'CRIT' : 'WARN';
      const durTxt = _netmonFormatDur(ev.end - ev.start);
      const maxTxt = (ev.maxV != null && Number.isFinite(Number(ev.maxV))) ? `${Number(ev.maxV).toFixed(1)}ms` : '—';

      let nodeTxt = '';
      try{
        if(ev.maxNid && st.nodesMeta && st.nodesMeta[String(ev.maxNid)]){
          nodeTxt = String(st.nodesMeta[String(ev.maxNid)].name || ('节点-' + ev.maxNid));
        }
      }catch(_e){}

      let failTxt = '';
      try{
        if(ev.total > 0 && ev.fail > 0){
          failTxt = ` fail=${Math.round(ev.fail)}/${Math.round(ev.total)}`;
        }
      }catch(_e){}

      const title = `${stTxt} ${_netmonFormatTs(ev.start)} ~ ${_netmonFormatTs(ev.end)} (${durTxt}) max=${maxTxt}${nodeTxt ? (' node=' + nodeTxt) : ''}${failTxt}`;

      segHtml.push(
        `<button type="button" class="netmon-event ${cls}" style="left:${l.toFixed(3)}%;width:${w.toFixed(3)}%;" data-from="${Math.round(ev.start)}" data-to="${Math.round(ev.end)}" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}"></button>`
      );
    }
    this.eventsBar.innerHTML = segHtml.join('');


    // --- render compact summary (no long list on the card)
    const critCnt = events.filter(ev=>ev && ev.lvl >= 2).length;
    const warnCnt = events.filter(ev=>ev && ev.lvl === 1).length;
    const failCnt = events.filter(ev=>ev && (Number(ev.total)||0) > 0 && (Number(ev.fail)||0) > 0).length;

    if(this.eventsBadges){
      const bs = [];
      if(critCnt) bs.push(`<span class="nm-badge crit">CRIT ${critCnt}</span>`);
      if(warnCnt) bs.push(`<span class="nm-badge warn">WARN ${warnCnt}</span>`);
      if(failCnt) bs.push(`<span class="nm-badge">FAIL ${failCnt}</span>`);
      if(!bs.length) bs.push(`<span class="nm-badge ok">OK</span>`);
      this.eventsBadges.innerHTML = bs.join('');
    }

    if(this.eventsOpenBtn){
      if(!events.length){
        this.eventsOpenBtn.style.display = 'none';
      }else{
        this.eventsOpenBtn.style.display = '';
        this.eventsOpenBtn.textContent = `查看 ${events.length}`;
      }
    }

    if(this.eventsFoot){
      if(!events.length){
        try{ this.eventsFoot.style.display = ''; }catch(_e){}
        this.eventsFoot.innerHTML = `<div class="muted sm">当前窗口内无异常</div>`;
      }else{
        try{ this.eventsFoot.style.display = 'none'; }catch(_e){}
        this.eventsFoot.innerHTML = ``;
      }
    }
  }
}



// =========================
// NetMon Abnormal Center (one modal shows all abnormal segments)
// =========================

let NETMON_AB_MODAL = null;
let NETMON_AB_VIEW = null; // {mid,target,events,xMin,xMax,selectedKey,q,filter,focusFrom,focusTo}

function _netmonCloseAbModal(){
  try{ if(NETMON_AB_MODAL) NETMON_AB_MODAL.style.display = 'none'; }catch(_e){}
  NETMON_AB_VIEW = null;
  try{ document.body.classList.remove('modal-open'); }catch(_e){}
}

function _netmonAbKey(ev){
  return `${Math.round(Number(ev && ev.start)||0)}-${Math.round(Number(ev && ev.end)||0)}-${Math.round(Number(ev && ev.lvl)||0)}`;
}

function _netmonAbGetSelectedEvent(){
  if(!NETMON_AB_VIEW || !Array.isArray(NETMON_AB_VIEW.events)) return null;
  const key = NETMON_AB_VIEW.selectedKey;
  if(!key) return null;
  for(const ev of NETMON_AB_VIEW.events){
    if(ev && _netmonAbKey(ev) === key) return ev;
  }
  return null;
}

function _netmonEnsureAbModal(){
  if(NETMON_AB_MODAL) return NETMON_AB_MODAL;
  const m = document.createElement('div');
  m.id = 'netmonAbModal';
  m.className = 'modal netmon-ab-modal';
  m.style.display = 'none';

  m.innerHTML = `
    <div class="modal-inner netmon-ab-inner">
      <div class="netmon-ab-head">
        <div style="min-width:0;">
          <div class="h2">异常中心</div>
          <div class="muted sm" id="netmonAbTitle" style="margin-top:4px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"></div>
        </div>
        <div class="right" style="display:flex; gap:8px; align-items:center;">
          <button class="btn xs ghost" type="button" data-action="close">关闭</button>
        </div>
      </div>

      <div class="netmon-ab-summary" id="netmonAbSummary"></div>

      <div class="netmon-ab-body">
        <div class="netmon-ab-list">
          <div class="netmon-ab-tools">
            <input class="input sm" id="netmonAbSearch" placeholder="搜索 节点/时间/max/fail…" />
            <select class="select sm" id="netmonAbFilter" style="max-width:120px;">
              <option value="all">全部</option>
              <option value="crit">CRIT</option>
              <option value="warn">WARN</option>
              <option value="fail">FAIL</option>
            </select>
          </div>
          <div class="netmon-ab-listbox" id="netmonAbList"></div>
        </div>

        <div class="netmon-ab-detail" id="netmonAbDetail">
          <div class="muted sm">选择一段异常查看详情</div>
        </div>
      </div>
    </div>
  `;

  const escSel = (s)=>{
    try{
      if(window.CSS && CSS.escape) return CSS.escape(String(s||''));
    }catch(_e){}
    return String(s||'').replace(/"/g, '');
  };

  // Backdrop click closes
  m.addEventListener('click', (e)=>{
    try{
      if(e.target === m){
        _netmonCloseAbModal();
        return;
      }

      const actEl = (e.target && e.target.closest) ? e.target.closest('[data-action]') : null;
      if(actEl){
        const act = String(actEl.getAttribute('data-action') || '');
        if(act === 'close'){
          _netmonCloseAbModal();
          return;
        }
        const ev = _netmonAbGetSelectedEvent();
        if(!ev || !NETMON_AB_VIEW) return;
        const midStr = String(NETMON_AB_VIEW.mid || '');
        const ch = (NETMON_STATE && NETMON_STATE.charts) ? NETMON_STATE.charts[midStr] : null;

        if(act === 'jump'){
          if(ch && ch.jumpToRange){
            ch.jumpToRange(Number(ev.start), Number(ev.end));
            _netmonCloseAbModal();
          }
          return;
        }
        if(act === 'copy'){
          if(ch && ch.copyShareLinkForRange){
            ch.copyShareLinkForRange(Number(ev.start), Number(ev.end));
          }
          return;
        }
      }

      const row = (e.target && e.target.closest) ? e.target.closest('.netmon-ab-row') : null;
      if(row){
        const key = row.getAttribute('data-key');
        if(key) _netmonAbSelect(key, {scroll:true});
      }
    }catch(_e){}
  });

  // Inputs
  setTimeout(()=>{
    try{
      const qEl = m.querySelector('#netmonAbSearch');
      const fEl = m.querySelector('#netmonAbFilter');
      if(qEl){
        qEl.addEventListener('input', ()=>{
          if(!NETMON_AB_VIEW) return;
          NETMON_AB_VIEW.q = String(qEl.value || '').trim().toLowerCase();
          _netmonAbRenderList();
        });
      }
      if(fEl){
        fEl.addEventListener('change', ()=>{
          if(!NETMON_AB_VIEW) return;
          NETMON_AB_VIEW.filter = String(fEl.value || 'all');
          _netmonAbRenderList();
        });
      }
    }catch(_e){}
  }, 0);

  // ESC closes
  window.addEventListener('keydown', (e)=>{
    try{
      if(e.key === 'Escape' && NETMON_AB_MODAL && NETMON_AB_MODAL.style.display !== 'none'){
        _netmonCloseAbModal();
      }
    }catch(_e){}
  });

  document.body.appendChild(m);
  NETMON_AB_MODAL = m;
  return m;
}

function _netmonOpenAbModal(opts){
  const modal = _netmonEnsureAbModal();
  const o = (opts && typeof opts === 'object') ? opts : {};

  const events = Array.isArray(o.events) ? o.events.slice() : [];
  events.sort((a,b)=>{
    const at = Number(a && a.start) || 0;
    const bt = Number(b && b.start) || 0;
    return bt - at;
  });

  NETMON_AB_VIEW = {
    mid: o.mid,
    target: String(o.target || ''),
    events,
    xMin: (o.xMin != null ? Number(o.xMin) : null),
    xMax: (o.xMax != null ? Number(o.xMax) : null),
    q: '',
    filter: 'all',
    selectedKey: null,
    focusFrom: (o.focusFrom != null ? Number(o.focusFrom) : null),
    focusTo: (o.focusTo != null ? Number(o.focusTo) : null),
  };

  // Reset controls
  try{
    const qEl = modal.querySelector('#netmonAbSearch');
    const fEl = modal.querySelector('#netmonAbFilter');
    if(qEl) qEl.value = '';
    if(fEl) fEl.value = 'all';
  }catch(_e){}

  // Title
  try{
    const tEl = modal.querySelector('#netmonAbTitle');
    if(tEl){
      const range = (NETMON_AB_VIEW.xMin != null && NETMON_AB_VIEW.xMax != null)
        ? `${_netmonFormatTs(NETMON_AB_VIEW.xMin)} ~ ${_netmonFormatTs(NETMON_AB_VIEW.xMax)}`
        : '';
      const target = NETMON_AB_VIEW.target;
      tEl.textContent = target ? `${target}${range ? (' · ' + range) : ''}` : (range || '异常窗口');
    }
  }catch(_e){}

  // Summary
  try{
    const sEl = modal.querySelector('#netmonAbSummary');
    if(sEl){
      const total = events.length;
      const critCnt = events.filter(ev=>ev && Number(ev.lvl) >= 2).length;
      const warnCnt = events.filter(ev=>ev && Number(ev.lvl) === 1).length;
      const failCnt = events.filter(ev=>ev && (Number(ev.total)||0) > 0 && (Number(ev.fail)||0) > 0).length;
      const pills = [];
      pills.push(`<span class="nm-pill ghost"><span class="k">区间异常</span><span class="v">${total}</span></span>`);
      if(critCnt) pills.push(`<span class="nm-pill crit"><span class="k">CRIT</span><span class="v">${critCnt}</span></span>`);
      if(warnCnt) pills.push(`<span class="nm-pill warn"><span class="k">WARN</span><span class="v">${warnCnt}</span></span>`);
      if(failCnt) pills.push(`<span class="nm-pill"><span class="k">FAIL</span><span class="v">${failCnt}</span></span>`);
      if(!total) pills.push(`<span class="nm-pill ok"><span class="k">状态</span><span class="v">OK</span></span>`);
      sEl.innerHTML = pills.join('');
    }
  }catch(_e){}

  // Open
  modal.style.display = '';
  try{ document.body.classList.add('modal-open'); }catch(_e){}

  // Initial selection
  let focusKey = null;
  try{
    const fx = NETMON_AB_VIEW.focusFrom;
    const fy = NETMON_AB_VIEW.focusTo;
    if(Number.isFinite(fx)){
      const hit = events.find(ev=>{
        if(!ev) return false;
        const a = Number(ev.start)||0;
        const b = Number(ev.end)||0;
        if(!Number.isFinite(a) || !Number.isFinite(b) || b<=a) return false;
        if(fy != null && Number.isFinite(fy)) return a <= fx && b >= fy;
        return a <= fx && b >= fx;
      });
      if(hit) focusKey = _netmonAbKey(hit);
    }
  }catch(_e){}
  if(!focusKey && events.length) focusKey = _netmonAbKey(events[0]);
  if(focusKey) NETMON_AB_VIEW.selectedKey = focusKey;

  _netmonAbRenderList();
  _netmonAbRenderDetail();

  // Scroll selected into view
  if(focusKey){
    setTimeout(()=>{
      try{
        const row = modal.querySelector(`.netmon-ab-row[data-key="${focusKey}"]`);
        if(row && row.scrollIntoView) row.scrollIntoView({block:'nearest'});
      }catch(_e){}
    }, 30);
  }
}

function _netmonAbRenderList(){
  if(!NETMON_AB_MODAL || !NETMON_AB_VIEW) return;
  const listEl = NETMON_AB_MODAL.querySelector('#netmonAbList');
  if(!listEl) return;

  const q = String(NETMON_AB_VIEW.q || '').trim().toLowerCase();
  const mode = String(NETMON_AB_VIEW.filter || 'all');
  const st = NETMON_STATE;
  const nodesMeta = (st && st.nodesMeta && typeof st.nodesMeta === 'object') ? st.nodesMeta : {};

  const out = [];
  for(const ev of (NETMON_AB_VIEW.events || [])){
    if(!ev) continue;
    const lvl = Number(ev.lvl)||0;

    if(mode === 'crit' && lvl < 2) continue;
    if(mode === 'warn' && lvl !== 1) continue;
    if(mode === 'fail' && !((Number(ev.total)||0) > 0 && (Number(ev.fail)||0) > 0)) continue;

    let nodeName = '';
    try{
      if(ev.maxNid && nodesMeta[String(ev.maxNid)]){
        nodeName = String(nodesMeta[String(ev.maxNid)].name || nodesMeta[String(ev.maxNid)].display_ip || '');
      }
    }catch(_e){}

    const timeTxt = `${_netmonFormatClock(ev.start)}~${_netmonFormatClock(ev.end)}`;
    const durTxt = _netmonFormatDur((Number(ev.end)||0) - (Number(ev.start)||0));

    const metaParts = [];
    if(ev.maxV != null && Number.isFinite(Number(ev.maxV))) metaParts.push(`max ${Number(ev.maxV).toFixed(1)}ms`);
    if(nodeName) metaParts.push(nodeName);
    if((Number(ev.total)||0) > 0 && (Number(ev.fail)||0) > 0) metaParts.push(`fail ${Math.round(ev.fail)}/${Math.round(ev.total)}`);
    const metaTxt = metaParts.join(' · ');

    if(q){
      const hay = `${timeTxt} ${durTxt} ${metaTxt}`.toLowerCase();
      if(!hay.includes(q)) continue;
    }

    const key = _netmonAbKey(ev);
    const lvTxt = (lvl >= 2) ? 'CRIT' : 'WARN';
    const lvCls = (lvl >= 2) ? 'crit' : 'warn';
    const selCls = (NETMON_AB_VIEW.selectedKey === key) ? 'sel' : '';

    out.push(`
      <div class="netmon-ab-row ${selCls}" data-key="${key}">
        <div class="lv ${lvCls}">${lvTxt}</div>
        <div class="time mono">${escapeHtml(timeTxt)}</div>
        <div class="dur mono muted">${escapeHtml(durTxt)}</div>
        <div class="meta muted sm">${escapeHtml(metaTxt || '')}</div>
      </div>
    `);
  }

  if(!out.length){
    listEl.innerHTML = `<div class="muted sm" style="padding:10px;">无匹配异常</div>`;
  }else{
    listEl.innerHTML = out.join('');
  }
}

function _netmonAbSelect(key, opts){
  if(!NETMON_AB_VIEW) return;
  const k = String(key || '');
  if(!k) return;
  if(NETMON_AB_VIEW.selectedKey === k) return;
  NETMON_AB_VIEW.selectedKey = k;
  _netmonAbRenderList();
  _netmonAbRenderDetail();

  if(opts && opts.scroll && NETMON_AB_MODAL){
    try{
      const row = NETMON_AB_MODAL.querySelector(`.netmon-ab-row[data-key="${k}"]`);
      if(row && row.scrollIntoView) row.scrollIntoView({block:'nearest'});
    }catch(_e){}
  }
}

async function _netmonAbRenderDetail(){
  if(!NETMON_AB_MODAL || !NETMON_AB_VIEW) return;
  const detailEl = NETMON_AB_MODAL.querySelector('#netmonAbDetail');
  if(!detailEl) return;

  const ev = _netmonAbGetSelectedEvent();
  if(!ev){
    detailEl.innerHTML = `<div class="muted sm">当前窗口内无异常</div>`;
    return;
  }

  const mid = Number(NETMON_AB_VIEW.mid) || 0;
  const from = Math.round(Number(ev.start)||0);
  const to = Math.round(Number(ev.end)||0);
  if(mid <= 0 || !Number.isFinite(from) || !Number.isFinite(to) || to <= from){
    detailEl.innerHTML = `<div class="muted" style="color:var(--bad);">异常区间参数无效</div>`;
    return;
  }

  const headTxt = `${(Number(ev.lvl)||0) >= 2 ? 'CRIT' : 'WARN'} · ${_netmonFormatTs(from)} ~ ${_netmonFormatTs(to)} · ${_netmonFormatDur(to-from)}`;
  detailEl.innerHTML = `<div class="netmon-ab-detail-title mono">${escapeHtml(headTxt)}</div><div class="muted sm">加载中…</div>`;

  // Cache HTML for this range
  let cache = null;
  try{
    if(!window.__NETMON_AB_CACHE__) window.__NETMON_AB_CACHE__ = new Map();
    if(window.__NETMON_AB_CACHE__ instanceof Map) cache = window.__NETMON_AB_CACHE__;
  }catch(_e){}
  const cacheKey = `${mid}|${from}|${to}`;
  try{
    if(cache && cache.has(cacheKey)){
      detailEl.innerHTML = cache.get(cacheKey);
      return;
    }
  }catch(_e){}

  try{
    const st = NETMON_STATE;
    let url = `/api/netmon/range?mid=${encodeURIComponent(String(mid))}&from=${encodeURIComponent(String(from))}&to=${encodeURIComponent(String(to))}`;
    try{ if(st && st.shareToken){ url += `&t=${encodeURIComponent(String(st.shareToken))}`; } }catch(_e){}

    const res = await fetchJSON(url);
    if(!res || res.ok === false){
      throw new Error(res && res.error ? res.error : '加载失败');
    }

    const mInfo = res.monitor || {};
    const nodesMeta = (res.nodes && typeof res.nodes === 'object') ? res.nodes : (st ? st.nodesMeta : {});
    const series = (res.series && typeof res.series === 'object') ? res.series : {};

    let warnThr = Number(mInfo.warn_ms) || 0;
    let critThr = Number(mInfo.crit_ms) || 0;
    if(warnThr > 0 && critThr > 0 && warnThr > critThr){
      const tmp = warnThr; warnThr = critThr; critThr = tmp;
    }

    const nodeIdsRaw = Array.isArray(mInfo.node_ids) ? mInfo.node_ids : Object.keys(series);
    const nodeIds = [];
    for(const nid of nodeIdsRaw){
      const s = String(nid);
      if(!nodeIds.includes(s)) nodeIds.push(s);
    }
    for(const k of Object.keys(series)){
      const s = String(k);
      if(!nodeIds.includes(s)) nodeIds.push(s);
    }

    const _p95 = (vals)=>{
      const n = vals.length;
      if(!n) return null;
      if(n >= 3){
        const sorted = vals.slice().sort((a,b)=>a-b);
        const idx = Math.min(sorted.length - 1, Math.floor(0.95 * (sorted.length - 1)));
        return sorted[idx];
      }
      return Math.max(...vals);
    };

    const stats = [];
    let gMax = null;
    let gMaxNid = null;
    const gVals = [];
    let gTotal = 0;
    let gFail = 0;

    for(const nid of nodeIds){
      const pts = Array.isArray(series[nid]) ? series[nid] : [];
      const vals = [];
      let total = 0;
      let fail = 0;

      for(const p of pts){
        if(!p) continue;
        total += 1;
        gTotal += 1;

        if(p.ok){
          const v = Number(p.v);
          if(Number.isFinite(v)){
            vals.push(v);
            gVals.push(v);
            if(gMax == null || v > gMax){
              gMax = v;
              gMaxNid = nid;
            }
          }else{
            fail += 1;
            gFail += 1;
          }
        }else{
          fail += 1;
          gFail += 1;
        }
      }

      const okCnt = vals.length;
      const maxV = okCnt ? Math.max(...vals) : null;
      let avgV = null;
      if(okCnt){
        let sum = 0;
        for(const v of vals) sum += v;
        avgV = sum / okCnt;
      }
      const p95 = _p95(vals);
      const failRate = total > 0 ? (fail / total) : 0;

      let sev = 0;
      if(failRate >= 0.5) sev = 2;
      else if(critThr > 0 && maxV != null && maxV >= critThr) sev = 2;
      else if(warnThr > 0 && maxV != null && maxV >= warnThr) sev = 1;
      else if(failRate > 0) sev = 1;

      let nm = '节点-' + nid;
      let online = null;
      try{
        if(nodesMeta && nodesMeta[nid]){
          nm = String(nodesMeta[nid].name || nodesMeta[nid].display_ip || nm);
          online = !!nodesMeta[nid].online;
        }
      }catch(_e){}

      stats.push({nid, name:nm, online, total, fail, failRate, okCnt, maxV, avgV, p95, sev});
    }

    const totNodes = stats.length;
    const impacted = stats.filter(s=>s && s.sev > 0).length;
    const impactedRatio = totNodes ? (impacted / totNodes) : 0;
    const failRateAll = gTotal ? (gFail / gTotal) : 0;
    const p95All = _p95(gVals);

    let hintCls = 'ok';
    let hint = '';
    if(impactedRatio >= 0.7 && (failRateAll >= 0.2 || (critThr > 0 && gMax != null && gMax >= critThr))){
      hintCls = 'crit';
      hint = '全局异常：多节点同时失败/超阈，疑似目标侧或公网链路波动。';
    }else if(impactedRatio <= 0.25 && impacted > 0){
      hintCls = 'warn';
      hint = '局部异常：少数节点异常，疑似单节点出口/线路问题。';
    }else if(impactedRatio >= 0.7 && impacted > 0){
      hintCls = 'warn';
      hint = '多节点异常：可能区域性链路抖动或目标端拥塞。';
    }else if(impacted > 0){
      hintCls = 'warn';
      hint = '部分节点异常：建议对比异常节点出口/ISP/路由。';
    }else{
      hintCls = 'ok';
      hint = '该区间无明显异常（阈值较高或数据不足）。';
    }

    let maxNodeName = '';
    try{
      if(gMaxNid && nodesMeta && nodesMeta[String(gMaxNid)]){
        maxNodeName = String(nodesMeta[String(gMaxNid)].name || '');
      }
    }catch(_e){}
    if(!maxNodeName && gMaxNid) maxNodeName = '节点-' + gMaxNid;

    const kpis = [];
    kpis.push(`<span class="nm-pill ${hintCls}"><span class="k">影响节点</span><span class="v">${impacted}/${totNodes || 0}</span></span>`);
    if(gMax != null){
      const maxTxt = `${Number(gMax).toFixed(1)}ms`;
      kpis.push(`<span class="nm-pill ${hintCls}"><span class="k">峰值</span><span class="v">${escapeHtml(maxTxt)}${maxNodeName ? (' · ' + escapeHtml(maxNodeName)) : ''}</span></span>`);
    }
    if(p95All != null){
      kpis.push(`<span class="nm-pill"><span class="k">P95</span><span class="v">${Number(p95All).toFixed(1)}ms</span></span>`);
    }
    if(gTotal > 0){
      kpis.push(`<span class="nm-pill ${(failRateAll>0)?'warn':'ok'}"><span class="k">失败率</span><span class="v">${Math.round(failRateAll*100)}% (${gFail}/${gTotal})</span></span>`);
    }
    if(warnThr > 0) kpis.push(`<span class="nm-pill warn"><span class="k">Warn</span><span class="v">${warnThr}ms</span></span>`);
    if(critThr > 0) kpis.push(`<span class="nm-pill crit"><span class="k">Crit</span><span class="v">${critThr}ms</span></span>`);

    stats.sort((a,b)=>{
      if(a.sev !== b.sev) return b.sev - a.sev;
      const ap = (a.p95 != null) ? a.p95 : -1;
      const bp = (b.p95 != null) ? b.p95 : -1;
      if(ap !== bp) return bp - ap;
      const am = (a.maxV != null) ? a.maxV : -1;
      const bm = (b.maxV != null) ? b.maxV : -1;
      if(am !== bm) return bm - am;
      return (b.failRate || 0) - (a.failRate || 0);
    });

    let table = `<div class="netmon-ab-tablewrap"><table class="netmon-ab-table"><thead><tr>
      <th style="width:240px;">节点</th>
      <th>最大</th>
      <th>平均</th>
      <th>P95</th>
      <th>失败率</th>
      <th>样本</th>
    </tr></thead><tbody>`;

    for(const s of stats){
      const rowCls = (s.sev >= 2) ? 'crit' : ((s.sev >= 1) ? 'warn' : '');
      const maxTxt = (s.maxV != null && Number.isFinite(s.maxV)) ? `${s.maxV.toFixed(1)}ms` : '—';
      const avgTxt = (s.avgV != null && Number.isFinite(s.avgV)) ? `${s.avgV.toFixed(1)}ms` : '—';
      const p95Txt = (s.p95 != null && Number.isFinite(s.p95)) ? `${s.p95.toFixed(1)}ms` : '—';
      const frTxt = (s.total > 0) ? `${Math.round(s.failRate*100)}%` : '—';
      const smpTxt = `${s.total || 0}`;
      const dotCls = (s.online === null) ? 'offline' : (s.online ? 'online' : 'offline');
      const nm = escapeHtml(String(s.name || ('节点-' + s.nid)));

      table += `<tr class="${rowCls}">
        <td><span class="n-dot ${dotCls}" aria-hidden="true"></span><span class="mono">${nm}</span></td>
        <td class="mono">${escapeHtml(maxTxt)}</td>
        <td class="mono">${escapeHtml(avgTxt)}</td>
        <td class="mono">${escapeHtml(p95Txt)}</td>
        <td class="mono">${escapeHtml(frTxt)}</td>
        <td class="mono muted">${escapeHtml(smpTxt)}</td>
      </tr>`;
    }

    table += `</tbody></table></div>`;

    const html = `
      <div class="netmon-ab-detail-title mono">${escapeHtml(headTxt)}</div>
      <div class="netmon-ab-hint ${hintCls}"><span class="dot" aria-hidden="true"></span><div class="txt">${escapeHtml(hint)}</div></div>
      <div class="netmon-ab-kpis">${kpis.join('')}</div>
      ${table}
      <div class="netmon-ab-actions">
        <button class="btn xs ghost" type="button" data-action="jump">定位到图表</button>
        <button class="btn xs" type="button" data-action="copy">复制只读链接</button>
      </div>
    `;

    detailEl.innerHTML = html;
    try{ if(cache) cache.set(cacheKey, html); }catch(_e){}

  }catch(e){
    const msg = (e && e.message) ? e.message : String(e);
    detailEl.innerHTML = `<div class="netmon-ab-detail-title mono">${escapeHtml(headTxt)}</div><div class="muted" style="color:var(--bad);">加载失败：${escapeHtml(msg)}</div>`;
  }
}
// Expose for template inline init
window.initNetMonPage = initNetMonPage;
