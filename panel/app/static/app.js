// Realm Pro Panel Frontend JS (v15.1)

function qs(sel, el=document){return el.querySelector(sel)}
function qsa(sel, el=document){return Array.from(el.querySelectorAll(sel))}

function escapeHtml(s){
  return (s||"")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"','&quot;')
}

function showToast(msg){
  const t = qs('#toast')
  if(!t){
    alert(msg)
    return
  }
  t.textContent = msg
  t.classList.remove('hidden')
  setTimeout(()=>t.classList.add('hidden'), 2600)
}

async function api(url, method='GET', body=null){
  const opt = { method, headers: {} }
  if(body !== null){
    opt.headers['Content-Type'] = 'application/json'
    opt.body = JSON.stringify(body)
  }
  const res = await fetch(url, opt)
  const ct = res.headers.get('content-type')||''
  let data = null
  if(ct.includes('application/json')){
    data = await res.json().catch(()=>null)
  }else{
    data = await res.text().catch(()=>null)
  }
  if(!res.ok){
    const msg = (data && data.detail) ? data.detail : (typeof data === 'string' ? data : '请求失败')
    throw new Error(msg)
  }
  return data
}

function badgeDot(ok){
  if(ok===true) return '<span class="dot ok"></span><span class="small" style="color:rgba(167,255,207,0.85)">在线</span>'
  if(ok===false) return '<span class="dot bad"></span><span class="small" style="color:rgba(255,159,159,0.85)">离线</span>'
  return '<span class="dot warn"></span><span class="small">未知</span>'
}

function ruleTypeLabel(t){
  if(t==='tcp_udp') return 'TCP/UDP'
  if(t==='wss_client') return 'WSS 客户端'
  if(t==='wss_server') return 'WSS 服务端'
  return t || '-'
}

function renderTargets(targets){
  if(!targets || targets.length===0) return '<span class="small">(无目标)</span>'
  return targets.map(t=>`<span class="pill">${escapeHtml(t)}</span>`).join(' ')
}

function getPort(listen){
  if(!listen) return ''
  const idx = listen.lastIndexOf(':')
  return idx>=0 ? listen.slice(idx+1) : listen
}

function sumOutbound(outbound){
  if(!outbound) return 0
  try{
    return Object.values(outbound).reduce((a,b)=>a + (typeof b==='number'?b:0), 0)
  }catch(_){
    return 0
  }
}

function renderRuleCard(rule, service){
  const enabled = !!rule.enabled
  const statusPill = enabled ? '<span class="pill" style="border-color:rgba(34,197,94,.35)">运行</span>' : '<span class="pill" style="border-color:rgba(245,158,11,.35)">暂停</span>'

  const conn = service && service.connections ? service.connections[rule.id] : null
  const inbound = conn && typeof conn.inbound==='number' ? conn.inbound : 0
  const outSum = conn ? sumOutbound(conn.outbound) : 0

  const tstat = service && service.target_status ? service.target_status[rule.id] : null
  const tstatHtml = tstat ? Object.entries(tstat).map(([t,ok])=>{
    const c = ok ? 'ok' : 'bad'
    return `<span class="pill ${c}">${escapeHtml(t)} ${ok?'通':'断'}</span>`
  }).join(' ') : ''

  return `
    <div class="glass" style="padding:12px; margin-bottom:10px;">
      <div class="row" style="justify-content:space-between; gap:10px; flex-wrap:wrap;">
        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
          ${statusPill}
          <span class="mono">${escapeHtml(rule.listen)}</span>
          <span class="pill">${escapeHtml(ruleTypeLabel(rule.type))}</span>
          <span class="small" style="opacity:.85;">${escapeHtml(rule.name||'')}</span>
        </div>
        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
          <span class="mono">入:${inbound} 出:${outSum}</span>
          <button class="btn" data-action="toggle" data-rule-id="${escapeHtml(rule.id)}">${enabled ? '暂停' : '启用'}</button>
          <button class="btn danger" data-action="delete" data-rule-id="${escapeHtml(rule.id)}">删除</button>
        </div>
      </div>
      <div style="margin-top:10px; display:flex; flex-wrap:wrap; gap:6px;">
        ${renderTargets(rule.targets)}
      </div>
      ${tstatHtml ? `<div style="margin-top:10px; display:flex; flex-wrap:wrap; gap:6px;">${tstatHtml}</div>` : ''}
    </div>
  `
}

// ------------------------
// Index page
// ------------------------
async function refreshIndex(){
  const list = qs('#agentsList')
  if(!list) return

  let data
  try{
    data = await api('/api/agents')
  }catch(e){
    return
  }

  const agents = data.agents || []
  await Promise.allSettled(agents.map(async (a)=>{
    const id = a.id
    const stEl = qs(`[data-agent-status="${id}"]`)
    const lastEl = qs(`[data-agent-last="${id}"]`)
    if(stEl) stEl.innerHTML = badgeDot(null) + '<span class="small" style="margin-left:8px">检测中</span>'
    try{
      const s = await api(`/api/agents/${id}/service`)
      if(stEl) stEl.innerHTML = `<div style="display:flex; align-items:center; gap:8px;">${badgeDot(true)}<span class="mono">${escapeHtml(s.realm_status||'-')}</span></div>`
      if(lastEl) lastEl.textContent = new Date((s.now||Date.now()/1000)*1000).toLocaleString()
    }catch(_){
      if(stEl) stEl.innerHTML = `<div style="display:flex; align-items:center; gap:8px;">${badgeDot(false)}<span class="small">连接失败</span></div>`
    }
  }))
}

// ------------------------
// Agent detail page
// ------------------------
function openModal(){
  const m = qs('#ruleModal')
  if(!m) return
  m.classList.remove('hidden')
  m.classList.add('open')
  document.body.style.overflow = 'hidden'
}
function closeModal(){
  const m = qs('#ruleModal')
  if(!m) return
  m.classList.remove('open')
  m.classList.add('hidden')
  document.body.style.overflow = 'auto'
}

function syncRuleFields(){
  const type = qs('#ruleType')?.value || 'tcp_udp'
  const wssBox = qs('#wssBox')
  const pairBox = qs('#pairCodeBox')
  const lbBox = qs('#lbBox')

  // WSS 参数
  if(wssBox) wssBox.classList.toggle('hidden', !(type==='wss_client' || type==='wss_server'))
  if(pairBox) pairBox.classList.toggle('hidden', !(type==='wss_client'))

  // 负载均衡算法：仅 TCP/UDP 且多目标时才显示
  if(lbBox){
    lbBox.classList.toggle('hidden', type!=='tcp_udp')
  }
}

async function refreshAgentDetail(){
  const root = qs('[data-agent-id]')
  if(!root) return
  const agentId = root.getAttribute('data-agent-id')

  let service
  try{
    service = await api(`/api/agents/${agentId}/service`)
  }catch(e){
    showToast(e.message || '获取服务状态失败')
    return
  }

  // service summary
  const online = service.realm_active === true
  const onlineDot = qs('#svOnline')
  if(onlineDot){
    onlineDot.classList.remove('ok','bad','warn')
    onlineDot.classList.add(online ? 'ok' : 'bad')
  }
  const setTxt = (id, txt)=>{ const el = qs('#'+id); if(el) el.textContent = txt }
  setTxt('svRealm', service.realm_status || '-')
  setTxt('svRules', `${service.rules_enabled||0}/${service.rules_total||0}`)
  setTxt('svUpdated', new Date((service.now||Date.now()/1000)*1000).toLocaleString())

  // rules
  let rulesData
  try{
    rulesData = await api(`/api/agents/${agentId}/rules`)
  }catch(e){
    showToast(e.message || '获取规则失败')
    return
  }

  const rules = rulesData.rules || []
  const wrap = qs('#rulesWrap')
  if(wrap){
    if(rules.length===0){
      wrap.innerHTML = '<div class="small" style="opacity:.8; padding:6px 2px;">暂无规则，点击「添加规则」开始。</div>'
    }else{
      wrap.innerHTML = rules.map(r=>renderRuleCard(r, service)).join('')
      // bind actions
      qsa('button[data-action]', wrap).forEach(btn=>{
        btn.addEventListener('click', async ()=>{
          const act = btn.getAttribute('data-action')
          const rid = btn.getAttribute('data-rule-id')
          try{
            if(act==='toggle'){
              const toEnable = btn.textContent.trim() === '启用'
              await api(`/api/agents/${agentId}/rules/${rid}/toggle`, 'POST', {enabled: toEnable})
              showToast('已更新规则状态')
              await refreshAgentDetail()
            }else if(act==='delete'){
              if(!confirm('确定删除这条规则？')) return
              await api(`/api/agents/${agentId}/rules/${rid}`, 'DELETE')
              showToast('已删除规则')
              await refreshAgentDetail()
            }
          }catch(e){
            showToast(e.message || '操作失败')
          }
        })
      })
    }
  }
}

async function bindRuleModal(){
  const root = qs('[data-agent-id]')
  if(!root) return
  const agentId = root.getAttribute('data-agent-id')

  const btnAdd = qs('#btnAddRule')
  if(btnAdd) btnAdd.addEventListener('click', ()=>{ openModal(); syncRuleFields() })

  const btnClose = qs('#btnCloseModal')
  if(btnClose) btnClose.addEventListener('click', closeModal)

  const btnCancel = qs('#btnCancel')
  if(btnCancel) btnCancel.addEventListener('click', closeModal)

  const backdrop = qs('#modalBackdrop')
  if(backdrop) backdrop.addEventListener('click', (e)=>{
    if(e.target === backdrop) closeModal()
  })

  const typeSel = qs('#ruleType')
  if(typeSel) typeSel.addEventListener('change', syncRuleFields)

  const form = qs('#ruleForm')
  if(!form) return

  form.addEventListener('submit', async (ev)=>{
    ev.preventDefault()
    try{
      const get = (name)=> (form.elements.namedItem(name)?.value || '').trim()
      const getBool = (name)=> !!(form.elements.namedItem(name)?.checked)

      const name = get('name') || 'Rule'
      const listenPort = parseInt(get('listen_port'), 10)
      const type = get('type') || 'tcp_udp'
      const protocol = get('protocol') || 'tcp+udp'
      const balance = get('balance') || 'roundrobin'
      const enabled = getBool('enabled')

      if(!listenPort || listenPort<1 || listenPort>65535) throw new Error('本地端口不正确')

      const targetsRaw = get('targets')
      const targets = targetsRaw ? targetsRaw.split(/\n+/).map(s=>s.trim()).filter(Boolean) : []
      if(type !== 'wss_server' && targets.length===0) throw new Error('请至少填写一个目标地址')

      const payload = { name, listen_port: listenPort, type, protocol, targets, balance, enabled }

      if(type === 'wss_client'){
        const pair = get('pair_code')
        if(pair) payload.wss_pair_code = pair
        payload.wss_host = get('wss_host') || null
        payload.wss_path = get('wss_path') || null
        payload.wss_sni = get('wss_sni') || null
        payload.wss_insecure = getBool('wss_insecure')
      }
      if(type === 'wss_server'){
        payload.wss_host = get('wss_host') || null
        payload.wss_path = get('wss_path') || null
        payload.wss_sni = get('wss_sni') || null
        payload.wss_insecure = getBool('wss_insecure')
      }

      const res = await api(`/api/agents/${agentId}/rules`, 'POST', payload)

      // show pair code if returned (WSS server auto created)
      const pairBox = qs('#pairResult')
      if(pairBox){
        pairBox.classList.add('hidden')
      }

      if(res && res.pair_code){
        const codeEl = qs('#pairCode')
        if(codeEl) codeEl.textContent = res.pair_code
        if(pairBox) pairBox.classList.remove('hidden')
      }

      showToast('规则已创建')
      closeModal()
      await refreshAgentDetail()

      // Reset
      form.reset()
      // Keep default values
      qs('#ruleType').value = 'tcp_udp'
      syncRuleFields()

    }catch(e){
      showToast(e.message || '创建失败')
    }
  })

  const btnApply = qs('#btnApply')
  if(btnApply){
    btnApply.addEventListener('click', async ()=>{
      try{
        await api(`/api/agents/${agentId}/apply`, 'POST', {})
        showToast('已应用配置并重启 realm')
        await refreshAgentDetail()
      }catch(e){
        showToast(e.message || '应用失败')
      }
    })
  }

  const btnCopy = qs('#btnCopy')
  if(btnCopy){
    btnCopy.addEventListener('click', async ()=>{
      try{
        const code = qs('#pairCode')?.textContent || ''
        await navigator.clipboard.writeText(code)
        showToast('已复制对接码')
      }catch(_){
        showToast('复制失败，请手动复制')
      }
    })
  }
}

window.addEventListener('DOMContentLoaded', async ()=>{
  try{
    await refreshIndex()
    await refreshAgentDetail()
    await bindRuleModal()

    // periodic refresh
    if(qs('#agentsList')) setInterval(()=>refreshIndex().catch(()=>{}), 4500)
    if(qs('[data-agent-id]')) setInterval(()=>refreshAgentDetail().catch(()=>{}), 2600)
  }catch(_){
    // ignore
  }
})
