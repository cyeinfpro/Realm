// Realm Pro Panel v14 - minimal vanilla JS

const $ = (sel, el=document) => el.querySelector(sel);
const $$ = (sel, el=document) => Array.from(el.querySelectorAll(sel));

function toast(msg, type='') {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  t.className = `toast ${type}`;
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
}

async function api(url, opts={}) {
  const r = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!r.ok) {
    const txt = await r.text();
    throw new Error(txt || `HTTP ${r.status}`);
  }
  const ct = r.headers.get('content-type') || '';
  return ct.includes('application/json') ? r.json() : r.text();
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => toast('已复制'), () => toast('复制失败', 'bad'));
}

function escapeHtml(s='') {
  return String(s)
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'",'&#39;');
}

function openModal(title, innerHtml, actionsHtml='') {
  const root = $('#modalRoot');
  root.hidden = false;
  root.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true">
      <div class="modal-head">
        <div class="modal-title">${escapeHtml(title)}</div>
        <button class="btn ghost" id="_mClose">关闭</button>
      </div>
      <div class="modal-body">${innerHtml}</div>
      <div class="modal-actions">${actionsHtml}</div>
    </div>
  `;
  $('#_mClose', root).onclick = closeModal;
  root.onclick = (e) => {
    if (e.target === root) closeModal();
  };
}

function closeModal() {
  const root = $('#modalRoot');
  root.hidden = true;
  root.innerHTML = '';
}

// ---------------- Dashboard ----------------

async function initDashboard() {
  const btn = $('#btnNewPair');
  if (!btn) return;

  btn.onclick = async () => {
    try {
      const res = await api('/api/pair_codes', { method: 'POST', body: JSON.stringify({ ttl: 900 }) });
      openModal('配对码已生成', `
        <div class="hint">在 <b>Agent 安装脚本</b> 中输入以下配对码完成绑定：</div>
        <div class="code">${escapeHtml(res.code)}</div>
        <div class="row" style="gap:10px; margin-top:10px;">
          <button class="btn" id="mCopy">一键复制</button>
          <button class="btn ghost" id="mClose2">关闭</button>
        </div>
        <div class="kv" style="margin-top:12px;">
          <div><span>有效期：</span>${Math.round((res.expires_at - Date.now()/1000))} 秒</div>
        </div>
      `);
      $('#mCopy').onclick = () => copyText(res.code);
      $('#mClose2').onclick = closeModal;
    } catch (e) {
      toast('生成失败：' + e.message, 'bad');
    }
  };

  $$('.copy').forEach((b) => {
    b.onclick = () => {
      const val = b.getAttribute('data-copy') || '';
      copyText(val);
    };
  });

  $$('.agent-card').forEach((card) => {
    card.onclick = () => {
      const id = card.getAttribute('data-agent');
      if (id) window.location.href = `/agents/${id}`;
    };
  });
}

// ---------------- Agent Detail ----------------

function pill(ok, labelOk='通', labelBad='断') {
  return ok ? `<span class="pill ok">${labelOk}</span>` : `<span class="pill bad">${labelBad}</span>`;
}

function ruleTypeLabel(t) {
  if (t === 'wss_server') return 'WSS 接收';
  if (t === 'wss_client') return 'WSS 客户端';
  return 'TCP/UDP';
}

async function initAgentDetail() {
  const el = $('#rulesMount');
  if (!el) return;
  const agentId = el.getAttribute('data-agent');

  const btnAdd = $('#btnAddRule');
  const btnApply = $('#btnApply');
  const btnLogs = $('#btnLogs');

  async function refresh() {
    el.innerHTML = '<div class="muted">加载中...</div>';
    try {
      const [rules, st] = await Promise.all([
        api(`/api/agents/${agentId}/rules`),
        api(`/api/agents/${agentId}/status`),
      ]);

      const conn = st.conn_counts || {};
      const targetStatus = st.target_status || {};

      if (!rules.length) {
        el.innerHTML = '<div class="muted">暂无规则。点击右上角“新增规则”。</div>';
        return;
      }

      const rows = rules.map((r) => {
        const cs = conn[r.id] || { inbound: 0, outbound: {} };
        const ts = targetStatus[r.id] || {};
        const targets = (r.targets || []).map((t) => {
          const up = (t in ts) ? ts[t] : null;
          const outCnt = (cs.outbound && cs.outbound[t]) ? cs.outbound[t] : 0;
          return `
            <div class="target">
              ${up === null ? '<span class="pill">?</span>' : pill(!!up)}
              <span class="mono">${escapeHtml(t)}</span>
              <span class="muted">连接:${outCnt}</span>
            </div>
          `;
        }).join('');

        return `
          <tr>
            <td>
              <div class="rule-name">${escapeHtml(r.name)}</div>
              <div class="muted">${ruleTypeLabel(r.type)} · <span class="mono">${escapeHtml(r.listen)}</span></div>
            </td>
            <td>
              <div class="muted">入站连接：<b>${cs.inbound || 0}</b></div>
              <div class="targets">${targets || '<span class="muted">无目标</span>'}</div>
            </td>
            <td style="width:120px;">
              <label class="switch">
                <input type="checkbox" ${r.enabled ? 'checked' : ''} data-act="toggle" data-id="${r.id}" />
                <span class="slider"></span>
              </label>
            </td>
            <td style="width:210px; text-align:right;">
              <button class="btn ghost" data-act="edit" data-id="${r.id}">编辑</button>
              <button class="btn ghost" data-act="clone" data-id="${r.id}">克隆</button>
              <button class="btn danger" data-act="del" data-id="${r.id}">删除</button>
            </td>
          </tr>
        `;
      }).join('');

      el.innerHTML = `
        <div class="table">
          <table>
            <thead>
              <tr>
                <th>规则</th>
                <th>目标状态</th>
                <th>启用</th>
                <th style="text-align:right">操作</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;

      $$('input[data-act="toggle"]', el).forEach((i) => {
        i.onchange = async () => {
          try {
            await api(`/api/agents/${agentId}/rules/${i.getAttribute('data-id')}/toggle?enabled=${i.checked}`, { method: 'POST' });
            toast('已更新');
            refresh();
          } catch (e) {
            toast('更新失败：' + e.message, 'bad');
          }
        };
      });

      $$('button[data-act="del"]', el).forEach((b) => {
        b.onclick = async () => {
          const rid = b.getAttribute('data-id');
          if (!confirm('确定删除该规则？')) return;
          try {
            await api(`/api/agents/${agentId}/rules/${rid}`, { method: 'DELETE' });
            toast('已删除');
            refresh();
          } catch (e) {
            toast('删除失败：' + e.message, 'bad');
          }
        };
      });

      $$('button[data-act="edit"]', el).forEach((b) => {
        b.onclick = () => showRuleModal('edit', rules.find(x => x.id === b.getAttribute('data-id')));
      });

      $$('button[data-act="clone"]', el).forEach((b) => {
        b.onclick = () => showRuleModal('clone', rules.find(x => x.id === b.getAttribute('data-id')));
      });

    } catch (e) {
      el.innerHTML = `<div class="muted">加载失败：${escapeHtml(e.message)}</div>`;
    }
  }

  function ruleFormHtml(mode, rule) {
    const r = rule || { name:'', type:'tcp_udp', listen:'0.0.0.0:80', protocol:'tcp+udp', targets:['1.1.1.1:80'], balance:'roundrobin', enabled:true, wss_host:'', wss_path:'', wss_sni:'', wss_insecure:false };
    const targetsText = (r.targets || []).join('\n');
    return `
      <div class="form">
        <div class="field">
          <label>规则名称</label>
          <input id="f_name" value="${escapeHtml(r.name || '')}" placeholder="例如：Web 80" />
        </div>
        <div class="field">
          <label>类型</label>
          <select id="f_type">
            <option value="tcp_udp" ${r.type==='tcp_udp'?'selected':''}>TCP/UDP</option>
            <option value="wss_client" ${r.type==='wss_client'?'selected':''}>WSS 客户端（发起）</option>
            <option value="wss_server" ${r.type==='wss_server'?'selected':''}>WSS 接收（服务端）</option>
          </select>
        </div>
        <div class="field">
          <label>监听地址</label>
          <input id="f_listen" value="${escapeHtml(r.listen || '')}" placeholder="0.0.0.0:443" />
        </div>
        <div class="field">
          <label>协议</label>
          <select id="f_proto">
            <option value="tcp" ${r.protocol==='tcp'?'selected':''}>TCP</option>
            <option value="udp" ${r.protocol==='udp'?'selected':''}>UDP</option>
            <option value="tcp+udp" ${r.protocol==='tcp+udp'?'selected':''}>TCP+UDP</option>
          </select>
          <div class="hint">WSS 规则一般使用 TCP</div>
        </div>
        <div class="field">
          <label>目标地址（每行一个 host:port）</label>
          <textarea id="f_targets" rows="5" placeholder="1.2.3.4:80\n5.6.7.8:80">${escapeHtml(targetsText)}</textarea>
          <div class="hint">多个目标会自动负载均衡</div>
        </div>
        <div class="field">
          <label>负载算法</label>
          <select id="f_balance">
            <option value="roundrobin" ${r.balance==='roundrobin'?'selected':''}>Round Robin</option>
            <option value="iphash" ${r.balance==='iphash'?'selected':''}>IP Hash</option>
          </select>
        </div>
        <div class="split"></div>
        <div class="field">
          <label>WSS Host（可选）</label>
          <input id="f_whost" value="${escapeHtml(r.wss_host || '')}" placeholder="例如：www.bing.com" />
        </div>
        <div class="field">
          <label>WSS Path（可选）</label>
          <input id="f_wpath" value="${escapeHtml(r.wss_path || '')}" placeholder="例如：/ws" />
        </div>
        <div class="field">
          <label>WSS SNI（可选）</label>
          <input id="f_wsni" value="${escapeHtml(r.wss_sni || '')}" placeholder="默认等于 Host" />
        </div>
        <div class="row between">
          <div class="muted">启用该规则</div>
          <label class="switch">
            <input id="f_enabled" type="checkbox" ${r.enabled ? 'checked' : ''} />
            <span class="slider"></span>
          </label>
        </div>
      </div>
    `;
  }

  async function showRuleModal(mode, rule) {
    const title = mode === 'edit' ? '编辑规则' : (mode === 'clone' ? '克隆规则' : '新增规则');
    openModal(title, ruleFormHtml(mode, rule), `
      <button class="btn ghost" id="mCancel">取消</button>
      <button class="btn" id="mSave">保存</button>
    `);
    $('#mCancel').onclick = closeModal;

    $('#f_type').onchange = () => {
      const t = $('#f_type').value;
      if (t !== 'tcp_udp') $('#f_proto').value = 'tcp';
    };

    $('#mSave').onclick = async () => {
      try {
        const payload = {
          name: $('#f_name').value.trim() || 'Rule',
          type: $('#f_type').value,
          listen: $('#f_listen').value.trim(),
          protocol: $('#f_proto').value,
          targets: $('#f_targets').value.split(/\n+/).map(x => x.trim()).filter(Boolean),
          balance: $('#f_balance').value,
          enabled: $('#f_enabled').checked,
          wss_host: $('#f_whost').value.trim() || null,
          wss_path: $('#f_wpath').value.trim() || null,
          wss_sni: $('#f_wsni').value.trim() || null,
        };

        if (mode === 'edit') {
          await api(`/api/agents/${agentId}/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify(payload) });
          toast('已保存');
        } else {
          await api(`/api/agents/${agentId}/rules`, { method: 'POST', body: JSON.stringify(payload) });
          toast(mode === 'clone' ? '已克隆' : '已新增');
        }
        closeModal();
        refresh();
      } catch (e) {
        toast('保存失败：' + e.message, 'bad');
      }
    };
  }

  btnAdd && (btnAdd.onclick = () => showRuleModal('new', null));

  btnApply && (btnApply.onclick = async () => {
    try {
      const res = await api(`/api/agents/${agentId}/apply`, { method: 'POST' });
      toast(res.ok ? '已应用并重启 Realm' : ('应用失败：' + res.message), res.ok ? '' : 'bad');
      refresh();
    } catch (e) {
      toast('应用失败：' + e.message, 'bad');
    }
  });

  btnLogs && (btnLogs.onclick = async () => {
    try {
      const res = await api(`/api/agents/${agentId}/logs/realm?lines=200`);
      openModal('Realm 日志（最近 200 行）', `<pre class="logs">${escapeHtml((res.lines||[]).join('\n'))}</pre>`, `<button class="btn" id="mOk">关闭</button>`);
      $('#mOk').onclick = closeModal;
    } catch (e) {
      toast('获取日志失败：' + e.message, 'bad');
    }
  });

  refresh();
}

// Init
window.addEventListener('DOMContentLoaded', () => {
  initDashboard();
  initAgentDetail();
});
