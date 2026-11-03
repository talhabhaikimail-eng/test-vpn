'use strict';
// Onic control panel. No framework; all dynamic text goes through esc().
const $ = (s, el = document) => el.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const main = $('#main');
let tab = 'dash', timer = null, me = null;

async function api(method, path, body, isForm) {
  const opt = {method, headers: {'X-Onic': '1'}, credentials: 'same-origin'};
  if (body !== undefined) {
    if (isForm) opt.body = body;
    else { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  }
  const r = await fetch('/admin/api' + path, opt);
  if (r.status === 401 && path !== '/login') { showLogin(); throw new Error('login required'); }
  if (r.status === 204) return null;
  const t = await r.text();
  let j; try { j = JSON.parse(t); } catch { j = {error: t}; }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function toast(msg, bad) {
  const t = $('#toast'); t.textContent = msg; t.style.borderColor = bad ? 'var(--bad)' : 'var(--blue)';
  t.classList.remove('hidden'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add('hidden'), 3500);
}
const fail = e => toast(e.message || String(e), true);

const ago = ts => {
  if (!ts) return '—';
  const d = Math.floor(Date.now() / 1000) - ts;
  if (d < 60) return d + 's ago'; if (d < 3600) return Math.floor(d / 60) + 'm ago';
  if (d < 86400) return Math.floor(d / 3600) + 'h ago'; return Math.floor(d / 86400) + 'd ago';
};
const date = ts => ts ? new Date(ts * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
const bytes = n => { n = +n || 0; const u = ['B','KB','MB','GB','TB']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + ' ' + u[i]; };
const rate = bps => bytes(bps) + '/s';
const pct = (a, b) => b ? Math.round(a * 100 / b) : 0;
const barCls = p => p > 85 ? 'hot' : p > 65 ? 'warm' : '';
const dur = s => { s = +s || 0; const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600); return d ? d + 'd ' + h + 'h' : h + 'h ' + Math.floor(s % 3600 / 60) + 'm'; };

function modal(html, onReady) {
  $('#modalBody').innerHTML = html; $('#modal').classList.remove('hidden');
  if (onReady) onReady($('#modalBody'));
}
function closeModal() { $('#modal').classList.add('hidden'); $('#modalBody').innerHTML = ''; }
$('#modal').addEventListener('mousedown', e => { if (e.target.id === 'modal') closeModal(); });

// ---------- auth ----------
function showLogin() { $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); clearInterval(timer); }
$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api('POST', '/login', {username: f.get('username'), password: f.get('password'), totp: f.get('totp')});
    e.target.reset(); $('#loginErr').textContent = ''; boot();
  } catch (err) { $('#loginErr').textContent = err.message; }
});
$('#logout').addEventListener('click', async () => { await api('POST', '/logout').catch(() => {}); showLogin(); });

async function boot() {
  try { me = await api('GET', '/me'); } catch { return; }
  $('#who').textContent = me.user; $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  go(tab);
}
$('#tabs').addEventListener('click', e => { const t = e.target.dataset.tab; if (t) go(t); });
function go(t) {
  tab = t; clearInterval(timer);
  document.querySelectorAll('#tabs a').forEach(a => a.classList.toggle('active', a.dataset.tab === t));
  main.innerHTML = '<p class="muted">loading…</p>';
  ({dash, nodes, users, devices, ui: uiTab, releases, audit, settings})[t]().catch(fail);
}

// ---------- dashboard ----------
async function dash() {
  const render = async () => {
    const d = await api('GET', '/stats');
    const up = d.nodes.filter(n => n.state === 'up');
    const conns = up.reduce((a, n) => a + (n.last?.conns || 0), 0);
    let h = `<div class="kpis">
      <div class="kpi"><span>Nodes up</span><b>${up.length}/${d.nodes.filter(n => n.enabled).length}</b></div>
      <div class="kpi"><span>Active connections</span><b>${conns}</b></div>
      <div class="kpi"><span>Devices seen 24h</span><b>${d.devices_24h}</b></div>
      <div class="kpi"><span>Devices total</span><b>${d.devices_total}</b></div>
    </div><div class="grid">`;
    for (const n of d.nodes) {
      const s = n.last || {};
      const memP = pct(s.mem_used_mb, s.mem_total_mb), swP = pct(s.swap_used_mb, s.swap_total_mb), dkP = pct(s.disk_used_gb, s.disk_total_gb);
      const svc = Object.entries(s.services || {}).map(([k, v]) => `<span class="tag ${v === 'active' ? 'ok' : 'bad'}">${esc(k)}</span>`).join(' ');
      h += `<div class="card node">
        <h3><span class="dot ${esc(n.state)}"></span>${esc(n.name)}<small>${esc(n.location)} · ${esc(n.kind)}${n.enabled ? '' : ' · disabled'}</small></h3>
        ${n.state === 'no-agent' ? '<p class="muted">No stats agent installed.</p>' : `
        <div class="metrics">
          <div>CPU<b>${(s.cpu ?? 0).toFixed(0)}%</b><div class="bar"><i class="${barCls(s.cpu)}" style="width:${Math.min(100, s.cpu || 0)}%"></i></div></div>
          <div>RAM<b>${s.mem_used_mb ?? '?'} / ${s.mem_total_mb ?? '?'} MB</b><div class="bar"><i class="${barCls(memP)}" style="width:${memP}%"></i></div></div>
          <div>Swap<b>${s.swap_used_mb ?? 0} / ${s.swap_total_mb ?? 0} MB</b><div class="bar"><i class="${barCls(swP)}" style="width:${swP}%"></i></div></div>
          <div>Connections<b>${s.conns ?? 0}</b></div>
          <div>Net ↓/↑<b>${rate(s.rx_bps)} / ${rate(s.tx_bps)}</b></div>
          <div>Disk<b>${s.disk_used_gb ?? '?'} / ${s.disk_total_gb ?? '?'} GB</b><div class="bar"><i class="${barCls(dkP)}" style="width:${dkP}%"></i></div></div>
          <div>Load<b>${s.load1 ?? '?'}</b></div>
          <div>Uptime<b>${dur(s.uptime_s)}</b></div>
          <div>Seen<b>${ago(n.ts)}</b></div>
        </div>
        <div class="row">${svc}</div>
        <div class="row spread" style="margin-top:6px"><span class="legend"><i style="background:var(--blue)"></i>CPU<i style="background:var(--green)"></i>RAM<i style="background:var(--orange)"></i>conns</span><a data-chart="${esc(n.id)}">24h chart</a></div>
        <canvas class="hidden" id="c_${esc(n.id)}" width="600" height="140"></canvas>`}
      </div>`;
    }
    main.innerHTML = h + '</div>';
    main.querySelectorAll('[data-chart]').forEach(a => a.addEventListener('click', () => chart(a.dataset.chart)));
  };
  await render();
  timer = setInterval(() => render().catch(() => {}), 30000);
}

async function chart(id) {
  const c = document.getElementById('c_' + id); if (!c) return;
  c.classList.toggle('hidden'); if (c.classList.contains('hidden')) return;
  const pts = await api('GET', '/stats/' + encodeURIComponent(id) + '?hours=24');
  const g = c.getContext('2d'), W = c.width, H = c.height;
  g.clearRect(0, 0, W, H);
  if (pts.length < 2) { g.fillStyle = '#858585'; g.font = '20px monospace'; g.fillText('not enough data yet', 10, 40); return; }
  const maxC = Math.max(5, ...pts.map(p => p.conns || 0));
  const line = (f, color, max) => {
    g.strokeStyle = color; g.lineWidth = 2; g.beginPath();
    pts.forEach((p, i) => { const x = i * W / (pts.length - 1), y = H - 4 - (Math.min(max, f(p)) / max) * (H - 8); i ? g.lineTo(x, y) : g.moveTo(x, y); });
    g.stroke();
  };
  line(p => p.cpu || 0, '#569cd6', 100);
  line(p => pct(p.mem_used_mb, p.mem_total_mb), '#4ec9b0', 100);
  line(p => p.conns || 0, '#ce9178', maxC);
  g.fillStyle = '#858585'; g.font = '18px monospace'; g.fillText('max conns ' + maxC, 8, 20);
}

// ---------- nodes ----------
const KINDS = ['mux', 'vless-ws', 'xhttp', 'ssh', 'slowdns', 'infra']; // infra = monitored only, never sent to apps
async function nodes() {
  const list = await api('GET', '/nodes');
  let h = `<div class="row spread"><h2>Nodes (${list.length})</h2><button class="primary" id="addNode">+ Add node</button></div>
  <p class="muted">Enabled nodes are sent to the apps on their next config fetch, in this order.</p>
  <table><tr><th>#</th><th>ID</th><th>Name</th><th>Kind</th><th>Host</th><th>Bug host</th><th>Secret</th><th>Agent</th><th>Status</th><th></th></tr>`;
  for (const n of list) h += `<tr>
    <td>${n.sort}</td><td>${esc(n.id)}</td><td>${esc(n.name)} <span class="muted">${esc(n.location)}</span></td><td><span class="tag">${esc(n.kind)}</span></td>
    <td>${esc(n.host)}${n.path ? '<span class="muted">' + esc(n.path) + '</span>' : ''}</td><td>${esc(n.bug_host)}:${n.bug_port}${n.tls ? ' tls' : ''}</td>
    <td>${n.has_secret ? '<span class="tag ok">set</span>' : '<span class="tag">—</span>'}</td>
    <td>${n.has_agent ? '<span class="tag ok">key</span>' : '<span class="tag">—</span>'}</td>
    <td>${n.enabled ? '<span class="tag ok">enabled</span>' : '<span class="tag bad">disabled</span>'}</td>
    <td><button data-edit="${esc(n.id)}">Edit</button> <button data-probe="${esc(n.id)}">Probe</button> <button data-agent="${esc(n.id)}">Agent key</button></td></tr>`;
  main.innerHTML = h + '</table>';
  $('#addNode').onclick = () => nodeForm({kind: 'mux', bug_port: 443, tls: true, enabled: true, sort: 100, extra: '{}'});
  main.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => nodeForm(list.find(n => n.id === b.dataset.edit)));
  main.querySelectorAll('[data-probe]').forEach(b => b.onclick = async () => {
    b.disabled = true; b.textContent = '…';
    try { const r = await api('POST', `/nodes/${encodeURIComponent(b.dataset.probe)}/probe`); toast(r.ok ? `OK ${r.status} in ${r.ms} ms` : `FAIL ${r.status || ''} ${r.error || ''} (${r.ms} ms)`, !r.ok); }
    catch (e) { fail(e); } b.disabled = false; b.textContent = 'Probe';
  });
  main.querySelectorAll('[data-agent]').forEach(b => b.onclick = async () => {
    if (!confirm('Generate a new agent key for ' + b.dataset.agent + '? The old key stops working.')) return;
    const r = await api('POST', `/nodes/${encodeURIComponent(b.dataset.agent)}/agent-key`).catch(fail); if (!r) return;
    modal(`<h2>Agent key for ${esc(r.node)}</h2><p class="muted">Shown once. Put it in /etc/onic-agent.env on that VPS:</p>
      <div class="secret">ONIC_NODE=${esc(r.node)}\nONIC_KEY=${esc(r.agent_key)}\nONIC_URL=${esc(r.push_url)}</div>
      <div class="row" style="margin-top:10px"><button class="primary" id="mClose">Done</button></div>`, m => $('#mClose', m).onclick = () => { closeModal(); nodes(); });
  });
}

function nodeForm(n) {
  const isNew = !n.id;
  modal(`<h2>${isNew ? 'Add node' : 'Edit ' + esc(n.id)}</h2><form id="nf"><div class="form2">
    <label>ID (slug, fixed)<input name="id" value="${esc(n.id)}" ${isNew ? '' : 'readonly'} required placeholder="mux4"></label>
    <label>Name<input name="name" value="${esc(n.name)}" required placeholder="Onic Mux 4"></label>
    <label>Location<input name="location" value="${esc(n.location)}" placeholder="Riyadh"></label>
    <label>Kind<select name="kind">${KINDS.map(k => `<option ${k === n.kind ? 'selected' : ''}>${k}</option>`).join('')}</select></label>
    <label>Node host (SNI / Host)<input name="host" value="${esc(n.host)}"></label>
    <label>Path<input name="path" value="${esc(n.path)}" placeholder="/mux"></label>
    <label>Bug host / IP<input name="bug_host" value="${esc(n.bug_host)}"></label>
    <label>Bug port<input name="bug_port" type="number" value="${n.bug_port || 443}"></label>
    <label>Origin IP (direct mode / stats)<input name="origin_ip" value="${esc(n.origin_ip)}"></label>
    <label>Order<input name="sort" type="number" value="${n.sort ?? 100}"></label>
    <label>Secret (PSK / UUID) — leave blank to keep<input name="secret" type="password" autocomplete="off" placeholder="${n.has_secret ? '•••• set' : ''}"></label>
    <label>&nbsp;<span class="row"><label class="row"><input type="checkbox" name="tls" ${n.tls ? 'checked' : ''}> TLS</label>
      <label class="row"><input type="checkbox" name="enabled" ${n.enabled ? 'checked' : ''}> Enabled</label></span></label>
    </div>
    <label>Payload<input name="payload" value="${esc(n.payload)}"></label>
    <label>Extra JSON (passed to apps as-is)<textarea name="extra" style="min-height:90px">${esc(n.extra || '{}')}</textarea></label>
    <div class="row spread"><span>${isNew ? '' : '<button type="button" class="danger" id="nDel">Delete</button>'}</span>
      <span class="row"><button type="button" id="nCancel">Cancel</button><button class="primary">Save</button></span></div></form>`, m => {
    $('#nCancel', m).onclick = closeModal;
    if (!isNew) $('#nDel', m).onclick = async () => {
      if (!confirm('Delete node ' + n.id + ' and its stats?')) return;
      await api('DELETE', '/nodes/' + encodeURIComponent(n.id)).catch(fail); closeModal(); nodes();
    };
    $('#nf', m).onsubmit = async e => {
      e.preventDefault(); const f = new FormData(e.target);
      const body = Object.fromEntries(f); body.bug_port = +body.bug_port; body.sort = +body.sort; body.tls = f.has('tls'); body.enabled = f.has('enabled');
      try { await api('POST', '/nodes', body); closeModal(); toast('saved'); nodes(); } catch (err) { fail(err); }
    };
  });
}

// ---------- users ----------
async function users() {
  const [list, codes] = await Promise.all([api('GET', '/users'), api('GET', '/codes')]);
  const now = Date.now() / 1000;
  let h = `<div class="row spread"><h2>Users (${list.length})</h2><button class="primary" id="addUser">+ Add user</button></div>
  <table><tr><th>ID</th><th>Name</th><th>Group</th><th>Status</th><th>Expires</th><th>Devices</th><th>Last seen</th><th>Notes</th><th></th></tr>`;
  for (const u of list) {
    const expired = u.expires_at && u.expires_at < now;
    h += `<tr><td>${u.id}</td><td>${esc(u.name)}</td><td>${esc(u.group)}</td>
      <td>${u.status === 'active' && !expired ? '<span class="tag ok">active</span>' : `<span class="tag bad">${expired ? 'expired' : esc(u.status)}</span>`}</td>
      <td>${u.expires_at ? date(u.expires_at) : 'never'}</td><td>${u.devices}/${u.max_devices || '∞'}</td><td>${ago(u.last_seen)}</td><td class="wrap">${esc(u.notes)}</td>
      <td><button data-edit="${u.id}">Edit</button> <button data-code="${u.id}">+ Code</button></td></tr>`;
  }
  h += `</table><h2 style="margin-top:16px">Activation codes</h2><table><tr><th>Code</th><th>User</th><th>Uses left</th><th>Expires</th><th>Created</th><th></th></tr>`;
  for (const c of codes) h += `<tr><td class="mono">${esc(c.code)}</td><td>${esc(c.user)}</td><td>${c.uses_left < 0 ? '∞' : c.uses_left}</td><td>${c.expires_at ? date(c.expires_at) : 'never'}</td><td>${date(c.created_at)}</td><td><button class="danger" data-delcode="${esc(c.code)}">Delete</button></td></tr>`;
  main.innerHTML = h + '</table>';
  $('#addUser').onclick = () => userForm({status: 'active', max_devices: 3, group: 'default'});
  main.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => userForm(list.find(u => u.id == b.dataset.edit)));
  main.querySelectorAll('[data-delcode]').forEach(b => b.onclick = async () => { await api('DELETE', '/codes/' + encodeURIComponent(b.dataset.delcode)).catch(fail); users(); });
  main.querySelectorAll('[data-code]').forEach(b => b.onclick = () => modal(`<h2>New activation code</h2><form id="cf"><div class="form2">
      <label>Uses (-1 = unlimited)<input name="uses" type="number" value="1"></label><label>Valid for days (0 = forever)<input name="valid_days" type="number" value="7"></label></div>
      <div class="row"><button type="button" id="cCancel">Cancel</button><button class="primary">Create</button></div></form>`, m => {
    $('#cCancel', m).onclick = closeModal;
    $('#cf', m).onsubmit = async e => {
      e.preventDefault(); const f = new FormData(e.target);
      const r = await api('POST', `/users/${b.dataset.code}/codes`, {uses: +f.get('uses'), valid_days: +f.get('valid_days')}).catch(fail); if (!r) return;
      modal(`<h2>Activation code</h2><div class="secret" style="font-size:20px;text-align:center">${esc(r.code)}</div>
        <p class="muted">Give this to the user; they enter it once in the app.</p><button class="primary" id="mClose">Done</button>`, m2 => $('#mClose', m2).onclick = () => { closeModal(); users(); });
    };
  }));
}

function userForm(u) {
  const expDate = u.expires_at ? new Date(u.expires_at * 1000).toISOString().slice(0, 10) : '';
  modal(`<h2>${u.id ? 'Edit user #' + u.id : 'Add user'}</h2><form id="uf"><div class="form2">
    <label>Name<input name="name" value="${esc(u.name)}" required></label>
    <label>Group<input name="group" value="${esc(u.group)}"></label>
    <label>Status<select name="status"><option ${u.status === 'active' ? 'selected' : ''}>active</option><option ${u.status === 'disabled' ? 'selected' : ''}>disabled</option></select></label>
    <label>Expires (empty = never)<input name="expires" type="date" value="${expDate}"></label>
    <label>Max devices (0 = unlimited)<input name="max_devices" type="number" value="${u.max_devices ?? 3}"></label>
    <label>Quota MB (0 = unlimited)<input name="quota_mb" type="number" value="${u.quota_mb ?? 0}"></label></div>
    <label>Notes<input name="notes" value="${esc(u.notes)}"></label>
    <div class="row"><button type="button" id="uCancel">Cancel</button><button class="primary">Save</button></div></form>`, m => {
    $('#uCancel', m).onclick = closeModal;
    $('#uf', m).onsubmit = async e => {
      e.preventDefault(); const f = new FormData(e.target);
      const exp = f.get('expires') ? Math.floor(new Date(f.get('expires') + 'T23:59:59Z').getTime() / 1000) : 0;
      try {
        await api('POST', '/users', {id: u.id || 0, name: f.get('name'), group: f.get('group'), status: f.get('status'), expires_at: exp,
          max_devices: +f.get('max_devices'), quota_mb: +f.get('quota_mb'), notes: f.get('notes')});
        closeModal(); toast('saved'); users();
      } catch (err) { fail(err); }
    };
  });
}

// ---------- devices ----------
async function devices() {
  const list = await api('GET', '/devices');
  let h = `<h2>Devices (${list.length})</h2><table><tr><th>Device</th><th>User</th><th>Platform</th><th>App</th><th>Label</th><th>Activated</th><th>Last seen</th><th>IP</th><th></th></tr>`;
  for (const d of list) h += `<tr><td class="mono">${esc(d.id)}</td><td>${esc(d.user)}</td><td>${esc(d.platform)}</td><td>${esc(d.app_version)}</td><td>${esc(d.label)}</td>
    <td>${date(d.created_at)}</td><td>${ago(d.last_seen)}</td><td>${esc(d.last_ip)}</td>
    <td>${d.revoked ? '<span class="tag bad">revoked</span>' : `<button class="danger" data-revoke="${esc(d.id)}">Revoke</button>`}</td></tr>`;
  main.innerHTML = h + '</table>';
  main.querySelectorAll('[data-revoke]').forEach(b => b.onclick = async () => {
    if (!confirm('Revoke ' + b.dataset.revoke + '? The app loses access on its next fetch.')) return;
    await api('POST', `/devices/${encodeURIComponent(b.dataset.revoke)}/revoke`).catch(fail); devices();
  });
}

// ---------- remote UI ----------
const UI_TEMPLATE = JSON.stringify({
  theme: {bg: '#1e1e1e', panel: '#252526', accent: '#0e639c', text: '#d4d4d4', ok: '#89d185', bad: '#f14c4c'},
  strings: {connect: 'CONNECT', disconnect: 'DISCONNECT'},
  banner: {show: false, text: '', level: 'info', url: ''},
  flags: {show_speedtest: true, show_logs: true, allow_custom_profiles: true},
  server_order: [], hidden_nodes: []
}, null, 2);
async function uiTab() {
  const list = await api('GET', '/ui');
  const active = list.find(v => v.active);
  let h = `<div class="row spread"><h2>Remote UI config</h2><span class="muted">Apps apply the active version on their next config fetch.</span></div>
  <div class="card"><form id="uif"><label>JSON<textarea name="body" spellcheck="false">${esc(active ? JSON.stringify(JSON.parse(active.body), null, 2) : UI_TEMPLATE)}</textarea></label>
  <label>Change note<input name="note" placeholder="what changed"></label>
  <div class="row"><label class="row"><input type="checkbox" name="activate" checked> Activate now</label><button class="primary">Save new version</button></div></form></div>
  <h2 style="margin-top:14px">History</h2><table><tr><th>Version</th><th>Note</th><th>Created</th><th></th></tr>`;
  for (const v of list) h += `<tr><td>v${v.version}</td><td>${esc(v.note)}</td><td>${date(v.created_at)}</td><td>${v.active ? '<span class="tag ok">active</span>' : `<button data-act="${v.version}">Roll back to this</button>`}</td></tr>`;
  main.innerHTML = h + '</table>';
  $('#uif').onsubmit = async e => {
    e.preventDefault(); const f = new FormData(e.target);
    try { JSON.parse(f.get('body')); } catch (err) { return fail(new Error('Invalid JSON: ' + err.message)); }
    try { const r = await api('POST', '/ui', {body: f.get('body'), note: f.get('note'), activate: f.has('activate')}); toast('saved v' + r.version); uiTab(); } catch (err) { fail(err); }
  };
  main.querySelectorAll('[data-act]').forEach(b => b.onclick = async () => { await api('POST', `/ui/${b.dataset.act}/activate`).catch(fail); uiTab(); });
}

// ---------- releases ----------
async function releases() {
  const list = await api('GET', '/releases');
  let h = `<h2>OTA releases</h2><div class="card"><form id="rf"><div class="form2">
    <label>Platform<select name="platform"><option>android</option><option>windows</option></select></label>
    <label>File (.apk / .exe)<input name="file" type="file" accept=".apk,.exe" required></label>
    <label>Version code (integer, must increase)<input name="version_code" type="number" required></label>
    <label>Version name<input name="version_name" required placeholder="1.4.0"></label>
    <label>Rollout %<input name="rollout" type="number" value="100" min="1" max="100"></label>
    <label>&nbsp;<label class="row"><input type="checkbox" name="mandatory" value="1"> Mandatory (app blocks until updated)</label></label></div>
    <label>Release notes<input name="notes"></label><button class="primary">Upload & sign</button> <span id="rp" class="muted"></span></form></div>
  <table style="margin-top:10px"><tr><th>Platform</th><th>Version</th><th>Size</th><th>SHA-256</th><th>Rollout</th><th>Mandatory</th><th>Active</th><th>Uploaded</th><th></th></tr>`;
  for (const r of list) h += `<tr><td>${esc(r.platform)}</td><td>${esc(r.version_name)} (${r.version_code})</td><td>${bytes(r.size)}</td><td class="mono" title="${esc(r.sha256)}">${esc(r.sha256.slice(0, 12))}…</td>
    <td><input type="number" min="0" max="100" value="${r.rollout}" data-roll="${r.id}" style="width:70px"></td>
    <td><input type="checkbox" data-mand="${r.id}" ${r.mandatory ? 'checked' : ''}></td><td><input type="checkbox" data-actv="${r.id}" ${r.active ? 'checked' : ''}></td>
    <td>${date(r.created_at)}</td><td><button data-save="${r.id}">Save</button> <a href="${esc(r.url)}">download</a></td></tr>`;
  main.innerHTML = h + '</table>';
  $('#rf').onsubmit = async e => {
    e.preventDefault(); $('#rp').textContent = 'uploading…';
    try { const r = await api('POST', '/releases', new FormData(e.target), true); toast('uploaded, sha256 ' + r.sha256.slice(0, 12)); releases(); }
    catch (err) { $('#rp').textContent = ''; fail(err); }
  };
  main.querySelectorAll('[data-save]').forEach(b => b.onclick = async () => {
    const id = b.dataset.save;
    await api('POST', '/releases/' + id, {rollout: +$(`[data-roll="${id}"]`).value, mandatory: $(`[data-mand="${id}"]`).checked, active: $(`[data-actv="${id}"]`).checked}).catch(fail);
    toast('saved');
  });
}

// ---------- audit / settings ----------
async function audit() {
  const list = await api('GET', '/audit');
  let h = `<h2>Audit log</h2><table><tr><th>When</th><th>Actor</th><th>Action</th><th>Detail</th><th>IP</th></tr>`;
  for (const a of list) h += `<tr><td>${date(a.ts)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td class="wrap">${esc(a.detail)}</td><td>${esc(a.ip)}</td></tr>`;
  main.innerHTML = h + '</table>';
}

async function settings() {
  main.innerHTML = `<h2>Settings</h2><div class="card">
    <p>API host: <b>${esc(me.api_host)}</b></p>
    <p>Signing key id: <b>${esc(me.kid)}</b></p>
    <p>Ed25519 public key (embed in the apps; safe to publish):</p><div class="secret">${esc(me.pubkey)}</div>
    <p style="margin-top:14px">CI token (GitHub Actions uses it to report a new tunnel hostname to <code>/v1/ci/domain</code>):</p>
    <button id="rot">Generate new CI token</button></div>`;
  $('#rot').onclick = async () => {
    if (!confirm('Rotate the CI token? The old one stops working immediately.')) return;
    const r = await api('POST', '/settings/ci-token').catch(fail); if (!r) return;
    modal(`<h2>CI token</h2><p class="muted">Shown once. Save it as the GitHub secret ONIC_CI_TOKEN.</p><div class="secret">${esc(r.ci_token)}</div><button class="primary" id="mClose">Done</button>`, m => $('#mClose', m).onclick = closeModal);
  };
}

boot().catch(() => showLogin());
