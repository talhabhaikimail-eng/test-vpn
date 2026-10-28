/* ProxyScope Live — browser side.
 * One SSE stream (/api/events) carries every event for this tab; live sessions,
 * cold probes and speed tests are started with small POSTs. */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CLIENT = Math.random().toString(36).slice(2) + Date.now().toString(36);
  const STAB_WINDOW = 20;
  const MAX_PACKETS = 20000;
  const MAX_LOG = 6000;
  const MAX_DOM_LINES = 900;

  const store = {
    get(k, d) { try { const v = localStorage.getItem('ps.' + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem('ps.' + k, JSON.stringify(v)); } catch { /* private mode */ } },
  };

  const S = {
    nodes: [],
    ns: {},              // node id -> runtime state
    selected: store.get('selected', null),
    win: store.get('win', 300),
    logFilter: 'all',
    logAll: [],
    creds: {},
    hover: null,
    hoverAll: null,
    mode: store.get('mode', 'one'),
    hiddenSeries: new Set(store.get('hiddenSeries', [])),
    focus: null,
    dirty: true,
  };

  const opts = () => ({
    interval: +$('opt-interval').value,
    timeout: +$('opt-timeout').value,
    size: +$('opt-size').value,
  });

  // ── helpers ──────────────────────────────────────────────────────────────
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const fmtMs = (v, d = 0) => (v == null || !isFinite(v) ? '–' : v >= 1000 && d === 0 ? (v / 1000).toFixed(2) + 's' : v.toFixed(d));
  const fmtNum = (v, d = 1) => (v == null || !isFinite(v) ? '–' : v.toFixed(d));
  const fmtBytes = (b) => (b >= 1048576 ? (b / 1048576).toFixed(1) + ' MB' : b >= 1024 ? (b / 1024).toFixed(0) + ' KB' : b + ' B');
  const clock = (ts) => {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
  };
  const dur = (ms) => {
    const s = Math.floor(ms / 1000);
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + String(s % 60).padStart(2, '0') + 's';
    return Math.floor(m / 60) + 'h ' + String(m % 60).padStart(2, '0') + 'm';
  };
  const quantile = (sorted, q) => {
    if (!sorted.length) return null;
    const i = (sorted.length - 1) * q, lo = Math.floor(i), hi = Math.ceil(i);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
  };
  const api = (path, body) => fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client: CLIENT, ...body }),
  }).then((r) => r.json()).catch((e) => ({ error: e.message }));

  function newState(node) {
    return {
      node, live: false, state: 'idle', packets: [], bySeq: new Map(),
      sent: 0, recv: 0, lost: 0, reconnects: 0, outages: [],
      connectedAt: null, lastConnect: null, lastError: null,
      probes: [], probing: false,
      speed: { running: false, down: null, up: null, prog: {} },
    };
  }

  // ── stability model ─────────────────────────────────────────────────────
  // delivered share of the last N finished packets, reduced by relative jitter
  function windowStats(pk, end, n = STAB_WINDOW) {
    const from = Math.max(0, end - n + 1);
    let ok = 0, tot = 0, prev = null, jsum = 0, jn = 0, rsum = 0;
    for (let i = from; i <= end; i++) {
      const p = pk[i];
      if (p.rtt === undefined) continue;   // still in flight
      tot++;
      if (p.rtt === null) { prev = null; continue; }
      ok++; rsum += p.rtt;
      if (prev !== null) { jsum += Math.abs(p.rtt - prev); jn++; }
      prev = p.rtt;
    }
    if (!tot) return null;
    const jitter = jn ? jsum / jn : 0;
    const avg = ok ? rsum / ok : 0;
    const penalty = avg ? Math.min(0.25, (0.5 * jitter) / avg) : 0;
    return { stab: (ok / tot) * (1 - penalty) * 100, jitter, loss: (1 - ok / tot) * 100 };
  }

  function nodeStats(ns) {
    const rtts = [];
    let prev = null, jsum = 0, jn = 0;
    for (const p of ns.packets) {
      if (typeof p.rtt === 'number') {
        rtts.push(p.rtt);
        if (prev !== null) { jsum += Math.abs(p.rtt - prev); jn++; }
        prev = p.rtt;
      } else if (p.rtt === null) prev = null;
    }
    const sorted = rtts.slice().sort((a, b) => a - b);
    const done = ns.recv + ns.lost;
    const last = ns.packets.length ? ns.packets[ns.packets.length - 1] : null;
    let stab = null;
    for (let i = ns.packets.length - 1; i >= 0; i--) {
      if (ns.packets[i].stab != null) { stab = ns.packets[i].stab; break; }
    }
    const recent = rtts.slice(-10).sort((a, b) => a - b);
    return {
      sent: ns.sent, recv: ns.recv, lost: ns.lost,
      loss: done ? (ns.lost / done) * 100 : null,
      last: last && typeof last.rtt === 'number' ? last.rtt : (rtts.length ? rtts[rtts.length - 1] : null),
      min: sorted[0] ?? null, max: sorted[sorted.length - 1] ?? null,
      avg: rtts.length ? rtts.reduce((a, b) => a + b, 0) / rtts.length : null,
      p95: quantile(sorted, 0.95), jitter: jn ? jsum / jn : null,
      median10: quantile(recent, 0.5), stab,
    };
  }

  function derivedState(ns) {
    if (!ns.live) return ns.packets.length ? { k: 'idle', t: 'Stopped' } : { k: 'idle', t: 'Idle' };
    if (ns.state === 'connecting') return { k: 'connecting', t: ns.recv ? 'Reconnecting' : 'Connecting' };
    if (ns.state === 'reconnecting') return { k: 'reconnecting', t: 'Reconnecting' };
    if (ns.state === 'failed') return { k: 'down', t: 'Unreachable' };
    if (ns.state === 'connected') {
      const ws = ns.packets.length ? windowStats(ns.packets, ns.packets.length - 1) : null;
      if (ws && (ws.loss > 10 || ws.stab < 80)) return { k: 'degraded', t: 'Unstable' };
      return { k: 'up', t: 'Online' };
    }
    return { k: 'idle', t: 'Idle' };
  }

  // ── events ──────────────────────────────────────────────────────────────
  function log(nid, kind, msg, ts) {
    const e = { node: nid, kind, msg, ts: ts || Date.now() };
    S.logAll.push(e);
    if (S.logAll.length > MAX_LOG) S.logAll.splice(0, S.logAll.length - MAX_LOG);
    appendLogLine(e);
  }

  function handle(e) {
    if (e.type.startsWith('matrix')) return handleMatrix(e);
    const ns = S.ns[e.node];
    if (!ns) return;
    const nid = e.node;
    switch (e.type) {
      case 'session': {
        ns.state = e.state;
        if (e.state === 'connected') {
          ns.lastConnect = { phases: e.phases, info: e.info, total: e.total, ts: e.ts };
          ns.lastError = null;
          ns.connectedAt = e.ts;
          const open = ns.outages[ns.outages.length - 1];
          if (open && open.end == null) open.end = e.ts;
          log(nid, 'ok', `Tunnel up in ${fmtMs(e.total)} ms`, e.ts);
        } else if (e.state === 'failed') {
          ns.lastError = { error: e.error, stage: e.stage, total: e.total };
          ns.connectedAt = null;
          const open = ns.outages[ns.outages.length - 1];
          if (!open || open.end != null) ns.outages.push({ start: e.ts, end: null });
        } else if (e.state === 'reconnecting') {
          ns.reconnects++;
          ns.connectedAt = null;
          ns.outages.push({ start: e.ts, end: null });
        } else if (e.state === 'stopped') {
          ns.connectedAt = null;
          const open = ns.outages[ns.outages.length - 1];
          if (open && open.end == null) open.end = e.ts;
          if (!ns.live) ns.state = 'idle';
        }
        break;
      }
      case 'tx': {
        const p = { seq: e.seq, t: e.ts, rtt: undefined, size: e.size };
        ns.packets.push(p);
        ns.bySeq.set(e.seq, p);
        ns.sent++;
        if (ns.packets.length > MAX_PACKETS) {
          const cut = ns.packets.splice(0, ns.packets.length - MAX_PACKETS);
          cut.forEach((c) => ns.bySeq.delete(c.seq));
        }
        log(nid, 'tx', `TX #${e.seq}  ${e.size} B`, e.ts);
        break;
      }
      case 'rx': case 'lost': {
        const p = ns.bySeq.get(e.seq);
        if (!p) break;
        if (e.type === 'rx') {
          p.rtt = e.rtt; p.tx = e.tx; p.rx = e.rx; ns.recv++;
          log(nid, 'rx', `RX #${e.seq}  ${e.rx} B  <b>${e.rtt.toFixed(1)} ms</b>`, e.ts);
        } else {
          p.rtt = null; p.reason = e.reason; ns.lost++;
          log(nid, 'lost', `LOST #${e.seq}  ${esc(e.reason)}`, e.ts);
        }
        const ws = windowStats(ns.packets, ns.packets.indexOf(p));
        if (ws) { p.stab = ws.stab; p.jitter = ws.jitter; }
        ns.bySeq.delete(e.seq);
        break;
      }
      case 'log':
        log(nid, e.level === 'error' ? 'error' : e.level === 'warn' ? 'warn' : 'info', esc(e.msg), e.ts);
        break;
      case 'probe_start':
        ns.probes = []; ns.probing = true;
        log(nid, 'info', `Cold handshake series: ${e.count} fresh connections`, e.ts);
        break;
      case 'probe':
        ns.probes.push(e);
        log(nid, e.ok ? 'ok' : 'error', e.ok
          ? `Cold probe ${e.index + 1}: ${fmtMs(e.total)} ms total (upgrade ${fmtMs(e.phases.upgrade ?? e.phases.first_req)} ms)`
          : `Cold probe ${e.index + 1} failed — ${esc(e.error)}`, e.ts);
        break;
      case 'probe_done':
        ns.probing = false;
        break;
      case 'speed_start':
        ns.speed = { running: true, down: null, up: null, prog: {}, bytes: e.bytes };
        break;
      case 'speed_progress':
        ns.speed.prog[e.dir] = e;
        break;
      case 'speed_done':
        ns.speed.running = false;
        ns.speed.down = e.results?.down || null;
        ns.speed.up = e.results?.up || null;
        ns.speed.error = e.ok ? null : e.error;
        if (e.ok) log(nid, 'ok', `Speed: ↓ ${fmtNum(ns.speed.down?.mbps, 2)} Mbps  ↑ ${fmtNum(ns.speed.up?.mbps, 2)} Mbps`, e.ts);
        break;
    }
    S.dirty = true;
  }

  function connectEvents() {
    const link = $('link-state');
    const es = new EventSource(`/api/events?client=${CLIENT}`);
    es.onopen = () => { link.className = 'link-state ok'; link.querySelector('.txt').textContent = 'Server connected'; };
    es.onerror = () => { link.className = 'link-state bad'; link.querySelector('.txt').textContent = 'Server unreachable — retrying'; };
    es.onmessage = (m) => {
      let batch;
      try { batch = JSON.parse(m.data); } catch { return; }
      batch.forEach(handle);
    };
  }

  // ── actions ─────────────────────────────────────────────────────────────
  async function startNode(id) {
    const ns = S.ns[id];
    ns.live = true; ns.state = 'connecting';
    S.dirty = true;
    const r = await api('/api/live', { id, action: 'start', ...opts() });
    if (r.error) { ns.live = false; log(id, 'error', `Could not start: ${esc(r.error)}`); }
  }
  async function stopNode(id) {
    const ns = S.ns[id];
    ns.live = false; ns.state = 'idle';
    S.dirty = true;
    await api('/api/live', { id, action: 'stop' });
  }
  const toggleNode = (id) => (S.ns[id].live ? stopNode(id) : startNode(id));

  function restartLive() {
    Object.values(S.ns).filter((n) => n.live).forEach((n) => {
      log(n.node.id, 'info', `Settings changed — restarting session (${opts().interval} ms / ${opts().timeout} ms / ${opts().size} B)`);
      startNode(n.node.id);
    });
  }

  function exportCsv() {
    const ns = S.ns[S.selected];
    if (!ns) return;
    const rows = [['seq', 'time', 'rtt_ms', 'status', 'stability_pct', 'reason']];
    ns.packets.forEach((p) => rows.push([
      p.seq, new Date(p.t).toISOString(), typeof p.rtt === 'number' ? p.rtt.toFixed(2) : '',
      p.rtt === null ? 'lost' : p.rtt === undefined ? 'pending' : 'ok',
      p.stab != null ? p.stab.toFixed(1) : '', (p.reason || '').replace(/"/g, "'"),
    ]));
    const csv = rows.map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `proxyscope-${ns.node.id}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // ── node list ───────────────────────────────────────────────────────────
  function buildNodeList() {
    const list = $('node-list');
    list.innerHTML = '';
    S.nodes.forEach((n) => {
      const card = document.createElement('div');
      card.className = 'ncard';
      card.id = 'nc-' + n.id;
      card.tabIndex = 0;
      card.setAttribute('role', 'button');
      card.setAttribute('aria-label', `Show ${n.name}`);
      card.innerHTML = `
        <div class="nc-top">
          <div style="min-width:0">
            <div class="nc-name">${esc(n.name)}</div>
            <div class="nc-proto">${esc(n.protocol)}</div>
            <div class="nc-host" title="${esc(n.host)}${n.front ? ' via ' + esc(n.front) : ''}">${esc(n.host)}</div>
          </div>
          <span class="state-chip" data-state="idle"><span class="dot"></span><span class="txt">Idle</span></span>
        </div>
        <div class="nc-mid">
          <div class="nc-rtt"><span class="v">–</span><small> ms</small></div>
          <div class="nc-kv"><span><b>loss</b><span class="loss">–</span></span><span><b>stab</b><span class="stab">–</span></span></div>
          <button class="nc-btn" type="button">Start</button>
        </div>
        <canvas class="nc-spark" aria-hidden="true"></canvas>`;
      card.addEventListener('click', (ev) => {
        if (ev.target.closest('.nc-btn')) return;
        select(n.id);
      });
      card.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); select(n.id); } });
      card.querySelector('.nc-btn').addEventListener('click', () => toggleNode(n.id));
      list.appendChild(card);
    });
  }

  function renderNodeCards() {
    S.nodes.forEach((n) => {
      const ns = S.ns[n.id], card = $('nc-' + n.id);
      if (!card) return;
      const st = nodeStats(ns), ds = derivedState(ns);
      card.classList.toggle('sel', n.id === S.selected);
      const chip = card.querySelector('.state-chip');
      chip.dataset.state = ds.k;
      chip.querySelector('.txt').textContent = ds.t;
      card.querySelector('.nc-rtt .v').textContent = st.last != null ? st.last.toFixed(0) : '–';
      card.querySelector('.loss').textContent = st.loss != null ? st.loss.toFixed(1) + '%' : '–';
      card.querySelector('.stab').textContent = st.stab != null ? st.stab.toFixed(0) + '%' : '–';
      const b = card.querySelector('.nc-btn');
      b.textContent = ns.live ? 'Stop' : 'Start';
      b.classList.toggle('on', ns.live);
      drawSpark(card.querySelector('.nc-spark'), ns);
    });
  }

  // ── colours from CSS tokens ─────────────────────────────────────────────
  let C = {};
  function readColors() {
    const cs = getComputedStyle(document.documentElement);
    const g = (v) => cs.getPropertyValue(v).trim();
    C = {
      lat: g('--lat'), latSoft: g('--lat-soft'), stab: g('--stab'), stabSoft: g('--stab-soft'),
      goodText: g('--good-text'), crit: g('--crit'), critSoft: g('--crit-soft'), grid: g('--grid'), axis: g('--axis'),
      text2: g('--text-2'), muted: g('--muted'), surface: g('--surface'), border: g('--border-strong'),
      mono: '11px ' + g('--mono'), sans: '500 11px ' + g('--sans'),
      series: [1, 2, 3, 4, 5, 6, 7, 8].map((i) => g('--s' + i)),
    };
  }

  function fitCanvas(cv) {
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth, h = cv.clientHeight;
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    const ctx = cv.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h };
  }

  function drawSpark(cv, ns) {
    const { ctx, w, h } = fitCanvas(cv);
    const pts = ns.packets.filter((p) => p.rtt !== undefined).slice(-60);
    if (pts.length < 2) {
      ctx.strokeStyle = C.grid; ctx.setLineDash([3, 4]); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke(); ctx.setLineDash([]);
      return;
    }
    const vals = pts.filter((p) => p.rtt !== null).map((p) => p.rtt);
    let lo = Math.min(...vals), hi = Math.max(...vals);
    if (hi - lo < 20) { const m = (hi + lo) / 2; lo = m - 10; hi = m + 10; }
    const x = (i) => (i / 59) * (w - 4) + 2 + (60 - pts.length) * ((w - 4) / 59);
    const y = (v) => h - 4 - ((v - lo) / (hi - lo)) * (h - 8);
    ctx.lineWidth = 1.5; ctx.strokeStyle = C.lat; ctx.lineJoin = 'round';
    ctx.beginPath();
    let pen = false;
    pts.forEach((p, i) => {
      if (p.rtt === null) { pen = false; return; }
      if (!pen) { ctx.moveTo(x(i), y(p.rtt)); pen = true; } else ctx.lineTo(x(i), y(p.rtt));
    });
    ctx.stroke();
    ctx.fillStyle = C.crit;
    pts.forEach((p, i) => { if (p.rtt === null) ctx.fillRect(x(i) - 1, h - 8, 2, 8); });
  }

  // ── main chart: latency band over stability band, shared time axis ──────
  const CH = { padL: 52, padR: 14, padT: 14, gap: 26, axisH: 22, stabH: 84 };
  let chartGeo = null;

  function niceTicks(lo, hi, count) {
    const span = hi - lo || 1;
    const step0 = span / count;
    const mag = Math.pow(10, Math.floor(Math.log10(step0)));
    const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => span / s <= count) || 10 * mag;
    const out = [];
    for (let v = Math.ceil(lo / step) * step; v <= hi + 1e-9; v += step) out.push(+v.toFixed(6));
    return out;
  }

  // bands geometry shared by single-node and compare views
  function bands(h) {
    const latTop = CH.padT, latBot = h - CH.axisH - CH.stabH - CH.gap;
    return { latTop, latBot, stabTop: latBot + CH.gap, stabBot: h - CH.axisH };
  }

  // grid, y labels for both bands and the time axis; returns the y scales
  function drawFrame(ctx, w, h, t0, t1, X, vals) {
    const { latTop, latBot, stabTop, stabBot } = bands(h);
    let lo, hi;
    if (vals.length) {
      lo = Infinity; hi = -Infinity;
      vals.forEach((v) => { if (v < lo) lo = v; if (v > hi) hi = v; });
      const pad = Math.max((hi - lo) * 0.15, 8);
      lo = Math.max(0, lo - pad); hi += pad;
    } else { lo = 0; hi = 1000; }
    const ticks = niceTicks(lo, hi, 4);
    lo = Math.min(lo, ticks[0]); hi = Math.max(hi, ticks[ticks.length - 1]);
    const Y = (v) => latBot - ((v - lo) / (hi - lo)) * (latBot - latTop);
    const SY = (v) => stabBot - (v / 100) * (stabBot - stabTop);

    ctx.font = C.mono; ctx.textBaseline = 'middle'; ctx.textAlign = 'right';
    ctx.lineWidth = 1;
    ticks.forEach((v) => {
      const y = Math.round(Y(v)) + 0.5;
      if (y < latTop - 1 || y > latBot + 1) return;
      ctx.strokeStyle = C.grid; ctx.beginPath(); ctx.moveTo(CH.padL, y); ctx.lineTo(w - CH.padR, y); ctx.stroke();
      ctx.fillStyle = C.muted; ctx.fillText(v >= 1000 ? (v / 1000).toFixed(1) + 's' : String(Math.round(v)), CH.padL - 8, y);
    });
    ctx.save(); ctx.textAlign = 'left'; ctx.font = C.sans; ctx.fillStyle = C.text2;
    ctx.fillText('Round trip · ms', CH.padL + 6, latTop + 6); ctx.restore();

    [0, 50, 100].forEach((v) => {
      const y = Math.round(SY(v)) + 0.5;
      ctx.strokeStyle = C.grid; ctx.beginPath(); ctx.moveTo(CH.padL, y); ctx.lineTo(w - CH.padR, y); ctx.stroke();
      ctx.fillStyle = C.muted; ctx.fillText(v + '%', CH.padL - 8, y);
    });
    ctx.save(); ctx.textAlign = 'left'; ctx.font = C.sans; ctx.fillStyle = C.text2;
    ctx.fillText('Stability · %', CH.padL + 6, stabTop - 10); ctx.restore();

    const span = (t1 - t0) / 1000;
    const stepS = [5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600].find((s) => span / s <= 7) || 7200;
    ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.fillStyle = C.muted;
    for (let t = Math.ceil(t0 / (stepS * 1000)) * stepS * 1000; t <= t1; t += stepS * 1000) {
      const x = Math.round(X(t)) + 0.5;
      ctx.strokeStyle = C.grid; ctx.beginPath(); ctx.moveTo(x, latTop); ctx.lineTo(x, stabBot); ctx.stroke();
      const d = new Date(t);
      const lbl = stepS >= 60 ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
        : d.toLocaleTimeString([], { hour12: false });
      ctx.fillText(lbl, x, stabBot + 6);
    }
    return { Y, SY };
  }

  // ── compare view: every node on one chart ───────────────────────────────
  const MAX_SERIES = 8;   // categorical palette size; colour follows the node, never its rank
  const seriesColor = (id) => C.series[S.nodes.findIndex((n) => n.id === id)] || null;
  const compareSeries = () => S.nodes.slice(0, MAX_SERIES)
    .map((n) => S.ns[n.id])
    .filter((ns) => ns && ns.packets.length && !S.hiddenSeries.has(ns.node.id));

  function visiblePackets(pk, t0) {
    const out = [];
    for (let i = pk.length - 1; i >= 0; i--) {
      if (pk[i].t < t0 - 2000) break;
      out.push(pk[i]);
    }
    return out.reverse();
  }

  function drawCompare() {
    const cv = $('chart');
    const { ctx, w, h } = fitCanvas(cv);
    const series = compareSeries();
    $('chart-empty').hidden = series.length > 0;
    if (!series.length) { chartGeo = null; return; }

    const now = Date.now();
    const anyLive = series.some((s) => s.live);
    const t1 = anyLive ? now : Math.max(...series.map((s) => s.packets[s.packets.length - 1].t)) + 1000;
    const first = Math.min(...series.map((s) => s.packets[0].t)) - 1000;
    let t0 = S.win ? Math.max(t1 - S.win * 1000, first) : first;
    t0 = Math.min(t0, t1 - 30000);
    const plotW = w - CH.padL - CH.padR;
    const X = (t) => CH.padL + ((t - t0) / (t1 - t0)) * plotW;
    const { latTop, latBot, stabTop, stabBot } = bands(h);

    const vis = series.map((s) => ({ ns: s, color: seriesColor(s.node.id), pts: visiblePackets(s.packets, t0) }));
    const vals = [];
    vis.forEach((v) => v.pts.forEach((p) => { if (typeof p.rtt === 'number') vals.push(p.rtt); }));
    const { Y, SY } = drawFrame(ctx, w, h, t0, t1, X, vals);
    chartGeo = { compare: true, X, Y, SY, t0, t1, vis, latTop, latBot, stabTop, stabBot, w, h };

    ctx.save();
    ctx.beginPath(); ctx.rect(CH.padL, 0, plotW, h); ctx.clip();

    // focused series (legend hover) is drawn last and the rest recede
    const order = vis.slice().sort((a, b) => (a.ns.node.id === S.focus) - (b.ns.node.id === S.focus));
    const alphaFor = (v) => (S.focus && v.ns.node.id !== S.focus ? 0.18 : 1);

    order.forEach((v) => {
      ctx.globalAlpha = alphaFor(v);
      ctx.strokeStyle = v.color; ctx.lineWidth = 2; ctx.lineJoin = 'round';
      // latency, broken at losses
      ctx.beginPath();
      let pen = false;
      v.pts.forEach((p) => {
        if (typeof p.rtt !== 'number') { if (p.rtt === null) pen = false; return; }
        if (!pen) { ctx.moveTo(X(p.t), Y(p.rtt)); pen = true; } else ctx.lineTo(X(p.t), Y(p.rtt));
      });
      ctx.stroke();
      // stability
      ctx.beginPath();
      let first = true;
      v.pts.forEach((p) => {
        if (p.stab == null) return;
        if (first) { ctx.moveTo(X(p.t), SY(p.stab)); first = false; } else ctx.lineTo(X(p.t), SY(p.stab));
      });
      ctx.stroke();
      // losses: red × with a tick in the node's colour under it
      v.pts.forEach((p) => {
        if (p.rtt !== null) return;
        const x = X(p.t);
        ctx.strokeStyle = C.crit; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(x - 4, latTop + 4); ctx.lineTo(x + 4, latTop + 12);
        ctx.moveTo(x + 4, latTop + 4); ctx.lineTo(x - 4, latTop + 12); ctx.stroke();
        ctx.fillStyle = v.color; ctx.fillRect(x - 4, latTop + 15, 8, 2);
      });
    });
    ctx.globalAlpha = 1;

    // hover: one crosshair, a ring on every series at that moment
    if (S.hoverAll) {
      const x = X(S.hoverAll.t);
      ctx.strokeStyle = C.axis; ctx.lineWidth = 1; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(x, latTop); ctx.lineTo(x, stabBot); ctx.stroke(); ctx.setLineDash([]);
      S.hoverAll.rows.forEach((r) => {
        const px = X(r.p.t);
        const mark = (y) => {
          ctx.beginPath(); ctx.arc(px, y, 4.5, 0, Math.PI * 2);
          ctx.fillStyle = r.color; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = C.surface; ctx.stroke();
        };
        if (typeof r.p.rtt === 'number') mark(Y(r.p.rtt));
        if (r.p.stab != null) mark(SY(r.p.stab));
      });
    }
    ctx.restore();
  }

  function onCompareMove(mx, my, r) {
    const { X, vis, t0, t1 } = chartGeo;
    const t = t0 + ((mx - CH.padL) / (r.width - CH.padL - CH.padR)) * (t1 - t0);
    const rows = [];
    vis.forEach((v) => {
      let best = null, bd = Infinity;
      for (const p of v.pts) {
        if (p.rtt === undefined) continue;
        const d = Math.abs(p.t - t);
        if (d < bd) { bd = d; best = p; }
      }
      // only report a node if it actually had a packet near this moment
      if (best && bd <= Math.max(2500, 1.5 * +$('opt-interval').value)) rows.push({ ns: v.ns, color: v.color, p: best });
    });
    if (!rows.length || mx < CH.padL) return hideTip();
    rows.sort((a, b) => (a.p.rtt ?? Infinity) - (b.p.rtt ?? Infinity));
    S.hoverAll = { t, rows };
    const tip = $('tooltip');
    tip.innerHTML = `<div class="tt-time">${clock(t)}</div>` + rows.map((rw) => `
      <div class="tt-row${rw.ns.node.id === S.selected ? ' sel' : ''}">
        <span><i class="sw" style="background:${rw.color}"></i>${esc(rw.ns.node.name)}</span>
        <b>${rw.p.rtt === null ? '<span style="color:var(--crit-text)">lost</span>' : rw.p.rtt.toFixed(0) + ' ms'}
          <span style="color:var(--muted);font-weight:500"> · ${rw.p.stab != null ? rw.p.stab.toFixed(0) + '%' : '–'}</span></b>
      </div>`).join('') +
      '<div class="tt-row" style="margin-top:4px"><span style="color:var(--muted)">round trip · stability · fastest first</span></div>';
    tip.hidden = false;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let left = X(t) + 14;
    if (left + tw > r.width - 4) left = X(t) - tw - 14;
    tip.style.left = Math.max(4, left) + 'px';
    tip.style.top = Math.min(Math.max(4, my - th / 2), r.height - th - 4) + 'px';
    drawCompare();
  }

  // legend chips double as the series toggle (click) and focus (hover)
  function buildSeriesLegend() {
    const box = $('legend-all');
    box.innerHTML = '';
    S.nodes.forEach((n, i) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'sl';
      b.dataset.id = n.id;
      if (i >= MAX_SERIES) {
        b.disabled = true;
        b.title = `Only the first ${MAX_SERIES} nodes fit the colour palette`;
      }
      b.innerHTML = `<i></i><span class="sl-n">${esc(n.name)}</span><span class="sl-v"></span>`;
      b.addEventListener('click', () => {
        if (S.hiddenSeries.has(n.id)) S.hiddenSeries.delete(n.id); else S.hiddenSeries.add(n.id);
        store.set('hiddenSeries', [...S.hiddenSeries]);
        S.dirty = true;
      });
      b.addEventListener('mouseenter', () => { S.focus = n.id; S.dirty = true; });
      b.addEventListener('mouseleave', () => { S.focus = null; S.dirty = true; });
      b.addEventListener('dblclick', () => { select(n.id); });
      box.appendChild(b);
    });
  }

  function renderSeriesLegend() {
    document.querySelectorAll('#legend-all .sl').forEach((b) => {
      const id = b.dataset.id, ns = S.ns[id];
      const off = S.hiddenSeries.has(id) || b.disabled;
      b.classList.toggle('off', off);
      b.querySelector('i').style.background = seriesColor(id) || C.muted;
      const st = ns ? nodeStats(ns) : null;
      const v = b.querySelector('.sl-v');
      const idle = !ns || !ns.packets.length;
      b.classList.toggle('idle', idle);
      v.textContent = idle ? 'no data' : st.last != null ? st.last.toFixed(0) + ' ms' : '–';
      b.setAttribute('aria-pressed', String(!off));
      b.title = b.disabled ? b.title : `${off ? 'Show' : 'Hide'} ${ns.node.name} · double-click to open`;
    });
  }

  function applyChartMode() {
    const all = S.mode === 'all';
    document.querySelectorAll('#mode-seg button').forEach((b) => b.classList.toggle('on', b.dataset.mode === S.mode));
    $('legend-one').hidden = all;
    $('legend-all').hidden = !all;
    $('chart-title').textContent = all ? 'All nodes · latency & stability' : 'Latency & stability';
    $('chart-sub').textContent = all
      ? 'One line per node, same scales · hover for every node at that moment · click a name to hide it, double-click to open it'
      : "Every dot is one packet's round trip · stability = delivered % over the last 20 packets, reduced by jitter";
    $('chart-empty').innerHTML = all
      ? 'Start monitoring a few nodes to compare them here.'
      : 'Press <b>Start monitor</b> to send packets through this tunnel.';
    hideTip();
    S.dirty = true;
  }

  function drawChart() {
    if (S.mode === 'all') return drawCompare();
    const cv = $('chart'), ns = S.ns[S.selected];
    const { ctx, w, h } = fitCanvas(cv);
    $('chart-empty').hidden = !!(ns && ns.packets.length);
    if (!ns || !ns.packets.length) { chartGeo = null; return; }

    const now = Date.now();
    const pk = ns.packets;
    const t1 = ns.live ? now : pk[pk.length - 1].t + 1000;
    // grow from the first packet until the chosen window is full (min 30 s span)
    const first = Math.min(pk[0].t, ns.outages.length ? ns.outages[0].start : Infinity) - 1000;
    let t0 = S.win ? Math.max(t1 - S.win * 1000, first) : first;
    t0 = Math.min(t0, t1 - 30000);
    const plotW = w - CH.padL - CH.padR;
    const latTop = CH.padT, latBot = h - CH.axisH - CH.stabH - CH.gap;
    const stabTop = latBot + CH.gap, stabBot = h - CH.axisH;
    const X = (t) => CH.padL + ((t - t0) / (t1 - t0)) * plotW;

    const vis = [];
    for (let i = pk.length - 1; i >= 0; i--) {
      if (pk[i].t < t0 - 2000) break;
      vis.push(pk[i]);
    }
    vis.reverse();
    const { Y, SY } = drawFrame(ctx, w, h, t0, t1, X, vis.filter((p) => typeof p.rtt === 'number').map((p) => p.rtt));
    chartGeo = { X, Y, SY, t0, t1, vis, latTop, latBot, stabTop, stabBot, w, h };

    ctx.save();
    ctx.beginPath(); ctx.rect(CH.padL, 0, plotW, h); ctx.clip();

    // outages (reconnects) hatched across both bands
    ns.outages.forEach((o) => {
      const a = X(o.start), b = X(o.end ?? (ns.live ? now : o.start + 1000));
      if (b < CH.padL || a > w - CH.padR) return;
      ctx.fillStyle = C.critSoft;
      ctx.fillRect(a, latTop, Math.max(b - a, 2), stabBot - latTop);
    });

    // stability area
    const sp = vis.filter((p) => p.stab != null);
    if (sp.length) {
      ctx.beginPath();
      ctx.moveTo(X(sp[0].t), SY(0));
      sp.forEach((p) => ctx.lineTo(X(p.t), SY(p.stab)));
      ctx.lineTo(X(sp[sp.length - 1].t), SY(0));
      ctx.closePath(); ctx.fillStyle = C.stabSoft; ctx.fill();
      ctx.beginPath();
      sp.forEach((p, i) => (i ? ctx.lineTo(X(p.t), SY(p.stab)) : ctx.moveTo(X(p.t), SY(p.stab))));
      ctx.strokeStyle = C.stab; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.stroke();
    }

    // latency line (broken at losses)
    ctx.beginPath();
    let pen = false;
    vis.forEach((p) => {
      if (typeof p.rtt !== 'number') { if (p.rtt === null) pen = false; return; }
      const x = X(p.t), y = Y(p.rtt);
      if (!pen) { ctx.moveTo(x, y); pen = true; } else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = C.lat; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.stroke();

    // dots, only when sparse enough to read
    const dense = vis.length > plotW / 5;
    if (!dense) {
      vis.forEach((p) => {
        if (typeof p.rtt !== 'number') return;
        ctx.beginPath(); ctx.arc(X(p.t), Y(p.rtt), 3, 0, Math.PI * 2);
        ctx.fillStyle = C.lat; ctx.fill();
        ctx.lineWidth = 1.5; ctx.strokeStyle = C.surface; ctx.stroke();
      });
    }

    // lost packets: red guide + ×
    vis.forEach((p) => {
      if (p.rtt !== null) return;
      const x = X(p.t);
      ctx.strokeStyle = C.critSoft; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(x, latTop + 14); ctx.lineTo(x, latBot); ctx.stroke();
      ctx.strokeStyle = C.crit; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(x - 4, latTop + 4); ctx.lineTo(x + 4, latTop + 12);
      ctx.moveTo(x + 4, latTop + 4); ctx.lineTo(x - 4, latTop + 12); ctx.stroke();
    });

    // in-flight packet: hollow marker at the last measured level
    const lastRtt = [...vis].reverse().find((p) => typeof p.rtt === 'number');
    vis.filter((p) => p.rtt === undefined).forEach((p) => {
      ctx.beginPath(); ctx.arc(X(p.t), lastRtt ? Y(lastRtt.rtt) : (latTop + latBot) / 2, 3.5, 0, Math.PI * 2);
      ctx.strokeStyle = C.lat; ctx.lineWidth = 1.5; ctx.setLineDash([2, 2]); ctx.stroke(); ctx.setLineDash([]);
    });

    // hover crosshair
    if (S.hover) {
      const p = S.hover;
      const x = X(p.t);
      ctx.strokeStyle = C.axis; ctx.lineWidth = 1; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(x, latTop); ctx.lineTo(x, stabBot); ctx.stroke(); ctx.setLineDash([]);
      if (typeof p.rtt === 'number') {
        ctx.beginPath(); ctx.arc(x, Y(p.rtt), 5, 0, Math.PI * 2);
        ctx.fillStyle = C.lat; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = C.surface; ctx.stroke();
      }
      if (p.stab != null) {
        ctx.beginPath(); ctx.arc(x, SY(p.stab), 4.5, 0, Math.PI * 2);
        ctx.fillStyle = C.stab; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = C.surface; ctx.stroke();
      }
    }
    ctx.restore();

    // direct label for the latest value
    const lastOk = [...vis].reverse().find((p) => typeof p.rtt === 'number');
    if (lastOk && !S.hover) {
      const x = Math.min(X(lastOk.t), w - CH.padR), y = Y(lastOk.rtt);
      const label = lastOk.rtt.toFixed(0) + ' ms';
      ctx.font = '600 ' + C.mono; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      const tw = ctx.measureText(label).width;
      const ly = Math.max(latTop + 10, y - 16);
      ctx.fillStyle = C.surface; ctx.strokeStyle = C.border; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.roundRect(x - tw - 18, ly - 9, tw + 12, 18, 5); ctx.fill(); ctx.stroke();
      ctx.fillStyle = C.text2;
      ctx.fillText(label, x - 12, ly + 0.5);
    }
  }

  function onChartMove(ev) {
    if (!chartGeo) return;
    const r = $('chart').getBoundingClientRect();
    const mx = ev.clientX - r.left, my = ev.clientY - r.top;
    if (chartGeo.compare) return onCompareMove(mx, my, r);
    const { X, vis } = chartGeo;
    let best = null, bd = Infinity;
    vis.forEach((p) => {
      if (p.rtt === undefined) return;
      const d = Math.abs(X(p.t) - mx);
      if (d < bd) { bd = d; best = p; }
    });
    if (!best || bd > 40) return hideTip();
    S.hover = best;
    const tip = $('tooltip');
    const st = best.rtt === null
      ? `<div class="tt-row"><span><i class="sw" style="background:var(--crit)"></i>Lost</span><b>#${best.seq}</b></div>
         <div class="tt-row" style="margin-top:3px"><span style="color:var(--muted)">${esc(best.reason || '')}</span></div>`
      : `<div class="tt-row"><span><i class="sw" style="background:var(--lat)"></i>Round trip</span><b>${best.rtt.toFixed(1)} ms</b></div>`;
    tip.innerHTML = `<div class="tt-time">${clock(best.t)} · packet #${best.seq}</div>${st}
      <div class="tt-row"><span><i class="sw" style="background:var(--stab)"></i>Stability</span><b>${best.stab != null ? best.stab.toFixed(1) + '%' : '–'}</b></div>
      <div class="tt-row"><span><i class="sw" style="background:transparent"></i>Jitter (20 pkt)</span><b>${best.jitter != null ? best.jitter.toFixed(1) + ' ms' : '–'}</b></div>`;
    tip.hidden = false;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let left = X(best.t) + 14;
    if (left + tw > r.width - 4) left = X(best.t) - tw - 14;
    tip.style.left = Math.max(4, left) + 'px';
    tip.style.top = Math.min(Math.max(4, my - th / 2), r.height - th - 4) + 'px';
    drawChart();
  }
  function hideTip() {
    $('tooltip').hidden = true;
    if (S.hover || S.hoverAll) { S.hover = null; S.hoverAll = null; drawChart(); }
  }

  // ── detail panels ───────────────────────────────────────────────────────
  const PHASES = [
    ['dns', 'DNS lookup'], ['tcp', 'TCP connect'], ['tls', 'TLS handshake'], ['upgrade', 'WS upgrade (101)'],
    ['ssh', 'SSH kex + auth'], ['channel', 'Echo channel'], ['first_req', 'First request'],
  ];

  function renderDetail() {
    const ns = S.ns[S.selected];
    if (!ns) return;
    const n = ns.node, st = nodeStats(ns), ds = derivedState(ns);
    $('d-name').textContent = n.name;
    const chip = $('d-state');
    chip.dataset.state = ds.k;
    chip.querySelector('.txt').textContent = ds.t;
    $('d-meta').textContent = `${n.protocol} · ${n.tls ? 'https' : 'http'}://${n.host}:${n.port}${n.path}` +
      (n.front ? `  via ${n.front}` : '');
    $('d-method').textContent = 'Packet test: ' + n.method_label;
    const tg = $('d-toggle');
    tg.textContent = ns.live ? 'Stop monitor' : 'Start monitor';
    tg.className = ns.live ? 'btn btn-danger' : 'btn btn-primary';
    $('d-probe').disabled = ns.probing;
    $('d-probe').textContent = ns.probing ? `Probing ${ns.probes.length + 1}/5…` : 'Cold handshake ×5';

    const set = (id, v, cls) => { const el = $(id); el.textContent = v; if (cls !== undefined) el.parentElement.classList.toggle('bad', cls); };
    $('s-sent').textContent = st.sent;
    $('s-recv').textContent = st.recv;
    $('s-lost').textContent = st.lost;
    $('s-lost').classList.toggle('bad', st.lost > 0);
    set('s-loss', st.loss != null ? st.loss.toFixed(st.loss && st.loss < 1 ? 2 : 1) : '–', st.loss > 1);
    set('s-last', fmtNum(st.last, 0));
    set('s-min', fmtNum(st.min, 0));
    set('s-avg', fmtNum(st.avg, 0));
    set('s-p95', fmtNum(st.p95, 0));
    set('s-max', fmtNum(st.max, 0));
    set('s-jit', fmtNum(st.jitter, 1));
    set('s-stab', st.stab != null ? st.stab.toFixed(1) : '–', st.stab != null && st.stab < 80);
    $('s-up').textContent = ns.connectedAt ? dur(Date.now() - ns.connectedAt) : (ns.live ? '…' : '–');

    renderWaterfall(ns);
    renderSpeed(ns);
    renderProbes(ns);
  }

  function renderWaterfall(ns) {
    const wf = $('waterfall'), info = $('conn-info');
    const lc = ns.lastConnect;
    if (ns.lastError && (!lc || ns.state === 'failed')) {
      wf.innerHTML = `<div class="wf-row"><span class="wf-k res-bad">Failed at ${esc(ns.lastError.stage)}</span>
        <span class="res-bad" style="grid-column: span 2">${esc(ns.lastError.error)}</span></div>`;
      $('d-conn-total').textContent = `after ${fmtMs(ns.lastError.total)} ms`;
      if (!lc) { info.innerHTML = ''; return; }
    }
    if (!lc) {
      wf.innerHTML = '<div class="muted small">No connection yet.</div>';
      info.innerHTML = ''; $('d-conn-total').textContent = ' ';
      return;
    }
    const ph = PHASES.filter(([k]) => lc.phases[k] != null);
    const total = ph.reduce((a, [k]) => a + lc.phases[k], 0) || 1;
    let off = 0;
    const rows = ph.map(([k, label]) => {
      const v = lc.phases[k];
      const row = `<div class="wf-row"><span class="wf-k">${label}</span>
        <span class="wf-track"><i class="${v > 1500 ? 'slow' : ''}" style="left:${(off / total) * 100}%;width:${(v / total) * 100}%"></i></span>
        <span class="wf-v">${fmtMs(v, 0)} ms</span></div>`;
      off += v;
      return row;
    }).join('');
    if (ns.state !== 'failed' || !ns.lastError) {
      wf.innerHTML = rows + `<div class="wf-row total"><span class="wf-k">Tunnel ready</span><span></span><span class="wf-v">${fmtMs(lc.total, 0)} ms</span></div>`;
      $('d-conn-total').textContent = 'last connect ' + new Date(lc.ts).toLocaleTimeString([], { hour12: false });
    }
    const i = lc.info || {};
    info.innerHTML = [
      ['Edge IP', i.ip], ['TLS', i.tls], ['CF-Ray', i.cf_ray], ['Server', i.server],
    ].filter(([, v]) => v).map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('');
  }

  function renderSpeed(ns) {
    const btn = $('d-speed');
    const sp = ns.speed;
    btn.disabled = !ns.node.speed || sp.running;
    btn.textContent = sp.running ? 'Running…' : 'Run';
    document.querySelectorAll('.gauge').forEach((g) => {
      const dir = g.dataset.dir;
      const res = sp[dir], prog = sp.prog[dir];
      const running = sp.running && prog && !res;
      g.classList.toggle('running', !!running);
      const num = g.querySelector('.g-num'), bar = g.querySelector('.g-bar i'), sub = g.querySelector('.g-sub');
      if (res) {
        num.textContent = res.mbps.toFixed(2);
        bar.style.width = '100%';
        sub.textContent = `${fmtBytes(res.bytes)} in ${(res.ms / 1000).toFixed(1)} s` + (dir === 'down' && res.ttfb ? ` · TTFB ${res.ttfb.toFixed(0)} ms` : '');
      } else if (running) {
        num.textContent = prog.mbps.toFixed(2);
        bar.style.width = Math.min(100, (prog.bytes / prog.total) * 100) + '%';
        sub.textContent = `${fmtBytes(prog.bytes)} / ${fmtBytes(prog.total)} · ${(prog.elapsed / 1000).toFixed(1)} s`;
      } else {
        num.textContent = '–';
        bar.style.width = '0';
        sub.textContent = sp.running ? 'waiting…' : ' ';
      }
    });
    const n = ns.node;
    $('speed-note').textContent = !n.speed
      ? 'Not available for this node — this route has no data path to measure from here.'
      : sp.error ? 'Failed: ' + sp.error
        : n.method === 'vless' || n.method === 'vmess'
          ? `Real ${n.method.toUpperCase()} traffic through Xray to ${'speed.cloudflare.com'}.`
          : 'Random bytes streamed through an SSH channel on the runner (incompressible).';
  }

  function renderProbes(ns) {
    const tb = $('probe-rows');
    if (!ns.probes.length) {
      tb.innerHTML = `<tr><td colspan="8" class="muted">${ns.probing ? 'Opening first connection…' : 'Run “Cold handshake ×5” to measure.'}</td></tr>`;
      return;
    }
    const c = (v, slow) => (v == null ? '<td class="muted">–</td>' : `<td class="${v > slow ? 'slow' : ''}">${fmtMs(v, 0)}</td>`);
    let html = ns.probes.map((p) => `<tr>
      <td>${p.index + 1}</td>${c(p.phases.dns, 200)}${c(p.phases.tcp, 300)}${c(p.phases.tls, 500)}${c(p.phases.upgrade, 1500)}
      ${c(p.phases.origin ?? p.phases.first_req, 1500)}${c(p.total, 3000)}
      <td class="${p.ok ? 'res-ok' : 'res-bad'}">${p.ok ? '✓ ok' + (p.info?.banner ? ' · ' + esc(p.info.banner.replace('SSH-2.0-', '')) : '') : '✕ ' + esc(p.error)}</td></tr>`).join('');
    const ok = ns.probes.filter((p) => p.ok);
    if (ok.length > 1) {
      const tots = ok.map((p) => p.total).sort((a, b) => a - b);
      html += `<tr><td class="muted">median</td><td colspan="5"></td><td>${fmtMs(quantile(tots, 0.5), 0)}</td>
        <td class="muted">${ok.length}/${ns.probes.length} succeeded</td></tr>`;
    }
    tb.innerHTML = html;
  }

  function renderSummary() {
    const all = Object.values(S.ns);
    const live = all.filter((n) => n.live);
    const up = live.filter((n) => ['up', 'degraded'].includes(derivedState(n).k));
    $('sum-up').textContent = live.length ? `${up.length}/${live.length}` : '–';
    $('sum-up-sub').textContent = live.length ? `${live.length} monitored · ${all.length} known` : `${all.length} nodes · not monitoring`;
    let best = null;
    let sent = 0, lost = 0, done = 0, rc = 0;
    all.forEach((n) => {
      const st = nodeStats(n);
      if (n.live && n.state === 'connected' && st.median10 != null && (!best || st.median10 < best.v)) best = { v: st.median10, name: n.node.name };
      sent += n.sent; lost += n.lost; done += n.recv + n.lost; rc += n.reconnects;
    });
    $('sum-best').textContent = best ? best.v.toFixed(0) : '–';
    $('sum-best-sub').textContent = best ? best.name + ' (median of last 10)' : ' ';
    $('sum-pkts').textContent = sent.toLocaleString();
    $('sum-loss').textContent = done ? ((lost / done) * 100).toFixed(2) : '–';
    $('sum-loss-sub').textContent = done ? `${lost} lost of ${done.toLocaleString()} answered` : ' ';
    $('sum-rc').textContent = rc;
    const sel = S.ns[S.selected];
    document.title = sel && sel.live && nodeStats(sel).last != null
      ? `${nodeStats(sel).last.toFixed(0)} ms · ${sel.node.name} — ProxyScope` : 'ProxyScope Live';
  }

  // ── console ─────────────────────────────────────────────────────────────
  const ICON = { tx: '→', rx: '←', lost: '✕', info: '·', warn: '!', error: '✕', ok: '✓' };
  const isPkt = (k) => k === 'tx' || k === 'rx' || k === 'lost';
  const logVisible = (e) => (($('log-allnodes').checked || e.node === S.selected) &&
    (S.logFilter === 'all' || (S.logFilter === 'pkt' ? isPkt(e.kind) : !isPkt(e.kind) || e.kind === 'lost')));

  function lineEl(e) {
    const d = document.createElement('div');
    d.className = 'ln ' + e.kind;
    const nd = $('log-allnodes').checked ? `<span class="nd">[${esc(S.ns[e.node]?.node.name || e.node)}]</span> ` : '';
    d.innerHTML = `<span class="t">${clock(e.ts)}</span><span class="i">${ICON[e.kind] || '·'}</span><span class="m">${nd}${e.msg}</span>`;
    return d;
  }
  function appendLogLine(e) {
    if (!logVisible(e)) return;
    const con = $('console');
    const follow = $('log-follow').checked;
    con.appendChild(lineEl(e));
    while (con.childElementCount > MAX_DOM_LINES) con.firstChild.remove();
    if (follow) con.scrollTop = con.scrollHeight;
  }
  function rebuildConsole() {
    const con = $('console');
    con.innerHTML = '';
    const frag = document.createDocumentFragment();
    S.logAll.filter(logVisible).slice(-MAX_DOM_LINES).forEach((e) => frag.appendChild(lineEl(e)));
    con.appendChild(frag);
    con.scrollTop = con.scrollHeight;
  }

  // ── bug IP matrix: every node through every front IP, one chart ─────────
  const DEFAULT_IPS = '104.26.13.160\n141.193.213.11\n104.19.251.92\n104.16.15.14\n104.16.14.14\n104.19.252.92';
  const MX = {
    run: null, running: false, ips: [], nodes: [], cells: new Map(), pings: 10,
    metric: store.get('mxMetric', 'rtt'), sort: store.get('mxSort', 'input'),
    pick: new Set(store.get('mxNodes', [])), hover: null, geo: null, dirty: true,
  };
  const mxKey = (ip, id) => ip + '|' + id;
  const colo = (ray) => (ray && ray.includes('-') ? ray.split('-').pop() : null);
  const parseIps = (txt) => [...new Set(txt.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean))];

  function cellStats(c) {
    if (!c || c.state !== 'done') return null;
    const ok = (c.rtts || []).filter((v) => v != null).sort((a, b) => a - b);
    return {
      ok: c.ok, n: c.rtts?.length || 0, got: ok.length,
      min: ok[0] ?? null, max: ok[ok.length - 1] ?? null, med: quantile(ok, 0.5), p90: quantile(ok, 0.9),
      loss: c.rtts?.length ? (c.lost / c.rtts.length) * 100 : null,
      connect: c.connect ?? null, colo: colo(c.info?.cf_ray), error: c.error, stage: c.stage,
    };
  }
  const metricOf = (st) => (!st || !st.ok ? null : MX.metric === 'rtt' ? st.med : st.connect);

  // per-IP score: nodes that work first, then the median of their metric
  function ipScore(ip) {
    const vals = [];
    let ok = 0;
    MX.nodes.forEach((id) => {
      const st = cellStats(MX.cells.get(mxKey(ip, id)));
      if (st && st.ok) { ok++; vals.push(metricOf(st)); }
    });
    vals.sort((a, b) => a - b);
    return { ok, med: quantile(vals, 0.5) };
  }
  const byScore = (a, b) => {
    const sa = ipScore(a), sb = ipScore(b);
    return sb.ok - sa.ok || (sa.med ?? Infinity) - (sb.med ?? Infinity);
  };
  const mxRows = () => (MX.sort === 'best' ? MX.ips.slice().sort(byScore) : MX.ips.slice());
  // winner is only declared once the run is finished
  const bestIp = () => (MX.running || !MX.ips.length ? null : MX.ips.slice().sort(byScore)[0]);

  function handleMatrix(e) {
    if (e.type === 'matrix_start') {
      MX.run = e.run; MX.running = true; MX.ips = e.ips; MX.nodes = e.nodes; MX.pings = e.pings;
      MX.cells = new Map();
      log(S.selected, 'info', `Bug IP matrix: ${e.ips.length} IPs × ${e.nodes.length} nodes, ${e.pings} packets each`, e.ts);
    } else if (e.run !== MX.run) {
      return;
    } else if (e.type === 'matrix_cell') {
      MX.cells.set(mxKey(e.ip, e.node), e);
      if (e.state === 'done') {
        const st = cellStats(e);
        log(e.node, st.ok ? 'ok' : 'error', st.ok
          ? `Via ${esc(e.ip)}${st.colo ? ' (' + st.colo + ')' : ''}: median ${fmtMs(st.med)} ms, loss ${st.loss.toFixed(0)}%, connect ${fmtMs(st.connect)} ms`
          : `Via ${esc(e.ip)} failed — ${esc(e.error)}`, e.ts);
      }
    } else if (e.type === 'matrix_done') {
      MX.running = false;
      log(S.selected, 'info', `Bug IP matrix ${e.stopped ? 'stopped' : 'finished'}`, e.ts);
    }
    MX.dirty = true;
  }

  function buildMatrixNodes() {
    const box = $('mx-nodes');
    box.innerHTML = '';
    S.nodes.forEach((n) => {
      const l = document.createElement('label');
      l.className = 'check';
      const on = !MX.pick.size || MX.pick.has(n.id);
      l.innerHTML = `<input type="checkbox" value="${esc(n.id)}"${on ? ' checked' : ''}> ${esc(n.name)}`;
      l.querySelector('input').addEventListener('change', () => {
        MX.pick = new Set([...box.querySelectorAll('input:checked')].map((i) => i.value));
        store.set('mxNodes', [...MX.pick]);
      });
      box.appendChild(l);
    });
  }

  function renderMatrixLegend() {
    $('mx-legend').innerHTML = MX.nodes.map((id) => {
      const n = S.ns[id]?.node;
      return `<span class="sl" style="cursor:default"><i style="background:${seriesColor(id) || C.muted}"></i><span class="sl-n">${esc(n ? n.name : id)}</span></span>`;
    }).join('');
  }

  const MXG = { padL: 128, padR: 92, padT: 10, axisH: 24, lane: 9, rowPad: 10 };

  function drawMatrix() {
    const cv = $('mx-chart');
    const rows = mxRows();
    $('mx-empty').hidden = rows.length > 0;
    const laneN = Math.max(1, MX.nodes.length);
    const rowH = laneN * MXG.lane + MXG.rowPad * 2;
    cv.style.height = rows.length ? (MXG.padT + rows.length * rowH + MXG.axisH) + 'px' : '120px';
    const { ctx, w, h } = fitCanvas(cv);
    if (!rows.length) { MX.geo = null; return; }

    const vals = [];
    rows.forEach((ip) => MX.nodes.forEach((id) => {
      const st = cellStats(MX.cells.get(mxKey(ip, id)));
      if (st && st.ok) vals.push(MX.metric === 'rtt' ? st.max : st.connect);
    }));
    let hi = vals.length ? Math.max(...vals) * 1.08 : 500;
    const ticks = niceTicks(0, hi, 6);
    hi = Math.max(hi, ticks[ticks.length - 1]);
    const plotR = w - MXG.padR;
    const X = (v) => MXG.padL + (v / hi) * (plotR - MXG.padL);
    const bot = MXG.padT + rows.length * rowH;

    // grid + x axis
    ctx.font = C.mono; ctx.lineWidth = 1; ctx.textAlign = 'center'; ctx.textBaseline = 'top';
    ticks.forEach((v) => {
      const x = Math.round(X(v)) + 0.5;
      ctx.strokeStyle = C.grid; ctx.beginPath(); ctx.moveTo(x, MXG.padT); ctx.lineTo(x, bot); ctx.stroke();
      ctx.fillStyle = C.muted; ctx.fillText(v >= 1000 ? (v / 1000).toFixed(1) + 's' : String(Math.round(v)), x, bot + 6);
    });
    ctx.textAlign = 'right'; ctx.fillStyle = C.text2; ctx.font = C.sans;
    ctx.fillText(MX.metric === 'rtt' ? 'live RTT · ms' : 'connect · ms', plotR, bot + 6);
    // failure gutter
    ctx.textAlign = 'center'; ctx.fillStyle = C.muted;
    ctx.fillText('failed', plotR + MXG.padR / 2, bot + 6);
    ctx.strokeStyle = C.border; ctx.setLineDash([2, 3]);
    ctx.beginPath(); ctx.moveTo(plotR + 10.5, MXG.padT); ctx.lineTo(plotR + 10.5, bot); ctx.stroke(); ctx.setLineDash([]);

    const best = bestIp();
    const lanes = [];
    rows.forEach((ip, r) => {
      const top = MXG.padT + r * rowH;
      if (r) { ctx.strokeStyle = C.grid; ctx.beginPath(); ctx.moveTo(8, top + 0.5); ctx.lineTo(w - 8, top + 0.5); ctx.stroke(); }
      if (MX.hover && MX.hover.ip === ip) { ctx.fillStyle = C.grid; ctx.fillRect(0, top, w, rowH); }
      // row label: IP, then edge colos seen through it
      const sc = ipScore(ip);
      const colos = [...new Set(MX.nodes.map((id) => cellStats(MX.cells.get(mxKey(ip, id)))?.colo).filter(Boolean))];
      ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
      ctx.font = '600 ' + C.mono; ctx.fillStyle = ip === best && sc.ok ? C.goodText : C.text2;
      ctx.fillText(ip, 10, top + rowH / 2 - 7, MXG.padL - 16);
      ctx.font = C.mono; ctx.fillStyle = C.muted;
      ctx.fillText(`${sc.ok}/${MX.nodes.length} ok${colos.length ? ' · ' + colos.join(',') : ''}`, 10, top + rowH / 2 + 7, MXG.padL - 16);

      MX.nodes.forEach((id, li) => {
        const y = top + MXG.rowPad + li * MXG.lane + MXG.lane / 2;
        const color = seriesColor(id) || C.muted;
        const c = MX.cells.get(mxKey(ip, id));
        const st = cellStats(c);
        const dim = MX.hover && !(MX.hover.ip === ip && MX.hover.id === id) ? 0.35 : 1;
        ctx.globalAlpha = dim;
        lanes.push({ ip, id, y, top, rowH });
        if (!c) { // queued
          ctx.fillStyle = C.grid; ctx.fillRect(MXG.padL, y - 0.5, plotR - MXG.padL, 1);
        } else if (c.state === 'running') {
          ctx.strokeStyle = color; ctx.setLineDash([2, 4]); ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.moveTo(MXG.padL, y); ctx.lineTo(MXG.padL + 60, y); ctx.stroke(); ctx.setLineDash([]);
        } else if (!st.ok) {
          const x = plotR + MXG.padR / 2;
          ctx.strokeStyle = C.crit; ctx.lineWidth = 2;
          ctx.beginPath(); ctx.moveTo(x - 3.5, y - 3.5); ctx.lineTo(x + 3.5, y + 3.5); ctx.moveTo(x + 3.5, y - 3.5); ctx.lineTo(x - 3.5, y + 3.5); ctx.stroke();
          ctx.fillStyle = color; ctx.fillRect(x - 22, y - 1.5, 10, 3);
        } else {
          if (MX.metric === 'rtt' && st.max > st.min) {
            ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineCap = 'round';
            ctx.beginPath(); ctx.moveTo(X(st.min), y); ctx.lineTo(X(st.max), y); ctx.stroke(); ctx.lineCap = 'butt';
          }
          const v = metricOf(st);
          ctx.beginPath(); ctx.arc(X(v), y, 4, 0, Math.PI * 2);
          ctx.fillStyle = color; ctx.fill(); ctx.lineWidth = 1.5; ctx.strokeStyle = C.surface; ctx.stroke();
          if (st.loss > 0 && MX.metric === 'rtt') { // partial loss: small red tick right of the whisker
            ctx.fillStyle = C.crit; ctx.fillRect(X(st.max) + 5, y - 3, 2, 6);
          }
        }
        ctx.globalAlpha = 1;
      });
    });
    MX.geo = { lanes, X, rowH };
  }

  function onMatrixMove(ev) {
    if (!MX.geo) return;
    const r = $('mx-chart').getBoundingClientRect();
    const mx = ev.clientX - r.left, my = ev.clientY - r.top;
    let lane = null, bd = Infinity;
    MX.geo.lanes.forEach((l) => {
      if (my < l.top || my > l.top + l.rowH) return;
      const d = Math.abs(l.y - my);
      if (d < bd) { bd = d; lane = l; }
    });
    if (!lane) return hideMatrixTip();
    MX.hover = { ip: lane.ip, id: lane.id };
    const tip = $('mx-tip');
    const rowsHtml = MX.nodes.map((id) => {
      const st = cellStats(MX.cells.get(mxKey(lane.ip, id)));
      const c = MX.cells.get(mxKey(lane.ip, id));
      const v = !c ? '<span style="color:var(--muted)">queued</span>'
        : c.state === 'running' ? '<span style="color:var(--muted)">testing…</span>'
          : !st.ok ? '<span style="color:var(--crit-text)">failed</span>'
            : `${fmtMs(st.med)} ms <span style="color:var(--muted);font-weight:500">· ${st.loss.toFixed(0)}% loss · conn ${fmtMs(st.connect)}${st.colo ? ' · ' + st.colo : ''}</span>`;
      return `<div class="tt-row${id === lane.id ? ' sel' : ''}"><span><i class="sw" style="background:${seriesColor(id) || C.muted}"></i>${esc(S.ns[id]?.node.name || id)}</span><b>${v}</b></div>`;
    }).join('');
    const sel = cellStats(MX.cells.get(mxKey(lane.ip, lane.id)));
    const err = sel && !sel.ok ? `<div class="tt-row" style="margin-top:4px"><span style="color:var(--crit-text)">${esc(S.ns[lane.id]?.node.name)}: ${esc(sel.error)}</span></div>` : '';
    const range = sel && sel.ok ? `<div class="tt-row" style="margin-top:4px"><span style="color:var(--muted)">${esc(S.ns[lane.id]?.node.name)}: min ${fmtMs(sel.min)} · p90 ${fmtMs(sel.p90)} · max ${fmtMs(sel.max)} ms · ${sel.got}/${sel.n} packets</span></div>` : '';
    tip.innerHTML = `<div class="tt-time">via ${esc(lane.ip)}</div>${rowsHtml}${range}${err}`;
    tip.hidden = false;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let left = mx + 16;
    if (left + tw > r.width - 4) left = mx - tw - 16;
    tip.style.left = Math.max(4, left) + 'px';
    tip.style.top = Math.min(Math.max(4, my - th / 2), r.height - th - 4) + 'px';
    MX.dirty = true;
  }
  function hideMatrixTip() {
    $('mx-tip').hidden = true;
    if (MX.hover) { MX.hover = null; MX.dirty = true; }
  }

  function renderMatrixTable() {
    const rows = mxRows();
    if (!rows.length) { $('mx-thead').innerHTML = ''; $('mx-tbody').innerHTML = ''; return; }
    $('mx-thead').innerHTML = '<tr><th>IP</th>' + MX.nodes.map((id) =>
      `<th class="mx-h"><i class="sw" style="background:${seriesColor(id) || C.muted}"></i>${esc(S.ns[id]?.node.name || id)}</th>`).join('') +
      '<th>Score</th></tr>';
    const all = [];
    rows.forEach((ip) => MX.nodes.forEach((id) => { const v = metricOf(cellStats(MX.cells.get(mxKey(ip, id)))); if (v != null) all.push(v); }));
    all.sort((a, b) => a - b);
    const q1 = quantile(all, 0.25), q3 = quantile(all, 0.75);
    const bestIp_ = bestIp();
    $('mx-tbody').innerHTML = rows.map((ip) => {
      const sc = ipScore(ip);
      const tds = MX.nodes.map((id) => {
        const c = MX.cells.get(mxKey(ip, id));
        const st = cellStats(c);
        if (!c) return '<td class="mx-c pend">queued</td>';
        if (c.state === 'running') return '<td class="mx-c pend">testing…</td>';
        if (!st.ok) return `<td class="mx-c fail" title="${esc(st.error)}">✕ ${esc(st.stage || 'fail')}</td>`;
        const v = metricOf(st);
        const cls = all.length > 3 && v <= q1 ? 'fast' : all.length > 3 && v >= q3 ? 'slow' : '';
        return `<td class="mx-c ${cls}">${fmtMs(v)} ms<small>${st.loss.toFixed(0)}% loss${st.colo ? ' · ' + st.colo : ''}</small></td>`;
      }).join('');
      return `<tr class="${ip === bestIp_ && sc.ok ? 'best' : ''}"><td>${esc(ip)}${ip === bestIp_ && sc.ok ? ' ★' : ''}</td>${tds}
        <td class="muted">${sc.ok}/${MX.nodes.length} ok${sc.med != null ? ' · ' + fmtMs(sc.med) + ' ms' : ''}</td></tr>`;
    }).join('');
  }

  function renderMatrix() {
    const done = [...MX.cells.values()].filter((c) => c.state === 'done').length;
    const total = MX.ips.length * MX.nodes.length;
    $('mx-progress').textContent = !total ? ' ' : MX.running ? `${done}/${total} cells…` : `${done}/${total} cells done`;
    $('mx-start').disabled = MX.running;
    $('mx-stop').disabled = !MX.running;
    $('mx-export').disabled = !done;
    renderMatrixLegend();
    drawMatrix();
    renderMatrixTable();
  }

  function exportMatrixCsv() {
    const out = [['ip', 'node', 'ok', 'colo', 'connect_ms', 'median_ms', 'min_ms', 'p90_ms', 'max_ms', 'loss_pct', 'error']];
    MX.ips.forEach((ip) => MX.nodes.forEach((id) => {
      const st = cellStats(MX.cells.get(mxKey(ip, id)));
      if (!st) return;
      const f = (v) => (v == null ? '' : v.toFixed(1));
      out.push([ip, id, st.ok, st.colo || '', f(st.connect), f(st.med), f(st.min), f(st.p90), f(st.max), f(st.loss), (st.error || '').replace(/"/g, "'")]);
    }));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([out.map((r) => r.map((c) => `"${c}"`).join(',')).join('\n')], { type: 'text/csv' }));
    a.download = `proxyscope-bugip-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  function wireMatrix() {
    $('mx-ips').value = store.get('mxIps', DEFAULT_IPS);
    $('mx-ips').addEventListener('input', () => store.set('mxIps', $('mx-ips').value));
    $('mx-start').addEventListener('click', async () => {
      const ips = parseIps($('mx-ips').value);
      const nodes = [...document.querySelectorAll('#mx-nodes input:checked')].map((i) => i.value);
      if (!ips.length || !nodes.length) { $('mx-progress').textContent = 'Need at least one IP and one node'; return; }
      $('mx-start').disabled = true;
      const r = await api('/api/matrix', { ips, nodes, pings: +$('mx-pings').value, workers: +$('mx-workers').value, timeout: 10000 });
      if (r.error) { $('mx-progress').textContent = r.error; $('mx-start').disabled = false; }
    });
    $('mx-stop').addEventListener('click', () => api('/api/matrix', { action: 'stop' }));
    $('mx-export').addEventListener('click', exportMatrixCsv);
    [['mx-metric', 'm', 'metric', 'mxMetric'], ['mx-sort', 's', 'sort', 'mxSort']].forEach(([seg, attr, key, sk]) => {
      document.querySelectorAll(`#${seg} button`).forEach((b) => {
        b.classList.toggle('on', b.dataset[attr] === MX[key]);
        b.addEventListener('click', () => {
          MX[key] = b.dataset[attr]; store.set(sk, MX[key]);
          document.querySelectorAll(`#${seg} button`).forEach((x) => x.classList.toggle('on', x === b));
          MX.dirty = true;
        });
      });
    });
    const cv = $('mx-chart');
    cv.addEventListener('mousemove', onMatrixMove);
    cv.addEventListener('mouseleave', hideMatrixTip);
  }

  // ── selection / render loop ─────────────────────────────────────────────
  function select(id) {
    if (!S.ns[id]) return;
    S.selected = id;
    store.set('selected', id);
    S.hover = null; $('tooltip').hidden = true;
    rebuildConsole();
    S.dirty = true;
  }

  let lastFull = 0;
  function frame() {
    const now = performance.now();
    const anyLive = Object.values(S.ns).some((n) => n.live);
    // the time axis scrolls while live; repaint ~4×/s even without new events
    if (S.dirty || (anyLive && now - lastFull > 250)) {
      S.dirty = false; lastFull = now;
      renderNodeCards();
      renderDetail();
      renderSummary();
      if (S.mode === 'all') renderSeriesLegend();
      drawChart();
    }
    if (MX.dirty) { MX.dirty = false; renderMatrix(); }
    requestAnimationFrame(frame);
  }

  // ── wiring ──────────────────────────────────────────────────────────────
  function wire() {
    wireMatrix();
    ['opt-interval', 'opt-timeout', 'opt-size'].forEach((id) => {
      const saved = store.get(id, null);
      if (saved !== null && [...$(id).options].some((o) => o.value === saved)) $(id).value = saved;
      $(id).addEventListener('change', () => { store.set(id, $(id).value); restartLive(); });
    });
    $('btn-start-all').addEventListener('click', () => { store.set('autostart', true); S.nodes.forEach((n) => { if (!S.ns[n.id].live) startNode(n.id); }); });
    $('btn-stop-all').addEventListener('click', () => { store.set('autostart', false); S.nodes.forEach((n) => { if (S.ns[n.id].live) stopNode(n.id); }); });
    $('d-toggle').addEventListener('click', () => toggleNode(S.selected));
    $('d-probe').addEventListener('click', async () => {
      const ns = S.ns[S.selected];
      ns.probing = true; ns.probes = []; S.dirty = true;
      const r = await api('/api/probe', { id: S.selected, count: 5, timeout: 15000 });
      if (r.error) { ns.probing = false; log(S.selected, 'error', esc(r.error)); }
    });
    $('d-speed').addEventListener('click', async () => {
      const ns = S.ns[S.selected];
      ns.speed = { running: true, down: null, up: null, prog: {} }; S.dirty = true;
      const r = await api('/api/speed', { id: S.selected, bytes: +$('speed-size').value });
      if (r.error) { ns.speed.running = false; ns.speed.error = r.error; }
    });
    $('d-clear').addEventListener('click', () => {
      const ns = S.ns[S.selected];
      Object.assign(ns, { packets: [], bySeq: new Map(), sent: 0, recv: 0, lost: 0, reconnects: 0, outages: [] });
      S.logAll = S.logAll.filter((e) => e.node !== S.selected);
      rebuildConsole(); S.dirty = true;
    });
    $('d-export').addEventListener('click', exportCsv);

    document.querySelectorAll('#win-seg button').forEach((b) => {
      b.classList.toggle('on', +b.dataset.win === S.win);
      b.addEventListener('click', () => {
        S.win = +b.dataset.win; store.set('win', S.win);
        document.querySelectorAll('#win-seg button').forEach((x) => x.classList.toggle('on', x === b));
        S.dirty = true;
      });
    });
    document.querySelectorAll('#mode-seg button').forEach((b) => b.addEventListener('click', () => {
      S.mode = b.dataset.mode; store.set('mode', S.mode); applyChartMode();
    }));
    document.querySelectorAll('#log-filter button').forEach((b) => b.addEventListener('click', () => {
      S.logFilter = b.dataset.f;
      document.querySelectorAll('#log-filter button').forEach((x) => x.classList.toggle('on', x === b));
      rebuildConsole();
    }));
    $('log-allnodes').addEventListener('change', rebuildConsole);
    $('log-follow').addEventListener('change', () => { if ($('log-follow').checked) $('console').scrollTop = $('console').scrollHeight; });

    const cv = $('chart');
    cv.addEventListener('mousemove', onChartMove);
    cv.addEventListener('mouseleave', hideTip);

    // theme
    const applyTheme = (t) => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; readColors(); S.dirty = true; MX.dirty = true; };
    applyTheme(store.get('theme', null));
    $('btn-theme').addEventListener('click', () => {
      const cur = document.documentElement.dataset.theme ||
        (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
      const next = cur === 'dark' ? 'light' : 'dark';
      store.set('theme', next); applyTheme(next);
    });
    matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => { readColors(); S.dirty = true; MX.dirty = true; });
    window.addEventListener('resize', () => { S.dirty = true; MX.dirty = true; });

    // custom node dialog
    const dlg = $('custom-modal');
    $('btn-custom').addEventListener('click', () => { $('c-error').hidden = true; dlg.showModal(); });
    $('c-tls').addEventListener('change', () => { $('c-port').placeholder = $('c-tls').checked ? '443' : '80'; });
    $('custom-form').addEventListener('submit', async (ev) => {
      if (ev.submitter && ev.submitter.value === 'cancel') return;
      ev.preventDefault();
      const r = await fetch('/api/custom', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host: $('c-host').value.trim(), front: $('c-front').value.trim(), port: $('c-port').value,
          path: $('c-path').value.trim(), method: $('c-method').value, tls: $('c-tls').checked,
        }),
      }).then((x) => x.json()).catch((e) => ({ error: e.message }));
      if (r.error) { $('c-error').textContent = r.error; $('c-error').hidden = false; return; }
      dlg.close();
      await loadNodes();
      select(r.id);
      startNode(r.id);
    });
  }

  async function loadNodes() {
    const r = await fetch('/api/nodes').then((x) => x.json());
    S.nodes = r.nodes;
    S.creds = r.creds || {};
    S.nodes.forEach((n) => {
      if (!S.ns[n.id]) S.ns[n.id] = newState(n);
      else S.ns[n.id].node = n;
    });
    buildNodeList();
    buildSeriesLegend();
    buildMatrixNodes();
    if (!S.ns[S.selected]) S.selected = S.nodes[0]?.id;
    if (!S.creds.ssh) log(S.selected, 'warn', 'SSH_USER / SSH_PASS missing in .env — SSH nodes cannot authenticate');
    if (!S.creds.uuid) log(S.selected, 'warn', 'No V2Ray UUID (.v2ray_uuid / V2RAY_UUID) — VLESS / VMess tests will fail');
    S.dirty = true;
  }

  async function init() {
    readColors();
    wire();
    try {
      await loadNodes();
    } catch (e) {
      $('node-list').innerHTML = `<div class="empty">Cannot reach the ProxyScope server (${esc(e.message)}). Is <code>python web_server.py</code> running?</div>`;
      return;
    }
    connectEvents();
    select(S.selected);
    applyChartMode();
    requestAnimationFrame(frame);
    if (store.get('autostart', true)) S.nodes.forEach((n) => startNode(n.id));
  }

  document.addEventListener('DOMContentLoaded', init);
})();
