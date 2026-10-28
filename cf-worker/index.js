// VLESS-over-WebSocket proxy for Cloudflare Workers (free plan friendly).
//
//   client --TLS/WS--> Cloudflare edge (nearest colo) --> Worker --connect()--> target
//
// Config (wrangler secret / [vars]):
//   UUID     client UUID. If unset, ANY uuid is accepted (open proxy) -- set it.
//   PROXYIP  optional host[:port] used as a fallback when the target can't be reached
//            directly (Workers cannot connect() to Cloudflare-hosted IPs).
//
// Client side: network ws, TLS on, path "/" or "/?ed=2048", mux OFF.
import { connect } from 'cloudflare:sockets';

const FALLBACK_PROXY_IPS = ['cdn.xn--b6gac.eu.org', 'cdn-all.xn--b6gac.eu.org'];
const WS_OPEN = 1;
const WS_CLOSING = 2;
const CHUNK = 32 * 1024; // keep every outgoing WS message far below the 1 MiB limit

export default {
	async fetch(request, env) {
		try {
			const url = new URL(request.url);
			if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
				return handleSession(request, env);
			}
			const uuid = (env.UUID || '').toLowerCase();
			if (url.pathname === '/health') return new Response('OK');
			if (uuid && url.pathname === `/${uuid}`) {
				return new Response(configPage(uuid, url.host), { headers: { 'content-type': 'text/html;charset=utf-8' } });
			}
			if (uuid && url.pathname === `/sub/${uuid}`) {
				return new Response(btoa(links(uuid, url.host).join('\n')), { headers: { 'content-type': 'text/plain;charset=utf-8' } });
			}
			return new Response('Not Found', { status: 404 });
		} catch (err) {
			return new Response(String(err), { status: 500 });
		}
	},
};

// ── session ──────────────────────────────────────────────────────────────────

function handleSession(request, env) {
	const [client, server] = Object.values(new WebSocketPair());
	server.accept();

	const proto = request.headers.get('sec-websocket-protocol') || '';
	const early = decodeEarlyData(proto);
	const uuidBytes = parseUUID(env.UUID);
	const proxyIPs = env.PROXYIP ? [env.PROXYIP] : FALLBACK_PROXY_IPS;

	const st = {
		sock: null,
		writer: null,
		dns: null, // DoH writer once the session turned out to be UDP/53
		closed: false,
	};

	const shutdown = () => {
		if (st.closed) return;
		st.closed = true;
		try { st.writer && st.writer.releaseLock(); } catch {}
		try { st.sock && st.sock.close(); } catch {}
		closeWS(server);
	};

	// Messages are processed strictly in order; awaiting the socket writer gives
	// the remote side backpressure.
	let chain = Promise.resolve();
	const enqueue = (data) => {
		chain = chain
			.then(() => onData(data, st, server, uuidBytes, proxyIPs, shutdown))
			.catch((err) => {
				console.log('session error:', err && err.message ? err.message : err);
				shutdown();
			});
	};

	server.addEventListener('message', (ev) => enqueue(ev.data));
	server.addEventListener('close', shutdown);
	server.addEventListener('error', shutdown);
	if (early) enqueue(early);

	const headers = proto ? { 'Sec-WebSocket-Protocol': proto } : undefined;
	return new Response(null, { status: 101, webSocket: client, headers });
}

async function onData(data, st, ws, uuidBytes, proxyIPs, shutdown) {
	if (st.closed) return;
	const chunk = toBytes(data);

	if (st.dns) return st.dns(chunk);
	if (st.writer) return st.writer.write(chunk);

	const h = parseVless(chunk, uuidBytes);
	if (h.error) throw new Error(h.error);

	const respHeader = new Uint8Array([h.version, 0]);
	const payload = chunk.subarray(h.dataIndex);

	if (h.udp) {
		if (h.port !== 53) throw new Error(`udp/${h.port} not supported`);
		st.dns = makeDnsHandler(ws, respHeader);
		return st.dns(payload);
	}
	await openTcp(h.host, h.port, payload, st, ws, respHeader, proxyIPs, shutdown);
}

// ── TCP ──────────────────────────────────────────────────────────────────────

async function dial(host, port) {
	const sock = connect({ hostname: host, port });
	await sock.opened; // fails here (not later) if the target is unreachable
	return sock;
}

function splitHostPort(s, defPort) {
	const m = /^(.*?)(?::(\d+))?$/.exec(s);
	return [m[1], m[2] ? Number(m[2]) : defPort];
}

async function attach(sock, first, st, ws, respHeader, shutdown) {
	st.sock = sock;
	st.writer = sock.writable.getWriter();
	if (first.byteLength) await st.writer.write(first);
	return pump(sock, ws, respHeader);
}

// Resolves with the number of bytes received from the remote side.
async function pump(sock, ws, respHeader) {
	const reader = sock.readable.getReader();
	let total = 0;
	let header = respHeader;
	try {
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			if (ws.readyState !== WS_OPEN) break;
			total += value.byteLength;
			for (let o = 0; o < value.byteLength; o += CHUNK) {
				const part = value.subarray(o, Math.min(o + CHUNK, value.byteLength));
				if (header) {
					const m = new Uint8Array(header.byteLength + part.byteLength);
					m.set(header, 0);
					m.set(part, header.byteLength);
					ws.send(m);
					header = null;
				} else {
					ws.send(part);
				}
			}
		}
	} catch (err) {
		console.log('remote read error:', err && err.message ? err.message : err);
	} finally {
		try { reader.releaseLock(); } catch {}
	}
	return total;
}

async function openTcp(host, port, first, st, ws, respHeader, proxyIPs, shutdown) {
	// 1) direct
	let received = 0;
	let direct = null;
	try {
		direct = await dial(host, port);
	} catch (err) {
		console.log(`direct ${host}:${port} failed: ${err && err.message}`);
	}
	if (direct) {
		// Don't block the message chain on the (long-lived) download pump.
		attach(direct, first, st, ws, respHeader, shutdown)
			.then(async (n) => {
				received = n;
				if (received === 0 && !st.closed) await fallback();
				else shutdown();
			})
			.catch(() => (st.closed ? null : fallback()));
		return;
	}
	await fallback();

	async function fallback() {
		// 2) via a proxy IP that can reach Cloudflare-hosted targets
		for (const p of proxyIPs) {
			if (st.closed) return;
			try {
				const [h, pt] = splitHostPort(p, port);
				try { st.writer && st.writer.releaseLock(); } catch {}
				try { st.sock && st.sock.close(); } catch {}
				st.writer = null;
				const sock = await dial(h, pt);
				attach(sock, first, st, ws, respHeader, shutdown).then(shutdown, shutdown);
				return;
			} catch (err) {
				console.log(`proxyip ${p} failed: ${err && err.message}`);
			}
		}
		shutdown();
	}
}

// ── DNS (UDP/53 over DoH) ────────────────────────────────────────────────────

function makeDnsHandler(ws, respHeader) {
	let header = respHeader;
	let buf = new Uint8Array(0);
	return async (chunk) => {
		const m = new Uint8Array(buf.byteLength + chunk.byteLength);
		m.set(buf, 0);
		m.set(chunk, buf.byteLength);
		buf = m;
		while (buf.byteLength >= 2) {
			const len = (buf[0] << 8) | buf[1];
			if (buf.byteLength < 2 + len) break;
			const query = buf.slice(2, 2 + len);
			buf = buf.slice(2 + len);
			try {
				const r = await fetch('https://1.1.1.1/dns-query', {
					method: 'POST',
					headers: { 'content-type': 'application/dns-message' },
					body: query,
				});
				if (!r.ok) continue;
				const ans = new Uint8Array(await r.arrayBuffer());
				if (ws.readyState !== WS_OPEN) return;
				const out = new Uint8Array((header ? header.byteLength : 0) + 2 + ans.byteLength);
				let o = 0;
				if (header) { out.set(header, 0); o = header.byteLength; header = null; }
				out[o] = (ans.byteLength >> 8) & 0xff;
				out[o + 1] = ans.byteLength & 0xff;
				out.set(ans, o + 2);
				ws.send(out);
			} catch (err) {
				console.log('doh error:', err && err.message ? err.message : err);
			}
		}
	};
}

// ── VLESS header ─────────────────────────────────────────────────────────────

// [ver 1][uuid 16][addonsLen 1][addons][cmd 1][port 2][atype 1][addr][data...]
function parseVless(b, uuidBytes) {
	if (b.byteLength < 24) return { error: 'short header' };
	const version = b[0];
	if (uuidBytes) {
		for (let i = 0; i < 16; i++) if (b[1 + i] !== uuidBytes[i]) return { error: 'bad uuid' };
	}
	const optLen = b[17];
	let i = 18 + optLen;
	const cmd = b[i++];
	if (cmd !== 1 && cmd !== 2) return { error: `unsupported command ${cmd} (is mux on?)` };
	const port = (b[i] << 8) | b[i + 1];
	i += 2;
	const atype = b[i++];
	let host;
	if (atype === 1) {
		host = `${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`;
		i += 4;
	} else if (atype === 2) {
		const n = b[i++];
		host = new TextDecoder().decode(b.subarray(i, i + n));
		i += n;
	} else if (atype === 3) {
		const parts = [];
		for (let k = 0; k < 8; k++) parts.push(((b[i + k * 2] << 8) | b[i + k * 2 + 1]).toString(16));
		host = parts.join(':');
		i += 16;
	} else {
		return { error: `bad address type ${atype}` };
	}
	if (!host) return { error: 'empty address' };
	return { version, udp: cmd === 2, port, host, dataIndex: i };
}

// ── helpers ──────────────────────────────────────────────────────────────────

function toBytes(data) {
	if (typeof data === 'string') return new TextEncoder().encode(data);
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
}

function decodeEarlyData(s) {
	if (!s || s.length < 8) return null; // a header is >= 24 bytes => >= 32 base64 chars
	try {
		const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
		return Uint8Array.from(bin, (c) => c.charCodeAt(0));
	} catch {
		return null;
	}
}

function parseUUID(s) {
	if (!s) return null;
	const hex = s.replace(/-/g, '');
	if (!/^[0-9a-fA-F]{32}$/.test(hex)) return null;
	return Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
}

function closeWS(ws) {
	try {
		if (ws.readyState === WS_OPEN || ws.readyState === WS_CLOSING) ws.close();
	} catch {}
}

const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function links(uuid, host) {
	const q = `encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=%2F%3Fed%3D2048`;
	return [
		`vless://${uuid}@jsbl.com:443?${q}#${host}-bughost`,
		`vless://${uuid}@${host}:443?${q}#${host}`,
	];
}

function configPage(uuid, host) {
	const [bug, direct] = links(uuid, host);
	return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VLESS</title><body style="font-family:system-ui;background:#0d1117;color:#c9d1d9;padding:1.5rem">
<h3>Bug host (TLS 443)</h3><pre style="white-space:pre-wrap;word-break:break-all">${esc(bug)}</pre>
<h3>Direct</h3><pre style="white-space:pre-wrap;word-break:break-all">${esc(direct)}</pre>
<p>Mux must be off in the client.</p></body>`;
}
