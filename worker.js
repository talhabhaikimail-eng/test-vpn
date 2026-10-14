import { connect } from 'cloudflare:sockets';

// -- CONFIGURATION --
// Default UUID for VLESS authentication
const userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

// Backup fallback proxy IPs for Cloudflare-fronted destination sites
const proxyIPs = ['cdn.xn--b6gac.eu.org', 'cdn-all.xn--b6gac.eu.org', '104.16.132.229', '172.67.73.1'];
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			const uuid = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;
			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);

			if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
				switch (url.pathname) {
					case '/':
						return new Response(
							JSON.stringify(request.cf, null, 4),
							{
								status: 200,
								headers: { 'Content-Type': 'application/json;charset=utf-8' },
							}
						);
					case `/${uuid}`: {
						const vlessConfig = getVLESSConfig(uuid, request.headers.get('Host'));
						return new Response(vlessConfig, {
							status: 200,
							headers: { 'Content-Type': 'text/html;charset=utf-8' },
						});
					}
					case `/sub/${uuid}`: {
						const subConfig = getSubConfig(uuid, request.headers.get('Host'));
						return new Response(btoa(subConfig), {
							status: 200,
							headers: { 'Content-Type': 'text/plain;charset=utf-8' },
						});
					}
					default:
						return new Response('Not Found', { status: 404 });
				}
			} else {
				return await vlessOverWSHandler(request, uuid);
			}
		} catch (err) {
			return new Response(err.toString(), { status: 500 });
		}
	},
};

/**
 * Handles VLESS over WebSocket upgrade and outbound TCP tunneling via Cloudflare Sockets
 */
async function vlessOverWSHandler(request, userID) {
	const webSocketPair = new WebSocketPair();
	const [client, server] = Object.values(webSocketPair);
	server.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (info, event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(server, earlyDataHeader, log);

	let remoteSocketWapper = {
		value: null,
	};
	let isDns = false;
	let dOHWriter = null;

	readableWebSocketStream
		.pipeTo(
			new WritableStream({
				async write(chunk, controller) {
					if (isDns) {
						if (!dOHWriter) {
							dOHWriter = makeDOHWriter(server, new Uint8Array([0, 0]), log);
						}
						await dOHWriter(chunk);
						return;
					}

					if (remoteSocketWapper.value) {
						const writer = remoteSocketWapper.value.writable.getWriter();
						await writer.write(chunk);
						writer.releaseLock();
						return;
					}

					let buf = chunk;
					if (typeof buf === 'string') {
						console.log(`[Client Message (string)]: "${buf.slice(0, 50)}"`);
						buf = new TextEncoder().encode(buf).buffer;
					} else if (buf instanceof Uint8Array) {
						buf = buf.buffer;
					}

					const {
						hasError,
						message,
						portRemote = 443,
						addressRemote = '',
						rawDataIndex,
						vlessVersion = new Uint8Array([0, 0]),
						isUDP,
					} = processVlessHeader(buf, userID);

					address = addressRemote;
					portWithRandomLog = `${portRemote}--${Math.random().toFixed(4)} ${isUDP ? 'udp ' : 'tcp '}`;

					if (hasError) {
						log(`header error: ${message}`);
						controller.error(message);
						return;
					}

					if (isUDP) {
						if (portRemote === 53) {
							isDns = true;
						} else {
							log(`UDP packet on port ${portRemote} dropped (only DNS 53 supported)`);
							return;
						}
					}

					const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
					const rawClientData = chunk.slice(rawDataIndex);

					if (isDns) {
						dOHWriter = makeDOHWriter(server, vlessResponseHeader, log);
						await dOHWriter(rawClientData);
						return;
					}

					handleTCPOutBound(
						remoteSocketWapper,
						addressRemote,
						portRemote,
						rawClientData,
						server,
						vlessResponseHeader,
						log
					);
				},
				close() {
					log(`readableWebSocketStream closed`);
				},
				abort(reason) {
					log(`readableWebSocketStream abort: ${JSON.stringify(reason)}`);
				},
			})
		)
		.catch((err) => {
			log(`readableWebSocketStream pipeTo error: ${err}`);
		});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

function processVlessHeader(vlessBuffer, userID) {
	if (typeof vlessBuffer === 'string') {
		console.log(`[Client Data (Text)]: "${vlessBuffer.slice(0, 50).trim()}"`);
		if (vlessBuffer.startsWith('SSH-')) {
			return {
				hasError: true,
				message: `App Protocol Mismatch: Your client is sending SSH data ("${vlessBuffer.slice(0, 20).trim()}"). This worker runs V2Ray/VLESS! Please use v2rayNG or switch HTTP Custom to V2Ray mode.`
			};
		}
		vlessBuffer = new TextEncoder().encode(vlessBuffer).buffer;
	} else if (vlessBuffer instanceof Uint8Array) {
		vlessBuffer = vlessBuffer.buffer;
	}

	if (!vlessBuffer || vlessBuffer.byteLength < 24) {
		return { hasError: true, message: 'invalid data length (<24 bytes)' };
	}

	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);

	// Auto-permit any client UUID on your private worker & log it
	isValidUser = true;
	console.log(`[VLESS Auth] Connected with client UUID: ${slicedBufferString}`);

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

	if (command === 1) {
		isUDP = false;
	} else if (command === 2) {
		isUDP = true;
	} else {
		return { hasError: true, message: `command ${command} is not supported, only 1(TCP) and 2(UDP)` };
	}

	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';

	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `invalid addressType: ${addressType}` };
	}

	if (!addressValue) {
		return { hasError: true, message: 'addressValue is empty' };
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP,
	};
}

/**
 * Handles DNS-over-HTTPS (DoH) for UDP port 53 queries
 */
function makeDOHWriter(webSocket, vlessResponseHeader, log) {
	let isVlessHeaderSent = false;
	return async function(chunk) {
		try {
			for (let index = 0; index < chunk.byteLength;) {
				if (index + 2 > chunk.byteLength) break;
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
				if (index + 2 + udpPacketLength > chunk.byteLength) break;
				const udpData = chunk.slice(index + 2, index + 2 + udpPacketLength);
				index = index + 2 + udpPacketLength;

				const resp = await fetch('https://1.1.1.1/dns-query', {
					method: 'POST',
					headers: { 'content-type': 'application/dns-message' },
					body: udpData,
				});

				if (!resp.ok) {
					log(`DoH upstream HTTP ${resp.status}`);
					continue;
				}

				const dnsQueryResult = await resp.arrayBuffer();
				const udpSize = dnsQueryResult.byteLength;
				const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

				if (webSocket.readyState === WS_READY_STATE_OPEN) {
					if (isVlessHeaderSent) {
						webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					} else {
						webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
						isVlessHeaderSent = true;
					}
					log(`DoH resolved: ${udpSize} bytes`);
				}
			}
		} catch (err) {
			log(`DoH error: ${err.message || err}`);
		}
	};
}

async function handleTCPOutBound(
	remoteSocket,
	addressRemote,
	portRemote,
	rawClientData,
	webSocket,
	vlessResponseHeader,
	log
) {
	async function connectAndWrite(addr, port) {
		const tcpSocket = connect({
			hostname: addr,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${addr}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

	async function retry() {
		try {
			log(`retrying via proxyIP ${proxyIP}...`);
			const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
			tcpSocket.closed
				.catch((error) => {
					log(`retry tcpSocket closed: ${error}`);
				})
				.finally(() => {
					safeCloseWebSocket(webSocket);
				});
			remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
		} catch (err) {
			log(`retry failed: ${err.message || err}`);
			safeCloseWebSocket(webSocket);
		}
	}

	try {
		const tcpSocket = await connectAndWrite(addressRemote, portRemote);
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
	} catch (err) {
		log(`direct connect failed (${err.message || err}), falling back to proxyIP`);
		await retry();
	}
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});

			webSocketServer.addEventListener('error', (err) => {
				log(`webSocketServer error: ${err}`);
				controller.error(err);
			});

			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			log(`ReadableStream canceled: ${reason}`);
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		},
	});

	return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false;

	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {},
				async write(chunk, controller) {
					hasIncomingData = true;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error('webSocket is not open');
					}
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteSocket closed, incoming: ${hasIncomingData}`);
				},
				abort(reason) {
					log(`remoteSocket abort: ${reason}`);
				},
			})
		)
		.catch((error) => {
			log(`remoteSocketToWS exception: ${error.stack || error}`);
			safeCloseWebSocket(webSocket);
		});

	if (hasIncomingData === false && retry) {
		log(`no incoming data, triggering retry`);
		retry();
	}
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: null, error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: null, error };
	}
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		// Socket already closed
	}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function stringify(arr, offset = 0) {
	return (
		byteToHex[arr[offset + 0]] +
		byteToHex[arr[offset + 1]] +
		byteToHex[arr[offset + 2]] +
		byteToHex[arr[offset + 3]] +
		'-' +
		byteToHex[arr[offset + 4]] +
		byteToHex[arr[offset + 5]] +
		'-' +
		byteToHex[arr[offset + 6]] +
		byteToHex[arr[offset + 7]] +
		'-' +
		byteToHex[arr[offset + 8]] +
		byteToHex[arr[offset + 9]] +
		'-' +
		byteToHex[arr[offset + 10]] +
		byteToHex[arr[offset + 11]] +
		byteToHex[arr[offset + 12]] +
		byteToHex[arr[offset + 13]] +
		byteToHex[arr[offset + 14]] +
		byteToHex[arr[offset + 15]]
	).toLowerCase();
}

function getVLESSConfig(userID, hostName) {
	const vlessMain = `vless://${userID}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F#${hostName}`;
	const vlessBug = `vless://${userID}@jsbl.com:80?encryption=none&security=none&type=ws&host=${hostName}&path=%2F#${hostName}-BugHost`;

	return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VLESS Edge Configuration</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
pre { background: #161b22; padding: 1rem; border-radius: 8px; border: 1px solid #30363d; overflow-x: auto; color: #58a6ff; }
.card { background: #161b22; padding: 1.5rem; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 1.5rem; }
h3 { margin-top: 0; color: #f0f6fc; }
</style>
</head>
<body>
<h2>⚡ Cloudflare Edge VLESS Configuration</h2>
<div class="card">
<h3>Bug Host Config (Port 80 Plain / Zero-Rated)</h3>
<p>Address: <code>jsbl.com</code> | Port: <code>80</code> | Host: <code>${hostName}</code> | Path: <code>/</code></p>
<pre>${vlessBug}</pre>
</div>
<div class="card">
<h3>Direct TLS Config (Port 443)</h3>
<pre>${vlessMain}</pre>
</div>
</body>
</html>`;
}

function getSubConfig(userID, hostName) {
	const vlessMain = `vless://${userID}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F#${hostName}`;
	const vlessBug = `vless://${userID}@jsbl.com:80?encryption=none&security=none&type=ws&host=${hostName}&path=%2F#${hostName}-BugHost`;
	return `${vlessBug}\n${vlessMain}`;
}
