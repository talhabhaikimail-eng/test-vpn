// muxserver: serves the "/mux" WebSocket path of proxy_v2ray in-process.
//
// The Windows client dials the carrier bug host (a Cloudflare IP), sends a
// WebSocket upgrade with Host: <our domain> and path /mux, and after the 101
// speaks the encrypted mux protocol from muxproto.go over the raw socket.
// One such session carries every TCP connection and DNS query of the client,
// so the ~900 ms Cloudflare WebSocket setup is paid once per session, and a
// new connection opens with zero extra round trips.
//
// Built together with proxy_v2ray.go, muxproto.go and quickack_linux.go.
package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	muxDialTimeout   = 10 * time.Second
	muxDNSTimeout    = 2 * time.Second
	muxDNSCacheTTL   = 60 * time.Second
	muxDNSCacheLimit = 4096
	muxResumeGrace   = 90 * time.Second // keep a dropped session resumable this long
)

var muxDNSUpstreams = []string{"1.1.1.1:53", "8.8.8.8:53", "1.0.0.1:53"}

var (
	muxSessions atomic.Int64
	muxReg      = newMuxResumeRegistry()
)

func muxAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(strings.TrimSpace(key)))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// muxPrefixConn replays bytes net/http already buffered behind the headers.
type muxPrefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *muxPrefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// muxDialer refuses loopback, link-local and private targets: the runner's
// local services (Xray inbounds, metrics) are never reachable through a session.
var muxDialer = &net.Dialer{
	Timeout:   muxDialTimeout,
	KeepAlive: 30 * time.Second,
	Control: func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return errors.New("mux: unresolved target")
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("mux: target not allowed")
		}
		return nil
	},
}

// ── DNS: forward raw queries over UDP with a small cache ─────────────────────

type muxDNSEntry struct {
	data    []byte
	expires time.Time
}

var (
	muxDNSMu    sync.Mutex
	muxDNSCache = map[string]muxDNSEntry{}
)

func muxResolveDNS(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("short dns query")
	}
	txID := query[:2]
	key := string(query[12:])

	muxDNSMu.Lock()
	if e, ok := muxDNSCache[key]; ok && time.Now().Before(e.expires) {
		resp := append([]byte(nil), e.data...)
		muxDNSMu.Unlock()
		copy(resp[:2], txID)
		return resp, nil
	}
	muxDNSMu.Unlock()

	var lastErr error
	for _, up := range muxDNSUpstreams {
		ctx, cancel := context.WithTimeout(context.Background(), muxDNSTimeout)
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", up)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(muxDNSTimeout))
		if _, err = conn.Write(query); err != nil {
			_ = conn.Close()
			cancel()
			lastErr = err
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		_ = conn.Close()
		cancel()
		if err != nil || n < 12 {
			lastErr = err
			continue
		}
		resp := buf[:n]
		// Only cache answers that carry records and no error (RCODE 0).
		if resp[3]&0x0F == 0 && binary.BigEndian.Uint16(resp[6:8]) > 0 {
			muxDNSMu.Lock()
			if len(muxDNSCache) > muxDNSCacheLimit {
				muxDNSCache = map[string]muxDNSEntry{}
			}
			muxDNSCache[key] = muxDNSEntry{data: append([]byte(nil), resp...), expires: time.Now().Add(muxDNSCacheTTL)}
			muxDNSMu.Unlock()
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("dns upstreams failed")
	}
	return nil, lastErr
}

// ── HTTP handler ─────────────────────────────────────────────────────────────

// serveMux hijacks the upgraded connection, answers 101 and runs the session.
func (rt *router) serveMux(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	rt.hijacked.Add(1)
	defer rt.hijacked.Done()
	defer client.Close()
	_ = client.SetDeadline(time.Time{})

	var resp strings.Builder
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	if k := r.Header.Get("Sec-WebSocket-Key"); k != "" {
		resp.WriteString("Sec-WebSocket-Accept: " + muxAcceptKey(k) + "\r\n")
	}
	resp.WriteString("X-Server-Info: " + serverBanner() + "\r\n\r\n")
	if _, err := brw.WriteString(resp.String()); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}

	var conn net.Conn = client
	if brw.Reader.Buffered() > 0 {
		conn = &muxPrefixConn{Conn: client, r: brw.Reader}
	}

	n := muxSessions.Add(1)
	log.Printf("mux connection up (%d active) from %s", n, r.RemoteAddr)
	defer func() { log.Printf("mux connection down (%d active)", muxSessions.Add(-1)) }()

	// muxServerConn handshakes, decides fresh-vs-resume, serves, and on a link
	// drop keeps the session resumable for muxResumeGrace so the client can
	// reattach its open streams.
	muxServerConn(conn, rt.muxKey, muxReg, muxResumeGrace, func(sess *muxSession) {
		sess.onOpen = func(st *muxStream, host string, port int, initial []byte) {
			muxServeStream(st, host, port, initial, muxDialer)
		}
		sess.onDNS = muxResolveDNS
	}, func(msg string) { log.Printf("%s from %s", msg, r.RemoteAddr) })
}
