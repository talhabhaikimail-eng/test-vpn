// proxy_v2ray: the single port cloudflared (or Render) forwards to. It routes
// every request to the right Xray inbound and keeps the TCP path tuned:
//
//	WebSocket upgrade  /vless, /          -> VLESS WS inbound   (raw splice after hijack)
//	WebSocket upgrade  /vmess             -> VMess WS inbound   (raw splice after hijack)
//	WebSocket upgrade  /mux               -> in-process mux session (muxserver.go)
//	plain HTTP         /xh, /xh/...       -> VLESS XHTTP inbound (HTTP reverse proxy)
//	plain HTTP         /health, /ping     -> answered here
//	plain HTTP         anything else      -> optional web panel (--http) or 404
//
// Why an HTTP-aware router instead of a byte splice on the first request line:
// cloudflared pools keep-alive connections to the origin and reuses one for any
// later non-WebSocket request. With a per-connection splice, a connection first
// used for /xh would later carry a /health or panel request into the XHTTP
// inbound. net/http routes per request, so pooled connections stay correct.
// WebSockets consume their connection, so hijack + splice is exact for them.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxHeaderBytes   = 8192
	handshakeTimeout = 5 * time.Second
	dialTimeout      = 3 * time.Second
	idleTimeout      = 120 * time.Second // cloudflared keeps origin connections warm
	keepAlivePeriod  = 15 * time.Second
	maxUptimeHours   = 6
)

var (
	startTime  = time.Now()
	pktZone    = time.FixedZone("PKT", 5*60*60)
	startedStr = startTime.In(pktZone).Format("02 Jan 2006 15:04 PKT")
	nodeName   = "V2Ray Node"
)

func serverBanner() string {
	elapsed := time.Since(startTime)
	remaining := time.Duration(maxUptimeHours)*time.Hour - elapsed
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("[%s] Xray WS+XHTTP | Started: %s | Restarts in %dh %02dm",
		nodeName, startedStr, int(remaining.Hours()), int(remaining.Minutes())%60)
}

// ── TCP tuning ───────────────────────────────────────────────────────────────

func tune(c *net.TCPConn) {
	_ = c.SetNoDelay(true)
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(keepAlivePeriod)
	setQuickAck(c)
}

// rawTCP unwraps the *net.TCPConn behind a connection handed out by limitListener.
func rawTCP(c net.Conn) *net.TCPConn {
	switch v := c.(type) {
	case *net.TCPConn:
		return v
	case *limitedConn:
		return v.TCPConn
	}
	return nil
}

type halfCloser interface {
	net.Conn
	CloseWrite() error
}

func forward(dst, src halfCloser, done chan<- struct{}) {
	defer func() {
		_ = dst.CloseWrite()
		done <- struct{}{}
	}()
	if tc := rawTCP(src); tc != nil {
		setQuickAck(tc) // one-shot on Linux; re-arm as streaming starts
	}
	_, _ = io.Copy(dst, src)
}

// ── Listener: TCP tuning on accept + max-conns guard ─────────────────────────

type limitListener struct {
	*net.TCPListener
	sem chan struct{}
}

type limitedConn struct {
	*net.TCPConn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	c.once.Do(c.release)
	return c.TCPConn.Close()
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptTCP()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
		default:
			log.Printf("at capacity (%d), dropping %s", cap(l.sem), c.RemoteAddr())
			_ = c.Close()
			continue
		}
		tune(c)
		return &limitedConn{TCPConn: c, release: func() { <-l.sem }}, nil
	}
}

// ── Router ───────────────────────────────────────────────────────────────────

type router struct {
	vless, vmess string
	xhttpPrefix  string
	xhttp, ui    *httputil.ReverseProxy
	muxKey       []byte // pre-shared key for the /mux session protocol (nil = disabled)
	hijacked     sync.WaitGroup
}

func newReverseProxy(target string) *httputil.ReverseProxy {
	u := &url.URL{Scheme: "http", Host: target}
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: dialTimeout, KeepAlive: keepAlivePeriod}).DialContext,
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 1024,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = pr.In.Host // keep the public hostname (panel links, xhttp host check)
		},
		Transport:     tr,
		FlushInterval: -1, // XHTTP download is a long streaming GET: never buffer
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("upstream %s %s: %v", target, r.URL.Path, err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket")
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	ws := isWebSocketUpgrade(r)
	// A non-101 answer to an Upgrade request must close the socket: cloudflared
	// treats the WS request as a stream and otherwise waits for EOF (hangs).
	if ws {
		w.Header().Set("Connection", "close")
	}
	switch {
	case p == "/health" || p == "/ping":
		banner := serverBanner()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Server-Info", banner)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprintf(w, "OK - %s\n", banner)
	case ws && rt.muxKey != nil && (p == "/mux" || strings.HasPrefix(p, "/mux/")):
		rt.serveMux(w, r)
	case ws:
		rt.serveWebSocket(w, r)
	case rt.xhttp != nil && (p == rt.xhttpPrefix || strings.HasPrefix(p, rt.xhttpPrefix+"/")):
		rt.xhttp.ServeHTTP(w, r)
	case rt.ui != nil:
		rt.ui.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveWebSocket hijacks the client connection, replays the upgrade request to
// the Xray WS inbound on path "/" and splices bytes both ways. Early data in
// Sec-WebSocket-Protocol and any frames the client sent right behind the
// headers (already buffered by net/http) are forwarded untouched.
func (rt *router) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	target := rt.vless
	if rt.vmess != "" && strings.HasPrefix(r.URL.Path, "/vmess") {
		target = rt.vmess
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	up, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("dial upstream %s: %v", target, err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	upstream := up.(*net.TCPConn)
	tune(upstream)

	client, brw, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	rt.hijacked.Add(1)
	defer rt.hijacked.Done()
	defer client.Close()
	defer upstream.Close()
	_ = client.SetDeadline(time.Time{})

	var b strings.Builder
	b.Grow(1024)
	b.WriteString("GET / HTTP/1.1\r\nHost: ")
	b.WriteString(r.Host)
	b.WriteString("\r\n")
	for k, vs := range r.Header {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	if n := brw.Reader.Buffered(); n > 0 {
		early, _ := brw.Reader.Peek(n)
		b.Write(early)
	}
	if _, err := io.WriteString(upstream, b.String()); err != nil {
		return
	}

	cl, ok := client.(halfCloser)
	if !ok {
		return
	}
	done := make(chan struct{}, 2)
	go forward(upstream, cl, done)
	go forward(cl, upstream, done)
	<-done
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	listen := flag.String("listen", "0.0.0.0:8080", "listen address for Cloudflare Tunnel reverse proxy")
	vless := flag.String("vless", "127.0.0.1:10085", "upstream VLESS WS inbound")
	vmess := flag.String("vmess", "127.0.0.1:10086", "upstream VMess WS inbound (empty to disable)")
	xhttp := flag.String("xhttp", "127.0.0.1:10087", "upstream VLESS XHTTP inbound (empty to disable)")
	xhttpPath := flag.String("xhttp-path", "/xh", "path prefix routed to the XHTTP inbound")
	httpUp := flag.String("http", "", "optional upstream for other plain HTTP requests (web panel)")
	muxKeyFile := flag.String("mux-key-file", "/etc/v2ray/mux.key", "pre-shared key file for the /mux session protocol (missing = disabled)")
	maxConns := flag.Int("max-conns", 2048, "max concurrent connections")
	name := flag.String("name", "V2Ray Node 1", "server instance name")
	flag.Parse()
	nodeName = *name

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rt := &router{vless: *vless, vmess: *vmess, xhttpPrefix: strings.TrimSuffix(*xhttpPath, "/")}
	if *xhttp != "" {
		rt.xhttp = newReverseProxy(*xhttp)
	}
	if *httpUp != "" {
		rt.ui = newReverseProxy(*httpUp)
	}
	if key, err := muxReadPSKFile(*muxKeyFile); err == nil {
		rt.muxKey = key
		log.Printf("[V2Ray-Proxy] /mux session protocol enabled")
	} else {
		log.Printf("[V2Ray-Proxy] /mux disabled: %v", err)
	}

	addr, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	tl, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatalf("bind %s: %v", *listen, err)
	}
	ln := &limitListener{TCPListener: tl, sem: make(chan struct{}, *maxConns)}

	srv := &http.Server{
		Handler:           rt,
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	log.Printf("[V2Ray-Proxy] %s -> VLESS-WS:%s | VMess-WS:%s | XHTTP:%s%s | mux:%v | panel:%s (max-conns=%d)",
		*listen, *vless, *vmess, *xhttp, rt.xhttpPrefix, rt.muxKey != nil, *httpUp, *maxConns)
	log.Printf("[V2Ray-Proxy] %s", serverBanner())

	go func() {
		<-ctx.Done()
		log.Println("shutting down, draining active connections (10s max)...")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}

	done := make(chan struct{})
	go func() { rt.hijacked.Wait(); close(done) }()
	select {
	case <-done:
		log.Println("clean shutdown.")
	case <-time.After(10 * time.Second):
		log.Println("timeout, forcing exit.")
	}
}
