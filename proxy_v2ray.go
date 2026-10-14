package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	maxHeaderBytes   = 8192
	handshakeTimeout = 5 * time.Second
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
	return fmt.Sprintf("[%s] V2Ray WS+TLS | Started: %s | Restarts in %dh %02dm",
		nodeName, startedStr, int(remaining.Hours()), int(remaining.Minutes())%60)
}

func tune(c *net.TCPConn) {
	_ = c.SetNoDelay(true)
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(keepAlivePeriod)
	setQuickAck(c)
}

func forward(dst, src *net.TCPConn, done chan<- struct{}) {
	defer func() {
		_ = dst.CloseWrite()
		done <- struct{}{}
	}()

	setQuickAck(src)
	_, _ = io.Copy(dst, src)
}

// isWebSocketUpgrade reports whether the request headers carry "Upgrade: websocket".
func isWebSocketUpgrade(headerData []byte) bool {
	for _, line := range bytes.Split(headerData, []byte("\r\n")) {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if ok && bytes.EqualFold(bytes.TrimSpace(k), []byte("upgrade")) &&
			bytes.Contains(bytes.ToLower(v), []byte("websocket")) {
			return true
		}
	}
	return false
}

func handleClient(client *net.TCPConn, vlessAddr, vmessAddr, httpAddr *net.TCPAddr) {
	defer client.Close()
	tune(client)

	_ = client.SetReadDeadline(time.Now().Add(handshakeTimeout))

	headerBuf := make([]byte, maxHeaderBytes)
	n := 0
	headerEnd := -1

	for n < maxHeaderBytes {
		nr, err := client.Read(headerBuf[n:])
		if err != nil {
			return
		}
		n += nr
		idx := bytes.Index(headerBuf[:n], []byte("\r\n\r\n"))
		if idx != -1 {
			headerEnd = idx
			break
		}
	}

	if headerEnd == -1 {
		return
	}

	headerData := headerBuf[:headerEnd]

	// Extract path from request line: GET /path HTTP/1.1
	firstLine := headerData
	if crlf := bytes.Index(headerData, []byte("\r\n")); crlf != -1 {
		firstLine = headerData[:crlf]
	}
	parts := bytes.Split(firstLine, []byte(" "))
	path := []byte("/")
	if len(parts) >= 2 {
		path = parts[1]
	}

	// 1. Health check endpoint
	if bytes.Equal(path, []byte("/health")) || bytes.Equal(path, []byte("/ping")) {
		banner := serverBanner()
		body := fmt.Sprintf("OK - %s\n", banner)
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nX-Server-Info: %s\r\nConnection: close\r\n\r\n%s", len(body), banner, body)
		_, _ = client.Write([]byte(resp))
		return
	}

	// 2. Route: plain HTTP -> web UI (if enabled), WebSocket -> V2Ray inbound by path
	isWS := isWebSocketUpgrade(headerData)
	targetAddr := vlessAddr
	switch {
	case !isWS && httpAddr != nil:
		targetAddr = httpAddr
	case bytes.HasPrefix(path, []byte("/vmess")) && vmessAddr != nil:
		targetAddr = vmessAddr
	}

	_ = client.SetReadDeadline(time.Time{})

	upstream, err := net.DialTCP("tcp", nil, targetAddr)
	if err != nil {
		log.Printf("dial upstream %s: %v", targetAddr, err)
		return
	}
	defer upstream.Close()
	tune(upstream)

	// Send initial HTTP request bytes; WebSocket requests get the path normalized for V2Ray Core
	var forwardBuf bytes.Buffer
	forwardBuf.Grow(n + 32)
	if crlf := bytes.Index(headerBuf[:n], []byte("\r\n")); crlf != -1 && isWS {
		forwardBuf.WriteString("GET / HTTP/1.1\r\n")
		forwardBuf.Write(headerBuf[crlf+2 : n])
	} else {
		forwardBuf.Write(headerBuf[:n])
	}

	if _, err := upstream.Write(forwardBuf.Bytes()); err != nil {
		return
	}

	// Full-duplex streaming with immediate teardown
	done := make(chan struct{}, 2)
	go forward(upstream, client, done)
	go forward(client, upstream, done)

	<-done
}

func main() {
	listen    := flag.String("listen",    "0.0.0.0:8080",   "listen address for Cloudflare Tunnel reverse proxy")
	vless     := flag.String("vless",     "127.0.0.1:10085", "upstream V2Ray VLESS WS address")
	vmess     := flag.String("vmess",     "127.0.0.1:10086", "upstream V2Ray VMess WS address")
	httpUp    := flag.String("http",      "",                "optional upstream for non-WebSocket requests (web UI)")
	maxConns  := flag.Int("max-conns",    2048,              "max concurrent connections")
	name      := flag.String("name",      "V2Ray Node 1",    "server instance name")
	flag.Parse()
	nodeName = *name

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	listenAddr, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}

	vlessAddr, err := net.ResolveTCPAddr("tcp", *vless)
	if err != nil {
		log.Fatalf("resolve vless %s: %v", *vless, err)
	}

	var vmessAddr *net.TCPAddr
	if *vmess != "" {
		vmessAddr, err = net.ResolveTCPAddr("tcp", *vmess)
		if err != nil {
			log.Fatalf("resolve vmess %s: %v", *vmess, err)
		}
	}

	var httpAddr *net.TCPAddr
	if *httpUp != "" {
		httpAddr, err = net.ResolveTCPAddr("tcp", *httpUp)
		if err != nil {
			log.Fatalf("resolve http %s: %v", *httpUp, err)
		}
	}

	ln, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatalf("bind %s: %v", *listen, err)
	}
	go func() { <-ctx.Done(); ln.Close() }()

	log.Printf("[V2Ray-Proxy] %s -> VLESS:%s | VMess:%s (max-conns=%d)", *listen, *vless, *vmess, *maxConns)
	log.Printf("[V2Ray-Proxy] %s", serverBanner())

	sem := make(chan struct{}, *maxConns)
	var active sync.WaitGroup
	var backoff time.Duration

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			log.Printf("accept error (retry in %v): %v", backoff, err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0

		select {
		case sem <- struct{}{}:
		default:
			log.Printf("at capacity (%d), dropping %s", *maxConns, conn.RemoteAddr())
			conn.Close()
			continue
		}

		active.Add(1)
		go func(c *net.TCPConn) {
			defer active.Done()
			defer func() { <-sem }()
			handleClient(c, vlessAddr, vmessAddr, httpAddr)
		}(conn)
	}

	log.Println("shutting down, draining active connections (10s max)...")
	done := make(chan struct{})
	go func() { active.Wait(); close(done) }()
	select {
	case <-done:
		log.Println("clean shutdown.")
	case <-time.After(10 * time.Second):
		log.Println("timeout, forcing exit.")
	}
}
