package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	wsGUID           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxHeaderBytes   = 8192
	handshakeTimeout = 5 * time.Second
	keepAlivePeriod  = 15 * time.Second
	maxUptimeHours   = 6
	bufSize          = 65536 // 64KB buffer for wire-speed throughput
)

var (
	startTime  = time.Now()
	pktZone    = time.FixedZone("PKT", 5*60*60)
	startedStr = startTime.In(pktZone).Format("02 Jan 2006 15:04 PKT")

	bufPool = sync.Pool{
		New: func() any {
			b := make([]byte, bufSize)
			return &b
		},
	}
)

// serverBanner returns the live countdown header value, PKT-localised.
func serverBanner() string {
	elapsed := time.Since(startTime)
	remaining := time.Duration(maxUptimeHours)*time.Hour - elapsed
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("Made By Talha \u2764 | Started: %s | Restarts in %dh %02dm",
		startedStr, int(remaining.Hours()), int(remaining.Minutes())%60)
}

// acceptKey computes the Sec-WebSocket-Accept value with zero heap allocation.
func acceptKey(secKey []byte) string {
	k := bytes.TrimSpace(secKey)
	var in [128]byte
	n := copy(in[:], k)
	n += copy(in[n:], wsGUID)
	sum := sha1.Sum(in[:n])
	var out [28]byte
	base64.StdEncoding.Encode(out[:], sum[:])
	return string(out[:])
}

// tune sets TCP_NODELAY + keepalive on a TCPConn.
func tune(c *net.TCPConn) {
	_ = c.SetNoDelay(true)
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(keepAlivePeriod)
}

// forward copies src -> dst using pooled 64KB buffer for zero-lag streaming and line-rate speed.
func forward(dst, src *net.TCPConn, done chan<- struct{}) {
	defer func() {
		_ = dst.CloseWrite()
		done <- struct{}{}
	}()

	bPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bPtr)
	buf := *bPtr

	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			if _, ew := dst.Write(buf[:nr]); ew != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

func handleClient(client *net.TCPConn, targetAddr *net.TCPAddr) {
	defer client.Close()
	tune(client)

	// ── 1. Read HTTP Handshake with fast zero-alloc scan ─────────────────────
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
	leftover := headerBuf[headerEnd+4 : n]

	// ── 2. Extract Sec-WebSocket-Key ─────────────────────────────────────────
	var secKey []byte
	lines := bytes.Split(headerData, []byte("\r\n"))
	for _, line := range lines {
		if len(line) > 18 && bytes.EqualFold(line[:18], []byte("sec-websocket-key:")) {
			secKey = bytes.TrimSpace(line[18:])
			break
		}
	}

	// ── 3. Send 101 Switching Protocols IMMEDIATELY ─────────────────────────
	var resp bytes.Buffer
	resp.Grow(512)
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	resp.WriteString("Upgrade: websocket\r\n")
	resp.WriteString("Connection: Upgrade\r\n")
	if len(secKey) > 0 {
		resp.WriteString("Sec-WebSocket-Accept: ")
		resp.WriteString(acceptKey(secKey))
		resp.WriteString("\r\n")
	}
	resp.WriteString("X-Server-Info: ")
	resp.WriteString(serverBanner())
	resp.WriteString("\r\n")
	fmt.Fprintf(&resp, "X-Server-Uptime: %.0fs\r\n\r\n", time.Since(startTime).Seconds())

	if _, err := client.Write(resp.Bytes()); err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{}) // clear deadline — streaming phase is unbounded

	// ── 4. Connect to upstream SSH (pre-resolved target TCP address) ─────────
	upstream, err := net.DialTCP("tcp", nil, targetAddr)
	if err != nil {
		log.Printf("dial %s: %v", targetAddr, err)
		return
	}
	defer upstream.Close()
	tune(upstream)

	// Send any pre-read leftover bytes to SSH immediately
	if len(leftover) > 0 {
		if _, err := upstream.Write(leftover); err != nil {
			return
		}
	}

	// ── 5. Full-duplex streaming with immediate teardown on close ───────────
	done := make(chan struct{}, 2)
	go forward(upstream, client, done)
	go forward(client, upstream, done)

	// As soon as EITHER direction closes, unblock and exit.
	// Defers then immediately close both TCP sockets, unblocking the sibling goroutine.
	<-done
}

func main() {
	listen   := flag.String("listen",    "0.0.0.0:80",    "listen address")
	target   := flag.String("target",   "127.0.0.1:22",  "upstream SSH address")
	maxConns := flag.Int("max-conns",   1024,             "max concurrent connections")
	flag.Parse()

	// Graceful shutdown on SIGINT / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	listenAddr, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}

	targetAddr, err := net.ResolveTCPAddr("tcp", *target)
	if err != nil {
		log.Fatalf("resolve target %s: %v", *target, err)
	}

	ln, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatalf("bind %s: %v", *listen, err)
	}
	go func() { <-ctx.Done(); ln.Close() }()

	log.Printf("[WS-ePRO Go] %s -> %s (Immediate-101 + High-Throughput Buffer, max-conns=%d)", *listen, *target, *maxConns)
	log.Printf("[WS-ePRO Go] %s", serverBanner())

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
			handleClient(c, targetAddr)
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
