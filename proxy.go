
package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	wsGUID           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxHeaderBytes   = 16 << 10        // 16 KB — caps slowloris header floods
	handshakeTimeout = 10 * time.Second
	dialTimeout      = 2 * time.Second // fail fast against dead upstream
	keepAlivePeriod  = 15 * time.Second
	maxUptimeHours   = 6
)

var (
	startTime = time.Now()
	pktZone   = time.FixedZone("PKT", 5*60*60) // built once, reused

	// Static prefix of the 101 response — precomputed once at load.
	resp101Prefix = []byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n")
)

// serverBanner returns the live countdown header value, PKT-localised.
func serverBanner() string {
	elapsed := time.Since(startTime)
	remaining := time.Duration(maxUptimeHours)*time.Hour - elapsed
	if remaining < 0 {
		remaining = 0
	}
	started := startTime.In(pktZone).Format("02 Jan 2006 15:04 PKT")
	return fmt.Sprintf("Made By Talha \u2764 | Started: %s | Restarts in %dh %02dm",
		started, int(remaining.Hours()), int(remaining.Minutes())%60)
}

// acceptKey computes the Sec-WebSocket-Accept value into a stack array —
// 20 bytes -> exactly 28 base64 chars, no heap allocation.
func acceptKey(secKey string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(secKey) + wsGUID))
	var b [28]byte
	base64.StdEncoding.Encode(b[:], sum[:])
	return string(b[:])
}

// tune sets TCP_NODELAY + keepalive + QUICKACK on a TCPConn.
func tune(c *net.TCPConn) {
	_ = c.SetNoDelay(true)
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(keepAlivePeriod)
	
}

// pipe copies src -> dst. With both ends *net.TCPConn, io.Copy triggers
// splice(2) on Linux — zero userspace copies, kernel-space only.
func pipe(dst, src *net.TCPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
	_ = dst.CloseWrite() // half-close so the peer can drain its buffer
}

func handleClient(client *net.TCPConn, target string) {
	defer client.Close()
	tune(client)

	// ── Handshake phase ──────────────────────────────────────────────────────
	// Read deadline prevents slowloris (client connects but never sends).
	// LimitReader caps header size so we can't be OOM'd by a huge request.
	_ = client.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(io.LimitReader(client, maxHeaderBytes), 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		return // deadline hit or bad request — just drop it
	}
	secKey := req.Header.Get("Sec-WebSocket-Key")

	// ── Send 101 Switching Protocols BEFORE dialing upstream ────────────────
	// The client sees 101 immediately; the upstream dial no longer blocks
	// the perceived connect time. On dial failure we simply close — tunnel
	// clients auto-reconnect, so a clean 502 isn't worth the extra RTT.
	var resp []byte
	if secKey != "" {
		resp = []byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptKey(secKey) + "\r\n" +
			"X-Server-Info: " + serverBanner() + "\r\n" +
			fmt.Sprintf("X-Server-Uptime: %.0fs\r\n", time.Since(startTime).Seconds()) +
			"\r\n")
	} else {
		resp = append(append([]byte{}, resp101Prefix...),
			[]byte("X-Server-Info: "+serverBanner()+
				fmt.Sprintf("\r\nX-Server-Uptime: %.0fs\r\n\r\n", time.Since(startTime).Seconds()))...)
	}

	if _, err := client.Write(resp); err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{}) // clear deadline — data phase is unbounded

	// ── Dial upstream AFTER 101 ─────────────────────────────────────────────
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.Dial("tcp", target)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	upstream := c.(*net.TCPConn)
	defer upstream.Close()
	tune(upstream)

	// ── Drain bufio pre-read bytes ───────────────────────────────────────────
	// http.ReadRequest may have pulled bytes beyond the headers into br's
	// internal buffer. Flush them to upstream before starting splice.
	if n := br.Buffered(); n > 0 {
		if _, err := io.CopyN(upstream, br, int64(n)); err != nil {
			return
		}
	}
	// br is done — raw *net.TCPConn from here, splice path active.

	var wg sync.WaitGroup
	wg.Add(2)
	go pipe(upstream, client, &wg) // client  -> SSH
	go pipe(client, upstream, &wg) // SSH -> client
	wg.Wait()
}

func main() {
	listen := flag.String("listen", "0.0.0.0:80", "listen address")
	target := flag.String("target", "127.0.0.1:22", "upstream SSH address")
	maxConns := flag.Int("max-conns", 1024, "max concurrent connections")
	flag.Parse()

	// Graceful shutdown on SIGINT / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	addr, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.ListenTCP("tcp", addr) // ListenTCP -> AcceptTCP: no type assertion needed
	if err != nil {
		log.Fatalf("bind %s: %v", *listen, err)
	}
	go func() { <-ctx.Done(); ln.Close() }()

	log.Printf("[WS-ePRO Go] %s -> %s (splice/zero-copy, max-conns=%d)", *listen, *target, *maxConns)
	log.Printf("[WS-ePRO Go] %s", serverBanner())

	sem := make(chan struct{}, *maxConns) // semaphore caps concurrent goroutines
	var active sync.WaitGroup
	var backoff time.Duration

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break // clean shutdown
			}
			// Transient error (e.g. EMFILE — too many open files).
			// Back off exponentially instead of spinning the CPU at 100%.
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
		case sem <- struct{}{}: // slot acquired
		default:
			log.Printf("at capacity (%d), dropping %s", *maxConns, conn.RemoteAddr())
			conn.Close()
			continue
		}

		active.Add(1)
		go func(c *net.TCPConn) {
			defer active.Done()
			defer func() { <-sem }()
			handleClient(c, *target)
		}(conn)
	}

	// Drain active connections — up to 10 s before hard exit.
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
