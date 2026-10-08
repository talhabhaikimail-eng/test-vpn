package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
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
	wsGUID           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxHeaderBytes   = 8192
	handshakeTimeout = 5 * time.Second
	keepAlivePeriod  = 15 * time.Second
	maxUptimeHours   = 6
	rawBufSize       = 32768 // 32KB chunk for wire streaming
	maxFrameSize     = 65535

	// Frame flags
	flagRaw        = 0x00
	flagCompressed = 0x01
	flagHeartbeat  = 0x02
)

var (
	startTime  = time.Now()
	pktZone    = time.FixedZone("PKT", 5*60*60)
	startedStr = startTime.In(pktZone).Format("02 Jan 2006 15:04 PKT")
	nodeName   = "Server UDP (Compressed)"

	rawPool = sync.Pool{
		New: func() any {
			b := make([]byte, rawBufSize)
			return &b
		},
	}

	compPool = sync.Pool{
		New: func() any {
			b := make([]byte, rawBufSize+512)
			return &b
		},
	}
)

func serverBanner() string {
	elapsed := time.Since(startTime)
	remaining := time.Duration(maxUptimeHours)*time.Hour - elapsed
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("[%s] Made By Talha \u2764 | Started: %s | Restarts in %dh %02dm | Adaptive-Flate Enabled",
		nodeName, startedStr, int(remaining.Hours()), int(remaining.Minutes())%60)
}

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

func tune(c *net.TCPConn) {
	_ = c.SetNoDelay(true)
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(keepAlivePeriod)
}

// writeFramed compresses data with BestSpeed flate and sends it with a 3-byte header.
func writeFramed(w io.Writer, data []byte, compBuf []byte) error {
	if len(data) == 0 {
		return nil
	}

	// Try compression
	var b bytes.Buffer
	b.Grow(len(data))
	fw, err := flate.NewWriter(&b, flate.BestSpeed)
	if err == nil {
		_, _ = fw.Write(data)
		_ = fw.Close()
	}

	compressed := b.Bytes()
	header := make([]byte, 3)

	// Only send compressed if it actually saved space
	if len(compressed) > 0 && len(compressed) < len(data) {
		header[0] = flagCompressed
		binary.BigEndian.PutUint16(header[1:3], uint16(len(compressed)))
		if _, err := w.Write(header); err != nil {
			return err
		}
		_, err = w.Write(compressed)
		return err
	}

	// Otherwise send raw
	header[0] = flagRaw
	binary.BigEndian.PutUint16(header[1:3], uint16(len(data)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// readFramed reads one frame, decompresses if necessary, and writes raw bytes to dst.
func readFramed(r io.Reader, dst io.Writer, compBuf []byte) error {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}

	flag := header[0]
	length := binary.BigEndian.Uint16(header[1:3])
	if length == 0 {
		return nil
	}

	var payload []byte
	if int(length) <= len(compBuf) {
		payload = compBuf[:length]
	} else {
		payload = make([]byte, length)
	}

	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}

	switch flag {
	case flagHeartbeat:
		return nil // Ignore heartbeat ping

	case flagRaw:
		_, err := dst.Write(payload)
		return err

	case flagCompressed:
		fr := flate.NewReader(bytes.NewReader(payload))
		defer fr.Close()
		_, err := io.Copy(dst, fr)
		return err

	default:
		// Unknown flag, pass through
		_, err := dst.Write(payload)
		return err
	}
}

// clientToSSH reads compressed/framed packets from client and writes raw bytes to SSH.
func clientToSSH(client *net.TCPConn, ssh *net.TCPConn, done chan<- struct{}) {
	defer func() {
		_ = ssh.CloseWrite()
		done <- struct{}{}
	}()

	compPtr := compPool.Get().(*[]byte)
	defer compPool.Put(compPtr)
	compBuf := *compPtr

	for {
		if err := readFramed(client, ssh, compBuf); err != nil {
			break
		}
	}
}

// sshToClient reads raw bytes from SSH, compresses them with flate, and sends framed packets to client.
func sshToClient(ssh *net.TCPConn, client *net.TCPConn, done chan<- struct{}) {
	defer func() {
		_ = client.CloseWrite()
		done <- struct{}{}
	}()

	rawPtr := rawPool.Get().(*[]byte)
	defer rawPool.Put(rawPtr)
	rawBuf := *rawPtr

	compPtr := compPool.Get().(*[]byte)
	defer compPool.Put(compPtr)
	compBuf := *compPtr

	for {
		nr, err := ssh.Read(rawBuf)
		if nr > 0 {
			if ew := writeFramed(client, rawBuf[:nr], compBuf); ew != nil {
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

	// ── 1. Fast zero-alloc HTTP handshake scan ──────────────────────────────
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

	// ── 3. Send 101 Switching Protocols + UDP-Compressed Header ─────────────
	var resp bytes.Buffer
	resp.Grow(512)
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	resp.WriteString("Upgrade: websocket\r\n")
	resp.WriteString("Connection: Upgrade\r\n")
	resp.WriteString("X-Proxy-Protocol: UDP-Compressed-v1\r\n")
	if len(secKey) > 0 {
		resp.WriteString("Sec-WebSocket-Accept: ")
		resp.WriteString(acceptKey(secKey))
		resp.WriteString("\r\n")
	} else {
		resp.WriteString("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n")
	}
	resp.WriteString("X-Server-Info: ")
	resp.WriteString(serverBanner())
	resp.WriteString("\r\n")
	fmt.Fprintf(&resp, "X-Server-Uptime: %.0fs\r\n\r\n", time.Since(startTime).Seconds())

	if _, err := client.Write(resp.Bytes()); err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	// ── 4. Dial upstream SSH (127.0.0.1:22) ──────────────────────────────────
	upstream, err := net.DialTCP("tcp", nil, targetAddr)
	if err != nil {
		log.Printf("dial %s: %v", targetAddr, err)
		return
	}
	defer upstream.Close()
	tune(upstream)

	// If there were leftover bytes after \r\n\r\n, decode them as framed data
	if len(leftover) > 0 {
		compPtr := compPool.Get().(*[]byte)
		compBuf := *compPtr
		_ = readFramed(bytes.NewReader(leftover), upstream, compBuf)
		compPool.Put(compPtr)
	}

	// ── 5. Full-duplex streaming with immediate teardown ────────────────────
	done := make(chan struct{}, 2)
	go clientToSSH(client, upstream, done)
	go sshToClient(upstream, client, done)

	<-done
}

func main() {
	listen     := flag.String("listen",    "0.0.0.0:80",    "listen address")
	target     := flag.String("target",   "127.0.0.1:22",  "upstream SSH address")
	maxConns   := flag.Int("max-conns",   1024,             "max concurrent connections")
	serverName := flag.String("name",     "Server UDP (Compressed)", "server node display name")
	flag.Parse()
	nodeName = *serverName

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

	log.Printf("[UDP-Compressed Go] %s -> %s (Adaptive-Flate, max-conns=%d)", *listen, *target, *maxConns)
	log.Printf("[UDP-Compressed Go] %s", serverBanner())

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
