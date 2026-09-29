package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// 32KB pool — large enough for SSH bulk transfers, reused across connections.
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func computeAcceptKey(secKey string) string {
	h := sha1.New()
	h.Write([]byte(strings.TrimSpace(secKey) + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// pipe copies src -> dst until EOF or error, then half-closes the destination.
// Uses raw TCPConn reads — no bufio wrapper in the forwarding hot path.
func pipe(dst, src *net.TCPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr
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
	// Half-close: let the peer drain its remaining data instead of RST.
	dst.CloseWrite()
}

func handleClient(conn net.Conn, targetAddr string) {
	defer conn.Close()

	clientConn := conn.(*net.TCPConn)
	clientConn.SetNoDelay(true)         // Flush every write immediately — no Nagle
	clientConn.SetKeepAlive(true)
	clientConn.SetKeepAlivePeriod(10e9) // 10s OS keepalive

	// bufio.Reader is ONLY used to parse HTTP upgrade headers.
	// It is NOT passed into the forwarding path.
	hdrReader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(hdrReader)
	if err != nil {
		return
	}

	secKey := req.Header.Get("Sec-WebSocket-Key")

	var resp bytes.Buffer
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	resp.WriteString("Upgrade: websocket\r\n")
	resp.WriteString("Connection: Upgrade\r\n")
	if secKey != "" {
		resp.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", computeAcceptKey(secKey)))
	}
	resp.WriteString("\r\n")

	if _, err := clientConn.Write(resp.Bytes()); err != nil {
		return
	}

	raw, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		return
	}
	targetConn, err := net.DialTCP("tcp", nil, raw)
	if err != nil {
		return
	}
	defer targetConn.Close()
	targetConn.SetNoDelay(true)    // Critical: no Nagle on SSH side either
	targetConn.SetKeepAlive(true)
	targetConn.SetKeepAlivePeriod(10e9)

	// Flush any bytes the bufio.Reader already pulled off the wire.
	// Skipping this loses the first chunk of the SSH handshake.
	if n := hdrReader.Buffered(); n > 0 {
		leftover := make([]byte, n)
		io.ReadFull(hdrReader, leftover)
		if _, err := targetConn.Write(leftover); err != nil {
			return
		}
	}
	// hdrReader discarded here — raw TCPConn from this point forward.

	var wg sync.WaitGroup
	wg.Add(2)
	go pipe(targetConn, clientConn, &wg) // client -> SSH
	go pipe(clientConn, targetConn, &wg) // SSH -> client
	wg.Wait()
}

func main() {
	listenPort := "80"
	targetPort := "22"

	if len(os.Args) > 1 {
		listenPort = os.Args[1]
	}
	if len(os.Args) > 2 {
		targetPort = os.Args[2]
	}

	targetAddr := "127.0.0.1:" + targetPort

	listener, err := net.Listen("tcp", "0.0.0.0:"+listenPort)
	if err != nil {
		fmt.Printf("[WS-ePRO Go] Failed to bind :%s: %v\n", listenPort, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("[WS-ePRO Go] Listening on 0.0.0.0:%s -> %s (zero-buffer mode)\n", listenPort, targetAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, targetAddr)
	}
}
