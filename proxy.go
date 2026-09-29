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

func computeAcceptKey(secKey string) string {
	h := sha1.New()
	h.Write([]byte(strings.TrimSpace(secKey) + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// splice copies src -> dst using io.Copy.
// On Linux, Go's net.TCPConn.ReadFrom triggers splice(2) when src is also a
// *net.TCPConn — data moves entirely in kernel space, zero userspace copies.
// This is the single biggest throughput multiplier for a TCP relay.
func splice(dst, src *net.TCPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dst, src) //nolint — error intentionally ignored; connection drop is normal exit
	dst.CloseWrite()  // half-close so peer can drain its remaining data
}

func handleClient(conn net.Conn, targetAddr string) {
	defer conn.Close()

	clientConn := conn.(*net.TCPConn)
	clientConn.SetNoDelay(true)
	clientConn.SetKeepAlive(true)
	clientConn.SetKeepAlivePeriod(10e9) // 10s

	// bufio.Reader used ONLY for HTTP header parsing — never in the data path.
	hdrBuf := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(hdrBuf)
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

	rawAddr, err2 := net.ResolveTCPAddr("tcp", targetAddr)
	if err2 != nil {
		return
	}
	targetConn, err2 := net.DialTCP("tcp", nil, rawAddr)
	if err2 != nil {
		return
	}
	defer targetConn.Close()
	targetConn.SetNoDelay(true)
	targetConn.SetKeepAlive(true)
	targetConn.SetKeepAlivePeriod(10e9)

	// Drain bytes the bufio reader pre-fetched beyond the HTTP headers.
	// Must reach the SSH target before the splice loop starts, or the
	// SSH handshake will be corrupted.
	if n := hdrBuf.Buffered(); n > 0 {
		leftover := make([]byte, n)
		io.ReadFull(hdrBuf, leftover)
		if _, err := targetConn.Write(leftover); err != nil {
			return
		}
	}
	// hdrBuf is done. Raw *net.TCPConn from here — splice path active.

	var wg sync.WaitGroup
	wg.Add(2)
	go splice(targetConn, clientConn, &wg) // client  -> SSH  (splice)
	go splice(clientConn, targetConn, &wg) // SSH -> client  (splice)
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
	fmt.Printf("[WS-ePRO Go] Listening on 0.0.0.0:%s -> %s (splice/zero-copy mode)\n", listenPort, targetAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, targetAddr)
	}
}
