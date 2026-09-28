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
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// computeAcceptKey calculates the Sec-WebSocket-Accept header value
func computeAcceptKey(secKey string) string {
	h := sha1.New()
	h.Write([]byte(strings.TrimSpace(secKey) + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func handleClient(clientConn net.Conn, targetAddr string) {
	defer clientConn.Close()

	// In Go, TCPConn sets TCP_NODELAY = true automatically
	reader := bufio.NewReaderSize(clientConn, 65536)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	secKey := req.Header.Get("Sec-WebSocket-Key")

	// Construct HTTP 101 Switching Protocols response
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

	// Connect to local OpenSSH daemon
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Forward any buffered leftover bytes from the HTTP request phase
	if reader.Buffered() > 0 {
		buffered := make([]byte, reader.Buffered())
		if _, err := io.ReadFull(reader, buffered); err == nil {
			targetConn.Write(buffered)
		}
	}

	// Full-duplex zero-copy forwarding using Linux splice(2) via io.Copy
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, targetConn)
		if cc, ok := clientConn.(*net.TCPConn); ok {
			cc.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
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

	listener, err := net.Listen("tcp", "0.0.0.0:"+listenPort)
	if err != nil {
		fmt.Printf("[WS-ePRO Go] Failed to bind :%s: %v\n", listenPort, err)
		os.Exit(1)
	}
	defer listener.Close()

	targetAddr := "127.0.0.1:" + targetPort
	fmt.Printf("[WS-ePRO Go] Listening on 0.0.0.0:%s -> %s (Zero-Copy Splice Mode)\n", listenPort, targetAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(clientConn, targetAddr)
	}
}
