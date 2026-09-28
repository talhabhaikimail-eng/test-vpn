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

func computeAcceptKey(secKey string) string {
	h := sha1.New()
	h.Write([]byte(strings.TrimSpace(secKey) + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func forward(dst io.Writer, src io.Reader, done chan struct{}) {
	buf := make([]byte, 32768)
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
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	done <- struct{}{}
}

func handleClient(clientConn net.Conn, targetAddr string) {
	defer clientConn.Close()

	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
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

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	if tc, ok := targetConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	done := make(chan struct{}, 2)

	// Stream from reader (which contains any buffered HTTP leftover bytes + clientConn) to targetConn
	go forward(targetConn, reader, done)

	// Stream directly from targetConn (SSH) to clientConn
	go forward(clientConn, targetConn, done)

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
	fmt.Printf("[WS-ePRO Go] Listening on 0.0.0.0:%s -> %s (Immediate-Flush Mode)\n", listenPort, targetAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(clientConn, targetAddr)
	}
}
