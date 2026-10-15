package main

// muxproto: a small multiplexed, encrypted stream protocol carried over one
// long-lived "WebSocket" (raw bytes after the 101) through a Cloudflare bug host.
//
// This file is shared verbatim between the Windows client (package tunnel) and
// the GitHub Actions node (package main, muxproto.go); only the package line
// differs. It uses the standard library only so the node can keep building
// single-file binaries without a go.mod.
//
// Wire format
//
//	prelude  (client -> server, plaintext): "MUX1" + 16-byte salt
//	record   : [len uint16 BE][AES-256-GCM(frame)]   len = ciphertext length incl. tag
//	frame    : [type uint8][stream uint32 BE][payload]
//
// Keys: sha256(psk | salt | "c2s") and sha256(psk | salt | "s2c"); nonce is a
// per-direction 64-bit counter, so a key is never reused across sessions.
//
// Frames
//
//	OPEN   client->server  payload = port(2) hostLen(1) host [initial data]
//	DATA   both           payload = bytes
//	FIN    both           half-close: no more DATA from the sender
//	RST    both           abort the stream
//	WINDOW both           payload = uint32 bytes the receiver consumed (flow credit)
//	PING   both           payload = 8 bytes (sender timestamp); peer echoes as PONG
//	PONG   both
//	DNS    client->server payload = raw DNS message; stream id = query id
//	DNSR   server->client payload = raw DNS reply;   stream id = query id
//
// A stream is opened without waiting for a confirmation: the first DATA frames
// follow OPEN immediately, so a new TCP connection costs no extra round trip.
// The server answers with RST if the target cannot be reached.

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	muxMagic       = "MUX1"
	muxSaltLen     = 16
	muxFrameHdr    = 5
	muxMaxPayload  = 32 * 1024
	muxMaxRecord   = muxFrameHdr + muxMaxPayload + 16
	muxWindow      = 4 << 20 // per-stream receive window (bytes)
	muxWindowDelta = muxWindow / 4

	muxOpen     = 0x01
	muxData     = 0x02
	muxFin      = 0x03
	muxRst      = 0x04
	muxWindowUp = 0x05
	muxPing     = 0x06
	muxPong     = 0x07
	muxDNS      = 0x08
	muxDNSReply = 0x09
)

var (
	errMuxClosed   = errors.New("mux: session closed")
	errMuxReset    = errors.New("mux: stream reset by peer")
	errMuxBadMagic = errors.New("mux: bad prelude")
	errMuxTimeout  = &muxTimeoutError{}
)

type muxTimeoutError struct{}

func (*muxTimeoutError) Error() string   { return "mux: i/o timeout" }
func (*muxTimeoutError) Timeout() bool   { return true }
func (*muxTimeoutError) Temporary() bool { return true }

// ── crypto ───────────────────────────────────────────────────────────────────

type muxCipher struct {
	aead  cipher.AEAD
	nonce [12]byte
	ctr   uint64
}

func newMuxCipher(psk, salt []byte, dir string) (*muxCipher, error) {
	h := sha256.New()
	h.Write(psk)
	h.Write(salt)
	h.Write([]byte(dir))
	block, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &muxCipher{aead: aead}, nil
}

func (c *muxCipher) next() []byte {
	c.ctr++
	binary.BigEndian.PutUint64(c.nonce[4:], c.ctr)
	return c.nonce[:]
}

// ── link: framed, encrypted records over a net.Conn ──────────────────────────

type muxLink struct {
	conn net.Conn
	r    *bufio.Reader
	enc  *muxCipher
	dec  *muxCipher

	wmu  sync.Mutex
	wbuf []byte // 2 + muxMaxRecord
	rbuf []byte // muxMaxRecord
	pbuf []byte // decrypted frame
}

func newMuxLink(conn net.Conn, psk, salt []byte, isClient bool) (*muxLink, error) {
	encDir, decDir := "c2s", "s2c"
	if !isClient {
		encDir, decDir = "s2c", "c2s"
	}
	enc, err := newMuxCipher(psk, salt, encDir)
	if err != nil {
		return nil, err
	}
	dec, err := newMuxCipher(psk, salt, decDir)
	if err != nil {
		return nil, err
	}
	return &muxLink{
		conn: conn,
		r:    bufio.NewReaderSize(conn, 64*1024),
		enc:  enc,
		dec:  dec,
		wbuf: make([]byte, 2+muxMaxRecord),
		rbuf: make([]byte, muxMaxRecord),
		pbuf: make([]byte, muxFrameHdr+muxMaxPayload),
	}, nil
}

// writeFrame encrypts one frame and writes it as a single record.
func (l *muxLink) writeFrame(typ byte, id uint32, payload []byte) error {
	if len(payload) > muxMaxPayload {
		return fmt.Errorf("mux: payload %d exceeds max %d", len(payload), muxMaxPayload)
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()

	plain := l.pbuf[:muxFrameHdr+len(payload)]
	plain[0] = typ
	binary.BigEndian.PutUint32(plain[1:5], id)
	copy(plain[5:], payload)

	ctLen := len(plain) + l.enc.aead.Overhead()
	binary.BigEndian.PutUint16(l.wbuf[:2], uint16(ctLen))
	l.enc.aead.Seal(l.wbuf[2:2], l.enc.next(), plain, l.wbuf[:2])
	_, err := l.conn.Write(l.wbuf[:2+ctLen])
	return err
}

// readFrame reads and decrypts one record. The payload slice is only valid
// until the next call.
func (l *muxLink) readFrame() (typ byte, id uint32, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(l.r, hdr[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < l.dec.aead.Overhead()+muxFrameHdr || n > muxMaxRecord {
		err = fmt.Errorf("mux: bad record length %d", n)
		return
	}
	if _, err = io.ReadFull(l.r, l.rbuf[:n]); err != nil {
		return
	}
	plain, oerr := l.dec.aead.Open(l.rbuf[:0], l.dec.next(), l.rbuf[:n], hdr[:])
	if oerr != nil {
		err = fmt.Errorf("mux: decrypt failed (wrong key?)")
		return
	}
	typ = plain[0]
	id = binary.BigEndian.Uint32(plain[1:5])
	payload = plain[5:]
	return
}

// ── session ──────────────────────────────────────────────────────────────────

// muxOpenHandler is invoked on the server for every OPEN. It must not block the
// read loop: the session calls it in its own goroutine.
type muxOpenHandler func(s *muxStream, host string, port int, initial []byte)

// muxDNSHandler answers a raw DNS query on the server.
type muxDNSHandler func(query []byte) ([]byte, error)

type muxSession struct {
	link     *muxLink
	isClient bool

	mu      sync.Mutex
	streams map[uint32]*muxStream
	nextID  uint32

	dnsMu      sync.Mutex
	dnsWaiters map[uint32]chan []byte
	dnsNext    uint32

	onOpen  muxOpenHandler
	onDNS   muxDNSHandler
	onClose func(err error)

	closed   atomic.Bool
	closeErr error
	done     chan struct{}

	lastRecv atomic.Int64 // unix nanos of the last frame read
	rttMs    atomic.Int64
	pongCh   chan int64
}

func newMuxSession(link *muxLink, isClient bool) *muxSession {
	s := &muxSession{
		link:       link,
		isClient:   isClient,
		streams:    make(map[uint32]*muxStream),
		dnsWaiters: make(map[uint32]chan []byte),
		done:       make(chan struct{}),
		pongCh:     make(chan int64, 4),
	}
	if isClient {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	s.lastRecv.Store(time.Now().UnixNano())
	return s
}

// muxClientHandshake writes the prelude and returns a client session.
func muxClientHandshake(conn net.Conn, psk []byte) (*muxSession, error) {
	salt := make([]byte, muxSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	prelude := make([]byte, 0, 4+muxSaltLen)
	prelude = append(prelude, muxMagic...)
	prelude = append(prelude, salt...)
	if _, err := conn.Write(prelude); err != nil {
		return nil, err
	}
	link, err := newMuxLink(conn, psk, salt, true)
	if err != nil {
		return nil, err
	}
	return newMuxSession(link, true), nil
}

// muxServerHandshake reads the prelude and returns a server session. The
// caller must have already answered the HTTP 101.
func muxServerHandshake(conn net.Conn, psk []byte) (*muxSession, error) {
	var prelude [4 + muxSaltLen]byte
	if _, err := io.ReadFull(conn, prelude[:]); err != nil {
		return nil, err
	}
	if string(prelude[:4]) != muxMagic {
		return nil, errMuxBadMagic
	}
	link, err := newMuxLink(conn, psk, prelude[4:], false)
	if err != nil {
		return nil, err
	}
	return newMuxSession(link, false), nil
}

func (s *muxSession) Closed() bool { return s.closed.Load() }

func (s *muxSession) RTTms() int64 { return s.rttMs.Load() }

func (s *muxSession) LastRecv() time.Time { return time.Unix(0, s.lastRecv.Load()) }

func (s *muxSession) ActiveStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// Close tears the session down; every stream unblocks with err.
func (s *muxSession) Close() error { return s.closeWith(errMuxClosed) }

func (s *muxSession) closeWith(err error) error {
	if s.closed.Swap(true) {
		return nil
	}
	s.closeErr = err
	_ = s.link.conn.Close()
	close(s.done)

	s.mu.Lock()
	streams := make([]*muxStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*muxStream)
	s.mu.Unlock()
	for _, st := range streams {
		st.abort(err)
	}

	s.dnsMu.Lock()
	for id, ch := range s.dnsWaiters {
		close(ch)
		delete(s.dnsWaiters, id)
	}
	s.dnsMu.Unlock()

	if s.onClose != nil {
		go s.onClose(err)
	}
	return nil
}

// Ping sends a PING and waits for the matching PONG.
func (s *muxSession) Ping(timeout time.Duration) (time.Duration, error) {
	var payload [8]byte
	t0 := time.Now()
	binary.BigEndian.PutUint64(payload[:], uint64(t0.UnixNano()))
	// Drain any stale pongs.
	for {
		select {
		case <-s.pongCh:
			continue
		default:
		}
		break
	}
	if err := s.link.writeFrame(muxPing, 0, payload[:]); err != nil {
		return 0, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case ts := <-s.pongCh:
			if ts != t0.UnixNano() {
				continue
			}
			rtt := time.Since(t0)
			s.rttMs.Store(rtt.Milliseconds())
			return rtt, nil
		case <-timer.C:
			return 0, errMuxTimeout
		case <-s.done:
			return 0, errMuxClosed
		}
	}
}

// OpenStream opens a stream to host:port. It returns immediately; the peer
// resets the stream if the target is unreachable.
func (s *muxSession) OpenStream(host string, port int, initial []byte) (*muxStream, error) {
	if s.closed.Load() {
		return nil, errMuxClosed
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("mux: host too long")
	}
	payload := make([]byte, 0, 3+len(host)+len(initial))
	payload = binary.BigEndian.AppendUint16(payload, uint16(port))
	payload = append(payload, byte(len(host)))
	payload = append(payload, host...)
	room := muxMaxPayload - len(payload)
	if room < 0 {
		room = 0
	}
	first := initial
	if len(first) > room {
		first = initial[:room]
	}
	payload = append(payload, first...)

	s.mu.Lock()
	id := s.nextID
	s.nextID += 2
	st := newMuxStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.link.writeFrame(muxOpen, id, payload); err != nil {
		s.removeStream(id)
		return nil, err
	}
	if len(initial) > len(first) {
		if _, err := st.Write(initial[len(first):]); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// QueryDNS sends one raw DNS message and waits for the reply.
func (s *muxSession) QueryDNS(query []byte, timeout time.Duration) ([]byte, error) {
	if s.closed.Load() {
		return nil, errMuxClosed
	}
	if len(query) > muxMaxPayload {
		return nil, fmt.Errorf("mux: dns query too large")
	}
	ch := make(chan []byte, 1)
	s.dnsMu.Lock()
	s.dnsNext++
	id := s.dnsNext
	s.dnsWaiters[id] = ch
	s.dnsMu.Unlock()

	cleanup := func() {
		s.dnsMu.Lock()
		delete(s.dnsWaiters, id)
		s.dnsMu.Unlock()
	}
	if err := s.link.writeFrame(muxDNS, id, query); err != nil {
		cleanup()
		return nil, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errMuxClosed
		}
		return resp, nil
	case <-timer.C:
		cleanup()
		return nil, errMuxTimeout
	case <-s.done:
		return nil, errMuxClosed
	}
}

func (s *muxSession) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *muxSession) getStream(id uint32) *muxStream {
	s.mu.Lock()
	st := s.streams[id]
	s.mu.Unlock()
	return st
}

// Serve runs the read loop until the link fails. It always returns a non-nil
// error and closes the session.
func (s *muxSession) Serve() error {
	for {
		typ, id, payload, err := s.link.readFrame()
		if err != nil {
			s.closeWith(err)
			return err
		}
		s.lastRecv.Store(time.Now().UnixNano())

		switch typ {
		case muxOpen:
			if s.isClient || s.onOpen == nil {
				_ = s.link.writeFrame(muxRst, id, nil)
				continue
			}
			if len(payload) < 3 {
				_ = s.link.writeFrame(muxRst, id, nil)
				continue
			}
			port := int(binary.BigEndian.Uint16(payload[:2]))
			hl := int(payload[2])
			if len(payload) < 3+hl {
				_ = s.link.writeFrame(muxRst, id, nil)
				continue
			}
			host := string(payload[3 : 3+hl])
			initial := append([]byte(nil), payload[3+hl:]...)
			st := newMuxStream(s, id)
			s.mu.Lock()
			s.streams[id] = st
			s.mu.Unlock()
			go s.onOpen(st, host, port, initial)

		case muxData:
			if st := s.getStream(id); st != nil {
				st.deliver(payload)
			}

		case muxFin:
			if st := s.getStream(id); st != nil {
				st.peerFin()
			}

		case muxRst:
			if st := s.getStream(id); st != nil {
				s.removeStream(id)
				st.abort(errMuxReset)
			}

		case muxWindowUp:
			if len(payload) >= 4 {
				if st := s.getStream(id); st != nil {
					st.addCredit(int64(binary.BigEndian.Uint32(payload[:4])))
				}
			}

		case muxPing:
			_ = s.link.writeFrame(muxPong, id, payload)

		case muxPong:
			if len(payload) >= 8 {
				ts := int64(binary.BigEndian.Uint64(payload[:8]))
				select {
				case s.pongCh <- ts:
				default:
				}
			}

		case muxDNS:
			if s.isClient || s.onDNS == nil {
				continue
			}
			q := append([]byte(nil), payload...)
			go func(id uint32, q []byte) {
				resp, err := s.onDNS(q)
				if err != nil || len(resp) == 0 || len(resp) > muxMaxPayload {
					return
				}
				_ = s.link.writeFrame(muxDNSReply, id, resp)
			}(id, q)

		case muxDNSReply:
			s.dnsMu.Lock()
			ch := s.dnsWaiters[id]
			delete(s.dnsWaiters, id)
			s.dnsMu.Unlock()
			if ch != nil {
				ch <- append([]byte(nil), payload...)
			}
		}
	}
}

// ── stream: net.Conn over the session ────────────────────────────────────────

type muxStream struct {
	sess *muxSession
	id   uint32

	mu   sync.Mutex
	cond *sync.Cond

	recv     [][]byte // queued chunks
	recvHead int      // offset into recv[0]
	unacked  int64    // bytes consumed but not yet credited back
	finRecv  bool
	finSent  bool
	err      error // set on abort/reset

	credit int64 // bytes we may still send

	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
}

func newMuxStream(s *muxSession, id uint32) *muxStream {
	st := &muxStream{sess: s, id: id, credit: muxWindow}
	st.cond = sync.NewCond(&st.mu)
	return st
}

func (st *muxStream) deliver(p []byte) {
	buf := append([]byte(nil), p...)
	st.mu.Lock()
	if st.err == nil && !st.closed {
		st.recv = append(st.recv, buf)
	}
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *muxStream) peerFin() {
	st.mu.Lock()
	st.finRecv = true
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *muxStream) addCredit(n int64) {
	st.mu.Lock()
	st.credit += n
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *muxStream) abort(err error) {
	st.mu.Lock()
	if st.err == nil {
		st.err = err
	}
	st.recv = nil
	st.mu.Unlock()
	st.cond.Broadcast()
}

// waitLocked blocks on the condition until the deadline passes. The caller
// holds st.mu. Returns false if the deadline expired.
func (st *muxStream) waitLocked(deadline time.Time) bool {
	if deadline.IsZero() {
		st.cond.Wait()
		return true
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	t := time.AfterFunc(remaining, st.cond.Broadcast)
	st.cond.Wait()
	t.Stop()
	return time.Now().Before(deadline)
}

func (st *muxStream) Read(b []byte) (int, error) {
	st.mu.Lock()
	for {
		if len(st.recv) > 0 {
			chunk := st.recv[0]
			n := copy(b, chunk[st.recvHead:])
			st.recvHead += n
			if st.recvHead >= len(chunk) {
				st.recv = st.recv[1:]
				st.recvHead = 0
			}
			st.unacked += int64(n)
			var credit int64
			if st.unacked >= muxWindowDelta {
				credit = st.unacked
				st.unacked = 0
			}
			st.mu.Unlock()
			if credit > 0 {
				var p [4]byte
				binary.BigEndian.PutUint32(p[:], uint32(credit))
				_ = st.sess.link.writeFrame(muxWindowUp, st.id, p[:])
			}
			return n, nil
		}
		if st.err != nil {
			err := st.err
			st.mu.Unlock()
			return 0, err
		}
		if st.finRecv || st.closed {
			st.mu.Unlock()
			return 0, io.EOF
		}
		if !st.waitLocked(st.readDeadline) {
			st.mu.Unlock()
			return 0, errMuxTimeout
		}
	}
}

func (st *muxStream) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		st.mu.Lock()
		for st.credit <= 0 && st.err == nil && !st.finSent && !st.closed {
			if !st.waitLocked(st.writeDeadline) {
				st.mu.Unlock()
				return total, errMuxTimeout
			}
		}
		if st.err != nil {
			err := st.err
			st.mu.Unlock()
			return total, err
		}
		if st.finSent || st.closed {
			st.mu.Unlock()
			return total, net.ErrClosed
		}
		n := len(b)
		if int64(n) > st.credit {
			n = int(st.credit)
		}
		if n > muxMaxPayload {
			n = muxMaxPayload
		}
		st.credit -= int64(n)
		st.mu.Unlock()

		if err := st.sess.link.writeFrame(muxData, st.id, b[:n]); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

// CloseWrite sends FIN: no more data from this side.
func (st *muxStream) CloseWrite() error {
	st.mu.Lock()
	if st.finSent || st.closed || st.err != nil {
		st.mu.Unlock()
		return nil
	}
	st.finSent = true
	st.mu.Unlock()
	st.cond.Broadcast()
	return st.sess.link.writeFrame(muxFin, st.id, nil)
}

// Close releases the stream. If the peer has not finished, RST tells it so.
func (st *muxStream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	needRst := st.err == nil && !(st.finSent && st.finRecv)
	st.recv = nil
	st.mu.Unlock()
	st.cond.Broadcast()
	st.sess.removeStream(st.id)
	if needRst {
		return st.sess.link.writeFrame(muxRst, st.id, nil)
	}
	return nil
}

func (st *muxStream) LocalAddr() net.Addr  { return st.sess.link.conn.LocalAddr() }
func (st *muxStream) RemoteAddr() net.Addr { return st.sess.link.conn.RemoteAddr() }

func (st *muxStream) SetDeadline(t time.Time) error {
	st.mu.Lock()
	st.readDeadline, st.writeDeadline = t, t
	st.mu.Unlock()
	st.cond.Broadcast()
	return nil
}

func (st *muxStream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.readDeadline = t
	st.mu.Unlock()
	st.cond.Broadcast()
	return nil
}

func (st *muxStream) SetWriteDeadline(t time.Time) error {
	st.mu.Lock()
	st.writeDeadline = t
	st.mu.Unlock()
	st.cond.Broadcast()
	return nil
}

// ── server-side stream handling ──────────────────────────────────────────────

// muxServeStream dials host:port and pipes it to the stream. Used by the node.
func muxServeStream(st *muxStream, host string, port int, initial []byte, d *net.Dialer) {
	if d == nil {
		d = &net.Dialer{Timeout: 10 * time.Second}
	}
	target, err := d.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		_ = st.Close()
		return
	}
	tc, _ := target.(*net.TCPConn)
	if tc != nil {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	if len(initial) > 0 {
		if _, err := target.Write(initial); err != nil {
			_ = target.Close()
			_ = st.Close()
			return
		}
	}

	done := make(chan struct{}, 2)
	// stream -> target
	go func() {
		buf := make([]byte, muxMaxPayload)
		for {
			n, rerr := st.Read(buf)
			if n > 0 {
				if _, werr := target.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				if rerr == io.EOF && tc != nil {
					_ = tc.CloseWrite()
					done <- struct{}{}
					return
				}
				break
			}
		}
		_ = target.Close()
		done <- struct{}{}
	}()
	// target -> stream
	go func() {
		buf := make([]byte, muxMaxPayload)
		for {
			n, rerr := target.Read(buf)
			if n > 0 {
				if _, werr := st.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				if rerr == io.EOF {
					_ = st.CloseWrite()
					done <- struct{}{}
					return
				}
				break
			}
		}
		_ = st.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = target.Close()
	_ = st.Close()
}

// muxReadPSKFile loads a pre-shared key from a file, trimming whitespace.
func muxReadPSKFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return nil, errors.New("mux: empty key file")
	}
	return b, nil
}
