package main

// muxproto: a small multiplexed, encrypted, *resumable* stream protocol carried
// over one long-lived "WebSocket" (raw bytes after the 101) through a Cloudflare
// bug host.
//
// This file is shared verbatim between the Windows/Android client (package
// tunnel) and the GitHub Actions node (package main, muxproto.go); only the
// package line differs. It uses the standard library only so the node can keep
// building single-file binaries without a go.mod.
//
// Wire format
//
//	prelude  (client -> server, plaintext): "MUX2" + 16-byte salt
//	record   : [len uint16 BE][AES-256-GCM(frame)]   len = ciphertext length incl. tag
//	frame    : [type uint8][stream uint32 BE][payload]
//
// Keys: sha256(psk | salt | "c2s") and sha256(psk | salt | "s2c"); the nonce is
// a per-direction 64-bit counter, so a key is never reused on a link. Every
// reconnect uses a fresh salt, hence fresh keys, so replayed frames are
// re-encrypted under new keys and nonces are never reused across links either.
//
// Resumption
//
//	Each endpoint numbers its own outgoing *reliable* frames (OPEN/DATA/FIN/RST/
//	WINDOW) 1,2,3,... and keeps them in a replay buffer until the peer confirms
//	receipt (ACK frames carry the peer's count of reliable frames received).
//	When the link dies the session is not torn down: streams block, the client
//	redials the bug host and sends RESUME(sessionID, framesReceived); the server
//	adopts the existing session, both sides retransmit the reliable frames the
//	peer is missing, and streams continue exactly where they stopped. This is
//	what lets open connections survive a carrier NAT drop or the node's 6-hour
//	hand-off.
//
// A stream opens without waiting for a confirmation: the first DATA frames
// follow OPEN immediately, so a new TCP connection costs no extra round trip.

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	muxMagic      = "MUX2"
	muxSaltLen    = 16
	muxSessIDLen  = 16
	muxFrameHdr   = 5
	muxMaxPayload = 32 * 1024
	muxMaxRecord  = muxFrameHdr + muxMaxPayload + 16

	muxWindow      = 4 << 20   // per-stream receive window (bytes)
	muxWindowDelta = 128 << 10 // return credit after this many bytes are read
	// muxSendWindow caps a stream's unacknowledged bytes in flight, below the
	// window the peer grants. Bytes in flight sit in Cloudflare and carrier
	// buffers, and every other stream's data waits behind them, so a 4 MB
	// window let one download stall the whole link for seconds. It must stay
	// above 1 MB, the credit step of older peers (muxWindow/4).
	muxSendWindow = 1280 << 10
	// muxStreamQueue bounds DATA a stream may queue for the writer.
	muxStreamQueue = 2 * muxMaxPayload
	muxReplayCap   = 8 << 20 // max buffered unacked reliable bytes before Write() blocks
	muxAckEvery    = 64      // send an ACK after this many reliable frames received

	// Reliable frames (numbered, buffered for replay, acknowledged).
	muxOpen     = 0x01
	muxData     = 0x02
	muxFin      = 0x03
	muxRst      = 0x04
	muxWindowUp = 0x05
	// Unreliable frames (link-local, never replayed).
	muxPing       = 0x06
	muxPong       = 0x07
	muxDNS        = 0x08
	muxDNSReply   = 0x09
	muxAck        = 0x0a
	muxHello      = 0x0b
	muxResume     = 0x0c
	muxResumeOK   = 0x0d
	muxResumeFail = 0x0e
)

func muxReliable(typ byte) bool {
	return typ >= muxOpen && typ <= muxWindowUp
}

var (
	errMuxClosed   = errors.New("mux: session closed")
	errMuxReset    = errors.New("mux: stream reset by peer")
	errMuxBadMagic = errors.New("mux: bad prelude")
	errMuxResume   = errors.New("mux: resume rejected")
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
	wbuf []byte
	rbuf []byte
	pbuf []byte
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

// writeFrame encrypts one frame and writes it as a single record. Safe for one
// writer at a time; the session serializes all writes under its own lock.
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

// readFrame reads and decrypts one record. The payload slice is valid only
// until the next call on this link.
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

func (l *muxLink) close() { _ = l.conn.Close() }

// ── session ──────────────────────────────────────────────────────────────────

type muxOpenHandler func(s *muxStream, host string, port int, initial []byte)
type muxDNSHandler func(query []byte) ([]byte, error)

type muxReplayEntry struct {
	idx     uint64
	typ     byte
	id      uint32
	payload []byte
}

type muxSession struct {
	isClient  bool
	sessionID [muxSessIDLen]byte

	// write side: link + reliable numbering + replay buffer, all under wmu.
	wmu         sync.Mutex
	linkCond    *sync.Cond
	link        *muxLink // nil while detached
	txSeq       uint64   // reliable frames assigned so far
	peerAck     uint64   // reliable frames the peer has confirmed receiving
	replay      []muxReplayEntry
	replayBytes int

	// read side (touched only by the active serveLink goroutine).
	rxSeq       uint64
	lastAckSent uint64

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

	lastRecv atomic.Int64
	rttMs    atomic.Int64
	pongCh   chan int64
	helloCh  chan struct{}

	reg       *muxResumeRegistry // server only
	detachGen atomic.Uint64      // server only: bumped each time the session detaches

	sched muxSched
}

// muxSched orders outgoing frames for the session's writer goroutine: control
// frames (window updates, pings, DNS) first, then streams take turns one frame
// at a time, so a bulk transfer cannot hold up other streams or the replies
// the read loop has to send. A stream's own frames stay in order.
type muxSched struct {
	mu     sync.Mutex
	cond   *sync.Cond
	ctrl   []muxQFrame
	queues map[uint32]*muxStreamQ
	ring   []uint32 // streams with queued frames, in service order
}

type muxQFrame struct {
	typ     byte
	id      uint32
	payload []byte
}

type muxStreamQ struct {
	frames []muxQFrame
	bytes  int
}

// muxStreamOrdered reports whether a frame must stay in order with the
// stream's DATA (an OPEN before its data, a FIN or RST after it).
func muxStreamOrdered(typ byte) bool {
	return typ == muxOpen || typ == muxData || typ == muxFin || typ == muxRst
}

func newMuxSession(link *muxLink, isClient bool) *muxSession {
	s := &muxSession{
		isClient:   isClient,
		link:       link,
		streams:    make(map[uint32]*muxStream),
		dnsWaiters: make(map[uint32]chan []byte),
		done:       make(chan struct{}),
		pongCh:     make(chan int64, 4),
		helloCh:    make(chan struct{}, 1),
	}
	s.linkCond = sync.NewCond(&s.wmu)
	s.sched.cond = sync.NewCond(&s.sched.mu)
	s.sched.queues = make(map[uint32]*muxStreamQ)
	go s.writeLoop()
	if isClient {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	s.lastRecv.Store(time.Now().UnixNano())
	return s
}

// send queues one frame for the writer goroutine. DATA blocks while the
// stream already has muxStreamQueue bytes waiting; nothing else blocks, so the
// read loop can always answer pings and return window credit.
func (s *muxSession) send(typ byte, id uint32, payload []byte) error {
	if s.closed.Load() {
		return errMuxClosed
	}
	f := muxQFrame{typ: typ, id: id, payload: append([]byte(nil), payload...)}
	q := &s.sched
	q.mu.Lock()
	defer q.mu.Unlock()
	if !muxStreamOrdered(typ) {
		q.ctrl = append(q.ctrl, f)
		q.cond.Broadcast()
		return nil
	}
	sq := q.queues[id]
	if sq == nil {
		sq = &muxStreamQ{}
		q.queues[id] = sq
		q.ring = append(q.ring, id)
	}
	for typ == muxData && sq.bytes >= muxStreamQueue && !s.closed.Load() {
		q.cond.Wait()
		if q.queues[id] != sq { // drained and removed while we waited
			if sq = q.queues[id]; sq == nil {
				sq = &muxStreamQ{}
				q.queues[id] = sq
				q.ring = append(q.ring, id)
			}
		}
	}
	if s.closed.Load() {
		return errMuxClosed
	}
	sq.frames = append(sq.frames, f)
	sq.bytes += len(f.payload)
	q.cond.Broadcast()
	return nil
}

// nextFrame blocks until a frame is queued and returns it; false once the
// session is closed.
func (s *muxSession) nextFrame() (muxQFrame, bool) {
	q := &s.sched
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.ctrl) == 0 && len(q.ring) == 0 && !s.closed.Load() {
		q.cond.Wait()
	}
	if s.closed.Load() {
		return muxQFrame{}, false
	}
	if len(q.ctrl) > 0 {
		f := q.ctrl[0]
		q.ctrl = q.ctrl[1:]
		return f, true
	}
	id := q.ring[0]
	q.ring = q.ring[1:]
	sq := q.queues[id]
	f := sq.frames[0]
	sq.frames = sq.frames[1:]
	sq.bytes -= len(f.payload)
	if len(sq.frames) > 0 {
		q.ring = append(q.ring, id) // back of the line: round-robin
	} else {
		delete(q.queues, id)
	}
	q.cond.Broadcast()
	return f, true
}

func (s *muxSession) writeLoop() {
	for {
		f, ok := s.nextFrame()
		if !ok {
			return
		}
		_ = s.transmit(f.typ, f.id, f.payload)
	}
}

// transmit writes one frame on the link. Reliable frames are numbered and
// buffered for replay; if the link is momentarily down they queue and flush on
// resume (the writer only blocks once the replay buffer is full). Unreliable
// frames are dropped if the link is down. Only the writer goroutine calls it.
func (s *muxSession) transmit(typ byte, id uint32, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() {
		return errMuxClosed
	}
	if !muxReliable(typ) {
		if s.link != nil {
			_ = s.link.writeFrame(typ, id, payload)
		}
		return nil
	}
	// Reliable: apply replay-buffer backpressure.
	for s.replayBytes+len(payload) > muxReplayCap && !s.closed.Load() {
		s.linkCond.Wait()
	}
	if s.closed.Load() {
		return errMuxClosed
	}
	s.txSeq++
	buf := payload // send() already copied it
	s.replay = append(s.replay, muxReplayEntry{idx: s.txSeq, typ: typ, id: id, payload: buf})
	s.replayBytes += len(buf)
	if s.link != nil {
		if err := s.link.writeFrame(typ, id, buf); err != nil {
			// Link just died; the serveLink loop will notice and resume.
			s.link = nil
		}
	}
	return nil
}

// sendRaw writes directly on a specific link, bypassing the session link state.
// Used during the resume/hello handshake before the link is installed.
func (s *muxSession) sendRaw(link *muxLink, typ byte, id uint32, payload []byte) error {
	return link.writeFrame(typ, id, payload)
}

func (s *muxSession) trimReplay(ack uint64) {
	s.wmu.Lock()
	if ack > s.peerAck {
		s.peerAck = ack
		i := 0
		for i < len(s.replay) && s.replay[i].idx <= ack {
			s.replayBytes -= len(s.replay[i].payload)
			i++
		}
		if i > 0 {
			s.replay = append([]muxReplayEntry(nil), s.replay[i:]...)
		}
	}
	s.wmu.Unlock()
	s.linkCond.Broadcast()
}

// installLink swaps in a new link and retransmits the reliable frames the peer
// (which has received peerRx reliable frames) is missing. Caller must not hold
// wmu. Writers blocked in send() wake and continue after the backlog.
func (s *muxSession) installLink(link *muxLink, peerRx uint64) {
	s.wmu.Lock()
	if peerRx > s.peerAck {
		s.peerAck = peerRx
	}
	// Drop acknowledged entries, then replay the rest in order.
	i := 0
	for i < len(s.replay) && s.replay[i].idx <= s.peerAck {
		s.replayBytes -= len(s.replay[i].payload)
		i++
	}
	if i > 0 {
		s.replay = append([]muxReplayEntry(nil), s.replay[i:]...)
	}
	// A resume can arrive before the server notices the old link died (a silent
	// carrier drop or a Cloudflare edge that has not closed it yet). Close it so
	// its serveLink exits now instead of lingering and later detaching the
	// session out from under the new link.
	if old := s.link; old != nil && old != link {
		defer old.close()
	}
	s.link = link
	// Replay the backlog while still holding wmu. A single link delivers frames
	// in arrival order, so the wire order MUST equal seq order; if we unlocked
	// first, a concurrent send() could write a newer frame in between replayed
	// ones and the peer would deliver bytes out of order (stream corruption).
	for _, e := range s.replay {
		if err := link.writeFrame(e.typ, e.id, e.payload); err != nil {
			if s.link == link {
				s.link = nil
			}
			break
		}
	}
	s.wmu.Unlock()
	s.linkCond.Broadcast()
}

// dropLink forces the current link closed so the serveLink loop errors out and
// the supervisor starts a resume. Used by the keepalive watchdog.
func (s *muxSession) dropLink() {
	s.wmu.Lock()
	l := s.link
	s.link = nil
	s.wmu.Unlock()
	if l != nil {
		l.close()
	}
}

func (s *muxSession) currentLink() *muxLink {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.link
}

func (s *muxSession) Closed() bool        { return s.closed.Load() }
func (s *muxSession) RTTms() int64        { return s.rttMs.Load() }
func (s *muxSession) LastRecv() time.Time { return time.Unix(0, s.lastRecv.Load()) }

func (s *muxSession) ActiveStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

func (s *muxSession) Close() error { return s.closeWith(errMuxClosed) }

func (s *muxSession) closeWith(err error) error {
	if s.closed.Swap(true) {
		return nil
	}
	s.closeErr = err
	s.wmu.Lock()
	l := s.link
	s.link = nil
	s.wmu.Unlock()
	if l != nil {
		l.close()
	}
	close(s.done)
	s.linkCond.Broadcast()
	s.sched.mu.Lock()
	s.sched.ctrl, s.sched.ring = nil, nil
	s.sched.queues = make(map[uint32]*muxStreamQ)
	s.sched.cond.Broadcast()
	s.sched.mu.Unlock()

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

	if s.reg != nil {
		s.reg.remove(s.sessionID)
	}
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
	for {
		select {
		case <-s.pongCh:
			continue
		default:
		}
		break
	}
	if err := s.send(muxPing, 0, payload[:]); err != nil {
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

	if err := s.send(muxOpen, id, payload); err != nil {
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

// QueryDNS sends one raw DNS message and waits for the reply. DNS is
// best-effort: a query in flight during a link drop simply times out and the
// caller retries.
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
	if err := s.send(muxDNS, id, query); err != nil {
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

// serveLink runs the read loop on one link until it fails; it returns the read
// error (never nil). It does not close the session, so the caller can resume.
func (s *muxSession) serveLink(link *muxLink) error {
	for {
		typ, id, payload, err := link.readFrame()
		if err != nil {
			return err
		}
		s.lastRecv.Store(time.Now().UnixNano())

		if muxReliable(typ) {
			s.rxSeq++
			if s.rxSeq-s.lastAckSent >= muxAckEvery {
				s.sendAck(link)
			}
		}

		switch typ {
		case muxOpen:
			if s.isClient || s.onOpen == nil {
				_ = s.send(muxRst, id, nil)
				continue
			}
			if len(payload) < 3 {
				_ = s.send(muxRst, id, nil)
				continue
			}
			port := int(binary.BigEndian.Uint16(payload[:2]))
			hl := int(payload[2])
			if len(payload) < 3+hl {
				_ = s.send(muxRst, id, nil)
				continue
			}
			host := string(payload[3 : 3+hl])
			initial := append([]byte(nil), payload[3+hl:]...)
			if s.getStream(id) != nil {
				continue // duplicate OPEN after resume
			}
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

		case muxAck:
			if len(payload) >= 8 {
				s.trimReplay(binary.BigEndian.Uint64(payload[:8]))
			}

		case muxPing:
			_ = s.send(muxPong, id, payload)

		case muxPong:
			if len(payload) >= 8 {
				select {
				case s.pongCh <- int64(binary.BigEndian.Uint64(payload[:8])):
				default:
				}
			}

		case muxHello:
			if len(payload) >= muxSessIDLen {
				copy(s.sessionID[:], payload[:muxSessIDLen])
			}
			select {
			case s.helloCh <- struct{}{}:
			default:
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
				_ = s.send(muxDNSReply, id, resp)
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

func (s *muxSession) sendAck(link *muxLink) {
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], s.rxSeq)
	if err := link.writeFrame(muxAck, 0, p[:]); err == nil {
		s.lastAckSent = s.rxSeq
	}
}

// ── client handshake / hello / resume ────────────────────────────────────────

// muxClientHandshake writes the plaintext prelude and installs the link.
func muxClientHandshake(conn net.Conn, psk []byte) (*muxSession, error) {
	link, err := muxWritePrelude(conn, psk, true)
	if err != nil {
		return nil, err
	}
	return newMuxSession(link, true), nil
}

func muxWritePrelude(conn net.Conn, psk []byte, isClient bool) (*muxLink, error) {
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
	return newMuxLink(conn, psk, salt, isClient)
}

// clientHello sends HELLO (to learn the sessionID) plus a PING, and waits for
// the PONG that proves the server holds the same key. The HELLO reply carrying
// the sessionID arrives asynchronously and is stored by serveLink.
func (s *muxSession) clientHello(link *muxLink, timeout time.Duration) (time.Duration, error) {
	if err := s.sendRaw(link, muxHello, 0, nil); err != nil {
		return 0, err
	}
	var payload [8]byte
	t0 := time.Now()
	binary.BigEndian.PutUint64(payload[:], uint64(t0.UnixNano()))
	if err := s.sendRaw(link, muxPing, 0, payload[:]); err != nil {
		return 0, err
	}
	_ = link.conn.SetReadDeadline(time.Now().Add(timeout))
	defer link.conn.SetReadDeadline(time.Time{})
	for {
		typ, _, pl, err := link.readFrame()
		if err != nil {
			return 0, err
		}
		s.lastRecv.Store(time.Now().UnixNano())
		switch typ {
		case muxHello:
			if len(pl) >= muxSessIDLen {
				copy(s.sessionID[:], pl[:muxSessIDLen])
			}
		case muxPong:
			rtt := time.Since(t0)
			s.rttMs.Store(rtt.Milliseconds())
			return rtt, nil
		}
	}
}

// clientResume opens a fresh link over conn and reattaches this session on the
// server. On success the session's link is swapped and the backlog retransmitted.
func (s *muxSession) clientResume(conn net.Conn, psk []byte, timeout time.Duration) error {
	link, err := muxWritePrelude(conn, psk, true)
	if err != nil {
		return err
	}
	payload := make([]byte, muxSessIDLen+8)
	copy(payload, s.sessionID[:])
	binary.BigEndian.PutUint64(payload[muxSessIDLen:], s.rxSeq)
	if err := s.sendRaw(link, muxResume, 0, payload); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	typ, _, pl, err := link.readFrame()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	if typ != muxResumeOK || len(pl) < 8 {
		return errMuxResume
	}
	peerRx := binary.BigEndian.Uint64(pl[:8])
	s.lastRecv.Store(time.Now().UnixNano())
	s.installLink(link, peerRx)
	return nil
}

// ── server handshake / accept ────────────────────────────────────────────────

// muxResumeRegistry holds detached server sessions awaiting resume.
type muxResumeRegistry struct {
	mu    sync.Mutex
	items map[[muxSessIDLen]byte]*muxSession
}

func newMuxResumeRegistry() *muxResumeRegistry {
	return &muxResumeRegistry{items: make(map[[muxSessIDLen]byte]*muxSession)}
}

func (r *muxResumeRegistry) put(s *muxSession) {
	r.mu.Lock()
	r.items[s.sessionID] = s
	r.mu.Unlock()
}

func (r *muxResumeRegistry) take(id [muxSessIDLen]byte) *muxSession {
	r.mu.Lock()
	s := r.items[id]
	delete(r.items, id)
	r.mu.Unlock()
	return s
}

func (r *muxResumeRegistry) remove(id [muxSessIDLen]byte) {
	r.mu.Lock()
	delete(r.items, id)
	r.mu.Unlock()
}

// muxServerConn drives one incoming /mux connection: handshake, decide fresh vs
// resume, serve, and on link-down keep the session alive for the grace period
// so the client can reattach. setup is called once per fresh session to install
// its handlers. It blocks until the connection ends.
func muxServerConn(conn net.Conn, psk []byte, reg *muxResumeRegistry, grace time.Duration, setup func(*muxSession), log func(string)) {
	link, err := muxReadPrelude(conn, psk)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	typ, _, pl, err := link.readFrame()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}

	switch typ {
	case muxResume:
		if len(pl) < muxSessIDLen+8 {
			return
		}
		var id [muxSessIDLen]byte
		copy(id[:], pl[:muxSessIDLen])
		peerRx := binary.BigEndian.Uint64(pl[muxSessIDLen : muxSessIDLen+8])
		sess := reg.take(id)
		if sess == nil || sess.Closed() {
			_ = link.writeFrame(muxResumeFail, 0, nil)
			return
		}
		var ack [8]byte
		binary.BigEndian.PutUint64(ack[:], sess.rxSeq)
		if err := link.writeFrame(muxResumeOK, 0, ack[:]); err != nil {
			reg.put(sess) // put it back; another attempt may succeed
			return
		}
		sess.installLink(link, peerRx)
		if log != nil {
			log("mux: session resumed")
		}
		serr := sess.serveWithIdle(link, muxServerIdle)
		muxServerAfterServe(sess, link, reg, grace)
		_ = serr

	case muxHello:
		sess := newMuxSession(link, false)
		if _, err := rand.Read(sess.sessionID[:]); err != nil {
			return
		}
		sess.reg = reg
		if setup != nil {
			setup(sess)
		}
		reg.put(sess)
		// Reply HELLO (sessionID) and, if the client folded in a PING, it will
		// be answered by serveLink.
		_ = link.writeFrame(muxHello, 0, sess.sessionID[:])
		serr := sess.serveWithIdle(link, muxServerIdle)
		muxServerAfterServe(sess, link, reg, grace)
		_ = serr

	default:
		return
	}
}

// muxServeWithIdle runs serveLink while a watchdog drops the link if no frame
// arrives for idle (clients ping well within that window). Returns serveLink's error.
func (s *muxSession) serveWithIdle(link *muxLink, idle time.Duration) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(idle / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-s.done:
				return
			case <-t.C:
				if time.Since(s.LastRecv()) > idle {
					s.dropLink()
					return
				}
			}
		}
	}()
	return s.serveLink(link)
}

// muxServerIdle drops an attached server link after this much silence.
const muxServerIdle = 150 * time.Second

// muxServerAfterServe decides what to do when the server link `link` drops: if
// the session is still open, hold it in the registry for the grace period so
// the client can resume; otherwise it is already gone.
func muxServerAfterServe(sess *muxSession, link *muxLink, reg *muxResumeRegistry, grace time.Duration) {
	if sess.Closed() {
		return
	}
	sess.wmu.Lock()
	if sess.link != nil && sess.link != link {
		// A resume already moved the session onto a newer link; this one is a
		// stale leftover and must not detach the live session.
		sess.wmu.Unlock()
		return
	}
	sess.link = nil
	gen := sess.detachGen.Add(1)
	sess.wmu.Unlock()
	reg.put(sess)
	// Grace timer: if nobody resumes within the window, close it. A timer from
	// an earlier detach must not close a session that has since been resumed
	// and detached again, so it only acts while its detach is the latest one.
	time.AfterFunc(grace, func() {
		if sess.detachGen.Load() != gen {
			return
		}
		if s := reg.take(sess.sessionID); s == sess {
			_ = s.closeWith(fmt.Errorf("mux: resume grace expired"))
		} else if s != nil {
			reg.put(s) // not ours; put the current one back
		}
	})
}

func muxReadPrelude(conn net.Conn, psk []byte) (*muxLink, error) {
	var prelude [4 + muxSaltLen]byte
	if _, err := io.ReadFull(conn, prelude[:]); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(muxMagic), prelude[:4]) != 1 {
		return nil, errMuxBadMagic
	}
	return newMuxLink(conn, psk, prelude[4:], false)
}

// ── stream: net.Conn over the session ────────────────────────────────────────

type muxStream struct {
	sess *muxSession
	id   uint32

	mu   sync.Mutex
	cond *sync.Cond

	recv     [][]byte
	recvHead int
	unacked  int64
	finRecv  bool
	finSent  bool
	err      error

	credit int64

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
				_ = st.sess.send(muxWindowUp, st.id, p[:])
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
		for st.credit <= muxWindow-muxSendWindow && st.err == nil && !st.finSent && !st.closed {
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
		if avail := st.credit - (muxWindow - muxSendWindow); int64(n) > avail {
			n = int(avail)
		}
		if n > muxMaxPayload {
			n = muxMaxPayload
		}
		st.credit -= int64(n)
		st.mu.Unlock()

		if err := st.sess.send(muxData, st.id, b[:n]); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

func (st *muxStream) CloseWrite() error {
	st.mu.Lock()
	if st.finSent || st.closed || st.err != nil {
		st.mu.Unlock()
		return nil
	}
	st.finSent = true
	st.mu.Unlock()
	st.cond.Broadcast()
	return st.sess.send(muxFin, st.id, nil)
}

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
		return st.sess.send(muxRst, st.id, nil)
	}
	return nil
}

func (st *muxStream) LocalAddr() net.Addr  { return dummyAddr{} }
func (st *muxStream) RemoteAddr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "mux" }
func (dummyAddr) String() string  { return "mux" }

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
