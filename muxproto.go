package main

// muxproto: a multiplexed, encrypted, multi-link stream protocol carried over
// several long-lived "WebSocket" connections (raw bytes after the 101) through a
// Cloudflare bug host.
//
// This file is shared verbatim between the Windows/Android client (package
// tunnel) and the GitHub Actions node (package main, muxproto.go); only the
// package line differs. Standard library only.
//
// Wire format
//
//	prelude  (client -> server, plaintext): "MUX3" + 16-byte salt   (per link)
//	record   : [len uint16 BE][AES-256-GCM(frame)]
//	frame    : [type uint8][stream uint32 BE][payload]
//
// Keys are derived per link from sha256(psk | salt | dir); the nonce is a
// per-direction 64-bit counter, so a key is never reused on a link and every
// link uses a fresh salt.
//
// Multi-link aggregation (MUX3)
//
//	One session spans N links at once. A stream's bytes carry absolute offsets
//	(DATA = [offset u64][bytes]); the sender spreads a bulk stream's chunks
//	across all live links while the receiver reorders them per stream by offset.
//	This lets a single download exceed the per-connection throughput ceiling of
//	one tunnelled link. Reliability is per stream: the sender keeps unacked bytes
//	[ackedOff,sentOff) and, when a link dies, retransmits them on the surviving
//	links; the receiver deduplicates by offset. Losing a link therefore neither
//	drops the session nor corrupts a stream as long as one link remains, and a
//	client can add a link back (or on another node) with JOIN.
//
//	Latency is preserved: control frames (PING/PONG/DNS/OPEN) ride a single link,
//	and a stream's first muxHomeBytes bytes stay on its home link, so small and
//	interactive transfers never hit the reorder path.

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
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	muxMagic      = "MUX3"
	muxSaltLen    = 16
	muxSessIDLen  = 16
	muxFrameHdr   = 5
	muxMaxPayload = 32 * 1024
	muxMaxRecord  = muxFrameHdr + muxMaxPayload + 16

	muxDataHdr   = 8                        // uint64 offset prefix on DATA frames
	muxDataChunk = muxMaxPayload - muxDataHdr // max application bytes per DATA frame

	muxWindow    = 8 << 20          // per-stream flow-control window (bytes)
	muxAckEvery  = 256 * 1024       // send a cumulative ACK after this many new in-order bytes
	muxHomeBytes = 128 * 1024       // a stream's first bytes stay on its home link (latency)

	muxFrameTypes = 0

	muxOpen     = 0x01 // [port u16][hostLen u8][host][initial bytes @ offset 0]
	muxData     = 0x02 // [offset u64][bytes]
	muxFin      = 0x03 // [finalOffset u64]
	muxRst      = 0x04
	muxAck      = 0x05 // [recvOff u64]
	muxPing     = 0x06 // [ts u64]
	muxPong     = 0x07 // [ts u64]
	muxDNS      = 0x08
	muxDNSReply = 0x09
	muxHello    = 0x0a // [sessionID 16]
	muxJoin     = 0x0b // [sessionID 16]  (add this link to an existing session)
	muxJoinOK   = 0x0c
	muxJoinFail = 0x0d
)

var (
	errMuxClosed   = errors.New("mux: session closed")
	errMuxReset    = errors.New("mux: stream reset by peer")
	errMuxBadMagic = errors.New("mux: bad prelude")
	errMuxJoin     = errors.New("mux: join rejected")
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

// ── link: framed, encrypted records over one net.Conn ────────────────────────

type muxLink struct {
	conn net.Conn
	r    *bufio.Reader
	enc  *muxCipher
	dec  *muxCipher

	wmu  sync.Mutex
	wbuf []byte
	rbuf []byte
	pbuf []byte
	dead atomic.Bool
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

// writeFrame encrypts and writes one frame. One writer at a time per link.
func (l *muxLink) writeFrame(typ byte, id uint32, payload []byte) error {
	if len(payload) > muxMaxPayload {
		return fmt.Errorf("mux: payload %d exceeds max %d", len(payload), muxMaxPayload)
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	if l.dead.Load() {
		return net.ErrClosed
	}
	plain := l.pbuf[:muxFrameHdr+len(payload)]
	plain[0] = typ
	binary.BigEndian.PutUint32(plain[1:5], id)
	copy(plain[5:], payload)
	ctLen := len(plain) + l.enc.aead.Overhead()
	binary.BigEndian.PutUint16(l.wbuf[:2], uint16(ctLen))
	l.enc.aead.Seal(l.wbuf[2:2], l.enc.next(), plain, l.wbuf[:2])
	if _, err := l.conn.Write(l.wbuf[:2+ctLen]); err != nil {
		l.dead.Store(true)
		return err
	}
	return nil
}

// writeFrame2 writes a frame with a split payload (prefix + body) without an
// extra copy of body. Used for DATA: prefix = offset(8), body = bytes.
func (l *muxLink) writeData(id uint32, offset uint64, body []byte) error {
	if len(body)+muxDataHdr > muxMaxPayload {
		return fmt.Errorf("mux: data chunk too large")
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	if l.dead.Load() {
		return net.ErrClosed
	}
	plain := l.pbuf[:muxFrameHdr+muxDataHdr+len(body)]
	plain[0] = muxData
	binary.BigEndian.PutUint32(plain[1:5], id)
	binary.BigEndian.PutUint64(plain[5:13], offset)
	copy(plain[13:], body)
	ctLen := len(plain) + l.enc.aead.Overhead()
	binary.BigEndian.PutUint16(l.wbuf[:2], uint16(ctLen))
	l.enc.aead.Seal(l.wbuf[2:2], l.enc.next(), plain, l.wbuf[:2])
	if _, err := l.conn.Write(l.wbuf[:2+ctLen]); err != nil {
		l.dead.Store(true)
		return err
	}
	return nil
}

// tryWriteFrame writes a frame only if the link's write lock is immediately
// free, so a latency-sensitive control frame never waits behind a bulk DATA
// write that is blocked on TCP backpressure. Returns false if the link is busy.
func (l *muxLink) tryWriteFrame(typ byte, id uint32, payload []byte) (bool, error) {
	if !l.wmu.TryLock() {
		return false, nil
	}
	defer l.wmu.Unlock()
	if l.dead.Load() {
		return true, net.ErrClosed
	}
	plain := l.pbuf[:muxFrameHdr+len(payload)]
	plain[0] = typ
	binary.BigEndian.PutUint32(plain[1:5], id)
	copy(plain[5:], payload)
	ctLen := len(plain) + l.enc.aead.Overhead()
	binary.BigEndian.PutUint16(l.wbuf[:2], uint16(ctLen))
	l.enc.aead.Seal(l.wbuf[2:2], l.enc.next(), plain, l.wbuf[:2])
	if _, err := l.conn.Write(l.wbuf[:2+ctLen]); err != nil {
		l.dead.Store(true)
		return true, err
	}
	return true, nil
}

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

func (l *muxLink) close() {
	l.dead.Store(true)
	_ = l.conn.Close()
}

// ── session ──────────────────────────────────────────────────────────────────

type muxOpenHandler func(s *muxStream, host string, port int, initial []byte)
type muxDNSHandler func(query []byte) ([]byte, error)

type muxSession struct {
	isClient  bool
	sessionID [muxSessIDLen]byte

	lmu    sync.Mutex
	links  []*muxLink
	rrIdx  uint64 // round-robin cursor for data striping

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

	reg *muxResumeRegistry // server only
}

func newMuxSession(isClient bool) *muxSession {
	s := &muxSession{
		isClient:   isClient,
		streams:    make(map[uint32]*muxStream),
		dnsWaiters: make(map[uint32]chan []byte),
		done:       make(chan struct{}),
		pongCh:     make(chan int64, 8),
		helloCh:    make(chan struct{}, 1),
	}
	if isClient {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	s.lastRecv.Store(time.Now().UnixNano())
	return s
}

func (s *muxSession) addLink(l *muxLink) {
	s.lmu.Lock()
	s.links = append(s.links, l)
	s.lmu.Unlock()
}

func (s *muxSession) linkCount() int {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	n := 0
	for _, l := range s.links {
		if !l.dead.Load() {
			n++
		}
	}
	return n
}

// aliveLinks returns a snapshot of the currently live links.
func (s *muxSession) aliveLinks() []*muxLink {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	out := make([]*muxLink, 0, len(s.links))
	for _, l := range s.links {
		if !l.dead.Load() {
			out = append(out, l)
		}
	}
	return out
}

// pickLink returns the next live link round-robin, or nil if none.
func (s *muxSession) pickLink() *muxLink {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	n := len(s.links)
	for i := 0; i < n; i++ {
		idx := int(atomic.AddUint64(&s.rrIdx, 1) % uint64(n))
		if !s.links[idx].dead.Load() {
			return s.links[idx]
		}
	}
	return nil
}

// homeLink returns a stable link for a stream's first bytes / control frames.
func (s *muxSession) homeLink(id uint32) *muxLink {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	n := len(s.links)
	if n == 0 {
		return nil
	}
	start := int(id) % n
	for i := 0; i < n; i++ {
		l := s.links[(start+i)%n]
		if !l.dead.Load() {
			return l
		}
	}
	return nil
}

// removeDeadLinks prunes dead links and, if any died, retransmits unacked data
// for every stream on the survivors so no bytes are lost.
func (s *muxSession) onLinkError(dead *muxLink) {
	dead.close()
	s.lmu.Lock()
	kept := s.links[:0:0]
	removed := false
	for _, l := range s.links {
		if l == dead || l.dead.Load() {
			removed = true
			continue
		}
		kept = append(kept, l)
	}
	s.links = kept
	remaining := len(s.links)
	s.lmu.Unlock()
	if !removed {
		return
	}
	if remaining == 0 {
		return // no links left; writers block until one is re-added (or session closes)
	}
	// Retransmit unacked bytes for all streams on the surviving links.
	s.mu.Lock()
	sts := make([]*muxStream, 0, len(s.streams))
	for _, st := range s.streams {
		sts = append(sts, st)
	}
	s.mu.Unlock()
	for _, st := range sts {
		st.retransmit()
	}
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
	s.lmu.Lock()
	links := s.links
	s.links = nil
	s.lmu.Unlock()
	for _, l := range links {
		l.close()
	}
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

	if s.reg != nil {
		s.reg.remove(s.sessionID)
	}
	if s.onClose != nil {
		go s.onClose(err)
	}
	return nil
}

// controlWrite sends a non-data frame on the stream's home link (stable order).
func (s *muxSession) controlWrite(id uint32, typ byte, payload []byte) error {
	l := s.homeLink(id)
	if l == nil {
		return net.ErrClosed
	}
	if err := l.writeFrame(typ, id, payload); err != nil {
		go s.onLinkError(l)
		return err
	}
	return nil
}

// controlWriteFast sends a small control frame on the first link whose write
// lock is free (avoiding head-of-line blocking behind bulk data). If every link
// is busy it falls back to a blocking write on the stream's home link.
func (s *muxSession) controlWriteFast(id uint32, typ byte, payload []byte) error {
	for _, l := range s.aliveLinks() {
		ok, err := l.tryWriteFrame(typ, id, payload)
		if err != nil {
			go s.onLinkError(l)
			continue
		}
		if ok {
			return nil
		}
	}
	return s.controlWrite(id, typ, payload)
}

// Ping sends a PING on one link and waits for the matching PONG.
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
	if err := s.controlWriteFast(0, muxPing, payload[:]); err != nil {
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

// OpenStream opens a stream to host:port, sending OPEN (with any initial data at
// offset 0) on the stream's home link.
func (s *muxSession) OpenStream(host string, port int, initial []byte) (*muxStream, error) {
	if s.closed.Load() {
		return nil, errMuxClosed
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("mux: host too long")
	}
	s.mu.Lock()
	id := s.nextID
	s.nextID += 2
	st := newMuxStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()

	hdr := make([]byte, 0, 3+len(host))
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(port))
	hdr = append(hdr, byte(len(host)))
	hdr = append(hdr, host...)
	st.mu.Lock()
	st.openHdr = hdr
	st.mu.Unlock()
	if err := st.sendOpen(); err != nil {
		s.removeStream(id)
		return nil, err
	}
	if len(initial) > 0 {
		if _, err := st.Write(initial); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// QueryDNS sends one raw DNS message and waits for the reply (best effort).
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
	l := s.pickLink()
	if l == nil {
		cleanup()
		return nil, errMuxClosed
	}
	if err := l.writeFrame(muxDNS, id, query); err != nil {
		go s.onLinkError(l)
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

// serveLink runs the read loop for one link until it fails; returns the error.
func (s *muxSession) serveLink(link *muxLink) error {
	for {
		typ, id, payload, err := link.readFrame()
		if err != nil {
			go s.onLinkError(link)
			return err
		}
		s.lastRecv.Store(time.Now().UnixNano())

		switch typ {
		case muxOpen:
			if s.isClient || s.onOpen == nil {
				_ = s.controlWrite(id, muxRst, nil)
				continue
			}
			if len(payload) < 3 {
				_ = s.controlWrite(id, muxRst, nil)
				continue
			}
			port := int(binary.BigEndian.Uint16(payload[:2]))
			hl := int(payload[2])
			if len(payload) < 3+hl {
				_ = s.controlWrite(id, muxRst, nil)
				continue
			}
			host := string(payload[3 : 3+hl])
			initial := append([]byte(nil), payload[3+hl:]...)
			if s.getStream(id) != nil {
				continue // duplicate OPEN (retransmit)
			}
			st := newMuxStream(s, id)
			s.mu.Lock()
			s.streams[id] = st
			s.mu.Unlock()
			// initial bytes are at offset 0
			if len(initial) > 0 {
				st.deliver(0, initial)
			}
			go s.onOpen(st, host, port, initial)

		case muxData:
			if len(payload) < muxDataHdr {
				continue
			}
			off := binary.BigEndian.Uint64(payload[:muxDataHdr])
			if st := s.getStream(id); st != nil {
				st.deliver(off, payload[muxDataHdr:])
			}

		case muxFin:
			if len(payload) >= 8 {
				if st := s.getStream(id); st != nil {
					st.peerFin(binary.BigEndian.Uint64(payload[:8]))
				}
			}

		case muxRst:
			if st := s.getStream(id); st != nil {
				s.removeStream(id)
				st.abort(errMuxReset)
			}

		case muxAck:
			if len(payload) >= 8 {
				if st := s.getStream(id); st != nil {
					st.onAck(binary.BigEndian.Uint64(payload[:8]))
				}
			}

		case muxPing:
			_ = s.controlWriteFast(id, muxPong, payload)

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
				if l := s.pickLink(); l != nil {
					if err := l.writeFrame(muxDNSReply, id, resp); err != nil {
						go s.onLinkError(l)
					}
				}
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

// ── client handshake / hello / join ──────────────────────────────────────────

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

// muxClientHandshake performs the prelude on the first link and returns the session.
func muxClientHandshake(conn net.Conn, psk []byte) (*muxSession, error) {
	link, err := muxWritePrelude(conn, psk, true)
	if err != nil {
		return nil, err
	}
	s := newMuxSession(true)
	s.addLink(link)
	return s, nil
}

// clientHello sends HELLO + PING on the given link and waits for the PONG,
// capturing the sessionID the server returns. Verifies the key.
func (s *muxSession) clientHello(link *muxLink, timeout time.Duration) (time.Duration, error) {
	if err := link.writeFrame(muxHello, 0, nil); err != nil {
		return 0, err
	}
	var payload [8]byte
	t0 := time.Now()
	binary.BigEndian.PutUint64(payload[:], uint64(t0.UnixNano()))
	if err := link.writeFrame(muxPing, 0, payload[:]); err != nil {
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

// clientJoin opens a fresh link over conn and attaches it to this session on the
// server (so the server stripes/reassembles this link into the same session).
func (s *muxSession) clientJoin(conn net.Conn, psk []byte, timeout time.Duration) (*muxLink, error) {
	link, err := muxWritePrelude(conn, psk, true)
	if err != nil {
		return nil, err
	}
	if err := link.writeFrame(muxJoin, 0, s.sessionID[:]); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	typ, _, _, err := link.readFrame()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	if typ != muxJoinOK {
		return nil, errMuxJoin
	}
	s.lastRecv.Store(time.Now().UnixNano())
	s.addLink(link)
	return link, nil
}

// ── server accept / registry ─────────────────────────────────────────────────

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

func (r *muxResumeRegistry) get(id [muxSessIDLen]byte) *muxSession {
	r.mu.Lock()
	s := r.items[id]
	r.mu.Unlock()
	return s
}

func (r *muxResumeRegistry) remove(id [muxSessIDLen]byte) {
	r.mu.Lock()
	delete(r.items, id)
	r.mu.Unlock()
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

// muxServerConn drives one incoming link: handshake, then either start a new
// session (HELLO) or attach this link to an existing session (JOIN). It serves
// the link until it dies; the session persists in the registry while it has
// other links or until the grace timer fires after the last link drops.
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
	case muxJoin:
		if len(pl) < muxSessIDLen {
			return
		}
		var id [muxSessIDLen]byte
		copy(id[:], pl[:muxSessIDLen])
		sess := reg.get(id)
		if sess == nil || sess.Closed() {
			_ = link.writeFrame(muxJoinFail, 0, nil)
			return
		}
		if err := link.writeFrame(muxJoinOK, 0, nil); err != nil {
			return
		}
		sess.addLink(link)
		if log != nil {
			log("mux: link joined session")
		}
		_ = sess.serveLink(link)
		muxServerAfterLink(sess, reg, grace)

	case muxHello:
		sess := newMuxSession(false)
		if _, err := rand.Read(sess.sessionID[:]); err != nil {
			return
		}
		sess.reg = reg
		if setup != nil {
			setup(sess)
		}
		sess.addLink(link)
		reg.put(sess)
		if err := link.writeFrame(muxHello, 0, sess.sessionID[:]); err != nil {
			return
		}
		_ = sess.serveLink(link)
		muxServerAfterLink(sess, reg, grace)

	default:
		return
	}
}

// muxServerAfterLink is called when a server link's read loop ends. If the
// session still has other live links it stays up; if that was the last link it
// is held in the registry for the grace window so the client can JOIN again.
func muxServerAfterLink(sess *muxSession, reg *muxResumeRegistry, grace time.Duration) {
	if sess.Closed() {
		return
	}
	if sess.linkCount() > 0 {
		return // other links still carry the session
	}
	time.AfterFunc(grace, func() {
		if sess.Closed() {
			return
		}
		if sess.linkCount() == 0 {
			_ = sess.closeWith(fmt.Errorf("mux: all links gone, grace expired"))
		}
	})
}

// ── stream: net.Conn over the multi-link session ─────────────────────────────

type muxChunk struct {
	off  uint64
	data []byte
}

type muxStream struct {
	sess *muxSession
	id   uint32

	mu   sync.Mutex
	cond *sync.Cond

	// send side
	openHdr   []byte // port+host header for OPEN (retransmit until acked)
	openAcked bool
	sendOff   uint64 // next offset to assign
	ackedOff  uint64 // peer cumulative received
	unacked   []byte // bytes [ackedOff, sendOff)
	peerWindow uint64
	finSent   bool
	finOff    uint64

	// recv side
	recvOff   uint64            // cumulative in-order bytes received
	reorder   map[uint64][]byte // out-of-order chunks keyed by start offset
	reorderN  int               // bytes buffered out of order
	recvQ     [][]byte          // in-order chunks ready for Read
	recvHead  int
	unacked2  int64 // in-order bytes since last ACK sent
	finRecv   bool
	finRecvAt uint64

	err    error
	closed bool

	readDeadline  time.Time
	writeDeadline time.Time
}

func newMuxStream(s *muxSession, id uint32) *muxStream {
	st := &muxStream{
		sess:       s,
		id:         id,
		reorder:    make(map[uint64][]byte),
		peerWindow: muxWindow,
	}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// sendOpen transmits (or retransmits) the OPEN frame on the home link.
func (st *muxStream) sendOpen() error {
	st.mu.Lock()
	hdr := append([]byte(nil), st.openHdr...)
	st.mu.Unlock()
	return st.sess.controlWriteFast(st.id, muxOpen, hdr)
}

// ---- receive path ----

func (st *muxStream) deliver(off uint64, p []byte) {
	if len(p) == 0 {
		return
	}
	buf := append([]byte(nil), p...)
	st.mu.Lock()
	if st.err != nil || st.closed {
		st.mu.Unlock()
		return
	}
	end := off + uint64(len(buf))
	if end <= st.recvOff {
		st.mu.Unlock() // fully duplicate
		return
	}
	if off < st.recvOff {
		// partial overlap: trim already-received prefix
		buf = buf[st.recvOff-off:]
		off = st.recvOff
	}
	if off == st.recvOff {
		st.recvQ = append(st.recvQ, buf)
		st.recvOff += uint64(len(buf))
		st.unacked2 += int64(len(buf))
		// pull any contiguous chunks out of the reorder buffer
		for {
			nxt, ok := st.reorder[st.recvOff]
			if !ok {
				break
			}
			delete(st.reorder, st.recvOff)
			st.reorderN -= len(nxt)
			st.recvQ = append(st.recvQ, nxt)
			st.recvOff += uint64(len(nxt))
			st.unacked2 += int64(len(nxt))
		}
	} else {
		// future chunk (normal with multi-link): buffer for reorder. The sender's
		// flow-control window bounds how far ahead offsets can run, so this stays
		// bounded; we never drop, which would otherwise strand a gap.
		if _, exists := st.reorder[off]; !exists {
			st.reorder[off] = buf
			st.reorderN += len(buf)
		}
	}
	sendAck := st.unacked2 >= muxAckEvery || len(st.reorder) > 0
	recvOff := st.recvOff
	if sendAck {
		st.unacked2 = 0
	}
	st.mu.Unlock()
	st.cond.Broadcast()
	if sendAck {
		st.sendAck(recvOff)
	}
}

func (st *muxStream) sendAck(recvOff uint64) {
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], recvOff)
	_ = st.sess.controlWriteFast(st.id, muxAck, p[:])
}

func (st *muxStream) peerFin(finalOff uint64) {
	st.mu.Lock()
	st.finRecv = true
	st.finRecvAt = finalOff
	recvOff := st.recvOff
	st.mu.Unlock()
	st.cond.Broadcast()
	st.sendAck(recvOff)
}

// ---- send path ----

func (st *muxStream) onAck(ackOff uint64) {
	st.mu.Lock()
	if ackOff > st.ackedOff {
		trim := ackOff - st.ackedOff
		if trim >= uint64(len(st.unacked)) {
			st.unacked = st.unacked[:0]
		} else {
			st.unacked = append(st.unacked[:0], st.unacked[trim:]...)
		}
		st.ackedOff = ackOff
		if ackOff > 0 {
			st.openAcked = true
		}
	}
	st.mu.Unlock()
	st.cond.Broadcast()
}

// retransmit resends OPEN (if unacked) and all unacked bytes across live links.
// Called after a link dies so in-flight bytes are not lost.
func (st *muxStream) retransmit() {
	st.mu.Lock()
	if st.err != nil || st.closed {
		st.mu.Unlock()
		return
	}
	needOpen := !st.openAcked && len(st.openHdr) > 0
	base := st.ackedOff
	pending := append([]byte(nil), st.unacked...)
	finSent := st.finSent
	finOff := st.finOff
	st.mu.Unlock()

	if needOpen {
		_ = st.sendOpen()
	}
	off := base
	for len(pending) > 0 {
		n := len(pending)
		if n > muxDataChunk {
			n = muxDataChunk
		}
		l := st.sess.pickLink()
		if l == nil {
			return
		}
		if err := l.writeData(st.id, off, pending[:n]); err != nil {
			go st.sess.onLinkError(l)
			return
		}
		off += uint64(n)
		pending = pending[n:]
	}
	if finSent {
		var p [8]byte
		binary.BigEndian.PutUint64(p[:], finOff)
		_ = st.sess.controlWrite(st.id, muxFin, p[:])
	}
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
		if len(st.recvQ) > 0 {
			chunk := st.recvQ[0]
			n := copy(b, chunk[st.recvHead:])
			st.recvHead += n
			if st.recvHead >= len(chunk) {
				st.recvQ = st.recvQ[1:]
				st.recvHead = 0
			}
			st.mu.Unlock()
			return n, nil
		}
		if st.err != nil {
			err := st.err
			st.mu.Unlock()
			return 0, err
		}
		if st.finRecv && st.recvOff >= st.finRecvAt {
			st.mu.Unlock()
			return 0, io.EOF
		}
		if st.closed {
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
		// flow control: keep in-flight within the peer's window
		for uint64(len(st.unacked)) >= st.peerWindow && st.err == nil && !st.finSent && !st.closed {
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
		if n > muxDataChunk {
			n = muxDataChunk
		}
		// cap to remaining window
		if room := int(st.peerWindow) - len(st.unacked); n > room {
			n = room
		}
		if n <= 0 {
			st.mu.Unlock()
			continue
		}
		off := st.sendOff
		chunk := append([]byte(nil), b[:n]...)
		st.unacked = append(st.unacked, chunk...)
		st.sendOff += uint64(n)
		firstBytes := off < muxHomeBytes
		st.mu.Unlock()

		var l *muxLink
		if firstBytes {
			l = st.sess.homeLink(st.id) // first bytes on home link (latency)
		} else {
			l = st.sess.pickLink() // then stripe across all links (throughput)
		}
		if l == nil {
			// no live link right now; bytes are buffered in unacked and will be
			// retransmitted when a link returns.
			total += n
			b = b[n:]
			continue
		}
		if err := l.writeData(st.id, off, chunk); err != nil {
			go st.sess.onLinkError(l) // buffered in unacked; retransmit handles it
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
	st.finOff = st.sendOff
	finOff := st.finOff
	st.mu.Unlock()
	st.cond.Broadcast()
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], finOff)
	return st.sess.controlWrite(st.id, muxFin, p[:])
}

func (st *muxStream) abort(err error) {
	st.mu.Lock()
	if st.err == nil {
		st.err = err
	}
	st.recvQ = nil
	st.reorder = nil
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *muxStream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	needRst := st.err == nil && !(st.finSent && st.finRecv)
	st.recvQ = nil
	st.reorder = nil
	st.mu.Unlock()
	st.cond.Broadcast()
	st.sess.removeStream(st.id)
	if needRst {
		return st.sess.controlWrite(st.id, muxRst, nil)
	}
	return nil
}

func (st *muxStream) LocalAddr() net.Addr  { return muxAddr{} }
func (st *muxStream) RemoteAddr() net.Addr { return muxAddr{} }

type muxAddr struct{}

func (muxAddr) Network() string { return "mux" }
func (muxAddr) String() string  { return "mux" }

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
	go func() { // stream -> target
		buf := make([]byte, muxDataChunk)
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
	go func() { // target -> stream
		buf := make([]byte, muxDataChunk)
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

// muxSortedOffsets is a tiny helper kept for diagnostics/tests.
func muxSortedOffsets(m map[uint64][]byte) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
