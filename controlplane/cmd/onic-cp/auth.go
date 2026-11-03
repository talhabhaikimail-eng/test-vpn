package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pbkdfIter     = 600_000
	sessionTTL    = 12 * time.Hour
	sessionCookie = "onic_admin"
)

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func checkPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil {
		return false
	}
	salt, err1 := b64.DecodeString(p[2])
	want, err2 := b64.DecodeString(p[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, _ := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- TOTP (RFC 6238, SHA-1, 30 s, 6 digits; works with any authenticator app) ---

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

func totpAt(secret string, t time.Time) string {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	off := h[len(h)-1] & 0x0f
	code := (binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

func checkTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	now := time.Now()
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, now.Add(d))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// --- sessions ---

func createSession(db *sql.DB, user string) (string, error) {
	tok := randToken(32)
	_, err := db.Exec(`INSERT INTO sessions(id_hash,username,expires_at) VALUES(?,?,?)`, sha256hex(tok), user, time.Now().Add(sessionTTL).Unix())
	return tok, err
}

func sessionUser(db *sql.DB, r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return ""
	}
	var u string
	var exp int64
	if err := db.QueryRow(`SELECT username, expires_at FROM sessions WHERE id_hash=?`, sha256hex(c.Value)).Scan(&u, &exp); err != nil {
		return ""
	}
	if exp < time.Now().Unix() {
		_, _ = db.Exec(`DELETE FROM sessions WHERE id_hash=?`, sha256hex(c.Value))
		return ""
	}
	return u
}

// --- tiny fixed-window rate limiter (per key) ---

type limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func newLimiter(limit int, w time.Duration) *limiter {
	return &limiter{limit: limit, window: w, hits: map[string]*window{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 50_000 {
		l.hits = map[string]*window{}
	}
	w := l.hits[key]
	if w == nil || now.Sub(w.start) > l.window {
		l.hits[key] = &window{start: now, n: 1}
		return true
	}
	w.n++
	return w.n <= l.limit
}

// clientIP trusts CF-Connecting-IP only when the TCP peer is a Cloudflare edge;
// the firewall should only admit Cloudflare on 443 anyway.
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = strings.Trim(host[:i], "[]")
	}
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" && isCloudflare(host) {
		return cf
	}
	return host
}
