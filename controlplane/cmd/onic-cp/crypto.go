package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Envelope is what every /v1 endpoint returns. The payload is encrypted to the
// device's X25519 public key (ephemeral-static ECDH -> HKDF-SHA256 -> AES-256-GCM)
// and the whole envelope is signed with the server's Ed25519 key. Apps embed only
// the Ed25519 PUBLIC key, so extracting it from an APK gives an attacker nothing.
//
// Signature input (UTF-8, '\n'-joined):
//
//	"onic-v1", kid, ts, exp, nonce, epk, ct
//
// AES-GCM additional data: "onic-v1|" + kid + "|" + ts + "|" + exp
// HKDF: secret = X25519(eph, devicePub), salt = epk || devicePub, info = "onic-cp v1", 32 bytes.
type Envelope struct {
	V     int    `json:"v"`
	Kid   string `json:"kid"`
	TS    int64  `json:"ts"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
	EPK   string `json:"epk"`
	CT    string `json:"ct"`
	Sig   string `json:"sig"`
}

const envelopeTTL = 10 * time.Minute

var b64 = base64.StdEncoding

type signer struct {
	kid  string
	priv ed25519.PrivateKey
}

func (s *signer) pub() string { return b64.EncodeToString(s.priv.Public().(ed25519.PublicKey)) }

// loadOrCreateSigner keeps the Ed25519 seed in <data>/sign.key (0600).
func loadOrCreateSigner(dataDir string) (*signer, error) {
	p := filepath.Join(dataDir, "sign.key")
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		kid := "k" + time.Now().UTC().Format("20060102")
		line := kid + " " + b64.EncodeToString(seed) + "\n"
		if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
			return nil, err
		}
		raw = []byte(line)
	} else if err != nil {
		return nil, err
	}
	f := strings.Fields(string(raw))
	if len(f) != 2 {
		return nil, fmt.Errorf("sign.key: expected '<kid> <base64 seed>'")
	}
	seed, err := b64.DecodeString(f[1])
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("sign.key: bad seed")
	}
	return &signer{kid: f[0], priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func sigInput(kid string, ts, exp int64, nonce, epk, ct string) []byte {
	return []byte(strings.Join([]string{"onic-v1", kid, strconv.FormatInt(ts, 10), strconv.FormatInt(exp, 10), nonce, epk, ct}, "\n"))
}

// seal encrypts plaintext to devicePubB64 and signs the result.
func (s *signer) seal(devicePubB64 string, plaintext []byte) (*Envelope, error) {
	devRaw, err := b64.DecodeString(devicePubB64)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	devPub, err := ecdh.X25519().NewPublicKey(devRaw)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(devPub)
	if err != nil {
		return nil, err
	}
	epk := eph.PublicKey().Bytes()
	salt := append(append([]byte{}, epk...), devRaw...)
	key, err := hkdf.Key(sha256.New, shared, salt, "onic-cp v1", 32)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	exp := now + int64(envelopeTTL/time.Second)
	aad := []byte("onic-v1|" + s.kid + "|" + strconv.FormatInt(now, 10) + "|" + strconv.FormatInt(exp, 10))
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	e := &Envelope{V: 1, Kid: s.kid, TS: now, Exp: exp, Nonce: b64.EncodeToString(nonce), EPK: b64.EncodeToString(epk), CT: b64.EncodeToString(ct)}
	e.Sig = b64.EncodeToString(ed25519.Sign(s.priv, sigInput(e.Kid, e.TS, e.Exp, e.Nonce, e.EPK, e.CT)))
	return e, nil
}

// open is the client-side inverse; used by tests and the `selftest` command so
// app implementations can be checked against a known-good reference.
func openEnvelope(serverPub ed25519.PublicKey, dev *ecdh.PrivateKey, e *Envelope) ([]byte, error) {
	sig, err := b64.DecodeString(e.Sig)
	if err != nil || !ed25519.Verify(serverPub, sigInput(e.Kid, e.TS, e.Exp, e.Nonce, e.EPK, e.CT), sig) {
		return nil, errors.New("bad signature")
	}
	now := time.Now().Unix()
	if e.Exp < now || e.TS > now+300 {
		return nil, errors.New("expired envelope")
	}
	epk, _ := b64.DecodeString(e.EPK)
	pub, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return nil, err
	}
	shared, err := dev.ECDH(pub)
	if err != nil {
		return nil, err
	}
	salt := append(append([]byte{}, epk...), dev.PublicKey().Bytes()...)
	key, _ := hkdf.Key(sha256.New, shared, salt, "onic-cp v1", 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce, _ := b64.DecodeString(e.Nonce)
	ct, _ := b64.DecodeString(e.CT)
	aad := []byte("onic-v1|" + e.Kid + "|" + strconv.FormatInt(e.TS, 10) + "|" + strconv.FormatInt(e.Exp, 10))
	return gcm.Open(nil, nonce, ct, aad)
}

// releaseSigInput is what the server signs for an OTA artifact; apps verify it
// with the same embedded Ed25519 public key before installing anything.
func releaseSigInput(platform string, versionCode int64, sha string) []byte {
	return []byte("onic-release\n" + platform + "\n" + strconv.FormatInt(versionCode, 10) + "\n" + sha)
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
