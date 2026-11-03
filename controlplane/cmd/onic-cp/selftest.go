package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"
)

// runSelftest creates a throwaway user + code, activates a fake device through
// the real HTTP handlers, opens the envelope as an app would, then fetches the
// config again and cleans up. It touches only rows it creates.
func runSelftest(db *sql.DB, sg *signer, pub ed25519.PublicKey) error {
	s := &server{db: db, sign: sg, apiHost: "selftest.invalid", releasesDir: "/nonexistent",
		activateLimit: newLimiter(100, time.Minute), configLimit: newLimiter(100, time.Minute), loginLimit: newLimiter(100, time.Minute)}
	mux := http.NewServeMux()
	s.mountAPI(mux)

	res, err := db.Exec(`INSERT INTO users(name,status,max_devices,created_at,notes) VALUES('selftest','active',1,?,'temporary')`, time.Now().Unix())
	if err != nil {
		return err
	}
	uid, _ := res.LastInsertId()
	defer func() {
		db.Exec(`DELETE FROM devices WHERE user_id=?`, uid)
		db.Exec(`DELETE FROM codes WHERE user_id=?`, uid)
		db.Exec(`DELETE FROM users WHERE id=?`, uid)
		db.Exec(`DELETE FROM audit WHERE action='activate' AND detail LIKE ?`, fmt.Sprintf("user=%d %%", uid))
	}()
	code := newCode()
	if _, err := db.Exec(`INSERT INTO codes(code,user_id,uses_left,created_at) VALUES(?,?,1,?)`, code, uid, time.Now().Unix()); err != nil {
		return err
	}
	dev, _ := ecdh.X25519().GenerateKey(rand.Reader)

	call := func(path string, body any) (*httptest.ResponseRecorder, error) {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", path, bytes.NewReader(b))
		req.RemoteAddr = "127.0.0.1:1"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr, nil
	}
	rr, _ := call("/v1/activate", map[string]any{"code": code, "device_pub": b64.EncodeToString(dev.PublicKey().Bytes()), "platform": "selftest", "app_version": "0"})
	if rr.Code != 200 {
		return fmt.Errorf("activate: %d %s", rr.Code, rr.Body.String())
	}
	var env Envelope
	_ = json.Unmarshal(rr.Body.Bytes(), &env)
	pt, err := openEnvelope(pub, dev, &env)
	if err != nil {
		return fmt.Errorf("open activate: %w", err)
	}
	var act struct {
		DeviceID string     `json:"device_id"`
		Token    string     `json:"token"`
		Config   *appConfig `json:"config"`
	}
	if err := json.Unmarshal(pt, &act); err != nil || act.Token == "" {
		return fmt.Errorf("activate payload: %v", err)
	}
	// Tampering must be detected.
	bad := env
	bad.CT = b64.EncodeToString(append([]byte{1}, []byte(bad.CT)[:8]...))
	if _, err := openEnvelope(pub, dev, &bad); err == nil {
		return fmt.Errorf("tampered envelope accepted")
	}
	// Second activation with the used code must fail.
	rr, _ = call("/v1/activate", map[string]any{"code": code, "device_pub": b64.EncodeToString(dev.PublicKey().Bytes())})
	if rr.Code == 200 {
		return fmt.Errorf("single-use code reused")
	}
	rr, _ = call("/v1/config", map[string]any{"device_id": act.DeviceID, "token": act.Token, "platform": "selftest"})
	if rr.Code != 200 {
		return fmt.Errorf("config: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &env)
	pt, err = openEnvelope(pub, dev, &env)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	var cfg appConfig
	if err := json.Unmarshal(pt, &cfg); err != nil {
		return err
	}
	// Wrong token must fail.
	rr, _ = call("/v1/config", map[string]any{"device_id": act.DeviceID, "token": "nope"})
	if rr.Code != 401 {
		return fmt.Errorf("bad token gave %d", rr.Code)
	}
	fmt.Printf("activate+config OK: %d nodes, ui v%d, envelope %d bytes\n", len(cfg.Nodes), cfg.UIVersion, len(rr.Body.Bytes()))
	return nil
}
