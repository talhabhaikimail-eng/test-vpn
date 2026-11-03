package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------- app-facing API (/v1/*) ----------

type appNode struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Location string          `json:"location"`
	Kind     string          `json:"kind"`
	Host     string          `json:"host"`
	BugHost  string          `json:"bug_host"`
	BugPort  int             `json:"bug_port"`
	TLS      bool            `json:"tls"`
	Path     string          `json:"path,omitempty"`
	Payload  string          `json:"payload,omitempty"`
	Secret   string          `json:"secret,omitempty"`
	OriginIP string          `json:"origin_ip,omitempty"`
	Extra    json.RawMessage `json:"extra,omitempty"`
}

type appRelease struct {
	Platform    string `json:"platform"`
	VersionCode int64  `json:"version_code"`
	VersionName string `json:"version_name"`
	URL         string `json:"url"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Sig         string `json:"sig"`
	Mandatory   bool   `json:"mandatory"`
	Notes       string `json:"notes"`
}

type appConfig struct {
	IssuedAt     int64           `json:"issued_at"`
	RefreshAfter int64           `json:"refresh_after"` // seconds
	User         map[string]any  `json:"user"`
	Nodes        []appNode       `json:"nodes"`
	UIVersion    int64           `json:"ui_version"`
	UI           json.RawMessage `json:"ui,omitempty"` // only when newer than the app's
	Release      *appRelease     `json:"release,omitempty"`
}

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func (s *server) mountAPI(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/activate", s.hActivate)
	mux.HandleFunc("POST /v1/config", s.hConfig)
	mux.HandleFunc("POST /v1/agent/push", s.hAgentPush)
	mux.HandleFunc("POST /v1/ci/domain", s.hCIDomain)
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "kid": s.sign.kid})
	})
	mux.HandleFunc("GET /dl/{file}", s.hDownload)
}

// signedError is a plaintext but signed status, so a MITM cannot forge e.g. a
// "revoked" answer that makes the app wipe its credentials.
func (s *server) signedError(w http.ResponseWriter, status int, code, msg string) {
	ts := time.Now().Unix()
	body := "onic-err\n" + code + "\n" + strconv.FormatInt(ts, 10)
	sig := ed25519.Sign(s.sign.priv, []byte(body))
	writeJSON(w, status, map[string]any{"error": code, "message": msg, "ts": ts, "kid": s.sign.kid, "sig": b64.EncodeToString(sig)})
}

func readJSON(r *http.Request, v any, max int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *server) hActivate(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.activateLimit.allow(ip) {
		s.signedError(w, 429, "rate_limited", "too many attempts")
		return
	}
	var req struct {
		Code       string `json:"code"`
		DevicePub  string `json:"device_pub"`
		Platform   string `json:"platform"`
		AppVersion string `json:"app_version"`
		Label      string `json:"label"`
	}
	if err := readJSON(r, &req, 4096); err != nil {
		s.signedError(w, 400, "bad_request", "invalid body")
		return
	}
	raw, err := b64.DecodeString(req.DevicePub)
	if err != nil {
		s.signedError(w, 400, "bad_key", "device_pub must be base64 X25519")
		return
	}
	if _, err := ecdh.X25519().NewPublicKey(raw); err != nil {
		s.signedError(w, 400, "bad_key", "device_pub must be base64 X25519")
		return
	}
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	now := time.Now().Unix()

	tx, err := s.db.Begin()
	if err != nil {
		s.signedError(w, 500, "internal", "db")
		return
	}
	defer tx.Rollback()
	var userID, usesLeft, codeExp int64
	if err := tx.QueryRow(`SELECT user_id, uses_left, expires_at FROM codes WHERE code=?`, code).Scan(&userID, &usesLeft, &codeExp); err != nil {
		s.signedError(w, 403, "bad_code", "activation code not valid")
		return
	}
	if usesLeft == 0 || (codeExp > 0 && codeExp < now) {
		s.signedError(w, 403, "bad_code", "activation code used up or expired")
		return
	}
	u, err := loadUser(tx, userID)
	if err != nil || !u.activeAt(now) {
		s.signedError(w, 403, "account_inactive", "account disabled or expired")
		return
	}
	var devCount int64
	_ = tx.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=? AND revoked=0`, userID).Scan(&devCount)
	if u.MaxDevices > 0 && devCount >= u.MaxDevices {
		s.signedError(w, 403, "device_limit", "device limit reached for this account")
		return
	}
	devID := "d_" + randToken(12)
	token := randToken(32)
	if _, err := tx.Exec(`INSERT INTO devices(id,user_id,pubkey,token_hash,platform,app_version,label,created_at,last_seen,last_ip) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		devID, userID, req.DevicePub, sha256hex(token), clip(req.Platform, 20), clip(req.AppVersion, 40), clip(req.Label, 60), now, now, ip); err != nil {
		s.signedError(w, 500, "internal", "db")
		return
	}
	if usesLeft > 0 {
		_, _ = tx.Exec(`UPDATE codes SET uses_left=uses_left-1 WHERE code=?`, code)
	}
	if err := tx.Commit(); err != nil {
		s.signedError(w, 500, "internal", "db")
		return
	}
	audit(s.db, "device:"+devID, "activate", "user="+strconv.FormatInt(userID, 10)+" platform="+req.Platform, ip)

	cfg, err := s.buildConfig(u, devID, req.Platform, 0)
	if err != nil {
		s.signedError(w, 500, "internal", "config")
		return
	}
	out, _ := json.Marshal(map[string]any{"device_id": devID, "token": token, "config": cfg})
	env, err := s.sign.seal(req.DevicePub, out)
	if err != nil {
		s.signedError(w, 500, "internal", "seal")
		return
	}
	writeJSON(w, 200, env)
}

func (s *server) hConfig(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.configLimit.allow(ip) {
		s.signedError(w, 429, "rate_limited", "slow down")
		return
	}
	var req struct {
		DeviceID   string `json:"device_id"`
		Token      string `json:"token"`
		Platform   string `json:"platform"`
		AppVersion string `json:"app_version"`
		UIVersion  int64  `json:"ui_version"`
	}
	if err := readJSON(r, &req, 4096); err != nil {
		s.signedError(w, 400, "bad_request", "invalid body")
		return
	}
	var userID, revoked int64
	var pub, tokHash string
	err := s.db.QueryRow(`SELECT user_id, pubkey, token_hash, revoked FROM devices WHERE id=?`, req.DeviceID).Scan(&userID, &pub, &tokHash, &revoked)
	if err != nil || !hmac.Equal([]byte(tokHash), []byte(sha256hex(req.Token))) {
		s.signedError(w, 401, "unknown_device", "device not registered")
		return
	}
	if revoked != 0 {
		s.signedError(w, 403, "revoked", "device revoked")
		return
	}
	u, err := loadUser(s.db, userID)
	now := time.Now().Unix()
	if err != nil || !u.activeAt(now) {
		s.signedError(w, 403, "account_inactive", "account disabled or expired")
		return
	}
	_, _ = s.db.Exec(`UPDATE devices SET last_seen=?, last_ip=?, app_version=?, platform=COALESCE(NULLIF(?,''),platform) WHERE id=?`,
		now, ip, clip(req.AppVersion, 40), clip(req.Platform, 20), req.DeviceID)
	cfg, err := s.buildConfig(u, req.DeviceID, req.Platform, req.UIVersion)
	if err != nil {
		s.signedError(w, 500, "internal", "config")
		return
	}
	out, _ := json.Marshal(cfg)
	env, err := s.sign.seal(pub, out)
	if err != nil {
		s.signedError(w, 500, "internal", "seal")
		return
	}
	writeJSON(w, 200, env)
}

func (s *server) buildConfig(u *user, deviceID, platform string, haveUI int64) (*appConfig, error) {
	cfg := &appConfig{
		IssuedAt:     time.Now().Unix(),
		RefreshAfter: 6 * 3600,
		User:         map[string]any{"name": u.Name, "expires_at": u.ExpiresAt, "group": u.Group},
		Nodes:        []appNode{},
	}
	rows, err := s.db.Query(`SELECT id,name,location,kind,host,bug_host,bug_port,tls,path,payload,secret,origin_ip,extra FROM nodes WHERE enabled=1 AND kind!='infra' ORDER BY sort, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n appNode
		var tls int
		var extra string
		if err := rows.Scan(&n.ID, &n.Name, &n.Location, &n.Kind, &n.Host, &n.BugHost, &n.BugPort, &tls, &n.Path, &n.Payload, &n.Secret, &n.OriginIP, &extra); err != nil {
			return nil, err
		}
		n.TLS = tls != 0
		if extra != "" && extra != "{}" && json.Valid([]byte(extra)) {
			n.Extra = json.RawMessage(extra)
		}
		cfg.Nodes = append(cfg.Nodes, n)
	}
	var ver int64
	var body string
	if err := s.db.QueryRow(`SELECT version, body FROM ui_config WHERE active=1 ORDER BY version DESC LIMIT 1`).Scan(&ver, &body); err == nil {
		cfg.UIVersion = ver
		if ver > haveUI {
			cfg.UI = json.RawMessage(body)
		}
	}
	if platform != "" {
		var rel appRelease
		var id, rollout, mandatory int64
		var file string
		err := s.db.QueryRow(`SELECT id,platform,version_code,version_name,file,size,sha256,sig,rollout,mandatory,notes FROM releases WHERE platform=? AND active=1 ORDER BY version_code DESC LIMIT 1`, platform).
			Scan(&id, &rel.Platform, &rel.VersionCode, &rel.VersionName, &file, &rel.Size, &rel.SHA256, &rel.Sig, &rollout, &mandatory, &rel.Notes)
		if err == nil && inRollout(deviceID, id, rollout) {
			rel.Mandatory = mandatory != 0
			rel.URL = "https://" + s.apiHost + "/dl/" + file
			cfg.Release = &rel
		}
	}
	return cfg, nil
}

func inRollout(deviceID string, releaseID, pct int64) bool {
	if pct >= 100 {
		return true
	}
	h := fnv.New32a()
	h.Write([]byte(deviceID + "/" + strconv.FormatInt(releaseID, 10)))
	return int64(h.Sum32()%100) < pct
}

// ---------- stats agents ----------

func (s *server) hAgentPush(w http.ResponseWriter, r *http.Request) {
	nodeID := r.Header.Get("X-Onic-Node")
	tsStr := r.Header.Get("X-Onic-TS")
	sig := r.Header.Get("X-Onic-Sig")
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || nodeID == "" {
		http.Error(w, "bad request", 400)
		return
	}
	ts, _ := strconv.ParseInt(tsStr, 10, 64)
	if d := time.Now().Unix() - ts; d > 120 || d < -120 {
		http.Error(w, "stale", 401)
		return
	}
	var key string
	if err := s.db.QueryRow(`SELECT agent_key FROM nodes WHERE id=?`, nodeID).Scan(&key); err != nil || key == "" {
		http.Error(w, "unknown node", 401)
		return
	}
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(tsStr + "\n"))
	m.Write(body)
	if !hmac.Equal([]byte(hex.EncodeToString(m.Sum(nil))), []byte(sig)) {
		http.Error(w, "bad signature", 401)
		return
	}
	if !json.Valid(body) {
		http.Error(w, "bad json", 400)
		return
	}
	if _, err := s.db.Exec(`INSERT INTO stats(node_id,ts,body) VALUES(?,?,?)`, nodeID, ts, string(body)); err != nil {
		http.Error(w, "db", 500)
		return
	}
	w.WriteHeader(204)
}

// ---------- CI hook: GitHub Actions reports a new tunnel hostname ----------

func (s *server) hCIDomain(w http.ResponseWriter, r *http.Request) {
	want := getSetting(s.db, "ci_token")
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if want == "" || !hmac.Equal([]byte(want), []byte(got)) {
		http.Error(w, "unauthorized", 401)
		return
	}
	var req struct {
		Node string `json:"node"`
		Host string `json:"host"`
	}
	if err := readJSON(r, &req, 1024); err != nil || !hostRe.MatchString(req.Host) {
		http.Error(w, "bad request", 400)
		return
	}
	res, err := s.db.Exec(`UPDATE nodes SET host=?, updated_at=? WHERE id=?`, strings.ToLower(req.Host), time.Now().Unix(), req.Node)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		http.Error(w, "unknown node", 404)
		return
	}
	audit(s.db, "ci", "node.host", req.Node+" -> "+req.Host, clientIP(r))
	w.WriteHeader(204)
}

func (s *server) hDownload(w http.ResponseWriter, r *http.Request) {
	f := r.PathValue("file")
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}\.(apk|exe|zip)$`).MatchString(f) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable") // names are unique; lets Cloudflare cache
	w.Header().Set("Content-Disposition", "attachment; filename=\""+f+"\"")
	http.ServeFile(w, r, s.releasesDir+"/"+f)
}

// ---------- users ----------

type user struct {
	ID         int64
	Name       string
	Status     string
	ExpiresAt  int64
	MaxDevices int64
	Group      string
}

func (u *user) activeAt(now int64) bool {
	return u.Status == "active" && (u.ExpiresAt == 0 || u.ExpiresAt > now)
}

type queryer interface {
	QueryRow(string, ...any) *sql.Row
}

func loadUser(q queryer, id int64) (*user, error) {
	u := &user{}
	err := q.QueryRow(`SELECT id,name,status,expires_at,max_devices,grp FROM users WHERE id=?`, id).Scan(&u.ID, &u.Name, &u.Status, &u.ExpiresAt, &u.MaxDevices, &u.Group)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return u, err
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
