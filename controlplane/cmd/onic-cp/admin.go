package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type adminHandler func(w http.ResponseWriter, r *http.Request, actor string)

func (s *server) mountAdmin(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/api/login", s.hLogin)
	mux.HandleFunc("POST /admin/api/logout", s.hLogout)

	a := func(pattern string, h adminHandler) { mux.HandleFunc(pattern, s.requireAdmin(h)) }
	a("GET /admin/api/me", func(w http.ResponseWriter, r *http.Request, actor string) {
		writeJSON(w, 200, map[string]any{"user": actor, "kid": s.sign.kid, "pubkey": s.sign.pub(), "api_host": s.apiHost})
	})
	a("GET /admin/api/nodes", s.hNodesList)
	a("POST /admin/api/nodes", s.hNodeSave)
	a("DELETE /admin/api/nodes/{id}", s.hNodeDelete)
	a("POST /admin/api/nodes/{id}/agent-key", s.hNodeAgentKey)
	a("POST /admin/api/nodes/{id}/probe", s.hNodeProbe)

	a("GET /admin/api/users", s.hUsersList)
	a("POST /admin/api/users", s.hUserSave)
	a("POST /admin/api/users/{id}/codes", s.hCodeCreate)
	a("GET /admin/api/codes", s.hCodesList)
	a("DELETE /admin/api/codes/{code}", s.hCodeDelete)
	a("GET /admin/api/devices", s.hDevicesList)
	a("POST /admin/api/devices/{id}/revoke", s.hDeviceRevoke)

	a("GET /admin/api/ui", s.hUIList)
	a("POST /admin/api/ui", s.hUISave)
	a("POST /admin/api/ui/{v}/activate", s.hUIActivate)

	a("GET /admin/api/releases", s.hReleasesList)
	a("POST /admin/api/releases", s.hReleaseUpload)
	a("POST /admin/api/releases/{id}", s.hReleaseUpdate)

	a("GET /admin/api/stats", s.hStatsOverview)
	a("GET /admin/api/stats/{node}", s.hStatsSeries)
	a("GET /admin/api/audit", s.hAudit)
	a("POST /admin/api/settings/ci-token", s.hRotateCIToken)
}

func (s *server) requireAdmin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			// CSRF: cookie is SameSite=Strict, and we additionally require a
			// custom header (forces a CORS preflight that we never approve).
			if r.Header.Get("X-Onic") != "1" {
				http.Error(w, "csrf", 403)
				return
			}
		}
		u := sessionUser(s.db, r)
		if u == "" {
			writeJSON(w, 401, map[string]string{"error": "login required"})
			return
		}
		h(w, r, u)
	}
}

func (s *server) hLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.loginLimit.allow(ip) {
		writeJSON(w, 429, map[string]string{"error": "too many attempts, wait a few minutes"})
		return
	}
	if r.Header.Get("X-Onic") != "1" {
		http.Error(w, "csrf", 403)
		return
	}
	var req struct{ Username, Password, TOTP string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	var hash, secret string
	err := s.db.QueryRow(`SELECT pass_hash, totp_secret FROM admins WHERE username=?`, req.Username).Scan(&hash, &secret)
	ok := err == nil && checkPassword(hash, req.Password) && checkTOTP(secret, req.TOTP)
	if !ok {
		if err != nil {
			checkPassword("pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", req.Password) // equalise timing
		}
		audit(s.db, "?"+clip(req.Username, 40), "login.fail", "", ip)
		writeJSON(w, 401, map[string]string{"error": "wrong username, password or code"})
		return
	}
	tok, err := createSession(s.db, req.Username)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "session"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: !s.dev, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL / time.Second)})
	audit(s.db, req.Username, "login", "", ip)
	writeJSON(w, 200, map[string]string{"user": req.Username})
}

func (s *server) hLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE id_hash=?`, sha256hex(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: !s.dev, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(204)
}

// ---------- nodes ----------

type nodeRow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Location  string `json:"location"`
	Kind      string `json:"kind"`
	Host      string `json:"host"`
	BugHost   string `json:"bug_host"`
	BugPort   int    `json:"bug_port"`
	TLS       bool   `json:"tls"`
	Path      string `json:"path"`
	OriginIP  string `json:"origin_ip"`
	Payload   string `json:"payload"`
	Secret    string `json:"secret,omitempty"` // write-only from the UI; list returns has_secret
	HasSecret bool   `json:"has_secret"`
	Extra     string `json:"extra"`
	Enabled   bool   `json:"enabled"`
	Sort      int    `json:"sort"`
	HasAgent  bool   `json:"has_agent"`
	UpdatedAt int64  `json:"updated_at"`
}

func (s *server) hNodesList(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.db.Query(`SELECT id,name,location,kind,host,bug_host,bug_port,tls,path,origin_ip,payload,secret!='',extra,enabled,sort,agent_key!='',updated_at FROM nodes ORDER BY sort,id`)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []nodeRow{}
	for rows.Next() {
		var n nodeRow
		var tls, en int
		_ = rows.Scan(&n.ID, &n.Name, &n.Location, &n.Kind, &n.Host, &n.BugHost, &n.BugPort, &tls, &n.Path, &n.OriginIP, &n.Payload, &n.HasSecret, &n.Extra, &en, &n.Sort, &n.HasAgent, &n.UpdatedAt)
		n.TLS, n.Enabled = tls != 0, en != 0
		out = append(out, n)
	}
	writeJSON(w, 200, out)
}

var validKinds = map[string]bool{"mux": true, "vless-ws": true, "xhttp": true, "ssh": true, "slowdns": true, "infra": true}

func (s *server) hNodeSave(w http.ResponseWriter, r *http.Request, actor string) {
	var n nodeRow
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&n); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	n.ID = strings.ToLower(strings.TrimSpace(n.ID))
	if n.ID == "" || len(n.ID) > 40 || !hostRe.MatchString(n.ID) || !validKinds[n.Kind] || strings.TrimSpace(n.Name) == "" {
		writeJSON(w, 400, map[string]string{"error": "id (a-z0-9-), name and a valid kind are required"})
		return
	}
	if n.Extra == "" {
		n.Extra = "{}"
	}
	if !json.Valid([]byte(n.Extra)) {
		writeJSON(w, 400, map[string]string{"error": "extra must be valid JSON"})
		return
	}
	if n.BugPort == 0 {
		n.BugPort = 443
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO nodes(id,name,location,kind,host,bug_host,bug_port,tls,path,origin_ip,payload,secret,extra,enabled,sort,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,location=excluded.location,kind=excluded.kind,host=excluded.host,bug_host=excluded.bug_host,
		bug_port=excluded.bug_port,tls=excluded.tls,path=excluded.path,origin_ip=excluded.origin_ip,payload=excluded.payload,
		secret=CASE WHEN excluded.secret='' THEN nodes.secret ELSE excluded.secret END,
		extra=excluded.extra,enabled=excluded.enabled,sort=excluded.sort,updated_at=excluded.updated_at`,
		n.ID, n.Name, n.Location, n.Kind, n.Host, n.BugHost, n.BugPort, b2i(n.TLS), n.Path, n.OriginIP, n.Payload, n.Secret, n.Extra, b2i(n.Enabled), n.Sort, now)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	audit(s.db, actor, "node.save", n.ID+" enabled="+strconv.FormatBool(n.Enabled)+" host="+n.Host, clientIP(r))
	writeJSON(w, 200, map[string]string{"ok": n.ID})
}

func (s *server) hNodeDelete(w http.ResponseWriter, r *http.Request, actor string) {
	id := r.PathValue("id")
	_, _ = s.db.Exec(`DELETE FROM nodes WHERE id=?`, id)
	_, _ = s.db.Exec(`DELETE FROM stats WHERE node_id=?`, id)
	audit(s.db, actor, "node.delete", id, clientIP(r))
	w.WriteHeader(204)
}

func (s *server) hNodeAgentKey(w http.ResponseWriter, r *http.Request, actor string) {
	id := r.PathValue("id")
	key := randToken(32)
	res, _ := s.db.Exec(`UPDATE nodes SET agent_key=? WHERE id=?`, key, id)
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, 404, map[string]string{"error": "no such node"})
		return
	}
	audit(s.db, actor, "node.agent_key", id, clientIP(r))
	writeJSON(w, 200, map[string]string{"node": id, "agent_key": key, "push_url": "https://" + s.apiHost + "/v1/agent/push"})
}

// hNodeProbe checks the node through Cloudflare from the control plane
// (TLS handshake + one HTTP request) and reports latency/status.
func (s *server) hNodeProbe(w http.ResponseWriter, r *http.Request, _ string) {
	var host, path string
	if err := s.db.QueryRow(`SELECT host, path FROM nodes WHERE id=?`, r.PathValue("id")).Scan(&host, &path); err != nil || host == "" {
		writeJSON(w, 404, map[string]string{"error": "node has no host"})
		return
	}
	if path == "" {
		path = "/"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: host}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+path, nil)
	t0 := time.Now()
	resp, err := cl.Do(req)
	ms := time.Since(t0).Milliseconds()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "ms": ms})
		return
	}
	resp.Body.Close()
	writeJSON(w, 200, map[string]any{"ok": resp.StatusCode < 500, "status": resp.StatusCode, "ms": ms, "server": resp.Header.Get("Server")})
}

// ---------- users / codes / devices ----------

func (s *server) hUsersList(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.db.Query(`SELECT u.id,u.name,u.status,u.expires_at,u.max_devices,u.quota_mb,u.grp,u.notes,u.created_at,
		(SELECT COUNT(*) FROM devices d WHERE d.user_id=u.id AND d.revoked=0),
		(SELECT MAX(last_seen) FROM devices d WHERE d.user_id=u.id)
		FROM users u ORDER BY u.id`)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, exp, maxd, quota, created, devs int64
		var last sql.NullInt64
		var name, status, grp, notes string
		_ = rows.Scan(&id, &name, &status, &exp, &maxd, &quota, &grp, &notes, &created, &devs, &last)
		out = append(out, map[string]any{"id": id, "name": name, "status": status, "expires_at": exp, "max_devices": maxd, "quota_mb": quota, "group": grp, "notes": notes, "created_at": created, "devices": devs, "last_seen": last.Int64})
	}
	writeJSON(w, 200, out)
}

func (s *server) hUserSave(w http.ResponseWriter, r *http.Request, actor string) {
	var u struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		ExpiresAt  int64  `json:"expires_at"`
		MaxDevices int64  `json:"max_devices"`
		QuotaMB    int64  `json:"quota_mb"`
		Group      string `json:"group"`
		Notes      string `json:"notes"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&u); err != nil || strings.TrimSpace(u.Name) == "" {
		writeJSON(w, 400, map[string]string{"error": "name required"})
		return
	}
	if u.Status != "disabled" {
		u.Status = "active"
	}
	if u.Group == "" {
		u.Group = "default"
	}
	if u.ID == 0 {
		res, err := s.db.Exec(`INSERT INTO users(name,status,expires_at,max_devices,quota_mb,grp,notes,created_at) VALUES(?,?,?,?,?,?,?,?)`,
			u.Name, u.Status, u.ExpiresAt, u.MaxDevices, u.QuotaMB, u.Group, u.Notes, time.Now().Unix())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		u.ID, _ = res.LastInsertId()
	} else {
		if _, err := s.db.Exec(`UPDATE users SET name=?,status=?,expires_at=?,max_devices=?,quota_mb=?,grp=?,notes=? WHERE id=?`,
			u.Name, u.Status, u.ExpiresAt, u.MaxDevices, u.QuotaMB, u.Group, u.Notes, u.ID); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
	}
	audit(s.db, actor, "user.save", fmt.Sprintf("%d %s status=%s exp=%d", u.ID, u.Name, u.Status, u.ExpiresAt), clientIP(r))
	writeJSON(w, 200, map[string]any{"id": u.ID})
}

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O/1/I

func newCode() string {
	b := []byte(randToken(16))
	out := make([]byte, 0, 14)
	for i := 0; i < 12; i++ {
		if i == 4 || i == 8 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(b[i])%len(codeAlphabet)])
	}
	return string(out)
}

func (s *server) hCodeCreate(w http.ResponseWriter, r *http.Request, actor string) {
	uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Uses      int64 `json:"uses"`
		ValidDays int64 `json:"valid_days"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&req)
	if req.Uses == 0 {
		req.Uses = 1
	}
	var exp int64
	if req.ValidDays > 0 {
		exp = time.Now().Add(time.Duration(req.ValidDays) * 24 * time.Hour).Unix()
	}
	if _, err := loadUser(s.db, uid); err != nil {
		writeJSON(w, 404, map[string]string{"error": "no such user"})
		return
	}
	code := newCode()
	if _, err := s.db.Exec(`INSERT INTO codes(code,user_id,uses_left,expires_at,created_at) VALUES(?,?,?,?,?)`, code, uid, req.Uses, exp, time.Now().Unix()); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	audit(s.db, actor, "code.create", fmt.Sprintf("user=%d uses=%d", uid, req.Uses), clientIP(r))
	writeJSON(w, 200, map[string]any{"code": code, "uses": req.Uses, "expires_at": exp})
}

func (s *server) hCodesList(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.db.Query(`SELECT c.code,c.user_id,u.name,c.uses_left,c.expires_at,c.created_at FROM codes c LEFT JOIN users u ON u.id=c.user_id ORDER BY c.created_at DESC LIMIT 500`)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var code string
		var name sql.NullString
		var uid, uses, exp, created int64
		_ = rows.Scan(&code, &uid, &name, &uses, &exp, &created)
		out = append(out, map[string]any{"code": code, "user_id": uid, "user": name.String, "uses_left": uses, "expires_at": exp, "created_at": created})
	}
	writeJSON(w, 200, out)
}

func (s *server) hCodeDelete(w http.ResponseWriter, r *http.Request, actor string) {
	_, _ = s.db.Exec(`DELETE FROM codes WHERE code=?`, r.PathValue("code"))
	audit(s.db, actor, "code.delete", r.PathValue("code"), clientIP(r))
	w.WriteHeader(204)
}

func (s *server) hDevicesList(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.db.Query(`SELECT d.id,d.user_id,u.name,d.platform,d.app_version,d.label,d.revoked,d.created_at,d.last_seen,d.last_ip FROM devices d LEFT JOIN users u ON u.id=d.user_id ORDER BY d.last_seen DESC LIMIT 2000`)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, plat, ver, label, ip string
		var name sql.NullString
		var uid, rev, created, last int64
		_ = rows.Scan(&id, &uid, &name, &plat, &ver, &label, &rev, &created, &last, &ip)
		out = append(out, map[string]any{"id": id, "user_id": uid, "user": name.String, "platform": plat, "app_version": ver, "label": label, "revoked": rev != 0, "created_at": created, "last_seen": last, "last_ip": ip})
	}
	writeJSON(w, 200, out)
}

func (s *server) hDeviceRevoke(w http.ResponseWriter, r *http.Request, actor string) {
	_, _ = s.db.Exec(`UPDATE devices SET revoked=1 WHERE id=?`, r.PathValue("id"))
	audit(s.db, actor, "device.revoke", r.PathValue("id"), clientIP(r))
	w.WriteHeader(204)
}

// ---------- remote UI config ----------

func (s *server) hUIList(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.db.Query(`SELECT version,body,note,active,created_at FROM ui_config ORDER BY version DESC LIMIT 50`)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var v, act, created int64
		var body, note string
		_ = rows.Scan(&v, &body, &note, &act, &created)
		out = append(out, map[string]any{"version": v, "body": body, "note": note, "active": act != 0, "created_at": created})
	}
	writeJSON(w, 200, out)
}

func (s *server) hUISave(w http.ResponseWriter, r *http.Request, actor string) {
	var req struct {
		Body     string `json:"body"`
		Note     string `json:"note"`
		Activate bool   `json:"activate"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req); err != nil || !json.Valid([]byte(req.Body)) {
		writeJSON(w, 400, map[string]string{"error": "body must be valid JSON"})
		return
	}
	res, err := s.db.Exec(`INSERT INTO ui_config(body,note,active,created_at) VALUES(?,?,0,?)`, req.Body, req.Note, time.Now().Unix())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	v, _ := res.LastInsertId()
	if req.Activate {
		_, _ = s.db.Exec(`UPDATE ui_config SET active=(version=?)`, v)
	}
	audit(s.db, actor, "ui.save", fmt.Sprintf("v%d activate=%v %s", v, req.Activate, req.Note), clientIP(r))
	writeJSON(w, 200, map[string]any{"version": v})
}

func (s *server) hUIActivate(w http.ResponseWriter, r *http.Request, actor string) {
	v, _ := strconv.ParseInt(r.PathValue("v"), 10, 64)
	_, _ = s.db.Exec(`UPDATE ui_config SET active=(version=?)`, v)
	audit(s.db, actor, "ui.activate", fmt.Sprintf("v%d", v), clientIP(r))
	w.WriteHeader(204)
}

// ---------- OTA releases ----------

func (s *server) hReleasesList(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.db.Query(`SELECT id,platform,version_code,version_name,file,size,sha256,rollout,mandatory,notes,active,created_at FROM releases ORDER BY id DESC LIMIT 100`)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, vc, size, roll, mand, act, created int64
		var plat, vn, file, sha, notes string
		_ = rows.Scan(&id, &plat, &vc, &vn, &file, &size, &sha, &roll, &mand, &notes, &act, &created)
		out = append(out, map[string]any{"id": id, "platform": plat, "version_code": vc, "version_name": vn, "url": "https://" + s.apiHost + "/dl/" + file, "size": size, "sha256": sha, "rollout": roll, "mandatory": mand != 0, "notes": notes, "active": act != 0, "created_at": created})
	}
	writeJSON(w, 200, out)
}

func (s *server) hReleaseUpload(w http.ResponseWriter, r *http.Request, actor string) {
	r.Body = http.MaxBytesReader(w, r.Body, 200<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, 400, map[string]string{"error": "upload too large or malformed"})
		return
	}
	plat := r.FormValue("platform")
	ext := map[string]string{"android": ".apk", "windows": ".exe"}[plat]
	vc, _ := strconv.ParseInt(r.FormValue("version_code"), 10, 64)
	vn := strings.TrimSpace(r.FormValue("version_name"))
	if ext == "" || vc <= 0 || vn == "" {
		writeJSON(w, 400, map[string]string{"error": "platform (android|windows), version_code and version_name required"})
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "file required"})
		return
	}
	defer f.Close()
	name := plat + "-" + strconv.FormatInt(vc, 10) + "-" + randToken(6) + ext
	tmp := filepath.Join(s.releasesDir, name+".part")
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(out, h), f)
	out.Close()
	if err != nil {
		os.Remove(tmp)
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := os.Rename(tmp, filepath.Join(s.releasesDir, name)); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	sig := b64.EncodeToString(ed25519.Sign(s.sign.priv, releaseSigInput(plat, vc, sum)))
	rollout, _ := strconv.ParseInt(r.FormValue("rollout"), 10, 64)
	if rollout <= 0 || rollout > 100 {
		rollout = 100
	}
	mand := b2i(r.FormValue("mandatory") == "1" || r.FormValue("mandatory") == "true")
	res, err := s.db.Exec(`INSERT INTO releases(platform,version_code,version_name,file,size,sha256,sig,rollout,mandatory,notes,active,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,?)`,
		plat, vc, vn, name, size, sum, sig, rollout, mand, r.FormValue("notes"), time.Now().Unix())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	id, _ := res.LastInsertId()
	audit(s.db, actor, "release.upload", fmt.Sprintf("%s %s (%d) %d bytes sha256=%s", plat, vn, vc, size, sum[:16]), clientIP(r))
	writeJSON(w, 200, map[string]any{"id": id, "sha256": sum, "size": size})
}

func (s *server) hReleaseUpdate(w http.ResponseWriter, r *http.Request, actor string) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Rollout   int64 `json:"rollout"`
		Mandatory bool  `json:"mandatory"`
		Active    bool  `json:"active"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&req); err != nil || req.Rollout < 0 || req.Rollout > 100 {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	_, _ = s.db.Exec(`UPDATE releases SET rollout=?, mandatory=?, active=? WHERE id=?`, req.Rollout, b2i(req.Mandatory), b2i(req.Active), id)
	audit(s.db, actor, "release.update", fmt.Sprintf("%d rollout=%d mandatory=%v active=%v", id, req.Rollout, req.Mandatory, req.Active), clientIP(r))
	w.WriteHeader(204)
}

// ---------- stats ----------

func (s *server) hStatsOverview(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.db.Query(`SELECT n.id, n.name, n.location, n.kind, n.enabled, n.agent_key!='',
		(SELECT ts FROM stats s WHERE s.node_id=n.id ORDER BY ts DESC LIMIT 1),
		(SELECT body FROM stats s WHERE s.node_id=n.id ORDER BY ts DESC LIMIT 1)
		FROM nodes n ORDER BY n.sort, n.id`)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	now := time.Now().Unix()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, loc, kind string
		var en int
		var hasAgent bool
		var ts sql.NullInt64
		var body sql.NullString
		_ = rows.Scan(&id, &name, &loc, &kind, &en, &hasAgent, &ts, &body)
		state := "no-agent"
		if hasAgent {
			state = "down"
			if ts.Valid && now-ts.Int64 < 100 {
				state = "up"
			}
		}
		m := map[string]any{"id": id, "name": name, "location": loc, "kind": kind, "enabled": en != 0, "state": state, "ts": ts.Int64}
		if body.Valid {
			m["last"] = json.RawMessage(body.String)
		}
		out = append(out, m)
	}
	var devices24, devicesTotal int64
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE revoked=0 AND last_seen>?`, now-86400).Scan(&devices24)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE revoked=0`).Scan(&devicesTotal)
	writeJSON(w, 200, map[string]any{"nodes": out, "devices_24h": devices24, "devices_total": devicesTotal, "now": now})
}

func (s *server) hStatsSeries(w http.ResponseWriter, r *http.Request, _ string) {
	hours, _ := strconv.ParseInt(r.URL.Query().Get("hours"), 10, 64)
	if hours <= 0 || hours > 24*7 {
		hours = 24
	}
	since := time.Now().Unix() - hours*3600
	step := hours * 3600 / 240 // ~240 points
	if step < 30 {
		step = 30
	}
	rows, err := s.db.Query(`SELECT ts, body FROM stats WHERE node_id=? AND ts>? AND rowid IN (
		SELECT MAX(rowid) FROM stats WHERE node_id=? AND ts>? GROUP BY ts/?) ORDER BY ts`, r.PathValue("node"), since, r.PathValue("node"), since, step)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var ts int64
		var body string
		_ = rows.Scan(&ts, &body)
		out = append(out, json.RawMessage(body))
	}
	writeJSON(w, 200, out)
}

func (s *server) hAudit(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.db.Query(`SELECT ts,actor,action,detail,ip FROM audit ORDER BY id DESC LIMIT 300`)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ts int64
		var actor, action, detail, ip string
		_ = rows.Scan(&ts, &actor, &action, &detail, &ip)
		out = append(out, map[string]any{"ts": ts, "actor": actor, "action": action, "detail": detail, "ip": ip})
	}
	writeJSON(w, 200, out)
}

func (s *server) hRotateCIToken(w http.ResponseWriter, r *http.Request, actor string) {
	tok := randToken(32)
	_ = setSetting(s.db, "ci_token", tok)
	audit(s.db, actor, "ci_token.rotate", "", clientIP(r))
	writeJSON(w, 200, map[string]string{"ci_token": tok})
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
