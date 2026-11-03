// onic-cp is the control plane: app config API (signed + per-device encrypted),
// admin portal, OTA release hosting and the stats intake for node agents.
//
//	onic-cp serve      -data /var/lib/onic-cp -api-host api.talhacodes.site -admin-host admin.talhacodes.site
//	onic-cp admin-add  -data ... -user talha       (prints password + TOTP secret once)
//	onic-cp pubkey     -data ...                   (Ed25519 public key to embed in the apps)
//	onic-cp selftest   -data ...                   (activate + fetch config in-process, verifies crypto)
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web
var webFS embed.FS

type server struct {
	db          *sql.DB
	sign        *signer
	apiHost     string
	adminHost   string
	releasesDir string
	dev         bool

	activateLimit *limiter
	configLimit   *limiter
	loginLimit    *limiter
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: onic-cp serve|admin-add|pubkey|selftest [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fsx := flag.NewFlagSet(cmd, flag.ExitOnError)
	dataDir := fsx.String("data", "/var/lib/onic-cp", "data directory (db, keys, releases)")
	apiHost := fsx.String("api-host", "api.talhacodes.site", "public API hostname")
	adminHost := fsx.String("admin-host", "admin.talhacodes.site", "admin portal hostname")
	listen := fsx.String("listen", ":443", "HTTPS listen address")
	httpListen := fsx.String("http", ":80", "HTTP listen address (ACME challenges + redirect)")
	certFile := fsx.String("cert", "/etc/onic-cp/tls/fullchain.pem", "TLS certificate (reloaded on change)")
	keyFile := fsx.String("key", "/etc/onic-cp/tls/key.pem", "TLS key")
	acmeDir := fsx.String("acme-webroot", "/var/lib/onic-cp/acme", "webroot for /.well-known/acme-challenge")
	dev := fsx.Bool("dev", false, "plain HTTP on -listen, any Host; for local testing only")
	userName := fsx.String("user", "", "admin username (admin-add)")
	_ = fsx.Parse(os.Args[2:])

	if err := os.MkdirAll(filepath.Join(*dataDir, "releases"), 0o750); err != nil {
		log.Fatal(err)
	}
	db, err := openDB(filepath.Join(*dataDir, "onic.db"))
	if err != nil {
		log.Fatal(err)
	}
	sg, err := loadOrCreateSigner(*dataDir)
	if err != nil {
		log.Fatal(err)
	}

	switch cmd {
	case "pubkey":
		fmt.Printf("kid=%s\ned25519_pub=%s\n", sg.kid, sg.pub())
		return
	case "admin-add":
		if *userName == "" {
			log.Fatal("-user required")
		}
		pw := randToken(18)
		secret := newTOTPSecret()
		if _, err := db.Exec(`INSERT INTO admins(username,pass_hash,totp_secret,created_at) VALUES(?,?,?,?)
			ON CONFLICT(username) DO UPDATE SET pass_hash=excluded.pass_hash, totp_secret=excluded.totp_secret`,
			*userName, hashPassword(pw), secret, time.Now().Unix()); err != nil {
			log.Fatal(err)
		}
		audit(db, "cli", "admin.add", *userName, "")
		fmt.Printf("username: %s\npassword: %s\ntotp secret: %s\notpauth://totp/Onic%%20Admin:%s?secret=%s&issuer=Onic%%20Admin\n", *userName, pw, secret, *userName, secret)
		return
	case "selftest":
		if err := selftest(db, sg); err != nil {
			log.Fatal("SELFTEST FAIL: ", err)
		}
		fmt.Println("SELFTEST OK")
		return
	case "nodes-import":
		// Reads a JSON array of nodes on stdin and upserts them, so secrets can be
		// piped in without ever being printed or written to disk elsewhere.
		var list []nodeRow
		if err := json.NewDecoder(os.Stdin).Decode(&list); err != nil {
			log.Fatal(err)
		}
		for _, n := range list {
			if n.Extra == "" {
				n.Extra = "{}"
			}
			if _, err := db.Exec(`INSERT INTO nodes(id,name,location,kind,host,bug_host,bug_port,tls,path,origin_ip,payload,secret,extra,enabled,sort,updated_at)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(id) DO UPDATE SET name=excluded.name,location=excluded.location,kind=excluded.kind,host=excluded.host,bug_host=excluded.bug_host,
				bug_port=excluded.bug_port,tls=excluded.tls,path=excluded.path,origin_ip=excluded.origin_ip,payload=excluded.payload,
				secret=CASE WHEN excluded.secret='' THEN nodes.secret ELSE excluded.secret END,
				extra=excluded.extra,enabled=excluded.enabled,sort=excluded.sort,updated_at=excluded.updated_at`,
				n.ID, n.Name, n.Location, n.Kind, n.Host, n.BugHost, n.BugPort, b2i(n.TLS), n.Path, n.OriginIP, n.Payload, n.Secret, n.Extra, b2i(n.Enabled), n.Sort, time.Now().Unix()); err != nil {
				log.Fatalf("%s: %v", n.ID, err)
			}
			fmt.Printf("imported %-10s %-8s %-30s secret=%v enabled=%v\n", n.ID, n.Kind, n.Host, n.Secret != "", n.Enabled)
		}
		audit(db, "cli", "nodes.import", fmt.Sprintf("%d nodes", len(list)), "")
		return
	case "agent-key":
		// Prints a ready-to-use /etc/onic-agent.env for the node (new key; the old
		// one stops working). Pipe it straight to the target VPS.
		id := fsx.Arg(0)
		key := randToken(32)
		res, err := db.Exec(`UPDATE nodes SET agent_key=? WHERE id=?`, key, id)
		if err != nil {
			log.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			log.Fatalf("no node %q", id)
		}
		audit(db, "cli", "node.agent_key", id, "")
		fmt.Printf("ONIC_NODE=%s\nONIC_KEY=%s\nONIC_URL=https://%s/v1/agent/push\n", id, key, *apiHost)
		return
	case "serve":
	default:
		log.Fatalf("unknown command %q", cmd)
	}

	s := &server{
		db: db, sign: sg, apiHost: *apiHost, adminHost: *adminHost,
		releasesDir: filepath.Join(*dataDir, "releases"), dev: *dev,
		activateLimit: newLimiter(10, 10*time.Minute),
		configLimit:   newLimiter(120, time.Minute),
		loginLimit:    newLimiter(8, 10*time.Minute),
	}
	if getSetting(db, "ci_token") == "" {
		_ = setSetting(db, "ci_token", randToken(32))
	}
	go s.housekeeping()

	apiMux := http.NewServeMux()
	s.mountAPI(apiMux)
	adminMux := http.NewServeMux()
	s.mountAdmin(adminMux)
	sub, _ := fs.Sub(webFS, "web")
	static := http.FileServerFS(sub)
	adminMux.Handle("GET /", static)

	acmeHandler := http.StripPrefix("/.well-known/acme-challenge/", http.FileServer(http.Dir(filepath.Join(*acmeDir, ".well-known", "acme-challenge"))))
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			acmeHandler.ServeHTTP(w, r)
			return
		}
		switch {
		case host == s.adminHost || (s.dev && strings.HasPrefix(r.URL.Path, "/admin")) || (s.dev && !strings.HasPrefix(r.URL.Path, "/v1") && !strings.HasPrefix(r.URL.Path, "/dl")):
			adminHeaders(w)
			adminMux.ServeHTTP(w, r)
		case host == s.apiHost || s.dev:
			w.Header().Set("X-Content-Type-Options", "nosniff")
			apiMux.ServeHTTP(w, r)
		default:
			http.Error(w, "not found", 404)
		}
	})

	srv := &http.Server{Addr: *listen, Handler: root, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: 120 * time.Second}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if *dev {
		log.Printf("onic-cp DEV on http://%s  pubkey=%s", *listen, sg.pub())
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return
	}

	// :80 serves ACME challenges and redirects everything else to https.
	_ = os.MkdirAll(*acmeDir, 0o755)
	go func() {
		m := http.NewServeMux()
		m.Handle("GET /.well-known/acme-challenge/", acmeHandler)
		m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
		h := &http.Server{Addr: *httpListen, Handler: m, ReadHeaderTimeout: 10 * time.Second}
		log.Println(h.ListenAndServe())
	}()

	cr := &certReloader{cert: *certFile, key: *keyFile}
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cr.get}
	log.Printf("onic-cp serving https on %s (api=%s admin=%s kid=%s)", *listen, s.apiHost, s.adminHost, sg.kid)
	if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func adminHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("X-Robots-Tag", "noindex, nofollow")
}

// certReloader re-reads the cert when its mtime changes (acme.sh renewals).
type certReloader struct {
	cert, key string
	mu        sync.Mutex
	mod       time.Time
	c         *tls.Certificate
	checked   time.Time
}

func (cr *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if cr.c != nil && time.Since(cr.checked) < time.Minute {
		return cr.c, nil
	}
	cr.checked = time.Now()
	st, err := os.Stat(cr.cert)
	if err != nil {
		if cr.c != nil {
			return cr.c, nil
		}
		return nil, err
	}
	if cr.c == nil || st.ModTime() != cr.mod {
		c, err := tls.LoadX509KeyPair(cr.cert, cr.key)
		if err != nil {
			if cr.c != nil {
				return cr.c, nil
			}
			return nil, err
		}
		cr.c, cr.mod = &c, st.ModTime()
	}
	return cr.c, nil
}

// housekeeping trims old stats/sessions so the DB stays small.
func (s *server) housekeeping() {
	for {
		now := time.Now().Unix()
		_, _ = s.db.Exec(`DELETE FROM stats WHERE ts < ?`, now-7*86400)
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now)
		_, _ = s.db.Exec(`DELETE FROM audit WHERE ts < ?`, now-180*86400)
		time.Sleep(time.Hour)
	}
}

// selftest exercises activate -> config through real handlers with a fake device,
// verifying signatures and decryption end to end.
func selftest(db *sql.DB, sg *signer) error {
	return runSelftest(db, sg, ed25519.PublicKey(sg.priv.Public().(ed25519.PublicKey)))
}
