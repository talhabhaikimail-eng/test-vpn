// v2ray_ui: password-protected web panel for the V2Ray node — client config links
// (copy + QR) and a browser speed test (ping / download / upload).
//
// proxy_v2ray routes every non-WebSocket request here (--http), so the panel lives
// on the same public hostname as the proxy. Keep-alives are disabled so a pooled
// edge connection is never reused for a later WebSocket request.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	chunkSize    = 1 << 20   // 1 MiB of random (incompressible) data, reused for downloads
	maxDownBytes = 200 << 20 // per request
	maxUpBytes   = 100 << 20 // per request
)

var randomChunk = make([]byte, chunkSize)

type panelConfig struct {
	UUID     string `json:"uuid"`
	Host     string `json:"host"`
	BugHost  string `json:"bugHost"`
	NodeName string `json:"nodeName"`
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func basicAuth(user, pass string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="V2Ray Panel", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-transform")
}

func main() {
	listen := flag.String("listen", "127.0.0.1:10090", "listen address (behind proxy_v2ray)")
	page := flag.String("page", "/usr/share/v2ray-ui/index.html", "panel HTML template")
	flag.Parse()

	pass := env("UI_PASSWORD", "")
	if pass == "" {
		log.Fatal("UI_PASSWORD is not set; refusing to serve the panel (it exposes the UUID)")
	}
	user := env("UI_USER", "admin")

	tmpl, err := os.ReadFile(*page)
	if err != nil {
		log.Fatalf("read %s: %v", *page, err)
	}
	if _, err := rand.Read(randomChunk); err != nil {
		log.Fatal(err)
	}

	base := panelConfig{
		UUID:     env("V2RAY_UUID", ""),
		Host:     env("PUBLIC_HOST", ""),
		BugHost:  env("BUG_HOST", "jsbl.com"),
		NodeName: env("NODE_NAME", "V2Ray Node"),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		cfg := base
		if cfg.Host == "" {
			cfg.Host = r.Host // the hostname the user opened the panel on
		}
		js, _ := json.Marshal(cfg)
		safe := strings.NewReplacer("<", `<`, ">", `>`, "&", `&`).Replace(string(js))
		body := strings.Replace(string(tmpl), "__PANEL_CONFIG__", safe, 1)
		noStore(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = io.WriteString(w, body)
	})

	mux.HandleFunc("GET /speedtest/ping", func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /speedtest/down", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if n <= 0 || n > maxDownBytes {
			n = 25 << 20
		}
		noStore(w)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		for n > 0 {
			c := int64(chunkSize)
			if n < c {
				c = n
			}
			if _, err := w.Write(randomChunk[:c]); err != nil {
				return
			}
			n -= c
		}
	})

	mux.HandleFunc("POST /speedtest/up", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, maxUpBytes))
		noStore(w)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"bytes":`+strconv.FormatInt(n, 10)+`}`)
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           basicAuth(user, pass, mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       5 * time.Second,
	}
	srv.SetKeepAlivesEnabled(false)
	log.Printf("[v2ray-ui] panel on %s (user %q)", *listen, user)
	log.Fatal(srv.ListenAndServe())
}
