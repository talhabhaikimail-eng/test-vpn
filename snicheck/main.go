// snicheck: test SNI / bug-host payloads and probe whether a carrier zero-rates them.
//
// Each candidate is a (SNI, connect target) pair. For every pair it:
//  1. resolves the target, opens TCP, does a TLS handshake with the given SNI
//     (any certificate accepted; it reports whether the cert matches the SNI),
//  2. sends an HTTP payload (HTTP Injector-style tokens) and reads the reply,
//  3. with -zr, keeps pulling data through that connection to see whether the
//     carrier lets it flow (run on the phone with NO data balance, VPN off),
//  4. with -quota, does a measured balance-before/after test for one candidate.
//
// See README.md for the input file format and examples.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"
)

const defaultPayload = "GET [path] HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Accept: */*[crlf]Connection: keep-alive[crlf][crlf]"
const defaultUA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36"

// ---------------------------------------------------------------- config

type config struct {
	file, sni, endpoint, host, path, payload, payloadFile, alpn, dns, out, csvOut string
	port, conc                                                                    int
	noTLS, noHTTP, zr, ipv6, noColor, allowMismatch, json                         bool
	timeout, stall, zrTime                                                        time.Duration
	zrBytes                                                                       int64
	zrMaxReq                                                                      int
	quotaMB                                                                       float64
	portalWords                                                                   []string
}

type candidate struct {
	idx         int
	raw         string
	sni, target string
	port        int
}

type zrResult struct {
	bytes    int64
	dur      time.Duration
	requests int
	verdict  string
	detail   string
}

type result struct {
	candidate
	ip                        string
	verdict, detail           string
	tlsVer, alpn, certCN      string
	certMatch                 bool
	status                    int
	server, location          string
	tConnect, tTLS, tFirstRsp time.Duration
	zr                        *zrResult
}

func (r *result) ok() bool { return r.verdict == "OK" }

// ---------------------------------------------------------------- main

func main() {
	cfg, args := parseFlags()
	cands, err := loadCandidates(cfg, args)
	if err != nil {
		fatal(err)
	}
	if len(cands) == 0 {
		fmt.Fprintln(os.Stderr, "no candidates: pass hosts as arguments or -f file.txt (see -h)")
		os.Exit(2)
	}
	setupResolver(cfg)

	if cfg.quotaMB > 0 {
		runQuota(cfg, cands[0])
		return
	}

	if cfg.zr && !cfg.json {
		fmt.Println(c("33", "ZR mode: run this ON THE PHONE over mobile data, VPN OFF, with NO paid data balance"))
		fmt.Println(c("33", "(only the zero-rated package active). Data that keeps flowing = zero-rated.\n"))
	}
	if cfg.json {
		emit(map[string]any{"type": "start", "total": len(cands)})
	}

	results := make([]*result, len(cands))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var done int32
	for w := 0; w < cfg.conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = check(cfg, cands[i], cfg.zr)
				n := atomic.AddInt32(&done, 1)
				if cfg.json {
					emitResult(results[i], int(n), len(cands))
				} else if len(cands) > 1 && stderrTTY {
					fmt.Fprintf(os.Stderr, "\r  checked %d/%d", n, len(cands))
				}
			}
		}()
	}
	for i := range cands {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if len(cands) > 1 && stderrTTY {
		fmt.Fprint(os.Stderr, "\r                         \r")
	}

	if cfg.json {
		emit(map[string]any{"type": "done", "total": len(cands)})
	} else {
		printTable(cfg, results)
	}
	if cfg.out != "" {
		writeOK(cfg.out, results)
	}
	if cfg.csvOut != "" {
		writeCSV(cfg.csvOut, results)
	}
}

func parseFlags() (*config, []string) {
	cfg := &config{}
	flag.StringVar(&cfg.file, "f", "", "txt file with one candidate per line (# comments allowed)")
	flag.StringVar(&cfg.sni, "sni", "", "fixed SNI; then each input line is the CONNECT TARGET (bug host / IP)")
	flag.StringVar(&cfg.endpoint, "endpoint", "", "fixed connect target IP/host[:port]; then each input line is the SNI")
	flag.StringVar(&cfg.host, "host", "", "Host header for the payload (default: the SNI)")
	flag.StringVar(&cfg.path, "path", "/", "request path for [path] in the payload")
	flag.StringVar(&cfg.payload, "payload", defaultPayload, "HTTP payload; tokens: [crlf] [cr] [lf] [host] [sni] [path] [port] [ua] [protocol]")
	flag.StringVar(&cfg.payloadFile, "payload-file", "", "read the payload from a file (overrides -payload)")
	flag.StringVar(&cfg.alpn, "alpn", "http/1.1", "ALPN to offer, comma separated (keep http/1.1 when sending a payload)")
	flag.StringVar(&cfg.dns, "dns", "", "DNS server ip:53 to use instead of the system resolver")
	flag.StringVar(&cfg.out, "o", "", "write working candidates (sni@ip:port) to this file")
	flag.StringVar(&cfg.csvOut, "csv", "", "write all results to this CSV file")
	flag.IntVar(&cfg.port, "port", 0, "default port (443 with TLS, 80 with -no-tls)")
	flag.IntVar(&cfg.conc, "c", 8, "concurrent checks")
	flag.BoolVar(&cfg.noTLS, "no-tls", false, "plain TCP (port-80 style payload), no TLS")
	flag.BoolVar(&cfg.noHTTP, "handshake-only", false, "stop after the TLS handshake (no payload)")
	flag.BoolVar(&cfg.zr, "zr", false, "zero-rating probe: pull data through each working candidate")
	flag.BoolVar(&cfg.ipv6, "6", false, "prefer IPv6 when resolving")
	flag.BoolVar(&cfg.noColor, "no-color", false, "disable colors")
	flag.DurationVar(&cfg.timeout, "t", 8*time.Second, "timeout for connect / handshake / first response")
	flag.DurationVar(&cfg.stall, "stall", 6*time.Second, "zr: no bytes for this long = stalled")
	flag.DurationVar(&cfg.zrTime, "zr-time", 45*time.Second, "zr: max time per candidate")
	zrKB := flag.Int64("zr-kb", 2048, "zr: KB to pull per candidate")
	flag.IntVar(&cfg.zrMaxReq, "zr-max-req", 400, "zr: max requests per candidate (small replies need many)")
	flag.Float64Var(&cfg.quotaMB, "quota", 0, "measured balance test: push this many MB through the FIRST candidate")
	words := flag.String("portal-words", "recharge,balance,subscribe,bundle,captive,portal,insufficient,buy now,data package",
		"comma list of words that mark a carrier captive/landing page")
	flag.BoolVar(&cfg.json, "json", false, "machine output: one JSON object per line (used by the Android app)")
	flag.BoolVar(&cfg.allowMismatch, "allow-mismatch", false, "count a cert that doesn't match the SNI as OK (your own server answering a spoofed SNI)")
	flag.Usage = usage
	// allow flags before and after the hosts: snicheck host1 -path /x host2
	var args []string
	rest := os.Args[1:]
	for {
		flag.CommandLine.Parse(rest)
		rest = flag.Args()
		if len(rest) == 0 {
			break
		}
		args = append(args, rest[0])
		rest = rest[1:]
	}

	cfg.zrBytes = *zrKB * 1024
	for _, w := range strings.Split(*words, ",") {
		if w = strings.TrimSpace(strings.ToLower(w)); w != "" {
			cfg.portalWords = append(cfg.portalWords, w)
		}
	}
	if cfg.port == 0 {
		cfg.port = 443
		if cfg.noTLS {
			cfg.port = 80
		}
	}
	if cfg.payloadFile != "" {
		b, err := os.ReadFile(cfg.payloadFile)
		if err != nil {
			fatal(err)
		}
		cfg.payload = strings.TrimRight(string(b), "\r\n")
	}
	if cfg.conc < 1 {
		cfg.conc = 1
	}
	if cfg.noColor || os.Getenv("NO_COLOR") != "" {
		colorOn = false
	}
	return cfg, args
}

func usage() {
	o := flag.CommandLine.Output()
	fmt.Fprint(o, `snicheck - test SNI / bug-host payloads and carrier zero-rating

Usage:
  snicheck [flags] host1 host2 ...
  snicheck [flags] -f candidates.txt

Input lines (args or -f file):
  sni@target[:port]      explicit pair: send SNI "sni", connect to "target"
  sni target[:port]      same, space or comma separated
  host                   meaning depends on flags:
                           -sni X       -> host is the connect target, SNI = X
                           -endpoint Y  -> host is the SNI, connect to Y
                           neither      -> connect to host with SNI = host

Examples:
  snicheck -f bugs.txt -sni abc123xyz.execute-api.me-central-1.amazonaws.com
  snicheck -f snis.txt -endpoint 203.0.113.10
  snicheck -f snis.txt -endpoint 203.0.113.10 -zr -o working.txt
  snicheck -quota 20 api.example.com@203.0.113.10 -path /big.bin
  snicheck -no-tls -payload "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]" bug.com

Flags:
`)
	flag.PrintDefaults()
}

// ---------------------------------------------------------------- input

func loadCandidates(cfg *config, args []string) ([]candidate, error) {
	var lines []string
	lines = append(lines, args...)
	if cfg.file != "" {
		f, err := os.Open(cfg.file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	var out []candidate
	seen := map[string]bool{}
	for _, ln := range lines {
		if i := strings.Index(ln, "#"); i >= 0 {
			ln = ln[:i]
		}
		ln = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(ln), "https://"), "http://"))
		if ln == "" {
			continue
		}
		cd, err := parseLine(cfg, ln)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %q: %v\n", ln, err)
			continue
		}
		key := cd.sni + "@" + cd.target + ":" + strconv.Itoa(cd.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		cd.idx = len(out)
		out = append(out, cd)
	}
	return out, nil
}

func parseLine(cfg *config, ln string) (candidate, error) {
	cd := candidate{raw: ln, port: cfg.port}
	var sni, target string
	fields := strings.FieldsFunc(ln, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
	switch {
	case strings.Contains(fields[0], "@"):
		p := strings.SplitN(fields[0], "@", 2)
		sni, target = p[0], p[1]
	case len(fields) >= 2:
		sni, target = fields[0], fields[1]
	case cfg.sni != "":
		sni, target = cfg.sni, fields[0]
	case cfg.endpoint != "":
		sni, target = fields[0], cfg.endpoint
	default:
		sni, target = fields[0], fields[0]
	}
	sni = strings.TrimSuffix(strings.Split(sni, "/")[0], ".")
	target = strings.Split(target, "/")[0]
	host, port, err := splitHostPort(target, cfg.port)
	if err != nil {
		return cd, err
	}
	if sh, _, e := net.SplitHostPort(sni); e == nil { // tolerate "sni:443"
		sni = sh
	}
	if sni == "" || host == "" {
		return cd, errors.New("empty sni or target")
	}
	cd.sni, cd.target, cd.port = sni, host, port
	return cd, nil
}

func splitHostPort(s string, def int) (string, int, error) {
	if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
		return ip.String(), def, nil
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", 0, fmt.Errorf("bad port %q", p)
		}
		return strings.Trim(h, "[]"), n, nil
	}
	return s, def, nil
}

// ---------------------------------------------------------------- DNS

var resolver = net.DefaultResolver

func setupResolver(cfg *config) {
	server := cfg.dns
	if server == "" && (runtime.GOOS == "android" || runtime.GOOS == "linux") {
		if _, err := os.Stat("/etc/resolv.conf"); err != nil { // Termux/Android has no resolv.conf
			server = "8.8.8.8:53"
		}
	}
	if server == "" {
		return
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, server)
	}}
}

func resolve(cfg *config, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	var v4, v6 string
	for _, a := range addrs {
		if a.IP.To4() != nil && v4 == "" {
			v4 = a.IP.String()
		} else if a.IP.To4() == nil && v6 == "" {
			v6 = a.IP.String()
		}
	}
	if cfg.ipv6 && v6 != "" || v4 == "" {
		if v6 == "" {
			return "", errors.New("no addresses")
		}
		return v6, nil
	}
	return v4, nil
}

// ---------------------------------------------------------------- the check

// countConn counts every byte read so zr can measure total traffic (headers included).
type countConn struct {
	net.Conn
	n int64
}

func (cc *countConn) Read(p []byte) (int, error) {
	k, err := cc.Conn.Read(p)
	atomic.AddInt64(&cc.n, int64(k))
	return k, err
}

type session struct {
	raw  *countConn
	conn net.Conn // raw or TLS on top of raw
	br   *bufio.Reader
}

func (s *session) Close() { s.conn.Close() }

// dial opens TCP (+TLS) for a candidate and fills the connection fields of r.
func dial(cfg *config, cd candidate, r *result) (*session, bool) {
	ip, err := resolve(cfg, cd.target)
	if err != nil {
		r.verdict, r.detail = "DNS_FAIL", shortErr(err)
		return nil, false
	}
	r.ip = ip
	t0 := time.Now()
	tcp, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(cd.port)), cfg.timeout)
	if err != nil {
		r.verdict, r.detail = classifyNetErr("TCP", err)
		return nil, false
	}
	r.tConnect = time.Since(t0)
	cc := &countConn{Conn: tcp}
	s := &session{raw: cc, conn: cc}
	if cfg.noTLS {
		s.br = bufio.NewReaderSize(s.conn, 32*1024)
		return s, true
	}
	var protos []string
	for _, p := range strings.Split(cfg.alpn, ",") {
		if p = strings.TrimSpace(p); p != "" {
			protos = append(protos, p)
		}
	}
	tc := tls.Client(cc, &tls.Config{ServerName: cd.sni, InsecureSkipVerify: true, NextProtos: protos})
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	t1 := time.Now()
	if err := tc.HandshakeContext(ctx); err != nil {
		tcp.Close()
		r.verdict, r.detail = classifyTLSErr(err)
		return nil, false
	}
	r.tTLS = time.Since(t1)
	st := tc.ConnectionState()
	r.tlsVer = tlsVersion(st.Version)
	r.alpn = st.NegotiatedProtocol
	if len(st.PeerCertificates) > 0 {
		crt := st.PeerCertificates[0]
		r.certCN = crt.Subject.CommonName
		if r.certCN == "" && len(crt.DNSNames) > 0 {
			r.certCN = crt.DNSNames[0]
		}
		r.certMatch = crt.VerifyHostname(cd.sni) == nil
	}
	s.conn = tc
	s.br = bufio.NewReaderSize(tc, 32*1024)
	return s, true
}

func buildPayload(cfg *config, cd candidate) (string, string) {
	host := cfg.host
	if host == "" {
		host = cd.sni
	}
	proto := "HTTP/1.1"
	rep := strings.NewReplacer(
		"[crlf]", "\r\n", "[CRLF]", "\r\n", "[cr]", "\r", "[lf]", "\n",
		"[host]", host, "[sni]", cd.sni, "[path]", cfg.path, "[port]", strconv.Itoa(cd.port),
		"[ua]", defaultUA, "[protocol]", proto, "\\r", "\r", "\\n", "\n",
	)
	p := rep.Replace(cfg.payload)
	method := "GET"
	if f := strings.Fields(p); len(f) > 0 {
		method = strings.ToUpper(f[0])
	}
	return p, method
}

// request sends the payload once and reads the response header (and body unless keepBody).
func request(cfg *config, s *session, payload, method string, timeout time.Duration) (*http.Response, error) {
	s.conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(s.conn, payload); err != nil {
		return nil, err
	}
	return http.ReadResponse(s.br, &http.Request{Method: method})
}

func check(cfg *config, cd candidate, doZR bool) *result {
	r := &result{candidate: cd}
	s, ok := dial(cfg, cd, r)
	if !ok {
		return r
	}
	defer s.Close()
	defer markMismatch(cfg, r)
	if cfg.noHTTP {
		r.verdict = "OK"
		r.detail = "handshake only"
		return r
	}
	if !cfg.noTLS && r.alpn == "h2" {
		r.verdict, r.detail = "OK", "server forced h2 - payload not sent (use -alpn http/1.1)"
		return r
	}
	payload, method := buildPayload(cfg, cd)
	t0 := time.Now()
	resp, err := request(cfg, s, payload, method, cfg.timeout)
	if err != nil {
		r.verdict, r.detail = classifyNetErr("HTTP", err)
		if r.verdict == "HTTP_FAIL" && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			r.verdict, r.detail = "HTTP_CLOSED", "connection closed after payload (payload rejected / blocked?)"
		}
		return r
	}
	r.tFirstRsp = time.Since(t0)
	r.status = resp.StatusCode
	r.server = resp.Header.Get("Server")
	r.location = resp.Header.Get("Location")
	body := readSome(resp, 64*1024)
	r.verdict = "OK"
	if isPortal(cfg, cd, r.location, body) {
		r.verdict = "CAPTIVE"
		r.detail = "looks like a carrier landing page"
		if r.location != "" {
			r.detail += " -> " + r.location
		}
		return r
	}
	if doZR && resp.StatusCode != http.StatusSwitchingProtocols {
		r.zr = zeroRate(cfg, cd, s, resp, payload, method, cfg.zrBytes, cfg.zrTime, cfg.zrMaxReq, zrProgress(cfg, cd))
	}
	return r
}

// markMismatch downgrades OK to CERT_MISMATCH when the endpoint presented a cert that
// doesn't cover the SNI: on a CDN that means it doesn't host this name (default cert),
// so real traffic for that SNI won't be routed.
func markMismatch(cfg *config, r *result) {
	if r.verdict != "OK" || cfg.noTLS || cfg.allowMismatch || r.certMatch || r.certCN == "" {
		return
	}
	r.verdict = "CERT_MISMATCH"
	note := "endpoint doesn't serve this SNI (cert " + r.certCN + ")"
	if r.status != 0 {
		note += fmt.Sprintf(", HTTP %d", r.status)
	}
	r.detail = note + "; use -allow-mismatch if this is your own server answering a spoofed SNI"
}

func readSome(resp *http.Response, max int64) []byte {
	if resp.Body == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	return b
}

func isPortal(cfg *config, cd candidate, loc string, body []byte) bool {
	if loc != "" {
		if u, err := url.Parse(loc); err == nil && u.Host != "" {
			h := strings.ToLower(u.Hostname())
			own := strings.ToLower(cd.sni)
			if !(h == own || strings.HasSuffix(h, "."+own) || strings.HasSuffix(own, "."+h)) {
				for _, w := range cfg.portalWords {
					if strings.Contains(strings.ToLower(loc), w) {
						return true
					}
				}
			}
		}
	}
	lb := strings.ToLower(string(body))
	hits := 0
	for _, w := range cfg.portalWords {
		if strings.Contains(lb, w) {
			hits++
		}
	}
	return hits >= 2
}

// ---------------------------------------------------------------- zero-rating probe

// zeroRate keeps requesting through the candidate (reusing the connection when the
// server allows keep-alive, redialling otherwise) until want bytes have been read,
// counting every byte on the wire. progress (optional) is called with the running total.
func zeroRate(cfg *config, cd candidate, s *session, first *http.Response, payload, method string,
	want int64, maxTime time.Duration, maxReq int, progress func(int64)) *zrResult {

	z := &zrResult{requests: 1}
	start := time.Now()
	var base int64 // bytes from closed sessions
	cur := s
	ownCur := false
	total := func() int64 { return base + atomic.LoadInt64(&cur.raw.n) }
	defer func() {
		if ownCur {
			cur.Close()
		}
	}()

	resp := first
	for {
		// drain the current response body with stall detection
		if resp != nil && resp.Body != nil {
			buf := make([]byte, 32*1024)
			for {
				cur.conn.SetReadDeadline(time.Now().Add(cfg.stall))
				_, err := resp.Body.Read(buf)
				if progress != nil {
					progress(total())
				}
				if total() >= want {
					break
				}
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						z.verdict = "STALLED"
						z.detail = fmt.Sprintf("no data for %s after %s", cfg.stall, human(total()))
						return finishZR(z, total(), start)
					}
					break // EOF of this response
				}
			}
			resp.Body.Close()
		}
		if total() >= want {
			z.verdict = "FLOWING"
			return finishZR(z, total(), start)
		}
		if time.Since(start) > maxTime {
			z.verdict = "TIMEOUT"
			z.detail = "time limit reached at " + human(total())
			return finishZR(z, total(), start)
		}
		if z.requests >= maxReq {
			z.verdict = "INCONCLUSIVE"
			z.detail = fmt.Sprintf("only %s in %d requests - replies too small, use -path to a big file", human(total()), z.requests)
			return finishZR(z, total(), start)
		}
		// next request: reuse if keep-alive, else redial
		if resp == nil || resp.Close {
			base += atomic.LoadInt64(&cur.raw.n)
			if ownCur {
				cur.Close()
			}
			var tmp result
			ns, ok := dial(cfg, cd, &tmp)
			if !ok {
				cur = &session{raw: &countConn{}}
				ownCur = false
				z.verdict = "CUT"
				z.detail = fmt.Sprintf("reconnect failed after %s: %s %s", human(base), tmp.verdict, tmp.detail)
				return finishZR(z, base, start)
			}
			cur, ownCur = ns, true
		}
		var err error
		resp, err = request(cfg, cur, payload, method, cfg.stall+cfg.timeout)
		z.requests++
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				z.verdict = "STALLED"
				z.detail = fmt.Sprintf("request %d got no reply after %s", z.requests, human(total()))
				return finishZR(z, total(), start)
			}
			resp = nil // connection closed: redial on next loop
			continue
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			if isPortal(cfg, cd, loc, nil) {
				z.verdict = "CAPTIVE"
				z.detail = "redirected to " + loc + " after " + human(total())
				return finishZR(z, total(), start)
			}
		}
	}
}

func finishZR(z *zrResult, n int64, start time.Time) *zrResult {
	z.bytes = n
	z.dur = time.Since(start)
	return z
}

// ---------------------------------------------------------------- quota mode

func runQuota(cfg *config, cd candidate) {
	in := bufio.NewReader(os.Stdin)
	ask := func(q string) float64 {
		for {
			fmt.Print(q)
			line, _ := in.ReadString('\n')
			v, err := strconv.ParseFloat(strings.TrimSpace(line), 64)
			if err == nil {
				return v
			}
			fmt.Println("  enter a number (MB)")
		}
	}
	fmt.Println(c("1;36", "Measured zero-rating test"))
	fmt.Printf("  candidate: SNI %s -> %s:%d   push: %.0f MB\n", cd.sni, cd.target, cd.port, cfg.quotaMB)
	fmt.Println("  Run on the phone, VPN OFF, mobile data. Check balance via the carrier app / USSD.")
	fmt.Println("  Tip: calibrate first by downloading the same amount from a normal (billed) site.")
	before := ask("\nCurrent data balance in MB: ")

	r := &result{candidate: cd}
	s, ok := dial(cfg, cd, r)
	if !ok {
		fmt.Println(c("31", "connect failed: "+r.verdict+" "+r.detail))
		os.Exit(1)
	}
	defer s.Close()
	payload, method := buildPayload(cfg, cd)
	resp, err := request(cfg, s, payload, method, cfg.timeout)
	if err != nil {
		fmt.Println(c("31", "payload failed: "+err.Error()))
		os.Exit(1)
	}
	want := int64(cfg.quotaMB * 1024 * 1024)
	last := time.Now()
	z := zeroRate(cfg, cd, s, resp, payload, method, want, 30*time.Minute, 1<<30, func(n int64) {
		if time.Since(last) > 500*time.Millisecond {
			last = time.Now()
			fmt.Fprintf(os.Stderr, "\r  pushed %s / %s   ", human(n), human(want))
		}
	})
	fmt.Fprintf(os.Stderr, "\r  pushed %s in %s (%s)   \n", human(z.bytes), z.dur.Round(time.Second), z.verdict)
	if z.bytes < want/2 {
		fmt.Println(c("33", "  transfer stopped early: "+z.detail))
	}
	fmt.Println("\nWait ~1 minute for the carrier meter to update, then check again.")
	after := ask("Data balance now in MB: ")
	used := before - after
	pushed := float64(z.bytes) / (1024 * 1024)
	fmt.Printf("\n  pushed %.1f MB, balance dropped %.1f MB\n", pushed, used)
	switch {
	case pushed < 1:
		fmt.Println(c("33", "  INCONCLUSIVE: too little data moved to judge"))
	case used <= pushed*0.1:
		fmt.Println(c("32", "  ZERO-RATED: balance barely moved"))
	case used >= pushed*0.7:
		fmt.Println(c("31", "  BILLED: the carrier charged this traffic"))
	default:
		fmt.Println(c("33", "  PARTLY BILLED / unclear: repeat with a bigger -quota"))
	}
}

// ---------------------------------------------------------------- errors

func classifyNetErr(stage string, err error) (string, string) {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return stage + "_TIMEOUT", "no response (filtered?)"
	}
	m := strings.ToLower(err.Error())
	switch {
	case strings.Contains(m, "refused"):
		return stage + "_REFUSED", "port closed"
	case strings.Contains(m, "reset"):
		return stage + "_RESET", "RST (DPI / firewall?)"
	case strings.Contains(m, "unreachable"):
		return stage + "_UNREACH", shortErr(err)
	}
	return stage + "_FAIL", shortErr(err)
}

func classifyTLSErr(err error) (string, string) {
	m := strings.ToLower(err.Error())
	switch {
	case strings.Contains(m, "unrecognized name"):
		return "TLS_REJECT", "server refuses this SNI"
	case strings.Contains(m, "handshake failure"):
		return "TLS_REJECT", "handshake failure (SNI not served here?)"
	case strings.Contains(m, "deadline") || strings.Contains(m, "timeout"):
		return "TLS_TIMEOUT", "handshake stalled (SNI filtered?)"
	case strings.Contains(m, "reset"):
		return "TLS_RESET", "RST during handshake (DPI blocks this SNI?)"
	case strings.Contains(m, "eof"):
		return "TLS_CLOSED", "closed during handshake (blocked?)"
	}
	return "TLS_FAIL", shortErr(err)
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 80 {
		s = s[i+2:]
	}
	return s
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	}
	return "?"
}

// ---------------------------------------------------------------- output

var stderrTTY = func() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

var colorOn = func() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func c(code, s string) string {
	if !colorOn {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func ms(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return strconv.FormatInt(d.Milliseconds(), 10)
}

func printTable(cfg *config, rs []*result) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	type paint struct{ word, col string }
	var paints [][]paint
	hdr := "#\tSNI\tCONNECT\tRESULT\tTLS\tCERT\tHTTP\tSERVER\tTCP/TLS/RSP ms"
	if cfg.zr {
		hdr += "\tZERO-RATE"
	}
	fmt.Fprintln(tw, hdr)
	okN := 0
	for _, r := range rs {
		addr := r.target
		if r.ip != "" && r.ip != r.target {
			addr += " (" + r.ip + ")"
		}
		addr += ":" + strconv.Itoa(r.port)
		verdict := r.verdict
		col := "31"
		switch {
		case r.ok():
			col = "32"
			okN++
		case r.verdict == "CAPTIVE":
			col = "33"
		}
		cert := "-"
		if r.certCN != "" {
			cert = r.certCN
			if r.certMatch {
				cert = "match"
			} else if len(cert) > 28 {
				cert = cert[:28] + "~"
			}
		}
		httpS := "-"
		if r.status != 0 {
			httpS = strconv.Itoa(r.status)
		}
		tlsS := "-"
		if r.tlsVer != "" {
			tlsS = r.tlsVer
			if r.alpn != "" {
				tlsS += " " + r.alpn
			}
		}
		server := r.server
		if len(server) > 18 {
			server = server[:18]
		}
		if server == "" {
			server = "-"
		}
		line := fmt.Sprintf("%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s/%s/%s",
			r.idx+1, r.sni, addr, verdict, tlsS, cert, httpS, server, ms(r.tConnect), ms(r.tTLS), ms(r.tFirstRsp))
		ps := []paint{{verdict, col}}
		if cfg.zr {
			zs, zcol := zrString(r.zr)
			line += "\t" + zs
			if r.zr != nil {
				ps = append(ps, paint{r.zr.verdict, zcol})
			}
		}
		paints = append(paints, ps)
		fmt.Fprintln(tw, line)
	}
	tw.Flush()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	fmt.Println(c("1", lines[0]))
	for i, ln := range lines[1:] {
		for pi, p := range paints[i] {
			j := strings.Index(ln, "  "+p.word) // RESULT column: first match
			if pi > 0 {
				j = strings.LastIndex(ln, "  "+p.word) // ZERO-RATE column: last column
			}
			if j >= 0 {
				k := j + 2
				ln = ln[:k] + c(p.col, p.word) + ln[k+len(p.word):]
			}
		}
		fmt.Println(ln)
	}

	var notes []string
	for _, r := range rs {
		if r.detail != "" {
			notes = append(notes, fmt.Sprintf("  #%d %s: %s", r.idx+1, r.verdict, r.detail))
		}
		if r.zr != nil && r.zr.detail != "" {
			notes = append(notes, fmt.Sprintf("  #%d zero-rate %s: %s", r.idx+1, r.zr.verdict, r.zr.detail))
		}
	}
	if len(notes) > 0 {
		fmt.Println("\nNotes:")
		fmt.Println(strings.Join(notes, "\n"))
	}
	fmt.Printf("\n%d/%d working (TLS%s ok)\n", okN, len(rs), map[bool]string{true: "", false: " + payload"}[cfg.noHTTP])
	if cfg.zr {
		fmt.Println("ZERO-RATE: FLOWING = data kept flowing with no balance (likely zero-rated); STALLED/CUT/CAPTIVE = billed or blocked.")
	} else {
		fmt.Println("Zero-rating not tested. Add -zr (no balance, VPN off) or -quota MB for a measured test.")
	}
}

func zrString(z *zrResult) (string, string) {
	if z == nil {
		return "-", ""
	}
	rate := ""
	if z.dur > 0 && z.bytes > 0 {
		rate = fmt.Sprintf(" @%s/s", human(int64(float64(z.bytes)/z.dur.Seconds())))
	}
	col := "31"
	switch z.verdict {
	case "FLOWING":
		col = "32"
	case "INCONCLUSIVE", "TIMEOUT":
		col = "33"
	}
	return z.verdict + " " + human(z.bytes) + rate, col
}

func writeOK(path string, rs []*result) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "write -o:", err)
		return
	}
	defer f.Close()
	n := 0
	for _, r := range rs {
		if r.ok() && (r.zr == nil || r.zr.verdict == "FLOWING") {
			fmt.Fprintf(f, "%s@%s:%d\n", r.sni, r.target, r.port)
			n++
		}
	}
	fmt.Printf("wrote %d working candidates to %s\n", n, path)
}

func writeCSV(path string, rs []*result) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "write -csv:", err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"sni", "target", "ip", "port", "result", "detail", "tls", "alpn", "cert_cn", "cert_match",
		"http", "server", "location", "tcp_ms", "tls_ms", "rsp_ms", "zr_verdict", "zr_bytes", "zr_secs", "zr_detail"})
	for _, r := range rs {
		zv, zb, zs, zd := "", "", "", ""
		if r.zr != nil {
			zv, zb, zs, zd = r.zr.verdict, strconv.FormatInt(r.zr.bytes, 10), fmt.Sprintf("%.1f", r.zr.dur.Seconds()), r.zr.detail
		}
		w.Write([]string{r.sni, r.target, r.ip, strconv.Itoa(r.port), r.verdict, r.detail, r.tlsVer, r.alpn, r.certCN,
			strconv.FormatBool(r.certMatch), strconv.Itoa(r.status), r.server, r.location,
			ms(r.tConnect), ms(r.tTLS), ms(r.tFirstRsp), zv, zb, zs, zd})
	}
	w.Flush()
	fmt.Printf("wrote %s\n", path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// ---------------------------------------------------------------- JSON output (Android app)

var emitMu sync.Mutex

func emit(v map[string]any) {
	b, _ := json.Marshal(v)
	emitMu.Lock()
	os.Stdout.Write(append(b, '\n'))
	emitMu.Unlock()
}

// zrProgress returns a throttled callback that reports zero-rate bytes as JSON (nil when not in -json mode).
func zrProgress(cfg *config, cd candidate) func(int64) {
	if !cfg.json {
		return nil
	}
	var last time.Time
	return func(n int64) {
		if time.Since(last) < 400*time.Millisecond {
			return
		}
		last = time.Now()
		emit(map[string]any{"type": "zr", "idx": cd.idx, "sni": cd.sni, "bytes": n, "want": cfg.zrBytes})
	}
}

func emitResult(r *result, done, total int) {
	m := map[string]any{
		"type": "result", "idx": r.idx, "done": done, "total": total,
		"sni": r.sni, "target": r.target, "ip": r.ip, "port": r.port,
		"verdict": r.verdict, "detail": r.detail, "ok": r.ok(),
		"tls": r.tlsVer, "alpn": r.alpn, "cert": r.certCN, "certMatch": r.certMatch,
		"http": r.status, "server": r.server, "location": r.location,
		"tcpMs": r.tConnect.Milliseconds(), "tlsMs": r.tTLS.Milliseconds(), "rspMs": r.tFirstRsp.Milliseconds(),
	}
	if r.zr != nil {
		m["zrVerdict"] = r.zr.verdict
		m["zrBytes"] = r.zr.bytes
		m["zrSecs"] = r.zr.dur.Seconds()
		m["zrDetail"] = r.zr.detail
	}
	emit(m)
}
