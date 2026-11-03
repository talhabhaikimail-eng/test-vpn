//go:build linux

// onic-agent: tiny per-VPS stats pusher. Reads only /proc and statfs every
// INTERVAL seconds and POSTs ~1 KB of JSON to the control plane, HMAC-signed.
// Config from env (systemd EnvironmentFile=/etc/onic-agent.env):
//
//	ONIC_NODE=mux4  ONIC_KEY=...  ONIC_URL=https://api.talhacodes.site/v1/agent/push
//	ONIC_PORTS=80,443          (listening ports whose ESTABLISHED sockets count as connections)
//	ONIC_SERVICES=xray,x-ui    (systemd units to report)
//	ONIC_STATS_URL=http://127.0.0.1:8089/stats  (optional: app-level JSON merged in as "app")
//	ONIC_INTERVAL=30
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type sample struct {
	TS          int64             `json:"ts"`
	Host        string            `json:"host"`
	CPU         float64           `json:"cpu"`
	Load1       float64           `json:"load1"`
	MemTotalMB  int64             `json:"mem_total_mb"`
	MemUsedMB   int64             `json:"mem_used_mb"`
	MemAvailMB  int64             `json:"mem_avail_mb"`
	SwapTotalMB int64             `json:"swap_total_mb"`
	SwapUsedMB  int64             `json:"swap_used_mb"`
	DiskTotalGB float64           `json:"disk_total_gb"`
	DiskUsedGB  float64           `json:"disk_used_gb"`
	RxBps       int64             `json:"rx_bps"`
	TxBps       int64             `json:"tx_bps"`
	RxTotal     uint64            `json:"rx_total"`
	TxTotal     uint64            `json:"tx_total"`
	Conns       int               `json:"conns"`
	ConnsByPort map[string]int    `json:"conns_by_port"`
	UptimeS     int64             `json:"uptime_s"`
	Services    map[string]string `json:"services,omitempty"`
	App         json.RawMessage   `json:"app,omitempty"`
	Agent       string            `json:"agent"`
}

const version = "1"

func main() {
	node, key, url := os.Getenv("ONIC_NODE"), os.Getenv("ONIC_KEY"), os.Getenv("ONIC_URL")
	if node == "" || key == "" || url == "" {
		log.Fatal("ONIC_NODE, ONIC_KEY and ONIC_URL are required")
	}
	interval := 30
	if v, _ := strconv.Atoi(os.Getenv("ONIC_INTERVAL")); v >= 10 {
		interval = v
	}
	ports := map[uint16]string{}
	for _, p := range strings.Split(envOr("ONIC_PORTS", "80,443"), ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			ports[uint16(n)] = strconv.Itoa(n)
		}
	}
	var services []string
	for _, s := range strings.Split(os.Getenv("ONIC_SERVICES"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			services = append(services, s)
		}
	}
	appURL := os.Getenv("ONIC_STATS_URL")
	host, _ := os.Hostname()
	client := &http.Client{Timeout: 15 * time.Second}

	prevIdle, prevTotal := cpuTimes()
	prevRx, prevTx := netBytes()
	prevT := time.Now()
	for {
		time.Sleep(time.Duration(interval) * time.Second)
		s := sample{TS: time.Now().Unix(), Host: host, Agent: version, ConnsByPort: map[string]int{}}

		idle, total := cpuTimes()
		if dt := total - prevTotal; dt > 0 {
			s.CPU = round1(100 * float64(dt-(idle-prevIdle)) / float64(dt))
		}
		prevIdle, prevTotal = idle, total

		now := time.Now()
		rx, tx := netBytes()
		if secs := now.Sub(prevT).Seconds(); secs > 0 && rx >= prevRx && tx >= prevTx {
			s.RxBps, s.TxBps = int64(float64(rx-prevRx)/secs), int64(float64(tx-prevTx)/secs)
		}
		s.RxTotal, s.TxTotal = rx, tx
		prevRx, prevTx, prevT = rx, tx, now

		mem := meminfo()
		s.MemTotalMB = mem["MemTotal"] / 1024
		s.MemAvailMB = mem["MemAvailable"] / 1024
		s.MemUsedMB = s.MemTotalMB - s.MemAvailMB
		s.SwapTotalMB = mem["SwapTotal"] / 1024
		s.SwapUsedMB = (mem["SwapTotal"] - mem["SwapFree"]) / 1024

		if b, err := os.ReadFile("/proc/loadavg"); err == nil {
			if f := strings.Fields(string(b)); len(f) > 0 {
				s.Load1, _ = strconv.ParseFloat(f[0], 64)
			}
		}
		if b, err := os.ReadFile("/proc/uptime"); err == nil {
			if f := strings.Fields(string(b)); len(f) > 0 {
				u, _ := strconv.ParseFloat(f[0], 64)
				s.UptimeS = int64(u)
			}
		}
		var st syscall.Statfs_t
		if syscall.Statfs("/", &st) == nil {
			s.DiskTotalGB = round1(float64(st.Blocks*uint64(st.Bsize)) / 1e9)
			s.DiskUsedGB = round1(float64((st.Blocks-st.Bfree)*uint64(st.Bsize)) / 1e9)
		}
		for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
			countEstablished(f, ports, s.ConnsByPort)
		}
		for _, n := range s.ConnsByPort {
			s.Conns += n
		}
		if len(services) > 0 {
			s.Services = map[string]string{}
			for _, svc := range services {
				s.Services[svc] = unitState(svc)
			}
		}
		if appURL != "" {
			if r, err := (&http.Client{Timeout: 3 * time.Second}).Get(appURL); err == nil {
				b, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
				r.Body.Close()
				if json.Valid(b) {
					s.App = b
				}
			}
		}
		push(client, url, node, key, &s)
	}
}

func push(c *http.Client, url, node, key string, s *sample) {
	body, _ := json.Marshal(s)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(ts + "\n"))
	m.Write(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Onic-Node", node)
	req.Header.Set("X-Onic-TS", ts)
	req.Header.Set("X-Onic-Sig", hex.EncodeToString(m.Sum(nil)))
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("push: %v", err)
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 204 {
		log.Printf("push: HTTP %d", resp.StatusCode)
	}
}

func cpuTimes() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		fields := strings.Fields(sc.Text())
		// user nice system idle iowait irq softirq steal [guest guest_nice]
		// guest time is already included in user, so stop after steal.
		for i, v := range fields[1:] {
			if i > 7 {
				break
			}
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 || i == 4 { // idle + iowait
				idle += n
			}
		}
	}
	return
}

func netBytes() (rx, tx uint64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n")[2:] {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "tun") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) >= 9 {
			r, _ := strconv.ParseUint(f[0], 10, 64)
			t, _ := strconv.ParseUint(f[8], 10, 64)
			rx += r
			tx += t
		}
	}
	return
}

func meminfo() map[string]int64 {
	out := map[string]int64{}
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) > 0 {
			n, _ := strconv.ParseInt(f[0], 10, 64)
			out[k] = n
		}
	}
	return out
}

// countEstablished counts ESTABLISHED (state 01) sockets whose LOCAL port is one
// of the service ports, i.e. inbound client connections.
func countEstablished(path string, ports map[uint16]string, out map[string]int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	sc.Scan() // header
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 4 || fl[3] != "01" {
			continue
		}
		i := strings.LastIndexByte(fl[1], ':')
		if i < 0 {
			continue
		}
		p, err := strconv.ParseUint(fl[1][i+1:], 16, 16)
		if err != nil {
			continue
		}
		if name, ok := ports[uint16(p)]; ok {
			out[name]++
		}
	}
}

// unitState reports a systemd service as active when its cgroup has processes.
// Reading cgroupfs needs no D-Bus access, so it works under DynamicUser on any
// systemd version (Ubuntu 20.04 resets unprivileged systemctl connections).
func unitState(svc string) string {
	if !strings.Contains(svc, ".") {
		svc += ".service"
	}
	for _, dir := range []string{"/sys/fs/cgroup/system.slice/", "/sys/fs/cgroup/systemd/system.slice/", "/sys/fs/cgroup/unified/system.slice/"} {
		b, err := os.ReadFile(dir + svc + "/cgroup.procs")
		if err == nil {
			if len(strings.TrimSpace(string(b))) > 0 {
				return "active"
			}
			return "inactive"
		}
	}
	return "inactive"
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }
