package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS settings (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
	id          TEXT PRIMARY KEY,           -- stable slug, e.g. mux4
	name        TEXT NOT NULL,
	location    TEXT NOT NULL DEFAULT '',
	kind        TEXT NOT NULL,              -- mux | vless-ws | xhttp | ssh | slowdns
	host        TEXT NOT NULL DEFAULT '',   -- node domain (SNI / Host)
	bug_host    TEXT NOT NULL DEFAULT '',
	bug_port    INTEGER NOT NULL DEFAULT 443,
	tls         INTEGER NOT NULL DEFAULT 1,
	path        TEXT NOT NULL DEFAULT '',
	origin_ip   TEXT NOT NULL DEFAULT '',   -- direct-connect / stats only
	payload     TEXT NOT NULL DEFAULT '',
	secret      TEXT NOT NULL DEFAULT '',   -- PSK / UUID; sent only inside device-encrypted payloads
	extra       TEXT NOT NULL DEFAULT '{}', -- free-form JSON passed to apps
	enabled     INTEGER NOT NULL DEFAULT 1,
	sort        INTEGER NOT NULL DEFAULT 100,
	agent_key   TEXT NOT NULL DEFAULT '',   -- HMAC key for the stats agent
	updated_at  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS users (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'active', -- active | disabled
	expires_at  INTEGER NOT NULL DEFAULT 0,     -- 0 = never
	max_devices INTEGER NOT NULL DEFAULT 3,
	quota_mb    INTEGER NOT NULL DEFAULT 0,     -- 0 = unlimited (informational until nodes enforce)
	grp         TEXT NOT NULL DEFAULT 'default',
	notes       TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS codes (
	code        TEXT PRIMARY KEY,
	user_id     INTEGER NOT NULL,
	uses_left   INTEGER NOT NULL DEFAULT 1,  -- -1 = unlimited
	expires_at  INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
	id          TEXT PRIMARY KEY,
	user_id     INTEGER NOT NULL,
	pubkey      TEXT NOT NULL,           -- X25519, base64
	token_hash  TEXT NOT NULL,           -- sha256(device token), hex
	platform    TEXT NOT NULL DEFAULT '',
	app_version TEXT NOT NULL DEFAULT '',
	label       TEXT NOT NULL DEFAULT '',
	revoked     INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL DEFAULT 0,
	last_ip     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);
CREATE TABLE IF NOT EXISTS ui_config (
	version     INTEGER PRIMARY KEY AUTOINCREMENT,
	body        TEXT NOT NULL,
	note        TEXT NOT NULL DEFAULT '',
	active      INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS releases (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	platform     TEXT NOT NULL,          -- android | windows
	version_code INTEGER NOT NULL,
	version_name TEXT NOT NULL,
	file         TEXT NOT NULL,
	size         INTEGER NOT NULL,
	sha256       TEXT NOT NULL,
	sig          TEXT NOT NULL,          -- Ed25519 over releaseSigInput
	rollout      INTEGER NOT NULL DEFAULT 100,
	mandatory    INTEGER NOT NULL DEFAULT 0,
	notes        TEXT NOT NULL DEFAULT '',
	active       INTEGER NOT NULL DEFAULT 1,
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS stats (
	node_id TEXT NOT NULL,
	ts      INTEGER NOT NULL,
	body    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS stats_node_ts ON stats(node_id, ts);
CREATE TABLE IF NOT EXISTS admins (
	username    TEXT PRIMARY KEY,
	pass_hash   TEXT NOT NULL,
	totp_secret TEXT NOT NULL,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	id_hash    TEXT PRIMARY KEY,
	username   TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      INTEGER NOT NULL,
	actor   TEXT NOT NULL,
	action  TEXT NOT NULL,
	detail  TEXT NOT NULL DEFAULT '',
	ip      TEXT NOT NULL DEFAULT ''
);
`

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; keeps things simple and safe
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return db, nil
}

func getSetting(db *sql.DB, k string) string {
	var v string
	_ = db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v
}

func setSetting(db *sql.DB, k, v string) error {
	_, err := db.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

func audit(db *sql.DB, actor, action, detail, ip string) {
	_, _ = db.Exec(`INSERT INTO audit(ts,actor,action,detail,ip) VALUES(?,?,?,?,?)`, time.Now().Unix(), actor, action, detail, ip)
}
