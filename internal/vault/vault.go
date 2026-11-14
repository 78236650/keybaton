// Package vault 实现本地加密存储：AES-256-GCM 逐条加密，SQLite 单文件。
//
// 设计取舍：
//   - 主密钥与数据库分开存（master.key 0600，或环境变量 KEYBATON_MASTER_KEY）；
//   - 每条 secret 独立 nonce，避免重用；
//   - 只存密文，任何列表接口都不返回明文。
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	EnvHome      = "KEYBATON_HOME"
	EnvMasterKey = "KEYBATON_MASTER_KEY"

	schema = `
CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  username TEXT DEFAULT '',
  note TEXT DEFAULT '',
  cipher BLOB NOT NULL,
  nonce BLOB NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT DEFAULT '',
  ok INTEGER NOT NULL,
  detail TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
`
)

var (
	ErrNotFound  = errors.New("secret not found")
	ErrBadMaster = errors.New("master key invalid (want 32 bytes, base64)")
)

// Store 是打开的库。
type Store struct {
	db   *sql.DB
	aead cipher.AEAD
	Dir  string
}

// Entry 是带明文的读取结果（只在 get/run 内部短暂存在）。
type Entry struct {
	Name     string
	Username string
	Note     string
	Secret   string
}

// Meta 是列表用的元数据，永不含明文。
type Meta struct {
	Name      string `json:"name"`
	Username  string `json:"username"`
	Note      string `json:"note"`
	UpdatedAt string `json:"updated_at"`
}

// AuditRow 是一条审计。
type AuditRow struct {
	TS     string `json:"ts"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Dir 返回库目录：$KEYBATON_HOME 或 ~/.keybaton
func HomeDir() string {
	if v := os.Getenv(EnvHome); v != "" {
		return v
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ".keybaton"
	}
	return filepath.Join(h, ".keybaton")
}

// Open 打开（必要时初始化）库。init=false 时目录不存在会报错。
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}
	key, err := loadOrCreateKey(dir)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "vault.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db, aead: aead, Dir: dir}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func loadOrCreateKey(dir string) ([]byte, error) {
	if b64 := os.Getenv(EnvMasterKey); b64 != "" {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil || len(k) != 32 {
			return nil, ErrBadMaster
		}
		return k, nil
	}
	path := filepath.Join(dir, "master.key")
	if b, err := os.ReadFile(path); err == nil {
		k, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(k) != 32 {
			return nil, ErrBadMaster
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(k)
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	return k, nil
}

func now() string { return time.Now().Format("2006-01-02 15:04:05") }

// Put 新增或更新一条密钥。
func (s *Store) Put(name, username, note, secret string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("name required")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, []byte(secret), nil)
	_, err := s.db.Exec(`
INSERT INTO secrets(name, username, note, cipher, nonce, created_at, updated_at)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET
  username=excluded.username, note=excluded.note, cipher=excluded.cipher,
  nonce=excluded.nonce, updated_at=excluded.updated_at`,
		name, username, note, ct, nonce, now(), now())
	return err
}

// Get 取明文（调用方负责不落日志）。
func (s *Store) Get(name string) (Entry, error) {
	var e Entry
	var ct, nonce []byte
	err := s.db.QueryRow(`SELECT name,username,note,cipher,nonce FROM secrets WHERE name=?`, name).
		Scan(&e.Name, &e.Username, &e.Note, &ct, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	if err != nil {
		return e, err
	}
	pt, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return e, fmt.Errorf("decrypt: %w", err)
	}
	e.Secret = string(pt)
	return e, nil
}

// List 只返回元数据。
func (s *Store) List() ([]Meta, error) {
	rows, err := s.db.Query(`SELECT name,username,note,updated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Meta
	for rows.Next() {
		var m Meta
		if err := rows.Scan(&m.Name, &m.Username, &m.Note, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// All 取全部明文，供 run 注入环境变量。
func (s *Store) All() (map[string]Entry, error) {
	rows, err := s.db.Query(`SELECT name,username,note,cipher,nonce FROM secrets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Entry{}
	for rows.Next() {
		var e Entry
		var ct, nonce []byte
		if err := rows.Scan(&e.Name, &e.Username, &e.Note, &ct, &nonce); err != nil {
			return nil, err
		}
		pt, derr := s.aead.Open(nil, nonce, ct, nil)
		if derr != nil {
			return nil, fmt.Errorf("decrypt %s: %w", e.Name, derr)
		}
		e.Secret = string(pt)
		out[e.Name] = e
	}
	return out, rows.Err()
}

// Delete 删除一条。
func (s *Store) Delete(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM secrets WHERE name=?`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Audit 写一条审计（失败忽略，不影响主流程）。
func (s *Store) Audit(actor, action, target string, ok bool, detail string) {
	b := 0
	if ok {
		b = 1
	}
	_, _ = s.db.Exec(`INSERT INTO audit(ts,actor,action,target,ok,detail) VALUES(?,?,?,?,?,?)`,
		now(), actor, action, target, b, detail)
}

// AuditTail 取最近 n 条。
func (s *Store) AuditTail(n int) ([]AuditRow, error) {
	if n <= 0 {
		n = 50
	}
	rows, err := s.db.Query(`SELECT ts,actor,action,target,ok,detail FROM audit ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var a AuditRow
		var ok int
		if err := rows.Scan(&a.TS, &a.Actor, &a.Action, &a.Target, &ok, &a.Detail); err != nil {
			return nil, err
		}
		a.OK = ok == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// EnvName 把密钥名转成合法的环境变量名：KEYBATON_<UPPER_UNDERSCORE>
func EnvName(name string) string {
	var b strings.Builder
	b.WriteString("KEYBATON_")
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
