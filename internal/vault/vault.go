// Package vault 实现本地加密存储：AES-256-GCM 逐条加密，SQLite 单文件。
//
// 密文格式（v2）：
//
//	cipher = AES-256-GCM 密文（含 tag）
//	nonce  = 12 字节随机数
//	AAD    = "v2" ‖ key_id(2 字节大端) ‖ name
//
// 为什么要 AAD：不加绑定时，只要有人能写 vault.db，就能把 A 行的密文挪到 B 行，
// 服务端会用 B 的名字解出 A 的密钥，然后把 A 的密钥发到攻击者指定的地址。
// 绑定 name 之后，这种替换在解密阶段就会直接失败。
//
// 密钥环（keys.json）：
//
//	{"active": 2, "keys": {"1": "<base64 32B>", "2": "..."}}
//
// 保留旧密钥是为了 rotate 之后仍能读历史密文，也为了出错能回滚。
// 老版本只有 master.key 单文件，打开时自动导入为 key_id=1。
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

	// FmtV2 = 当前密文格式（AAD 绑定 + key_id）。0 表示 v1（裸 GCM）。
	FmtV2 = 2

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

// 需要补的列（老库自动迁移）
var addColumns = [][3]string{
	{"secrets", "fmt", "INTEGER DEFAULT 0"},
	{"secrets", "key_id", "INTEGER DEFAULT 0"},
	{"secrets", "allow_hosts", "TEXT DEFAULT ''"},
}

var (
	ErrNotFound  = errors.New("secret not found")
	ErrBadMaster = errors.New("master key invalid (want 32 bytes, base64)")
)

// Store 是打开的库。
type Store struct {
	db     *sql.DB
	aeads  map[int]cipher.AEAD
	active int
	Dir    string
}

// Entry 是带明文的读取结果（只在 get/run 内部短暂存在）。
type Entry struct {
	Name       string
	Username   string
	Note       string
	Secret     string
	AllowHosts string
}

// Meta 是列表用的元数据，永不含明文。
type Meta struct {
	Name       string `json:"name"`
	Username   string `json:"username"`
	Note       string `json:"note"`
	AllowHosts string `json:"allow_hosts,omitempty"`
	UpdatedAt  string `json:"updated_at"`
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

// HomeDir 返回库目录：$KEYBATON_HOME 或 ~/.keybaton
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

type keyFile struct {
	Active int               `json:"active"`
	Keys   map[string]string `json:"keys"` // key_id -> base64(32B)
}

// Open 打开（必要时初始化）库。
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}
	kf, err := loadOrCreateKeyring(dir)
	if err != nil {
		return nil, err
	}
	aeads := map[int]cipher.AEAD{}
	for idStr, b64 := range kf.Keys {
		var id int
		if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
			continue
		}
		k, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if derr != nil || len(k) != 32 {
			return nil, fmt.Errorf("key %s: %w", idStr, ErrBadMaster)
		}
		block, berr := aes.NewCipher(k)
		if berr != nil {
			return nil, berr
		}
		aead, gerr := cipher.NewGCM(block)
		if gerr != nil {
			return nil, gerr
		}
		aeads[id] = aead
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "vault.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	for _, c := range addColumns {
		_, _ = db.Exec("ALTER TABLE " + c[0] + " ADD COLUMN " + c[1] + " " + c[2])
	}
	s := &Store{db: db, aeads: aeads, active: kf.Active, Dir: dir}
	if err := s.migrateToV2(); err != nil {
		db.Close()
		return nil, fmt.Errorf("迁移到 v2 失败: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ActiveKeyID 返回当前用于加密的 key_id（运维与测试用）。
func (s *Store) ActiveKeyID() int { return s.active }

func loadOrCreateKeyring(dir string) (keyFile, error) {
	// 1) 环境变量优先（CI / 容器）：导入为 key 1，不落盘
	if b64 := os.Getenv(EnvMasterKey); b64 != "" {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil || len(k) != 32 {
			return keyFile{}, ErrBadMaster
		}
		return keyFile{Active: 1, Keys: map[string]string{"1": base64.StdEncoding.EncodeToString(k)}}, nil
	}
	// 2) keys.json
	p := filepath.Join(dir, "keys.json")
	if b, err := os.ReadFile(p); err == nil {
		var kf keyFile
		if err := json.Unmarshal(b, &kf); err != nil {
			return keyFile{}, fmt.Errorf("解析 keys.json: %w", err)
		}
		if kf.Keys == nil || kf.Active == 0 {
			return keyFile{}, errors.New("keys.json 不完整（缺 active 或 keys）")
		}
		return kf, nil
	}
	// 3) 老版本 master.key → 导入为 key 1
	if b, err := os.ReadFile(filepath.Join(dir, "master.key")); err == nil {
		k, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(k) != 32 {
			return keyFile{}, ErrBadMaster
		}
		kf := keyFile{Active: 1, Keys: map[string]string{"1": base64.StdEncoding.EncodeToString(k)}}
		if err := saveKeyring(dir, kf); err != nil {
			return keyFile{}, err
		}
		return kf, nil
	}
	// 4) 全新库
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return keyFile{}, err
	}
	kf := keyFile{Active: 1, Keys: map[string]string{"1": base64.StdEncoding.EncodeToString(k)}}
	if err := saveKeyring(dir, kf); err != nil {
		return keyFile{}, err
	}
	return kf, nil
}

func saveKeyring(dir string, kf keyFile) error {
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "keys.json"), append(b, '\n'), 0o600)
}

// aad 构造附加认证数据：格式版本 ‖ key_id ‖ 条目名。
func aad(fmtVer, keyID int, name string) []byte {
	b := make([]byte, 4, 4+len(name))
	b[0] = byte(fmtVer)
	binary.BigEndian.PutUint16(b[2:4], uint16(keyID))
	return append(b, name...)
}

func (s *Store) seal(name, secret string) (ct, nonce []byte, keyID int, err error) {
	keyID = s.active
	aead, ok := s.aeads[keyID]
	if !ok {
		return nil, nil, 0, fmt.Errorf("key_id %d 不在密钥环里", keyID)
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, 0, err
	}
	ct = aead.Seal(nil, nonce, []byte(secret), aad(FmtV2, keyID, name))
	return ct, nonce, keyID, nil
}

func (s *Store) open(name string, ct, nonce []byte, fmtVer, keyID int) (string, error) {
	if fmtVer == 0 {
		aead, ok := s.aeads[1]
		if !ok {
			return "", errors.New("缺少 key 1，无法解密 v1 密文")
		}
		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return "", fmt.Errorf("decrypt(v1): %w", err)
		}
		return string(pt), nil
	}
	aead, ok := s.aeads[keyID]
	if !ok {
		return "", fmt.Errorf("缺少 key_id=%d，无法解密（密钥环被删过？）", keyID)
	}
	pt, err := aead.Open(nil, nonce, ct, aad(fmtVer, keyID, name))
	if err != nil {
		return "", fmt.Errorf("decrypt(v2): %w（密文与条目名不匹配，可能被替换过）", err)
	}
	return string(pt), nil
}

// migrateToV2 把 fmt=0 的老条目重写成 v2。失败即中止，不动原数据。
func (s *Store) migrateToV2() error {
	rows, err := s.db.Query(`SELECT name, cipher, nonce FROM secrets WHERE COALESCE(fmt,0)=0`)
	if err != nil {
		return err
	}
	type item struct {
		name  string
		ct    []byte
		nonce []byte
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.name, &it.ct, &it.nonce); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	if len(items) == 0 {
		return nil
	}
	type out struct {
		name  string
		ct    []byte
		nonce []byte
		key   int
	}
	outs := make([]out, 0, len(items))
	for _, it := range items {
		pt, err := s.open(it.name, it.ct, it.nonce, 0, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", it.name, err)
		}
		ct, nonce, kid, err := s.seal(it.name, pt)
		if err != nil {
			return err
		}
		outs = append(outs, out{it.name, ct, nonce, kid})
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, o := range outs {
		if _, err := tx.Exec(`UPDATE secrets SET cipher=?, nonce=?, fmt=?, key_id=? WHERE name=?`,
			o.ct, o.nonce, FmtV2, o.key, o.name); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func now() string { return time.Now().Format("2006-01-02 15:04:05") }

// Put 新增或更新一条密钥。
func (s *Store) Put(name, username, note, secret string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("name required")
	}
	ct, nonce, kid, err := s.seal(name, secret)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO secrets(name, username, note, cipher, nonce, created_at, updated_at, fmt, key_id)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET
  username=excluded.username, note=excluded.note, cipher=excluded.cipher,
  nonce=excluded.nonce, updated_at=excluded.updated_at, fmt=excluded.fmt, key_id=excluded.key_id`,
		name, username, note, ct, nonce, now(), now(), FmtV2, kid)
	return err
}

// Get 取明文（调用方负责不落日志）。
func (s *Store) Get(name string) (Entry, error) {
	var e Entry
	var ct, nonce []byte
	var f, kid int
	var hosts sql.NullString
	err := s.db.QueryRow(`SELECT name,username,note,cipher,nonce,COALESCE(fmt,0),COALESCE(key_id,0),COALESCE(allow_hosts,'')
FROM secrets WHERE name=?`, name).
		Scan(&e.Name, &e.Username, &e.Note, &ct, &nonce, &f, &kid, &hosts)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	if err != nil {
		return e, err
	}
	e.AllowHosts = hosts.String
	pt, err := s.open(e.Name, ct, nonce, f, kid)
	if err != nil {
		return e, err
	}
	e.Secret = pt
	return e, nil
}

// List 只返回元数据。
func (s *Store) List() ([]Meta, error) {
	rows, err := s.db.Query(`SELECT name,username,note,COALESCE(allow_hosts,''),updated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Meta
	for rows.Next() {
		var m Meta
		if err := rows.Scan(&m.Name, &m.Username, &m.Note, &m.AllowHosts, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// All 取全部明文，供 run 注入环境变量。
func (s *Store) All() (map[string]Entry, error) {
	rows, err := s.db.Query(`SELECT name,username,note,cipher,nonce,COALESCE(fmt,0),COALESCE(key_id,0),COALESCE(allow_hosts,'')
FROM secrets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Entry{}
	for rows.Next() {
		var e Entry
		var ct, nonce []byte
		var f, kid int
		var hosts sql.NullString
		if err := rows.Scan(&e.Name, &e.Username, &e.Note, &ct, &nonce, &f, &kid, &hosts); err != nil {
			return nil, err
		}
		pt, derr := s.open(e.Name, ct, nonce, f, kid)
		if derr != nil {
			return nil, fmt.Errorf("%s: %w", e.Name, derr)
		}
		e.Secret = pt
		e.AllowHosts = hosts.String
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

// SetAllowHosts 设置某条允许外发的主机（逗号分隔；空 = 禁止外发）。
func (s *Store) SetAllowHosts(name, hosts string) error {
	res, err := s.db.Exec(`UPDATE secrets SET allow_hosts=? WHERE name=?`, hosts, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// HostAllowed 判断目标主机是否在该条目的白名单里。
// 空名单 = 一律拒绝（默认安全）；支持 *.example.com 通配。
func HostAllowed(allowHosts, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	for _, raw := range strings.Split(allowHosts, ",") {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, p[1:]) || host == p[2:] {
				return true
			}
			continue
		}
		if host == p {
			return true
		}
	}
	return false
}

// Rotate 生成新的 key_id 并把全部条目重新加密，旧密钥保留在密钥环里。
func (s *Store) Rotate() (oldID, newID int, err error) {
	oldID = s.active
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return 0, 0, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return 0, 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return 0, 0, err
	}
	newID = oldID + 1
	s.aeads[newID] = aead

	kfPath := filepath.Join(s.Dir, "keys.json")
	b, err := os.ReadFile(kfPath)
	if err != nil {
		b = []byte(`{"active":0,"keys":{}}`)
	}
	var kf keyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return 0, 0, err
	}
	if kf.Keys == nil {
		kf.Keys = map[string]string{}
	}
	kf.Keys[fmt.Sprintf("%d", newID)] = base64.StdEncoding.EncodeToString(k)
	kf.Active = newID
	if err := saveKeyring(s.Dir, kf); err != nil {
		return 0, 0, err
	}

	rows, err := s.db.Query(`SELECT name, cipher, nonce, COALESCE(fmt,0), COALESCE(key_id,0) FROM secrets`)
	if err != nil {
		return 0, 0, err
	}
	type rec struct {
		name  string
		ct    []byte
		nonce []byte
		f     int
		kid   int
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.name, &r.ct, &r.nonce, &r.f, &r.kid); err != nil {
			rows.Close()
			return 0, 0, err
		}
		recs = append(recs, r)
	}
	rows.Close()

	s.active = newID
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	for _, r := range recs {
		pt, derr := s.open(r.name, r.ct, r.nonce, r.f, r.kid)
		if derr != nil {
			tx.Rollback()
			s.active = oldID
			return 0, 0, fmt.Errorf("%s: %w", r.name, derr)
		}
		nct, nnonce, nkid, serr := s.seal(r.name, pt)
		if serr != nil {
			tx.Rollback()
			s.active = oldID
			return 0, 0, serr
		}
		if _, err := tx.Exec(`UPDATE secrets SET cipher=?, nonce=?, fmt=?, key_id=? WHERE name=?`,
			nct, nnonce, FmtV2, nkid, r.name); err != nil {
			tx.Rollback()
			s.active = oldID
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		s.active = oldID
		return 0, 0, err
	}
	return oldID, newID, nil
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
