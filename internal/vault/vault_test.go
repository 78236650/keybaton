package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// 密文换行：把 A 行的 cipher/nonce 挪到 B 行，必须解密失败。
// 这是 v0.2 之前真实存在的漏洞（AAD 未绑定条目名）。
func TestCiphertextSwapFails(t *testing.T) {
	s := newStore(t)
	if err := s.Put("github", "me", "", "GITHUB-SECRET"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("aws", "me", "", "AWS-SECRET"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(s.Dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var gct, gnonce, act, anonce []byte
	if err := db.QueryRow(`SELECT cipher,nonce FROM secrets WHERE name='github'`).Scan(&gct, &gnonce); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT cipher,nonce FROM secrets WHERE name='aws'`).Scan(&act, &anonce); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE secrets SET cipher=?,nonce=? WHERE name='github'`, act, anonce); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE secrets SET cipher=?,nonce=? WHERE name='aws'`, gct, gnonce); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("github"); err == nil {
		t.Fatal("交换密文后仍然解密成功——AAD 没有生效")
	}
	if _, err := s.Get("aws"); err == nil {
		t.Fatal("交换密文后仍然解密成功——AAD 没有生效")
	}
}

// 篡改密文任意一字节必须被 GCM tag 拦住。
func TestTamperDetected(t *testing.T) {
	s := newStore(t)
	if err := s.Put("k", "", "", "VALUE"); err != nil {
		t.Fatal(err)
	}
	db, _ := sql.Open("sqlite", filepath.Join(s.Dir, "vault.db"))
	defer db.Close()
	var ct []byte
	if err := db.QueryRow(`SELECT cipher FROM secrets WHERE name='k'`).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0x01
	if _, err := db.Exec(`UPDATE secrets SET cipher=? WHERE name='k'`, ct); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("k"); err == nil {
		t.Fatal("篡改密文后仍然解密成功")
	}
}

// 轮换后数据可读、key_id 前进、新写入用新密钥。
func TestRotateKeepsData(t *testing.T) {
	s := newStore(t)
	if err := s.Put("a", "u", "", "AAA"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("b", "u", "", "BBB"); err != nil {
		t.Fatal(err)
	}
	oldID := s.ActiveKeyID()
	old, newID, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if old != oldID || newID != oldID+1 {
		t.Fatalf("key_id 不符合预期: old=%d new=%d (原 %d)", old, newID, oldID)
	}
	for name, want := range map[string]string{"a": "AAA", "b": "BBB"} {
		e, err := s.Get(name)
		if err != nil {
			t.Fatalf("轮换后读取 %s 失败: %v", name, err)
		}
		if e.Secret != want {
			t.Fatalf("%s 明文变了: %q", name, e.Secret)
		}
	}
	// 所有条目都应换成新 key_id
	db, _ := sql.Open("sqlite", filepath.Join(s.Dir, "vault.db"))
	defer db.Close()
	var oldCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE key_id<>?`, newID).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatalf("还有 %d 条没换密钥", oldCount)
	}
}

// 老库（fmt=0、无 AAD、master.key 单密钥）打开时自动迁移到 v2 且数据不变。
func TestMigrateFromV1(t *testing.T) {
	dir := t.TempDir()
	// 用 v1 方式写一条：master.key + 裸 GCM
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(dir, "master.key"),
		[]byte(encodeB64(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	aead := mustGCM(t, key)
	nonce := make([]byte, aead.NonceSize())
	for i := range nonce {
		nonce[i] = byte(i + 10)
	}
	ct := aead.Seal(nil, nonce, []byte("LEGACY-SECRET"), nil)

	db, err := sql.Open("sqlite", filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO secrets(name,username,note,cipher,nonce,created_at,updated_at)
VALUES('legacy','u','',?,?,'2026-01-01 00:00:00','2026-01-01 00:00:00')`, ct, nonce); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("打开老库失败: %v", err)
	}
	defer s.Close()
	e, err := s.Get("legacy")
	if err != nil {
		t.Fatalf("迁移后读不到: %v", err)
	}
	if e.Secret != "LEGACY-SECRET" {
		t.Fatalf("明文不符: %q", e.Secret)
	}
	// 迁移后应标记为 v2
	db2, _ := sql.Open("sqlite", filepath.Join(dir, "vault.db"))
	defer db2.Close()
	var f int
	if err := db2.QueryRow(`SELECT fmt FROM secrets WHERE name='legacy'`).Scan(&f); err != nil {
		t.Fatal(err)
	}
	if f != FmtV2 {
		t.Fatalf("fmt 未升级: %d", f)
	}
	// 迁移后仍然不能换行解密
	var ct2, n2 []byte
	if err := db2.QueryRow(`SELECT cipher,nonce FROM secrets WHERE name='legacy'`).Scan(&ct2, &n2); err != nil {
		t.Fatal(err)
	}
	if _, err := db2.Exec(`INSERT INTO secrets(name,username,note,cipher,nonce,created_at,updated_at,fmt,key_id)
VALUES('other','','',?,?,'x','x',2,1)`, ct2, n2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("other"); err == nil {
		t.Fatal("迁移后密文仍可跨条目复用")
	}
}

func TestHostAllowed(t *testing.T) {
	cases := []struct {
		allow, host string
		want        bool
	}{
		{"", "api.github.com", false},
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "API.GitHub.com", true},
		{"api.github.com", "evil.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "badexample.com", false},
		{"a.com, b.com", "b.com", true},
		{"a.com,", "a.com", true},
	}
	for _, c := range cases {
		if got := HostAllowed(c.allow, c.host); got != c.want {
			t.Errorf("HostAllowed(%q,%q)=%v want %v", c.allow, c.host, got, c.want)
		}
	}
}
