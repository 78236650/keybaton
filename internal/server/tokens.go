package server

// 令牌模型：令牌 = { name, token_hash, scopes[] }，与 nxmem / 旧 Python 版共用一套口径。
//
//	tokens.json（KEYBATON_TOKENS_FILE 指向它，默认 $KEYBATON_HOME/tokens.json）
//	{
//	  "version": 1,
//	  "tokens": [
//	    {"name": "hermes-nas", "token_hash": "<sha256 hex>", "scopes": ["kb:read", "kb:http"]},
//	    {"name": "zfg",        "token": "<明文仅首次>",        "scopes": ["kb:read", "kb:http", "kb:audit"]}
//	  ]
//	}
//
// 能力 scope：kb:read（列出条目）/ kb:http（服务端代发）/ kb:audit（读审计）/ kb:reveal（取明文，另需 --allow-get）；
// 支持 <资源>:* 与 "*"（全权）。令牌本身只在签发时显示一次，文件里存 sha256。

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Identity 是一次请求解析出的调用方：name 进审计，scopes 决定能干什么。
type Identity struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

// TokenEntry 是 tokens.json 的一条记录。
type TokenEntry struct {
	Name      string   `json:"name"`
	TokenHash string   `json:"token_hash,omitempty"`
	Token     string   `json:"token,omitempty"` // 明文仅用于首次落地；加载时折成 hash
	Scopes    []string `json:"scopes"`
	Note      string   `json:"note,omitempty"`
}

type tokenFile struct {
	Version int          `json:"version"`
	Tokens  []TokenEntry `json:"tokens"`
}

// HashToken 返回令牌的 sha256 hex：令牌只在签发时显示一次，库里只存这个。
func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// NewToken 生成一个新令牌（32 字节随机数的 hex），返回明文与 hash。
func NewToken() (string, string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// 随机源不可用时不降级，宁可失败
		panic("crypto/rand 不可用: " + err.Error())
	}
	t := hex.EncodeToString(b)
	return t, HashToken(t)
}

// LoadTokens 读取 tokens.json；顶层是数组也接受。校验 name/scopes 必填。
func LoadTokens(path string) ([]TokenEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f tokenFile
	if err := json.Unmarshal(b, &f); err != nil {
		var arr []TokenEntry
		if err2 := json.Unmarshal(b, &arr); err2 != nil {
			return nil, fmt.Errorf("tokens.json 解析失败（%s）: %w", path, err)
		}
		f.Tokens = arr
	}
	out := make([]TokenEntry, 0, len(f.Tokens))
	for i, e := range f.Tokens {
		e.Name = strings.TrimSpace(e.Name)
		e.TokenHash = strings.ToLower(strings.TrimSpace(e.TokenHash))
		if e.Name == "" {
			return nil, fmt.Errorf("tokens.json 第 %d 条缺少 name", i+1)
		}
		if e.TokenHash == "" {
			if e.Token == "" {
				return nil, fmt.Errorf("tokens.json 第 %d 条（%s）缺少 token_hash 或 token", i+1, e.Name)
			}
			e.TokenHash = HashToken(e.Token)
		}
		if len(e.Scopes) == 0 {
			return nil, fmt.Errorf("tokens.json 第 %d 条（%s）缺少 scopes；要全权请写 \"*\"", i+1, e.Name)
		}
		e.Token = "" // 明文不驻留内存
		out = append(out, e)
	}
	return out, nil
}

// AppendToken 往 tokens.json 追加一条（文件不存在则新建），返回明文令牌。
func AppendToken(path, name string, scopes []string, note string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("name 不能为空")
	}
	if len(scopes) == 0 {
		return "", fmt.Errorf("scopes 不能为空（要全权请写 *）")
	}
	var f tokenFile
	f.Version = 1
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &f); err != nil {
			var arr []TokenEntry
			if err2 := json.Unmarshal(b, &arr); err2 != nil {
				return "", fmt.Errorf("tokens.json 解析失败（%s）: %w", path, err)
			}
			f.Tokens = arr
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	for _, e := range f.Tokens {
		if e.Name == name {
			return "", fmt.Errorf("令牌 name 已存在: %s（换一个名字，或在文件里删掉旧条）", name)
		}
	}
	plain, hash := NewToken()
	f.Tokens = append(f.Tokens, TokenEntry{Name: name, TokenHash: hash, Scopes: scopes, Note: note})
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	return plain, nil
}

// tokenFrom 取请求里的令牌：X-Keybaton-Token / X-Api-Key / Bearer。
func tokenFrom(r *http.Request) string {
	if t := r.Header.Get("X-Keybaton-Token"); t != "" {
		return t
	}
	if t := r.Header.Get("X-Api-Key"); t != "" {
		return t
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// identify 把令牌映射到身份；tokens.json 优先，--token 单令牌模式兜底（全权）。
func (s *Server) identify(r *http.Request) (Identity, bool) {
	tok := tokenFrom(r)
	if tok == "" {
		return Identity{}, false
	}
	sum := HashToken(tok)
	for _, e := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(sum), []byte(e.TokenHash)) == 1 {
			return Identity{Name: e.Name, Scopes: e.Scopes}, true
		}
	}
	if s.opt.Token != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.opt.Token)) == 1 {
		name := s.opt.Actor
		if name == "" {
			name = "legacy"
		}
		return Identity{Name: name, Scopes: []string{"*"}}, true
	}
	return Identity{}, false
}

// Can 判定能力：admin / * 全放行 → 精确匹配 → <资源>:* 前缀匹配。
func (id Identity) Can(cap string) bool {
	for _, sc := range id.Scopes {
		switch {
		case sc == "*" || sc == "admin":
			return true
		case sc == cap:
			return true
		case strings.HasSuffix(sc, ":*") && strings.HasPrefix(cap, strings.TrimSuffix(sc, "*")):
			return true
		}
	}
	return false
}
