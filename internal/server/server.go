// Package server 提供 HTTP + MCP 接口。
//
// 核心设计：**默认不把明文交给调用方**。
// agent 只能通过 kb_http 让服务端代发请求，凭据在服务端被注入到出站请求里，
// 不进入模型上下文、不进入日志。需要明文时必须显式 `--allow-get` 启动。
package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/keybaton/keybaton/internal/vault"
)

const version = "0.1.0"
const maxBody = 64 << 10 // 响应体截断到 64KB，避免把大文件灌进上下文

// Options 是启动参数。
type Options struct {
	Addr     string
	Token    string
	AllowGet bool
	Store    *vault.Store
	Actor    string
}

// Server 持有 http.Server 与依赖。
type Server struct {
	opt Options
	srv *http.Server
}

// New 构造服务器。
func New(opt Options) *Server {
	mux := http.NewServeMux()
	s := &Server{opt: opt}
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/mcp", s.mcp)
	mux.HandleFunc("/api/secrets", s.listHTTP)
	s.srv = &http.Server{Addr: opt.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return s
}

// ListenAndServe 阻塞运行。
func (s *Server) ListenAndServe() error { return s.srv.ListenAndServe() }

// 非 loopback 且没设令牌时拒绝启动，避免把钥匙柜暴露到内网。
func (s *Server) CheckSafety() error {
	host, _, err := net.SplitHostPort(s.opt.Addr)
	if err != nil {
		return err
	}
	loopback := host == "127.0.0.1" || host == "localhost" || host == "::1"
	if !loopback && s.opt.Token == "" {
		return fmt.Errorf("拒绝启动：监听 %s 但未设置令牌（--token 或 KEYBATON_TOKEN）", s.opt.Addr)
	}
	return nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "version": version, "ts": time.Now().Format(time.RFC3339)})
}

func (s *Server) authorized(r *http.Request) bool {
	if s.opt.Token == "" {
		return true // 仅 loopback 场景（CheckSafety 已保证）
	}
	tok := r.Header.Get("X-Keybaton-Token")
	if tok == "" {
		tok = r.Header.Get("X-Api-Key")
	}
	if tok == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
	}
	return tok == s.opt.Token
}

func (s *Server) listHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeJSON(w, 401, map[string]any{"error": "unauthorized"})
		return
	}
	list, err := s.opt.Store.List()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"secrets": list})
}

// ---- MCP ----

var tools = []map[string]any{
	{"name": "kb_whoami", "description": "返回当前身份与能力（是否允许取明文）。",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
	{"name": "kb_list", "description": "列出密钥条目（仅名称/账号/用途，永不含明文）。",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
	{"name": "kb_http", "description": "由服务端代发 HTTP 请求并把凭据注入请求头；调用方永远拿不到明文。" +
		"auth 支持 bearer / basic / header / query。",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"secret":      map[string]any{"type": "string", "description": "密钥名称"},
			"url":         map[string]any{"type": "string"},
			"method":      map[string]any{"type": "string", "default": "GET"},
			"headers":     map[string]any{"type": "object"},
			"body":        map[string]any{"type": "string"},
			"auth":        map[string]any{"type": "string", "description": "bearer|basic|header|query"},
			"header_name": map[string]any{"type": "string", "description": "auth=header 时的头名"},
			"param_name":  map[string]any{"type": "string", "description": "auth=query 时的参数名"},
		}, "required": []string{"secret", "url"}}},
	{"name": "kb_audit", "description": "查看最近调用记录。",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"limit": map[string]any{"type": "integer"}}}},
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeJSON(w, 401, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	ok := func(result any) {
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	switch req.Method {
	case "initialize":
		ok(map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "keybaton", "version": version},
		})
	case "notifications/initialized", "notifications/cancelled":
		ok(map[string]any{})
	case "ping":
		ok(map[string]any{})
	case "tools/list":
		list := tools
		if s.opt.AllowGet {
			list = append(list, map[string]any{
				"name":        "kb_get",
				"description": "【危险】直接返回明文；仅在显式 --allow-get 时可用。",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
					"name": map[string]any{"type": "string"}}, "required": []string{"name"}}})
		}
		ok(map[string]any{"tools": list})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			ok(errResult("bad params"))
			return
		}
		ok(s.callTool(p.Name, p.Arguments))
	default:
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID,
			"error": map[string]any{"code": -32601, "message": "method not found"}})
	}
}

func errResult(msg string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true}
}

func textResult(v any) map[string]any {
	b, _ := json.Marshal(v)
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}, "isError": false}
}

func (s *Server) callTool(name string, args json.RawMessage) map[string]any {
	switch name {
	case "kb_whoami":
		return textResult(map[string]any{"actor": s.opt.Actor, "allow_get": s.opt.AllowGet, "version": version})

	case "kb_list":
		list, err := s.opt.Store.List()
		if err != nil {
			return errResult(err.Error())
		}
		s.opt.Store.Audit(s.opt.Actor, "list", "", true, "")
		return textResult(list)

	case "kb_audit":
		var a struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(args, &a)
		rows, err := s.opt.Store.AuditTail(a.Limit)
		if err != nil {
			return errResult(err.Error())
		}
		return textResult(rows)

	case "kb_get":
		if !s.opt.AllowGet {
			s.opt.Store.Audit(s.opt.Actor, "get_denied", "", false, "allow_get=false")
			return errResult("kb_get 未启用：请用 kb_http 让服务端代发请求（凭据不进上下文）")
		}
		var a struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(args, &a)
		e, err := s.opt.Store.Get(a.Name)
		if err != nil {
			s.opt.Store.Audit(s.opt.Actor, "get", a.Name, false, err.Error())
			return errResult(err.Error())
		}
		s.opt.Store.Audit(s.opt.Actor, "get", a.Name, true, "plaintext-returned")
		return textResult(map[string]any{"name": e.Name, "username": e.Username, "secret": e.Secret})

	case "kb_http":
		return s.brokerHTTP(args)
	}
	return errResult("unknown tool: " + name)
}

func (s *Server) brokerHTTP(args json.RawMessage) map[string]any {
	var a struct {
		Secret     string            `json:"secret"`
		URL        string            `json:"url"`
		Method     string            `json:"method"`
		Headers    map[string]string `json:"headers"`
		Body       string            `json:"body"`
		Auth       string            `json:"auth"`
		HeaderName string            `json:"header_name"`
		ParamName  string            `json:"param_name"`
		// 别名：README 早期版本写的是 header / param，两个都收
		HeaderAlias string `json:"header"`
		ParamAlias  string `json:"param"`
	}
	dec := json.NewDecoder(strings.NewReader(string(args)))
	dec.DisallowUnknownFields() // 未知字段直接报错，避免"参数被静默忽略"
	if err := dec.Decode(&a); err != nil {
		return errResult("参数错误（未知字段会被拒绝）: " + err.Error())
	}
	if a.HeaderName == "" {
		a.HeaderName = a.HeaderAlias
	}
	if a.ParamName == "" {
		a.ParamName = a.ParamAlias
	}
	if a.URL == "" || a.Secret == "" {
		return errResult("secret 与 url 必填")
	}
	e, err := s.opt.Store.Get(a.Secret)
	if err != nil {
		s.opt.Store.Audit(s.opt.Actor, "http", a.Secret, false, err.Error())
		return errResult(err.Error())
	}
	method := strings.ToUpper(a.Method)
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, a.URL, strings.NewReader(a.Body))
	if err != nil {
		return errResult("bad url: " + err.Error())
	}
	for k, v := range a.Headers {
		req.Header.Set(k, v)
	}
	// 注入凭据（四种方式）
	switch strings.ToLower(a.Auth) {
	case "", "bearer":
		req.Header.Set("Authorization", "Bearer "+e.Secret)
	case "basic":
		user := e.Username
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(user+":"+e.Secret)))
	case "header":
		name := a.HeaderName
		if name == "" {
			name = "X-Api-Key"
		}
		req.Header.Set(name, e.Secret)
	case "query":
		pn := a.ParamName
		if pn == "" {
			pn = "api_key"
		}
		q := req.URL.Query()
		q.Set(pn, e.Secret)
		req.URL.RawQuery = q.Encode()
	default:
		return errResult("auth 只能是 bearer|basic|header|query")
	}

	// 安全：禁止跨主机重定向（防止凭据被带到第三方）
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) > 0 && r.URL.Host != via[0].URL.Host {
				return fmt.Errorf("拒绝跨主机重定向：%s → %s", via[0].URL.Host, r.URL.Host)
			}
			if len(via) >= 5 {
				return fmt.Errorf("重定向过多")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		s.opt.Store.Audit(s.opt.Actor, "http", a.Secret, false, err.Error())
		return errResult("请求失败: " + err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	// 上游可能把请求头回显在响应里（4xx 调试页很常见）——此处再做一次脱敏，
	// 保证"凭据不回到调用方"这句话在回显场景下也成立。
	redacted := false
	sensitive := []string{}
	if e.Secret != "" {
		sensitive = append(sensitive, e.Secret)
		// basic 模式泄露的是 base64(user:secret)，必须一起替换
		basicTok := base64.StdEncoding.EncodeToString([]byte(e.Username + ":" + e.Secret))
		if basicTok != "" {
			sensitive = append(sensitive, basicTok)
		}
	}
	bodyStr := string(body)
	for _, v := range sensitive {
		if v != "" && strings.Contains(bodyStr, v) {
			bodyStr = strings.ReplaceAll(bodyStr, v, "[REDACTED-BY-KEYBATON]")
			redacted = true
		}
	}
	if redacted {
		body = []byte(bodyStr)
	}
	s.opt.Store.Audit(s.opt.Actor, "http", a.Secret, resp.StatusCode < 400,
		fmt.Sprintf("%s %s %d", method, hostOf(a.URL), resp.StatusCode))
	return textResult(map[string]any{
		"status":  resp.StatusCode,
		"headers": map[string]string{"content-type": resp.Header.Get("Content-Type")},
		"body":    string(body),
		"truncated": len(body) >= maxBody,
		"redacted":  redacted,
	})
}

func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return u
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
