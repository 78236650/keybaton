// keybaton —— 给脚本与 agent 用的本地凭据代理。
//
// 三个命令就能用起来：
//	keybaton init
//	echo "$TOKEN" | keybaton put github --user me
//	keybaton run -- npm start
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/78236650/keybaton/internal/server"
	"github.com/78236650/keybaton/internal/vault"
)

const version = "0.2.0"

const usage = `keybaton —— 本地凭据代理（凭据不进上下文）

用法:
  keybaton init                              初始化库（~/.keybaton）
  keybaton put <name> [--user U] [--note N]  从 stdin 读密钥并加密保存
  keybaton get <name> [--field secret|user|note]  打印明文（本机人类用）
  keybaton list                              列出条目（不含明文）
  keybaton rm <name>                         删除
  keybaton run [--only P] -- <cmd> [args...] 把密钥注入环境变量后运行命令
  keybaton import [--file .env]              从 dotenv 批量导入
  keybaton serve [--addr 127.0.0.1:8765] [--tokens-file F] [--allow-get]
                                             启动 HTTP + MCP（agent 用 kb_http 代发请求）
  keybaton token new --name <name> --scopes kb:read,kb:http
                                             签发一个令牌（name + scopes，明文只显示一次）
  keybaton token list                       列出令牌身份（name / scopes / hash 前 8 位）
  keybaton audit [--limit 20]                查看调用记录
  keybaton version

环境变量:
  KEYBATON_HOME        库目录（默认 ~/.keybaton）
  KEYBATON_MASTER_KEY  主密钥 base64（CI/容器场景，优先于 master.key）
  KEYBATON_TOKENS_FILE tokens.json 路径（默认 $KEYBATON_HOME/tokens.json）
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "put":
		err = cmdPut(args)
	case "get":
		err = cmdGet(args)
	case "list", "ls":
		err = cmdList(args)
	case "rm", "delete":
		err = cmdRm(args)
	case "run":
		err = cmdRun(args)
	case "import":
		err = cmdImport(args)
	case "serve":
		err = cmdServe(args)
	case "audit":
		err = cmdAudit(args)
	case "rotate":
		err = cmdRotate(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "token", "tokens":
		err = cmdToken(args)
	case "version", "-v", "--version":
		fmt.Printf("keybaton %s\n", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n%s", cmd, usage)
		os.Exit(1)
	}
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			fmt.Fprintln(os.Stderr, "错误: 条目不存在")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}


// splitArgs 允许"位置参数在前、flag 在后"的写法（标准 flag 包遇到位置参数就停）：
//   keybaton put github --user me --note "CI token"
// 返回：name（第一个非 flag 参数）、flags（同名 flag 及其值，布尔值为 "true"）、其余参数。
func splitArgs(args []string, valueFlags map[string]bool) (string, map[string]string, []string) {
	name := ""
	flags := map[string]string{}
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			k := strings.TrimPrefix(a, "--")
			if eq := strings.Index(k, "="); eq >= 0 {
				flags[k[:eq]] = k[eq+1:]
				continue
			}
			if valueFlags[k] && i+1 < len(args) {
				flags[k] = args[i+1]
				i++
				continue
			}
			flags[k] = "true"
			continue
		}
		if name == "" {
			name = a
			continue
		}
		rest = append(rest, a)
	}
	return name, flags, rest
}

func flagOr(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

func openStore() (*vault.Store, error) { return vault.Open(vault.HomeDir()) }

// tokensFileDefault 决定 tokens.json 的位置：显式环境变量优先，否则用库目录下的文件；
// 文件不存在时返回空串（没有配置多身份，退化为单令牌/loopback 模式）。
func tokensFileDefault() string {
	if v := os.Getenv("KEYBATON_TOKENS_FILE"); v != "" {
		return v
	}
	p := filepath.Join(vault.HomeDir(), "tokens.json")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// cmdToken 管 tokens.json：签发（name + scopes）与列出。
func cmdToken(args []string) error {
	sub := "new"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "new", "add":
		fs := flag.NewFlagSet("token new", flag.ExitOnError)
		name := fs.String("name", "", "调用方名字（写进审计的 agent 字段）")
		scopes := fs.String("scopes", "", "逗号分隔：kb:read,kb:http,kb:audit,kb:reveal 或 *（全权）")
		file := fs.String("file", tokensFileDefault(), "tokens.json 路径（默认 $KEYBATON_HOME/tokens.json）")
		note := fs.String("note", "", "备注")
		fs.Parse(args)
		if *name == "" || *scopes == "" {
			return fmt.Errorf("用法: keybaton token new --name <name> --scopes kb:read,kb:http")
		}
		path := *file
		if path == "" {
			path = filepath.Join(vault.HomeDir(), "tokens.json")
		}
		plain, err := server.AppendToken(path, *name, splitCSV(*scopes), *note)
		if err != nil {
			return err
		}
		fmt.Printf("令牌（只显示这一次，请立刻存进调用方）:\n\n  %s\n\n已写入 %s（库里只存 sha256）\n", plain, path)
		return nil
	case "list", "ls":
		fs := flag.NewFlagSet("token list", flag.ExitOnError)
		file := fs.String("file", tokensFileDefault(), "tokens.json 路径")
		fs.Parse(args)
		if *file == "" {
			fmt.Println("没有 tokens.json（只用 --token 单令牌模式）")
			return nil
		}
		toks, err := server.LoadTokens(*file)
		if err != nil {
			return err
		}
		fmt.Printf("%-20s %-40s %s\n", "NAME", "SCOPES", "HASH")
		for _, t := range toks {
			h := t.TokenHash
			if len(h) > 8 {
				h = h[:8] + "…"
			}
			fmt.Printf("%-20s %-40s %s\n", t.Name, strings.Join(t.Scopes, ","), h)
		}
		return nil
	default:
		return fmt.Errorf("用法: keybaton token new|list")
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "", "库目录（默认 $KEYBATON_HOME 或 ~/.keybaton）")
	fs.Parse(args)
	if *dir != "" {
		os.Setenv(vault.EnvHome, *dir)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	s.Audit("cli", "init", s.Dir, true, "")
	fmt.Printf("库就绪: %s（已存在的数据不会被改动）\n（master.key 与 vault.db 必须一起备份，缺一不可恢复）\n", s.Dir)
	return nil
}

func cmdPut(args []string) error {
	name, fl, _ := splitArgs(args, map[string]bool{"user": true, "note": true, "from-env": true})
	if name == "" {
		return errors.New("用法: keybaton put <name> [--user U] [--note N]")
	}
	user := flagOr(fl, "user", "")
	note := flagOr(fl, "note", "")
	fromEnv := flagOr(fl, "from-env", "")

	var secret string
	switch {
	case fromEnv != "":
		secret = os.Getenv(fromEnv)
		if secret == "" {
			return fmt.Errorf("环境变量 %s 为空", fromEnv)
		}
	default:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		secret = strings.TrimRight(string(b), "\r\n")
	}
	if secret == "" {
		return errors.New("密钥为空：请通过 stdin 传入，例如 echo \"$TOKEN\" | keybaton put github")
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	_, gerr := s.Get(name)
	if err := s.Put(name, user, note, secret); err != nil {
		return err
	}
	verb := "已保存"
	if gerr == nil {
		verb = "已覆盖"
	}
	s.Audit("cli", "put", name, true, verb)
	fmt.Printf("%s: %s（%d 字节，AES-256-GCM）\n", verb, name, len(secret))
	return nil
}

func cmdGet(args []string) error {
	name, fl, _ := splitArgs(args, map[string]bool{"field": true})
	if name == "" {
		return errors.New("用法: keybaton get <name> [--field secret|user|note]")
	}
	field := flagOr(fl, "field", "secret")
	s, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	e, err := s.Get(name)
	if err != nil {
		s.Audit("cli", "get", name, false, err.Error())
		return err
	}
	sink := "plaintext-stdout"
	if fi, statErr := os.Stdout.Stat(); statErr == nil && fi.Mode()&os.ModeCharDevice != 0 {
		sink = "plaintext-to-tty"
	}
	s.Audit("cli", "get", e.Name, true, sink)
	switch field {
	case "secret":
		fmt.Println(e.Secret)
	case "user":
		fmt.Println(e.Username)
	case "note":
		fmt.Println(e.Note)
	default:
		return fmt.Errorf("未知字段 %q：只能是 secret | user | note", field)
	}
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "输出 JSON")
	fs.Parse(args)
	s, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	list, err := s.List()
	if err != nil {
		return err
	}
	if *asJSON {
		fmt.Print("[")
		for i, m := range list {
			if i > 0 {
				fmt.Print(",")
			}
			fmt.Printf(`{"name":%q,"username":%q,"note":%q,"updated_at":%q}`, m.Name, m.Username, m.Note, m.UpdatedAt)
		}
		fmt.Println("]")
		return nil
	}
	if len(list) == 0 {
		fmt.Println("（空）用 keybaton put <name> 添加")
		return nil
	}
	fmt.Printf("%-24s %-20s %-30s %s\n", "NAME", "USERNAME", "NOTE", "UPDATED")
	for _, m := range list {
		fmt.Printf("%-24s %-20s %-30s %s\n", m.Name, trunc(m.Username, 20), trunc(m.Note, 30), m.UpdatedAt)
	}
	return nil
}

func cmdRm(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() < 1 {
		return errors.New("用法: keybaton rm <name>")
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	ok, err := s.Delete(fs.Arg(0))
	if err != nil {
		return err
	}
	if !ok {
		return vault.ErrNotFound
	}
	s.Audit("cli", "rm", fs.Arg(0), true, "")
	fmt.Println("已删除:", fs.Arg(0))
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	only := fs.String("only", "", "只注入名称匹配该前缀/子串的密钥")
	fs.Parse(args)
	rest := fs.Args()
	// 允许 `keybaton run -- cmd` 与 `keybaton run cmd`
	for len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return errors.New("用法: keybaton run [--only P] -- <cmd> [args...]")
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	all, err := s.All()
	if err != nil {
		return err
	}
	env := os.Environ()
	injected := 0
	onlyLower := strings.ToLower(*only)
	for name, e := range all {
		if *only != "" {
			if !strings.Contains(strings.ToLower(name), onlyLower) &&
				!strings.Contains(vault.EnvName(name), strings.ToUpper(*only)) {
				continue
			}
		}
		env = append(env, vault.EnvName(name)+"="+e.Secret)
		injected++
	}
	if *only != "" && injected == 0 {
		s.Audit("cli", "run", rest[0], false, "only matched 0")
		s.Close()
		return fmt.Errorf("--only %q 没有匹配任何密钥（子串匹配）；已注入 0 条，拒绝执行", *only)
	}
	cmd := exec.Command(rest[0], rest[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := cmd.Run()
	code, why := 0, ""
	if runErr != nil {
		var ee *exec.ExitError
		switch {
		case errors.As(runErr, &ee):
			code = ee.ExitCode()
			why = "exited"
		case errors.Is(runErr, exec.ErrNotFound):
			code, why = -1, "exec not found"
		default:
			code, why = -1, "start: "+runErr.Error()
		}
	}
	// 审计写"注入了几条 + 子进程退出码 + 原因"，避免把没跑起来的命令记成成功
	s.Audit("cli", "run", rest[0], code == 0,
		fmt.Sprintf("injected=%d exit=%d %s", injected, code, why))
	s.Close()
	if runErr != nil {
		if code >= 0 {
			os.Exit(code)
		}
		return runErr
	}
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	file := fs.String("file", "", ".env 文件路径（默认 stdin）")
	fs.Parse(args)

	var r io.Reader = os.Stdin
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			return fmt.Errorf("打开 %s 失败: %w", *file, err)
		}
		defer f.Close()
		r = f
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()

	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k == "" || v == "" {
			continue
		}
		if err := s.Put(k, "", "", v); err != nil {
			return err
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	s.Audit("cli", "import", *file, true, fmt.Sprintf("count=%d", n))
	fmt.Printf("已导入 %d 条\n", n)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8765", "监听地址")
	token := fs.String("token", os.Getenv("KEYBATON_TOKEN"), "单令牌模式（全权，兼容旧配置）")
	tokensFile := fs.String("tokens-file", tokensFileDefault(), "tokens.json 路径（name + scopes）")
	allowGet := fs.Bool("allow-get", false, "允许 kb_get 直接返回明文（危险）")
	actor := fs.String("actor", "agent", "审计里记录的调用方名称")
	fs.Parse(args)

	s, err := openStore()
	if err != nil {
		return err
	}
	srv, err := server.New(server.Options{Addr: *addr, Token: *token, TokensFile: *tokensFile, AllowGet: *allowGet, Store: s, Actor: *actor})
	if err != nil {
		return err
	}
	if err := srv.CheckSafety(); err != nil {
		return err
	}
	s.Audit("cli", "serve", *addr, true, fmt.Sprintf("allow_get=%v", *allowGet))
	fmt.Printf("keybaton %s 监听 http://%s\n  MCP:  POST /mcp\n  只读: GET /api/secrets\n  健康: GET /healthz\n", version, *addr)
	if *token == "" && *tokensFile == "" {
		fmt.Println("  提示: 未设令牌，仅本机可访问；给 agent 用请执行 keybaton token new")
	} else if *tokensFile != "" {
		fmt.Printf("  令牌文件: %s\n", *tokensFile)
	}
	if *token != "" {
		fmt.Printf("  单令牌模式: actor=%s（全权，建议改为 tokens.json 多身份）\n", *actor)
	}
	return srv.ListenAndServe()
}

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	limit := fs.Int("limit", 20, "条数")
	fs.Parse(args)
	s, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	rows, err := s.AuditTail(*limit)
	if err != nil {
		return err
	}
	fmt.Printf("%-20s %-10s %-10s %-20s %s\n", "TIME", "ACTOR", "ACTION", "TARGET", "RESULT")
	for _, a := range rows {
		res := "ok"
		if !a.OK {
			res = "FAIL"
		}
		fmt.Printf("%-20s %-10s %-10s %-20s %s %s\n", a.TS, a.Actor, a.Action, a.Target, res, a.Detail)
	}
	return nil
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// cmdRotate 轮换主密钥：生成新 key_id，重新加密全部条目，旧密钥保留可回滚。
func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	force := fs.Bool("yes", false, "确认执行（会重写全部密文）")
	fs.Parse(args)
	if !*force {
		return fmt.Errorf("这会重新加密全部条目。确认请加 --yes（建议先备份 keys.json 与 vault.db）")
	}
	s, err := vault.Open(vault.HomeDir())
	if err != nil {
		return err
	}
	defer s.Close()
	oldID, newID, err := s.Rotate()
	if err != nil {
		return err
	}
	s.Audit("cli", "rotate", fmt.Sprintf("%d->%d", oldID, newID), true, "")
	fmt.Printf("密钥已轮换：key_id %d → %d\n旧密钥仍保留在 keys.json 中（可用于回滚或解密历史备份）。\n", oldID, newID)
	return nil
}

// cmdPolicy 管理条目的出站白名单：默认禁止外发，必须显式授权主机。
func cmdPolicy(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("用法: keybaton policy <name> [--allow host1,host2] [--clear] | keybaton policy --list")
	}
	s, err := vault.Open(vault.HomeDir())
	if err != nil {
		return err
	}
	defer s.Close()

	if args[0] == "--list" || args[0] == "list" {
		list, err := s.List()
		if err != nil {
			return err
		}
		fmt.Printf("%-24s %s\n", "NAME", "ALLOW_HOSTS")
		for _, m := range list {
			hosts := m.AllowHosts
			if hosts == "" {
				hosts = "(禁止外发)"
			}
			fmt.Printf("%-24s %s\n", m.Name, hosts)
		}
		return nil
	}

	name := args[0]
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	allow := fs.String("allow", "", "允许的目标主机，逗号分隔，支持 *.example.com")
	clear := fs.Bool("clear", false, "清空白名单（恢复为禁止外发）")
	fs.Parse(args[1:])

	hosts := ""
	if !*clear {
		if *allow == "" {
			return fmt.Errorf("需要 --allow host1,host2 或 --clear")
		}
		hosts = *allow
	}
	if err := s.SetAllowHosts(name, hosts); err != nil {
		return err
	}
	s.Audit("cli", "policy", name, true, hosts)
	if hosts == "" {
		fmt.Printf("%s：已清空白名单，禁止外发\n", name)
	} else {
		fmt.Printf("%s：允许发往 %s\n", name, hosts)
	}
	return nil
}
