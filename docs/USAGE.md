# 使用文档

面向使用者的完整说明。只想快速跑起来，看 [README](../README.md) 的「30 秒上手」即可。

---

## 1. 安装

### 1.1 下载二进制（推荐）

从 [Releases](https://github.com/gomind-nx/keybaton/releases) 下载对应平台：

| 平台 | 文件 |
|---|---|
| macOS Apple Silicon | `keybaton-darwin-arm64` |
| macOS Intel | `keybaton-darwin-amd64` |
| Linux x86_64 | `keybaton-linux-amd64` |
| Linux ARM64 | `keybaton-linux-arm64` |

```bash
chmod +x keybaton-darwin-arm64
sudo install -m 0755 keybaton-darwin-arm64 /usr/local/bin/keybaton
keybaton version
```

**没有 sudo** 时，把二进制放到任意目录，用 `./keybaton` 调用：

```bash
mkdir -p ~/.local/bin && cp keybaton-darwin-arm64 ~/.local/bin/keybaton
chmod 755 ~/.local/bin/keybaton
export PATH="$HOME/.local/bin:$PATH"     # 写进 ~/.zshrc 或 ~/.bashrc
keybaton version
```

### 1.2 go install

```bash
go install github.com/gomind-nx/keybaton/cmd/keybaton@latest
```

需要 Go 1.22+，产物在 `$(go env GOPATH)/bin/keybaton`。

### 1.3 容器

```bash
docker build -t keybaton:0.1.0 .          # 在仓库根目录执行
docker run -v ~/.keybaton:/home/kb/.keybaton \
  -e KEYBATON_TOKEN=$KEYBATON_TOKEN \
  -p 127.0.0.1:8765:8765 \
  keybaton:0.1.0 serve --addr 0.0.0.0:8765
```

> 容器内监听 `0.0.0.0`，**必须**传 `KEYBATON_TOKEN`，否则服务会按安全策略拒绝启动。

---

## 2. 初始化

```bash
keybaton init
```

生成两个文件，**必须一起备份**：

```
~/.keybaton/master.key   主密钥（0600）
~/.keybaton/vault.db     SQLite 库
```

库目录可用环境变量覆盖：

```bash
export KEYBATON_HOME=/secure/keybaton     # 优先于 ~/.keybaton
```

`init` 是幂等的：已存在时不会改动任何数据，重复执行安全。

---

## 3. 存密钥

从 stdin 读入（推荐，不留在 shell 历史里）：

```bash
printf '%s' "$GITHUB_TOKEN" | keybaton put github --user myname --note "CI 只读"
```

或从已有变量读：

```bash
keybaton put github --from-env GITHUB_TOKEN --user myname
```

同名再次 `put` 会覆盖，并提示 `已覆盖`（旧值不保留——需要留痕的场景请用 `mem_history` 类服务的做法，keybaton 定位是运行时凭据，不是审计档案）。

### 批量导入

```bash
keybaton import --file .env      # 文件不存在会报错退出
cat .env | keybaton import       # 从 stdin
```

支持 `KEY=VALUE`、`export KEY=VALUE`、引号包裹的值；空值行会被跳过。

---

## 4. 用密钥

### 4.1 给命令注入环境变量

```bash
keybaton run -- npm start
keybaton run -- sh -c 'curl -H "Authorization: Bearer $KEYBATON_GITHUB" https://api.github.com/user'
```

变量名规则：`<条目名>` → `KEYBATON_<大写，非字母数字转下划线>`。

| 条目名 | 环境变量 |
|---|---|
| `github` | `KEYBATON_GITHUB` |
| `my-app.v2` | `KEYBATON_MY_APP_V2` |

只注入一部分：

```bash
keybaton run --only github -- gh repo list
```

`--only` 是**子串匹配、大小写不敏感**，同时匹配条目名与 `KEYBATON_` 变量名；**无匹配时报错退出**，不会静默注入 0 条。

子进程退出码会原样透传，可用于脚本判断。

### 4.2 本机人工查看

```bash
keybaton get github                 # 打印明文
keybaton get github --field user    # 只看账号
keybaton get github --field note    # 只看备注
```

`--field` 只接受 `secret | user | note`，其它值直接报错（不会静默回落成打印明文）。

---

## 5. 给 agent 用（重点）

### 5.1 起服务

```bash
export KEYBATON_TOKEN=$(openssl rand -hex 24)
keybaton serve --addr 0.0.0.0:8765 --token "$KEYBATON_TOKEN"
```

启动横幅会列出三类端点：

```
MCP:  POST /mcp
只读: GET /api/secrets
健康: GET /healthz
```

### 5.2 接 MCP

```jsonc
// 任何支持 HTTP MCP 的客户端
{
  "url": "http://<host>:8765/mcp",
  "headers": { "X-Keybaton-Token": "<你的令牌>" }
}
```

工具清单：

| 工具 | 作用 |
|---|---|
| `kb_list` | 列出条目（名称/账号/用途，**不含明文**） |
| `kb_http` | 服务端代发 HTTP 请求并注入凭据；响应里回显的凭据会被替换成 `[REDACTED-BY-KEYBATON]` |
| `kb_audit` | 最近的调用记录 |
| `kb_whoami` | 当前身份与能力 |

**默认没有 `kb_get`**。要允许 agent 直接拿明文必须显式 `--allow-get`，不建议。

### 5.3 `kb_http` 参数

| 字段 | 必填 | 说明 |
|---|---|---|
| `secret` | 是 | 条目名 |
| `url` | 是 | 目标地址 |
| `method` | 否 | 默认 `GET` |
| `headers` | 否 | 附加请求头（对象） |
| `body` | 否 | 请求体 |
| `auth` | 否 | `bearer`（默认）/ `basic` / `header` / `query` |
| `header_name` | auth=header 时 | 头名，默认 `X-Api-Key`（兼容旧名 `header`） |
| `param_name` | auth=query 时 | 参数名，默认 `api_key`（兼容旧名 `param`） |

**未知字段会被拒绝**，不会静默回落到默认值。

### 5.4 只支持 stdio 的客户端

用内置的 HTTP 桥（`scripts/mcp_stdio.py`，纯标准库）：

```jsonc
{
  "command": "/usr/bin/python3",
  "args": ["/path/to/mcp_stdio.py"],
  "env": {
    "KEYBATON_URL": "http://<host>:8765/mcp",
    "KEYBATON_TOKEN": "<令牌>"
  }
}
```

---

## 6. 审计

```bash
keybaton audit --limit 20
```

```
TIME                 ACTOR      ACTION     TARGET               RESULT
2026-11-14 17:30:12  agent      http       github               ok GET api.github.com 200
2026-11-14 17:29:40  cli        run        npm                  ok injected=1 exit=0
2026-11-14 17:28:01  cli        get        github               ok plaintext-to-tty
2026-11-14 17:27:33  cli        run        gh                   FAIL injected=1 exit=-1 exec not found
```

`run` 记录注入条数、子进程退出码与失败原因（命令未启动时 `exit=-1`）。

---

## 7. 删除与清理

```bash
keybaton rm github        # 不存在时退出码 2
keybaton list             # 查看现有条目
keybaton list --json      # 字段：name/username/note/updated_at
```

---

## 8. 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 一般错误（参数、IO、网络、加密失败） |
| 2 | 条目不存在 |
| 126/127 | `run` 的子进程不可执行 / 未找到（透传） |

---

## 9. 常见问题

**Q：`keybaton: command not found`**
二进制不在 PATH 里。用 `./keybaton`，或按 1.1 装到 `/usr/local/bin`。

**Q：`错误: 密钥为空`**
`put` 从 stdin 读，没给输入。用 `printf '%s' "$TOKEN" | keybaton put xxx`。

**Q：`拒绝启动：监听 0.0.0.0:8765 但未设置令牌`**
非 loopback 监听必须带令牌：`--token` 或 `KEYBATON_TOKEN`。

**Q：容器里报同样错误**
`docker run` 要加 `-e KEYBATON_TOKEN=...`。

**Q：`kb_get 未启用`**
默认关闭。这是设计选择，用 `kb_http` 代发请求即可。

**Q：换了机器，库读不出来**
`master.key` 没带过去。**丢主密钥等于数据永久不可恢复**，务必单独备份到密码管理器。
