# keybaton

[![release](https://img.shields.io/github/v/release/78236650/keybaton)](https://github.com/78236650/keybaton/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![go](https://img.shields.io/badge/go-1.22%2B-00ADD8)](go.mod)
[![platform](https://img.shields.io/badge/platform-darwin%20%7C%20linux-lightgrey)](#32-构建)

**给脚本和 agent 用的本地凭据代理。凭据不进上下文。**

```bash
keybaton run -- npm start          # 密钥注入环境变量，不进 shell history、不进日志
keybaton serve                     # agent 通过 kb_http 让服务端代发请求，永远拿不到明文
```

| 文档 | 内容 |
|---|---|
| [使用文档](docs/USAGE.md) | 安装、九个命令、MCP 接入、参数、退出码、常见问题 |
| [设计文档](docs/DESIGN.md) | 威胁模型、两种交付模式、取舍与被否掉的方案 |
| [运维文档](docs/OPERATIONS.md) | systemd / Docker / launchd、备份、升级、令牌轮换、故障处置 |
| [安全策略](SECURITY.md) | 防什么、不防什么、漏洞怎么报 |
| [变更日志](CHANGELOG.md) | 版本沿革 |

一个二进制、一个 SQLite 文件、一个主密钥。不需要 PostgreSQL、不需要反向代理、不需要有人运维。

---

## 为什么还要一个

| | `.env` 文件 | HashiCorp Vault / OpenBao | Infisical | **keybaton** |
|---|---|---|---|---|
| 安装 | 无 | 服务端 + 存储后端 + 反代 | 容器 + PG + 反代 | **一个二进制 / 一个容器** |
| 给进程注入 | 手工 export | 要写集成代码 | CLI / SDK | **`keybaton run -- cmd`** |
| 给 agent 用 | 明文塞进 prompt（危险） | 需自建适配层 | Agent Vault（按请求计费） | **MCP `kb_http`，凭据不进上下文** |
| 审计"谁取的" | 无 | 有，但要配 | 有 | **自带，`keybaton audit`** |
| 单机可用 | 是 | 否（重） | 勉强 | **是** |

我们不做"密码管理器"——那是给人点开复制的。keybaton 服务的是**进程**：脚本、CI、定时任务、agent。

---

## 30 秒上手

```bash
# 1. 装（三种方式任选）
#   a) 从 Releases 下载对应平台二进制（darwin-arm64 / darwin-amd64 / linux-amd64 / linux-arm64）
#      下载后需要让它可执行，并放进 PATH：
#      chmod +x keybaton-darwin-arm64
#      sudo install -m 0755 keybaton-darwin-arm64 /usr/local/bin/keybaton
#      keybaton version        # 确认装好；没有 sudo 就用 ./keybaton 代替下面的 keybaton
#   b) 用 Go 装（需要 Go 1.22+）
go install github.com/78236650/keybaton/cmd/keybaton@latest
#   c) 容器（必须带 KEYBATON_TOKEN：容器内监听 0.0.0.0，没有令牌会被拒绝启动）
#      下面的 docker build 需在源码仓库根目录执行（那里才有 Dockerfile）
docker build -t keybaton:0.1.0 .          # 或 ghcr.io/78236650/keybaton:0.1.0（发布后）
docker run -v ~/.keybaton:/home/kb/.keybaton \
  -e KEYBATON_TOKEN=$KEYBATON_TOKEN \
  -p 127.0.0.1:8765:8765 keybaton:0.1.0 serve --addr 0.0.0.0:8765

# 2. 初始化（生成 master.key + vault.db，默认在 ~/.keybaton）
#    库目录可用环境变量 KEYBATON_HOME 覆盖（优先于 ~/.keybaton；CI/容器场景常用）
keybaton init

# 3. 存一把钥匙（从 stdin 读，不进 shell history）
printf '%s' "$GITHUB_TOKEN" | keybaton put github --user me --note "CI 只读"

# 4. 用它跑命令（示例用 gh，需先装 GitHub CLI；没有 gh 可换成下面的自测）
keybaton run -- gh repo list
keybaton run -- sh -c 'echo $KEYBATON_GITHUB'   # 自测注入是否生效
# 子进程里可用 $KEYBATON_GITHUB
```

## 给 agent 用（这是重点）

```bash
export KEYBATON_TOKEN=$(openssl rand -hex 24)
keybaton serve --addr 0.0.0.0:8765 --token "$KEYBATON_TOKEN"
```

agent 侧接 MCP（HTTP）：`http://<host>:8765/mcp`，Header `X-Keybaton-Token`。

可用工具：

| 工具 | 作用 |
|---|---|
| `kb_list` | 列出条目（只有名称/账号/用途） |
| `kb_http` | **服务端代发 HTTP 请求并注入凭据**，返回响应；响应体里若回显了该凭据会被替换成 `[REDACTED-BY-KEYBATON]` |
| `kb_audit` | 最近的调用记录 |
| `kb_whoami` | 当前身份与能力 |

`kb_http` 支持四种注入方式：`bearer`（默认）、`basic`、`header`、`query`。
**未知字段会被拒绝**（不会静默回落到默认值）。

| auth | 额外参数 | 效果 |
|---|---|---|
| `bearer` | 无 | `Authorization: Bearer <密钥>` |
| `basic` | 无（用条目的 username） | `Authorization: Basic base64(user:密钥)` |
| `header` | `header_name`（兼容别名 `header`）：头名，默认 `X-Api-Key` | `<头名>: <密钥>` |
| `query` | `param_name`（兼容别名 `param`）：参数名，默认 `api_key` | `?<参数名>=<密钥>` |

```json
{"secret":"stripe","url":"https://api.stripe.com/v1/charges","auth":"header","header_name":"Authorization"}
```

```json
{
  "name": "kb_http",
  "arguments": {
    "secret": "github",
    "url": "https://api.github.com/user",
    "auth": "bearer"
  }
}
```

服务端还有两个只读端点：`GET /healthz`（不需要令牌，返回版本）与 `GET /api/secrets`（需要令牌，只返回元数据）。

**默认没有 `kb_get`**。要允许 agent 直接拿明文，必须显式 `keybaton serve --allow-get`——我们建议永远不要开。

---

## 安全模型（请先读这段再用于生产）

**做了什么**
- 每条密钥独立 nonce，AES-256-GCM 加密；主密钥与数据库分开存放
- 主密钥可用 `KEYBATON_MASTER_KEY`（base64）从环境注入，适配容器与 CI
- 所有取用写审计（谁、何时、哪条、成功与否）；`run` 记录注入条数、子进程退出码与失败原因
  （命令未启动时 `exit=-1`）
- 非 loopback 监听时**强制要求令牌**，否则拒绝启动
- 出站请求**禁止跨主机重定向**，避免凭据被带到第三方
- 响应体截断 64KB，防止把大文件灌进模型上下文

**没做什么（明确边界）**
- 不是密码管理器：没有图形界面、没有浏览器插件
- 不做云同步、多租户、K8s Operator
- 不防"agent 自身被攻破"——本机进程能读 `master.key`，这是单机方案的固有限制
- 不建议直接暴露到公网；跨网请走 VPN / ZeroTier

**备份**：`master.key` 和 `vault.db` 必须一起备份。**丢了 master.key，数据无法恢复。**

---

## 命令

```
keybaton init                              初始化
keybaton put <name> [--user U] [--note N]  从 stdin 读入并加密（同名覆盖会提示"已覆盖"）
keybaton get <name> [--field secret|user|note]  打印明文（本机人类用）
keybaton list [--json]                     列出条目（JSON 字段：name/username/note/updated_at）
keybaton rm <name>                         删除（不存在时退出码 2）
keybaton version                           版本
keybaton run [--only P] -- <cmd>           注入环境变量后运行
                                           P 匹配条目名或 KEYBATON_ 变量名，大小写不敏感，子串匹配；
                                           无匹配则报错退出（不会静默注入 0 条）
keybaton import [--file .env]              批量导入 dotenv（文件不存在会报错退出）
keybaton serve [--addr] [--token] [--allow-get]
keybaton audit [--limit N]                 调用记录
```

注入的变量名规则：`<NAME>` → `KEYBATON_<大写、非字母数字转下划线>`。

---

## 构建

```bash
make build      # 本机
make cross      # darwin-arm64 / darwin-amd64 / linux-amd64 / linux-arm64
make test
```

需要 Go 1.22+。交叉编译不需要 CGO（SQLite 用纯 Go 驱动 `modernc.org/sqlite`）。

---

## 路线图

- v0.1（当前）：CLI + HTTP/MCP + egress broker
- v0.2：TOTP 代取（agent 登录要 2FA）、`--file` 注入、导入 1Password/Bitwarden
- v0.3：团队模式（多用户令牌 + 审批）、轮换提醒
- 不做：图形界面、浏览器插件、SaaS

---

## 许可

MIT
