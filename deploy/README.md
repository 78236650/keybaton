# keybaton 部署

单机、单二进制、凭据不进上下文。容器只做两件事：跑 `serve`，把 `/data` 挂出来。

## 1. 初始化（宿主机，一次性）

```bash
cd deploy
mkdir -p data && chmod 700 data
KEYBATON_HOME=./data ../bin/keybaton-linux-arm64 init
KEYBATON_HOME=./data ../bin/keybaton-linux-arm64 token new --name hermes-nas --scopes kb:read,kb:http,kb:audit
```

`token new` 只在屏幕上打印一次明文，文件里存 `sha256`。把明文立刻交给调用方（Hermes MCP 配置、zfg 客户端等）。

## 2. 起容器

```bash
docker compose -f deploy/compose.yaml up -d --build
curl -s http://127.0.0.1:8765/healthz
curl -s -H "X-Keybaton-Token: $T" -X POST http://127.0.0.1:8765/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## 3. 令牌与权限

| scope | 能干什么 |
|---|---|
| `kb:read` | `kb_list`、`GET /api/secrets`（只有名称/账号/用途） |
| `kb:http` | `kb_http`：服务端代发并注入凭据 |
| `kb:audit` | `kb_audit`：读调用记录 |
| `kb:reveal` | `kb_get` 取明文（还需服务端 `--allow-get`，默认关） |
| `*` / `admin` | 全部能力 |

- 一机一令牌，`name` 直接进审计；新增/轮换：`keybaton token new --name <新名> ...`，吊销＝从 `tokens.json` 删掉该条并 `docker compose restart`。
- `tokens.json` 只存 hash，泄露文件不等于泄露令牌；仍然 0600、不进备份包。
- 备份：`data/master.key` + `data/vault.db`（丢了 master.key 数据不可恢复）；`tokens.json` 单独备份。

## 4. 排错

- 启动即退出并报“没有任何令牌”：`tokens.json` 不存在或为空；容器内监听 0.0.0.0 时至少要有一条令牌。
- 401：调用方没带 `X-Keybaton-Token` / `Bearer`，或令牌不在文件里。
- 403：令牌缺对应 scope，响应体里 `cap` 字段就是缺的那个。
