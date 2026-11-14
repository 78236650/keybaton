# 变更日志

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 计划中
- TOTP 代取：2FA 种子不出服务端，由服务端生成动态码
- `--file` 注入、导入 1Password / Bitwarden
- 加密备份包（`keybaton backup`）与审计哈希链

## [0.2.0] - 2026-11-14

### 安全（破坏性变更）
- **密文 AAD 绑定条目名**：`AAD = "v2" ‖ key_id ‖ name`。
  修复"把 A 行的密文挪到 B 行即可让服务端用 B 的名字解出 A 的密钥"这一攻击——
  旧版本可以稳定复现（交换两行 cipher/nonce 后 `get` 返回另一条的值且不报错），现在直接解密失败。
- **出站主机白名单 `allow_hosts`**：`kb_http` 默认**禁止外发**，必须显式授权：
  `keybaton policy <name> --allow api.github.com`。修复"拿到令牌即可把任意密钥发到任意域名"。
  支持通配 `*.example.com`；`--clear` 恢复为禁止。
- **密钥环 `keys.json`**：支持多代密钥（`active` + `keys`），为轮换与回滚做准备。老库的 `master.key` 自动导入为 `key_id=1`。

### 新增
- `keybaton rotate --yes`：生成新 `key_id`，重新加密全部条目，旧密钥保留可回滚
- `keybaton policy <name> --allow ... | --clear`、`keybaton policy --list`
- `internal/vault/vault_test.go`：交换密文 / 篡改 / 轮换 / 老库迁移 / 主机白名单，共 5 组断言

### 变更
- 老库打开时自动迁移到 v2（`ALTER TABLE` 补 `fmt` / `key_id` / `allow_hosts`，逐条重加密；失败即中止不改数据）
- 升级后**必须**为每个要外发的条目配 `allow_hosts`，否则 `kb_http` 会拒绝

## [0.1.1] - 2026-11-14

### 计划中
- TOTP 代取：2FA 种子不出服务端，由服务端生成动态码
- `--file` 注入：把凭据写成临时文件并注入路径（给只支持文件读取的工具）
- 导入：1Password / Bitwarden / dotenv 目录批量
- 团队模式：多令牌 + 按条目授权 + 审批流

## [0.1.1] - 2026-11-14

### 新增
- **多身份令牌 `tokens.json`**：`令牌 = { name, token_hash, scopes[] }`，与 nxmem / 旧 Python 版统一口径
- `keybaton token new --name N --scopes kb:read,kb:http`：签发令牌（明文只显示一次，库里只存 sha256）；
  `keybaton token list` 查看 name / scopes / hash
- 按工具做能力校验：`kb_list`→`kb:read`、`kb_http`→`kb:http`、`kb_audit`→`kb:audit`、`kb_get`→`kb:reveal`；
  越权返回 403 与缺失的 cap，并写审计 `tool_denied`
- `deploy/`：compose、tokens.json 模板、部署与轮换说明；镜像带 HEALTHCHECK

### 变更
- 审计 actor 取令牌的 `name`（不再统一写 `--actor`）；`kb_whoami` 返回 name + scopes
- `--token` / `KEYBATON_TOKEN` 降级为兼容模式（等价 `scopes=["*"]`），启动时提示改用 tokens.json

## [0.1.0] - 2026-11-14

首个公开版本。定位：**单机、单二进制、给脚本与 agent 用的凭据代理**。

### 新增
- **CLI**：`init` / `put` / `get` / `list` / `rm` / `run` / `import` / `serve` / `audit` / `version`
- **`run` 环境变量注入**：子进程可见 `KEYBATON_<NAME>`，不进 shell 历史；子进程退出码透传
- **`serve` HTTP + MCP**：`initialize` / `tools/list` / `tools/call`，支持 `X-Keybaton-Token`、`X-Api-Key`、`Bearer` 三种认证头
- **`kb_http` 代发请求**：服务端注入凭据，支持 `bearer` / `basic` / `header` / `query` 四种方式
- **响应脱敏**：响应体里出现的明文与 `base64(user:secret)` 替换为 `[REDACTED-BY-KEYBATON]`
- **审计**：记录 agent、动作、目标、成败；`run` 附带注入条数与子进程退出码
- **加密存储**：AES-256-GCM 逐条加密，主密钥独立存放（文件或环境变量）
- **只读端点**：`GET /healthz`（无鉴权）、`GET /api/secrets`（仅元数据）
- **容器镜像**：多阶段构建，非 root（UID 10001），单静态二进制
- **端到端测试**：`scripts/e2e_mcp.py`，10 条机器可判断言

### 安全
- 非 loopback 监听且无令牌时**拒绝启动**
- `kb_get` 默认关闭，需显式 `--allow-get`
- 出站请求**禁止跨主机重定向**（防凭据被 302 带走）
- 响应体截断 64KB
- `master.key` 以 0600 创建

### 已知限制
- 单令牌模型（一个服务一个令牌），无按条目授权
- 脱敏只覆盖明文与 base64(basic)，不覆盖 URL 编码等变形
- 主密钥与库同机存放；主机被攻破则失守
- 无 TOTP 支持

### 版本沿革（内部）
发布前的三轮"陌生人可用性测试"修复了 5 个阻塞级问题：

1. README 未说明下载后需要 `chmod +x` / 安装到 PATH
2. Docker 示例未带令牌，与"非 loopback 强制令牌"策略冲突
3. `kb_http` 的 `header` / `query` 参数名与实现不一致，且未知字段被静默忽略
4. `basic` 模式下回显的 base64 凭据未脱敏
5. `run` 在命令未启动时仍记审计为成功
