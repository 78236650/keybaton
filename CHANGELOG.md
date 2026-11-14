# 变更日志

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 计划中
- TOTP 代取：2FA 种子不出服务端，由服务端生成动态码
- `--file` 注入：把凭据写成临时文件并注入路径（给只支持文件读取的工具）
- 导入：1Password / Bitwarden / dotenv 目录批量
- 团队模式：多令牌 + 按条目授权 + 审批流

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
