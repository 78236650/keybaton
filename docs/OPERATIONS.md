# 运维文档

给"要在服务器上长期跑"的人：部署、备份、升级、故障处置。

---

## 1. 部署形态选择

| 形态 | 场景 | 要点 |
|---|---|---|
| 前台进程 | 本机试用 | `keybaton serve --addr 127.0.0.1:8765` |
| systemd | Linux 服务器 | 见 §2 |
| Docker | 客户现场、NAS | 见 §3 |
| launchd | macOS 常驻 | 见 §4 |

**共同原则**：服务只监听你真正要暴露的地址。跨网访问请不要直接暴露公网——走 VPN / ZeroTier / 内网。

---

## 2. systemd

`/etc/systemd/system/keybaton.service`：

```ini
[Unit]
Description=keybaton credential broker
After=network-online.target

[Service]
Type=simple
User=keybaton
Group=keybaton
Environment=KEYBATON_HOME=/var/lib/keybaton
Environment=KEYBATON_TOKEN=<换成随机值>
ExecStart=/usr/local/bin/keybaton serve --addr 127.0.0.1:8765
Restart=on-failure
RestartSec=3

# 加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/keybaton

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now keybaton
sudo systemctl status keybaton
journalctl -u keybaton -f
```

> `KEYBATON_TOKEN` 写在 unit 里是明文。更稳妥：用 `EnvironmentFile=/etc/keybaton.env`（权限 600）。

---

## 3. Docker

```yaml
services:
  keybaton:
    image: ghcr.io/gomind-nx/keybaton:0.1.0
    container_name: keybaton
    restart: unless-stopped
    ports:
      - "127.0.0.1:8765:8765"
    environment:
      KEYBATON_TOKEN: ${KEYBATON_TOKEN}
    volumes:
      - ./data:/home/kb/.keybaton
```

```bash
docker compose up -d
docker compose logs -f
```

注意事项：

- 端口前缀写 `127.0.0.1:`，别写成 `0.0.0.0:`
- 数据卷必须持久化，否则重建容器 = 库没了
- 容器内 UID 是 10001，宿主目录要 `chown 10001:10001`

---

## 4. macOS launchd

`~/Library/LaunchAgents/dev.keybaton.serve.plist`：

```xml
<key>ProgramArguments</key>
<array>
  <string>/Users/你/.local/bin/keybaton</string>
  <string>serve</string>
  <string>--addr</string>
  <string>127.0.0.1:8765</string>
  <string>--token</string>
  <string>换成随机值</string>
</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
```

```bash
launchctl load ~/Library/LaunchAgents/dev.keybaton.serve.plist
launchctl list | grep keybaton
```

---

## 5. 备份

**必须一起备份的两个文件**：

```
master.key   主密钥
vault.db     SQLite 库
```

```bash
# 冷备（推荐，先停服务）
systemctl stop keybaton
tar czf keybaton-$(date +%F).tgz -C /var/lib keybaton
systemctl start keybaton

# 热备（WAL 模式下可用）
sqlite3 /var/lib/keybaton/vault.db ".backup '/backup/vault-$(date +%F).db'"
```

**备份策略建议**：

| 项 | 建议 |
|---|---|
| 频率 | 每周 + 每次批量变更后 |
| 位置 | 与主机不同的介质 |
| 加密 | 备份包本身再加密（`age` 或 `gpg`） |
| 主密钥 | **单独**存到密码管理器，不要和备份包放一起 |

> 主密钥和数据库放在同一个压缩包里，等于把钥匙和保险箱捆在一起丢。

---

## 6. 升级

```bash
# 1. 备份（见 §5）
# 2. 停服务
systemctl stop keybaton
# 3. 替换二进制
sudo install -m 0755 keybaton-linux-amd64 /usr/local/bin/keybaton
# 4. 起服务并自检
systemctl start keybaton
keybaton version
curl -s http://127.0.0.1:8765/healthz
```

Docker：

```bash
docker compose pull && docker compose up -d
```

**升级前看 CHANGELOG 的「破坏性变更」小节**。库结构若有迁移，会在启动时自动执行并打印日志。

---

## 7. 令牌轮换

```bash
# 生成新令牌
NEW=$(openssl rand -hex 24)
# 更新 unit / compose 里的 KEYBATON_TOKEN
systemctl restart keybaton     # 或 docker compose up -d
# 通知所有 agent 客户端更新 Header
```

旧令牌在重启后立即失效。**轮换期间会有短暂中断**，建议在低峰做。

---

## 8. 故障处置

| 症状 | 原因 | 处置 |
|---|---|---|
| `拒绝启动：监听 0.0.0.0 但未设置令牌` | 没传 token | 加 `--token` 或 `KEYBATON_TOKEN` |
| 启动即退出，日志 `decrypt: cipher: message authentication failed` | `master.key` 与库不匹配 | 恢复对应版本的 master.key；无法恢复则库作废 |
| `401 unauthorized` | 客户端令牌不对 | 核对 Header 名（`X-Keybaton-Token` / `X-Api-Key` / `Bearer`） |
| `kb_get 未启用` | 默认关闭 | 用 `kb_http`；确实需要明文才加 `--allow-get` |
| `请求失败: 拒绝跨主机重定向` | 目标 302 到别的域名 | 直接请求最终地址，或让上游改配置 |
| 审计里大量 `FAIL exec not found` | `run` 的命令不存在 | 检查子进程命令与 PATH |
| 数据库锁超时 | 并发写入 | WAL 已开，仍失败则检查磁盘与 NFS |

日志位置：systemd 看 `journalctl -u keybaton`，Docker 看 `docker logs keybaton`，前台看 stdout。

---

## 9. 安全检查清单（上线前）

- [ ] 监听地址不是 `0.0.0.0`（除非确实需要，且已配令牌 + 防火墙）
- [ ] `KEYBATON_TOKEN` 是随机值，不是 `changeme`
- [ ] `~/.keybaton` 权限 700，`master.key` 600
- [ ] 主密钥已单独备份到密码管理器
- [ ] 没有开 `--allow-get`（除非明确需要）
- [ ] 审计能被读到（`keybaton audit`），且知道谁持有令牌
- [ ] 容器/主机的端口没有被映射到公网
