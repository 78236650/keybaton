# 参与贡献

欢迎 issue 与 PR。这个项目不大，规则也简单。

## 提 issue 前

1. 先看 [使用文档](docs/USAGE.md) 的「常见问题」
2. 确认版本：`keybaton version`
3. 附上：命令、完整输出、系统与架构

**安全漏洞请不要开 public issue**，见 [SECURITY.md](SECURITY.md)。

## 提 PR

```bash
go build ./... && go test ./... && go vet ./...
python3 scripts/e2e_mcp.py      # 需要先 go build -o /tmp/keybaton ./cmd/keybaton
```

要求：

- 新增命令/参数 → 同步更新 `docs/USAGE.md` 与 `--help`
- 涉及安全行为 → 同步更新 `docs/DESIGN.md` 与 `SECURITY.md`
- 破坏性变更 → 在 `CHANGELOG.md` 的 Unreleased 里写清楚
- 提交信息用 `feat:` / `fix:` / `docs:` / `refactor:` 前缀

## 不接受的方向

为了保持定位，以下 PR 会被拒（不是不好，是不合适）：

- 图形界面、浏览器插件（那是给人用的密码管理器）
- 引入重量级依赖（PG、Redis、向量库）
- 默认开放 `kb_get`
- 把主密钥和数据库合并成一个文件
