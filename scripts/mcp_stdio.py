#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keybaton stdio ⇄ HTTP 桥。

给只支持 stdio 的 MCP 客户端用（Claude Desktop、部分 agent 框架）：
    command: /usr/bin/python3
    args:    ["/path/to/mcp_stdio.py"]
    env:     KEYBATON_URL=http://127.0.0.1:8765/mcp  KEYBATON_TOKEN=<令牌>

只用标准库，不需要 pip 安装。
"""
import json
import os
import sys
import urllib.error
import urllib.request

URL = os.environ.get("KEYBATON_URL", "http://127.0.0.1:8765/mcp")
TOKEN = os.environ.get("KEYBATON_TOKEN", "")


def post(payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(URL, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("X-Keybaton-Token", TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")[:300]
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": -32000, "message": f"HTTP {e.code}: {body}"}}
    except Exception as e:  # noqa: BLE001
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": -32000, "message": str(e)[:300]}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = post(req)
        if req.get("id") is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
