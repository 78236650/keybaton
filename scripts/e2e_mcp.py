#!/usr/bin/env python3
"""keybaton 端到端验收：MCP + egress broker。

断言（机器可判）：
 A. serve 启动后 /healthz 返回 ok
 B. tools/list 不含 kb_get（默认不给明文）
 C. kb_http 能代发请求，且凭据被注入到目标服务（echo 服务记录到 Authorization）
 D. 返回给调用方的响应体里 **不含明文**
 E. 调用 kb_get 被拒
 F. 审计里出现 http 记录
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

BIN = os.environ.get("KB_BIN", "/tmp/keybaton")
PORT = 18765
ECHO_PORT = 18080
seen = {}


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        seen["auth"] = self.headers.get("Authorization", "")
        if self.path.startswith("/reveal"):
            # 模拟"上游把请求头回显在响应体里"的调试端点/4xx 页面
            body = json.dumps({k: v for k, v in self.headers.items()}).encode()
        else:
            body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def rpc(method, params=None, rid=1):
    payload = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/mcp",
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "X-Keybaton-Token": "tkn"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def main():
    home = tempfile.mkdtemp(prefix="kb-e2e-")
    env = dict(os.environ, KEYBATON_HOME=home)
    subprocess.run([BIN, "init"], env=env, check=True, capture_output=True)
    subprocess.run([BIN, "put", "github", "--user", "me"], env=env,
                   input=b"s3cr3t-value\n", check=True, capture_output=True)
    # v0.2 起：出站必须显式授权主机（默认禁止外发）
    subprocess.run([BIN, "policy", "github", "--allow", "127.0.0.1"], env=env, check=True, capture_output=True)

    srv = subprocess.Popen([BIN, "serve", "--addr", f"127.0.0.1:{PORT}", "--token", "tkn"],
                           env=env, stdout=open("/tmp/kb_serve.log", "w"), stderr=subprocess.STDOUT)
    httpd = HTTPServer(("127.0.0.1", ECHO_PORT), Echo)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(1.2)

    results = []
    try:
        # A
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=5) as r:
            results.append(("A healthz", r.status == 200))
        # B
        tl = rpc("tools/list", rid=2)
        names = [t["name"] for t in tl["result"]["tools"]]
        results.append(("B 无 kb_get", "kb_get" not in names))
        # C
        res = rpc("tools/call", {"name": "kb_http", "arguments": {
            "secret": "github", "url": f"http://127.0.0.1:{ECHO_PORT}/", "auth": "bearer"}}, rid=3)
        text = res["result"]["content"][0]["text"]
        results.append(("C 凭据已注入", seen.get("auth", "") == "Bearer s3cr3t-value"))
        # D
        results.append(("D 响应不含明文", "s3cr3t-value" not in text))
        # D2 上游回显也必须被脱敏
        res2 = rpc("tools/call", {"name": "kb_http", "arguments": {
            "secret": "github", "url": f"http://127.0.0.1:{ECHO_PORT}/reveal", "auth": "bearer"}}, rid=5)
        t2 = res2["result"]["content"][0]["text"]
        results.append(("D2 回显也被脱敏", "s3cr3t-value" not in t2 and "REDACTED-BY-KEYBATON" in t2))
        # D3 basic 形态（base64）也必须脱敏
        subprocess.run([BIN, "put", "basic1", "--user", "bob"], env=env,
                       input=b"pass123\n", check=True, capture_output=True)
        subprocess.run([BIN, "policy", "basic1", "--allow", "127.0.0.1"], env=env, check=True, capture_output=True)
        r3 = rpc("tools/call", {"name": "kb_http", "arguments": {
            "secret": "basic1", "url": f"http://127.0.0.1:{ECHO_PORT}/reveal", "auth": "basic"}}, rid=6)
        t3 = r3["result"]["content"][0]["text"]
        import base64 as _b64
        tok = _b64.b64encode(b"bob:pass123").decode()
        results.append(("D3 basic 已脱敏", tok not in t3 and "REDACTED-BY-KEYBATON" in t3))

        # C2 header_name 生效（README 里的真实字段名）
        r4 = rpc("tools/call", {"name": "kb_http", "arguments": {
            "secret": "github", "url": f"http://127.0.0.1:{ECHO_PORT}/reveal",
            "auth": "header", "header_name": "X-Custom-Auth"}}, rid=7)
        t4 = r4["result"]["content"][0]["text"]
        results.append(("C2 header_name 生效", "X-Custom-Auth" in t4))

        # C3 未知字段必须报错，不能静默忽略
        r5 = rpc("tools/call", {"name": "kb_http", "arguments": {
            "secret": "github", "url": f"http://127.0.0.1:{ECHO_PORT}/", "bogus_field": "x"}}, rid=8)
        results.append(("C3 未知字段被拒", r5["result"].get("isError") is True))

        # E
        res = rpc("tools/call", {"name": "kb_get", "arguments": {"name": "github"}}, rid=4)
        e = res["result"]
        results.append(("E kb_get 被拒", e.get("isError") is True))
        # F
        out = subprocess.run([BIN, "audit", "--limit", "10"], env=env, capture_output=True, text=True).stdout
        results.append(("F 审计含 http", "http" in out))
    finally:
        srv.terminate()
        httpd.shutdown()

    ok = all(v for _, v in results)
    for name, v in results:
        print(("PASS  " if v else "FAIL  ") + name)
    print("\nRESULT:", "ALL PASS" if ok else "HAS FAILURE")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
