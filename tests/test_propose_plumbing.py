#!/usr/bin/env python3
"""Plumbing test for `shaar.py propose` with NO real model.

Starts a local fake OpenAI-compatible endpoint that returns a canned reply
(the human-written reference fix), runs `propose` against it, then gates the
result. This only proves the request/parse/diff/gate path works. It is not
evidence of any model's ability. Output goes to a temp copy, not out/.
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    work = tempfile.mkdtemp(prefix="shaar-plumbing-")
    repo = os.path.join(work, "repo")
    shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns("out", ".git", "__pycache__"))

    # Canned reply = fixture with the reference patch applied.
    sys.path.insert(0, repo)
    import shaar  # noqa: E402
    with open(os.path.join(repo, "fixture", "server.c"), encoding="utf-8") as fh:
        original = fh.read()
    with open(os.path.join(repo, "patches", "reference.diff"), encoding="utf-8") as fh:
        fixed = shaar.apply_patch(original, fh.read())
    reply = "Here is the corrected file.\n\n```c\n" + fixed + "```\n"
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen["path"], seen["auth"], seen["model"] = self.path, self.headers.get("Authorization"), body["model"]
            out = json.dumps({"model": body["model"], "choices": [{"message": {"content": reply},
                              "finish_reason": "stop"}], "usage": {"prompt_tokens": 0, "completion_tokens": 0}})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out.encode())

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = dict(os.environ, MODEL_API_KEY="test-key", SHAAR_MODEL="fake-model",
               SHAAR_API_BASE=f"http://127.0.0.1:{srv.server_port}/v1", NO_COLOR="1")
    p1 = subprocess.run([sys.executable, "shaar.py", "propose"], cwd=repo, env=env,
                        capture_output=True, text=True)
    p2 = subprocess.run([sys.executable, "shaar.py", "gate", "out/proposed/proposed.diff"],
                        cwd=repo, env=env, capture_output=True, text=True)
    srv.shutdown()
    shutil.rmtree(work, ignore_errors=True)

    ok = (p1.returncode == 0 and seen.get("path") == "/v1/chat/completions"
          and seen.get("auth") == "Bearer test-key" and seen.get("model") == "fake-model"
          and "=> ACCEPT" in p2.stdout)
    print("propose rc:", p1.returncode, "| request:", seen)
    print(p2.stdout.strip().splitlines()[-2] if p2.stdout else p2.stderr)
    print("PLUMBING TEST", "PASSED" if ok else "FAILED")
    if not ok:
        print(p1.stdout, p1.stderr, p2.stdout, p2.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
