#!/usr/bin/env python3
"""shaar-lite: the agent proposes, a deterministic gate decides.

Proof of concept of the Sha'ar loop on one C fixture:

    scan     deterministic detector for classical-only TLS group pinning
    propose  ask a model (OpenAI-compatible API, e.g. Meta Model API) for a fix
    gate     apply a patch and judge it with deterministic checks only
    replay   re-run the gate on a recorded verdict with zero model calls
    demo     scan, then gate the reference fix, the mutants and any proposal
    diff     turn an edited copy of fixture/server.c into a patch file

Standard library only. Requires a C compiler and OpenSSL >= 3.5.
"""

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(ROOT, "fixture")
TARGET = "server.c"
OUT = os.path.join(ROOT, "out")

# Golden invariant: whatever policy.json says, the required group must be a
# post-quantum (ML-KEM based) group. A policy file cannot weaken this.
GOLDEN_PQ_MARKER = "MLKEM"

CLASSICAL_GROUPS = {
    "p-256", "p-384", "p-521", "prime256v1", "secp256r1", "secp384r1",
    "secp521r1", "x25519", "x448", "ffdhe2048", "ffdhe3072", "ffdhe4096",
    "ffdhe6144", "ffdhe8192", "brainpoolp256r1", "brainpoolp384r1",
    "brainpoolp512r1", "brainpoolp256r1tls13", "brainpoolp384r1tls13",
    "brainpoolp512r1tls13",
}

# ----------------------------------------------------------------- output

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def mark(status):
    return {
        "PASS": c("PASS", "32;1"),
        "FAIL": c("FAIL", "31;1"),
        "SKIP": c("SKIP", "2"),
        "ACCEPT": c("ACCEPT", "32;1"),
        "REJECT": c("REJECT", "31;1"),
    }.get(status, status)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    with open(path, "rb") as fh:
        return sha256_bytes(fh.read())


def die(msg):
    print(c("error: ", "31;1") + msg, file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------- toolchain


def openssl_prefix():
    env = os.environ.get("SHAAR_OPENSSL_PREFIX")
    if env:
        return env
    if shutil.which("brew"):
        try:
            p = subprocess.run(["brew", "--prefix", "openssl@3"], capture_output=True,
                               text=True, timeout=30)
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return "/usr"


def toolchain():
    prefix = openssl_prefix()
    exe = os.path.join(prefix, "bin", "openssl")
    if not os.path.exists(exe):
        die(f"no openssl binary at {exe}. Set SHAAR_OPENSSL_PREFIX to an OpenSSL >= 3.5 install.")
    env = dict(os.environ)
    libdir = os.path.join(prefix, "lib")
    env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    ver = subprocess.run([exe, "version"], capture_output=True, text=True, env=env).stdout.strip()
    m = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", ver)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        die(f"{exe} reports '{ver}'. OpenSSL >= 3.5 is required (ML-KEM support).")
    cc = os.environ.get("SHAAR_CC", "cc")
    if not shutil.which(cc):
        die(f"C compiler '{cc}' not found. Set SHAAR_CC.")
    return {"prefix": prefix, "openssl": exe, "version": ver, "env": env, "cc": cc,
            "libdir": libdir, "include": os.path.join(prefix, "include")}


# ------------------------------------------------------------------ scanner


def strip_comments(src):
    """Blank out C comments and keep string literals, preserving line numbers."""
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


GROUP_LIST_CALL = re.compile(
    r"\b(SSL_CTX_set1_groups_list|SSL_set1_groups_list|SSL_CTX_set1_curves_list|"
    r"SSL_set1_curves_list)\s*\(\s*[^,]+,\s*\"([^\"]*)\"")
GROUP_ARRAY_CALL = re.compile(
    r"\b(SSL_CTX_set1_groups|SSL_set1_groups|SSL_CTX_set1_curves|SSL_set1_curves)\s*\(")


def group_tokens(spec):
    toks = []
    for t in re.split(r"[:/,]", spec):
        t = t.strip().lstrip("?*-").strip()
        if t:
            toks.append(t)
    return toks


def classify_group_list(spec):
    toks = group_tokens(spec)
    if any(t.upper() == "DEFAULT" for t in toks):
        return "default"
    if any(GOLDEN_PQ_MARKER in t.upper() for t in toks):
        return "pq"
    if toks and all(t.lower() in CLASSICAL_GROUPS for t in toks):
        return "classical-only"
    return "unknown"


def scan_source(name, text):
    findings = []
    clean = strip_comments(text)
    raw_lines = text.splitlines()

    def line_of(pos):
        return clean.count("\n", 0, pos) + 1

    for m in GROUP_LIST_CALL.finditer(clean):
        kind = classify_group_list(m.group(2))
        if kind == "classical-only":
            ln = line_of(m.start())
            findings.append({
                "rule": "SHAAR-G001",
                "title": "Classical-only TLS group list pinned in code",
                "file": name, "line": ln,
                "evidence": raw_lines[ln - 1].strip(),
                "groups": group_tokens(m.group(2)),
                "detail": "Overrides OpenSSL 3.5's hybrid post-quantum default; "
                          "upgrading the library does not change what this negotiates.",
            })
    for m in GROUP_ARRAY_CALL.finditer(clean):
        ln = line_of(m.start())
        findings.append({
            "rule": "SHAAR-G002",
            "title": "TLS groups set from a NID array (needs review)",
            "file": name, "line": ln,
            "evidence": raw_lines[ln - 1].strip(),
            "groups": [],
            "detail": "shaar-lite does not evaluate NID arrays; flagged for manual review.",
        })
    for f in findings:
        f["id"] = "F-" + sha256_bytes(f"{f['rule']}|{f['file']}|{f['evidence']}".encode())[:12]
    return sorted(findings, key=lambda f: (f["file"], f["line"], f["rule"]))


def scan_dir(src_dir):
    findings = []
    for name in sorted(os.listdir(src_dir)):
        if name.endswith((".c", ".h")):
            with open(os.path.join(src_dir, name), encoding="utf-8") as fh:
                findings += scan_source(name, fh.read())
    return findings


# ------------------------------------------------------------ patch handling


class PatchError(Exception):
    pass


HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_patch(text):
    """Parse a single-file unified diff. Returns (target_name, hunks)."""
    lines = text.splitlines()
    i, target = 0, None
    while i < len(lines) and not lines[i].startswith("--- "):
        i += 1
    if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
        raise PatchError("no unified diff header found")
    target = lines[i + 1][4:].split("\t")[0].strip()
    if target.startswith("b/"):
        target = target[2:]
    i += 2
    hunks = []
    while i < len(lines):
        m = HUNK.match(lines[i])
        if not m:
            if lines[i].startswith("--- "):
                raise PatchError("multi-file patches are out of scope for shaar-lite")
            i += 1
            continue
        old_start = int(m.group(1))
        old_len = int(m.group(2)) if m.group(2) is not None else 1
        new_len = int(m.group(4)) if m.group(4) is not None else 1
        i += 1
        body = []
        while i < len(lines) and not HUNK.match(lines[i]) and not lines[i].startswith("--- "):
            ln = lines[i]
            if ln.startswith("\\"):
                i += 1
                continue
            if ln == "":
                ln = " "
            if ln[0] not in " +-":
                raise PatchError(f"malformed hunk line: {ln!r}")
            body.append(ln)
            i += 1
        olds = sum(1 for b in body if b[0] in " -")
        news = sum(1 for b in body if b[0] in " +")
        if olds != old_len or news != new_len:
            raise PatchError(f"hunk at line {old_start} has wrong line counts")
        hunks.append((old_start, body))
    if not hunks:
        raise PatchError("patch contains no hunks")
    return target, hunks


def apply_patch(original, patch_text):
    """Strict application: every context/removed line must match exactly."""
    target, hunks = parse_patch(patch_text)
    if target != TARGET:
        raise PatchError(f"patch targets '{target}', expected '{TARGET}'")
    src = original.splitlines()
    out, pos = [], 0
    for old_start, body in hunks:
        start = old_start - 1 if old_start > 0 else 0
        if start < pos:
            raise PatchError("overlapping hunks")
        out.extend(src[pos:start])
        k = start
        for b in body:
            if b[0] in " -":
                if k >= len(src) or src[k] != b[1:]:
                    raise PatchError(f"context mismatch at line {k + 1}")
                if b[0] == " ":
                    out.append(src[k])
                k += 1
            else:
                out.append(b[1:])
        pos = k
    out.extend(src[pos:])
    return "\n".join(out) + "\n"


def make_diff(original, modified):
    d = difflib.unified_diff(original.splitlines(), modified.splitlines(),
                             fromfile="a/" + TARGET, tofile="b/" + TARGET, lineterm="")
    return "\n".join(d) + "\n"


# --------------------------------------------------------------------- gate


def compile_fixture(tc, src_dir, out_bin):
    cmd = [tc["cc"], "-std=gnu11", "-O2", "-Wall", "-Wextra",
           "-Werror", f"-ffile-prefix-map={src_dir}=fixture", "-I", tc["include"],
           os.path.join(src_dir, TARGET), "-o", out_bin, "-L", tc["libdir"],
           f"-Wl,-rpath,{tc['libdir']}", "-lssl", "-lcrypto"]
    p = subprocess.run(cmd, capture_output=True, text=True, env=tc["env"])
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# OpenSSL 3.5 s_client -brief prints, depending on the group type:
#   "Negotiated TLS1.3 group: X25519MLKEM768"      (KEM / hybrid groups)
#   "Peer Temp Key: ECDH, prime256v1, 256 bits"    (classical ECDHE)
#   "Peer Temp Key: X25519, 253 bits"
NEGOTIATED_KEM = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)")
PEER_TEMP_KEY = re.compile(r"(?:Peer|Server) Temp Key:\s*([^\n]+)")
GROUP_ALIASES = {"prime256v1": "P-256", "secp256r1": "P-256", "secp384r1": "P-384",
                 "secp521r1": "P-521"}


def parse_negotiated(text):
    m = NEGOTIATED_KEM.search(text)
    if m:
        return m.group(1)
    m = PEER_TEMP_KEY.search(text)
    if m:
        parts = [p.strip() for p in m.group(1).split(",")]
        name = parts[1] if parts[0] in ("ECDH", "DH") and len(parts) > 1 else parts[0]
        return GROUP_ALIASES.get(name, name)
    return None


def probe(tc, port, groups):
    cmd = [tc["openssl"], "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-brief"]
    if groups:
        cmd += ["-groups", groups]
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=15, env=tc["env"])
    except subprocess.TimeoutExpired:
        return {"handshake": False, "group": None}
    text = p.stdout + p.stderr
    ok = "CONNECTION ESTABLISHED" in text
    return {"handshake": ok, "group": parse_negotiated(text) if ok else None}


def run_server(tc, binary, workdir):
    key, cert = os.path.join(workdir, "key.pem"), os.path.join(workdir, "cert.pem")
    cnf = os.path.join(workdir, "req.cnf")
    with open(cnf, "w", encoding="utf-8") as fh:
        fh.write("[req]\ndistinguished_name = dn\n[dn]\n")
    # Throwaway test certificate. Certificate signatures/PKI are out of scope here.
    subprocess.run([tc["openssl"], "req", "-config", cnf, "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=localhost", "-days", "1",
                    "-keyout", key, "-out", cert], capture_output=True, check=True, env=tc["env"])
    port = free_port()
    errlog = open(os.path.join(workdir, "server.stderr"), "w")
    proc = subprocess.Popen([binary, str(port), cert, key], stdout=subprocess.PIPE,
                            stderr=errlog, text=True, env=tc["env"])
    deadline = time.time() + 10
    ready = False
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.strip() == "READY":
            ready = True
            break
        if proc.poll() is not None:
            break
    return proc, port, ready, errlog


def gate(tc, policy, patch_path, label):
    with open(os.path.join(FIXTURE, TARGET), encoding="utf-8") as fh:
        original = fh.read()
    if patch_path is None:  # baseline: judge the unpatched fixture
        patch_text = None
    else:
        with open(patch_path, encoding="utf-8") as fh:
            patch_text = fh.read()

    gates = []

    def record(gid, title, status, evidence):
        gates.append({"gate": gid, "title": title, "status": status, "evidence": evidence})

    def skip_rest(ids):
        for gid, title in ids:
            record(gid, title, "SKIP", {"reason": "not run: an earlier gate failed"})

    later = [("G2", "Compiles with -Wall -Wextra -Werror"),
             ("G3", "Reproducible build (two builds, different paths, same SHA-256)"),
             ("G4", "Live handshake negotiates post-quantum hybrid (reference client)"),
             ("G5", "Re-scan: no classical-only group pinning remains")]

    work = tempfile.mkdtemp(prefix="shaar-gate-")
    server = None
    try:
        # G1 apply
        g1 = "Patch applies cleanly (strict context match)"
        if patch_text is None:
            patched = original
            record("G1", g1, "PASS", {"note": "baseline run: unpatched source"})
        else:
            try:
                patched = apply_patch(original, patch_text)
            except PatchError as e:
                record("G1", g1, "FAIL", {"error": str(e)})
                skip_rest(later)
                return finish(tc, policy, patch_path, patch_text, label, gates)
            record("G1", g1, "PASS", {"patched_source_sha256": sha256_bytes(patched.encode())})

        builds = []
        for i, sub in enumerate(("b1/src", "b2/elsewhere/src")):
            sdir = os.path.join(work, sub)
            os.makedirs(sdir)
            with open(os.path.join(sdir, TARGET), "w", encoding="utf-8") as fh:
                fh.write(patched)
            bdir = os.path.join(work, f"bin{i + 1}")
            os.makedirs(bdir)
            ok, log = compile_fixture(tc, sdir, os.path.join(bdir, "server"))
            builds.append((ok, log, os.path.join(bdir, "server")))
            if not ok:
                break

        # G2 compile
        ok, log, bin1 = builds[0]
        if not ok:
            first = [ln for ln in log.splitlines() if "error" in ln][:3]
            first = [re.sub(re.escape(work) + r"\S*?/", "", ln) for ln in first]
            record("G2", later[0][1], "FAIL", {"compiler_errors": first})
            skip_rest(later[1:])
            return finish(tc, policy, patch_path, patch_text, label, gates)
        record("G2", later[0][1], "PASS", {"compiler": os.path.basename(tc["cc"])})

        # G3 reproducible
        ok2, log2, bin2 = builds[1]
        h1 = sha256_file(bin1)
        h2 = sha256_file(bin2) if ok2 else None
        status = "PASS" if ok2 and h1 == h2 else "FAIL"
        record("G3", later[1][1], status, {"build1_sha256": h1, "build2_sha256": h2})
        if status == "FAIL":
            skip_rest(later[2:])
            return finish(tc, policy, patch_path, patch_text, label, gates)

        # G4 handshake
        server, port, ready, errlog = run_server(tc, bin1, work)
        results, gated_ok = [], ready
        if ready:
            for pr in policy["probes"]:
                r = probe(tc, port, pr["client_groups"])
                passed = r["handshake"] and r["group"] == pr["expect_group"]
                gated_ok = gated_ok and passed
                results.append({"probe": pr["id"], "client_groups": pr["client_groups"] or "default",
                                "expected": pr["expect_group"], "observed": r["group"],
                                "handshake": r["handshake"], "pass": passed})
            info = []
            for pr in policy.get("info_probes", []):
                r = probe(tc, port, pr["client_groups"])
                info.append({"probe": pr["id"], "client_groups": pr["client_groups"],
                             "observed": r["group"], "handshake": r["handshake"]})
        else:
            info = []
        server.terminate()
        server.wait(timeout=5)
        errlog.close()
        with open(os.path.join(work, "server.stderr"), encoding="utf-8", errors="replace") as fh:
            claims = sorted(set(re.findall(r"group=(\S+)", fh.read())))
        record("G4", later[2][1], "PASS" if gated_ok else "FAIL",
               {"server_started": ready, "probes": results, "info_probes": info,
                "server_self_reported_groups_untrusted": claims})
        if not gated_ok:
            skip_rest(later[3:])
            return finish(tc, policy, patch_path, patch_text, label, gates)

        # G5 rescan
        remaining = [f for f in scan_source(TARGET, patched) if f["rule"] in ("SHAAR-G001", "SHAAR-G002")]
        record("G5", later[3][1], "PASS" if not remaining else "FAIL",
               {"remaining_findings": [f["id"] for f in remaining]})
        return finish(tc, policy, patch_path, patch_text, label, gates)
    finally:
        if server is not None and server.poll() is None:
            server.kill()
        shutil.rmtree(work, ignore_errors=True)


def finish(tc, policy, patch_path, patch_text, label, gates):
    decision = "ACCEPT" if all(g["status"] == "PASS" for g in gates) else "REJECT"
    with open(os.path.join(FIXTURE, TARGET), "rb") as fh:
        fixture_hash = sha256_bytes(fh.read())
    body = {
        "tool": "shaar-lite",
        "label": label,
        "policy_id": policy["policy_id"],
        "inputs": {
            "fixture_sha256": fixture_hash,
            "patch_file": os.path.relpath(patch_path, ROOT) if patch_path else None,
            "patch_sha256": sha256_bytes(patch_text.encode()) if patch_text is not None else None,
            "policy_sha256": sha256_bytes(canonical(policy).encode()),
            "openssl": tc["version"],
        },
        "gates": gates,
        "decision": decision,
        "model_calls_during_gate": 0,
    }
    body["verdict_sha256"] = sha256_bytes(canonical(body).encode())
    return body


def load_policy():
    with open(os.path.join(ROOT, "policy.json"), encoding="utf-8") as fh:
        policy = json.load(fh)
    for pr in policy["probes"]:
        if GOLDEN_PQ_MARKER not in (pr["expect_group"] or "").upper():
            die(f"policy probe '{pr['id']}' expects a non-post-quantum group; "
                "the golden invariant forbids this.")
    return policy


def print_verdict(v):
    print(f"\n{c('Gate', '1')}: {v['label']}  ({v['inputs']['patch_file'] or 'no patch: unpatched fixture'})")
    for g in v["gates"]:
        print(f"  {g['gate']}  {mark(g['status']):>6}  {g['title']}")
        ev = g["evidence"]
        if "note" in ev:
            print(f"         ({ev['note']})")
        if g["status"] == "FAIL":
            if "error" in ev:
                print(f"         -> {ev['error']}")
            for line in ev.get("compiler_errors", []):
                print(f"         -> {line}")
            if g["gate"] == "G3":
                print(f"         -> build1 {ev['build1_sha256']}\n         -> build2 {ev['build2_sha256']}")
            for f in ev.get("remaining_findings", []):
                print(f"         -> still present: {f}")
        if g["gate"] == "G3" and g["status"] == "PASS":
            print(f"         sha256 {ev['build1_sha256'][:16]}... (both builds)")
        if g["gate"] == "G4" and g["status"] != "SKIP":
            for p in ev["probes"]:
                obs = p["observed"] or ("no shared group / handshake failed" if not p["handshake"] else "?")
                print(f"         client[{p['client_groups']}] -> {obs}   "
                      f"(want {p['expected']}) {mark('PASS' if p['pass'] else 'FAIL')}")
            for p in ev["info_probes"]:
                obs = p["observed"] or "refused"
                print(f"         client[{p['client_groups']}] -> {obs}   (info only)")
            if ev["server_self_reported_groups_untrusted"]:
                print(f"         server claims {ev['server_self_reported_groups_untrusted']} "
                      "(ignored: the gate trusts the reference client, not the patched code)")
    print(f"  => {mark(v['decision'])}   verdict {v['verdict_sha256'][:16]}...")


def save_verdict(v, name):
    d = os.path.join(OUT, "verdicts")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{name}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(v, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


# ------------------------------------------------------------------ propose

SYSTEM_PROMPT = """You are a code-migration agent. You fix C code that uses OpenSSL so that its
TLS key exchange is post-quantum ready. The deployment links OpenSSL 3.5, which supports the
hybrid group X25519MLKEM768.

Rules:
- Return the COMPLETE corrected file in a single ```c fenced block, and nothing else after it.
- Keep the change minimal. Do not change unrelated behaviour, APIs or formatting.
- The server must prefer X25519MLKEM768 and may keep classical groups as fallbacks.
- Do not add logging that claims a group; your patch will be verified by an external client."""


def propose(args):
    findings = scan_dir(FIXTURE)
    if not findings:
        die("scanner found nothing to fix")
    with open(os.path.join(FIXTURE, TARGET), encoding="utf-8") as fh:
        original = fh.read()
    key = os.environ.get("SHAAR_API_KEY") or os.environ.get("MODEL_API_KEY")
    base = os.environ.get("SHAAR_API_BASE", "https://api.meta.ai/v1").rstrip("/")
    model = os.environ.get("SHAAR_MODEL", "muse-spark-1.3")
    if not key:
        die("set MODEL_API_KEY (or SHAAR_API_KEY) to your Meta Model API key")
    user = ("Findings from a deterministic scanner:\n" + json.dumps(findings, indent=2) +
            f"\n\nFile `{TARGET}`:\n```c\n{original}```")
    payload = {"model": model, "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                            {"role": "user", "content": user}],
               "max_completion_tokens": int(os.environ.get("SHAAR_MAX_TOKENS", "8192"))}
    req = urllib.request.Request(base + "/chat/completions", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {key}"})
    print(f"Asking {model} at {base} for a fix to {len(findings)} finding(s)...")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        die(f"API returned HTTP {e.code}: {e.read().decode(errors='replace')[:500]}")
    except urllib.error.URLError as e:
        die(f"could not reach {base}: {e.reason}")
    elapsed = round(time.time() - t0, 1)
    content = data["choices"][0]["message"].get("content") or ""
    blocks = re.findall(r"```(?:c|C)?\s*\n(.*?)```", content, re.S)
    d = os.path.join(OUT, "proposed")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "response.json"), "w", encoding="utf-8") as fh:
        json.dump({"model": data.get("model", model), "endpoint": base, "usage": data.get("usage"),
                   "finish_reason": data["choices"][0].get("finish_reason"),
                   "elapsed_seconds": elapsed, "content": content}, fh, indent=2)
    if not blocks:
        die("model reply contained no ```c block; raw reply saved to out/proposed/response.json")
    proposed = max(blocks, key=len)
    if not proposed.endswith("\n"):
        proposed += "\n"
    diff = make_diff(original, proposed)
    path = os.path.join(d, "proposed.diff")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(diff)
    usage = data.get("usage") or {}
    print(f"Model replied in {elapsed}s; tokens in/out: "
          f"{usage.get('prompt_tokens', '?')}/{usage.get('completion_tokens', '?')}")
    print(f"Proposed patch: {os.path.relpath(path, ROOT)}\n")
    print(diff)
    print("Next: python3 shaar.py gate out/proposed/proposed.diff")


# --------------------------------------------------------------- commands


def cmd_scan(args):
    findings = scan_dir(FIXTURE)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
        fh.write("\n")
    print(f"{c('Scan', '1')}: fixture/  ({len(findings)} finding(s))")
    for f in findings:
        print(f"  {c(f['rule'], '33;1')} {f['id']}  {f['file']}:{f['line']}  {f['title']}")
        print(f"         {f['evidence']}")
    return findings


def cmd_gate(args):
    tc, policy = toolchain(), load_policy()
    label = args.label or os.path.splitext(os.path.basename(args.patch))[0]
    v = gate(tc, policy, os.path.abspath(args.patch), label)
    print_verdict(v)
    path = save_verdict(v, label)
    print(f"  saved {os.path.relpath(path, ROOT)}")
    return v


def cmd_replay(args):
    with open(args.verdict, encoding="utf-8") as fh:
        old = json.load(fh)
    patch = None
    if old["inputs"]["patch_file"]:
        patch = os.path.join(ROOT, old["inputs"]["patch_file"])
        if not os.path.exists(patch) or sha256_file(patch) != old["inputs"]["patch_sha256"]:
            die("recorded patch file is missing or has changed; cannot replay")
    tc, policy = toolchain(), load_policy()
    new = gate(tc, policy, patch, old["label"])
    same = new["verdict_sha256"] == old["verdict_sha256"]
    print(f"{c('Replay', '1')}: {old['label']}  (0 model calls)")
    print(f"  recorded {old['verdict_sha256']}")
    print(f"  replayed {new['verdict_sha256']}")
    print(f"  => {mark('PASS') if same else mark('FAIL')} "
          f"{'identical verdict' if same else 'verdict differs'}")
    return 0 if same else 1


def cmd_demo(args):
    tc, policy = toolchain(), load_policy()
    print(f"OpenSSL: {tc['version']}   compiler: {tc['cc']}\n")
    cmd_scan(args)
    runs = [("baseline-unpatched", None),
            ("reference", os.path.join(ROOT, "patches", "reference.diff"))]
    for name in sorted(os.listdir(os.path.join(ROOT, "mutants"))):
        if name.endswith(".diff"):
            runs.append((os.path.splitext(name)[0], os.path.join(ROOT, "mutants", name)))
    prop = os.path.join(OUT, "proposed", "proposed.diff")
    if os.path.exists(prop):
        runs.append(("proposed", prop))
    summary = []
    for label, path in runs:
        v = gate(tc, policy, path, label)
        print_verdict(v)
        save_verdict(v, label)
        failed = next((g["gate"] for g in v["gates"] if g["status"] == "FAIL"), "-")
        summary.append((label, v["decision"], failed))
    print(f"\n{c('Summary', '1')}")
    for label, decision, failed in summary:
        print(f"  {label:<28} {mark(decision):>8}   first failed gate: {failed}")
    print("\nReplay any verdict with: python3 shaar.py replay out/verdicts/<name>.json")


def cmd_diff(args):
    with open(os.path.join(FIXTURE, TARGET), encoding="utf-8") as fh:
        original = fh.read()
    with open(args.modified, encoding="utf-8") as fh:
        modified = fh.read()
    sys.stdout.write(make_diff(original, modified))


def main():
    ap = argparse.ArgumentParser(description="shaar-lite: the agent proposes, a deterministic gate decides.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan", help="run the deterministic scanner on fixture/")
    sub.add_parser("propose", help="ask the model for a patch (needs MODEL_API_KEY)")
    g = sub.add_parser("gate", help="judge a patch with deterministic gates")
    g.add_argument("patch")
    g.add_argument("--label")
    r = sub.add_parser("replay", help="re-run the gate for a recorded verdict")
    r.add_argument("verdict")
    sub.add_parser("demo", help="scan, then gate reference, mutants and any proposal")
    d = sub.add_parser("diff", help="print a patch from an edited copy of fixture/server.c")
    d.add_argument("modified")
    args = ap.parse_args()
    fn = {"scan": cmd_scan, "propose": propose, "gate": cmd_gate, "replay": cmd_replay,
          "demo": cmd_demo, "diff": cmd_diff}[args.cmd]
    rc = fn(args)
    sys.exit(rc if isinstance(rc, int) else 0)


if __name__ == "__main__":
    main()
