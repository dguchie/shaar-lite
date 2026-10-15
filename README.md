# shaar-lite

**The library is post-quantum. The application isn't.**

OpenSSL 3.5 negotiates hybrid post-quantum key exchange (`X25519MLKEM768`) by default.
But an application that pins its own TLS group list overrides that default, so
upgrading the library changes nothing. `shaar-lite` is a small proof of concept of
the Sha'ar approach to fixing this: **the agent proposes, a deterministic gate decides.**

```
scan  ──►  propose (model)  ──►  gate (no model)  ──►  ACCEPT / REJECT  ──►  replay
deterministic   untrusted         5 deterministic       decided on           same verdict,
detector        patch             checks                evidence only        zero model calls
```

## What it does

1. **Scan.** A deterministic detector finds a classical-only group list pinned in C code
   (`SSL_CTX_set1_groups_list(ctx, "P-256")`).
2. **Propose.** A model (any OpenAI-compatible chat API; Meta Model API by default) returns
   a corrected file. `shaar-lite` turns it into a patch itself.
3. **Gate.** The patch is judged by checks that involve no model at all:

| Gate | Check |
|---|---|
| G1 | Patch applies with exact context match |
| G2 | Compiles with `-Wall -Wextra -Werror` against OpenSSL ≥ 3.5 |
| G3 | Two builds from different directories produce the same SHA-256 |
| G4 | A live server built from the patch negotiates `X25519MLKEM768` with a **reference OpenSSL client**, both when the client offers only the hybrid group and with the client's defaults |
| G5 | Re-scan finds no classical-only group pinning left |

4. **Replay.** Every verdict is written to `out/verdicts/*.json` with a SHA-256 over its
   contents. `replay` re-runs the gate from the recorded patch and checks that the verdict
   is identical. No model is called.

The gate trusts what the reference client observes on the wire, not what the patched
program says about itself (see mutant `m3_fake_telemetry`).

## Results (recorded run)

Recorded on macOS (Intel, Apple clang 17, OpenSSL 3.6.3) and on Linux x86_64 (OpenSSL 3.5.9,
gcc 13.3 and clang 18.1). All three toolchains gave the same decisions. The `reference` patch
is a **human-written** fix included to show what a passing patch looks like. The mutants are
deliberately wrong patches. `proposed` is the patch written by Muse Spark (below).

| Run | Decision | First failed gate | What the gate saw |
|---|---|---|---|
| `baseline-unpatched` | REJECT | G4 | Linked to OpenSSL 3.5+, still negotiates P-256; a PQ-only client gets no shared group |
| `reference` | **ACCEPT** | – | Negotiates `X25519MLKEM768` with both reference clients; legacy P-256 client still served |
| `m1_comment_only` | REJECT | G4 | Comment says "reviewed for post-quantum readiness"; behaviour unchanged |
| `m2_classical_upgrade` | REJECT | G4 | Swaps in X25519 and calls it "modern"; still not post-quantum |
| `m3_fake_telemetry` | REJECT | G4 | Server logs claim `X25519MLKEM768`; the reference client observes P-256 |
| `m4_wrong_api` | REJECT | G2 | Calls a non-existent OpenSSL function (`SSL_CTX_set1_group_list`) |
| `m5_stale_base` | REJECT | G1 | Patch written against a different version of the file |
| `proposed` (Muse Spark 1.3) | **ACCEPT** | – | Model's patch passes all five gates |

Replays matched their recorded verdict hashes with zero model calls (all runs on Linux; `reference` and `proposed` on macOS).

### The model's patch

`muse-spark-1.3` via the Meta Model API, one request per run, about 19 s and roughly
1,000 input / 3,000 output tokens. Two separate runs proposed the same change:

```diff
-    if (SSL_CTX_set1_groups_list(ctx, "P-256") != 1)
+    if (SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:P-256") != 1)
```

The gate accepted it: built from the patch, the server negotiates `X25519MLKEM768` with the
reference client. One thing the gate does not check: the model left the old comment
("pinned to NIST P-256") in place, so the comment is now stale. The patch, the raw model
reply and the verdict are in `out/`.

## Run it (macOS, Homebrew)

```bash
brew install openssl@3          # must be 3.5 or newer:
"$(brew --prefix openssl@3)/bin/openssl" version

python3 shaar.py demo           # scan + gate baseline, reference, mutants
python3 shaar.py replay out/verdicts/reference.json
```

To use a different OpenSSL install: `export SHAAR_OPENSSL_PREFIX=/path/to/openssl`.
To use a different compiler: `export SHAAR_CC=clang`.

### Ask a model for the fix

```bash
export MODEL_API_KEY=...                       # Meta Model API key
python3 shaar.py propose                       # writes out/proposed/proposed.diff
python3 shaar.py gate out/proposed/proposed.diff
python3 shaar.py demo                          # now includes the proposal
```

Defaults: endpoint `https://api.meta.ai/v1`, model `muse-spark-1.3`. Override with
`SHAAR_API_BASE` and `SHAAR_MODEL`. These defaults come from third-party documentation;
check them against Meta's docs. Any OpenAI-compatible endpoint works, including a local
Ollama server (`SHAAR_API_BASE=http://localhost:11434/v1`). The raw reply, token usage
and timing are saved to `out/proposed/response.json`.

`tests/test_propose_plumbing.py` checks the request/parse/gate path against a local fake
endpoint. It proves the plumbing works, not anything about a model.

## Scope (what this is not)

- One C file, one rule. The full Sha'ar design covers whole repositories, more rules,
  raw RSA/ECDH use, a CBOM diff and the application's own test suite.
- Key exchange only. Certificate signatures and PKI are out of scope; the test certificate
  is a throwaway ECDSA P-256 certificate.
- G3 compares two builds on one machine, with the same toolchain.
- A gate is only as good as its checks. These five are narrow by design.

## Requirements

Python 3.9+ (standard library only), a C compiler, OpenSSL ≥ 3.5.

## License

Apache-2.0. See `LICENSE`.
