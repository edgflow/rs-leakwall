# rs-leakwall

An AI data-leak firewall in Rust. `leakwall` inspects an outbound prompt **before** it reaches an AI provider, finds secrets and personal data with deterministic rules, redacts or blocks them according to a local policy, and only then asks an AI classifier about the remaining context.

Companion code for the video tutorial *Build an AI Data-Leak Firewall in Rust*.

```
prompt ─► 1. detect (regex + entropy) ─► 2. policy (policy.toml) ─► 3. redact ─► 4. AI risk ─► verdict
                                              │                                    ▲
                                              └─ block ─► never sent to the AI     └─ sees only [EMAIL_1], [AWS_KEY_1], …
```

**Deterministic detection is the first line of defense, not an LLM.** Regexes and an entropy check are fast, predictable and testable, and they run before any model sees the text. The AI layer only judges context (is this a confidential memo?) on the already-redacted prompt, and it fails closed.

## What it detects

| Kind | Rule | Default action |
|---|---|---|
| `email` | `name@domain.tld` | redact |
| `aws_key` | `AKIA…` / `ASIA…` + 16 chars | redact |
| `api_key` | `sk-…` (20+ chars) | redact |
| `github_token` | `ghp_…`, `gho_…`, … + 36 chars | redact |
| `private_key` | `-----BEGIN … PRIVATE KEY-----` | block |
| `high_entropy` | token of 24+ chars with Shannon entropy > 4.0 bits/char (hex tops out at exactly 4.0) | redact |

Edit `policy.toml` to change the actions (`allow`, `redact`, `block`) or the AI risk level that blocks (`[ai] block_on`).

## Usage

```bash
cargo run --release -- scan prompts/leaky.txt   # redact
cargo run --release -- scan prompts/key.txt     # block, exit code 2
cat my_prompt.txt | cargo run --release -- scan -
cargo run --release -- bench                    # latency per prompt size
cargo run --release -- entropy hello 7hG2kQ9xLm4Vr8Tz1Wq6Yb3NcP5s
cargo test
```

Exit codes: `0` allow or redact (send the redacted text), `2` block.

### AI classifier

By default the contextual risk check uses `LocalClassifier`, an offline, deterministic stand-in (weighted cues such as *confidential* or *internal only*). To use Claude instead:

```bash
export ANTHROPIC_API_KEY=...
cargo run --release --features llm -- scan prompts/memo.txt
```

`LEAKWALL_MODEL` overrides the model (default `claude-opus-5-5`). The classifier sends only the redacted prompt, asks for a JSON answer (`{"risk": "low|medium|high", "reason": "…"}`) and treats any error as high risk.

## Layout

```
src/detect.rs    Kind, Finding, Detector (regex rules + entropy safety net)
src/entropy.rs   Shannon entropy, high-entropy token finder
src/policy.rs    Action, Policy (policy.toml)
src/redact.rs    stable placeholders: the same secret → the same [EMAIL_1]
src/classify.rs  RiskClassifier trait, LocalClassifier
src/llm.rs       ClaudeClassifier (feature "llm")
src/lib.rs       Firewall::inspect – the pipeline
src/main.rs      CLI: scan, bench, entropy
```

All keys, tokens and addresses in `prompts/` and `tests/` are synthetic (`AKIAIOSFODNN7EXAMPLE` is AWS's documented example key; `example.com` is reserved for documentation).
