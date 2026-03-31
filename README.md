# cli-warden

`cli-warden` is a Rust daemon/client system for running a strict, explicit set of CLI
capabilities over gRPC with mandatory mTLS.

It is designed for scenarios where an agent environment needs controlled access to
sensitive tooling on another machine.

## Security Model

- Explicit whitelist of exposed commands (`[commands]`).
- Structured argv policy evaluation (no remote shell semantics).
- mTLS only (daemon and client certs signed by a local CA).
- Optional external approval path (`allow_hook`) for `ask` decisions.
- Best-effort literal secret redaction in output streams.
- Fail-closed on non-UTF-8 command output.

Non-goals:

- Absolute exfiltration prevention in all contexts.
- Defending against full sandbox/host compromise chains.
- Insecure/no-verify transport mode.

## Features

- `setup` wizard to create CA/server/client certs + daemon config
- `emit-client` to mint additional client certs
- command registry + policy engine (`allow`/`deny`/`ask`/`audit`)
- advanced rules (`args_exact` / `args_prefix` / `args_glob` / `args_regex`)
- precedence: `exact > prefix > glob > regex` (with fail-closed tied-conflict rejection)
- bidirectional streaming execution RPC
- argv0 shim mode + shim installer
- `policy lint`, `policy test`, `policy explain`

## Quickstart

### 1) Build

```bash
cargo build
```

### 2) Initial setup

```bash
cargo run -- setup \
  --out-dir ./warden-state \
  --listen 127.0.0.1:50051 \
  --server-domain localhost \
  --client-name default-client
```

Optional SANs can be added with repeated `--san` flags.

`setup` writes daemon config and PKI material under `./warden-state`, and prints a client
bootstrap snippet (for `~/.config/cli-warden/client.toml`).

### 3) Configure command registry and policy

Edit `./warden-state/config/daemon.toml`. Minimal example:

```toml
[commands]
gog = "/opt/tools/gogcli"

[policy]
default = "deny"
ask_requires_intent = true
allow_hook_timeout_secs = 1800
allow_hook = "/usr/local/bin/warden-allow-hook"
allow = ["gog calendar list"]
deny = ["gog contacts delete"]
ask = ["gog calendar add"]
```

### 4) Run daemon

```bash
cargo run -- daemon --config ./warden-state/config/daemon.toml
```

### 5) Client operations

List registered commands:

```bash
cargo run -- client list-commands --config ~/.config/cli-warden/client.toml
```

Execute command:

```bash
cargo run -- client exec \
  --config ~/.config/cli-warden/client.toml \
  --cmd gog \
  --intent "sync calendar" \
  -- calendar list
```

Execute command with inline stdin payload:

```bash
cargo run -- client exec \
  --config ~/.config/cli-warden/client.toml \
  --cmd gog \
  --stdin '{"hello":"world"}' \
  -- import
```

### 6) Optional shim mode

Install symlink shims for all registered commands:

```bash
cargo run -- client install-shims \
  --config ~/.config/cli-warden/client.toml \
  --dir ./shims \
  --force
```

Invoke through argv0:

```bash
CLI_WARDEN_CLIENT_CONFIG=~/.config/cli-warden/client.toml ./shims/gog calendar list
```

Optional intent:

```bash
CLI_WARDEN_CLIENT_CONFIG=~/.config/cli-warden/client.toml \
CLI_WARDEN_INTENT="sync calendar" \
./shims/gog calendar list
```

## Additional Client Provisioning

Generate another client cert/key:

```bash
cargo run -- emit-client --config ./warden-state/config/daemon.toml --name laptop
```

This writes cert/key under `pki/clients/` and prints a bootstrap snippet for client config.

## Policy Reference

Shorthand lists:

- `policy.allow = ["cmd ..."]`
- `policy.deny = ["cmd ..."]`
- `policy.ask = ["cmd ..."]`

Advanced rules:

```toml
[[rules]]
effect = "allow"
cmd = "gog"
args_prefix = ["calendar", "list"]

[[rules]]
effect = "ask"
cmd = "gog"
args_prefix = ["calendar", "add"]
intent_required = true
```

Matching behavior:

- Most specific match wins.
- Specificity order: `exact > prefix > glob > regex`.
- Same-specificity same-fingerprint conflicts with different effects are rejected at config load.
- No match falls back to `policy.default`.

## Allow Hook Contract

For `ask` decisions, daemon executes `policy.allow_hook` directly (no shell).

stdin JSON:

```json
{"cmd":"gog","argv":["calendar","add"],"intent":"add reminder"}
```

stdout JSON response:

```json
{"decision":"yes"}
```

Supported `decision` values:

- `yes`
- `no`
- `cancel`
- `user-reply` (must include `reply`)

Fail-closed behavior:

- invalid JSON
- non-zero exit
- timeout (`policy.allow_hook_timeout_secs`, default `1800`)
- non-UTF-8 output

All are treated as `cancel`.

## Streaming and Flow Control

- Data is packetized in fixed-size chunks (`8 KiB`) per read/send step.
- Queue capacity is bounded (`128` packets).
- In-flight byte budget is bounded (`128 KiB`) in both directions.
- stdout and stderr are streamed independently and preserved separately.

## Secret Redaction

- Configure secrets file via `[secrets].file`.
- Each non-empty line is treated as a literal secret value.
- Matching output substrings are replaced with `<redacted>`.
- Non-UTF-8 command output is rejected (fail closed).

## Policy Tooling

Lint config:

```bash
cargo run -- policy lint --config ./warden-state/config/daemon.toml
```

Test decision:

```bash
cargo run -- policy test \
  --config ./warden-state/config/daemon.toml \
  --cmd gog \
  --intent "sync" \
  -- calendar list
```

Explain match details:

```bash
cargo run -- policy explain \
  --config ./warden-state/config/daemon.toml \
  --cmd gog \
  --intent "sync" \
  -- calendar list
```

## Development

```bash
cargo fmt
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```
