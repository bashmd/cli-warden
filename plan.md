cli-warden

An AI agent sandbox boundary, written in Rust. It allows a sandboxed agent (for example
inside a VM or container) to access a curated set of CLI capabilities through a daemon
that holds sensitive credentials on the daemon side.

Goal

Enable practical prevention as far as feasible while still allowing sensitive workloads.
Not a 100% security guarantee. Out-of-scope attacks include full sandbox escape chains
and host takeover via unrelated lower-level vulnerabilities.

Threat model and scope

- The agent can be untrusted and may try to exfiltrate secrets.
- The daemon host is trusted to enforce policy.
- Supported tools are assumed non-RCE under normal use.
- Security depends heavily on capability design (what commands are allowed at all).

Transport and authentication

- Primary use is remote transport.
- Optional deployment over Unix domain sockets is supported (for example container -> host).
- mTLS is mandatory for RPC authentication and transport security.
- Daemon and clients authenticate each other with certificates signed by a cli-warden CA.
- No token/HMAC authentication path.
- No insecure/no-verify mode in MVP.

PKI setup flow

- `cli-warden setup` provides a small interactive wizard.
- Wizard creates a local CA, a daemon certificate/key, and an initial client certificate/key.
- Wizard writes daemon config and prints a client bootstrap shell snippet to produce client config.
- Additional clients can be provisioned later via `cli-warden emit-client --name <client>`.
- SANs for daemon certificates must be explicitly configured (host/IP clients will connect to).

Execution protocol

- No shell semantics are supported over the network.
- The client sends structured command requests (entrypoint id + argv vector + stdin stream).
- The daemon executes directly (no remote shell invocation).
- Policy evaluation happens on structured argv tokens, not raw shell command strings.
- The daemon returns stdout, stderr, and exit code.

Command registry and policy

- Whitelist-only model: supported binaries must be explicitly registered in daemon config.
- No automatic command discovery for execution.
- 1:1 mapping between exposed command id and concrete binary path.
- Daemon can expose the list of registered command entrypoints to clients.
- Policy decisions can be allow, deny, ask, and audit.
- Rules apply to command + subcommand argv structure (for example prefix/glob/regex on tokens).
  - allow camoufox-cli *
  - deny gogcli contacts delete
  - ask gogcli calendar add

Secret handling

- Daemon loads known secrets from a configured secrets file.
- Outbound streams are scanned and exact known secret values are replaced (for example `<redacted>`).
- This is best-effort literal redaction, not full exfiltration prevention.
- Transformed or indirect leakage (for example base64 encoding, JS/browser abuse, image rendering)
  is out of scope unless capabilities are constrained to prevent those paths.
- Non-UTF-8 stream data is currently unsupported; daemon fails closed instead of attempting partial/binary redaction.

Operational guidance

- Restrict command capabilities aggressively for high-assurance workloads.
- For browser flows, use narrow-scope helper tools (for example field-specific credential injectors)
  instead of broad automation powers when possible.

Policy configuration ergonomics

- If the policy is simple, config should stay simple.
- Keep two layers:
  - command registry (explicit whitelist of exposed binaries)
  - policy rules (allow/deny/ask decisions)
- Provide shorthand for common cases and structured rule blocks for advanced cases.
- Rule ids are not required in config; daemon can reference rules by file position for logs/explain output.

Example (simple)

```toml
[commands]
camoufox = "/opt/tools/camoufox-cli"
gog = "/opt/tools/gogcli"

[policy]
default = "deny"
ask_requires_intent = true
allow = ["camoufox *"]
deny = ["gog contacts delete"]
ask = ["gog calendar add"]
allow_hook = "/usr/local/bin/warden-allow-hook"
```

Example (advanced, no rule ids)

```toml
[commands]
camoufox = "/opt/tools/camoufox-cli"
gog = "/opt/tools/gogcli"

[policy]
default = "deny"
ask_requires_intent = true
allow_hook = "/usr/local/bin/warden-allow-hook"

[[rules]]
effect = "allow"
cmd = "camoufox"
args_glob = ["*"]

[[rules]]
effect = "deny"
cmd = "gog"
args_prefix = ["contacts", "delete"]

[[rules]]
effect = "ask"
cmd = "gog"
args_prefix = ["calendar", "add"]
# optional override; if omitted, global ask_requires_intent applies
intent_required = true
```

Matching and precedence

- Match on structured argv tokens only (no shell string parsing).
- Most-specific rule wins.
- Specificity order is: exact > prefix > glob > regex.
- Within the same match type, the rule matching the longest arg sequence is more specific.
- If multiple rules are still tied and effects differ, treat config as invalid (fail closed) and reject load/start.
- If no rule matches, use `policy.default`.

Intent handling

- Intent is a first-class request field processed by the daemon, not shell-expanded.
- Intent requirements for ask decisions are controlled by:
  - global: `policy.ask_requires_intent`
  - optional per-rule override: `intent_required`
- If intent is required and missing, daemon denies with a machine-readable error and rerun hint.

Allow hook

- `policy.allow_hook` is an executable path for external approval routing.
- Daemon executes the hook directly (no shell).
- Daemon writes exactly this JSON shape to hook stdin:
  - `{"cmd":"<entrypoint>","argv":["..."],"intent":"..."}`
- Hook must write exactly one JSON object to stdout with:
  - `decision`: one of `yes`, `no`, `cancel`, `user-reply`
  - `reply`: required only when `decision` is `user-reply`
- Decision handling:
  - `yes`: allow execution
  - `no`: deny execution
  - `cancel`: stop request as cancelled
  - `user-reply`: do not execute; return `reply` to caller/agent
- Hook may run for a long time (asynchronous human approval flows are expected).
- Any invalid output, non-zero hook exit, or timeout is treated as `cancel` (fail closed).
