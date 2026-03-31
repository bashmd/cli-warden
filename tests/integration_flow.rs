use std::{
    fs,
    io::Write,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

mod pb {
    tonic::include_proto!("warden");
}

struct DaemonGuard {
    child: Option<Child>,
}

impl DaemonGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("daemon child present")
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn e2e_daemon_client_policy_flow() {
    let bin = cargo_bin_path();

    let temp = TempDir::new().expect("create temp dir");
    let state_dir = temp.path().join("state");

    let listen_port = reserve_ephemeral_port();
    let listen = format!("127.0.0.1:{listen_port}");

    let setup_output = Command::new(&bin)
        .args([
            "setup",
            "--out-dir",
            state_dir.to_str().expect("utf8 path"),
            "--listen",
            &listen,
            "--server-domain",
            "localhost",
            "--client-name",
            "itest-client",
        ])
        .output()
        .expect("run setup");
    assert_success(&setup_output, "setup");

    let daemon_cfg_path = state_dir.join("config/daemon.toml");
    let client_cfg_path = state_dir.join("client.toml");
    let hook_path = state_dir.join("allow-hook.sh");

    write_hook(&hook_path);
    write_client_config(&client_cfg_path, &state_dir, listen_port);
    patch_daemon_config(&daemon_cfg_path, &hook_path);

    let daemon = Command::new(&bin)
        .args([
            "daemon",
            "--config",
            daemon_cfg_path.to_str().expect("utf8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let mut daemon = DaemonGuard::new(daemon);

    wait_for_daemon(&bin, &client_cfg_path, daemon.child_mut());

    let shims_dir = state_dir.join("shims");
    let install_shims = Command::new(&bin)
        .args([
            "client",
            "install-shims",
            "--config",
            client_cfg_path.to_str().expect("utf8 path"),
            "--dir",
            shims_dir.to_str().expect("utf8 path"),
            "--force",
        ])
        .output()
        .expect("run install-shims");
    assert_success(&install_shims, "install-shims");

    let shim_demo = shims_dir.join("demo");
    let shim_out = Command::new(&shim_demo)
        .env("CLI_WARDEN_CLIENT_CONFIG", &client_cfg_path)
        .args(["ok", "from-shim"])
        .output()
        .expect("run shim command");
    assert_success(&shim_out, "shim exec");
    let shim_text = output_text(&shim_out);
    assert_contains(&shim_text, "ok from-shim");

    let allow_out = run_client_exec(&bin, &client_cfg_path, "demo", &["ok", "hello"], None);
    assert_contains(&allow_out, "outcome: Executed");

    let deny_out = run_client_exec(
        &bin,
        &client_cfg_path,
        "demo",
        &["blocked", "whatever"],
        None,
    );
    assert_contains(&deny_out, "outcome: Denied");
    assert_contains(&deny_out, "denied by policy");

    let ask_missing_intent = run_client_exec(&bin, &client_cfg_path, "demo", &["ask", "job"], None);
    assert_contains(&ask_missing_intent, "outcome: Denied");
    assert_contains(&ask_missing_intent, "intent_required");

    let ask_approved = run_client_exec(
        &bin,
        &client_cfg_path,
        "demo",
        &["ask", "job"],
        Some("approve"),
    );
    assert_contains(&ask_approved, "outcome: Executed");

    let ask_denied = run_client_exec(
        &bin,
        &client_cfg_path,
        "demo",
        &["ask", "job"],
        Some("deny"),
    );
    assert_contains(&ask_denied, "outcome: Denied");
    assert_contains(&ask_denied, "denied by allow_hook");

    let ask_user_reply = run_client_exec(
        &bin,
        &client_cfg_path,
        "demo",
        &["ask", "job"],
        Some("reply"),
    );
    assert_contains(&ask_user_reply, "outcome: UserReply");
    assert_contains(&ask_user_reply, "Need human approval");

    let redaction_out = run_client_exec(
        &bin,
        &client_cfg_path,
        "demo",
        &["secret", "TOPSECRET"],
        None,
    );
    assert_contains(&redaction_out, "outcome: Executed");
    assert_contains(&redaction_out, "<redacted>");
    assert_not_contains(&redaction_out, "TOPSECRET");
}

#[test]
fn shim_exits_even_when_stdin_is_open() {
    let bin = cargo_bin_path();

    let temp = TempDir::new().expect("create temp dir");
    let state_dir = temp.path().join("state");

    let listen_port = reserve_ephemeral_port();
    let listen = format!("127.0.0.1:{listen_port}");

    let setup_output = Command::new(&bin)
        .args([
            "setup",
            "--out-dir",
            state_dir.to_str().expect("utf8 path"),
            "--listen",
            &listen,
            "--server-domain",
            "localhost",
            "--client-name",
            "itest-client",
        ])
        .output()
        .expect("run setup");
    assert_success(&setup_output, "setup");

    let daemon_cfg_path = state_dir.join("config/daemon.toml");
    let client_cfg_path = state_dir.join("client.toml");

    write_client_config(&client_cfg_path, &state_dir, listen_port);
    patch_daemon_config_fast(&daemon_cfg_path);

    let daemon = Command::new(&bin)
        .args([
            "daemon",
            "--config",
            daemon_cfg_path.to_str().expect("utf8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let mut daemon = DaemonGuard::new(daemon);

    wait_for_daemon(&bin, &client_cfg_path, daemon.child_mut());

    let shims_dir = state_dir.join("shims");
    let install_shims = Command::new(&bin)
        .args([
            "client",
            "install-shims",
            "--config",
            client_cfg_path.to_str().expect("utf8 path"),
            "--dir",
            shims_dir.to_str().expect("utf8 path"),
            "--force",
        ])
        .output()
        .expect("run install-shims");
    assert_success(&install_shims, "install-shims");

    let shim_fast = shims_dir.join("fast");
    let mut child = Command::new(&shim_fast)
        .env("CLI_WARDEN_CLIENT_CONFIG", &client_cfg_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shim command");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("poll shim child") {
            assert!(status.success(), "shim exited non-successfully: {status}");
            break;
        }

        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("shim did not exit while stdin remained open");
        }

        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn fast_exit_command_handles_large_streamed_stdin() {
    let bin = cargo_bin_path();

    let temp = TempDir::new().expect("create temp dir");
    let state_dir = temp.path().join("state");

    let listen_port = reserve_ephemeral_port();
    let listen = format!("127.0.0.1:{listen_port}");

    let setup_output = Command::new(&bin)
        .args([
            "setup",
            "--out-dir",
            state_dir.to_str().expect("utf8 path"),
            "--listen",
            &listen,
            "--server-domain",
            "localhost",
            "--client-name",
            "itest-client",
        ])
        .output()
        .expect("run setup");
    assert_success(&setup_output, "setup");

    let daemon_cfg_path = state_dir.join("config/daemon.toml");
    let client_cfg_path = state_dir.join("client.toml");

    write_client_config(&client_cfg_path, &state_dir, listen_port);
    patch_daemon_config_fast(&daemon_cfg_path);

    let daemon = Command::new(&bin)
        .args([
            "daemon",
            "--config",
            daemon_cfg_path.to_str().expect("utf8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let mut daemon = DaemonGuard::new(daemon);

    wait_for_daemon(&bin, &client_cfg_path, daemon.child_mut());

    let stdin_payload = "X".repeat(32 * 1024);
    let out = run_client_exec_with_stdin(
        &bin,
        &client_cfg_path,
        "fast",
        &[],
        None,
        Some(&stdin_payload),
    );
    assert_contains(&out, "outcome: Executed");
}

#[test]
fn streaming_preserves_output_without_newline() {
    let bin = cargo_bin_path();

    let temp = TempDir::new().expect("create temp dir");
    let state_dir = temp.path().join("state");

    let listen_port = reserve_ephemeral_port();
    let listen = format!("127.0.0.1:{listen_port}");

    let setup_output = Command::new(&bin)
        .args([
            "setup",
            "--out-dir",
            state_dir.to_str().expect("utf8 path"),
            "--listen",
            &listen,
            "--server-domain",
            "localhost",
            "--client-name",
            "itest-client",
        ])
        .output()
        .expect("run setup");
    assert_success(&setup_output, "setup");

    let daemon_cfg_path = state_dir.join("config/daemon.toml");
    let client_cfg_path = state_dir.join("client.toml");

    write_client_config(&client_cfg_path, &state_dir, listen_port);
    patch_daemon_config_streaming(&daemon_cfg_path);

    let daemon = Command::new(&bin)
        .args([
            "daemon",
            "--config",
            daemon_cfg_path.to_str().expect("utf8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let mut daemon = DaemonGuard::new(daemon);

    wait_for_daemon(&bin, &client_cfg_path, daemon.child_mut());

    let shims_dir = state_dir.join("shims");
    let install_shims = Command::new(&bin)
        .args([
            "client",
            "install-shims",
            "--config",
            client_cfg_path.to_str().expect("utf8 path"),
            "--dir",
            shims_dir.to_str().expect("utf8 path"),
            "--force",
        ])
        .output()
        .expect("run install-shims");
    assert_success(&install_shims, "install-shims");

    let out = Command::new(shims_dir.join("fmt"))
        .env("CLI_WARDEN_CLIENT_CONFIG", &client_cfg_path)
        .arg("abc")
        .output()
        .expect("run fmt shim");
    assert_success(&out, "shim fmt");
    assert_eq!(out.stdout, b"abc");
    assert!(
        out.stderr.is_empty(),
        "unexpected stderr: {}",
        output_text(&out)
    );
}

#[test]
fn shim_live_stdin_roundtrip() {
    let bin = cargo_bin_path();

    let temp = TempDir::new().expect("create temp dir");
    let state_dir = temp.path().join("state");

    let listen_port = reserve_ephemeral_port();
    let listen = format!("127.0.0.1:{listen_port}");

    let setup_output = Command::new(&bin)
        .args([
            "setup",
            "--out-dir",
            state_dir.to_str().expect("utf8 path"),
            "--listen",
            &listen,
            "--server-domain",
            "localhost",
            "--client-name",
            "itest-client",
        ])
        .output()
        .expect("run setup");
    assert_success(&setup_output, "setup");

    let daemon_cfg_path = state_dir.join("config/daemon.toml");
    let client_cfg_path = state_dir.join("client.toml");

    write_client_config(&client_cfg_path, &state_dir, listen_port);
    patch_daemon_config_streaming(&daemon_cfg_path);

    let daemon = Command::new(&bin)
        .args([
            "daemon",
            "--config",
            daemon_cfg_path.to_str().expect("utf8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let mut daemon = DaemonGuard::new(daemon);

    wait_for_daemon(&bin, &client_cfg_path, daemon.child_mut());

    let shims_dir = state_dir.join("shims");
    let install_shims = Command::new(&bin)
        .args([
            "client",
            "install-shims",
            "--config",
            client_cfg_path.to_str().expect("utf8 path"),
            "--dir",
            shims_dir.to_str().expect("utf8 path"),
            "--force",
        ])
        .output()
        .expect("run install-shims");
    assert_success(&install_shims, "install-shims");

    let mut child = Command::new(shims_dir.join("catcmd"))
        .env("CLI_WARDEN_CLIENT_CONFIG", &client_cfg_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn catcmd shim");

    let mut stdin = child.stdin.take().expect("child stdin");
    stdin.write_all(b"hello ").expect("write chunk 1");
    thread::sleep(Duration::from_millis(50));
    stdin.write_all(b"world").expect("write chunk 2");
    drop(stdin);

    let out = child.wait_with_output().expect("wait for catcmd");
    assert_success(&out, "shim catcmd");
    assert_eq!(out.stdout, b"hello world");
}

#[test]
fn protocol_missing_start_returns_error_done_event() {
    let bin = cargo_bin_path();

    let temp = TempDir::new().expect("create temp dir");
    let state_dir = temp.path().join("state");

    let listen_port = reserve_ephemeral_port();
    let listen = format!("127.0.0.1:{listen_port}");

    let setup_output = Command::new(&bin)
        .args([
            "setup",
            "--out-dir",
            state_dir.to_str().expect("utf8 path"),
            "--listen",
            &listen,
            "--server-domain",
            "localhost",
            "--client-name",
            "itest-client",
        ])
        .output()
        .expect("run setup");
    assert_success(&setup_output, "setup");

    let daemon_cfg_path = state_dir.join("config/daemon.toml");
    let client_cfg_path = state_dir.join("client.toml");

    write_client_config(&client_cfg_path, &state_dir, listen_port);
    patch_daemon_config_fast(&daemon_cfg_path);

    let daemon = Command::new(&bin)
        .args([
            "daemon",
            "--config",
            daemon_cfg_path.to_str().expect("utf8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let mut daemon = DaemonGuard::new(daemon);

    wait_for_daemon(&bin, &client_cfg_path, daemon.child_mut());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    let done = rt.block_on(async {
        let mut client = connect_raw_warden_client(&client_cfg_path)
            .await
            .expect("connect raw warden client");

        let (tx, rx) = mpsc::channel(4);
        let mut stream = client
            .execute_stream(ReceiverStream::new(rx))
            .await
            .expect("execute_stream call")
            .into_inner();

        tx.send(pb::ExecuteStreamRequest {
            payload: Some(pb::execute_stream_request::Payload::StdinEof(true)),
        })
        .await
        .expect("send malformed first message");
        drop(tx);

        let event = stream
            .message()
            .await
            .expect("read stream message")
            .expect("done event");

        match event.payload {
            Some(pb::execute_stream_event::Payload::Done(done)) => done,
            other => panic!("expected done event, got {:?}", other),
        }
    });

    let outcome = pb::Outcome::try_from(done.outcome).unwrap_or(pb::Outcome::Unspecified);
    assert_eq!(outcome, pb::Outcome::Error);
    assert!(done.message.contains("first stream message must be start"));
}

#[test]
fn non_utf8_output_fails_fast_instead_of_hanging() {
    let bin = cargo_bin_path();

    let temp = TempDir::new().expect("create temp dir");
    let state_dir = temp.path().join("state");

    let listen_port = reserve_ephemeral_port();
    let listen = format!("127.0.0.1:{listen_port}");

    let setup_output = Command::new(&bin)
        .args([
            "setup",
            "--out-dir",
            state_dir.to_str().expect("utf8 path"),
            "--listen",
            &listen,
            "--server-domain",
            "localhost",
            "--client-name",
            "itest-client",
        ])
        .output()
        .expect("run setup");
    assert_success(&setup_output, "setup");

    let daemon_cfg_path = state_dir.join("config/daemon.toml");
    let client_cfg_path = state_dir.join("client.toml");

    write_client_config(&client_cfg_path, &state_dir, listen_port);
    patch_daemon_config_non_utf8(&daemon_cfg_path);

    let daemon = Command::new(&bin)
        .args([
            "daemon",
            "--config",
            daemon_cfg_path.to_str().expect("utf8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let mut daemon = DaemonGuard::new(daemon);

    wait_for_daemon(&bin, &client_cfg_path, daemon.child_mut());

    let started = Instant::now();
    let out = Command::new(&bin)
        .args([
            "client",
            "exec",
            "--config",
            client_cfg_path.to_str().expect("utf8 path"),
            "--cmd",
            "badutf8",
            "--",
            "-c",
            "1000000",
            "/dev/urandom",
        ])
        .output()
        .expect("run badutf8 command");
    assert_success(&out, "client exec badutf8");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "non-UTF8 path should fail fast, got {:?}",
        started.elapsed()
    );
    let text = output_text(&out);
    assert_contains(&text, "outcome: Error");
    assert_contains(&text, "non-UTF-8");
}

fn cargo_bin_path() -> PathBuf {
    std::env::var("CARGO_BIN_EXE_cli_warden")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("CARGO_BIN_EXE_cli-warden").map(PathBuf::from))
        .unwrap_or_else(|_| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let target_dir = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| manifest_dir.join("target"));
            let bin = target_dir
                .join("debug")
                .join(format!("cli-warden{}", std::env::consts::EXE_SUFFIX));

            if !bin.exists() {
                let status = Command::new("cargo")
                    .args(["build", "--bin", "cli-warden"])
                    .current_dir(&manifest_dir)
                    .status()
                    .expect("failed to build cli-warden binary for integration test");
                assert!(status.success(), "cargo build --bin cli-warden failed");
            }

            assert!(
                bin.exists(),
                "cli-warden binary not found at {}",
                bin.display()
            );
            bin
        })
}

fn reserve_ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("listener local addr").port();
    drop(listener);
    port
}

fn write_hook(path: &Path) {
    let script = r#"#!/usr/bin/env bash
set -euo pipefail
payload="$(cat)"
if [[ "$payload" == *'"intent":"approve"'* ]]; then
  echo '{"decision":"yes"}'
elif [[ "$payload" == *'"intent":"deny"'* ]]; then
  echo '{"decision":"no"}'
elif [[ "$payload" == *'"intent":"reply"'* ]]; then
  echo '{"decision":"user-reply","reply":"Need human approval"}'
else
  echo '{"decision":"cancel"}'
fi
"#;

    fs::write(path, script).expect("write hook script");
    let mut perms = fs::metadata(path).expect("hook metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set hook permissions");
}

fn write_client_config(path: &Path, state_dir: &Path, port: u16) {
    let content = format!(
        "server_uri = \"https://localhost:{port}\"\nserver_domain = \"localhost\"\nca_cert_path = \"{}\"\nclient_cert_path = \"{}\"\nclient_key_path = \"{}\"\n",
        state_dir.join("pki/ca-cert.pem").display(),
        state_dir.join("pki/clients/itest-client-cert.pem").display(),
        state_dir.join("pki/clients/itest-client-key.pem").display(),
    );

    fs::write(path, content).expect("write client config");
}

fn patch_daemon_config(daemon_cfg_path: &Path, hook_path: &Path) {
    let raw = fs::read_to_string(daemon_cfg_path).expect("read daemon config");
    let mut cfg: toml::Value = toml::from_str(&raw).expect("parse daemon config toml");

    let root = cfg
        .as_table_mut()
        .expect("daemon config root should be a table");

    let commands = root
        .entry("commands")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .expect("commands should be a table");
    commands.insert(
        "demo".to_string(),
        toml::Value::String(find_existing_binary(&["/bin/echo", "/usr/bin/echo"])),
    );

    let policy = root
        .entry("policy")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .expect("policy should be a table");
    policy.insert(
        "default".to_string(),
        toml::Value::String("deny".to_string()),
    );
    policy.insert(
        "ask_requires_intent".to_string(),
        toml::Value::Boolean(true),
    );
    policy.insert(
        "allow_hook".to_string(),
        toml::Value::String(hook_path.display().to_string()),
    );
    policy.insert(
        "allow".to_string(),
        toml::Value::Array(vec![
            toml::Value::String("demo ok *".to_string()),
            toml::Value::String("demo secret *".to_string()),
        ]),
    );
    policy.insert(
        "deny".to_string(),
        toml::Value::Array(vec![toml::Value::String("demo blocked *".to_string())]),
    );
    policy.insert(
        "ask".to_string(),
        toml::Value::Array(vec![toml::Value::String("demo ask *".to_string())]),
    );

    let secrets_file = root
        .get("secrets")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("file"))
        .and_then(|v| v.as_str())
        .expect("secrets.file path")
        .to_string();
    fs::write(&secrets_file, "TOPSECRET\n").expect("write secrets file");

    let updated = toml::to_string_pretty(&cfg).expect("serialize daemon config");
    fs::write(daemon_cfg_path, updated).expect("write updated daemon config");
}

fn patch_daemon_config_fast(daemon_cfg_path: &Path) {
    let raw = fs::read_to_string(daemon_cfg_path).expect("read daemon config");
    let mut cfg: toml::Value = toml::from_str(&raw).expect("parse daemon config toml");

    let root = cfg
        .as_table_mut()
        .expect("daemon config root should be a table");

    let commands = root
        .entry("commands")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .expect("commands should be a table");
    commands.insert(
        "fast".to_string(),
        toml::Value::String(find_existing_binary(&["/bin/true", "/usr/bin/true"])),
    );

    let policy = root
        .entry("policy")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .expect("policy should be a table");
    policy.insert(
        "default".to_string(),
        toml::Value::String("deny".to_string()),
    );
    policy.insert(
        "allow".to_string(),
        toml::Value::Array(vec![toml::Value::String("fast".to_string())]),
    );
    policy.insert("deny".to_string(), toml::Value::Array(vec![]));
    policy.insert("ask".to_string(), toml::Value::Array(vec![]));
    policy.remove("allow_hook");

    let updated = toml::to_string_pretty(&cfg).expect("serialize daemon config");
    fs::write(daemon_cfg_path, updated).expect("write updated daemon config");
}

fn patch_daemon_config_streaming(daemon_cfg_path: &Path) {
    let raw = fs::read_to_string(daemon_cfg_path).expect("read daemon config");
    let mut cfg: toml::Value = toml::from_str(&raw).expect("parse daemon config toml");

    let root = cfg
        .as_table_mut()
        .expect("daemon config root should be a table");

    let commands = root
        .entry("commands")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .expect("commands should be a table");
    commands.insert(
        "fmt".to_string(),
        toml::Value::String(find_existing_binary(&["/usr/bin/printf", "/bin/printf"])),
    );
    commands.insert(
        "catcmd".to_string(),
        toml::Value::String(find_existing_binary(&["/bin/cat", "/usr/bin/cat"])),
    );

    let policy = root
        .entry("policy")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .expect("policy should be a table");
    policy.insert(
        "default".to_string(),
        toml::Value::String("deny".to_string()),
    );
    policy.insert(
        "allow".to_string(),
        toml::Value::Array(vec![
            toml::Value::String("fmt *".to_string()),
            toml::Value::String("catcmd *".to_string()),
        ]),
    );
    policy.insert("deny".to_string(), toml::Value::Array(vec![]));
    policy.insert("ask".to_string(), toml::Value::Array(vec![]));
    policy.remove("allow_hook");

    let updated = toml::to_string_pretty(&cfg).expect("serialize daemon config");
    fs::write(daemon_cfg_path, updated).expect("write updated daemon config");
}

fn patch_daemon_config_non_utf8(daemon_cfg_path: &Path) {
    let raw = fs::read_to_string(daemon_cfg_path).expect("read daemon config");
    let mut cfg: toml::Value = toml::from_str(&raw).expect("parse daemon config toml");

    let root = cfg
        .as_table_mut()
        .expect("daemon config root should be a table");

    let commands = root
        .entry("commands")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .expect("commands should be a table");
    commands.insert(
        "badutf8".to_string(),
        toml::Value::String(find_existing_binary(&["/usr/bin/head", "/bin/head"])),
    );

    let policy = root
        .entry("policy")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .expect("policy should be a table");
    policy.insert(
        "default".to_string(),
        toml::Value::String("deny".to_string()),
    );
    policy.insert(
        "allow".to_string(),
        toml::Value::Array(vec![toml::Value::String("badutf8 *".to_string())]),
    );
    policy.insert("deny".to_string(), toml::Value::Array(vec![]));
    policy.insert("ask".to_string(), toml::Value::Array(vec![]));
    policy.remove("allow_hook");

    let updated = toml::to_string_pretty(&cfg).expect("serialize daemon config");
    fs::write(daemon_cfg_path, updated).expect("write updated daemon config");
}

fn find_existing_binary(candidates: &[&str]) -> String {
    for path in candidates {
        if Path::new(path).exists() {
            return (*path).to_string();
        }
    }
    panic!("no binary found from candidates: {:?}", candidates);
}

fn wait_for_daemon(bin: &Path, client_cfg: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("check daemon child") {
            panic!("daemon exited early with status {status}");
        }

        let out = Command::new(bin)
            .args([
                "client",
                "list-commands",
                "--config",
                client_cfg.to_str().expect("utf8 path"),
            ])
            .output()
            .expect("run list-commands probe");

        if out.status.success() {
            return;
        }

        if Instant::now() > deadline {
            let text = output_text(&out);
            panic!("daemon did not become ready in time; probe output:\n{text}");
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn run_client_exec(
    bin: &Path,
    client_cfg: &Path,
    cmd: &str,
    args: &[&str],
    intent: Option<&str>,
) -> String {
    let mut command = Command::new(bin);
    command.args([
        "client",
        "exec",
        "--config",
        client_cfg.to_str().expect("utf8 path"),
        "--cmd",
        cmd,
    ]);

    if let Some(intent) = intent {
        command.args(["--intent", intent]);
    }

    command.arg("--");
    command.args(args);

    let out = command.output().expect("run client exec");
    assert_success(&out, "client exec");
    output_text(&out)
}

fn run_client_exec_with_stdin(
    bin: &Path,
    client_cfg: &Path,
    cmd: &str,
    args: &[&str],
    intent: Option<&str>,
    stdin: Option<&str>,
) -> String {
    let mut command = Command::new(bin);
    command.args([
        "client",
        "exec",
        "--config",
        client_cfg.to_str().expect("utf8 path"),
        "--cmd",
        cmd,
    ]);

    if let Some(intent) = intent {
        command.args(["--intent", intent]);
    }
    if let Some(stdin) = stdin {
        command.args(["--stdin", stdin]);
    }

    command.arg("--");
    command.args(args);

    let out = command.output().expect("run client exec");
    assert_success(&out, "client exec");
    output_text(&out)
}

async fn connect_raw_warden_client(
    client_cfg_path: &Path,
) -> anyhow::Result<pb::warden_client::WardenClient<tonic::transport::Channel>> {
    let raw = fs::read_to_string(client_cfg_path)?;
    let cfg: toml::Value = toml::from_str(&raw)?;
    let table = cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("client config root must be a table"))?;

    let server_uri = table
        .get("server_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing server_uri"))?;
    let server_domain = table
        .get("server_domain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing server_domain"))?;
    let ca_cert_path = table
        .get("ca_cert_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing ca_cert_path"))?;
    let client_cert_path = table
        .get("client_cert_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing client_cert_path"))?;
    let client_key_path = table
        .get("client_key_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing client_key_path"))?;

    let ca = fs::read(ca_cert_path)?;
    let cert = fs::read(client_cert_path)?;
    let key = fs::read(client_key_path)?;

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key))
        .domain_name(server_domain.to_string());

    let endpoint = Endpoint::from_shared(server_uri.to_string())?;
    let channel = endpoint.tls_config(tls)?.connect().await?;
    Ok(pb::warden_client::WardenClient::new(channel))
}

fn assert_success(output: &Output, context: &str) {
    if !output.status.success() {
        panic!(
            "{context} failed with status {}\n{}",
            output.status,
            output_text(output)
        );
    }
}

fn output_text(output: &Output) -> String {
    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&output.stdout));
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected output to contain '{needle}', got:\n{haystack}"
    );
}

fn assert_not_contains(haystack: &str, needle: &str) {
    assert!(
        !haystack.contains(needle),
        "expected output to not contain '{needle}', got:\n{haystack}"
    );
}
