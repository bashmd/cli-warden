use crate::{
    config::{DaemonConfig, Effect},
    hook::{run_allow_hook, HookDecision},
    policy::{Decision, PolicyEngine},
    proto::pb,
    redaction::{load_secrets, Redactor},
    stream_queue::{
        self, send_metered as queue_send_metered, send_unbounded as queue_send_unbounded,
        QueuedItem, DEFAULT_CHUNK_BYTES, DEFAULT_MAX_UNCONFIRMED_BYTES,
        DEFAULT_PACKET_QUEUE_CAPACITY,
    },
};
use anyhow::Context;
use std::{
    collections::BTreeMap, fs, io::ErrorKind, path::PathBuf, pin::Pin, sync::Arc, time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::{mpsc, Semaphore},
};
use tokio_stream::Stream;
use tonic::{
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Response, Status, Streaming,
};
use tracing::{error, info};

use pb::{
    execute_stream_event, execute_stream_request,
    warden_server::{Warden, WardenServer},
    ExecuteDone, ExecuteRequest, ExecuteResponse, ExecuteStreamEvent, ExecuteStreamRequest,
    ListCommandsRequest, ListCommandsResponse, Outcome,
};

pub async fn run_daemon(config_path: PathBuf) -> anyhow::Result<()> {
    let cfg = DaemonConfig::load(&config_path)
        .with_context(|| format!("failed loading daemon config {}", config_path.display()))?;

    let policy = PolicyEngine::from_config(&cfg.policy, &cfg.rules)?;

    let secrets = match cfg.secrets.as_ref() {
        Some(s) => {
            let path = PathBuf::from(&s.file);
            load_secrets(path.as_path())?
        }
        None => Vec::new(),
    };
    let redactor = Redactor::from_secrets(secrets)?;

    let cert = fs::read(&cfg.server.tls_cert_path)?;
    let key = fs::read(&cfg.server.tls_key_path)?;
    let ca = fs::read(&cfg.server.client_ca_cert_path)?;

    let identity = Identity::from_pem(cert, key);
    let ca = Certificate::from_pem(ca);

    let tls = ServerTlsConfig::new().identity(identity).client_ca_root(ca);

    let addr = cfg.server.listen.parse()?;

    let svc = WardenService {
        commands: cfg.commands,
        policy,
        redactor,
    };

    info!("daemon listening on {}", cfg.server.listen);

    Server::builder()
        .tls_config(tls)?
        .add_service(WardenServer::new(svc))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(sig) => sig,
                Err(e) => {
                    error!("failed to register SIGTERM handler: {e}");
                    let _ = tokio::signal::ctrl_c().await;
                    info!("shutdown signal received");
                    return;
                }
            };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    info!("shutdown signal received");
}

#[derive(Clone)]
struct WardenService {
    commands: BTreeMap<String, String>,
    policy: PolicyEngine,
    redactor: Redactor,
}

type StreamEventItem = Result<ExecuteStreamEvent, Status>;
type StreamEventQueueItem = QueuedItem<StreamEventItem>;

enum GateResult {
    Allow(Decision),
    Return { outcome: Outcome, message: String },
}

#[tonic::async_trait]
impl Warden for WardenService {
    type ExecuteStreamStream =
        Pin<Box<dyn Stream<Item = Result<ExecuteStreamEvent, Status>> + Send>>;

    async fn list_commands(
        &self,
        _request: Request<ListCommandsRequest>,
    ) -> Result<Response<ListCommandsResponse>, Status> {
        let mut command_ids: Vec<String> = self.commands.keys().cloned().collect();
        command_ids.sort();
        Ok(Response::new(ListCommandsResponse { command_ids }))
    }

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        let remote = request
            .remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let started = Instant::now();

        let req = request.into_inner();
        let cmd_id = req.cmd;
        let args = req.args;
        let intent = req.intent;

        let Some(binary_path) = self.commands.get(&cmd_id) else {
            let out = resp(
                Outcome::Denied,
                -1,
                "",
                "",
                format!("command '{}' is not registered", cmd_id),
            );
            audit_log(
                &remote,
                &cmd_id,
                &args,
                None,
                Outcome::Denied,
                -1,
                &out.message,
                started,
            );
            return Ok(Response::new(out));
        };

        let gate = self.apply_gate(&cmd_id, &args, &intent).await;
        let decision = match gate {
            GateResult::Allow(d) => d,
            GateResult::Return { outcome, message } => {
                let out = resp(outcome, -1, "", "", message);
                audit_log(
                    &remote,
                    &cmd_id,
                    &args,
                    None,
                    outcome,
                    -1,
                    &out.message,
                    started,
                );
                return Ok(Response::new(out));
            }
        };

        let mut cmd = Command::new(binary_path);
        cmd.args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let out = resp(
                    Outcome::Error,
                    -1,
                    "",
                    "",
                    format!("failed to start command: {e}"),
                );
                audit_log(
                    &remote,
                    &cmd_id,
                    &args,
                    Some(&decision),
                    Outcome::Error,
                    -1,
                    &out.message,
                    started,
                );
                return Ok(Response::new(out));
            }
        };

        if !req.stdin_utf8.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                if let Err(e) = stdin.write_all(req.stdin_utf8.as_bytes()).await {
                    let out = resp(
                        Outcome::Error,
                        -1,
                        "",
                        "",
                        format!("failed writing stdin: {e}"),
                    );
                    audit_log(
                        &remote,
                        &cmd_id,
                        &args,
                        Some(&decision),
                        Outcome::Error,
                        -1,
                        &out.message,
                        started,
                    );
                    return Ok(Response::new(out));
                }
            }
        }

        let output = match child.wait_with_output().await {
            Ok(o) => o,
            Err(e) => {
                let out = resp(
                    Outcome::Error,
                    -1,
                    "",
                    "",
                    format!("command execution error: {e}"),
                );
                audit_log(
                    &remote,
                    &cmd_id,
                    &args,
                    Some(&decision),
                    Outcome::Error,
                    -1,
                    &out.message,
                    started,
                );
                return Ok(Response::new(out));
            }
        };

        let stdout = match self.redactor.redact_utf8(&output.stdout) {
            Ok(v) => v,
            Err(e) => {
                let out = resp(
                    Outcome::Error,
                    output.status.code().unwrap_or(-1),
                    "",
                    "",
                    format!("output redaction failed: {e}"),
                );
                audit_log(
                    &remote,
                    &cmd_id,
                    &args,
                    Some(&decision),
                    Outcome::Error,
                    out.exit_code,
                    &out.message,
                    started,
                );
                return Ok(Response::new(out));
            }
        };

        let stderr = match self.redactor.redact_utf8(&output.stderr) {
            Ok(v) => v,
            Err(e) => {
                let out = resp(
                    Outcome::Error,
                    output.status.code().unwrap_or(-1),
                    "",
                    "",
                    format!("output redaction failed: {e}"),
                );
                audit_log(
                    &remote,
                    &cmd_id,
                    &args,
                    Some(&decision),
                    Outcome::Error,
                    out.exit_code,
                    &out.message,
                    started,
                );
                return Ok(Response::new(out));
            }
        };

        let out = resp(
            Outcome::Executed,
            output.status.code().unwrap_or(-1),
            stdout,
            stderr,
            "",
        );
        audit_log(
            &remote,
            &cmd_id,
            &args,
            Some(&decision),
            Outcome::Executed,
            out.exit_code,
            &out.message,
            started,
        );
        Ok(Response::new(out))
    }

    async fn execute_stream(
        &self,
        request: Request<Streaming<ExecuteStreamRequest>>,
    ) -> Result<Response<Self::ExecuteStreamStream>, Status> {
        let remote = request
            .remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let inbound = request.into_inner();

        let (tx, rx) = mpsc::channel(DEFAULT_PACKET_QUEUE_CAPACITY);
        let byte_budget = Arc::new(Semaphore::new(DEFAULT_MAX_UNCONFIRMED_BYTES));
        let svc = self.clone();

        tokio::spawn(async move {
            svc.handle_execute_stream(remote, inbound, tx, byte_budget)
                .await;
        });

        let stream = stream_queue::into_stream(rx);
        Ok(Response::new(Box::pin(stream)))
    }
}

impl WardenService {
    async fn handle_execute_stream(
        &self,
        remote: String,
        mut inbound: Streaming<ExecuteStreamRequest>,
        tx: mpsc::Sender<StreamEventQueueItem>,
        byte_budget: Arc<Semaphore>,
    ) {
        let started = Instant::now();
        let first = match inbound.message().await {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                send_done(
                    &tx,
                    Outcome::Error,
                    -1,
                    "missing stream start message".to_string(),
                )
                .await;
                let args: Vec<String> = Vec::new();
                audit_log(
                    &remote,
                    "<missing-start>",
                    &args,
                    None,
                    Outcome::Error,
                    -1,
                    "missing stream start message",
                    started,
                );
                return;
            }
            Err(status) => {
                let message = format!("input stream failed before start: {status}");
                send_done(&tx, Outcome::Error, -1, message.clone()).await;
                let args: Vec<String> = Vec::new();
                audit_log(
                    &remote,
                    "<missing-start>",
                    &args,
                    None,
                    Outcome::Error,
                    -1,
                    &message,
                    started,
                );
                return;
            }
        };
        let start_msg = match first.payload {
            Some(execute_stream_request::Payload::Start(s)) => s,
            _ => {
                send_done(
                    &tx,
                    Outcome::Error,
                    -1,
                    "first stream message must be start".to_string(),
                )
                .await;
                let args: Vec<String> = Vec::new();
                audit_log(
                    &remote,
                    "<missing-start>",
                    &args,
                    None,
                    Outcome::Error,
                    -1,
                    "first stream message must be start",
                    started,
                );
                return;
            }
        };

        let cmd_id = start_msg.cmd;
        let args = start_msg.args;
        let intent = start_msg.intent;

        let Some(binary_path) = self.commands.get(&cmd_id) else {
            let message = format!("command '{}' is not registered", cmd_id);
            send_done(&tx, Outcome::Denied, -1, message.clone()).await;
            audit_log(
                &remote,
                &cmd_id,
                &args,
                None,
                Outcome::Denied,
                -1,
                &message,
                started,
            );
            return;
        };

        let gate = self.apply_gate(&cmd_id, &args, &intent).await;
        let decision = match gate {
            GateResult::Allow(d) => d,
            GateResult::Return { outcome, message } => {
                send_done(&tx, outcome, -1, message.clone()).await;
                audit_log(
                    &remote, &cmd_id, &args, None, outcome, -1, &message, started,
                );
                return;
            }
        };

        let mut cmd = Command::new(binary_path);
        cmd.args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let message = format!("failed to start command: {e}");
                send_done(&tx, Outcome::Error, -1, message.clone()).await;
                audit_log(
                    &remote,
                    &cmd_id,
                    &args,
                    Some(&decision),
                    Outcome::Error,
                    -1,
                    &message,
                    started,
                );
                return;
            }
        };

        let Some(stdout) = child.stdout.take() else {
            send_done(
                &tx,
                Outcome::Error,
                -1,
                "stdout pipe unavailable".to_string(),
            )
            .await;
            return;
        };
        let Some(stderr) = child.stderr.take() else {
            send_done(
                &tx,
                Outcome::Error,
                -1,
                "stderr pipe unavailable".to_string(),
            )
            .await;
            return;
        };

        let redactor_stdout = self.redactor.clone();
        let tx_stdout = tx.clone();
        let budget_stdout = byte_budget.clone();
        let mut stdout_task = Some(tokio::spawn(async move {
            pump_output_stream(
                stdout,
                "stdout",
                redactor_stdout,
                tx_stdout,
                budget_stdout,
                stream_stdout,
            )
            .await
        }));

        let redactor_stderr = self.redactor.clone();
        let tx_stderr = tx.clone();
        let budget_stderr = byte_budget.clone();
        let mut stderr_task = Some(tokio::spawn(async move {
            pump_output_stream(
                stderr,
                "stderr",
                redactor_stderr,
                tx_stderr,
                budget_stderr,
                stream_stderr,
            )
            .await
        }));

        let mut child_stdin = child.stdin.take();
        let status = loop {
            tokio::select! {
                wait = child.wait() => {
                    match wait {
                        Ok(s) => break s,
                        Err(e) => {
                            let message = format!("command wait failed: {e}");
                            send_done(&tx, Outcome::Error, -1, message.clone()).await;
                            audit_log(
                                &remote,
                                &cmd_id,
                                &args,
                                Some(&decision),
                                Outcome::Error,
                                -1,
                                &message,
                                started,
                            );
                            return;
                        }
                    }
                }
                stdout_done = async { stdout_task.as_mut().expect("guarded").await }, if stdout_task.is_some() => {
                    match stdout_done {
                        Ok(Ok(())) => {
                            stdout_task.take();
                        }
                        Ok(Err(e)) => {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            if let Some(task) = stderr_task.take() {
                                task.abort();
                            }
                            let message = format!("stdout stream failed: {e}");
                            send_done(&tx, Outcome::Error, -1, message.clone()).await;
                            audit_log(
                                &remote,
                                &cmd_id,
                                &args,
                                Some(&decision),
                                Outcome::Error,
                                -1,
                                &message,
                                started,
                            );
                            return;
                        }
                        Err(e) => {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            if let Some(task) = stderr_task.take() {
                                task.abort();
                            }
                            let message = format!("stdout stream task join failed: {e}");
                            send_done(&tx, Outcome::Error, -1, message.clone()).await;
                            audit_log(
                                &remote,
                                &cmd_id,
                                &args,
                                Some(&decision),
                                Outcome::Error,
                                -1,
                                &message,
                                started,
                            );
                            return;
                        }
                    }
                }
                stderr_done = async { stderr_task.as_mut().expect("guarded").await }, if stderr_task.is_some() => {
                    match stderr_done {
                        Ok(Ok(())) => {
                            stderr_task.take();
                        }
                        Ok(Err(e)) => {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            if let Some(task) = stdout_task.take() {
                                task.abort();
                            }
                            let message = format!("stderr stream failed: {e}");
                            send_done(&tx, Outcome::Error, -1, message.clone()).await;
                            audit_log(
                                &remote,
                                &cmd_id,
                                &args,
                                Some(&decision),
                                Outcome::Error,
                                -1,
                                &message,
                                started,
                            );
                            return;
                        }
                        Err(e) => {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            if let Some(task) = stdout_task.take() {
                                task.abort();
                            }
                            let message = format!("stderr stream task join failed: {e}");
                            send_done(&tx, Outcome::Error, -1, message.clone()).await;
                            audit_log(
                                &remote,
                                &cmd_id,
                                &args,
                                Some(&decision),
                                Outcome::Error,
                                -1,
                                &message,
                                started,
                            );
                            return;
                        }
                    }
                }
                msg = inbound.message(), if child_stdin.is_some() => {
                    match msg {
                        Ok(Some(msg)) => match msg.payload {
                            Some(execute_stream_request::Payload::StdinChunk(bytes)) => {
                                if let Some(stdin) = child_stdin.as_mut() {
                                    if let Err(e) = stdin.write_all(&bytes).await {
                                        if e.kind() == ErrorKind::BrokenPipe {
                                            child_stdin.take();
                                            continue;
                                        }
                                        let _ = child.kill().await;
                                        let _ = child.wait().await;
                                        let message = format!("stdin write failed: {e}");
                                        send_done(&tx, Outcome::Error, -1, message.clone()).await;
                                        audit_log(
                                            &remote,
                                            &cmd_id,
                                            &args,
                                            Some(&decision),
                                            Outcome::Error,
                                            -1,
                                            &message,
                                            started,
                                        );
                                        return;
                                    }
                                }
                            }
                            Some(execute_stream_request::Payload::StdinEof(_)) => {
                                child_stdin.take();
                            }
                            Some(execute_stream_request::Payload::Start(_)) => {
                                let _ = child.kill().await;
                                let _ = child.wait().await;
                                let message = "unexpected start message after stream start".to_string();
                                send_done(&tx, Outcome::Error, -1, message.clone()).await;
                                audit_log(
                                    &remote,
                                    &cmd_id,
                                    &args,
                                    Some(&decision),
                                    Outcome::Error,
                                    -1,
                                    &message,
                                    started,
                                );
                                return;
                            }
                            None => {}
                        },
                        Ok(None) => {
                            child_stdin.take();
                        }
                        Err(status) => {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            let message = format!("input stream failed: {status}");
                            send_done(&tx, Outcome::Error, -1, message.clone()).await;
                            audit_log(
                                &remote,
                                &cmd_id,
                                &args,
                                Some(&decision),
                                Outcome::Error,
                                -1,
                                &message,
                                started,
                            );
                            return;
                        }
                    }
                }
            }
        };

        let stdout_result = if let Some(task) = stdout_task.take() {
            task.await
        } else {
            Ok(Ok(()))
        };
        let stderr_result = if let Some(task) = stderr_task.take() {
            task.await
        } else {
            Ok(Ok(()))
        };

        let output_err = match (stdout_result, stderr_result) {
            (Ok(Ok(())), Ok(Ok(()))) => None,
            (Ok(Err(e)), _) => Some(format!("stdout stream failed: {e}")),
            (Err(e), _) => Some(format!("stdout stream task join failed: {e}")),
            (_, Ok(Err(e))) => Some(format!("stderr stream failed: {e}")),
            (_, Err(e)) => Some(format!("stderr stream task join failed: {e}")),
        };

        if let Some(e) = output_err {
            send_done(&tx, Outcome::Error, status.code().unwrap_or(-1), e.clone()).await;
            audit_log(
                &remote,
                &cmd_id,
                &args,
                Some(&decision),
                Outcome::Error,
                status.code().unwrap_or(-1),
                &e,
                started,
            );
            return;
        }

        send_done(
            &tx,
            Outcome::Executed,
            status.code().unwrap_or(-1),
            "".to_string(),
        )
        .await;
        audit_log(
            &remote,
            &cmd_id,
            &args,
            Some(&decision),
            Outcome::Executed,
            status.code().unwrap_or(-1),
            "",
            started,
        );
    }

    async fn apply_gate(&self, cmd_id: &str, args: &[String], intent: &str) -> GateResult {
        let decision = match self.policy.evaluate(cmd_id, args) {
            Ok(v) => v,
            Err(e) => {
                error!("policy evaluation failed: {e:#}");
                return GateResult::Return {
                    outcome: Outcome::Error,
                    message: "policy evaluation failed".to_string(),
                };
            }
        };

        match decision.effect {
            Effect::Allow | Effect::Audit => GateResult::Allow(decision),
            Effect::Deny => GateResult::Return {
                outcome: Outcome::Denied,
                message: "denied by policy".to_string(),
            },
            Effect::Ask => {
                if decision.intent_required && intent.trim().is_empty() {
                    return GateResult::Return {
                        outcome: Outcome::Denied,
                        message: "intent_required: provide intent and retry".to_string(),
                    };
                }

                let Some(hook_path) = self.policy.allow_hook.as_ref() else {
                    return GateResult::Return {
                        outcome: Outcome::Cancelled,
                        message: "ask policy matched but no allow_hook configured".to_string(),
                    };
                };

                match run_allow_hook(
                    hook_path,
                    cmd_id,
                    args,
                    intent,
                    self.policy.allow_hook_timeout_secs,
                )
                .await
                {
                    HookDecision::Yes => GateResult::Allow(decision),
                    HookDecision::No => GateResult::Return {
                        outcome: Outcome::Denied,
                        message: "denied by allow_hook".to_string(),
                    },
                    HookDecision::Cancel => GateResult::Return {
                        outcome: Outcome::Cancelled,
                        message: "cancelled by allow_hook".to_string(),
                    },
                    HookDecision::UserReply(message) => GateResult::Return {
                        outcome: Outcome::UserReply,
                        message,
                    },
                }
            }
        }
    }
}

fn stream_stdout(chunk: String) -> ExecuteStreamEvent {
    ExecuteStreamEvent {
        payload: Some(execute_stream_event::Payload::StdoutUtf8(chunk)),
    }
}

fn stream_stderr(chunk: String) -> ExecuteStreamEvent {
    ExecuteStreamEvent {
        payload: Some(execute_stream_event::Payload::StderrUtf8(chunk)),
    }
}

async fn pump_output_stream<R>(
    reader: R,
    stream_name: &'static str,
    redactor: Redactor,
    tx: mpsc::Sender<StreamEventQueueItem>,
    byte_budget: Arc<Semaphore>,
    event_builder: fn(String) -> ExecuteStreamEvent,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut read_buf = vec![0u8; DEFAULT_CHUNK_BYTES];
    let mut utf8_pending = Vec::new();
    let mut redaction_pending = String::new();

    loop {
        match reader.read(&mut read_buf).await {
            Ok(0) => break,
            Ok(n) => {
                utf8_pending.extend_from_slice(&read_buf[..n]);
                drain_utf8_into_text(&mut utf8_pending, &mut redaction_pending)?;

                flush_pending_text(
                    &mut redaction_pending,
                    false,
                    &redactor,
                    &tx,
                    &byte_budget,
                    event_builder,
                )
                .await?;
            }
            Err(e) => return Err(format!("{stream_name} read failed: {e}")),
        }
    }

    if !utf8_pending.is_empty() {
        let tail = std::str::from_utf8(&utf8_pending)
            .map_err(|_| "non-UTF-8 stream data is unsupported; fail closed".to_string())?;
        redaction_pending.push_str(tail);
        utf8_pending.clear();
    }

    flush_pending_text(
        &mut redaction_pending,
        true,
        &redactor,
        &tx,
        &byte_budget,
        event_builder,
    )
    .await?;

    Ok(())
}

fn drain_utf8_into_text(utf8_pending: &mut Vec<u8>, text_out: &mut String) -> Result<(), String> {
    loop {
        match std::str::from_utf8(utf8_pending) {
            Ok(s) => {
                text_out.push_str(s);
                utf8_pending.clear();
                return Ok(());
            }
            Err(err) => match err.error_len() {
                Some(_) => {
                    return Err("non-UTF-8 stream data is unsupported; fail closed".to_string());
                }
                None => {
                    let valid = err.valid_up_to();
                    if valid == 0 {
                        return Ok(());
                    }
                    let valid_text = std::str::from_utf8(&utf8_pending[..valid]).map_err(|_| {
                        "non-UTF-8 stream data is unsupported; fail closed".to_string()
                    })?;
                    text_out.push_str(valid_text);
                    utf8_pending.drain(..valid);
                }
            },
        }
    }
}

async fn flush_pending_text(
    text: &mut String,
    flush_all: bool,
    redactor: &Redactor,
    tx: &mpsc::Sender<StreamEventQueueItem>,
    byte_budget: &Arc<Semaphore>,
    event_builder: fn(String) -> ExecuteStreamEvent,
) -> Result<(), String> {
    let emit_until = if flush_all {
        text.len()
    } else {
        redactor.stable_prefix_len(text)
    };
    if emit_until == 0 {
        return Ok(());
    }

    let emit_text = text[..emit_until].to_string();
    text.replace_range(..emit_until, "");

    let redacted = redactor.redact_text(&emit_text);
    send_text_events(tx, byte_budget, event_builder, redacted).await
}

async fn send_text_events(
    tx: &mpsc::Sender<StreamEventQueueItem>,
    byte_budget: &Arc<Semaphore>,
    event_builder: fn(String) -> ExecuteStreamEvent,
    text: String,
) -> Result<(), String> {
    let mut offset = 0usize;
    while offset < text.len() {
        let mut end = (offset + DEFAULT_CHUNK_BYTES).min(text.len());
        while end > offset && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == offset {
            return Err("failed splitting UTF-8 stream chunk".to_string());
        }

        let chunk = text[offset..end].to_string();
        let chunk_len = chunk.len();
        queue_send_metered(tx, byte_budget, Ok(event_builder(chunk)), chunk_len).await?;

        offset = end;
    }

    Ok(())
}

async fn send_done(
    tx: &mpsc::Sender<StreamEventQueueItem>,
    outcome: Outcome,
    exit_code: i32,
    message: String,
) {
    let _ = queue_send_unbounded(
        tx,
        Ok(ExecuteStreamEvent {
            payload: Some(execute_stream_event::Payload::Done(ExecuteDone {
                outcome: outcome as i32,
                exit_code,
                message,
            })),
        }),
    )
    .await;
}

fn resp(
    outcome: Outcome,
    exit_code: i32,
    stdout_utf8: impl Into<String>,
    stderr_utf8: impl Into<String>,
    message: impl Into<String>,
) -> ExecuteResponse {
    ExecuteResponse {
        outcome: outcome as i32,
        exit_code,
        stdout_utf8: stdout_utf8.into(),
        stderr_utf8: stderr_utf8.into(),
        message: message.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_log(
    remote: &str,
    cmd: &str,
    args: &[String],
    decision: Option<&Decision>,
    outcome: Outcome,
    exit_code: i32,
    message: &str,
    started: Instant,
) {
    let (effect, rule_source) = match decision {
        Some(d) => (
            format!("{:?}", d.effect),
            d.matched_rule
                .as_ref()
                .map(|r| r.source.clone())
                .unwrap_or_else(|| "default".to_string()),
        ),
        None => ("<none>".to_string(), "<none>".to_string()),
    };

    info!(
        remote = %remote,
        cmd = %cmd,
        args = ?args,
        effect = %effect,
        rule_source = %rule_source,
        outcome = ?outcome,
        exit_code = exit_code,
        elapsed_ms = started.elapsed().as_millis(),
        message = %message,
        "audit"
    );
}
