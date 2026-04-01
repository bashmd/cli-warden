use crate::{
    config::ClientConfig,
    proto::pb,
    stream_queue::{
        self, send_metered as queue_send_metered, send_unbounded as queue_send_unbounded,
        QueuedItem, DEFAULT_CHUNK_BYTES, DEFAULT_MAX_UNCONFIRMED_BYTES,
        DEFAULT_PACKET_QUEUE_CAPACITY,
    },
};
use anyhow::{bail, Context};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, Semaphore},
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use pb::warden_client::WardenClient;
use pb::{execute_stream_event, execute_stream_request, ExecuteDone, ExecuteStart};

enum StdinSource {
    Bytes(Vec<u8>),
    Live,
}

pub async fn run_list_commands(config_path: PathBuf) -> anyhow::Result<()> {
    let cfg_path = expand_tilde_path(&config_path);
    let cfg = ClientConfig::load(&cfg_path)
        .with_context(|| format!("failed loading client config {}", cfg_path.display()))?;
    let mut client = connect(&cfg).await?;

    let resp = client
        .list_commands(pb::ListCommandsRequest {})
        .await?
        .into_inner();

    for cmd in resp.command_ids {
        println!("{}", cmd);
    }

    Ok(())
}

pub async fn run_execute(
    config_path: PathBuf,
    cmd: String,
    args: Vec<String>,
    intent: Option<String>,
    stdin_utf8: Option<String>,
) -> anyhow::Result<()> {
    let cfg_path = expand_tilde_path(&config_path);
    let cfg = ClientConfig::load(&cfg_path)
        .with_context(|| format!("failed loading client config {}", cfg_path.display()))?;

    let stdin_bytes = stdin_utf8.unwrap_or_default().into_bytes();
    let done = execute_stream(
        &cfg,
        cmd,
        args,
        intent.unwrap_or_default(),
        StdinSource::Bytes(stdin_bytes),
        true,
    )
    .await?;

    let outcome = pb::Outcome::try_from(done.outcome).unwrap_or(pb::Outcome::Unspecified);
    println!("\noutcome: {:?}", outcome);
    println!("exit_code: {}", done.exit_code);
    if !done.message.is_empty() {
        println!("message: {}", done.message);
    }

    Ok(())
}

pub async fn run_install_shims(
    config_path: PathBuf,
    dir: PathBuf,
    force: bool,
) -> anyhow::Result<()> {
    let cfg_path = expand_tilde_path(&config_path);
    let cfg = ClientConfig::load(&cfg_path)
        .with_context(|| format!("failed loading client config {}", cfg_path.display()))?;
    let mut client = connect(&cfg).await?;
    let resp = client
        .list_commands(pb::ListCommandsRequest {})
        .await?
        .into_inner();

    fs::create_dir_all(&dir)?;
    let exe = std::env::current_exe()?;

    let mut installed = 0usize;
    for cmd in resp.command_ids {
        let link = dir.join(&cmd);
        if link.exists() {
            if force {
                fs::remove_file(&link)?;
            } else {
                bail!(
                    "shim already exists at {} (use --force to overwrite)",
                    link.display()
                );
            }
        }

        create_symlink(&exe, &link)?;
        installed += 1;
    }

    println!("installed {} shims into {}", installed, dir.display());
    Ok(())
}

pub async fn run_shim(
    config_path: PathBuf,
    cmd: String,
    args: Vec<String>,
    intent: Option<String>,
) -> anyhow::Result<i32> {
    let cfg_path = expand_tilde_path(&config_path);
    let cfg = ClientConfig::load(&cfg_path)
        .with_context(|| format!("failed loading client config {}", cfg_path.display()))?;

    let done = execute_stream(
        &cfg,
        cmd,
        args,
        intent.unwrap_or_default(),
        StdinSource::Live,
        true,
    )
    .await?;
    let outcome = pb::Outcome::try_from(done.outcome).unwrap_or(pb::Outcome::Unspecified);

    let code = match outcome {
        pb::Outcome::Executed => {
            if done.exit_code >= 0 {
                done.exit_code
            } else {
                1
            }
        }
        pb::Outcome::Denied => 126,
        pb::Outcome::Cancelled => 125,
        pb::Outcome::UserReply => {
            if !done.message.is_empty() {
                eprintln!("{}", done.message);
            }
            125
        }
        pb::Outcome::Error | pb::Outcome::Unspecified => 1,
    };

    Ok(code)
}

async fn execute_stream(
    cfg: &ClientConfig,
    cmd: String,
    args: Vec<String>,
    intent: String,
    stdin_source: StdinSource,
    passthrough_io: bool,
) -> anyhow::Result<ExecuteDone> {
    let mut client = connect(cfg).await?;

    let (tx, rx) =
        mpsc::channel::<QueuedItem<pb::ExecuteStreamRequest>>(DEFAULT_PACKET_QUEUE_CAPACITY);
    let request_stream = stream_queue::into_stream(rx);
    let byte_budget = std::sync::Arc::new(Semaphore::new(DEFAULT_MAX_UNCONFIRMED_BYTES));

    let mut stream = client.execute_stream(request_stream).await?.into_inner();

    queue_send_unbounded(
        &tx,
        pb::ExecuteStreamRequest {
            payload: Some(execute_stream_request::Payload::Start(ExecuteStart {
                cmd,
                args,
                intent,
            })),
        },
    )
    .await
    .map_err(anyhow::Error::msg)?;

    let stdin_task = match stdin_source {
        StdinSource::Bytes(stdin_bytes) => {
            for chunk in stdin_bytes.chunks(DEFAULT_CHUNK_BYTES) {
                send_stdin_chunk(&tx, &byte_budget, chunk.to_vec())
                    .await
                    .map_err(anyhow::Error::msg)?;
            }

            queue_send_unbounded(
                &tx,
                pb::ExecuteStreamRequest {
                    payload: Some(execute_stream_request::Payload::StdinEof(true)),
                },
            )
            .await
            .map_err(anyhow::Error::msg)?;
            None
        }
        StdinSource::Live => {
            let tx_stdin = tx.clone();
            let budget_stdin = byte_budget.clone();
            Some(tokio::spawn(async move {
                let mut stdin = tokio::io::stdin();
                let mut buf = vec![0u8; DEFAULT_CHUNK_BYTES];
                loop {
                    match stdin.read(&mut buf).await {
                        Ok(0) => {
                            let _ = queue_send_unbounded(
                                &tx_stdin,
                                pb::ExecuteStreamRequest {
                                    payload: Some(execute_stream_request::Payload::StdinEof(true)),
                                },
                            )
                            .await;
                            break;
                        }
                        Ok(n) => {
                            if send_stdin_chunk(&tx_stdin, &budget_stdin, buf[..n].to_vec())
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = queue_send_unbounded(
                                &tx_stdin,
                                pb::ExecuteStreamRequest {
                                    payload: Some(execute_stream_request::Payload::StdinEof(true)),
                                },
                            )
                            .await;
                            break;
                        }
                    }
                }
            }))
        }
    };
    drop(tx);

    while let Some(event) = stream.message().await? {
        match event.payload {
            Some(execute_stream_event::Payload::StdoutUtf8(chunk)) => {
                if passthrough_io {
                    print!("{}", chunk);
                    let _ = std::io::stdout().flush();
                }
            }
            Some(execute_stream_event::Payload::StderrUtf8(chunk)) => {
                if passthrough_io {
                    eprint!("{}", chunk);
                    let _ = std::io::stderr().flush();
                }
            }
            Some(execute_stream_event::Payload::Done(done)) => {
                if let Some(stdin_task) = stdin_task.as_ref() {
                    stdin_task.abort();
                }
                return Ok(done);
            }
            None => {}
        }
    }

    if let Some(stdin_task) = stdin_task {
        stdin_task.abort();
    }

    bail!("stream ended without done event")
}

async fn send_stdin_chunk(
    tx: &mpsc::Sender<QueuedItem<pb::ExecuteStreamRequest>>,
    byte_budget: &std::sync::Arc<Semaphore>,
    chunk: Vec<u8>,
) -> Result<(), String> {
    let bytes = chunk.len();
    queue_send_metered(
        tx,
        byte_budget,
        pb::ExecuteStreamRequest {
            payload: Some(execute_stream_request::Payload::StdinChunk(chunk)),
        },
        bytes,
    )
    .await
}

async fn connect(cfg: &ClientConfig) -> anyhow::Result<WardenClient<Channel>> {
    let ca_path = expand_tilde(&cfg.ca_cert_path);
    let cert_path = expand_tilde(&cfg.client_cert_path);
    let key_path = expand_tilde(&cfg.client_key_path);

    let ca = fs::read(&ca_path).with_context(|| format!("failed reading {}", ca_path.display()))?;
    let cert =
        fs::read(&cert_path).with_context(|| format!("failed reading {}", cert_path.display()))?;
    let key =
        fs::read(&key_path).with_context(|| format!("failed reading {}", key_path.display()))?;

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key))
        .domain_name(cfg.server_domain.clone());

    let endpoint = Endpoint::from_shared(cfg.server_uri.clone())?;
    let channel = endpoint.tls_config(tls)?.connect().await?;
    Ok(WardenClient::new(channel))
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    PathBuf::from(path)
}

fn expand_tilde_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    expand_tilde(&raw)
}

#[cfg(unix)]
fn create_symlink(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::os::unix::fs::symlink(src, dst)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_symlink(_src: &Path, _dst: &Path) -> anyhow::Result<()> {
    bail!("shim installation via symlink is currently only supported on unix")
}

#[cfg(test)]
mod tests {
    use super::expand_tilde_path;
    use std::path::Path;

    #[test]
    fn expand_tilde_path_expands_home_prefix() {
        let p = expand_tilde_path(Path::new("~/cli-warden-test/client.toml"));
        assert!(
            !p.to_string_lossy().starts_with("~/"),
            "tilde must be expanded"
        );
        assert!(
            p.to_string_lossy().contains("cli-warden-test/client.toml"),
            "unexpected expanded path: {}",
            p.display()
        );
    }
}
