mod client;
mod config;
mod hook;
mod policy;
mod policy_tool;
mod proto;
mod redaction;
mod server;
mod setup;
mod stream_queue;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "cli-warden")]
#[command(about = "Remote CLI policy daemon with mTLS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Setup {
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        server_domain: Option<String>,
        #[arg(long = "san")]
        sans: Vec<String>,
        #[arg(long)]
        client_name: Option<String>,
    },
    EmitClient {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        name: String,
    },
    Daemon {
        #[arg(long)]
        config: PathBuf,
    },
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ClientCommand {
    ListCommands {
        #[arg(long)]
        config: PathBuf,
    },
    Exec {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        cmd: String,
        #[arg(long)]
        intent: Option<String>,
        #[arg(long)]
        stdin: Option<String>,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    InstallShims {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Lint {
        #[arg(long)]
        config: PathBuf,
    },
    Test {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        cmd: String,
        #[arg(long)]
        intent: Option<String>,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    Explain {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        cmd: String,
        #[arg(long)]
        intent: Option<String>,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    if let Some(shim_cmd) = shim_command_name() {
        let config_path = std::env::var("CLI_WARDEN_CLIENT_CONFIG")
            .unwrap_or_else(|_| "~/.config/cli-warden/client.toml".to_string());
        let intent = std::env::var("CLI_WARDEN_INTENT").ok();
        let args: Vec<String> = std::env::args().skip(1).collect();
        let exit_code =
            client::run_shim(PathBuf::from(config_path), shim_cmd, args, intent).await?;
        std::process::exit(exit_code);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            out_dir,
            listen,
            server_domain,
            sans,
            client_name,
        } => {
            setup::run_setup(setup::SetupOptions {
                out_dir,
                listen,
                server_domain,
                sans,
                client_name,
            })?;
        }
        Commands::EmitClient { config, name } => {
            setup::emit_client(&config, &name)?;
        }
        Commands::Daemon { config } => {
            server::run_daemon(config).await?;
        }
        Commands::Client { command } => match command {
            ClientCommand::ListCommands { config } => {
                client::run_list_commands(config).await?;
            }
            ClientCommand::Exec {
                config,
                cmd,
                intent,
                stdin,
                args,
            } => {
                client::run_execute(config, cmd, args, intent, stdin).await?;
            }
            ClientCommand::InstallShims { config, dir, force } => {
                client::run_install_shims(config, dir, force).await?;
            }
        },
        Commands::Policy { command } => match command {
            PolicyCommand::Lint { config } => {
                policy_tool::run_lint(config)?;
            }
            PolicyCommand::Test {
                config,
                cmd,
                intent,
                args,
            } => {
                policy_tool::run_test(config, cmd, args, intent)?;
            }
            PolicyCommand::Explain {
                config,
                cmd,
                intent,
                args,
            } => {
                policy_tool::run_explain(config, cmd, args, intent)?;
            }
        },
    }

    Ok(())
}

fn shim_command_name() -> Option<String> {
    let argv0 = std::env::args().next()?;
    let name = Path::new(&argv0).file_name()?.to_string_lossy().to_string();
    let self_names = [
        format!("cli-warden{}", std::env::consts::EXE_SUFFIX),
        "cli-warden".to_string(),
    ];
    if self_names.iter().any(|s| s == &name) {
        None
    } else {
        Some(name)
    }
}
