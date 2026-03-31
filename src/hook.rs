use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

#[derive(Debug, Clone)]
pub enum HookDecision {
    Yes,
    No,
    Cancel,
    UserReply(String),
}

#[derive(Debug, Serialize)]
struct HookRequest<'a> {
    cmd: &'a str,
    argv: &'a [String],
    intent: &'a str,
}

#[derive(Debug, Deserialize)]
struct HookResponse {
    decision: String,
    reply: Option<String>,
}

pub async fn run_allow_hook(
    hook_path: &str,
    cmd: &str,
    argv: &[String],
    intent: &str,
    timeout_secs: u64,
) -> HookDecision {
    let payload = HookRequest { cmd, argv, intent };
    let encoded = match serde_json::to_vec(&payload) {
        Ok(v) => v,
        Err(_) => return HookDecision::Cancel,
    };

    let mut child = match Command::new(hook_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return HookDecision::Cancel,
    };

    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(&encoded).await.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return HookDecision::Cancel;
        }
    }

    let mut stdout_pipe = match child.stdout.take() {
        Some(stdout) => stdout,
        None => return HookDecision::Cancel,
    };
    let stdout_reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        match stdout_pipe.read_to_end(&mut buf).await {
            Ok(_) => Ok(buf),
            Err(err) => Err(err),
        }
    });

    let status = match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => return HookDecision::Cancel,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_reader.await;
            return HookDecision::Cancel;
        }
    };

    let stdout_bytes = match stdout_reader.await {
        Ok(Ok(bytes)) => bytes,
        _ => return HookDecision::Cancel,
    };

    if !status.success() {
        return HookDecision::Cancel;
    }

    let stdout = match String::from_utf8(stdout_bytes) {
        Ok(s) => s,
        Err(_) => return HookDecision::Cancel,
    };

    let resp: HookResponse = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(_) => return HookDecision::Cancel,
    };

    match resp.decision.as_str() {
        "yes" => HookDecision::Yes,
        "no" => HookDecision::No,
        "cancel" => HookDecision::Cancel,
        "user-reply" => HookDecision::UserReply(resp.reply.unwrap_or_default()),
        _ => HookDecision::Cancel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::Instant};

    #[cfg(unix)]
    fn write_executable_script(path: &std::path::Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, body).expect("write script");
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod +x");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn hook_timeout_returns_cancel() {
        let dir = tempfile::tempdir().expect("temp dir");
        let hook = dir.path().join("hook-timeout.sh");
        write_executable_script(
            &hook,
            "#!/usr/bin/env bash\nset -euo pipefail\nsleep 2\necho '{\"decision\":\"yes\"}'\n",
        );

        let started = Instant::now();
        let decision = run_allow_hook(hook.to_str().expect("utf8 path"), "demo", &[], "", 1).await;
        assert!(matches!(decision, HookDecision::Cancel));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timeout path took unexpectedly long"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn invalid_json_returns_cancel() {
        let dir = tempfile::tempdir().expect("temp dir");
        let hook = dir.path().join("hook-invalid-json.sh");
        write_executable_script(
            &hook,
            "#!/usr/bin/env bash\nset -euo pipefail\necho 'not-json'\n",
        );

        let decision = run_allow_hook(hook.to_str().expect("utf8 path"), "demo", &[], "", 5).await;
        assert!(matches!(decision, HookDecision::Cancel));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn non_utf8_stdout_returns_cancel() {
        let dir = tempfile::tempdir().expect("temp dir");
        let hook = dir.path().join("hook-non-utf8.sh");
        write_executable_script(
            &hook,
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '\\xff'\n",
        );

        let decision = run_allow_hook(hook.to_str().expect("utf8 path"), "demo", &[], "", 5).await;
        assert!(matches!(decision, HookDecision::Cancel));
    }

    #[tokio::test]
    async fn missing_hook_binary_returns_cancel() {
        let decision = run_allow_hook("/no/such/hook", "demo", &[], "", 1).await;
        assert!(matches!(decision, HookDecision::Cancel));
    }
}
