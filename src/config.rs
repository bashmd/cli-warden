use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    pub server: ServerConfig,
    pub pki: PkiConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub commands: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: Option<SecretsConfig>,
    #[serde(default)]
    pub rules: Vec<RawRule>,
}

impl DaemonConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = toml::to_string_pretty(self)?;
        fs::write(path, text)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub client_ca_cert_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PkiConfig {
    pub ca_cert_path: String,
    pub ca_key_path: String,
    pub clients_dir: String,
    pub server_uri: String,
    pub server_domain: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    pub file: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    pub server_uri: String,
    pub server_domain: String,
    pub ca_cert_path: String,
    pub client_cert_path: String,
    pub client_key_path: String,
}

impl ClientConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        Ok(cfg)
    }
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
    Ask,
    Audit,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    #[serde(default = "default_effect")]
    pub default: Effect,
    #[serde(default)]
    pub ask_requires_intent: bool,
    #[serde(default = "default_allow_hook_timeout_secs")]
    pub allow_hook_timeout_secs: u64,
    pub allow_hook: Option<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: default_effect(),
            ask_requires_intent: false,
            allow_hook_timeout_secs: default_allow_hook_timeout_secs(),
            allow_hook: None,
            allow: Vec::new(),
            deny: Vec::new(),
            ask: Vec::new(),
        }
    }
}

fn default_effect() -> Effect {
    Effect::Deny
}

fn default_allow_hook_timeout_secs() -> u64 {
    1800
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawRule {
    pub effect: Effect,
    pub cmd: String,
    pub args_exact: Option<Vec<String>>,
    pub args_prefix: Option<Vec<String>>,
    pub args_glob: Option<Vec<String>>,
    pub args_regex: Option<Vec<String>>,
    pub intent_required: Option<bool>,
}
