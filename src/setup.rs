use crate::config::{ClientConfig, DaemonConfig, Effect, PkiConfig, PolicyConfig, ServerConfig};
use anyhow::{anyhow, bail, Context};
use dialoguer::Input;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::{
    collections::BTreeMap,
    fs,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

const CA_COMMON_NAME: &str = "cli-warden-ca";

#[derive(Debug, Clone)]
pub struct SetupOptions {
    pub out_dir: Option<PathBuf>,
    pub listen: Option<String>,
    pub server_domain: Option<String>,
    pub sans: Vec<String>,
    pub client_name: Option<String>,
}

pub fn run_setup(opts: SetupOptions) -> anyhow::Result<()> {
    let out_dir: PathBuf = match opts.out_dir {
        Some(v) => v,
        None => Input::<String>::new()
            .with_prompt("Output directory")
            .default("./warden-state".to_string())
            .interact_text()?
            .into(),
    };

    let listen = match opts.listen {
        Some(v) => v,
        None => Input::<String>::new()
            .with_prompt("Daemon listen address")
            .default("0.0.0.0:50051".to_string())
            .interact_text()?,
    };
    let listen = normalize_listen_addr(&listen)?;

    let server_domain = match opts.server_domain {
        Some(v) => v,
        None => Input::<String>::new()
            .with_prompt("Server domain name (TLS)")
            .default("localhost".to_string())
            .interact_text()?,
    };

    let client_name = match opts.client_name {
        Some(v) => v,
        None => Input::<String>::new()
            .with_prompt("Initial client name")
            .default("default-client".to_string())
            .interact_text()?,
    };

    let mut sans = vec![server_domain.clone()];
    sans.extend(opts.sans);
    sans.sort();
    sans.dedup();

    let pki_dir = out_dir.join("pki");
    let clients_dir = pki_dir.join("clients");
    let config_dir = out_dir.join("config");
    fs::create_dir_all(&clients_dir)?;
    fs::create_dir_all(&config_dir)?;

    let ca = make_ca_cert()?;
    let daemon = make_daemon_cert(&sans, &ca.cert, &ca.key)?;
    let client = make_client_cert(&client_name, &ca.cert, &ca.key)?;

    let ca_cert_path = pki_dir.join("ca-cert.pem");
    let ca_key_path = pki_dir.join("ca-key.pem");
    let daemon_cert_path = pki_dir.join("daemon-cert.pem");
    let daemon_key_path = pki_dir.join("daemon-key.pem");
    let client_cert_path = clients_dir.join(format!("{}-cert.pem", client_name));
    let client_key_path = clients_dir.join(format!("{}-key.pem", client_name));

    fs::write(&ca_cert_path, ca.cert.pem())?;
    fs::write(&ca_key_path, ca.key.serialize_pem())?;
    fs::write(&daemon_cert_path, daemon.cert_pem)?;
    fs::write(&daemon_key_path, daemon.key_pem)?;
    fs::write(&client_cert_path, client.cert_pem)?;
    fs::write(&client_key_path, client.key_pem)?;

    let server_uri = server_uri_from_listen(listen.port(), &server_domain)?;

    let secrets_file = out_dir.join("secrets.txt");
    if !secrets_file.exists() {
        fs::write(&secrets_file, "")?;
    }

    let daemon_cfg = DaemonConfig {
        server: ServerConfig {
            listen: listen.to_string(),
            tls_cert_path: daemon_cert_path.display().to_string(),
            tls_key_path: daemon_key_path.display().to_string(),
            client_ca_cert_path: ca_cert_path.display().to_string(),
        },
        pki: PkiConfig {
            ca_cert_path: ca_cert_path.display().to_string(),
            ca_key_path: ca_key_path.display().to_string(),
            clients_dir: clients_dir.display().to_string(),
            server_uri: server_uri.clone(),
            server_domain: server_domain.clone(),
        },
        policy: PolicyConfig {
            default: Effect::Deny,
            ask_requires_intent: true,
            allow_hook_timeout_secs: 1800,
            allow_hook: None,
            allow: Vec::new(),
            deny: Vec::new(),
            ask: Vec::new(),
        },
        commands: BTreeMap::new(),
        secrets: Some(crate::config::SecretsConfig {
            file: secrets_file.display().to_string(),
        }),
        rules: Vec::new(),
    };

    let daemon_cfg_path = config_dir.join("daemon.toml");
    daemon_cfg.save(&daemon_cfg_path)?;

    let client_cfg = ClientConfig {
        server_uri,
        server_domain,
        ca_cert_path: "~/.config/cli-warden/pki/ca-cert.pem".to_string(),
        client_cert_path: format!("~/.config/cli-warden/pki/{}-cert.pem", client_name),
        client_key_path: format!("~/.config/cli-warden/pki/{}-key.pem", client_name),
    };

    println!("\nSetup complete.");
    println!("Daemon config: {}", daemon_cfg_path.display());
    println!("\nCopy these files to the client machine:");
    println!("- {}", ca_cert_path.display());
    println!("- {}", client_cert_path.display());
    println!("- {}", client_key_path.display());

    print_client_bootstrap(&client_cfg);

    Ok(())
}

pub fn emit_client(daemon_config_path: &Path, name: &str) -> anyhow::Result<()> {
    let cfg = DaemonConfig::load(daemon_config_path)?;

    let clients_dir = PathBuf::from(&cfg.pki.clients_dir);
    fs::create_dir_all(&clients_dir)?;

    let ca_key_pem = fs::read_to_string(&cfg.pki.ca_key_path)
        .with_context(|| format!("failed reading {}", cfg.pki.ca_key_path))?;
    let ca = make_ca_from_existing_key(&ca_key_pem)?;

    let client = make_client_cert(name, &ca.cert, &ca.key)?;
    let client_cert_path = clients_dir.join(format!("{}-cert.pem", name));
    let client_key_path = clients_dir.join(format!("{}-key.pem", name));

    fs::write(&client_cert_path, client.cert_pem)?;
    fs::write(&client_key_path, client.key_pem)?;

    let client_cfg = ClientConfig {
        server_uri: cfg.pki.server_uri,
        server_domain: cfg.pki.server_domain,
        ca_cert_path: "~/.config/cli-warden/pki/ca-cert.pem".to_string(),
        client_cert_path: format!("~/.config/cli-warden/pki/{}-cert.pem", name),
        client_key_path: format!("~/.config/cli-warden/pki/{}-key.pem", name),
    };

    println!("Generated client cert/key for '{}'.", name);
    println!("Client cert: {}", client_cert_path.display());
    println!("Client key : {}", client_key_path.display());
    print_client_bootstrap(&client_cfg);

    Ok(())
}

fn print_client_bootstrap(cfg: &ClientConfig) {
    println!("\nClient bootstrap snippet (paste on client machine):\n");
    println!("mkdir -p ~/.config/cli-warden");
    println!("cat > ~/.config/cli-warden/client.toml <<'EOF'");
    println!("server_uri = \"{}\"", cfg.server_uri);
    println!("server_domain = \"{}\"", cfg.server_domain);
    println!("ca_cert_path = \"{}\"", cfg.ca_cert_path);
    println!("client_cert_path = \"{}\"", cfg.client_cert_path);
    println!("client_key_path = \"{}\"", cfg.client_key_path);
    println!("EOF\n");
}

fn normalize_listen_addr(listen: &str) -> anyhow::Result<SocketAddr> {
    let trimmed = listen.trim();
    if trimmed.is_empty() {
        bail!("invalid listen address: value is empty");
    }

    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let mut resolved = trimmed
        .to_socket_addrs()
        .with_context(|| format!("invalid listen address '{}'", listen))?;
    resolved.next().ok_or_else(|| {
        anyhow!(
            "invalid listen address '{}': resolved to no addresses",
            listen
        )
    })
}

fn server_uri_from_listen(port: u16, domain: &str) -> anyhow::Result<String> {
    let domain = domain.trim();
    if domain.is_empty() {
        bail!("invalid server domain: value is empty");
    }
    Ok(format!("https://{}:{}", domain, port))
}

struct BuiltCert {
    cert_pem: String,
    key_pem: String,
}

struct CaBundle {
    cert: Certificate,
    key: KeyPair,
}

fn make_ca_params() -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    params.distinguished_name = dn;
    Ok(params)
}

fn make_ca_cert() -> anyhow::Result<CaBundle> {
    let key = KeyPair::generate()?;
    let cert = make_ca_params()?.self_signed(&key)?;
    Ok(CaBundle { cert, key })
}

fn make_ca_from_existing_key(ca_key_pem: &str) -> anyhow::Result<CaBundle> {
    let key = KeyPair::from_pem(ca_key_pem)?;
    let cert = make_ca_params()?.self_signed(&key)?;
    Ok(CaBundle { cert, key })
}

fn make_daemon_cert(
    sans: &[String],
    ca_cert: &Certificate,
    ca_key: &KeyPair,
) -> anyhow::Result<BuiltCert> {
    if sans.is_empty() {
        bail!("at least one daemon SAN is required");
    }

    let leaf_key = KeyPair::generate()?;
    let mut params = CertificateParams::new(sans.to_vec())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "cli-warden-daemon");
    params.distinguished_name = dn;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let cert = params.signed_by(&leaf_key, ca_cert, ca_key)?;

    Ok(BuiltCert {
        cert_pem: cert.pem(),
        key_pem: leaf_key.serialize_pem(),
    })
}

fn make_client_cert(
    name: &str,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
) -> anyhow::Result<BuiltCert> {
    let leaf_key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("cli-warden-client:{}", name));
    params.distinguished_name = dn;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let cert = params.signed_by(&leaf_key, ca_cert, ca_key)?;

    Ok(BuiltCert {
        cert_pem: cert.pem(),
        key_pem: leaf_key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::{normalize_listen_addr, server_uri_from_listen};
    use std::net::IpAddr;

    #[test]
    fn normalize_listen_accepts_ip_socket_addr() {
        let addr = normalize_listen_addr("127.0.0.1:50051").expect("must parse");
        assert_eq!(addr.ip(), IpAddr::from([127, 0, 0, 1]));
        assert_eq!(addr.port(), 50051);
    }

    #[test]
    fn normalize_listen_accepts_hostname() {
        let addr = normalize_listen_addr("localhost:50051").expect("must resolve");
        assert_eq!(addr.port(), 50051);
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn normalize_listen_rejects_missing_port() {
        let err = normalize_listen_addr("localhost").expect_err("must fail");
        assert!(
            err.to_string().contains("invalid listen address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn server_uri_uses_domain_and_port() {
        let uri = server_uri_from_listen(50051, "localhost").expect("must build uri");
        assert_eq!(uri, "https://localhost:50051");
    }
}
