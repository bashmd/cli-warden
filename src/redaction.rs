use aho_corasick::AhoCorasick;

#[derive(Debug, Clone)]
pub struct Redactor {
    secrets: Vec<String>,
    matcher: Option<AhoCorasick>,
}

impl Redactor {
    pub fn from_secrets(secrets: Vec<String>) -> anyhow::Result<Self> {
        if secrets.is_empty() {
            return Ok(Self {
                secrets,
                matcher: None,
            });
        }

        let matcher = AhoCorasick::new(&secrets)?;
        Ok(Self {
            secrets,
            matcher: Some(matcher),
        })
    }

    pub fn redact_utf8(&self, data: &[u8]) -> anyhow::Result<String> {
        let text = std::str::from_utf8(data)
            .map_err(|_| anyhow::anyhow!("non-UTF-8 stream data is unsupported; fail closed"))?;

        Ok(self.redact_text(text))
    }

    pub fn redact_text(&self, text: &str) -> String {
        if self.secrets.is_empty() {
            return text.to_string();
        }

        let matcher = self.matcher.as_ref().expect("matcher present with secrets");
        let replacements = vec!["<redacted>"; self.secrets.len()];
        matcher.replace_all(text, &replacements)
    }

    pub fn max_secret_len_bytes(&self) -> usize {
        self.secrets.iter().map(|s| s.len()).max().unwrap_or(0)
    }

    pub fn stable_prefix_len(&self, text: &str) -> usize {
        if text.is_empty() {
            return 0;
        }
        if self.secrets.is_empty() {
            return text.len();
        }

        let max_secret_len = self.max_secret_len_bytes();
        if max_secret_len <= 1 {
            return text.len();
        }
        if text.len() < max_secret_len {
            return 0;
        }

        let matcher = self.matcher.as_ref().expect("matcher present with secrets");
        let mut stable_end = text.len() - (max_secret_len - 1);

        loop {
            let mut changed = false;
            for mat in matcher.find_overlapping_iter(text) {
                if mat.start() < stable_end && mat.end() > stable_end {
                    stable_end = mat.start();
                    changed = true;
                    break;
                }
            }
            if !changed {
                break;
            }
        }

        while stable_end > 0 && !text.is_char_boundary(stable_end) {
            stable_end -= 1;
        }
        stable_end
    }
}

pub fn load_secrets(path: &std::path::Path) -> anyhow::Result<Vec<String>> {
    let raw = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}
