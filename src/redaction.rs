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

    pub fn trailing_secret_prefix_len(&self, text: &str) -> usize {
        if text.is_empty() {
            return 0;
        }
        if self.secrets.is_empty() {
            return 0;
        }
        if self.secrets.iter().any(|secret| text.ends_with(secret)) {
            return 0;
        }

        let mut best = 0usize;
        for secret in &self.secrets {
            if secret.len() <= 1 {
                continue;
            }

            for (prefix_len, _) in secret.char_indices().skip(1) {
                if prefix_len <= best || prefix_len >= secret.len() || prefix_len > text.len() {
                    continue;
                }
                if !text.is_char_boundary(text.len() - prefix_len) {
                    continue;
                }

                if text[text.len() - prefix_len..] == secret[..prefix_len] {
                    best = prefix_len;
                }
            }
        }

        best
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

#[cfg(test)]
mod tests {
    use super::Redactor;

    #[test]
    fn trailing_secret_prefix_len_detects_suffix_candidate() {
        let redactor =
            Redactor::from_secrets(vec!["TOPSECRET".to_string()]).expect("build redactor");
        assert_eq!(redactor.trailing_secret_prefix_len("abcTOPSEC"), 6);
    }

    #[test]
    fn trailing_secret_prefix_len_returns_zero_without_candidate() {
        let redactor =
            Redactor::from_secrets(vec!["TOPSECRET".to_string()]).expect("build redactor");
        assert_eq!(redactor.trailing_secret_prefix_len("abcXYZ"), 0);
        assert_eq!(redactor.trailing_secret_prefix_len("TOPSECRET"), 0);
    }

    #[test]
    fn trailing_secret_prefix_len_supports_multibyte_boundaries() {
        let redactor =
            Redactor::from_secrets(vec!["secrét-value".to_string()]).expect("build redactor");
        assert_eq!(
            redactor.trailing_secret_prefix_len("prefix secré"),
            "secré".len()
        );
    }
}
