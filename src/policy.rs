use crate::config::{Effect, PolicyConfig, RawRule};
use anyhow::{bail, Context};
use glob::Pattern;
use regex::Regex;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub default: Effect,
    pub ask_requires_intent: bool,
    pub allow_hook_timeout_secs: u64,
    pub allow_hook: Option<String>,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    effect: Effect,
    cmd: String,
    matcher: Matcher,
    intent_required: Option<bool>,
    source: String,
}

#[derive(Debug, Clone)]
enum Matcher {
    Exact(Vec<String>),
    Prefix(Vec<String>),
    Glob(Vec<Pattern>),
    Regex(Vec<Regex>),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct MatchQuality {
    specificity: u8,
    arg_len: usize,
}

#[derive(Debug, Clone)]
pub struct MatchedRule {
    pub source: String,
    pub matcher: String,
    pub specificity: u8,
    pub arg_len: usize,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub effect: Effect,
    pub intent_required: bool,
    pub matched_rule: Option<MatchedRule>,
}

impl PolicyEngine {
    pub fn from_config(cfg: &PolicyConfig, advanced: &[RawRule]) -> anyhow::Result<Self> {
        let mut raw_rules: Vec<(RawRule, String)> = Vec::new();

        for (idx, rule) in cfg.allow.iter().enumerate() {
            raw_rules.push((
                parse_shorthand(rule, Effect::Allow)?,
                format!("policy.allow[{idx}]"),
            ));
        }
        for (idx, rule) in cfg.deny.iter().enumerate() {
            raw_rules.push((
                parse_shorthand(rule, Effect::Deny)?,
                format!("policy.deny[{idx}]"),
            ));
        }
        for (idx, rule) in cfg.ask.iter().enumerate() {
            raw_rules.push((
                parse_shorthand(rule, Effect::Ask)?,
                format!("policy.ask[{idx}]"),
            ));
        }
        for (idx, rule) in advanced.iter().cloned().enumerate() {
            raw_rules.push((rule, format!("rules[{idx}]")));
        }

        let mut compiled = Vec::with_capacity(raw_rules.len());
        for (rr, source) in raw_rules {
            compiled.push(compile_rule(rr, source)?);
        }

        validate_conflicting_ties(&compiled)?;

        Ok(Self {
            default: cfg.default,
            ask_requires_intent: cfg.ask_requires_intent,
            allow_hook_timeout_secs: cfg.allow_hook_timeout_secs,
            allow_hook: cfg.allow_hook.clone(),
            rules: compiled,
        })
    }

    pub fn evaluate(&self, cmd: &str, args: &[String]) -> anyhow::Result<Decision> {
        let mut best_quality: Option<MatchQuality> = None;
        let mut best_rules: Vec<&CompiledRule> = Vec::new();

        for rule in &self.rules {
            if rule.cmd != cmd {
                continue;
            }

            let Some(q) = rule.matcher.quality(args) else {
                continue;
            };

            match best_quality {
                None => {
                    best_quality = Some(q);
                    best_rules.clear();
                    best_rules.push(rule);
                }
                Some(curr) if q > curr => {
                    best_quality = Some(q);
                    best_rules.clear();
                    best_rules.push(rule);
                }
                Some(curr) if q == curr => {
                    best_rules.push(rule);
                }
                Some(_) => {}
            }
        }

        if best_rules.is_empty() {
            let intent_required = self.default == Effect::Ask && self.ask_requires_intent;
            return Ok(Decision {
                effect: self.default,
                intent_required,
                matched_rule: None,
            });
        }

        let mut effects = HashSet::new();
        for rule in &best_rules {
            effects.insert(rule.effect);
        }
        if effects.len() > 1 {
            let sources: Vec<&str> = best_rules.iter().map(|r| r.source.as_str()).collect();
            bail!(
                "conflicting policy rules for cmd '{}' at same specificity: {:?}",
                cmd,
                sources
            );
        }

        let picked = best_rules[0];
        let effect = picked.effect;
        let intent_required = if effect == Effect::Ask {
            picked.intent_required.unwrap_or(self.ask_requires_intent)
        } else {
            false
        };
        let q = best_quality.expect("best quality present with best rule");

        Ok(Decision {
            effect,
            intent_required,
            matched_rule: Some(MatchedRule {
                source: picked.source.clone(),
                matcher: picked.matcher.name().to_string(),
                specificity: q.specificity,
                arg_len: q.arg_len,
            }),
        })
    }
}

impl Matcher {
    fn quality(&self, args: &[String]) -> Option<MatchQuality> {
        match self {
            Matcher::Exact(pat) => {
                if args == pat {
                    Some(MatchQuality {
                        specificity: 4,
                        arg_len: pat.len(),
                    })
                } else {
                    None
                }
            }
            Matcher::Prefix(pat) => {
                if args.starts_with(pat) {
                    Some(MatchQuality {
                        specificity: 3,
                        arg_len: pat.len(),
                    })
                } else {
                    None
                }
            }
            Matcher::Glob(pat) => {
                if pat.len() != args.len() {
                    return None;
                }

                for (p, arg) in pat.iter().zip(args.iter()) {
                    if !p.matches(arg) {
                        return None;
                    }
                }

                Some(MatchQuality {
                    specificity: 2,
                    arg_len: pat.len(),
                })
            }
            Matcher::Regex(pat) => {
                if pat.len() != args.len() {
                    return None;
                }

                for (p, arg) in pat.iter().zip(args.iter()) {
                    if !p.is_match(arg) {
                        return None;
                    }
                }

                Some(MatchQuality {
                    specificity: 1,
                    arg_len: pat.len(),
                })
            }
        }
    }

    fn static_quality(&self) -> MatchQuality {
        match self {
            Matcher::Exact(v) => MatchQuality {
                specificity: 4,
                arg_len: v.len(),
            },
            Matcher::Prefix(v) => MatchQuality {
                specificity: 3,
                arg_len: v.len(),
            },
            Matcher::Glob(v) => MatchQuality {
                specificity: 2,
                arg_len: v.len(),
            },
            Matcher::Regex(v) => MatchQuality {
                specificity: 1,
                arg_len: v.len(),
            },
        }
    }

    fn fingerprint(&self) -> String {
        match self {
            Matcher::Exact(v) => format!("exact:{:?}", v),
            Matcher::Prefix(v) => format!("prefix:{:?}", v),
            Matcher::Glob(v) => {
                let parts: Vec<_> = v.iter().map(|p| p.as_str()).collect();
                format!("glob:{:?}", parts)
            }
            Matcher::Regex(v) => {
                let parts: Vec<_> = v.iter().map(|p| p.as_str()).collect();
                format!("regex:{:?}", parts)
            }
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Matcher::Exact(_) => "exact",
            Matcher::Prefix(_) => "prefix",
            Matcher::Glob(_) => "glob",
            Matcher::Regex(_) => "regex",
        }
    }
}

fn parse_shorthand(spec: &str, effect: Effect) -> anyhow::Result<RawRule> {
    let tokens: Vec<String> = spec.split_whitespace().map(ToString::to_string).collect();
    if tokens.is_empty() {
        bail!("empty shorthand rule");
    }

    let cmd = tokens[0].clone();
    let args = tokens[1..].to_vec();

    if args.is_empty() {
        return Ok(RawRule {
            effect,
            cmd,
            args_exact: None,
            args_prefix: Some(Vec::new()),
            args_glob: None,
            args_regex: None,
            intent_required: None,
        });
    }

    let has_glob = args.iter().any(|s| has_glob_meta(s));
    let trailing_star = args.last().is_some_and(|s| s == "*")
        && args[..args.len() - 1].iter().all(|s| !has_glob_meta(s));

    if trailing_star {
        return Ok(RawRule {
            effect,
            cmd,
            args_exact: None,
            args_prefix: Some(args[..args.len() - 1].to_vec()),
            args_glob: None,
            args_regex: None,
            intent_required: None,
        });
    }

    if has_glob {
        return Ok(RawRule {
            effect,
            cmd,
            args_exact: None,
            args_prefix: None,
            args_glob: Some(args),
            args_regex: None,
            intent_required: None,
        });
    }

    Ok(RawRule {
        effect,
        cmd,
        args_exact: None,
        args_prefix: Some(args),
        args_glob: None,
        args_regex: None,
        intent_required: None,
    })
}

fn has_glob_meta(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

fn compile_rule(rr: RawRule, source: String) -> anyhow::Result<CompiledRule> {
    let mut matcher_count = 0usize;
    if rr.args_exact.is_some() {
        matcher_count += 1;
    }
    if rr.args_prefix.is_some() {
        matcher_count += 1;
    }
    if rr.args_glob.is_some() {
        matcher_count += 1;
    }
    if rr.args_regex.is_some() {
        matcher_count += 1;
    }

    if matcher_count > 1 {
        bail!("rule for '{}' has multiple matcher types", rr.cmd);
    }

    let matcher = if let Some(v) = rr.args_exact {
        Matcher::Exact(v)
    } else if let Some(v) = rr.args_prefix {
        Matcher::Prefix(v)
    } else if let Some(v) = rr.args_glob {
        let mut compiled = Vec::with_capacity(v.len());
        for token in v {
            compiled
                .push(Pattern::new(&token).with_context(|| format!("invalid glob '{}'", token))?);
        }
        Matcher::Glob(compiled)
    } else if let Some(v) = rr.args_regex {
        let mut compiled = Vec::with_capacity(v.len());
        for token in v {
            compiled
                .push(Regex::new(&token).with_context(|| format!("invalid regex '{}'", token))?);
        }
        Matcher::Regex(compiled)
    } else {
        Matcher::Prefix(Vec::new())
    };

    Ok(CompiledRule {
        effect: rr.effect,
        cmd: rr.cmd,
        matcher,
        intent_required: rr.intent_required,
        source,
    })
}

fn validate_conflicting_ties(rules: &[CompiledRule]) -> anyhow::Result<()> {
    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            let a = &rules[i];
            let b = &rules[j];

            if a.cmd != b.cmd {
                continue;
            }
            if a.matcher.static_quality() != b.matcher.static_quality() {
                continue;
            }
            if a.matcher.fingerprint() == b.matcher.fingerprint() && a.effect != b.effect {
                bail!(
                    "conflicting tied rules for command '{}': {} vs {}",
                    a.cmd,
                    a.source,
                    b.source
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_policy() -> PolicyConfig {
        PolicyConfig {
            default: Effect::Deny,
            ask_requires_intent: true,
            allow_hook_timeout_secs: 1800,
            allow_hook: None,
            allow: Vec::new(),
            deny: Vec::new(),
            ask: Vec::new(),
        }
    }

    fn empty_rule(effect: Effect, cmd: &str) -> RawRule {
        RawRule {
            effect,
            cmd: cmd.to_string(),
            args_exact: None,
            args_prefix: None,
            args_glob: None,
            args_regex: None,
            intent_required: None,
        }
    }

    #[test]
    fn precedence_exact_over_prefix_over_glob_over_regex() {
        let cfg = base_policy();
        let mut rules = Vec::new();

        let mut regex = empty_rule(Effect::Allow, "demo");
        regex.args_regex = Some(vec![".*".to_string(), ".*".to_string()]);
        rules.push(regex);

        let mut glob = empty_rule(Effect::Deny, "demo");
        glob.args_glob = Some(vec!["*".to_string(), "*".to_string()]);
        rules.push(glob);

        let mut prefix = empty_rule(Effect::Ask, "demo");
        prefix.args_prefix = Some(vec!["alpha".to_string()]);
        rules.push(prefix);

        let mut exact = empty_rule(Effect::Audit, "demo");
        exact.args_exact = Some(vec!["alpha".to_string(), "beta".to_string()]);
        rules.push(exact);

        let engine = PolicyEngine::from_config(&cfg, &rules).expect("build policy");
        let args = vec!["alpha".to_string(), "beta".to_string()];
        let decision = engine.evaluate("demo", &args).expect("evaluate");
        assert_eq!(decision.effect, Effect::Audit);
        assert_eq!(
            decision.matched_rule.as_ref().map(|m| m.matcher.as_str()),
            Some("exact")
        );

        let args = vec!["alpha".to_string(), "zzz".to_string()];
        let decision = engine.evaluate("demo", &args).expect("evaluate");
        assert_eq!(decision.effect, Effect::Ask);
        assert_eq!(
            decision.matched_rule.as_ref().map(|m| m.matcher.as_str()),
            Some("prefix")
        );

        let args = vec!["x".to_string(), "y".to_string()];
        let decision = engine.evaluate("demo", &args).expect("evaluate");
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(
            decision.matched_rule.as_ref().map(|m| m.matcher.as_str()),
            Some("glob")
        );
    }

    #[test]
    fn conflicting_tied_rules_are_rejected_at_load() {
        let cfg = base_policy();
        let mut a = empty_rule(Effect::Allow, "demo");
        a.args_prefix = Some(vec!["calendar".to_string(), "add".to_string()]);
        let mut b = empty_rule(Effect::Deny, "demo");
        b.args_prefix = Some(vec!["calendar".to_string(), "add".to_string()]);

        let err = PolicyEngine::from_config(&cfg, &[a, b]).expect_err("must reject conflicts");
        assert!(
            err.to_string().contains("conflicting tied rules"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ask_intent_can_be_overridden_per_rule() {
        let cfg = base_policy();
        let mut ask_no_intent = empty_rule(Effect::Ask, "demo");
        ask_no_intent.args_prefix = Some(vec!["sync".to_string()]);
        ask_no_intent.intent_required = Some(false);

        let engine = PolicyEngine::from_config(&cfg, &[ask_no_intent]).expect("build policy");
        let decision = engine
            .evaluate("demo", &["sync".to_string(), "now".to_string()])
            .expect("evaluate");

        assert_eq!(decision.effect, Effect::Ask);
        assert!(
            !decision.intent_required,
            "rule-level override should disable global ask_requires_intent"
        );
    }
}
