use crate::{
    config::{DaemonConfig, Effect},
    policy::PolicyEngine,
};
use std::path::PathBuf;

pub fn run_lint(config: PathBuf) -> anyhow::Result<()> {
    let cfg = DaemonConfig::load(&config)?;
    let _ = PolicyEngine::from_config(&cfg.policy, &cfg.rules)?;
    println!("OK: policy config parsed and validated");
    Ok(())
}

pub fn run_test(
    config: PathBuf,
    cmd: String,
    args: Vec<String>,
    intent: Option<String>,
) -> anyhow::Result<()> {
    let cfg = DaemonConfig::load(&config)?;
    let engine = PolicyEngine::from_config(&cfg.policy, &cfg.rules)?;
    let decision = engine.evaluate(&cmd, &args)?;

    println!("effect: {:?}", decision.effect);
    println!("intent_required: {}", decision.intent_required);
    if let Some(m) = decision.matched_rule {
        println!("matched_rule: {}", m.source);
    } else {
        println!("matched_rule: <default>");
    }

    let intent = intent.unwrap_or_default();
    if decision.effect == Effect::Ask && decision.intent_required && intent.trim().is_empty() {
        println!("would_deny: missing intent");
    }

    Ok(())
}

pub fn run_explain(
    config: PathBuf,
    cmd: String,
    args: Vec<String>,
    intent: Option<String>,
) -> anyhow::Result<()> {
    let cfg = DaemonConfig::load(&config)?;
    let engine = PolicyEngine::from_config(&cfg.policy, &cfg.rules)?;
    let decision = engine.evaluate(&cmd, &args)?;

    println!("cmd: {}", cmd);
    println!("args: {:?}", args);
    println!("effect: {:?}", decision.effect);
    println!("intent_required: {}", decision.intent_required);

    if let Some(m) = decision.matched_rule {
        println!("matched_source: {}", m.source);
        println!("matcher: {}", m.matcher);
        println!("specificity: {}", m.specificity);
        println!("arg_len: {}", m.arg_len);
    } else {
        println!("matched_source: <default policy>");
    }

    let intent = intent.unwrap_or_default();
    if decision.effect == Effect::Ask && decision.intent_required && intent.trim().is_empty() {
        println!("effective_result: deny (missing intent)");
    } else {
        println!("effective_result: {:?}", decision.effect);
    }

    Ok(())
}
