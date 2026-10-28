use crate::classify::Risk;
use crate::detect::Kind;
use serde::Deserialize;
use std::collections::HashMap;
use std::{error::Error, fs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Redact,
    Block,
}

#[derive(Deserialize)]
pub struct Policy {
    rules: HashMap<Kind, Action>,
    ai: AiRules,
}

#[derive(Deserialize)]
struct AiRules {
    block_on: Risk,
}

impl Policy {
    pub fn load(path: &str) -> Result<Policy, Box<dyn Error>> {
        let text = fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    /// Unknown kinds are blocked: the policy fails closed.
    pub fn action_for(&self, kind: Kind) -> Action {
        self.rules.get(&kind).copied().unwrap_or(Action::Block)
    }

    pub fn blocks_risk(&self, risk: Risk) -> bool {
        risk >= self.ai.block_on
    }
}
