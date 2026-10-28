use crate::entropy;
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Email,
    AwsKey,
    ApiKey,
    GithubToken,
    PrivateKey,
    HighEntropy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
}

pub struct Detector {
    rules: Vec<(Kind, Regex)>,
}

impl Detector {
    pub fn new() -> Self {
        let patterns = [
            (Kind::Email, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
            (Kind::AwsKey, r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
            (Kind::ApiKey, r"\bsk-[A-Za-z0-9_-]{20,}"),
            (Kind::GithubToken, r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
            (Kind::PrivateKey, r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ];
        let rules = patterns
            .into_iter()
            .map(|(kind, p)| (kind, Regex::new(p).unwrap()))
            .collect();
        LazyLock::force(&entropy::TOKEN);
        Detector { rules }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut found = Vec::new();
        for (kind, re) in &self.rules {
            for m in re.find_iter(text) {
                found.push(Finding {
                    kind: *kind,
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
        // Entropy is the safety net: only where no rule matched.
        let mut taken = vec![false; text.len()];
        for f in &found {
            taken[f.start..f.end].fill(true);
        }
        for f in entropy::find_secrets(text) {
            if !taken[f.start..f.end].contains(&true) {
                found.push(f);
            }
        }
        found.sort_by_key(|f| (f.start, f.kind));
        found.dedup_by(|b, a| overlaps(a, b));
        found
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

fn overlaps(a: &Finding, b: &Finding) -> bool {
    a.start < b.end && b.start < a.end
}

impl Kind {
    pub fn tag(self) -> &'static str {
        match self {
            Kind::Email => "EMAIL",
            Kind::AwsKey => "AWS_KEY",
            Kind::ApiKey => "API_KEY",
            Kind::GithubToken => "GITHUB_TOKEN",
            Kind::PrivateKey => "PRIVATE_KEY",
            Kind::HighEntropy => "SECRET",
        }
    }
}
