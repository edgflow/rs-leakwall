pub mod classify;
pub mod detect;
pub mod entropy;
#[cfg(feature = "llm")]
pub mod llm;
pub mod policy;
pub mod redact;

use classify::{Assessment, RiskClassifier};
use detect::{Detector, Finding, Kind};
use policy::{Action, Policy};

pub struct Firewall {
    detector: Detector,
    policy: Policy,
    classifier: Box<dyn RiskClassifier>,
}

pub struct Verdict {
    pub action: Action,
    pub findings: Vec<Finding>,
    pub redacted: Option<String>,
    pub risk: Option<Assessment>,
}

impl Firewall {
    pub fn new(policy: Policy, classifier: Box<dyn RiskClassifier>) -> Self {
        Firewall { detector: Detector::new(), policy, classifier }
    }

    pub fn inspect(&self, prompt: &str) -> Verdict {
        // 1. Deterministic detection always runs first.
        let findings = self.detector.scan(prompt);
        let mut action = findings
            .iter()
            .map(|f| self.policy.action_for(f.kind))
            .max()
            .unwrap_or(Action::Allow);

        // 2. A blocked prompt never reaches the AI layer.
        if action == Action::Block {
            return Verdict { action, findings, redacted: None, risk: None };
        }

        // 3. Redact, then let the AI judge the context.
        let hide: Vec<Finding> = findings
            .iter()
            .filter(|f| self.policy.action_for(f.kind) == Action::Redact)
            .cloned()
            .collect();
        let redacted = redact::redact(prompt, &hide);
        let risk = self.classifier.classify(&redacted);
        if self.policy.blocks_risk(risk.risk) {
            action = Action::Block;
        }
        Verdict {
            action,
            findings,
            redacted: Some(redacted),
            risk: Some(risk),
        }
    }

    pub fn action_for(&self, kind: Kind) -> Action {
        self.policy.action_for(kind)
    }
}
