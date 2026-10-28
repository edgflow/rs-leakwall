use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Deserialize)]
pub struct Assessment {
    pub risk: Risk,
    pub reason: String,
}

/// The AI layer. It only ever sees the redacted prompt.
pub trait RiskClassifier {
    fn classify(&self, redacted: &str) -> Assessment;
}

/// Offline stand-in for a model: weighted context cues.
pub struct LocalClassifier;

const CUES: &[(&str, u32)] = &[
    ("confidential", 3),
    ("internal only", 3),
    ("do not share", 3),
    ("acquisition", 2),
    ("production", 1),
    ("customer", 1),
];

impl RiskClassifier for LocalClassifier {
    fn classify(&self, redacted: &str) -> Assessment {
        let text = redacted.to_lowercase();
        let hits: Vec<_> =
            CUES.iter().filter(|(cue, _)| text.contains(cue)).collect();
        let score: u32 = hits.iter().map(|(_, weight)| weight).sum();
        let risk = match score {
            0..=1 => Risk::Low,
            2..=5 => Risk::Medium,
            _ => Risk::High,
        };
        let cues: Vec<_> = hits.iter().map(|(cue, _)| *cue).collect();
        let reason = match cues.is_empty() {
            true => "no sensitive context".to_string(),
            false => format!("score {score}: {}", cues.join(", ")),
        };
        Assessment { risk, reason }
    }
}
