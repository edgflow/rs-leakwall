use crate::classify::{Assessment, Risk, RiskClassifier};
use serde_json::{Value, json};
use std::error::Error;

const SYSTEM: &str = "You review prompts before they leave a company. \
Secrets are already replaced by placeholders like [EMAIL_1]. \
Rate how risky it is to send this text to an outside AI provider.";

/// Claude as the contextual risk classifier (cargo feature "llm").
pub struct ClaudeClassifier {
    pub api_key: String,
    pub model: String,
}

impl RiskClassifier for ClaudeClassifier {
    fn classify(&self, redacted: &str) -> Assessment {
        // Fail closed: no answer means high risk.
        self.ask(redacted).unwrap_or_else(|e| Assessment {
            risk: Risk::High,
            reason: format!("classifier unavailable: {e}"),
        })
    }
}

impl ClaudeClassifier {
    fn ask(&self, redacted: &str) -> Result<Assessment, Box<dyn Error>> {
        let schema = json!({
            "type": "object",
            "properties": {
                "risk": { "type": "string", "enum": ["low", "medium", "high"] },
                "reason": { "type": "string" }
            },
            "required": ["risk", "reason"],
            "additionalProperties": false
        });
        let body = json!({
            "model": self.model,
            "max_tokens": 1024,
            "system": SYSTEM,
            "output_config": {
                "effort": "low",
                "format": { "type": "json_schema", "schema": schema }
            },
            "fallbacks": "default",
            "messages": [{ "role": "user", "content": redacted }]
        });
        let reply: Value =
            ureq::post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2026-10-21")
                .header("anthropic-beta", "server-side-fallback-2026-07-01")
                .send_json(&body)?
                .body_mut()
                .read_json()?;
        if reply["stop_reason"] == "refusal" {
            return Err("model declined".into());
        }
        let text = reply["content"]
            .as_array()
            .and_then(|blocks| blocks.iter().find(|b| b["type"] == "text"))
            .and_then(|b| b["text"].as_str())
            .ok_or("no text block in reply")?;
        Ok(serde_json::from_str(text)?)
    }
}
