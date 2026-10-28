use crate::detect::{Finding, Kind};
use std::collections::HashMap;

/// Replace each finding with a placeholder like [EMAIL_1].
/// The same secret always gets the same placeholder.
pub fn redact(text: &str, findings: &[Finding]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut labels: HashMap<&str, String> = HashMap::new();
    let mut counts: HashMap<Kind, usize> = HashMap::new();
    let mut last = 0;
    for f in findings {
        out.push_str(&text[last..f.start]);
        let secret = &text[f.start..f.end];
        let label = labels.entry(secret).or_insert_with(|| {
            let n = counts.entry(f.kind).or_insert(0);
            *n += 1;
            format!("[{}_{}]", f.kind.tag(), n)
        });
        out.push_str(label);
        last = f.end;
    }
    out.push_str(&text[last..]);
    out
}
