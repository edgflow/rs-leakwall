use crate::detect::{Finding, Kind};
use regex::Regex;
use std::sync::LazyLock;

pub static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{24,}").unwrap());

/// Shannon entropy in bits per character.
pub fn shannon(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Long tokens that look random are probably secrets.
pub fn find_secrets(text: &str) -> Vec<Finding> {
    TOKEN
        .find_iter(text)
        .filter(|m| shannon(m.as_str()) > 4.0)
        .map(|m| Finding {
            kind: Kind::HighEntropy,
            start: m.start(),
            end: m.end(),
        })
        .collect()
}
