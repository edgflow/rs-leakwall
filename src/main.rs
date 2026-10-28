use leakwall::classify::{LocalClassifier, RiskClassifier};
use leakwall::policy::{Action, Policy};
use leakwall::{Firewall, entropy};
use std::io::{IsTerminal, Read};
use std::time::Instant;
use std::{env, fs, hint, io, process};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scan") if args.len() == 2 => scan(&args[1]),
        Some("bench") => bench(),
        Some("entropy") => {
            for word in &args[1..] {
                println!("{:>5.2} bits/char  {word}", entropy::shannon(word));
            }
        }
        _ => {
            eprintln!(
                "usage: leakwall scan <file|-> | bench | entropy <words>"
            );
            process::exit(64);
        }
    }
}

fn firewall() -> Firewall {
    let policy = Policy::load("policy.toml").unwrap_or_else(|e| {
        eprintln!("cannot load policy.toml: {e}");
        process::exit(70);
    });
    Firewall::new(policy, classifier())
}

/// Claude when built with `--features llm` and a key is set, else offline.
fn classifier() -> Box<dyn RiskClassifier> {
    #[cfg(feature = "llm")]
    if let Ok(api_key) = env::var("ANTHROPIC_API_KEY") {
        let model = env::var("LEAKWALL_MODEL")
            .unwrap_or_else(|_| "claude-opus-5-5".to_string());
        return Box::new(leakwall::llm::ClaudeClassifier { api_key, model });
    }
    Box::new(LocalClassifier)
}

fn scan(path: &str) {
    let mut prompt = String::new();
    if path == "-" {
        io::stdin().read_to_string(&mut prompt).expect("read stdin");
    } else {
        prompt = fs::read_to_string(path).expect("read prompt file");
    }
    let fw = firewall();
    let started = Instant::now();
    let verdict = fw.inspect(&prompt);
    let micros = started.elapsed().as_secs_f64() * 1e6;

    println!("{} {path} · {} bytes\n", paint("1", "leakwall"), prompt.len());
    let none = if verdict.findings.is_empty() { "  none" } else { "" };
    println!("{}{none}", paint("1", "FINDINGS"));
    for f in &verdict.findings {
        let secret = mask(&prompt[f.start..f.end]);
        let action = format!("{:?}", fw.action_for(f.kind)).to_lowercase();
        println!("  {:<12} {:<16} {action}", f.kind.tag(), secret);
    }
    match &verdict.redacted {
        Some(text) => {
            println!("\n{}", paint("1", "SENT TO AI"));
            for line in text.lines() {
                println!("  {}", paint("2", line));
            }
        }
        None => println!("\n{}", paint("1;31", "NOT SENT TO AI")),
    }
    if let Some(risk) = &verdict.risk {
        let level = format!("{:?}", risk.risk).to_lowercase();
        println!("\nAI RISK   {level} · {}", risk.reason);
    }
    let (code, color) = match verdict.action {
        Action::Allow => (0, "1;32"),
        Action::Redact => (0, "1;33"),
        Action::Block => (2, "1;31"),
    };
    let label = format!("{:?}", verdict.action).to_uppercase();
    println!("VERDICT   {}  in {micros:.1} µs", paint(color, &label));
    process::exit(code);
}

/// Never print a secret: keep 4 characters on each side.
fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

fn bench() {
    let fw = firewall();
    let base = include_str!("../prompts/leaky.txt");
    println!("{:>8}  {:>10}  {:>10}", "prompt", "per scan", "throughput");
    for kb in [1, 10, 100] {
        let mut prompt = base.repeat(kb * 1024 / base.len() + 1);
        prompt.truncate(kb * 1024);
        let runs = 2_000 / kb;
        let mut batches: Vec<f64> = (0..9)
            .map(|_| {
                let started = Instant::now();
                for _ in 0..runs {
                    hint::black_box(fw.inspect(hint::black_box(&prompt)));
                }
                started.elapsed().as_secs_f64() / runs as f64
            })
            .collect();
        batches.sort_by(f64::total_cmp);
        let secs = batches[4]; // median of 9 batches
        let mbps = prompt.len() as f64 / secs / 1e6;
        println!("{kb:>5} KB  {:>7.1} µs  {mbps:>6.0} MB/s", secs * 1e6);
    }
}

fn paint(code: &str, text: &str) -> String {
    let color =
        io::stdout().is_terminal() || env::var_os("CLICOLOR_FORCE").is_some();
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}
