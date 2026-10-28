use leakwall::Firewall;
use leakwall::classify::{Assessment, LocalClassifier, RiskClassifier};
use leakwall::detect::{Detector, Kind};
use leakwall::entropy::shannon;
use leakwall::policy::{Action, Policy};

fn policy() -> Policy {
    toml::from_str(include_str!("../policy.toml")).unwrap()
}

fn kinds(text: &str) -> Vec<Kind> {
    Detector::new().scan(text).iter().map(|f| f.kind).collect()
}

#[test]
fn finds_email_and_aws_key() {
    let text = "mail jane.doe@example.com key AKIAIOSFODNN7EXAMPLE";
    assert_eq!(kinds(text), [Kind::Email, Kind::AwsKey]);
}

#[test]
fn random_tokens_have_high_entropy() {
    assert!(shannon("7hG2kQ9xLm4Vr8Tz1Wq6Yb3NcP5s") > 4.0);
    assert!(shannon("password_password_password") < 4.0);
}

#[test]
fn same_secret_gets_same_placeholder() {
    let fw = Firewall::new(policy(), Box::new(LocalClassifier));
    let v = fw.inspect("a@example.com, b@example.com, a@example.com");
    let sent = v.redacted.unwrap();
    assert_eq!(sent, "[EMAIL_1], [EMAIL_2], [EMAIL_1]");
}

/// A classifier that fails the test if it is ever called.
struct MustNotBeCalled;

impl RiskClassifier for MustNotBeCalled {
    fn classify(&self, _: &str) -> Assessment {
        panic!("the AI layer saw a blocked prompt");
    }
}

#[test]
fn private_key_never_reaches_the_ai() {
    let fw = Firewall::new(policy(), Box::new(MustNotBeCalled));
    let v = fw.inspect("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
    assert_eq!(v.action, Action::Block);
    assert!(v.redacted.is_none());
}
