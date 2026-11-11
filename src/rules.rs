//! Secret detection rules for SecretHound
//! Author: 0xBrdn

use regex::Regex;
use std::sync::OnceLock;

/// A single secret detection rule.
#[derive(Debug, Clone)]
pub struct SecretRule {
    /// Short identifier (e.g. "aws-access-key")
    pub name: &'static str,
    /// Human-readable description
    #[allow(dead_code)]
    pub description: &'static str,
    /// Compiled regular expression
    pub regex: Regex,
}

/// Returns the full set of built-in secret rules.
/// Patterns are compiled exactly once thanks to `OnceLock`.
pub fn get_rules() -> &'static [SecretRule] {
    static RULES: OnceLock<Vec<SecretRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            // 1. AWS Access Key ID
            SecretRule {
                name: "aws-access-key-id",
                description: "AWS Access Key ID (AKIA...)",
                regex: Regex::new(r"(?i)\b(AKIA[0-9A-Z]{16})\b")
                    .expect("invalid AWS Access Key ID regex"),
            },
            // 2. AWS Secret Access Key
            SecretRule {
                name: "aws-secret-access-key",
                description: "AWS Secret Access Key",
                regex: Regex::new(
                    r#"(?i)(?:aws)?[_\-\s]?(?:secret)?[_\-\s]?(?:access)?[_\-\s]?key[_\-\s]*(?:=|:)\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
                )
                .expect("invalid AWS Secret Access Key regex"),
            },
            // 3. GitHub Personal Access Token
            SecretRule {
                name: "github-pat",
                description: "GitHub Personal Access Token (ghp_...)",
                regex: Regex::new(r"\b(ghp_[A-Za-z0-9_]{36,})\b")
                    .expect("invalid GitHub PAT regex"),
            },
            // 4. Generic private key (RSA / OpenSSH)
            SecretRule {
                name: "private-key",
                description: "Generic private key (BEGIN RSA/OPENSSH PRIVATE KEY)",
                regex: Regex::new(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")
                    .expect("invalid private key regex"),
            },
            // 5. Password embedded in URL (user:pass@host)
            SecretRule {
                name: "url-password",
                description: "Credentials embedded inside a URL",
                regex: Regex::new(r"(?i)(?:[a-z][a-z0-9+.-]*)://[^:\s/]+:([^@\s/]+)@")
                    .expect("invalid URL password regex"),
            },
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_valid_aws_access_key() {
        let rules = get_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "aws-access-key-id")
            .expect("aws-access-key-id rule missing");

        let sample = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        assert!(rule.regex.is_match(sample));

        let captures = rule.regex.captures(sample).unwrap();
        assert_eq!(&captures[1], "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn ignores_random_text_for_aws_key() {
        let rules = get_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "aws-access-key-id")
            .expect("aws-access-key-id rule missing");

        let noise = "This is just some random text without any secrets AKIA too short";
        assert!(!rule.regex.is_match(noise));
    }

    #[test]
    fn detects_github_pat() {
        let rules = get_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "github-pat")
            .expect("github-pat rule missing");

        let sample = "token = ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
        assert!(rule.regex.is_match(sample));
    }

    #[test]
    fn detects_private_key_header() {
        let rules = get_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "private-key")
            .expect("private-key rule missing");

        assert!(rule.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(rule.regex.is_match("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(!rule.regex.is_match("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn detects_url_password() {
        let rules = get_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "url-password")
            .expect("url-password rule missing");

        let sample = "amqp://admin:s3cr3tPass@rabbitmq.internal:5672";
        assert!(rule.regex.is_match(sample));
    }
}
