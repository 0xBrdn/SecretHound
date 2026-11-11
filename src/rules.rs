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
                regex: Regex::new(r"(?i)\b(AKIA[0-9A-Z]{16})\b").expect("invalid AWS Access Key ID regex"),
            },
            // 2. AWS Secret Access Key
            SecretRule {
                name: "aws-secret-access-key",
                description: "AWS Secret Access Key",
                regex: Regex::new(
                    r"(?i)(?:aws)?[_\-\s]?(?:secret)?[_\-\s]?(?:access)?[_\-\s]?key[_\-\s]*(?:=|:)\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
                )
                .expect("invalid AWS Secret Access Key regex"),
            },
            // 3. GitHub Personal Access Token
            SecretRule {
                name: "github-pat",
                description: "GitHub Personal Access Token (ghp_...)",
                regex: Regex::new(r"\b(ghp_[A-Za-z0-9_]{36,})\b").expect("invalid GitHub PAT regex"),
            },
            // 4. Generic private key (RSA / OpenSSH)
            SecretRule {
                name: "private-key",
                description: "Generic private key (BEGIN RSA/OPENSSH PRIVATE KEY)",
                regex: Regex::new(
                    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
                )
                .expect("invalid private key regex"),
            },
            // 5. Password embedded in URL (user:pass@host)
            SecretRule {
                name: "url-password",
                description: "Password embedded in URL (e.g. amqp://user:pass@host)",
                regex: Regex::new(
                    r"(?i)(?:[a-z][a-z0-9+.-]*)://[^:\s/]+:([^@\s/]+)@",
                )
                .expect("invalid URL password regex"),
            },
        ]
    })
}
