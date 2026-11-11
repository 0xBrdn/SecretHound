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
            // ── Cloud Providers ──────────────────────────────────────────────
            SecretRule {
                name: "aws-access-key-id",
                description: "AWS Access Key ID (AKIA...)",
                regex: Regex::new(r"(?i)\b(AKIA[0-9A-Z]{16})\b")
                    .expect("invalid AWS Access Key ID regex"),
            },
            SecretRule {
                name: "aws-secret-access-key",
                description: "AWS Secret Access Key",
                regex: Regex::new(
                    r#"(?i)(?:aws)?[_\-\s]?(?:secret)?[_\-\s]?(?:access)?[_\-\s]?key[_\-\s]*(?:=|:)\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
                )
                .expect("invalid AWS Secret Access Key regex"),
            },
            // ── GitHub ───────────────────────────────────────────────────────
            SecretRule {
                name: "github-pat",
                description: "GitHub Personal Access Token (ghp_...)",
                regex: Regex::new(r"\b(ghp_[A-Za-z0-9_]{36,})\b")
                    .expect("invalid GitHub PAT regex"),
            },
            SecretRule {
                name: "github-oauth",
                description: "GitHub OAuth Access Token (gho_...)",
                regex: Regex::new(r"\b(gho_[A-Za-z0-9_]{36,})\b")
                    .expect("invalid GitHub OAuth regex"),
            },
            SecretRule {
                name: "github-app-token",
                description: "GitHub App Token (ghu_/ghs_...)",
                regex: Regex::new(r"\b(gh[us]_[A-Za-z0-9_]{36,})\b")
                    .expect("invalid GitHub App token regex"),
            },
            // ── Private Keys ─────────────────────────────────────────────────
            SecretRule {
                name: "private-key",
                description: "Generic private key (BEGIN RSA/OPENSSH/EC/DSA PRIVATE KEY)",
                regex: Regex::new(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")
                    .expect("invalid private key regex"),
            },
            // ── Slack ────────────────────────────────────────────────────────
            SecretRule {
                name: "slack-token",
                description: "Slack Token (xox[baprs]-...)",
                regex: Regex::new(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")
                    .expect("invalid Slack token regex"),
            },
            SecretRule {
                name: "slack-webhook",
                description: "Slack Incoming Webhook URL",
                regex: Regex::new(
                    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
                )
                .expect("invalid Slack webhook regex"),
            },
            // ── Stripe ───────────────────────────────────────────────────────
            SecretRule {
                name: "stripe-api-key",
                description: "Stripe API Key (sk_live_/pk_live_/sk_test_...)",
                regex: Regex::new(r"\b([sp]k_(?:live|test)_[0-9a-zA-Z]{20,})\b")
                    .expect("invalid Stripe API key regex"),
            },
            // ── Google ───────────────────────────────────────────────────────
            SecretRule {
                name: "google-api-key",
                description: "Google API Key (AIza...)",
                regex: Regex::new(r"\b(AIza[0-9A-Za-z_-]{35})\b")
                    .expect("invalid Google API key regex"),
            },
            // ── Twilio ───────────────────────────────────────────────────────
            SecretRule {
                name: "twilio-api-key",
                description: "Twilio API Key (SK...)",
                regex: Regex::new(r"\b(SK[0-9a-fA-F]{32})\b")
                    .expect("invalid Twilio API key regex"),
            },
            // ── JWT ──────────────────────────────────────────────────────────
            SecretRule {
                name: "jwt-token",
                description: "JSON Web Token (JWT)",
                regex: Regex::new(r"\b(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)\b")
                    .expect("invalid JWT regex"),
            },
            // ── Generic / High-entropy ───────────────────────────────────────
            SecretRule {
                name: "generic-api-key",
                description: "Generic API key / secret assignment",
                regex: Regex::new(
                    r#"(?i)(?:api[_\-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]"#,
                )
                .expect("invalid generic API key regex"),
            },
            // ── URL credentials ──────────────────────────────────────────────
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

    #[test]
    fn detects_slack_token() {
        let rules = get_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "slack-token")
            .expect("slack-token rule missing");

        assert!(rule.regex.is_match("xoxb-1234567890-ABCDEFG"));
    }

    #[test]
    fn detects_stripe_key() {
        let rules = get_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "stripe-api-key")
            .expect("stripe-api-key rule missing");

        assert!(rule.regex.is_match("sk_live_abcdefghijklmnopqrstuv"));
    }

    #[test]
    fn detects_jwt() {
        let rules = get_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "jwt-token")
            .expect("jwt-token rule missing");

        let sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(rule.regex.is_match(sample));
    }
}
