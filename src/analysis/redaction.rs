use regex::Regex;
use sha2::{Digest, Sha256};

const REDACTED: &str = "[REDACTED]";

pub fn redact_and_bound(input: &str, maximum_bytes: usize) -> String {
    let mut output = input.to_owned();
    let patterns = [
        (
            r"(?i)(authorization\s*:\s*)(?:bearer\s+)?[^\s]+",
            "$1[REDACTED]",
        ),
        (r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]"),
        (
            r"(?im)^([^\r\n:=]*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY)[^\r\n:=]*\s*[:=]\s*).*$",
            "$1[REDACTED]",
        ),
        (r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@", "$1[REDACTED]@"),
        (
            r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
            "[REDACTED PRIVATE KEY]",
        ),
    ];
    for (pattern, replacement) in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            output = regex.replace_all(&output, replacement).into_owned();
        }
    }
    output = redact_long_tokens(&output);
    truncate_utf8(&output, maximum_bytes)
}

/// Redacts an untrusted value and makes it safe for one-line text logs.
pub fn redact_and_bound_single_line(input: &str, maximum_bytes: usize) -> String {
    let redacted = redact_and_bound(input, maximum_bytes.saturating_mul(2));
    let normalized = redacted.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_utf8(&normalized, maximum_bytes)
}

pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub fn truncate_utf8(input: &str, maximum_bytes: usize) -> String {
    if input.len() <= maximum_bytes {
        return input.to_owned();
    }
    let mut boundary = maximum_bytes;
    while boundary > 0 && !input.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}…[truncated]", &input[..boundary])
}

fn redact_long_tokens(input: &str) -> String {
    input
        .split_inclusive(char::is_whitespace)
        .map(|part| {
            let token = part.trim_end_matches(char::is_whitespace);
            let suffix = &part[token.len()..];
            let looks_secret = token.len() >= 48
                && token.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "+/=_-.".contains(character)
                })
                && token.chars().any(|character| character.is_ascii_digit())
                && token
                    .chars()
                    .any(|character| character.is_ascii_alphabetic());
            if looks_secret {
                format!("{REDACTED}{suffix}")
            } else {
                part.to_owned()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::redact_and_bound_single_line;

    #[test]
    fn log_values_are_redacted_and_kept_on_one_line() {
        let value = redact_and_bound_single_line(
            "502 Bad Gateway\nAuthorization: Bearer sensitive-value\ntry again",
            200,
        );

        assert_eq!(value, "502 Bad Gateway Authorization: [REDACTED] try again");
    }
}
