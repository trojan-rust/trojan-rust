//! Small helpers shared by the handlers.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Today in UTC, as `YYYY-MM-DD` — the granularity `traffic_logs` aggregates on.
pub fn today_date() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

/// A fresh password: 24 random bytes, base64 — the same shape as
/// `openssl rand -base64 24`. Also used for node tokens.
pub fn gen_password() -> String {
    let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).expect("system randomness unavailable");
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Parse a duration like `24h`, `30m`, `1d12h`, `90s` into seconds.
///
/// Unsupported units are skipped, and a bare number means hours. Returns 0 for
/// anything unparseable, which callers read as "no interval configured".
pub fn parse_duration_secs(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }

    let mut total: u64 = 0;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: u64 = num.parse().unwrap_or(0);
        num.clear();
        match c {
            'd' => total += n * 86400,
            'h' => total += n * 3600,
            'm' => total += n * 60,
            's' => total += n,
            _ => {}
        }
    }
    if !num.is_empty() {
        total += num.parse().unwrap_or(0) * 3600;
    }
    total
}

/// Percent-encode for RFC 5987's `filename*` parameter.
pub fn percent_encode_rfc5987(s: &str) -> String {
    /// RFC 5987 attr-char, minus the characters that still need escaping
    /// inside a header parameter.
    const RFC5987_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'!')
        .remove(b'#')
        .remove(b'$')
        .remove(b'&')
        .remove(b'+')
        .remove(b'-')
        .remove(b'.')
        .remove(b'^')
        .remove(b'_')
        .remove(b'`')
        .remove(b'|')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(s, RFC5987_SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_accumulate_across_units() {
        assert_eq!(parse_duration_secs("1d12h"), 86400 + 12 * 3600);
        assert_eq!(parse_duration_secs("90s"), 90);
        assert_eq!(parse_duration_secs("30m"), 1800);
    }

    #[test]
    fn a_bare_number_means_hours() {
        assert_eq!(parse_duration_secs("24"), 24 * 3600);
    }

    #[test]
    fn unparseable_durations_are_zero() {
        assert_eq!(parse_duration_secs(""), 0);
        assert_eq!(parse_duration_secs("soon"), 0);
    }

    #[test]
    fn today_is_an_iso_date() {
        let today = today_date();
        assert_eq!(today.len(), 10, "{today}");
        assert!(
            today
                .split('-')
                .all(|p| p.chars().all(|c| c.is_ascii_digit()))
        );
    }
}
