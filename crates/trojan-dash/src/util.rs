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
    date_days_ago(0)
}

/// A UTC date `days` before today, in the same `YYYY-MM-DD` form.
///
/// `traffic_logs.date` is text, so a range query compares strings; ISO order
/// and lexical order agree, which is why the column is stored this way.
pub fn date_days_ago(days: i64) -> String {
    format_date(time::OffsetDateTime::now_utc() - time::Duration::days(days))
}

/// The current UTC hour, as `YYYY-MM-DDTHH` — the key `traffic_hourly` sums on.
///
/// Prefixed by the date it falls in, so the same lexical-order trick works and
/// an hour range is a string comparison.
pub fn current_hour() -> String {
    format_hour(time::OffsetDateTime::now_utc())
}

/// A UTC hour `hours` before now, in the same `YYYY-MM-DDTHH` form.
pub fn hour_hours_ago(hours: i64) -> String {
    format_hour(time::OffsetDateTime::now_utc() - time::Duration::hours(hours))
}

fn format_date(at: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        at.year(),
        u8::from(at.month()),
        at.day()
    )
}

fn format_hour(at: time::OffsetDateTime) -> String {
    format!("{}T{:02}", format_date(at), at.hour())
}

/// The first day of the current UTC month, in the same `YYYY-MM-DD` form.
///
/// `traffic_logs.date` is UTC text, so the month a quota covers is a string
/// comparison against this — and nothing needs resetting when it rolls over.
pub fn month_start() -> String {
    let at = time::OffsetDateTime::now_utc();
    format!("{:04}-{:02}-01", at.year(), u8::from(at.month()))
}

/// The `Authorization: Basic` credential for a user: base64 of
/// `username:password`.
///
/// What a client script needs to call `/me`, in the one encoding that survives
/// being pasted into a config file — base64's alphabet has none of the
/// characters those formats delimit on.
pub fn basic_auth(username: &str, password: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
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

    /// The month a quota covers is compared against `traffic_logs.date` as a
    /// string, so it has to be the same shape and the same calendar.
    #[test]
    fn the_month_starts_on_the_first_of_todays_month() {
        let today = today_date();
        let start = month_start();

        assert_eq!(start.len(), today.len());
        assert!(start.ends_with("-01"));
        assert_eq!(start[..7], today[..7], "same year and month as today");
        assert!(start <= today, "a month starts on or before today");
    }

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

    /// An hour key must sort with the date it belongs to, since every range
    /// query on `traffic_hourly` is a string comparison.
    #[test]
    fn an_hour_extends_the_date_it_falls_in() {
        let hour = current_hour();
        assert_eq!(hour.len(), 13, "{hour}");
        assert!(hour.starts_with(&today_date()), "{hour}");
    }

    #[test]
    fn hours_ago_orders_before_now() {
        assert!(hour_hours_ago(1) < current_hour());
        assert!(hour_hours_ago(48) < hour_hours_ago(24));
    }

    /// Padding is what makes lexical order agree with time: `2026-08-13T09`
    /// must sort before `2026-08-13T10`.
    #[test]
    fn a_single_digit_hour_is_padded() {
        let at = time::OffsetDateTime::from_unix_timestamp(1_775_000_000)
            .expect("a fixed timestamp is in range");
        let hour = format_hour(at.replace_hour(9).expect("9 is a valid hour"));
        assert!(hour.ends_with("T09"), "{hour}");
        assert!(hour < format_hour(at.replace_hour(10).expect("10 is a valid hour")));
    }
}
