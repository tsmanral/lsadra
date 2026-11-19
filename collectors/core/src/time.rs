//! Minimal UTC time formatting, so the agents need no date-time crate.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

pub fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// RFC 3339 UTC (`…Z`) with microseconds, from microseconds since the epoch.
/// Returns `None` before year 1 or past year 9999 (outside the contract).
pub fn rfc3339_from_unix_micros(micros: i64) -> Option<String> {
    let secs = micros.div_euclid(1_000_000);
    let frac = micros.rem_euclid(1_000_000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    if !(1..=9999).contains(&y) {
        return None;
    }
    let sod = secs.rem_euclid(86_400);
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:06}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    ))
}

/// The current time as RFC 3339 UTC.
pub fn now_rfc3339() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);
    rfc3339_from_unix_micros(micros).unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(
            rfc3339_from_unix_micros(0).unwrap(),
            "1970-01-01T00:00:00.000000Z"
        );
        assert_eq!(
            rfc3339_from_unix_micros(1_709_164_800_123_456).unwrap(),
            "2024-02-29T00:00:00.123456Z"
        );
        assert_eq!(
            rfc3339_from_unix_micros(1_768_442_472_000_000).unwrap(),
            "2026-01-15T02:01:12.000000Z"
        );
        assert_eq!(
            rfc3339_from_unix_micros(-1).unwrap(),
            "1969-12-31T23:59:59.999999Z"
        );
    }

    #[test]
    fn now_is_valid_contract_time() {
        crate::event::validate_timestamp(&now_rfc3339()).unwrap();
    }
}
