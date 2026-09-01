//! Conversion from `rss_core::FileTime` (100-ns ticks since 1601-01-01 UTC)
//! to RFC 3339 / ISO 8601 UTC timestamps, without pulling in a date library.

use rss_core::FileTime;

/// 100-ns intervals between 1601-01-01 and 1970-01-01 (mirrors the private
/// constant in `rss-core`).
const FILETIME_UNIX_EPOCH_DELTA: i64 = 116_444_736_000_000_000;

/// Format a [`FileTime`] as an RFC 3339 UTC timestamp, e.g.
/// `2023-11-14T22:13:20Z`. A fractional second is appended only when the
/// value has sub-second precision (FILETIME resolves to 100 ns).
pub(crate) fn format_rfc3339(ft: FileTime) -> String {
    let ticks = ft - FILETIME_UNIX_EPOCH_DELTA; // 100-ns ticks since Unix epoch
    let secs = ticks.div_euclid(10_000_000);
    let sub_ticks = ticks.rem_euclid(10_000_000); // [0, 10_000_000)

    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    let base = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    if sub_ticks == 0 {
        format!("{base}Z")
    } else {
        let frac = format!("{sub_ticks:07}");
        format!("{base}.{}Z", frac.trim_end_matches('0'))
    }
}

/// Civil date (year, month, day) from a count of days since 1970-01-01.
/// Howard Hinnant's `civil_from_days` algorithm; correct for negative inputs.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era, [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month index from March, [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::filetime_from_unix;

    #[test]
    fn unix_epoch() {
        assert_eq!(
            format_rfc3339(filetime_from_unix(0)),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn known_date() {
        assert_eq!(
            format_rfc3339(filetime_from_unix(1_700_000_000)),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn pre_epoch() {
        // 1900-01-01 00:00:00 UTC.
        assert_eq!(
            format_rfc3339(filetime_from_unix(-2_208_988_800)),
            "1900-01-01T00:00:00Z"
        );
    }

    #[test]
    fn subsecond_precision() {
        // One 100-ns tick past the epoch, and 1.5 s past the epoch.
        assert_eq!(
            format_rfc3339(filetime_from_unix(0) + 1),
            "1970-01-01T00:00:00.0000001Z"
        );
        assert_eq!(
            format_rfc3339(filetime_from_unix(1) + 5_000_000),
            "1970-01-01T00:00:01.5Z"
        );
    }
}
