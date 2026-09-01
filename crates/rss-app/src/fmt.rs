//! Small formatting helpers shared by the CLI summary and the GUI
//! (status bar, tooltips).

use rss_core::FileTime;

/// Human-readable binary-unit size (1024-based, matching the FR-4.4 units).
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Format a [`FileTime`] as `YYYY-MM-DD HH:MM:SS UTC`. A zero timestamp
/// (unknown / not provided by the scanner) renders as `—`.
pub fn format_filetime(ft: FileTime) -> String {
    if ft <= 0 {
        return "—".to_string();
    }
    let secs = rss_core::filetime_to_unix(ft);
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        day_secs / 3600,
        (day_secs / 60) % 60,
        day_secs % 60
    )
}

/// Civil calendar date from days since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, public domain algorithm).
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

#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::filetime_from_unix;

    #[test]
    fn bytes_formatting() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn filetime_formatting() {
        // 1970-01-01 00:00:00 UTC.
        assert_eq!(
            format_filetime(filetime_from_unix(0)),
            "1970-01-01 00:00:00 UTC"
        );
        // 2000-02-29 12:34:56 UTC = 951827696 (leap day exercises the civil math).
        assert_eq!(
            format_filetime(filetime_from_unix(951_827_696)),
            "2000-02-29 12:34:56 UTC"
        );
        // Unknown timestamps render as a dash.
        assert_eq!(format_filetime(0), "—");
    }
}
