//! Which of two timestamps is earlier.
//!
//! Written out rather than pulled in because the only thing it is needed for is
//! telling two timestamps apart, and lexical comparison gets that wrong the
//! moment one of them carries an offset (`+03:00`) and the other a `Z` — which
//! is exactly the pair this crate compares: docker reports local time with an
//! offset, Docker Hub reports UTC.

/// RFC 3339 to Unix seconds.
///
/// Accepts a `T` or a space between the date and the time, an optional
/// fractional part, and `Z`, `+HH:MM`, `-HH:MM` or `+HHMM` as the offset.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 19 || (bytes[10] != b'T' && bytes[10] != b' ') {
        return None;
    }
    let num = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let minute = num(14, 16)?;
    let second = num(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // The offset is whatever follows the seconds and any fractional part.
    let rest = &s[19..];
    let rest = match rest.strip_prefix('.') {
        Some(frac) => {
            let n = frac.chars().take_while(char::is_ascii_digit).count();
            &frac[n..]
        }
        None => rest,
    };
    let offset = match rest.chars().next() {
        None | Some('Z') | Some('z') => 0,
        Some(sign @ ('+' | '-')) => {
            let body = &rest[1..];
            let (h, m) = match body.split_once(':') {
                Some((h, m)) => (h, m),
                None if body.len() == 4 => (&body[..2], &body[2..]),
                None => return None,
            };
            let secs = h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60;
            if sign == '-' { -secs } else { secs }
        }
        Some(_) => return None,
    };

    // Days from the civil calendar — Howard Hinnant's `days_from_civil`.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_and_a_leap_day_land_where_they_should() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(parse_rfc3339("2024-02-29T12:00:00Z"), Some(1_709_208_000));
    }

    #[test]
    fn timestamps_are_compared_as_instants_and_not_as_text() {
        // Same instant, two spellings — the case a string comparison gets wrong.
        assert_eq!(
            parse_rfc3339("2026-07-28T20:42:46.902542441+03:00"),
            parse_rfc3339("2026-07-28T17:42:46Z")
        );
        assert!(
            parse_rfc3339("2026-07-28T20:00:00+03:00").unwrap()
                < parse_rfc3339("2026-07-28T18:00:00Z").unwrap(),
            "an offset-bearing timestamp must not win on its text"
        );
        // A negative offset is behind UTC, so the instant is later.
        assert_eq!(
            parse_rfc3339("2026-07-28T14:00:00-04:00"),
            parse_rfc3339("2026-07-28T18:00:00Z")
        );
        // Offsets without a colon are legal too.
        assert_eq!(
            parse_rfc3339("2026-07-28T14:00:00-0400"),
            parse_rfc3339("2026-07-28T18:00:00Z")
        );
    }

    #[test]
    fn the_shapes_docker_and_docker_hub_actually_emit_are_accepted() {
        assert!(parse_rfc3339("2026-07-28T18:27:14.917129Z").is_some());
        assert!(parse_rfc3339("2026-07-28T20:42:46.902542441+03:00").is_some());
        // Docker's zero time for a container that never stopped.
        assert!(parse_rfc3339("0001-01-01T00:00:00Z").is_some());
        assert!(parse_rfc3339("2026-07-28 21:00:00Z").is_some());
    }

    #[test]
    fn what_is_not_a_timestamp_is_refused() {
        for s in [
            "",
            "28 July 2026",
            "2026-07-28",
            "2026-13-01T00:00:00Z",
            "x",
        ] {
            assert!(parse_rfc3339(s).is_none(), "{s:?} was accepted");
        }
    }
}
