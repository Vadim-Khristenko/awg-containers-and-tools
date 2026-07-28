//! Which of two versions is newer.
//!
//! The entire reason this is not `a < b` on two strings: lexically `"0.1.9"`
//! sorts above `"0.1.10"`, so a text comparison would tell a user on 0.1.10 to
//! downgrade. Semver 2.0.0 ordering is implemented properly, pre-release tails
//! and all.

/// The version this binary was compiled as.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// One dot-separated identifier of a pre-release tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreField {
    /// Numeric identifiers compare numerically and always rank below
    /// alphanumeric ones — semver 2.0.0, rule 11.4.
    Num(u64),
    Text(String),
}

impl Ord for PreField {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use PreField::{Num, Text};
        use std::cmp::Ordering::{Greater, Less};
        match (self, other) {
            (Num(a), Num(b)) => a.cmp(b),
            (Text(a), Text(b)) => a.cmp(b),
            (Num(_), Text(_)) => Less,
            (Text(_), Num(_)) => Greater,
        }
    }
}

impl PartialOrd for PreField {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A semantic version, enough of one to order releases correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Empty for a normal release.
    pub pre: Vec<PreField>,
}

impl SemVer {
    /// Parse `1.2.3`, `v1.2.3`, `1.2`, `1.2.3-rc.1`, `1.2.3+build`.
    ///
    /// A leading `v` is accepted because that is how the release tags are
    /// spelled. Build metadata is dropped because semver says it takes no part
    /// in ordering. A two-component version is accepted with a zero patch —
    /// container tags are spelled that way often enough to be worth handling.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s
            .strip_prefix('v')
            .or_else(|| s.strip_prefix('V'))
            .unwrap_or(s);
        let s = s.split('+').next()?;
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, p),
            None => (s, ""),
        };

        let mut it = core.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = match it.next() {
            Some(v) => v.parse().ok()?,
            None => 0,
        };
        let patch = match it.next() {
            Some(v) => v.parse().ok()?,
            None => 0,
        };
        if it.next().is_some() {
            return None;
        }

        Some(SemVer {
            major,
            minor,
            patch,
            pre: if pre.is_empty() {
                Vec::new()
            } else {
                pre.split('.')
                    .map(|f| match f.parse::<u64>() {
                        Ok(n) => PreField::Num(n),
                        Err(_) => PreField::Text(f.to_string()),
                    })
                    .collect()
            },
        })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::{Equal, Greater, Less};
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                // A pre-release tail ranks below the release it leads up to:
                // 1.0.0-rc.1 < 1.0.0.
                (true, true) => Equal,
                (true, false) => Greater,
                (false, true) => Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            f.write_str("-")?;
            for (i, p) in self.pre.iter().enumerate() {
                if i > 0 {
                    f.write_str(".")?;
                }
                match p {
                    PreField::Num(n) => write!(f, "{n}")?,
                    PreField::Text(t) => f.write_str(t)?,
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_ordered_numerically_and_not_lexically() {
        // The whole reason this is not a string comparison.
        assert!(SemVer::parse("0.1.10").unwrap() > SemVer::parse("0.1.9").unwrap());
        assert!(SemVer::parse("0.2.0").unwrap() > SemVer::parse("0.1.99").unwrap());
        assert!(SemVer::parse("1.0.0").unwrap() > SemVer::parse("0.99.99").unwrap());
        assert!(SemVer::parse("v10.0.0").unwrap() > SemVer::parse("v9.0.0").unwrap());
        assert_eq!(
            SemVer::parse("v0.1.0").unwrap(),
            SemVer::parse("0.1.0").unwrap()
        );
    }

    #[test]
    fn a_prerelease_ranks_below_the_release_it_leads_to() {
        assert!(SemVer::parse("1.0.0-rc.1").unwrap() < SemVer::parse("1.0.0").unwrap());
        assert!(SemVer::parse("1.0.0-rc.1").unwrap() < SemVer::parse("1.0.0-rc.2").unwrap());
        // Numeric identifiers sort below alphanumeric ones — semver 11.4.
        assert!(SemVer::parse("1.0.0-1").unwrap() < SemVer::parse("1.0.0-alpha").unwrap());
        assert!(SemVer::parse("1.0.0-alpha.2").unwrap() < SemVer::parse("1.0.0-alpha.10").unwrap());
        assert!(SemVer::parse("1.0.0-rc.1").unwrap().is_prerelease());
        assert!(!SemVer::parse("1.0.0").unwrap().is_prerelease());
    }

    #[test]
    fn build_metadata_is_ignored_and_short_versions_fill_in_zeroes() {
        assert_eq!(
            SemVer::parse("1.2.3+build.7").unwrap(),
            SemVer::parse("1.2.3").unwrap()
        );
        assert_eq!(
            SemVer::parse("1.2").unwrap(),
            SemVer::parse("1.2.0").unwrap()
        );
        assert_eq!(SemVer::parse("3").unwrap(), SemVer::parse("3.0.0").unwrap());
    }

    #[test]
    fn what_is_not_a_version_is_refused_rather_than_guessed_at() {
        for s in ["", "latest", "1.2.3.4", "v", "x.y.z", "1.2.-3"] {
            assert!(SemVer::parse(s).is_none(), "{s:?} was accepted");
        }
        // The amneziawg-go tags this project pins do parse, which matters
        // because they are compared the same way.
        assert!(SemVer::parse("v0.2.14-beta-awg-1.5-1").is_some());
        assert!(SemVer::parse("v3.0.2").is_some());
    }

    #[test]
    fn versions_render_back_to_what_they_were_parsed_from() {
        for s in ["0.1.0", "1.2.3", "1.0.0-rc.1", "2.0.0-alpha.10"] {
            assert_eq!(SemVer::parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn the_compiled_version_is_a_version() {
        // If this ever fails the update check silently degrades to Unknown.
        assert!(
            SemVer::parse(CURRENT_VERSION).is_some(),
            "{CURRENT_VERSION}"
        );
    }
}
