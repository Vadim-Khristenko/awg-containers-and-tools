//! Named generator settings, kept between runs.
//!
//! A set is every knob of [`GenOptions`] written down by identifier (version,
//! profile, client and its build, engine, region, browser), so the file reads
//! and edits by hand and survives a release that reorders an enum. It lives
//! beside the connection profiles, in `sets.json`. It holds no key material:
//! a set describes how to generate, never what was generated.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::awg3::Intensity;
use crate::engines::Engine;
use crate::mimic::hostdb::Region;
use crate::mimic::{BrowserProfile, MimicOptions, MimicProfile};
use crate::profile::ensure_config_dir;
use crate::versions::{self, AwgVersion, GenOptions};
use crate::{Error, Result};

pub const SETS_FILE: &str = "sets.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSet {
    pub name: String,
    pub version: String,
    pub profile: String,
    pub client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_release: Option<String>,
    pub server_engine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whitelisted_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_host: Option<String>,
    pub intensity: String,
    pub junk_level: u8,
    pub mtu: u32,
    pub attempt: u32,
    pub mimic_all: bool,
    pub header_protection: bool,
    pub content_padding: bool,
    pub random_timings: bool,
    pub random_trailers: bool,
    pub disable_cookies: bool,
    pub narrow_h: bool,
    pub same_s: bool,
    pub disable_h: bool,
    pub tag_t: bool,
    pub tag_r: bool,
    pub tag_rc: bool,
    pub tag_rd: bool,
    pub router_mode: bool,
    pub extreme: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SetsFile {
    #[serde(default)]
    sets: Vec<SavedSet>,
}

fn intensity_id(i: Intensity) -> &'static str {
    match i {
        Intensity::Low => "low",
        Intensity::Medium => "medium",
        Intensity::High => "high",
    }
}

impl SavedSet {
    /// Write the options down under `name`.
    pub fn from_options(name: &str, o: &GenOptions) -> Self {
        // A client build is stored as the client and the release it is, so
        // the file names what the user picked rather than a copy of its limits.
        let (client, client_release) = versions::CLIENT_RELEASES
            .iter()
            .find(|r| r.caps == *o.client)
            .map_or((o.client.id.to_string(), None), |r| {
                (r.client_id.to_string(), Some(r.id.to_string()))
            });
        let m = &o.mimic;
        Self {
            name: name.trim().to_string(),
            version: o.version.as_str().into(),
            profile: o.profile.id().into(),
            client,
            client_release,
            server_engine: o.server_engine.id().into(),
            region: m.region.map(|r| r.id().into()),
            whitelisted_in: m.whitelisted_in.map(|r| r.id().into()),
            browser: m.browser.map(|b| b.id().into()),
            custom_host: m.custom_host.clone(),
            intensity: intensity_id(o.intensity).into(),
            junk_level: o.junk_level,
            mtu: m.mtu,
            attempt: m.iter_count,
            mimic_all: m.mimic_all,
            header_protection: o.header_protection,
            content_padding: o.content_padding,
            random_timings: o.random_timings,
            random_trailers: o.random_trailers,
            disable_cookies: o.disable_cookies,
            narrow_h: o.narrow_h,
            same_s: o.same_s,
            disable_h: o.disable_h,
            tag_t: m.tag_t,
            tag_r: m.tag_r,
            tag_rc: m.tag_rc,
            tag_rd: m.tag_rd,
            router_mode: o.router_mode,
            extreme: o.extreme,
        }
    }

    /// The options a set describes. Every identifier is looked up, and one
    /// this build does not know is an error naming it rather than a silent
    /// default: a set that quietly generates something else is worse than one
    /// that refuses.
    pub fn to_options(&self) -> Result<GenOptions> {
        let bad = |what: &str, v: &str| {
            Error::Config(format!("set {:?}: unknown {what} {v:?}", self.name))
        };
        let version =
            AwgVersion::parse(&self.version).ok_or_else(|| bad("version", &self.version))?;
        let profile =
            MimicProfile::parse(&self.profile).ok_or_else(|| bad("profile", &self.profile))?;
        let client = versions::client_release(&self.client, self.client_release.as_deref())
            .ok_or_else(|| bad("client", &self.client))?;
        let server_engine =
            Engine::parse(&self.server_engine).ok_or_else(|| bad("engine", &self.server_engine))?;
        let region = |v: &Option<String>| -> Result<Option<Region>> {
            v.as_deref()
                .map(|r| Region::parse(r).ok_or_else(|| bad("region", r)))
                .transpose()
        };
        let browser = self
            .browser
            .as_deref()
            .map(|b| BrowserProfile::parse(b).ok_or_else(|| bad("browser", b)))
            .transpose()?;
        let intensity = match self.intensity.as_str() {
            "low" => Intensity::Low,
            "medium" => Intensity::Medium,
            "high" => Intensity::High,
            other => return Err(bad("intensity", other)),
        };
        Ok(GenOptions {
            version,
            profile,
            intensity,
            client,
            server_engine,
            header_protection: self.header_protection,
            content_padding: self.content_padding,
            random_timings: self.random_timings,
            random_trailers: self.random_trailers,
            disable_cookies: self.disable_cookies,
            router_mode: self.router_mode,
            extreme: self.extreme,
            junk_level: self.junk_level,
            narrow_h: self.narrow_h,
            same_s: self.same_s,
            disable_h: self.disable_h,
            mimic: MimicOptions {
                mtu: self.mtu,
                mimic_all: self.mimic_all,
                custom_host: self.custom_host.clone(),
                region: region(&self.region)?,
                whitelisted_in: region(&self.whitelisted_in)?,
                tag_t: self.tag_t,
                tag_r: self.tag_r,
                tag_rc: self.tag_rc,
                tag_rd: self.tag_rd,
                browser,
                router_mode: self.router_mode,
                iter_count: self.attempt,
                ..MimicOptions::default()
            },
        })
    }
}

pub fn sets_path(base: &Path) -> PathBuf {
    base.join(SETS_FILE)
}

/// Every saved set, in the order they were saved. A missing file is no sets.
pub fn load_all(base: &Path) -> Result<Vec<SavedSet>> {
    let path = sets_path(base);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Config(format!("{}: {e}", path.display()))),
    };
    let file: SetsFile = serde_json::from_str(&text)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    Ok(file.sets)
}

pub fn get(base: &Path, name: &str) -> Result<Option<SavedSet>> {
    Ok(load_all(base)?.into_iter().find(|s| s.name == name.trim()))
}

/// Save a set, replacing one of the same name.
pub fn save(base: &Path, set: SavedSet) -> Result<()> {
    if set.name.is_empty() {
        return Err(Error::Config("a set needs a name".into()));
    }
    let mut sets = load_all(base)?;
    match sets.iter_mut().find(|s| s.name == set.name) {
        Some(existing) => *existing = set,
        None => sets.push(set),
    }
    write(base, sets)
}

/// Remove a set; `false` when there was none by that name.
pub fn remove(base: &Path, name: &str) -> Result<bool> {
    let mut sets = load_all(base)?;
    let before = sets.len();
    sets.retain(|s| s.name != name.trim());
    if sets.len() == before {
        return Ok(false);
    }
    write(base, sets)?;
    Ok(true)
}

fn write(base: &Path, sets: Vec<SavedSet>) -> Result<()> {
    ensure_config_dir(base)?;
    let path = sets_path(base);
    let text = serde_json::to_string_pretty(&SetsFile { sets })
        .map_err(|e| Error::Config(e.to_string()))?;
    std::fs::write(&path, text + "\n")
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("awg-sets-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rich() -> GenOptions {
        let mut o = GenOptions::for_version(AwgVersion::V3_1);
        o.profile = MimicProfile::Stun;
        o.client = versions::client_release("amneziawg-windows", Some("pre-2.0.2")).unwrap();
        o.server_engine = Engine::Kmod;
        o.mimic.region = Some(Region::Ru);
        o.mimic.whitelisted_in = Some(Region::Ru);
        o.mimic.browser = Some(BrowserProfile::Firefox);
        o.mimic.custom_host = Some("stun.example.org".into());
        o.mimic.tag_rd = false;
        o.mimic.iter_count = 4;
        o.same_s = true;
        o.junk_level = 9;
        o
    }

    #[test]
    fn a_set_comes_back_as_the_options_it_was_made_from() {
        let o = rich();
        let back = SavedSet::from_options("home", &o).to_options().unwrap();
        assert_eq!(
            SavedSet::from_options("home", &back),
            SavedSet::from_options("home", &o)
        );
        assert_eq!(
            back.client.max_h_value, 2_147_483_647,
            "the older build survives"
        );
        let set = SavedSet::from_options("home", &o);
        assert_eq!(set.client, "amneziawg-windows");
        assert_eq!(set.client_release.as_deref(), Some("pre-2.0.2"));
    }

    #[test]
    fn sets_are_saved_replaced_and_removed_by_name() {
        let dir = Scratch::new("store");
        assert!(load_all(&dir.0).unwrap().is_empty(), "no file is no sets");
        save(&dir.0, SavedSet::from_options("a", &rich())).unwrap();
        save(&dir.0, SavedSet::from_options("b", &GenOptions::default())).unwrap();
        let mut changed = SavedSet::from_options("a", &rich());
        changed.junk_level = 1;
        save(&dir.0, changed).unwrap();
        let all = load_all(&dir.0).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(get(&dir.0, "a").unwrap().unwrap().junk_level, 1);
        assert!(remove(&dir.0, "a").unwrap());
        assert!(!remove(&dir.0, "a").unwrap());
        assert_eq!(load_all(&dir.0).unwrap().len(), 1);
    }

    #[test]
    fn an_unknown_identifier_is_named_not_defaulted() {
        let mut set = SavedSet::from_options("x", &GenOptions::default());
        set.profile = "carrier-pigeon".into();
        let err = set.to_options().unwrap_err().to_string();
        assert!(
            err.contains("carrier-pigeon") && err.contains("profile"),
            "{err}"
        );
    }
}
