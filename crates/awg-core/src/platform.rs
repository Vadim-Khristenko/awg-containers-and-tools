//! Target-system detection and install planning.
//!
//! Pure logic on purpose: it takes the text of `/etc/os-release` and returns a
//! plan, so the whole matrix is unit-tested without touching a real server.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Pacman,
    Zypper,
    Apk,
    Xbps,
    Emerge,
    /// NixOS cannot be provisioned imperatively — see [`Distro::is_declarative`].
    NixOS,
    Unknown,
}

impl PackageManager {
    pub fn install_cmd(&self, pkgs: &[&str]) -> Option<String> {
        let list = pkgs.join(" ");
        Some(match self {
            Self::Apt => format!(
                "DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq {list}"
            ),
            Self::Dnf => format!("dnf install -y -q {list}"),
            Self::Pacman => format!("pacman -Sy --noconfirm --needed {list}"),
            Self::Zypper => format!("zypper --non-interactive install {list}"),
            Self::Apk => format!("apk add --no-cache {list}"),
            Self::Xbps => format!("xbps-install -Sy {list}"),
            Self::Emerge => format!("emerge --quiet --noreplace {list}"),
            Self::NixOS | Self::Unknown => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distro {
    pub id: String,
    pub name: String,
    pub version: String,
    pub pm: PackageManager,
}

impl Distro {
    /// NixOS installs nothing imperatively: packages and services come from
    /// configuration.nix. Detecting it and saying so beats running apt-get and
    /// leaving the user with a confusing failure.
    pub fn is_declarative(&self) -> bool {
        self.pm == PackageManager::NixOS
    }

    /// Package names differ per family for the same tool.
    pub fn package_for(&self, tool: Tool) -> Option<&'static str> {
        use PackageManager as P;
        use Tool as T;
        Some(match (tool, self.pm) {
            (T::Docker, P::Apt) => "docker.io",
            (T::Docker, P::Pacman) => "docker",
            (T::Docker, P::Dnf) => "docker",
            (T::Docker, P::Zypper) => "docker",
            (T::Docker, P::Apk) => "docker",
            (T::Docker, P::Xbps) => "docker",
            (T::Docker, P::Emerge) => "app-containers/docker",
            (T::Iptables, P::Apk) => "iptables",
            (T::Iptables, _) => "iptables",
            (T::Iproute2, P::Apt) => "iproute2",
            (T::Iproute2, P::Apk) => "iproute2",
            (T::Iproute2, _) => "iproute2",
            (T::Curl, _) => "curl",
            (T::Conntrack, P::Apt) => "conntrack",
            (T::Conntrack, P::Dnf) => "conntrack-tools",
            (T::Conntrack, P::Pacman) => "conntrack-tools",
            (T::Conntrack, _) => "conntrack-tools",
            (_, P::NixOS) | (_, P::Unknown) => return None,
        })
    }
}

/// What the server needs before a container can carry traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Docker,
    Iptables,
    Iproute2,
    Curl,
    Conntrack,
}

impl Tool {
    pub const REQUIRED: [Tool; 4] = [Tool::Docker, Tool::Iptables, Tool::Iproute2, Tool::Curl];

    pub fn binary(&self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Iptables => "iptables",
            Self::Iproute2 => "ip",
            Self::Curl => "curl",
            Self::Conntrack => "conntrack",
        }
    }
}

/// Parse `/etc/os-release`. Falls back through `ID_LIKE` so derivatives that
/// nobody enumerated still get the right package manager.
pub fn detect(os_release: &str) -> Distro {
    let mut id = String::new();
    let mut like = String::new();
    let mut name = String::new();
    let mut version = String::new();

    for line in os_release.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "ID" => id = v.to_ascii_lowercase(),
            "ID_LIKE" => like = v.to_ascii_lowercase(),
            "PRETTY_NAME" | "NAME" if name.is_empty() => name = v,
            "VERSION_ID" => version = v,
            _ => {}
        }
    }

    let pm = pm_for(&id).unwrap_or_else(|| {
        like.split_whitespace()
            .find_map(pm_for)
            .unwrap_or(PackageManager::Unknown)
    });

    Distro {
        id,
        name,
        version,
        pm,
    }
}

fn pm_for(id: &str) -> Option<PackageManager> {
    use PackageManager as P;
    Some(match id {
        "debian" | "ubuntu" | "linuxmint" | "mint" | "pop" | "raspbian" | "devuan" | "kali" => {
            P::Apt
        }
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol" => P::Dnf,
        "arch" | "manjaro" | "endeavouros" | "garuda" | "artix" => P::Pacman,
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "suse" => P::Zypper,
        "alpine" => P::Apk,
        "void" => P::Xbps,
        "gentoo" => P::Emerge,
        "nixos" => P::NixOS,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Everything needed is already present.
    Ready,
    Install {
        cmd: String,
        packages: Vec<String>,
    },
    /// The distro manages packages declaratively; hand the user the snippet.
    Manual {
        reason: String,
        hint: String,
    },
}

/// Decide what to do given a detected distro and which binaries are missing.
pub fn plan(distro: &Distro, missing: &[Tool]) -> Step {
    if missing.is_empty() {
        return Step::Ready;
    }

    if distro.is_declarative() {
        return Step::Manual {
            reason: format!("{} manages packages declaratively", distro.name),
            hint: "virtualisation.docker.enable = true;\nenvironment.systemPackages = with pkgs; [ iptables iproute2 curl ];"
                .into(),
        };
    }

    let mut packages = Vec::new();
    for tool in missing {
        match distro.package_for(*tool) {
            Some(p) => packages.push(p.to_string()),
            None => {
                return Step::Manual {
                    reason: format!(
                        "unknown package name for {} on {}",
                        tool.binary(),
                        distro.name
                    ),
                    hint: format!("install {} manually, then re-run", tool.binary()),
                };
            }
        }
    }

    let refs: Vec<&str> = packages.iter().map(String::as_str).collect();
    match distro.pm.install_cmd(&refs) {
        Some(cmd) => Step::Install { cmd, packages },
        None => Step::Manual {
            reason: format!("no known package manager for {}", distro.name),
            hint: "install docker, iptables, iproute2 and curl manually".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(id: &str, like: &str) -> String {
        format!("ID={id}\nID_LIKE={like}\nPRETTY_NAME=\"Test {id}\"\nVERSION_ID=\"1\"\n")
    }

    #[test]
    fn the_common_distros_map_to_their_package_managers() {
        for (id, want) in [
            ("ubuntu", PackageManager::Apt),
            ("debian", PackageManager::Apt),
            ("linuxmint", PackageManager::Apt),
            ("arch", PackageManager::Pacman),
            ("manjaro", PackageManager::Pacman),
            ("fedora", PackageManager::Dnf),
            ("rocky", PackageManager::Dnf),
            ("opensuse-tumbleweed", PackageManager::Zypper),
            ("alpine", PackageManager::Apk),
            ("void", PackageManager::Xbps),
            ("gentoo", PackageManager::Emerge),
            ("nixos", PackageManager::NixOS),
        ] {
            assert_eq!(detect(&os(id, "")).pm, want, "{id}");
        }
    }

    #[test]
    fn unknown_derivatives_fall_back_through_id_like() {
        assert_eq!(
            detect(&os("zorin", "ubuntu debian")).pm,
            PackageManager::Apt
        );
        assert_eq!(detect(&os("cachyos", "arch")).pm, PackageManager::Pacman);
        assert_eq!(detect(&os("nobara", "fedora")).pm, PackageManager::Dnf);
    }

    #[test]
    fn nixos_is_never_given_an_imperative_command() {
        let d = detect(&os("nixos", ""));
        assert!(d.is_declarative());
        match plan(&d, &[Tool::Docker]) {
            Step::Manual { hint, .. } => assert!(hint.contains("virtualisation.docker.enable")),
            other => panic!("NixOS must not get an install command, got {other:?}"),
        }
    }

    #[test]
    fn debian_gets_docker_io_and_arch_gets_docker() {
        assert_eq!(
            detect(&os("debian", "")).package_for(Tool::Docker),
            Some("docker.io")
        );
        assert_eq!(
            detect(&os("arch", "")).package_for(Tool::Docker),
            Some("docker")
        );
    }

    #[test]
    fn nothing_missing_means_nothing_to_do() {
        assert_eq!(plan(&detect(&os("ubuntu", "")), &[]), Step::Ready);
    }

    #[test]
    fn an_unrecognised_distro_asks_for_help_instead_of_guessing() {
        let d = detect("ID=plan9\n");
        assert!(matches!(plan(&d, &[Tool::Docker]), Step::Manual { .. }));
    }
}
