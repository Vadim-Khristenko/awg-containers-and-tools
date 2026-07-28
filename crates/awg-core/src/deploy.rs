//! Deploying an AmneziaWG 3.0 server onto a machine reached over SSH.
//!
//! The module is split so that almost none of it needs a server to be tested:
//!
//! * [`survey`] — command output in, a picture of the machine out.
//! * [`prepare`] — that picture in, packages/sysctl/fallback decisions out.
//! * [`config`] — one parameter set in, a server config, a UAPI request and a
//!   client `.conf` out, all three provably carrying the same obfuscation.
//!
//! What is left here is the part that genuinely needs a socket: running the
//! commands those modules produced, in order, and stopping at the first one that
//! did not work.
//!
//! Two rules shape the sequence, and both are about key material:
//!
//! * The **server** private key is generated on the target, written to a file on
//!   the target by the target's own shell, and substituted into the config
//!   there. It never crosses the network, not even encrypted.
//! * The **client** private key has no such luxury — it is the thing the user
//!   asked for — so it is generated on the target and read back over the SSH
//!   channel, and nothing else about it is written to disk on either side.

pub mod config;
pub mod prepare;
pub mod survey;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::{Error, Result};

pub use config::{
    ContainerSpec, Keys, NetworkSpec, SERVER_KEY_PLACEHOLDER, Tunnel, client_conf,
    docker_run_command, server_conf, server_uapi_request,
};
pub use prepare::{Preparation, SourceBuildOptions, SourceBuildPlan};
pub use survey::{DockerAccess, Survey};

/// Ship a file to the target without a second channel and without quoting
/// hazards: base64 has no shell metacharacters, so the payload cannot break out
/// of the command no matter what is in the file.
pub fn write_file_command(path: &str, contents: &str, mode: u32) -> String {
    let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or(".");
    let dir = if dir.is_empty() { "/" } else { dir };
    format!(
        "install -d '{dir}' && printf '%s' '{payload}' | base64 -d > '{path}' && chmod {mode:04o} '{path}'",
        payload = B64.encode(contents)
    )
}

/// Generate the server key pair on the target and print only the public half.
///
/// The redirection is run by the target's shell, so the private key goes from
/// the container's stdout into a root-owned file without ever entering the SSH
/// channel. `umask 077` is applied before the file is created rather than
/// `chmod` after, which would leave a window where it is world-readable.
pub fn server_key_command(image: &str, key_path: &str) -> String {
    format!(
        "umask 077 && docker run --rm --entrypoint awg {image} genkey > '{key_path}' && \
         docker run --rm -i --entrypoint awg {image} pubkey < '{key_path}'"
    )
}

/// Generate the client's key pair and a preshared key in one container run.
///
/// One run rather than three: each `docker run` costs a container start, and the
/// three values have to come from the same `awg` build anyway.
pub fn client_key_command(image: &str) -> String {
    format!(
        "docker run --rm --entrypoint sh {image} -c \
         'p=$(awg genkey); printf \"%s\\n%s\\n%s\\n\" \"$p\" \"$(printf %s \"$p\" | awg pubkey)\" \"$(awg genpsk)\"'"
    )
}

/// Write the server config and complete it from the key file that stayed put.
///
/// `sed` with `|` as the delimiter: base64 contains `+`, `/` and `=`, so `/`
/// would need escaping and `|` never can.
pub fn install_server_conf_command(conf_path: &str, key_path: &str, conf: &str) -> String {
    format!(
        "{write} && k=$(cat '{key_path}') && sed -i \"s|{SERVER_KEY_PLACEHOLDER}|$k|\" '{conf_path}'",
        write = write_file_command(conf_path, conf, 0o600)
    )
}

/// Is the image already on the target?
pub fn image_check_command(image: &str) -> String {
    format!("docker image inspect {image} >/dev/null 2>&1")
}

/// A base64 curve25519 key is 32 bytes and nothing else. A shorter one still
/// handshakes — with nobody.
fn check_key(value: &str, what: &str) -> Result<String> {
    let raw = B64
        .decode(value)
        .map_err(|e| Error::Key(format!("{what} is not base64: {e}")))?;
    if raw.len() != 32 {
        return Err(Error::Key(format!(
            "{what} decodes to {} bytes, not 32",
            raw.len()
        )));
    }
    Ok(value.to_string())
}

/// Read back what [`client_key_command`] printed: private key, public key,
/// preshared key, one per line.
pub fn parse_key_bundle(output: &str) -> Result<(String, String, String)> {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let [private, public, psk] = lines[..] else {
        return Err(Error::Key(format!(
            "expected three keys from the target, got {} line(s)",
            lines.len()
        )));
    };
    Ok((
        check_key(private, "the client private key")?,
        check_key(public, "the client public key")?,
        check_key(psk, "the preshared key")?,
    ))
}

/// Everything the user gets out of a successful deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployResult {
    /// The `.conf` to hand to a client, complete with its private key.
    pub client_conf: String,
    /// The same config as the link the Amnezia client imports.
    pub vpn_link: String,
    pub server_public_key: String,
    pub endpoint: String,
    pub interface: String,
    pub container: String,
    /// Things that worked but should not be left as they are — a private
    /// endpoint address, say. Empty on a clean deploy.
    pub warnings: Vec<String>,
}

/// Assemble the result from material that is already in hand. Separate from the
/// deploy itself so the rendering can be tested without a server.
pub fn build_result(
    net: &NetworkSpec,
    tunnel: &Tunnel,
    keys: &Keys,
    container: &str,
    warnings: Vec<String>,
) -> Result<DeployResult> {
    let client_conf = client_conf(net, tunnel, keys);
    let vpn_link = crate::vpn::conf_to_vpn(&client_conf)?;
    Ok(DeployResult {
        client_conf,
        vpn_link,
        server_public_key: keys.server_public.clone(),
        endpoint: net.endpoint(),
        interface: net.interface.clone(),
        container: container.to_string(),
        warnings,
    })
}

// ------------------------------------------------------------------- transport
// Everything below needs a socket. WASM has none; see the note in lib.rs.

#[cfg(not(target_arch = "wasm32"))]
pub mod remote {
    use std::thread::sleep;
    use std::time::Duration;

    use crate::awg3::Awg3Options;
    use crate::platform::Tool;
    use crate::rng::Rng;
    use crate::ssh::{Session, exec, exec_sudo};
    use crate::{Error, Result};

    // Spelled out rather than glob-imported: the transport functions below share
    // their names with the modules they drive, and only one of the two should
    // ever be ambiguous to a reader.
    use super::config::{self, ContainerSpec, NetworkSpec};
    use super::prepare::{self, Preparation, SourceBuildOptions};
    use super::survey::{self, Probes, Survey, survey_from_probes};
    use super::{
        DeployResult, Keys, Tunnel, build_result, check_key, client_key_command,
        docker_run_command, image_check_command, install_server_conf_command, parse_key_bundle,
        server_conf, server_key_command,
    };

    /// How the caller wants the survey done.
    #[derive(Debug, Clone)]
    pub struct SurveyOptions {
        /// Ask a third party what this machine's public address is. Off by
        /// default: it tells that third party a server is being deployed, and
        /// on a machine with a directly attached public address the default
        /// route already knows the answer.
        pub allow_external_echo: bool,
        pub echo_url: String,
        /// Retry the docker probe under sudo when it fails as the login user.
        pub probe_sudo: bool,
    }

    impl Default for SurveyOptions {
        fn default() -> Self {
            Self {
                allow_external_echo: false,
                // Plain text, one line, no JSON to parse and no redirect.
                echo_url: "https://api.ipify.org".into(),
                probe_sudo: true,
            }
        }
    }

    /// A session plus what is known about privileges on the other end.
    pub struct Remote<'a> {
        session: &'a Session,
        sudo_password: Option<&'a str>,
        is_root: bool,
        docker_needs_sudo: bool,
    }

    impl<'a> Remote<'a> {
        pub fn new(session: &'a Session, sudo_password: Option<&'a str>) -> Self {
            Self {
                session,
                sudo_password,
                is_root: false,
                docker_needs_sudo: false,
            }
        }

        /// Adopt what the survey learned: whether we are already root, and
        /// whether docker answers without sudo.
        pub fn with_survey(mut self, s: &Survey) -> Self {
            self.is_root = s.is_root;
            self.docker_needs_sudo = s.docker.needs_sudo();
            self
        }

        /// As the login user.
        pub fn run(&self, cmd: &str) -> Result<(String, String, i32)> {
            exec(self.session, cmd)
        }

        /// As root — directly if we already are, since a minimal image may not
        /// even have sudo installed.
        pub fn run_root(&self, cmd: &str) -> Result<(String, String, i32)> {
            if self.is_root {
                exec(self.session, cmd)
            } else {
                exec_sudo(self.session, cmd, self.sudo_password)
            }
        }

        /// A docker command, escalated only if the survey said it has to be.
        pub fn run_docker(&self, cmd: &str) -> Result<(String, String, i32)> {
            if self.docker_needs_sudo || self.is_root {
                self.run_root(cmd)
            } else {
                self.run(cmd)
            }
        }

        fn ok(&self, what: &str, out: (String, String, i32)) -> Result<String> {
            let (stdout, stderr, code) = out;
            if code == 0 {
                return Ok(stdout);
            }
            let detail = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            Err(Error::Ssh(format!("{what} failed (exit {code}): {detail}")))
        }
    }

    /// Ask the target what it is. Every command is best-effort: a probe that
    /// fails is an answer ("not installed", "no default route"), not a reason to
    /// abandon the deploy.
    pub fn survey(
        session: &Session,
        opts: &SurveyOptions,
        sudo_password: Option<&str>,
    ) -> Result<Survey> {
        let r = Remote::new(session, sudo_password);

        let os_release = r.run("cat /etc/os-release 2>/dev/null || true")?.0;
        let uid = r.run("id -u")?.0;
        let tool_probe = r.run(&survey::tool_probe_command(&Tool::REQUIRED))?.0;

        // Both in one round trip: `route get` answers when there is no default
        // route line to read, and parse_route prefers a real default anyway.
        let route = r
            .run("ip -4 route show default 2>/dev/null; ip -4 route get 1.1.1.1 2>/dev/null")?
            .0;
        let ip_forward = r
            .run("sysctl -n net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0")?
            .0;

        let docker_present = survey::tool_path(&tool_probe, Tool::Docker.binary()).is_some();
        let docker_direct_code = if docker_present {
            r.run("docker info >/dev/null 2>&1")?.2
        } else {
            127
        };
        let docker_sudo_code = if docker_present && docker_direct_code != 0 && opts.probe_sudo {
            Some(r.run_root("docker info >/dev/null 2>&1")?.2)
        } else {
            None
        };

        let mut probes = Probes {
            os_release,
            tool_probe,
            route,
            ip_forward,
            uid,
            docker_direct_code,
            docker_sudo_code,
            echo: None,
        };

        // Only bother a third party when the machine's own answer is unusable.
        let local_is_global = survey::parse_route(&probes.route)
            .and_then(|route| route.source)
            .map(|src| survey::is_global_ipv4(&src))
            .unwrap_or(false);
        if opts.allow_external_echo && !local_is_global {
            let cmd = format!("curl -fsS --max-time 8 {}", opts.echo_url);
            if let Ok((out, _, 0)) = r.run(&cmd) {
                probes.echo = Some(out);
            }
        }

        Ok(survey_from_probes(&probes))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Forwarding {
        AlreadyOn,
        Enabled,
        /// Nothing was run, because nothing was going to be deployed either.
        NotAttempted,
    }

    #[derive(Debug, Clone)]
    pub struct PrepareOutcome {
        pub preparation: Preparation,
        pub installed: bool,
        pub forwarding: Forwarding,
    }

    /// Install what is missing and turn on forwarding.
    ///
    /// A [`Preparation::Manual`] or [`Preparation::SourceFallback`] stops here
    /// and changes nothing: the caller has a hint to show a human, and half-
    /// preparing a machine that cannot be finished is worse than not starting.
    pub fn prepare(
        session: &Session,
        s: &Survey,
        fallback: Option<&SourceBuildOptions>,
        sudo_password: Option<&str>,
    ) -> Result<PrepareOutcome> {
        let r = Remote::new(session, sudo_password).with_survey(s);
        let preparation = prepare::plan_preparation(&s.distro, &s.missing, fallback);

        let installed = match &preparation {
            Preparation::Manual { .. } | Preparation::SourceFallback { .. } => {
                return Ok(PrepareOutcome {
                    preparation,
                    installed: false,
                    forwarding: Forwarding::NotAttempted,
                });
            }
            Preparation::Install { cmd, .. } => {
                let out = r.run_root(cmd)?;
                r.ok("installing packages", out)?;
                true
            }
            Preparation::Ready => false,
        };

        let forwarding = if s.ip_forward {
            Forwarding::AlreadyOn
        } else {
            let out = r.run_root(&prepare::enable_forwarding_command())?;
            r.ok("enabling IPv4 forwarding", out)?;
            Forwarding::Enabled
        };

        Ok(PrepareOutcome {
            preparation,
            installed,
            forwarding,
        })
    }

    #[derive(Debug, Clone)]
    pub struct DeployOptions {
        pub network: NetworkSpec,
        pub container: ContainerSpec,
        pub awg3: Awg3Options,
        /// Pull the image when the target does not have it. Off by default: the
        /// image is normally built from `containers/awg3` and pulling silently
        /// would be a different binary than the one that was reviewed.
        pub pull: bool,
        /// How long to wait for the interface to appear, in half-seconds.
        pub verify_attempts: u32,
    }

    impl Default for DeployOptions {
        fn default() -> Self {
            Self {
                network: NetworkSpec::default(),
                container: ContainerSpec::default(),
                awg3: Awg3Options::default(),
                pull: false,
                verify_attempts: 20,
            }
        }
    }

    /// Put an AmneziaWG 3.0 server on the target and come back with the client's
    /// config. See the module note for what does and does not cross the wire.
    pub fn deploy(
        session: &Session,
        s: &Survey,
        opts: &DeployOptions,
        rng: &mut impl Rng,
        sudo_password: Option<&str>,
    ) -> Result<DeployResult> {
        if !s.docker.is_usable() {
            return Err(Error::Config(format!(
                "docker is not usable on this target ({:?}); run prepare first, or use the source fallback",
                s.docker
            )));
        }
        let r = Remote::new(session, sudo_password).with_survey(s);

        // Fill in what the survey knows, unless the caller was explicit.
        let mut net = opts.network.clone();
        let mut warnings = Vec::new();
        if net.endpoint_host.is_empty() {
            let ip = s.public_ip.as_ref().ok_or_else(|| {
                Error::Config(
                    "no public address found for the endpoint — pass one explicitly".into(),
                )
            })?;
            net.endpoint_host = ip.address.clone();
            if !ip.global {
                warnings.push(format!(
                    "{} is not reachable from outside this network; clients elsewhere will not connect",
                    ip.address
                ));
            }
        }
        if s.egress_interface().is_none() {
            warnings.push("no default route found; the container's NAT rule may not match".into());
        }

        // --- image -----------------------------------------------------------
        let image = &opts.container.image;
        if r.run_docker(&image_check_command(image))?.2 != 0 {
            if !opts.pull {
                return Err(Error::Config(format!(
                    "image {image} is not on the target; build it from containers/awg3 and load it, or allow a pull"
                )));
            }
            let out = r.run_docker(&format!("docker pull {image}"))?;
            r.ok("pulling the image", out)?;
        }

        // --- keys ------------------------------------------------------------
        let conf_dir = opts.container.conf_dir.trim_end_matches('/').to_string();
        let key_path = format!("{conf_dir}/server.key");
        let out = r.run_root(&format!("install -d -m 0700 '{conf_dir}'"))?;
        r.ok("creating the config directory", out)?;

        let out = r.run_root(&server_key_command(image, &key_path))?;
        let printed = r.ok("generating the server key", out)?;
        let server_public = check_key(printed.trim(), "the server public key")?;

        let out = r.run_docker(&client_key_command(image))?;
        let (client_private, client_public, psk) =
            parse_key_bundle(&r.ok("generating the client keys", out)?)?;

        let keys = Keys {
            server_public,
            client_private,
            client_public,
            preshared: Some(psk),
        };

        // --- config ----------------------------------------------------------
        let tunnel = Tunnel::generate(rng, opts.awg3)?;
        let conf_path = opts.container.conf_path();
        let out = r.run_root(&install_server_conf_command(
            &conf_path,
            &key_path,
            &server_conf(&net, &tunnel, &keys),
        ))?;
        r.ok("writing the server config", out)?;

        // --- run -------------------------------------------------------------
        r.run_docker(&config::docker_reset_command(&opts.container))?;
        let out = r.run_docker(&docker_run_command(&opts.container, &net))?;
        r.ok("starting the container", out)?;

        // --- verify ----------------------------------------------------------
        let check = config::interface_check_command(&opts.container, &net);
        let mut up = false;
        for attempt in 0..opts.verify_attempts.max(1) {
            if attempt > 0 {
                sleep(Duration::from_millis(500));
            }
            let (stdout, _, _) = r.run_docker(&check)?;
            if config::parse_interface_up(&stdout, &net.interface) {
                up = true;
                break;
            }
        }
        if !up {
            // The daemon's own complaint is far more useful than "it did not
            // come up", so go and get it.
            let logs = r
                .run_docker(&config::docker_logs_command(&opts.container))
                .map(|(o, e, _)| format!("{o}{e}"))
                .unwrap_or_default();
            return Err(Error::Ssh(format!(
                "{} never came up inside {}; container log:\n{}",
                net.interface,
                opts.container.name,
                logs.trim()
            )));
        }

        build_result(&net, &tunnel, &keys, &opts.container.name, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::awg3::Awg3Options;
    use crate::rng::SeededRng;

    fn keys() -> Keys {
        Keys {
            server_public: "0RSyG3nCXLBLGvNGqIzfhAqxV5s+RBgs1cq5AhCUcng=".into(),
            client_private: "yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=".into(),
            client_public: "7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM=".into(),
            preshared: None,
        }
    }

    #[test]
    fn a_file_write_command_carries_its_payload_out_of_reach_of_the_shell() {
        let nasty = "'; rm -rf / #\n$(whoami)\n`id`\n";
        let cmd = write_file_command("/etc/awg/server.conf", nasty, 0o600);
        assert!(
            !cmd.contains("rm -rf"),
            "the payload must not appear literally: {cmd}"
        );
        assert!(!cmd.contains("$(whoami)"));
        assert!(cmd.contains("install -d '/etc/awg'"));
        assert!(cmd.contains("chmod 0600 '/etc/awg/server.conf'"));
        // And it must still be the same bytes on the other end.
        let payload = cmd
            .split('\'')
            .find(|s| {
                s.len() > 8
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
            })
            .expect("no base64 payload in the command");
        assert_eq!(
            String::from_utf8(B64.decode(payload).unwrap()).unwrap(),
            nasty
        );
    }

    #[test]
    fn a_file_at_the_root_still_gets_a_valid_directory() {
        assert!(write_file_command("/hosts", "x", 0o644).contains("install -d '/'"));
    }

    #[test]
    fn the_server_private_key_is_never_read_back_over_the_channel() {
        let cmd = server_key_command("awg3:latest", "/etc/amnezia/awg3/server.key");
        // genkey's output is redirected on the target; only pubkey prints.
        assert!(
            cmd.contains("genkey > '/etc/amnezia/awg3/server.key'"),
            "{cmd}"
        );
        assert!(cmd.contains("pubkey < '/etc/amnezia/awg3/server.key'"));
        assert!(
            cmd.starts_with("umask 077 &&"),
            "the key file must never be world-readable"
        );
    }

    #[test]
    fn the_conf_install_substitutes_the_key_that_stayed_on_the_target() {
        let cmd = install_server_conf_command(
            "/etc/amnezia/awg3/server.conf",
            "/etc/amnezia/awg3/server.key",
            "[Interface]\nPrivateKey = __SERVER_PRIVATE_KEY__\n",
        );
        assert!(
            cmd.contains("k=$(cat '/etc/amnezia/awg3/server.key')"),
            "{cmd}"
        );
        assert!(cmd.contains(&format!("s|{SERVER_KEY_PLACEHOLDER}|$k|")));
        // `/` in base64 would end a `s/../../` expression early.
        assert!(!cmd.contains("s/__SERVER"));
        assert!(cmd.contains("chmod 0600"));
    }

    #[test]
    fn the_key_bundle_is_read_back_as_three_checked_keys() {
        let out = "yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=\n\
                   7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM=\n\
                   dGVzdHBza3Rlc3Rwc2t0ZXN0cHNrdGVzdHBza3Rlc3Q=\n";
        let (priv_, pub_, psk) = parse_key_bundle(out).unwrap();
        assert!(priv_.starts_with("yNMD"));
        assert!(pub_.starts_with("7DHF"));
        assert!(psk.starts_with("dGVz"));
    }

    #[test]
    fn a_truncated_or_noisy_key_bundle_is_refused_rather_than_deployed() {
        assert!(parse_key_bundle("").is_err());
        assert!(parse_key_bundle("only-one-line\n").is_err());
        // A key that is not 32 bytes would connect to nothing, silently.
        assert!(
            parse_key_bundle("c2hvcnQ=\nc2hvcnQ=\nc2hvcnQ=\n").is_err(),
            "short keys must be refused"
        );
        // A warning line on stdout must not be taken for key material.
        assert!(
            parse_key_bundle(
                "WARNING: the requested image's platform does not match\n\
                 yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=\n\
                 7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM=\n\
                 dGVzdHBza3Rlc3Rwc2t0ZXN0cHNrdGVzdHBza3Rlc3Q=\n"
            )
            .is_err()
        );
    }

    #[test]
    fn the_client_key_command_produces_all_three_values_in_one_container_run() {
        let cmd = client_key_command("awg3:latest");
        assert_eq!(cmd.matches("docker run").count(), 1);
        assert!(cmd.contains("awg genkey"));
        assert!(cmd.contains("awg pubkey"));
        assert!(cmd.contains("awg genpsk"));
    }

    #[test]
    fn the_result_carries_both_a_conf_and_a_link_that_agree() {
        let net = NetworkSpec {
            endpoint_host: "95.85.30.7".into(),
            ..Default::default()
        };
        let tunnel = Tunnel::generate(&mut SeededRng::new(21), Awg3Options::default()).unwrap();
        let result = build_result(&net, &tunnel, &keys(), "awg3-server", vec![]).unwrap();

        assert!(result.vpn_link.starts_with("vpn://"));
        assert_eq!(result.endpoint, "95.85.30.7:51820");
        assert_eq!(result.interface, "awg0");
        assert_eq!(result.server_public_key, keys().server_public);
        assert!(result.client_conf.contains(&keys().client_private));
        assert!(result.warnings.is_empty());

        let decoded = crate::vpn::decode(&result.vpn_link).unwrap();
        assert_eq!(
            decoded["containers"][0]["awg"]["config"].as_str().unwrap(),
            result.client_conf
        );
        assert_eq!(decoded["hostName"].as_str().unwrap(), "95.85.30.7");
    }

    #[test]
    fn the_image_check_is_silent_and_only_reports_through_its_exit_code() {
        let cmd = image_check_command("awg3:latest");
        assert_eq!(cmd, "docker image inspect awg3:latest >/dev/null 2>&1");
    }
}
