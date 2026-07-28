//! Finding, inspecting and diagnosing this project's containers on a machine
//! reached over SSH.
//!
//! Where to look:
//!
//! | module          | question it answers                                             |
//! |-----------------|-----------------------------------------------------------------|
//! | [`host`]        | how a command gets to the target, and whether it needs sudo      |
//! | [`image`]       | is this image one of ours, and which generation                  |
//! | [`discover`]    | which containers on this host are ours                           |
//! | [`inspect`]     | what privileges and ports one container was given                |
//! | [`health`]      | is the interface up, does the socket answer, who has handshaked  |
//! | [`obfuscation`] | do the two ends of a tunnel carry the same shared parameters     |
//! | [`logs`]        | what the container said — with the secrets taken out             |
//! | [`diagnose`]    | what is wrong, on what evidence, and what to do about it         |
//! | [`faults`]      | the rules about how the container was started                    |
//! | [`tunnel`]      | the rules about whether the protocol is working                  |
//!
//! Three properties hold across all of them.
//!
//! **Detection is by image, not by name.** A container this tool started and one
//! someone started by hand from `docker run vaiprog/amnezia-wg-3` are the same
//! thing, so the match is on the image reference and on the
//! [`image::PROTOCOL_LABEL`] the images carry. A user-renamed container is ours;
//! a container called `awg-server` running nginx is not.
//!
//! **Nothing secret leaves a function here.** [`logs::logs`] redacts before it
//! returns, [`health::parse_uapi_get`] records *that* a private or preshared key
//! is set and never its value, and [`obfuscation`] reports which field differs
//! without printing the header-protection key. The rule sits at the function
//! boundary rather than at the print site: a caller cannot leak what it was
//! never given.
//!
//! **Every verdict names its evidence.** [`diagnose::diagnose`] is a pure
//! function over captured output, and each [`Finding`] carries the observations
//! it was drawn from plus the causes those observations cannot separate. Where
//! the evidence is missing the diagnosis says so in [`Diagnosis::blind_spots`],
//! because an empty finding list on a host we could not probe is not a clean
//! bill of health.

pub mod diagnose;
pub mod discover;
pub mod faults;
pub mod health;
pub mod host;
pub mod image;
pub mod inspect;
pub mod logs;
pub mod obfuscation;
pub mod tunnel;

pub use diagnose::{
    Confidence, Diagnosis, Evidence, FaultKind, Finding, PortTraffic, Rule, STALE_HANDSHAKE_SECS,
    diagnose, diagnose_container, parse_port_traffic, port_traffic_command,
};
pub use discover::{
    Container, ContainerState, PS_FORMAT, PublishedPort, apply_label_evidence, find_awg_containers,
    list_containers, parse_label_ids, parse_ports, parse_ps, ps_command, ps_label_command,
};
pub use health::{
    Health, PROBE_MARKER, UapiDevice, UapiPeer, UdpStats, health, health_probe_command,
    parse_health, parse_sections, parse_uapi_get, parse_udp_snmp,
};
pub use host::Host;
pub use image::{AWG_REPOSITORIES, Generation, ImageRef, PROTOCOL_LABEL, parse_image_ref};
pub use inspect::{
    Inspect, image_inspect_command, inspect, inspect_command, local_image, parse_image_inspect,
    parse_inspect,
};
pub use logs::{REDACTED, logs, logs_command, looks_like_key_material, redact};
pub use obfuscation::{
    OBFUSCATION_CONF_KEYS, OBFUSCATION_UAPI_KEYS, ObfuscationComparison, ObfuscationMismatch,
    compare_obfuscation, obfuscation_from_conf, obfuscation_from_uapi,
};
