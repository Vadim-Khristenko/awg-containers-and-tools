# Contributing

Thanks for wanting to help. This document covers what you need to know before opening a pull request.

**По-русски: [RU.CONTRIBUTING.MD](RU.CONTRIBUTING.MD)**

## Getting set up

```bash
git clone https://github.com/Vadim-Khristenko/awg-containers-and-tools
cd awg-containers-and-tools
cargo test --workspace
```

You need Rust 1.90 or newer — the workspace is on edition 2024. For anything touching the containers you also need Docker, and the test scripts need to create tun devices, so they want root.

## Before you open a PR

```bash
cargo test --workspace              # all tests pass
cargo clippy --workspace --all-targets   # zero warnings
cargo fmt --check
```

If you changed anything under `containers/`:

```bash
cd containers
./build.sh
sudo ./selftest.sh        # live tunnel per generation
sudo ./paralleltest.sh    # all four at once
sudo ./dnstest.sh         # leak protection still holds
```

These are slow, but they are the difference between "it compiles" and "it carries traffic". The container work in this project has repeatedly shipped bugs that only a live tunnel exposes.

## Things that will get a PR sent back

**Protocol invariants are not style preferences.** The generator refuses to emit certain combinations because real daemons reject them, and the reasons are recorded next to the checks. If a validation rule is in your way, find out why it exists before removing it. Some examples of what these rules encode:

- the S-value floor when header protection is enabled
- the required relation between the rekey and reject timers
- which junk-packet tags each protocol version actually accepts — 1.5 daemons reject `<rc>` and `<rd>` with `errno=-22`, and `<c>` is unimplemented on 2.0 and 3.0
- the size ceilings that keep junk packets inside the path MTU

Every one of these was found by a daemon refusing a config, not by reading a spec.

**Do not introduce a shared default parameter set.** Parameters are randomised per install on purpose. A built-in default would give every server deployed with this tool the same DPI fingerprint, and one signature would block all of them. This is the single most important design constraint in the project.

**Do not weaken key generation.** Key material comes from the OS CSPRNG. A seeded or thread-local PRNG anywhere near key generation is a security bug, not an optimisation.

**Do not log secrets.** The event log is meant to be shareable with someone helping you debug. Keys, pre-shared keys and header-protection keys must never reach it.

**Do not retune the terminal palette.** `crates/awg-cli/src/theme.rs` is the Any Tech ARCHITECT palette transcribed for a terminal, and a test pins the key values. The two halves of the release are meant to look like one product; a tidy-up here quietly splits them. If Architect's palette changes, change it here to match and say so in the commit.

## Tests

New behaviour needs a test. The protocol logic in `awg-core` is deliberately written as pure functions over inputs — parameter generation, validation, rendering and platform detection all take data and return data — so almost everything can be tested without a network, a container or a server. If your change is hard to test, that is usually a sign it should be split.

Name tests after the behaviour they protect, not the function they call. `nixos_is_never_given_an_imperative_command` tells the next person what broke; `test_plan_3` does not.

## Commit messages

Conventional commits:

```
type(scope): summary in the imperative

Why the change was needed, if it is not obvious from the summary.
```

Types in use: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `chore`. Scopes follow the layout — `awg-core`, `awg-cli`, `containers`, `ci`.

Write the body for someone reading it in a year with no memory of the discussion.

## Reporting bugs

The useful ones include:

- which protocol version and which client
- the generated parameters, **with the keys removed**
- what the daemon said — `awg-uapi get` output and the container log
- whether it fails at import, at handshake, or after traffic starts

Never paste private keys, pre-shared keys or `HeaderProtectionKey` values into an issue. Regenerate them if you already have.

## Scope

This project deliberately does not:

- ship a public server or hosting of any kind
- bundle a default configuration meant for everyone
- claim any affiliation with AmneziaVPN

Issues asking for those will be closed with a pointer back here.

## License

Contributions are accepted under the MIT license — see [LICENSE](LICENSE).
