# Contributing

Thanks for wanting to help. What follows is what a contributor actually needs — the commands, the gotchas this project has already fallen into, and where things live.

## What you need

- **Rust stable** — the workspace builds on it alone.
- **Docker** — only for the live tunnel tests and the images. Everything else (unit tests, clippy, the CLI itself) runs without it.
- No OpenSSL on your machine, and that is on purpose: `ssh2` vendors its own, and a system OpenSSL is one more thing to disagree about.

## The commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Warnings are errors in CI on purpose: more than one bug here started life as a clippy warning nobody acted on. If your change needs an `#[allow]`, the comment above it should say why the lint is wrong rather than inconvenient.

## The gotchas

**The exec bit.** A Windows working copy cannot record file modes, and a shell script committed without `100755` works for whoever added it and fails everywhere else. CI checks the index and will send you here:

```bash
git update-index --chmod=+x containers/your-script.sh
```

**Live tunnel tests do not run on every push.** They need `/dev/net/tun`, privileged containers and about forty minutes, so they are `workflow_dispatch` plus a weekly schedule. If your change touches the images, the entrypoint or the test scripts, trigger "Live tunnel tests" by hand before calling it done — the unit tests cannot see a handshake.

**The status page's stylesheet is generated.** `containers/status-www/architect.css` is extracted from the [Architect repository](https://github.com/Vadim-Khristenko/Any-Tech-ARCHITECT)'s kit so the page renders as the site's sibling. Edit the kit over there, then:

```bash
node containers/status-www/extract-kit.js
```

and commit the result. The image build never needs the Architect repo — the generated file is committed.

**Image rebuilds are fingerprinted.** `containers/inputs-digest.sh` hashes everything that decides what ends up inside an image; the release pipeline compares it against what is published and skips identical images. If you add a file that ends up in an image — a script, a config — add it to the fingerprint list, or a changed image will quietly look unchanged.

## Where things live

| Path | What it is |
|---|---|
| `crates/awg-core` | parameter generation, rendering, the version capability table |
| `crates/awg-cli` | `awg-tool`: the command surface and the TUI |
| `containers/` | one Dockerfile per shape, the entrypoints, the live test scripts |

New protocol vocabulary goes through the same door as everything else: the capability table in `awg-core/src/versions.rs` decides what a version reads, and the renderer, the parser and the tests follow from it. A key the version does not read must not be emitted — a device refuses unknown keys at config parse, and a config that fails elsewhere is not a feature.

## Commits

Conventional prefixes (`feat`, `fix`, `docs`, `chore`), a lowercase summary that says what happened, and a body that says why when the why is not obvious. English.
